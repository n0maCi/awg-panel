import { createHash, timingSafeEqual } from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import type { ClusterRuntimeConfig, ClusterSnapshot, ClusterStatus } from '../shared/types.js';
import { StateStore, parsePanelState } from './store.js';
import { AwgManager } from './wireguard.js';

const snapshotSchema = z.object({
  format: z.literal('awg-panel-cluster-state'),
  version: z.literal(1),
  sourceNode: z.string().min(1).max(128),
  createdAt: z.string().datetime(),
  digest: z.string().regex(/^[a-f0-9]{64}$/),
  state: z.unknown(),
});

function digestState(state: unknown): string {
  return createHash('sha256').update(JSON.stringify(state)).digest('hex');
}

function secretMatches(expected: string, supplied: string): boolean {
  const expectedDigest = createHash('sha256').update(expected).digest();
  const suppliedDigest = createHash('sha256').update(supplied).digest();
  return timingSafeEqual(expectedDigest, suppliedDigest);
}

export class ClusterCoordinator {
  private timer: NodeJS.Timeout | null = null;
  private syncing: Promise<void> | null = null;
  private receiveQueue: Promise<unknown> = Promise.resolve();
  private lastDigest: string | null = null;
  private lastReceivedAt: string | null = null;
  private lastSnapshotTime = 0;
  private lastSyncAt: string | null = null;
  private lastSource: string | null = null;
  private lastError: string | null = null;

  constructor(
    private readonly config: ClusterRuntimeConfig,
    private readonly store: StateStore,
    private readonly manager: AwgManager,
  ) {}

  get isWritable(): boolean {
    return this.config.role !== 'replica';
  }

  status(): ClusterStatus {
    return {
      role: this.config.role,
      nodeId: this.config.nodeId,
      peerCount: this.config.peers.length,
      readOnly: !this.isWritable,
      lastSyncAt: this.lastSyncAt,
      lastSource: this.lastSource,
      lastError: this.lastError,
    };
  }

  start(): void {
    if (this.config.role === 'standalone' || this.timer) return;
    void this.syncNow().catch(() => undefined);
    this.timer = setInterval(() => void this.syncNow().catch(() => undefined), this.config.syncIntervalMs);
    this.timer.unref();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  notifyLocalChange(): void {
    if (this.config.role === 'primary') void this.syncNow().catch(() => undefined);
  }

  syncNow(): Promise<void> {
    if (this.config.role === 'standalone') return Promise.resolve();
    if (this.syncing) return this.syncing;
    this.syncing = this.performSync().finally(() => { this.syncing = null; });
    return this.syncing;
  }

  authenticate = (request: Request, response: Response, next: NextFunction): void => {
    response.set('Cache-Control', 'no-store');
    if (this.config.role === 'standalone') {
      response.status(404).json({ error: 'Кластеризация отключена' });
      return;
    }
    const authorization = request.get('authorization') ?? '';
    const supplied = authorization.startsWith('Bearer ') ? authorization.slice(7) : '';
    if (!supplied || !secretMatches(this.config.secret, supplied)) {
      response.set('WWW-Authenticate', 'Bearer').status(401).json({ error: 'Узел кластера не авторизован' });
      return;
    }
    next();
  };

  requireWritable = (_request: Request, response: Response, next: NextFunction): void => {
    if (!this.isWritable) {
      response.status(409).json({ error: 'Изменения выполняются только на primary-узле кластера' });
      return;
    }
    next();
  };

  snapshot(): ClusterSnapshot {
    if (this.config.role !== 'primary') throw new Error('Снимок кластера выдаёт только primary-узел');
    const state = this.store.get();
    this.lastSnapshotTime = Math.max(Date.now(), this.lastSnapshotTime + 1);
    return {
      format: 'awg-panel-cluster-state',
      version: 1,
      sourceNode: this.config.nodeId,
      createdAt: new Date(this.lastSnapshotTime).toISOString(),
      digest: digestState(state),
      state,
    };
  }

  async receive(input: unknown): Promise<{ applied: boolean; digest: string }> {
    const run = () => this.receiveNow(input);
    const result = this.receiveQueue.then(run, run);
    this.receiveQueue = result.then(() => undefined, () => undefined);
    return result;
  }

  private async receiveNow(input: unknown): Promise<{ applied: boolean; digest: string }> {
    if (this.config.role !== 'replica') throw new Error('Снимок кластера принимает только replica-узел');
    const envelope = snapshotSchema.parse(input);
    const state = parsePanelState(envelope.state);
    const calculatedDigest = digestState(state);
    if (calculatedDigest !== envelope.digest) throw new Error('Контрольная сумма снимка кластера не совпадает');

    if (this.lastReceivedAt && envelope.createdAt < this.lastReceivedAt) {
      return { applied: false, digest: envelope.digest };
    }
    if (this.lastReceivedAt === envelope.createdAt && this.lastDigest && this.lastDigest !== envelope.digest) {
      throw new Error('Получены конфликтующие снимки кластера с одинаковым временем');
    }

    let applied = false;
    if (this.lastDigest !== envelope.digest) {
      applied = await this.store.importClusterState(state);
      if (applied) await this.manager.apply(this.store.get());
      this.lastDigest = envelope.digest;
    }
    this.lastReceivedAt = envelope.createdAt;
    this.lastSyncAt = new Date().toISOString();
    this.lastSource = envelope.sourceNode;
    this.lastError = null;
    return { applied, digest: envelope.digest };
  }

  private async performSync(): Promise<void> {
    try {
      if (this.config.role === 'primary') await this.pushToReplicas();
      else await this.pullFromPrimary();
      this.lastError = null;
    } catch (error) {
      this.lastError = error instanceof Error ? error.message : 'Ошибка синхронизации кластера';
      throw error;
    }
  }

  private async pushToReplicas(): Promise<void> {
    const snapshot = this.snapshot();
    const results = await Promise.allSettled(this.config.peers.map((peer) => this.push(peer, snapshot)));
    const failures = results.flatMap((result, index) => result.status === 'rejected'
      ? [`${this.config.peers[index]}: ${result.reason instanceof Error ? result.reason.message : 'ошибка'}`]
      : []);
    if (failures.length === results.length) throw new Error(`Ни одна replica не приняла состояние: ${failures.join('; ')}`);
    this.lastSyncAt = new Date().toISOString();
    this.lastSource = this.config.nodeId;
    if (failures.length) throw new Error(`Часть replica недоступна: ${failures.join('; ')}`);
  }

  private async pullFromPrimary(): Promise<void> {
    const failures: string[] = [];
    for (const peer of this.config.peers) {
      try {
        const response = await fetch(`${peer}/api/cluster/state`, {
          headers: { Authorization: `Bearer ${this.config.secret}`, Accept: 'application/json' },
          signal: AbortSignal.timeout(this.config.requestTimeoutMs),
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        await this.receive(await response.json());
        return;
      } catch (error) {
        failures.push(`${peer}: ${error instanceof Error ? error.message : 'ошибка'}`);
      }
    }
    throw new Error(`Primary недоступен: ${failures.join('; ')}`);
  }

  private async push(peer: string, snapshot: ClusterSnapshot): Promise<void> {
    const response = await fetch(`${peer}/api/cluster/state`, {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${this.config.secret}`,
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(snapshot),
      signal: AbortSignal.timeout(this.config.requestTimeoutMs),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
  }
}

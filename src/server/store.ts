import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import path from 'node:path';
import { z } from 'zod';
import type { PanelState, Peer, PortableEnvironment, WgEasyBackupFile } from '../shared/types.js';
import { SAFE_PEER_NAME } from './config.js';
import { allocateAddress, addressBelongsToCidr, networkCidr } from './network.js';
import { generateKeyPair, generatePresharedKey } from './keys.js';
import { createProtocol } from './protocol.js';

const protocolVersionSchema = z.enum(['1.5', '2.0', '3.1']);
const keySchema = z.string().regex(/^[A-Za-z0-9+/]{43}=$/, 'Некорректный ключ WireGuard');
const lineSchema = z.string().min(1).max(4096).regex(/^[^\r\n]+$/, 'Перенос строки недопустим');
const stateSchema: z.ZodType<PanelState> = z.object({
  schemaVersion: z.literal(1),
  server: z.object({ privateKey: keySchema, publicKey: keySchema }),
  interface: z.object({
    address: lineSchema,
    dns: z.array(lineSchema),
    allowedIps: z.array(lineSchema).min(1),
    mtu: z.number().int().min(576).max(9000),
    persistentKeepalive: z.number().int().min(0).max(65_535),
  }),
  protocol: z.object({ version: protocolVersionSchema, values: z.record(z.string(), lineSchema) }),
  peers: z.array(z.object({
    id: z.string().uuid(),
    name: z.string().min(1).max(64).regex(SAFE_PEER_NAME),
    address: lineSchema,
    privateKey: keySchema,
    publicKey: keySchema,
    presharedKey: keySchema,
    enabled: z.boolean(),
    createdAt: z.string().datetime(),
    updatedAt: z.string().datetime().optional(),
  })),
  environmentSnapshot: z.object({
    version: protocolVersionSchema,
    address: lineSchema,
    dns: z.array(lineSchema),
    allowedIps: z.array(lineSchema),
    mtu: z.number().int(),
    persistentKeepalive: z.number().int(),
    protocolOverrides: z.record(z.string(), lineSchema),
  }),
});

const wgEasyClientSchema = z.object({
  id: z.string().uuid(),
  name: z.string().min(1).max(64).regex(SAFE_PEER_NAME),
  address: lineSchema,
  privateKey: keySchema,
  publicKey: keySchema,
  preSharedKey: keySchema,
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime().optional(),
  expiredAt: z.string().datetime().nullable().optional(),
  enabled: z.boolean(),
});

const wgEasyBackupSchema = z.object({
  server: z.object({
    privateKey: keySchema,
    publicKey: keySchema,
    address: lineSchema,
  }).catchall(z.union([z.string(), z.number()])),
  clients: z.record(z.string(), wgEasyClientSchema),
}).superRefine((backup, context) => {
  for (const [id, client] of Object.entries(backup.clients)) {
    if (id !== client.id) context.addIssue({ code: 'custom', path: ['clients', id, 'id'], message: 'ID клиента не совпадает с ключом объекта' });
  }
});

const protocolParameterNames = [
  'Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4',
  'H1', 'H2', 'H3', 'H4', 'I1', 'I2', 'I3', 'I4', 'I5',
  'HeaderProtectionKey', 'ContentPaddingAddition', 'RekeyAfterTime',
  'RekeyTimeout', 'RejectAfterTime', 'KeepaliveTimeout',
  'MaxHandshakeAttempts', 'RandomTrailers', 'DisableCookies',
] as const;

function backupParameterName(name: string): string {
  return `${name[0].toLowerCase()}${name.slice(1)}`;
}

function backupParameterValue(name: string, value: string): string | number {
  return /^(?:S|H)\d$/.test(name) && /^\d+$/.test(value) ? Number(value) : value;
}

function compatibleBackupToState(input: unknown, environment: PortableEnvironment): PanelState {
  const backup = wgEasyBackupSchema.parse(input);
  const defaults = createProtocol(environment.version);
  const allowed = new Set(Object.keys(defaults.values));
  const importedValues: Record<string, string> = {};
  for (const name of protocolParameterNames) {
    const value = backup.server[backupParameterName(name)];
    if (value !== undefined && allowed.has(name)) importedValues[name] = String(value);
  }
  const protocol = createProtocol(environment.version, { ...importedValues, ...environment.protocolOverrides }, defaults);
  return parsePanelState({
    schemaVersion: 1,
    server: { privateKey: backup.server.privateKey, publicKey: backup.server.publicKey },
    interface: {
      address: environment.address,
      dns: environment.dns,
      allowedIps: environment.allowedIps,
      mtu: environment.mtu,
      persistentKeepalive: environment.persistentKeepalive,
    },
    protocol,
    peers: Object.values(backup.clients).map((client) => ({
      id: client.id,
      name: client.name,
      address: client.address,
      privateKey: client.privateKey,
      publicKey: client.publicKey,
      presharedKey: client.preSharedKey,
      enabled: client.enabled,
      createdAt: client.createdAt,
      updatedAt: client.updatedAt ?? client.createdAt,
    })),
    environmentSnapshot: structuredClone(environment),
  });
}

export function parsePanelState(input: unknown): PanelState {
  const state = stateSchema.parse(input);
  networkCidr(state.interface.address);
  const addresses = new Set<string>();
  for (const peer of state.peers) {
    if (!addressBelongsToCidr(peer.address, state.interface.address)) {
      throw new Error(`Адрес ${peer.address} не входит в подсеть интерфейса`);
    }
    if (addresses.has(peer.address)) throw new Error(`Адрес ${peer.address} используется дважды`);
    addresses.add(peer.address);
  }
  return state;
}

function sameEnvironment(left: PortableEnvironment, right: PortableEnvironment): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function applyEnvironment(state: PanelState, env: PortableEnvironment): PanelState {
  const versionChanged = state.protocol.version !== env.version;
  return {
    ...state,
    interface: {
      address: env.address,
      dns: env.dns,
      allowedIps: env.allowedIps,
      mtu: env.mtu,
      persistentKeepalive: env.persistentKeepalive,
    },
    protocol: createProtocol(env.version, env.protocolOverrides, versionChanged ? undefined : state.protocol),
    environmentSnapshot: structuredClone(env),
  };
}

export class StateStore {
  private state!: PanelState;
  private queue: Promise<unknown> = Promise.resolve();
  readonly filePath: string;

  constructor(private readonly dataDir: string, private readonly portableEnvironment: PortableEnvironment) {
    this.filePath = path.join(dataDir, 'state.json');
  }

  async initialize(): Promise<void> {
    await mkdir(this.dataDir, { recursive: true, mode: 0o700 });
    try {
      const parsed = parsePanelState(JSON.parse(await readFile(this.filePath, 'utf8')));
      this.state = sameEnvironment(parsed.environmentSnapshot, this.portableEnvironment)
        ? parsed
        : applyEnvironment(parsed, this.portableEnvironment);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      const server = generateKeyPair();
      this.state = {
        schemaVersion: 1,
        server,
        interface: {
          address: this.portableEnvironment.address,
          dns: this.portableEnvironment.dns,
          allowedIps: this.portableEnvironment.allowedIps,
          mtu: this.portableEnvironment.mtu,
          persistentKeepalive: this.portableEnvironment.persistentKeepalive,
        },
        protocol: createProtocol(this.portableEnvironment.version, this.portableEnvironment.protocolOverrides),
        peers: [],
        environmentSnapshot: structuredClone(this.portableEnvironment),
      };
    }
    await this.persist();
  }

  get(): PanelState {
    return structuredClone(this.state);
  }

  async createPeer(name: string): Promise<Peer> {
    return this.mutate((state) => {
      if (state.peers.some((peer) => peer.name.toLocaleLowerCase() === name.toLocaleLowerCase())) {
        throw new Error('Конфигурация с таким именем уже существует');
      }
      const keys = generateKeyPair();
      const peer: Peer = {
        id: randomUUID(),
        name,
        address: allocateAddress(state.interface.address, state.peers.map((item) => item.address)),
        ...keys,
        presharedKey: generatePresharedKey(),
        enabled: true,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
      state.peers.push(peer);
      return structuredClone(peer);
    });
  }

  async renamePeer(id: string, name: string): Promise<Peer> {
    return this.mutate((state) => {
      const peer = state.peers.find((item) => item.id === id);
      if (!peer) throw new Error('Конфигурация не найдена');
      if (state.peers.some((item) => item.id !== id && item.name.toLocaleLowerCase() === name.toLocaleLowerCase())) {
        throw new Error('Конфигурация с таким именем уже существует');
      }
      peer.name = name;
      peer.updatedAt = new Date().toISOString();
      return structuredClone(peer);
    });
  }

  async togglePeer(id: string): Promise<Peer> {
    return this.mutate((state) => {
      const peer = state.peers.find((item) => item.id === id);
      if (!peer) throw new Error('Конфигурация не найдена');
      peer.enabled = !peer.enabled;
      peer.updatedAt = new Date().toISOString();
      return structuredClone(peer);
    });
  }

  async deletePeer(id: string): Promise<void> {
    return this.mutate((state) => {
      const index = state.peers.findIndex((item) => item.id === id);
      if (index < 0) throw new Error('Конфигурация не найдена');
      state.peers.splice(index, 1);
    });
  }

  findPeer(id: string): Peer | undefined {
    const peer = this.state.peers.find((item) => item.id === id);
    return peer ? structuredClone(peer) : undefined;
  }

  createBackup(): WgEasyBackupFile {
    const state = this.get();
    const server: WgEasyBackupFile['server'] = {
      privateKey: state.server.privateKey,
      publicKey: state.server.publicKey,
      address: state.interface.address.split('/')[0],
    };
    for (const [name, value] of Object.entries(state.protocol.values)) {
      server[backupParameterName(name)] = backupParameterValue(name, value);
    }
    const clients = Object.fromEntries(state.peers.map((peer) => [peer.id, {
      id: peer.id,
      name: peer.name,
      address: peer.address,
      privateKey: peer.privateKey,
      publicKey: peer.publicKey,
      preSharedKey: peer.presharedKey,
      createdAt: peer.createdAt,
      updatedAt: peer.updatedAt ?? peer.createdAt,
      expiredAt: null,
      enabled: peer.enabled,
    }]));
    return { server, clients };
  }

  async restoreBackup(input: unknown): Promise<void> {
    const restored = compatibleBackupToState(input, this.portableEnvironment);
    restored.protocol = createProtocol(restored.protocol.version, restored.protocol.values);
    const nextState = sameEnvironment(restored.environmentSnapshot, this.portableEnvironment)
      ? restored
      : applyEnvironment(restored, this.portableEnvironment);
    await this.mutate((state) => {
      Object.assign(state, nextState);
    });
  }

  async importClusterState(input: unknown): Promise<boolean> {
    const imported = parsePanelState(input);
    imported.protocol = createProtocol(imported.protocol.version, imported.protocol.values);
    const nextState = sameEnvironment(imported.environmentSnapshot, this.portableEnvironment)
      ? imported
      : applyEnvironment(imported, this.portableEnvironment);

    return this.replace(nextState);
  }

  private async mutate<T>(operation: (state: PanelState) => T): Promise<T> {
    const run = async (): Promise<T> => {
      const draft = structuredClone(this.state);
      const result = operation(draft);
      this.state = draft;
      await this.persist();
      return result;
    };
    const result = this.queue.then(run, run);
    this.queue = result.then(() => undefined, () => undefined);
    return result;
  }

  private async replace(nextState: PanelState): Promise<boolean> {
    const run = async (): Promise<boolean> => {
      if (JSON.stringify(this.state) === JSON.stringify(nextState)) return false;
      this.state = structuredClone(nextState);
      await this.persist();
      return true;
    };
    const result = this.queue.then(run, run);
    this.queue = result.then(() => undefined, () => undefined);
    return result;
  }

  private async persist(): Promise<void> {
    const temporaryPath = `${this.filePath}.tmp`;
    await writeFile(temporaryPath, `${JSON.stringify(this.state, null, 2)}\n`, { mode: 0o600 });
    await rename(temporaryPath, this.filePath);
  }
}

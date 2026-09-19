import path from 'node:path';
import { fileURLToPath } from 'node:url';
import cookieParser from 'cookie-parser';
import express, { type NextFunction, type Request, type Response } from 'express';
import QRCode from 'qrcode';
import { z, ZodError } from 'zod';
import type { DashboardData, RuntimeConfig } from '../shared/types.js';
import { AuthService } from './auth.js';
import { ClusterCoordinator } from './cluster.js';
import { peerNameSchema } from './config.js';
import { StateStore } from './store.js';
import { AwgManager, renderClientConfig } from './wireguard.js';

const loginSchema = z.object({ password: z.string().min(1).max(1024) });
const __dirname = path.dirname(fileURLToPath(import.meta.url));

function safeFilename(name: string): string {
  const normalized = name.normalize('NFKD').replace(/[^a-zA-Z0-9_-]+/g, '-').replace(/^-+|-+$/g, '');
  return normalized || 'client';
}

function sameOrigin(request: Request, response: Response, next: NextFunction): void {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method)) return next();
  const origin = request.get('origin');
  if (!origin) return next();
  try {
    if (new URL(origin).host === request.get('host')) return next();
  } catch {
    // Invalid origins are rejected below.
  }
  response.status(403).json({ error: 'Запрос с другого источника отклонён' });
}

export interface ApplicationContext {
  app: express.Express;
  store: StateStore;
  manager: AwgManager;
  cluster: ClusterCoordinator;
}

export async function createApplication(runtime: RuntimeConfig): Promise<ApplicationContext> {
  const store = new StateStore(runtime.dataDir, runtime.portable);
  await store.initialize();
  const manager = new AwgManager(runtime);
  await manager.apply(store.get());
  const cluster = new ClusterCoordinator(runtime.cluster, store, manager);
  const auth = new AuthService(runtime.passwordHash, runtime.sessionTtlMs, runtime.cookieSecure);
  const app = express();

  app.disable('x-powered-by');
  app.use((_request, response, next) => {
    response.set({
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
      'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'",
    });
    next();
  });
  app.use('/api/cluster', cluster.authenticate);
  app.use(express.json({ limit: '5mb' }));
  app.use(cookieParser());
  app.use(sameOrigin);

  app.get('/api/health', (_request, response) => response.json({ status: 'ok' }));
  app.get('/api/session', (request, response) => response.json({ authenticated: auth.isAuthenticated(request) }));
  app.post('/api/auth/login', async (request, response) => {
    const { password } = loginSchema.parse(request.body);
    if (await auth.login(request, response, password)) response.json({ ok: true });
  });
  app.post('/api/auth/logout', (request, response) => {
    auth.logout(request, response);
    response.json({ ok: true });
  });

  app.get('/api/cluster/state', (_request, response) => {
    if (cluster.status().role !== 'primary') return response.status(409).json({ error: 'Состояние выдаёт только primary-узел' });
    return response.json(cluster.snapshot());
  });
  app.put('/api/cluster/state', async (request, response) => {
    if (cluster.status().role !== 'replica') return response.status(409).json({ error: 'Состояние принимает только replica-узел' });
    return response.json(await cluster.receive(request.body));
  });

  app.use('/api', auth.middleware);
  app.use('/api', (_request, response, next) => {
    response.set('Cache-Control', 'no-store');
    next();
  });

  app.get('/api/dashboard', async (_request, response) => {
    const state = store.get();
    const live = await manager.peerViews(state);
    const data: DashboardData = {
      interface: {
        name: runtime.interfaceName,
        endpoint: `${runtime.endpointHost}:${runtime.listenPort}`,
        address: state.interface.address,
        version: state.protocol.version,
        publicKey: state.server.publicKey,
        status: live.status,
      },
      peers: live.peers,
      cluster: cluster.status(),
    };
    response.json(data);
  });

  app.post('/api/peers', cluster.requireWritable, async (request, response) => {
    const { name } = peerNameSchema.parse(request.body);
    const peer = await store.createPeer(name);
    await manager.apply(store.get());
    cluster.notifyLocalChange();
    response.status(201).json({ id: peer.id });
  });

  app.put('/api/peers/:id', cluster.requireWritable, async (request, response) => {
    const { name } = peerNameSchema.parse(request.body);
    await store.renamePeer(String(request.params.id), name);
    await manager.apply(store.get());
    cluster.notifyLocalChange();
    response.json({ ok: true });
  });

  app.post('/api/peers/:id/toggle', cluster.requireWritable, async (request, response) => {
    const peer = await store.togglePeer(String(request.params.id));
    await manager.apply(store.get());
    cluster.notifyLocalChange();
    response.json({ enabled: peer.enabled });
  });

  app.delete('/api/peers/:id', cluster.requireWritable, async (request, response) => {
    await store.deletePeer(String(request.params.id));
    await manager.apply(store.get());
    cluster.notifyLocalChange();
    response.status(204).end();
  });

  app.get('/api/peers/:id/config', (request, response) => {
    const peer = store.findPeer(request.params.id);
    if (!peer) return response.status(404).json({ error: 'Конфигурация не найдена' });
    const config = renderClientConfig(store.get(), runtime, peer.id);
    response.set({
      'Content-Type': 'text/plain; charset=utf-8',
      'Content-Disposition': `attachment; filename="${safeFilename(peer.name)}.conf"`,
    });
    return response.send(config);
  });

  app.get('/api/peers/:id/qr', async (request, response) => {
    const peer = store.findPeer(request.params.id);
    if (!peer) return response.status(404).json({ error: 'Конфигурация не найдена' });
    const svg = await QRCode.toString(renderClientConfig(store.get(), runtime, peer.id), {
      type: 'svg',
      errorCorrectionLevel: 'L',
      margin: 2,
      color: { dark: '#0b0f14', light: '#ffffff' },
    });
    response.type('image/svg+xml').send(svg);
  });

  app.get('/api/backup', (_request, response) => {
    const date = new Date().toISOString().slice(0, 10);
    response.set({
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Disposition': `attachment; filename="awg-panel-${date}.awgbak"`,
    });
    response.send(`${JSON.stringify(store.createBackup(), null, 2)}\n`);
  });

  app.post('/api/backup/restore', cluster.requireWritable, async (request, response) => {
    await store.restoreBackup(request.body);
    await manager.apply(store.get());
    cluster.notifyLocalChange();
    response.json({ ok: true });
  });

  app.use('/api', (_request, response) => response.status(404).json({ error: 'Метод API не найден' }));

  const webRoot = path.resolve(__dirname, '../../web');
  app.use(express.static(webRoot, { index: false, maxAge: '1h' }));
  app.get('*path', (_request, response) => response.sendFile(path.join(webRoot, 'index.html')));

  app.use((error: unknown, _request: Request, response: Response, _next: NextFunction) => {
    if (error instanceof ZodError) {
      response.status(400).json({ error: error.issues[0]?.message ?? 'Некорректные данные' });
      return;
    }
    const message = error instanceof Error ? error.message : 'Внутренняя ошибка';
    const status = /не найдена/i.test(message) ? 404
      : /уже существует|не осталось|конфликтующие снимки/i.test(message) ? 409
        : /контрольная сумма/i.test(message) ? 400
          : 500;
    if (status === 500) console.error(error);
    response.status(status).json({ error: message });
  });

  cluster.start();
  return { app, store, manager, cluster };
}

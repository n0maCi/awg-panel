import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { once } from 'node:events';
import type { Server } from 'node:http';
import bcrypt from 'bcryptjs';
import request from 'supertest';
import { afterEach, describe, expect, it } from 'vitest';
import { createApplication, type ApplicationContext } from '../../src/server/app.js';
import type { ClusterRole, RuntimeConfig } from '../../src/shared/types.js';

const directories: string[] = [];
const contexts: ApplicationContext[] = [];
const servers: Server[] = [];
const secret = 'cluster-test-secret-with-more-than-32-characters';

async function runtime(role: ClusterRole, nodeId: string, peers: string[]): Promise<RuntimeConfig> {
  const dataDir = await mkdtemp(path.join(tmpdir(), 'awg-panel-cluster-test-'));
  directories.push(dataDir);
  return {
    dataDir,
    interfaceName: 'awg0',
    endpointHost: `${nodeId}.example.com`,
    listenPort: 51820,
    outboundDevice: 'eth0',
    uiPort: 51821,
    passwordHash: await bcrypt.hash('secret', 4),
    cookieSecure: false,
    sessionTtlMs: 60_000,
    dryRun: true,
    portable: {
      version: '3.1',
      address: '10.8.0.1/24',
      dns: ['1.1.1.1'],
      allowedIps: ['0.0.0.0/0'],
      mtu: 1420,
      persistentKeepalive: 25,
      protocolOverrides: {},
    },
    cluster: { role, nodeId, secret, peers, syncIntervalMs: 60_000, requestTimeoutMs: 1_000 },
  };
}

afterEach(async () => {
  contexts.splice(0).forEach((context) => context.cluster.stop());
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe('cluster replication', () => {
  it('authenticates nodes, pushes state and makes replicas read-only', async () => {
    const replica = await createApplication(await runtime('replica', 'replica-1', ['http://127.0.0.1:1']));
    contexts.push(replica);
    const replicaServer = replica.app.listen(0, '127.0.0.1');
    servers.push(replicaServer);
    await once(replicaServer, 'listening');
    const address = replicaServer.address();
    if (!address || typeof address === 'string') throw new Error('Не удалось открыть тестовый порт');

    const primary = await createApplication(await runtime('primary', 'primary-1', [`http://127.0.0.1:${address.port}`]));
    contexts.push(primary);
    await primary.cluster.syncNow();
    const staleSnapshot = primary.cluster.snapshot();

    await primary.store.createPeer('Cluster phone');
    await primary.manager.apply(primary.store.get());
    await primary.cluster.syncNow();

    expect(replica.store.get().server.publicKey).toBe(primary.store.get().server.publicKey);
    expect(replica.store.get().peers.map((peer) => peer.name)).toEqual(['Cluster phone']);
    expect(replica.cluster.status()).toMatchObject({ role: 'replica', lastSource: 'primary-1', lastError: null });

    await request(replica.app).put('/api/cluster/state').send(primary.cluster.snapshot()).expect(401);
    await request(replica.app).put('/api/cluster/state').set('Authorization', 'Bearer wrong-secret').send(primary.cluster.snapshot()).expect(401);
    await request(replica.app).put('/api/cluster/state').set('Authorization', `Bearer ${secret}`).send(staleSnapshot)
      .expect(200, { applied: false, digest: staleSnapshot.digest });
    expect(replica.store.get().peers).toHaveLength(1);

    await request(replica.app).put('/api/cluster/state').set('Authorization', `Bearer ${secret}`)
      .send({ ...primary.cluster.snapshot(), digest: '0'.repeat(64) }).expect(400);

    const replicaUser = request.agent(replica.app);
    await replicaUser.post('/api/auth/login').send({ password: 'secret' }).expect(200);
    await replicaUser.post('/api/peers').send({ name: 'Rejected write' }).expect(409);
    const dashboard = await replicaUser.get('/api/dashboard').expect(200);
    expect(dashboard.body.cluster).toMatchObject({ role: 'replica', readOnly: true });
  });
});

import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import bcrypt from 'bcryptjs';
import request from 'supertest';
import { afterEach, describe, expect, it } from 'vitest';
import { createApplication } from '../../src/server/app.js';
import type { RuntimeConfig } from '../../src/shared/types.js';

const directories: string[] = [];

async function runtime(): Promise<RuntimeConfig> {
  const dataDir = await mkdtemp(path.join(tmpdir(), 'awg-panel-test-'));
  directories.push(dataDir);
  const portable = {
    version: '2.0' as const,
    address: '10.8.0.1/24',
    dns: ['1.1.1.1'],
    allowedIps: ['0.0.0.0/0'],
    mtu: 1420,
    persistentKeepalive: 25,
    protocolOverrides: {},
  };
  return {
    dataDir, interfaceName: 'awg0', endpointHost: 'vpn.example.com', listenPort: 51820,
    outboundDevice: 'eth0', uiPort: 51821, passwordHash: await bcrypt.hash('secret', 4),
    cookieSecure: false, sessionTtlMs: 60_000, dryRun: true, portable,
    cluster: { role: 'standalone', nodeId: 'test-node', secret: '', peers: [], syncIntervalMs: 15_000, requestTimeoutMs: 1_000 },
  };
}

afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe('panel API', () => {
  it('protects API and supports login, create and toggle', async () => {
    const { app } = await createApplication(await runtime());
    const agent = request.agent(app);

    await agent.get('/api/dashboard').expect(401);
    await agent.post('/api/auth/login').send({ password: 'wrong' }).expect(401);
    await agent.post('/api/auth/login').send({ password: 'secret' }).expect(200);
    await agent.post('/api/peers').send({ name: 'bad\nPostUp = touch /tmp/x' }).expect(400);
    const created = await agent.post('/api/peers').send({ name: 'Laptop' }).expect(201);
    const first = await agent.get('/api/dashboard').expect(200);
    expect(first.body.peers).toHaveLength(1);
    expect(first.body.peers[0].enabled).toBe(true);

    await agent.post(`/api/peers/${created.body.id}/toggle`).expect(200, { enabled: false });
    const config = await agent.get(`/api/peers/${created.body.id}/config`).expect(200);
    expect(config.text).toContain('Endpoint = vpn.example.com:51820');
  });

  it('exports and restores a portable backup', async () => {
    const firstRuntime = await runtime();
    const first = await createApplication(firstRuntime);
    const firstAgent = request.agent(first.app);
    await firstAgent.post('/api/auth/login').send({ password: 'secret' });
    await firstAgent.post('/api/peers').send({ name: 'Tablet' }).expect(201);
    const backupResponse = await firstAgent.get('/api/backup').expect(200);
    expect(backupResponse.headers['content-disposition']).toContain('filename="wg0.json"');
    const backup = JSON.parse(backupResponse.text);
    expect(Object.keys(backup).sort()).toEqual(['clients', 'server']);
    expect(backup.server).toMatchObject({ address: '10.8.0.1' });
    expect(Object.values(backup.clients)).toHaveLength(1);
    expect(Object.values(backup.clients)[0]).toMatchObject({ name: 'Tablet', expiredAt: null, enabled: true });
    expect(Object.values(backup.clients)[0]).toHaveProperty('preSharedKey');

    const secondRuntime = await runtime();
    secondRuntime.endpointHost = 'new.example.com';
    const second = await createApplication(secondRuntime);
    const secondAgent = request.agent(second.app);
    await secondAgent.post('/api/auth/login').send({ password: 'secret' });
    await secondAgent.post('/api/backup/restore').send(backup).expect(200);
    const dashboard = await secondAgent.get('/api/dashboard').expect(200);
    const config = await secondAgent.get(`/api/peers/${dashboard.body.peers[0].id}/config`).expect(200);
    expect(config.text).toContain('Endpoint = new.example.com:51820');
  });
});

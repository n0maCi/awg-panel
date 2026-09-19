import { describe, expect, it } from 'vitest';
import { loadConfig } from '../../src/server/config.js';

const base = {
  PASSWORD_HASH: '$2b$12$12345678901234567890123456789012345678901234567890123',
  AWG_HOST: 'vpn.example.com',
};

describe('environment config', () => {
  it('accepts the short version 2 alias', () => {
    const config = loadConfig({ ...base, AWG_VERSION: '2' });
    expect(config.portable.version).toBe('2.0');
  });

  it('parses interface variables and protocol overrides', () => {
    const config = loadConfig({
      ...base,
      AWG_ADDRESS: '10.20.30.1/24',
      AWG_DNS: '9.9.9.9, 1.1.1.1',
      AWG_MTU: '1380',
      AWG_JC: '7',
    });
    expect(config.portable.address).toBe('10.20.30.1/24');
    expect(config.portable.dns).toEqual(['9.9.9.9', '1.1.1.1']);
    expect(config.portable.mtu).toBe(1380);
    expect(config.portable.protocolOverrides.Jc).toBe('7');
  });

  it('does not allow startup with a plain-text password', () => {
    expect(() => loadConfig({ ...base, PASSWORD_HASH: 'password' })).toThrow(/bcrypt/);
  });

  it('parses cluster settings and requires a strong shared secret', () => {
    const config = loadConfig({
      ...base,
      CLUSTER_ROLE: 'primary',
      CLUSTER_NODE_ID: 'vpn-1',
      CLUSTER_SECRET: 'a-very-long-shared-cluster-secret-123456',
      CLUSTER_PEERS: 'https://vpn-2.example.com, http://10.0.0.3:51821/',
      CLUSTER_SYNC_INTERVAL_SECONDS: '30',
    });
    expect(config.cluster).toMatchObject({
      role: 'primary',
      nodeId: 'vpn-1',
      peers: ['https://vpn-2.example.com', 'http://10.0.0.3:51821'],
      syncIntervalMs: 30_000,
    });
    expect(() => loadConfig({ ...base, CLUSTER_ROLE: 'replica', CLUSTER_PEERS: 'http://vpn-1:51821', CLUSTER_SECRET: 'short' }))
      .toThrow(/CLUSTER_SECRET/);
  });
});

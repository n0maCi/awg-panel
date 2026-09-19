import { describe, expect, it } from 'vitest';
import type { PanelState, RuntimeConfig } from '../../src/shared/types.js';
import { createProtocol } from '../../src/server/protocol.js';
import { generateKeyPair, generatePresharedKey } from '../../src/server/keys.js';
import { renderClientConfig, renderServerConfig } from '../../src/server/wireguard.js';

function fixture(): { state: PanelState; runtime: RuntimeConfig } {
  const server = generateKeyPair();
  const peer = generateKeyPair();
  const portable = {
    version: '3.1' as const,
    address: '10.8.0.1/24',
    dns: ['1.1.1.1'],
    allowedIps: ['0.0.0.0/0'],
    mtu: 1420,
    persistentKeepalive: 25,
    protocolOverrides: {},
  };
  return {
    state: {
      schemaVersion: 1,
      server,
      interface: portable,
      protocol: createProtocol('3.1'),
      peers: [{
        id: '22aebf0a-56a6-49cf-ad2a-a54b9651cd23', name: 'Phone', address: '10.8.0.2',
        ...peer, presharedKey: generatePresharedKey(), enabled: true, createdAt: new Date().toISOString(),
      }],
      environmentSnapshot: portable,
    },
    runtime: {
      dataDir: '/tmp/awg-panel-test', interfaceName: 'awg0', endpointHost: 'old.example.com',
      listenPort: 51820, outboundDevice: 'eth0', uiPort: 51821,
      passwordHash: '$2b$12$12345678901234567890123456789012345678901234567890123',
      cookieSecure: false, sessionTtlMs: 1000, dryRun: true, portable,
      cluster: { role: 'standalone', nodeId: 'test-node', secret: '', peers: [], syncIntervalMs: 15_000, requestTimeoutMs: 1_000 },
    },
  };
}

describe('AWG config rendering', () => {
  it('omits disabled peers from the server interface', () => {
    const { state, runtime } = fixture();
    state.peers[0].enabled = false;
    expect(renderServerConfig(state, runtime)).not.toContain('[Peer]');
  });

  it('uses the current deployment host in restored client configs', () => {
    const { state, runtime } = fixture();
    runtime.endpointHost = 'new.example.com';
    const config = renderClientConfig(state, runtime, state.peers[0].id);
    expect(config).toContain('Endpoint = new.example.com:51820');
    expect(config).not.toContain('old.example.com');
    expect(config).toContain('HeaderProtectionKey = ');
  });
});

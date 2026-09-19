import { z } from 'zod';
import type { ClusterRole, PortableEnvironment, ProtocolVersion, RuntimeConfig } from '../shared/types.js';

const VERSION_ALIASES: Record<string, ProtocolVersion> = {
  '1.5': '1.5',
  '2': '2.0',
  '2.0': '2.0',
  '3.1': '3.1',
};

export const PROTOCOL_ENV_KEYS: Record<string, string> = {
  AWG_JC: 'Jc',
  AWG_JMIN: 'Jmin',
  AWG_JMAX: 'Jmax',
  AWG_S1: 'S1',
  AWG_S2: 'S2',
  AWG_S3: 'S3',
  AWG_S4: 'S4',
  AWG_H1: 'H1',
  AWG_H2: 'H2',
  AWG_H3: 'H3',
  AWG_H4: 'H4',
  AWG_I1: 'I1',
  AWG_I2: 'I2',
  AWG_I3: 'I3',
  AWG_I4: 'I4',
  AWG_I5: 'I5',
  AWG_HEADER_PROTECTION_KEY: 'HeaderProtectionKey',
  AWG_CONTENT_PADDING_ADDITION: 'ContentPaddingAddition',
  AWG_REKEY_AFTER_TIME: 'RekeyAfterTime',
  AWG_REKEY_TIMEOUT: 'RekeyTimeout',
  AWG_REJECT_AFTER_TIME: 'RejectAfterTime',
  AWG_KEEPALIVE_TIMEOUT: 'KeepaliveTimeout',
  AWG_MAX_HANDSHAKE_ATTEMPTS: 'MaxHandshakeAttempts',
  AWG_RANDOM_TRAILERS: 'RandomTrailers',
  AWG_DISABLE_COOKIES: 'DisableCookies',
};

export const SAFE_PEER_NAME = /^[\p{L}\p{N} _.-]+$/u;

function integer(value: string | undefined, fallback: number, name: string, min = 1, max = 65_535): number {
  const parsed = Number(value ?? fallback);
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(`${name} должен быть целым числом от ${min} до ${max}`);
  }
  return parsed;
}

function csv(value: string | undefined, fallback: string): string[] {
  const items = (value ?? fallback)
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
  if (items.some((item) => /[\r\n]/.test(item) || item.length > 256)) {
    throw new Error('Список содержит недопустимое значение');
  }
  return items;
}

function boolean(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  if (['1', 'true', 'yes', 'on'].includes(value.toLowerCase())) return true;
  if (['0', 'false', 'no', 'off'].includes(value.toLowerCase())) return false;
  throw new Error(`Ожидалось логическое значение, получено: ${value}`);
}

function parseVersion(value = '3.1'): ProtocolVersion {
  const parsed = VERSION_ALIASES[value];
  if (!parsed) throw new Error('AWG_VERSION должен быть одним из: 1.5, 2, 2.0, 3.1');
  return parsed;
}

function validateInterfaceAddress(address: string): string {
  const match = address.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/);
  if (!match || match.slice(1, 5).some((part) => Number(part) > 255)) {
    throw new Error('AWG_ADDRESS должен быть IPv4 CIDR, например 10.8.0.1/24');
  }
  const prefix = Number(match[5]);
  if (prefix < 8 || prefix > 30) {
    throw new Error('Префикс AWG_ADDRESS должен быть от /8 до /30');
  }
  return address;
}

function clusterRole(value = 'standalone'): ClusterRole {
  if (value === 'standalone' || value === 'primary' || value === 'replica') return value;
  throw new Error('CLUSTER_ROLE должен быть одним из: standalone, primary, replica');
}

function clusterPeers(value: string | undefined): string[] {
  const peers = (value ?? '').split(',').map((item) => item.trim()).filter(Boolean).map((item) => {
    let url: URL;
    try { url = new URL(item); } catch { throw new Error(`Некорректный URL узла кластера: ${item}`); }
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) {
      throw new Error(`URL узла кластера должен использовать HTTP(S) без credentials, query и fragment: ${item}`);
    }
    return `${url.origin}${url.pathname.replace(/\/+$/, '')}`;
  });
  return [...new Set(peers)];
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): RuntimeConfig {
  const endpointHost = (env.AWG_HOST ?? '').trim();
  if (!endpointHost) throw new Error('Не задан AWG_HOST');
  if (endpointHost.length > 253 || !/^[a-zA-Z0-9._:[\]-]+$/.test(endpointHost)) {
    throw new Error('AWG_HOST должен быть IP-адресом или DNS-именем');
  }

  const passwordHash = (env.PASSWORD_HASH ?? '').trim();
  const passwordMatch = passwordHash.match(/^\$2[aby]\$(\d{2})\$[./A-Za-z0-9]{53}$/);
  if (!passwordMatch || Number(passwordMatch[1]) < 10 || Number(passwordMatch[1]) > 15) {
    throw new Error('PASSWORD_HASH должен содержать bcrypt-хеш');
  }

  const protocolOverrides: Record<string, string> = {};
  for (const [envName, configName] of Object.entries(PROTOCOL_ENV_KEYS)) {
    const value = env[envName]?.trim();
    if (value) {
      if (value.length > 4096 || /[\r\n]/.test(value)) throw new Error(`${envName} содержит недопустимое значение`);
      protocolOverrides[configName] = value;
    }
  }

  const portable: PortableEnvironment = {
    version: parseVersion(env.AWG_VERSION),
    address: validateInterfaceAddress(env.AWG_ADDRESS ?? '10.8.0.1/24'),
    dns: csv(env.AWG_DNS, '1.1.1.1,1.0.0.1'),
    allowedIps: csv(env.AWG_ALLOWED_IPS, '0.0.0.0/0,::/0'),
    mtu: integer(env.AWG_MTU, 1420, 'AWG_MTU', 576, 9000),
    persistentKeepalive: integer(env.AWG_PERSISTENT_KEEPALIVE, 25, 'AWG_PERSISTENT_KEEPALIVE', 0, 65_535),
    protocolOverrides,
  };

  const interfaceName = env.AWG_INTERFACE?.trim() || 'awg0';
  if (!/^[a-zA-Z0-9_=+.-]{1,15}$/.test(interfaceName)) {
    throw new Error('Некорректное имя AWG_INTERFACE');
  }

  const outboundDevice = env.AWG_DEVICE?.trim() || 'eth0';
  if (!/^[a-zA-Z0-9_.:-]{1,32}$/.test(outboundDevice)) {
    throw new Error('Некорректное имя AWG_DEVICE');
  }

  const role = clusterRole(env.CLUSTER_ROLE?.trim());
  const peers = clusterPeers(env.CLUSTER_PEERS);
  const nodeId = env.CLUSTER_NODE_ID?.trim() || endpointHost;
  if (!/^[a-zA-Z0-9_.:-]{1,128}$/.test(nodeId)) {
    throw new Error('CLUSTER_NODE_ID должен содержать 1–128 букв, цифр, точек, двоеточий, дефисов или подчёркиваний');
  }
  const clusterSecret = env.CLUSTER_SECRET?.trim() || '';
  if (role !== 'standalone') {
    if (clusterSecret.length < 32 || clusterSecret.length > 512 || /[\r\n]/.test(clusterSecret)) {
      throw new Error('CLUSTER_SECRET должен содержать от 32 до 512 символов');
    }
    if (peers.length === 0) throw new Error('Для режима кластера задайте CLUSTER_PEERS');
  }

  return {
    dataDir: env.DATA_DIR?.trim() || '/data',
    interfaceName,
    endpointHost,
    listenPort: integer(env.AWG_PORT, 51820, 'AWG_PORT'),
    outboundDevice,
    uiPort: integer(env.UI_PORT, 51821, 'UI_PORT'),
    passwordHash,
    cookieSecure: boolean(env.COOKIE_SECURE, false),
    sessionTtlMs: integer(env.SESSION_TTL_HOURS, 12, 'SESSION_TTL_HOURS', 1, 720) * 60 * 60 * 1000,
    dryRun: boolean(env.AWG_DRY_RUN, false),
    portable,
    cluster: {
      role,
      nodeId,
      secret: clusterSecret,
      peers,
      syncIntervalMs: integer(env.CLUSTER_SYNC_INTERVAL_SECONDS, 15, 'CLUSTER_SYNC_INTERVAL_SECONDS', 2, 3600) * 1000,
      requestTimeoutMs: integer(env.CLUSTER_REQUEST_TIMEOUT_SECONDS, 5, 'CLUSTER_REQUEST_TIMEOUT_SECONDS', 1, 60) * 1000,
    },
  };
}

export const peerNameSchema = z.object({
  name: z.string().trim().min(1, 'Введите имя').max(64, 'Не более 64 символов')
    .regex(SAFE_PEER_NAME, 'Используйте буквы, цифры, пробел, точку, дефис или подчёркивание'),
});

export type ProtocolVersion = '1.5' | '2.0' | '3.1';
export type ClusterRole = 'standalone' | 'primary' | 'replica';

export interface InterfaceSettings {
  address: string;
  dns: string[];
  allowedIps: string[];
  mtu: number;
  persistentKeepalive: number;
}

export interface ProtocolSettings {
  version: ProtocolVersion;
  values: Record<string, string>;
}

export interface Peer {
  id: string;
  name: string;
  address: string;
  privateKey: string;
  publicKey: string;
  presharedKey: string;
  enabled: boolean;
  createdAt: string;
  updatedAt?: string;
}

export interface PanelState {
  schemaVersion: 1;
  server: {
    privateKey: string;
    publicKey: string;
  };
  interface: InterfaceSettings;
  protocol: ProtocolSettings;
  peers: Peer[];
  environmentSnapshot: PortableEnvironment;
}

export interface PortableEnvironment {
  version: ProtocolVersion;
  address: string;
  dns: string[];
  allowedIps: string[];
  mtu: number;
  persistentKeepalive: number;
  protocolOverrides: Record<string, string>;
}

export interface RuntimeConfig {
  dataDir: string;
  interfaceName: string;
  endpointHost: string;
  listenPort: number;
  outboundDevice: string;
  uiPort: number;
  passwordHash: string;
  cookieSecure: boolean;
  sessionTtlMs: number;
  dryRun: boolean;
  portable: PortableEnvironment;
  cluster: ClusterRuntimeConfig;
}

export interface ClusterRuntimeConfig {
  role: ClusterRole;
  nodeId: string;
  secret: string;
  peers: string[];
  syncIntervalMs: number;
  requestTimeoutMs: number;
}

export interface ClusterSnapshot {
  format: 'awg-panel-cluster-state';
  version: 1;
  sourceNode: string;
  createdAt: string;
  digest: string;
  state: PanelState;
}

export interface ClusterStatus {
  role: ClusterRole;
  nodeId: string;
  peerCount: number;
  readOnly: boolean;
  lastSyncAt: string | null;
  lastSource: string | null;
  lastError: string | null;
}

export interface PeerView {
  id: string;
  name: string;
  address: string;
  enabled: boolean;
  createdAt: string;
  online: boolean;
  latestHandshakeAt: string | null;
  endpoint: string | null;
  receivedBytes: number;
  sentBytes: number;
}

export interface DashboardData {
  interface: {
    name: string;
    endpoint: string;
    address: string;
    version: ProtocolVersion;
    publicKey: string;
    status: 'up' | 'down' | 'unknown';
  };
  peers: PeerView[];
  cluster: ClusterStatus;
}

export interface WgEasyBackupClient {
  id: string;
  name: string;
  address: string;
  privateKey: string;
  publicKey: string;
  preSharedKey: string;
  createdAt: string;
  updatedAt: string;
  expiredAt: string | null;
  enabled: boolean;
}

export interface WgEasyBackupFile {
  server: {
    privateKey: string;
    publicKey: string;
    address: string;
    [parameter: string]: string | number;
  };
  clients: Record<string, WgEasyBackupClient>;
}

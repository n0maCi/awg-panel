import { randomInt } from 'node:crypto';
import type { ProtocolSettings, ProtocolVersion } from '../shared/types.js';
import { generatePrivateKey } from './keys.js';

const order = [
  'Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4',
  'H1', 'H2', 'H3', 'H4', 'I1', 'I2', 'I3', 'I4', 'I5',
  'HeaderProtectionKey', 'ContentPaddingAddition', 'RekeyAfterTime',
  'RekeyTimeout', 'RejectAfterTime', 'KeepaliveTimeout',
  'MaxHandshakeAttempts', 'RandomTrailers', 'DisableCookies',
];

const allowedByVersion: Record<ProtocolVersion, Set<string>> = {
  '1.5': new Set(['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'H1', 'H2', 'H3', 'H4']),
  '2.0': new Set(['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4', 'I1', 'I2', 'I3', 'I4', 'I5']),
  '3.1': new Set(order),
};

function int(min: number, max: number): string {
  return String(randomInt(min, max + 1));
}

function range(start: number, width = 80_000_000): string {
  return `${start}-${start + width - 1}`;
}

function handshakePaddings(): { S1: string; S2: string } {
  const S1 = int(20, 120);
  let S2 = int(20, 120);
  while (Number(S1) + 56 === Number(S2)) S2 = int(20, 120);
  return { S1, S2 };
}

function numericRange(name: string, value: string, min: number, max: number): [number, number] {
  const match = value.match(/^(\d+)(?:-(\d+))?$/);
  if (!match) throw new Error(`${name} должен быть числом или диапазоном`);
  const left = Number(match[1]);
  const right = Number(match[2] ?? match[1]);
  if (!Number.isSafeInteger(left) || !Number.isSafeInteger(right) || left < min || right > max || left > right) {
    throw new Error(`Некорректное значение ${name}`);
  }
  return [left, right];
}

function validateValues(version: ProtocolVersion, values: Record<string, string>): void {
  const scalarLimits: Record<string, [number, number]> = {
    Jc: [0, 128], Jmin: [0, 1280], Jmax: [0, 1280],
    S1: [0, 1132], S2: [0, 1188], S3: [0, 64], S4: [0, 32],
  };
  for (const [name, limits] of Object.entries(scalarLimits)) {
    if (values[name] !== undefined) {
      const [left, right] = numericRange(name, values[name], limits[0], limits[1]);
      if (left !== right) throw new Error(`${name} не поддерживает диапазон`);
    }
  }
  if (Number(values.Jmin) > Number(values.Jmax)) throw new Error('Jmin должен быть меньше или равен Jmax');
  if (Number(values.S1) + 56 === Number(values.S2)) throw new Error('S1 и S2 создают пакеты одинакового размера');

  const headerRanges = ['H1', 'H2', 'H3', 'H4'].map((name) => ({
    name,
    range: numericRange(name, values[name], 0, 0xffff_ffff),
  }));
  for (let left = 0; left < headerRanges.length; left += 1) {
    for (let right = left + 1; right < headerRanges.length; right += 1) {
      const a = headerRanges[left];
      const b = headerRanges[right];
      if (a.range[0] <= b.range[1] && b.range[0] <= a.range[1]) {
        throw new Error(`${a.name} и ${b.name} не должны пересекаться`);
      }
    }
  }

  if (version === '3.1') {
    if (!/^[A-Za-z0-9+/]{43}=$/.test(values.HeaderProtectionKey ?? '')) {
      throw new Error('HeaderProtectionKey должен быть 32-байтовым base64-ключом');
    }
    const ranges: Record<string, [number, number]> = {
      ContentPaddingAddition: [0, 1280], RekeyAfterTime: [0, 86_400],
      RekeyTimeout: [0, 3600], RejectAfterTime: [0, 86_400],
      KeepaliveTimeout: [0, 3600], MaxHandshakeAttempts: [0, 1000],
    };
    for (const [name, limits] of Object.entries(ranges)) {
      numericRange(name, values[name], limits[0], limits[1]);
    }
    for (const name of ['RandomTrailers', 'DisableCookies']) {
      if (!['on', 'off'].includes(values[name])) throw new Error(`${name} должен быть on или off`);
    }
  }
}

function defaults(version: ProtocolVersion): Record<string, string> {
  if (version === '1.5') {
    return {
      Jc: int(4, 8), Jmin: '40', Jmax: '120', ...handshakePaddings(),
      H1: '129', H2: '130', H3: '131', H4: '132',
    };
  }

  const base = {
    Jc: int(4, 8), Jmin: '40', Jmax: '120', ...handshakePaddings(),
    S3: int(20, 55), S4: int(12, 20),
    H1: range(5), H2: range(80_000_005), H3: range(160_000_005), H4: range(240_000_005),
    I1: '<b 0x16030100><r 32>',
  };

  if (version === '2.0') return base;

  return {
    ...base,
    ...handshakePaddings(), S3: int(20, 55), S4: int(12, 20),
    H1: '1', H2: '2', H3: '3', H4: '4',
    HeaderProtectionKey: generatePrivateKey(),
    ContentPaddingAddition: '16-64',
    RekeyAfterTime: '3000-4000',
    RekeyTimeout: '5-10',
    RejectAfterTime: '180-190',
    KeepaliveTimeout: '8-15',
    MaxHandshakeAttempts: '15-20',
    RandomTrailers: 'on',
    DisableCookies: 'off',
  };
}

export function createProtocol(
  version: ProtocolVersion,
  overrides: Record<string, string> = {},
  existing?: ProtocolSettings,
): ProtocolSettings {
  const values = existing?.version === version ? { ...existing.values } : defaults(version);
  const allowed = allowedByVersion[version];

  for (const [key, value] of Object.entries(overrides)) {
    if (!allowed.has(key)) {
      throw new Error(`${key} не поддерживается протоколом AWG ${version}`);
    }
    values[key] = value;
  }

  for (const key of Object.keys(values)) {
    if (!allowed.has(key)) delete values[key];
  }

  if (version === '3.1') {
    for (const key of ['S1', 'S2', 'S3', 'S4']) {
      const value = Number(values[key]);
      if (!Number.isInteger(value) || value < 12) {
        throw new Error(`${key} должен быть не меньше 12 для AWG 3.1`);
      }
    }
  }

  validateValues(version, values);

  return { version, values };
}

export function protocolLines(protocol: ProtocolSettings): string[] {
  return order
    .filter((key) => protocol.values[key] !== undefined && protocol.values[key] !== '')
    .map((key) => `${key} = ${protocol.values[key]}`);
}

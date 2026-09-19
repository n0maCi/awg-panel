import { describe, expect, it } from 'vitest';
import { createProtocol } from '../../src/server/protocol.js';

describe('protocol profiles', () => {
  it('creates a legacy 1.5 profile without 2.0 fields', () => {
    const protocol = createProtocol('1.5');
    expect(protocol.values).toHaveProperty('S1');
    expect(protocol.values).not.toHaveProperty('S3');
    expect(protocol.values).not.toHaveProperty('HeaderProtectionKey');
  });

  it('creates a 2.0 profile with ranges and signature packet', () => {
    const protocol = createProtocol('2.0');
    expect(protocol.values.S3).toBeDefined();
    expect(protocol.values.H1).toMatch(/^\d+-\d+$/);
    expect(protocol.values.I1).toContain('<b 0x');
    expect(protocol.values).not.toHaveProperty('HeaderProtectionKey');
  });

  it('creates a 3.1 profile with header protection and flags', () => {
    const protocol = createProtocol('3.1');
    expect(Buffer.from(protocol.values.HeaderProtectionKey, 'base64')).toHaveLength(32);
    expect(protocol.values.RandomTrailers).toBe('on');
    expect(protocol.values.ContentPaddingAddition).toBe('16-64');
    for (const name of ['S1', 'S2', 'S3', 'S4']) expect(Number(protocol.values[name])).toBeGreaterThanOrEqual(12);
  });

  it('rejects fields unavailable in the selected version', () => {
    expect(() => createProtocol('1.5', { S4: '16' })).toThrow(/не поддерживается/);
  });

  it('rejects overlapping header ranges', () => {
    expect(() => createProtocol('2.0', { H1: '10-20', H2: '20-30' })).toThrow(/не должны пересекаться/);
  });
});

import {
  createPrivateKey,
  createPublicKey,
  randomBytes,
} from 'node:crypto';

const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');
const X25519_SPKI_PREFIX_LENGTH = 12;

export interface KeyPair {
  privateKey: string;
  publicKey: string;
}

export function generatePrivateKey(): string {
  const key = randomBytes(32);
  key[0] &= 248;
  key[31] &= 127;
  key[31] |= 64;
  return key.toString('base64');
}

export function derivePublicKey(privateKey: string): string {
  const raw = Buffer.from(privateKey, 'base64');
  if (raw.length !== 32) {
    throw new Error('Некорректная длина приватного ключа');
  }

  const key = createPrivateKey({
    key: Buffer.concat([X25519_PKCS8_PREFIX, raw]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicDer = createPublicKey(key).export({ format: 'der', type: 'spki' });
  return publicDer.subarray(X25519_SPKI_PREFIX_LENGTH).toString('base64');
}

export function generateKeyPair(): KeyPair {
  const privateKey = generatePrivateKey();
  return { privateKey, publicKey: derivePublicKey(privateKey) };
}

export function generatePresharedKey(): string {
  return randomBytes(32).toString('base64');
}

import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { decodePublicKey } from './leaf.js';

// Configure synchronous SHA-512 for @noble/ed25519
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

export interface Ed25519Keypair {
  secretKey: Uint8Array;
  secretKeyHex: string;
  publicKey: Uint8Array;
  publicKeyHex: string;
}

/**
 * Generates a new random Ed25519 keypair.
 */
export function generateEd25519Keypair(): Ed25519Keypair {
  const secretKey = ed.utils.randomPrivateKey();
  const publicKey = ed.getPublicKey(secretKey);
  return {
    secretKey,
    secretKeyHex: Buffer.from(secretKey).toString('hex'),
    publicKey,
    publicKeyHex: Buffer.from(publicKey).toString('hex'),
  };
}

/**
 * Derives public key from 32-byte secret seed.
 */
export function getPublicKeyFromSecret(secretKey: Uint8Array | string): Uint8Array {
  const raw =
    typeof secretKey === 'string'
      ? Buffer.from(secretKey.startsWith('0x') ? secretKey.slice(2) : secretKey, 'hex')
      : secretKey;
  if (raw.length !== 32) {
    throw new Error(`Secret key must be 32 bytes (got ${raw.length})`);
  }
  return ed.getPublicKey(raw);
}

/**
 * Signs a message (or leaf hash) using Ed25519.
 * Returns 64-byte signature.
 */
export function sign(message: Uint8Array, secretKey: Uint8Array | string): Uint8Array {
  const rawSecret =
    typeof secretKey === 'string'
      ? Buffer.from(secretKey.startsWith('0x') ? secretKey.slice(2) : secretKey, 'hex')
      : secretKey;
  return ed.sign(message, rawSecret);
}

/**
 * Verifies an Ed25519 signature against a message and public key.
 */
export function verifySignature(
  signature: Uint8Array | string,
  message: Uint8Array | string,
  publicKey: Uint8Array | string
): boolean {
  try {
    const rawSig =
      typeof signature === 'string'
        ? Buffer.from(signature.startsWith('0x') ? signature.slice(2) : signature, 'hex')
        : signature;

    const rawMsg =
      typeof message === 'string'
        ? Buffer.from(message.startsWith('0x') ? message.slice(2) : message, 'hex')
        : message;

    const rawPub = decodePublicKey(publicKey);

    if (rawSig.length !== 64) {
      return false;
    }

    return ed.verify(rawSig, rawMsg, rawPub);
  } catch {
    return false;
  }
}

import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  generateEd25519Keypair,
  getPublicKeyFromSecret,
  sign,
  verifySignature,
} from '../src/index.js';

describe('PB1 Ed25519 Signatures', () => {
  it('generates valid keypairs and derives public key from secret seed', () => {
    const kp = generateEd25519Keypair();
    assert.strictEqual(kp.secretKey.length, 32);
    assert.strictEqual(kp.publicKey.length, 32);

    const derivedPub = getPublicKeyFromSecret(kp.secretKey);
    assert.deepStrictEqual(derivedPub, kp.publicKey);
  });

  it('signs and verifies messages correctly', () => {
    const kp = generateEd25519Keypair();
    const message = new TextEncoder().encode('Proofbook audit commitment');

    const signature = sign(message, kp.secretKey);
    assert.strictEqual(signature.length, 64);

    const valid = verifySignature(signature, message, kp.publicKey);
    assert.strictEqual(valid, true);

    // Tampered message
    const tampered = new TextEncoder().encode('Proofbook audit commitment TAMPERED');
    assert.strictEqual(verifySignature(signature, tampered, kp.publicKey), false);

    // Tampered signature
    const tamperedSig = new Uint8Array(signature);
    tamperedSig[0] ^= 0xff;
    assert.strictEqual(verifySignature(tamperedSig, message, kp.publicKey), false);
  });
});

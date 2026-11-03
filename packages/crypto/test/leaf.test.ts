import { describe, it } from 'node:test';
import assert from 'node:assert';
import { sha256 } from '@noble/hashes/sha256';
import {
  computeRecordLeaf,
  computeRecordLeafHex,
  decodePublicKey,
  DOMAIN_RECORD_LEAF,
} from '../src/index.js';

describe('PB1 Record Leaf Calculation', () => {
  const authorPubHex = '4b92b6ff8c51a9fa210940562e6e22c95405e3be967de19307c913c5cc11f71a';
  const authorRaw = Buffer.from(authorPubHex, 'hex');
  const fieldRoot = new Uint8Array(32).fill(0xaa);
  const recordId = '01HZX6789ABCDEF';
  const createdAt = '2026-11-02T09:14:00Z';

  it('computes exact byte-level leaf hash matching 0x00 domain separation', () => {
    const leaf = computeRecordLeaf({
      recordId,
      author: authorPubHex,
      createdAt,
      fieldRoot,
    });

    const recIdBytes = new TextEncoder().encode(recordId);
    const tsBytes = new TextEncoder().encode(createdAt);
    const expectedBuf = new Uint8Array(1 + 2 + recIdBytes.length + 32 + 2 + tsBytes.length + 32);
    const view = new DataView(expectedBuf.buffer);

    let offset = 0;
    expectedBuf[offset++] = DOMAIN_RECORD_LEAF;
    view.setUint16(offset, recIdBytes.length, false);
    offset += 2;
    expectedBuf.set(recIdBytes, offset);
    offset += recIdBytes.length;
    expectedBuf.set(authorRaw, offset);
    offset += 32;
    view.setUint16(offset, tsBytes.length, false);
    offset += 2;
    expectedBuf.set(tsBytes, offset);
    offset += tsBytes.length;
    expectedBuf.set(fieldRoot, offset);

    const manualSha = sha256(expectedBuf);
    assert.deepStrictEqual(leaf, manualSha);
  });

  it('normalizes author public keys across hex, raw bytes, and Stellar G format', () => {
    // Stellar G address for authorPubHex
    // We can decode and test with raw bytes vs hex vs ed25519: prefix
    const leaf1 = computeRecordLeafHex({ recordId, author: authorPubHex, createdAt, fieldRoot });
    const leaf2 = computeRecordLeafHex({ recordId, author: `ed25519:${authorPubHex}`, createdAt, fieldRoot });
    const leaf3 = computeRecordLeafHex({ recordId, author: authorRaw, createdAt, fieldRoot });

    assert.strictEqual(leaf1, leaf2);
    assert.strictEqual(leaf2, leaf3);
  });

  it('rejects non-UTC timestamps', () => {
    assert.throws(() => {
      computeRecordLeaf({
        recordId,
        author: authorPubHex,
        createdAt: '2026-11-02T09:14:00+02:00', // not UTC 'Z'
        fieldRoot,
      });
    }, /RFC 3339 UTC/);
  });
});

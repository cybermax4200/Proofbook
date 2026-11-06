import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {
  generateSalt,
  computeFieldRoot,
  computeRecordLeafHex,
  generateEd25519Keypair,
  sign,
  buildMerkleTree,
  getMerkleProof,
} from '@proofbook/crypto';
import { main } from '../src/index.js';

function createTempBundle(tamper = false): string {
  const authorKeys = generateEd25519Keypair();
  const approverKeys = generateEd25519Keypair();

  const fields = {
    amount: tamper ? '9999.00' : '1250.00',
    currency: 'USD',
  };

  const salts = {
    amount: Buffer.from(generateSalt()).toString('hex'),
    currency: Buffer.from(generateSalt()).toString('hex'),
  };

  const fieldRootResult = computeFieldRoot(
    { amount: '1250.00', currency: 'USD' },
    salts
  );

  const leafHex = computeRecordLeafHex({
    recordId: '01HZX6789ABCDEF0123456789A',
    author: authorKeys.publicKeyHex,
    createdAt: '2026-11-02T09:14:00Z',
    fieldRoot: fieldRootResult.rootHex,
  });

  const leafBytes = Buffer.from(leafHex, 'hex');
  const authorSig = Buffer.from(sign(leafBytes, authorKeys.secretKey)).toString('hex');
  const approverSig = Buffer.from(sign(leafBytes, approverKeys.secretKey)).toString('hex');

  const tree = buildMerkleTree([leafBytes, new Uint8Array(32).fill(1)]);
  const merklePath = getMerkleProof(tree, 0);

  const bundle = {
    version: 'PB1',
    network: 'standalone',
    contract_id: 'CDB4DCLRAIAGILGM4DWIOKOTSWDDY6IGP4X4FF62DA3GUQQ4LEKD5VCD',
    org: 'GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ',
    checkpoint_id: 1,
    record: {
      record_id: '01HZX6789ABCDEF0123456789A',
      created_at: '2026-11-02T09:14:00Z',
      author: authorKeys.publicKeyHex,
      field_root: fieldRootResult.rootHex,
      disclosed_fields: fields,
      salts,
    },
    merkle_path: merklePath,
    signatures: {
      author: authorSig,
      approvers: [
        {
          publicKey: approverKeys.publicKeyHex,
          signature: approverSig,
        },
      ],
    },
    expected_root: tree.rootHex,
  };

  const tmpFile = path.join(os.tmpdir(), `test-bundle-${Date.now()}-${Math.random()}.json`);
  fs.writeFileSync(tmpFile, JSON.stringify(bundle, null, 2));
  return tmpFile;
}

describe('Proofbook CLI', () => {
  it('returns 0 on --help', async () => {
    const code = await main(['--help']);
    assert.strictEqual(code, 0);
  });

  it('returns 1 on non-existent file', async () => {
    const code = await main(['verify', './does-not-exist.json']);
    assert.strictEqual(code, 1);
  });

  it('returns 0 on valid bundle with --skip-blockchain', async () => {
    const bundleFile = createTempBundle(false);
    try {
      const code = await main(['verify', bundleFile, '--skip-blockchain']);
      assert.strictEqual(code, 0);
    } finally {
      fs.unlinkSync(bundleFile);
    }
  });

  it('returns 1 on tampered bundle with --skip-blockchain', async () => {
    const bundleFile = createTempBundle(true);
    try {
      const code = await main(['verify', bundleFile, '--skip-blockchain']);
      assert.strictEqual(code, 1);
    } finally {
      fs.unlinkSync(bundleFile);
    }
  });
});

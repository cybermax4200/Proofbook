import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  generateSalt,
  computeFieldRoot,
  getFieldProof,
  computeRecordLeafHex,
  generateEd25519Keypair,
  sign,
  buildMerkleTree,
  getMerkleProof,
} from '@proofbook/crypto';
import {
  verifyBundleOffline,
  evaluateMerklePath,
  parseCheckpointData,
  ProofBundle,
} from '../src/index.js';

function createValidBundleFixture() {
  const authorKeys = generateEd25519Keypair();
  const approverKeys = generateEd25519Keypair();

  const fields = {
    amount: '1250.00',
    currency: 'USD',
    payee: 'Acme Supplies Ltd',
    purpose: 'Classroom materials, batch 4',
  };

  const salts = {
    amount: Buffer.from(generateSalt()).toString('hex'),
    currency: Buffer.from(generateSalt()).toString('hex'),
    payee: Buffer.from(generateSalt()).toString('hex'),
    purpose: Buffer.from(generateSalt()).toString('hex'),
  };

  const fieldRootResult = computeFieldRoot(fields, salts);
  const recordId = '01HZX6789ABCDEF0123456789A';
  const createdAt = '2026-11-02T09:14:00Z';

  const leafHex = computeRecordLeafHex({
    recordId,
    author: authorKeys.publicKeyHex,
    createdAt,
    fieldRoot: fieldRootResult.rootHex,
  });

  const leafBytes = Buffer.from(leafHex, 'hex');
  const authorSig = Buffer.from(sign(leafBytes, authorKeys.secretKey)).toString('hex');
  const approverSig = Buffer.from(sign(leafBytes, approverKeys.secretKey)).toString('hex');

  // Build a Merkle tree with 3 leaves
  const dummyLeaf2 = new Uint8Array(32).fill(1);
  const dummyLeaf3 = new Uint8Array(32).fill(2);
  const tree = buildMerkleTree([leafBytes, dummyLeaf2, dummyLeaf3]);
  const merklePath = getMerkleProof(tree, 0);

  const bundle: ProofBundle = {
    version: 'PB1',
    network: 'standalone',
    contract_id: 'CDB4DCLRAIAGILGM4DWIOKOTSWDDY6IGP4X4FF62DA3GUQQ4LEKD5VCD',
    org: 'GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ',
    checkpoint_id: 1,
    record: {
      record_id: recordId,
      created_at: createdAt,
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

  return { bundle, fieldRootResult, authorKeys, approverKeys, tree };
}

describe('PB1 Bundle Verification Engine', () => {
  it('successfully verifies a completely valid proof bundle (full disclosure)', () => {
    const { bundle } = createValidBundleFixture();
    const report = verifyBundleOffline(bundle);

    assert.strictEqual(report.valid, true);
    assert.strictEqual(report.errors.length, 0);
    assert.strictEqual(report.authorVerified, true);
    assert.strictEqual(report.approverCountVerified, 1);
    assert.strictEqual(report.approverTotal, 1);
    assert.strictEqual(report.recomputedMerkleRoot, bundle.expected_root.toLowerCase());
  });

  it('successfully verifies selective disclosure with field proofs', () => {
    const { bundle, fieldRootResult, authorKeys, approverKeys, tree } = createValidBundleFixture();

    // Selectively disclose only 'amount' and 'currency'
    const proofAmount = getFieldProof(fieldRootResult, 'amount');
    const proofCurrency = getFieldProof(fieldRootResult, 'currency');

    const selectiveBundle: ProofBundle = {
      ...bundle,
      record: {
        record_id: bundle.record.record_id,
        created_at: bundle.record.created_at,
        author: bundle.record.author,
        field_root: fieldRootResult.rootHex,
        disclosed_fields: {
          amount: bundle.record.disclosed_fields.amount,
          currency: bundle.record.disclosed_fields.currency,
        },
        salts: {
          amount: bundle.record.salts.amount,
          currency: bundle.record.salts.currency,
        },
        field_proofs: {
          amount: proofAmount.proof,
          currency: proofCurrency.proof,
        },
      },
    };

    const report = verifyBundleOffline(selectiveBundle);
    assert.strictEqual(report.valid, true);
    assert.strictEqual(report.errors.length, 0);
  });

  it('rejects tampered field value', () => {
    const { bundle } = createValidBundleFixture();
    const tampered = JSON.parse(JSON.stringify(bundle)) as ProofBundle;
    tampered.record.disclosed_fields.amount = '9999.00'; // Tampered amount

    const report = verifyBundleOffline(tampered);
    assert.strictEqual(report.valid, false);
    assert.ok(report.errors.length > 0);
  });

  it('rejects tampered salt', () => {
    const { bundle } = createValidBundleFixture();
    const tampered = JSON.parse(JSON.stringify(bundle)) as ProofBundle;
    tampered.record.salts.amount = Buffer.from(generateSalt()).toString('hex'); // Tampered salt

    const report = verifyBundleOffline(tampered);
    assert.strictEqual(report.valid, false);
    assert.ok(report.errors.length > 0);
  });

  it('rejects tampered author signature', () => {
    const { bundle } = createValidBundleFixture();
    const tampered = JSON.parse(JSON.stringify(bundle)) as ProofBundle;
    // Mutate signature hex
    tampered.signatures.author =
      '00' + tampered.signatures.author.slice(2);

    const report = verifyBundleOffline(tampered);
    assert.strictEqual(report.valid, false);
    assert.strictEqual(report.authorVerified, false);
  });

  it('rejects tampered approver signature', () => {
    const { bundle } = createValidBundleFixture();
    const tampered = JSON.parse(JSON.stringify(bundle)) as ProofBundle;
    if (typeof tampered.signatures.approvers?.[0] === 'object') {
      tampered.signatures.approvers[0].signature =
        'ff' + tampered.signatures.approvers[0].signature.slice(2);
    }

    const report = verifyBundleOffline(tampered);
    assert.strictEqual(report.valid, false);
  });

  it('rejects Merkle path mismatch or tampered expected_root', () => {
    const { bundle } = createValidBundleFixture();
    const tampered = JSON.parse(JSON.stringify(bundle)) as ProofBundle;
    tampered.expected_root =
      '0000000000000000000000000000000000000000000000000000000000000000';

    const report = verifyBundleOffline(tampered);
    assert.strictEqual(report.valid, false);
  });

  it('evaluates Merkle path correctly', () => {
    const { tree, bundle } = createValidBundleFixture();
    const leafHex = computeRecordLeafHex({
      recordId: bundle.record.record_id,
      author: bundle.record.author,
      createdAt: bundle.record.created_at,
      fieldRoot: bundle.record.field_root!,
    });

    const evaluated = evaluateMerklePath(leafHex, bundle.merkle_path);
    assert.strictEqual(evaluated, tree.rootHex);
  });

  it('parses contract Checkpoint ScVal properly', () => {
    const raw = {
      id: 42,
      root: Buffer.from(new Uint8Array(32).fill(0xaa)),
      prev_root: Buffer.from(new Uint8Array(32).fill(0xbb)),
      record_count: 100n,
      period_start: 1700000000n,
      period_end: 1700003600n,
      ledger: 1234567,
      timestamp: 1700003650n,
    };

    const parsed = parseCheckpointData(raw);
    assert.strictEqual(parsed.id, 42);
    assert.strictEqual(parsed.root, 'aa'.repeat(32));
    assert.strictEqual(parsed.prevRoot, 'bb'.repeat(32));
    assert.strictEqual(parsed.recordCount, 100n);
    assert.strictEqual(parsed.ledger, 1234567);
  });
});

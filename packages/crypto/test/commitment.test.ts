import { describe, it } from 'node:test';
import assert from 'node:assert';
import { sha256 } from '@noble/hashes/sha256';
import {
  commitField,
  computeFieldRoot,
  getFieldProof,
  generateSalt,
  computeEvidenceHash,
  verifyEvidenceHash,
  bindEvidenceField,
  DOMAIN_FIELD_COMMIT,
} from '../src/index.js';
import { verifyMerkleProof } from '../src/merkle.js';

describe('PB1 Salted Field Commitments', () => {
  it('computes exact byte-level commitment matching 0x02 domain separation', () => {
    const key = 'amount';
    const val = '1250.00';
    const salt = new Uint8Array(32).fill(7);

    const commitment = commitField(key, val, salt);

    // Compute expected manually
    const keyBytes = new TextEncoder().encode(key);
    const valBytes = new TextEncoder().encode(val);
    const expectedBuf = new Uint8Array(1 + 2 + keyBytes.length + 4 + valBytes.length + 32);
    const view = new DataView(expectedBuf.buffer);

    let offset = 0;
    expectedBuf[offset++] = DOMAIN_FIELD_COMMIT;
    view.setUint16(offset, keyBytes.length, false);
    offset += 2;
    expectedBuf.set(keyBytes, offset);
    offset += keyBytes.length;
    view.setUint32(offset, valBytes.length, false);
    offset += 4;
    expectedBuf.set(valBytes, offset);
    offset += valBytes.length;
    expectedBuf.set(salt, offset);

    const manualSha = sha256(expectedBuf);
    assert.deepStrictEqual(commitment, manualSha);
  });

  it('computes field root over lexicographically sorted fields', () => {
    const fields = {
      purpose: 'Classroom materials, batch 4',
      amount: '1250.00',
      currency: 'USD',
      payee: 'Acme Supplies Ltd',
    };

    const salts = {
      purpose: generateSalt(),
      amount: generateSalt(),
      currency: generateSalt(),
      payee: generateSalt(),
    };

    const res = computeFieldRoot(fields, salts);
    const expectedSortedKeys = ['amount', 'currency', 'payee', 'purpose'];
    assert.deepStrictEqual(
      res.sortedFields.map((f) => f.name),
      expectedSortedKeys
    );
    assert.strictEqual(res.root.length, 32);
  });

  it('proves selective disclosure of single field against field root', () => {
    const fields = {
      amount: '1250.00',
      currency: 'USD',
      payee: 'Acme Supplies Ltd',
      purpose: 'Classroom materials, batch 4',
    };

    const salts = {
      amount: generateSalt(),
      currency: generateSalt(),
      payee: generateSalt(),
      purpose: generateSalt(),
    };

    const fieldRootRes = computeFieldRoot(fields, salts);

    // Prover discloses only 'amount' and its salt
    const { index, proof } = getFieldProof(fieldRootRes, 'amount');
    const amountCommitment = commitField('amount', fields.amount, salts.amount);

    // Verifier checks commitment with proof against field root
    const valid = verifyMerkleProof(amountCommitment, proof, fieldRootRes.root);
    assert.strictEqual(valid, true);

    // Tampered amount fails
    const tamperedCommitment = commitField('amount', '9999.00', salts.amount);
    const invalid = verifyMerkleProof(tamperedCommitment, proof, fieldRootRes.root);
    assert.strictEqual(invalid, false);
  });

  it('calculates evidence_hash (sha256:...) and binds it into canonical record fields', () => {
    const invoicePdfBytes = new TextEncoder().encode('PDF-1.7 Invoice #INV-2026-042 Total: $1250.00');
    const evidenceHash = computeEvidenceHash(invoicePdfBytes);

    assert.ok(evidenceHash.startsWith('sha256:'));
    assert.strictEqual(evidenceHash.length, 7 + 64);
    assert.strictEqual(verifyEvidenceHash(invoicePdfBytes, evidenceHash), true);
    assert.strictEqual(verifyEvidenceHash('tampered-invoice', evidenceHash), false);

    const boundFields = bindEvidenceField(
      { amount: '1250.00', payee: 'Acme Supplies Ltd' },
      invoicePdfBytes
    );
    assert.strictEqual(boundFields.evidence_hash, evidenceHash);

    const salts = {
      amount: generateSalt(),
      evidence_hash: generateSalt(),
      payee: generateSalt(),
    };

    const rootRes = computeFieldRoot(boundFields, salts);
    const { proof } = getFieldProof(rootRes, 'evidence_hash');
    const evCommit = commitField('evidence_hash', evidenceHash, salts.evidence_hash);
    assert.strictEqual(verifyMerkleProof(evCommit, proof, rootRes.root), true);
  });
});

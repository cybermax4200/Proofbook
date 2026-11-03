import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  canonicalJson,
  commitField,
  computeFieldRoot,
  computeRecordLeafHex,
  verifyMerkleProof,
  verifySignature,
  getPublicKeyFromSecret,
} from '../src/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const vectorPath = path.resolve(__dirname, '../../../spec/test-vectors/pb1-vectors.json');

describe('PB1 Specification Test Vectors', () => {
  const vectors = JSON.parse(fs.readFileSync(vectorPath, 'utf8'));

  it('passes canonical JSON serialization vector', () => {
    const actual = canonicalJson(vectors.canonical_serialization.input);
    assert.strictEqual(actual, vectors.canonical_serialization.expected);
  });

  it('passes salted field commitment and field root vectors', () => {
    const { fields, salts, commitments, field_root } = vectors.field_commitments;

    for (const [key, value] of Object.entries(fields)) {
      const actualCommitment = Buffer.from(commitField(key, value as string, salts[key])).toString('hex');
      assert.strictEqual(actualCommitment, commitments[key], `Commitment mismatch for field: ${key}`);
    }

    const fieldRootRes = computeFieldRoot(fields, salts);
    assert.strictEqual(fieldRootRes.rootHex, field_root);
  });

  it('passes record leaf vector', () => {
    const { record_id, author, created_at, field_root, expected_leaf } = vectors.record_leaf;
    const actualLeaf = computeRecordLeafHex({
      recordId: record_id,
      author,
      createdAt: created_at,
      fieldRoot: field_root,
    });
    assert.strictEqual(actualLeaf, expected_leaf);
  });

  it('passes Ed25519 signature vector', () => {
    const { secret_key, public_key, message, signature } = vectors.signatures;
    const derivedPub = Buffer.from(getPublicKeyFromSecret(secret_key)).toString('hex');
    assert.strictEqual(derivedPub, public_key);

    const valid = verifySignature(signature, message, public_key);
    assert.strictEqual(valid, true);
  });

  it('passes 3-leaf Merkle tree with odd-node promotion vector', () => {
    const { leaves, root, proofs } = vectors.merkle_trees.three_leaves;

    for (let i = 0; i < leaves.length; i++) {
      const valid = verifyMerkleProof(leaves[i], proofs[i], root);
      assert.strictEqual(valid, true, `Proof failed for leaf index ${i}`);
    }
  });

  it('passes 5-leaf Merkle tree with multi-level odd promotion vector', () => {
    const { leaves, root, proofs } = vectors.merkle_trees.five_leaves;

    for (let i = 0; i < leaves.length; i++) {
      const valid = verifyMerkleProof(leaves[i], proofs[i], root);
      assert.strictEqual(valid, true, `Proof failed for leaf index ${i}`);
    }
  });
});

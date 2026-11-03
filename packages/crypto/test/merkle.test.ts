import { describe, it } from 'node:test';
import assert from 'node:assert';
import { sha256 } from '@noble/hashes/sha256';
import {
  buildMerkleTree,
  getMerkleProof,
  verifyMerkleProof,
  hashInternalNode,
  DOMAIN_INTERNAL_NODE,
} from '../src/merkle.js';

describe('PB1 Merkle Tree Builder & Proofs', () => {
  function makeDummyLeaf(id: number): Uint8Array {
    return sha256(new Uint8Array([0x00, id]));
  }

  it('builds a tree from 1 leaf', () => {
    const leaf0 = makeDummyLeaf(0);
    const tree = buildMerkleTree([leaf0]);
    assert.strictEqual(tree.levels.length, 1);
    assert.deepStrictEqual(tree.root, leaf0);

    const proof = getMerkleProof(tree, 0);
    assert.strictEqual(proof.length, 0);
    assert.strictEqual(verifyMerkleProof(leaf0, proof, tree.root), true);
  });

  it('builds a 2-leaf balanced tree', () => {
    const l0 = makeDummyLeaf(0);
    const l1 = makeDummyLeaf(1);
    const expectedRoot = hashInternalNode(l0, l1);

    const tree = buildMerkleTree([l0, l1]);
    assert.deepStrictEqual(tree.root, expectedRoot);

    const proof0 = getMerkleProof(tree, 0);
    assert.strictEqual(proof0.length, 1);
    assert.strictEqual(proof0[0].side, 'right');
    assert.strictEqual(verifyMerkleProof(l0, proof0, tree.root), true);

    const proof1 = getMerkleProof(tree, 1);
    assert.strictEqual(proof1.length, 1);
    assert.strictEqual(proof1[0].side, 'left');
    assert.strictEqual(verifyMerkleProof(l1, proof1, tree.root), true);
  });

  it('builds a 3-leaf tree with odd-node promotion without duplicate hashing', () => {
    const l0 = makeDummyLeaf(0);
    const l1 = makeDummyLeaf(1);
    const l2 = makeDummyLeaf(2);

    // Level 0: [l0, l1, l2]
    // Level 1: [Parent(l0, l1), l2 (promoted unchanged!)]
    // Root: Parent(Parent(l0, l1), l2)
    const p01 = hashInternalNode(l0, l1);
    const expectedRoot = hashInternalNode(p01, l2);

    const tree = buildMerkleTree([l0, l1, l2]);
    assert.deepStrictEqual(tree.root, expectedRoot);
    assert.strictEqual(tree.levels.length, 3);
    assert.strictEqual(tree.levels[1].length, 2);
    assert.deepStrictEqual(tree.levels[1][1], l2); // promoted unchanged

    // Proof for leaf 0: sibling right l1, then sibling right l2
    const p0 = getMerkleProof(tree, 0);
    assert.strictEqual(p0.length, 2);
    assert.strictEqual(p0[0].side, 'right');
    assert.strictEqual(p0[1].side, 'right');
    assert.strictEqual(verifyMerkleProof(l0, p0, tree.root), true);

    // Proof for leaf 1: sibling left l0, then sibling right l2
    const p1 = getMerkleProof(tree, 1);
    assert.strictEqual(p1.length, 2);
    assert.strictEqual(p1[0].side, 'left');
    assert.strictEqual(p1[1].side, 'right');
    assert.strictEqual(verifyMerkleProof(l1, p1, tree.root), true);

    // Proof for leaf 2 (the promoted node):
    // In Level 0, it has NO sibling, so no step!
    // In Level 1, its sibling is Parent(l0, l1) on the left!
    const p2 = getMerkleProof(tree, 2);
    assert.strictEqual(p2.length, 1);
    assert.strictEqual(p2[0].side, 'left');
    assert.strictEqual(p2[0].hash, Buffer.from(p01).toString('hex'));
    assert.strictEqual(verifyMerkleProof(l2, p2, tree.root), true);
  });

  it('rejects tampered proofs and leaves', () => {
    const leaves = [0, 1, 2, 3, 4].map(makeDummyLeaf);
    const tree = buildMerkleTree(leaves);

    for (let i = 0; i < leaves.length; i++) {
      const proof = getMerkleProof(tree, i);
      assert.strictEqual(verifyMerkleProof(leaves[i], proof, tree.root), true);

      // Tamper leaf
      const tamperedLeaf = new Uint8Array(leaves[i]);
      tamperedLeaf[0] ^= 0xff;
      assert.strictEqual(verifyMerkleProof(tamperedLeaf, proof, tree.root), false);

      // Tamper proof side
      if (proof.length > 0) {
        const tamperedProof = [{ side: proof[0].side === 'left' ? 'right' : 'left', hash: proof[0].hash }, ...proof.slice(1)] as any;
        assert.strictEqual(verifyMerkleProof(leaves[i], tamperedProof, tree.root), false);
      }
    }
  });

  it('enforces 0x01 domain separation on internal nodes', () => {
    const left = new Uint8Array(32).fill(1);
    const right = new Uint8Array(32).fill(2);
    const manualHash = sha256(new Uint8Array([DOMAIN_INTERNAL_NODE, ...left, ...right]));
    assert.deepStrictEqual(hashInternalNode(left, right), manualHash);
  });
});

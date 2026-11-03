import { sha256 } from '@noble/hashes/sha256';

/**
 * Domain separation tags according to PB1 specification:
 * - 0x00: Record Leaf
 * - 0x01: Internal Merkle Node
 * - 0x02: Salted Field Commitment
 */
export const DOMAIN_RECORD_LEAF = 0x00;
export const DOMAIN_INTERNAL_NODE = 0x01;
export const DOMAIN_FIELD_COMMIT = 0x02;

export interface MerkleProofStep {
  side: 'left' | 'right';
  hash: string; // 64-character lowercase hex string
}

export type MerkleProof = MerkleProofStep[];

export interface MerkleTree {
  leaves: Uint8Array[];
  levels: Uint8Array[][];
  root: Uint8Array;
  rootHex: string;
}

/**
 * Computes internal node hash: SHA256( 0x01 || left || right )
 */
export function hashInternalNode(left: Uint8Array, right: Uint8Array): Uint8Array {
  if (left.length !== 32 || right.length !== 32) {
    throw new Error('Internal node hashes must be exactly 32 bytes');
  }
  const payload = new Uint8Array(65);
  payload[0] = DOMAIN_INTERNAL_NODE;
  payload.set(left, 1);
  payload.set(right, 33);
  return sha256(payload);
}

/**
 * Builds a PB1 Merkle tree with odd-node promotion (no duplicate hashing).
 */
export function buildMerkleTree(leaves: Uint8Array[]): MerkleTree {
  if (!leaves || leaves.length === 0) {
    throw new Error('Cannot build Merkle tree from empty leaf list');
  }

  for (let i = 0; i < leaves.length; i++) {
    if (leaves[i].length !== 32) {
      throw new Error(`Leaf at index ${i} has invalid length ${leaves[i].length} (must be 32 bytes)`);
    }
  }

  const levels: Uint8Array[][] = [[...leaves]];
  let currentLevel = leaves;

  while (currentLevel.length > 1) {
    const nextLevel: Uint8Array[] = [];
    const len = currentLevel.length;

    for (let i = 0; i < len; i += 2) {
      if (i + 1 < len) {
        // Paired nodes
        const parent = hashInternalNode(currentLevel[i], currentLevel[i + 1]);
        nextLevel.push(parent);
      } else {
        // Odd node: promoted unchanged without duplicate hashing
        nextLevel.push(currentLevel[i]);
      }
    }

    levels.push(nextLevel);
    currentLevel = nextLevel;
  }

  const root = currentLevel[0];
  const rootHex = Buffer.from(root).toString('hex');

  return {
    leaves,
    levels,
    root,
    rootHex,
  };
}

/**
 * Generates a PB1 Merkle proof for the leaf at leafIndex.
 */
export function getMerkleProof(tree: MerkleTree, leafIndex: number): MerkleProof {
  if (leafIndex < 0 || leafIndex >= tree.leaves.length) {
    throw new RangeError(`Leaf index ${leafIndex} out of bounds (0..${tree.leaves.length - 1})`);
  }

  const proof: MerkleProof = [];
  let currentIndex = leafIndex;

  // Walk through levels up to (but not including) root level
  for (let levelIdx = 0; levelIdx < tree.levels.length - 1; levelIdx++) {
    const level = tree.levels[levelIdx];
    const isEven = currentIndex % 2 === 0;

    if (isEven) {
      // Node has right sibling if not trailing odd node
      if (currentIndex + 1 < level.length) {
        proof.push({
          side: 'right',
          hash: Buffer.from(level[currentIndex + 1]).toString('hex'),
        });
      }
      // If trailing odd node with no right sibling, promoted unchanged (no proof step added)
    } else {
      // Node is odd, sibling is on the left
      proof.push({
        side: 'left',
        hash: Buffer.from(level[currentIndex - 1]).toString('hex'),
      });
    }

    // Move to index in next level
    currentIndex = Math.floor(currentIndex / 2);
  }

  return proof;
}

/**
 * Verifies a Merkle proof against an expected root.
 *
 * @param leaf - 32-byte leaf hash (Uint8Array or hex string)
 * @param proof - Array of proof steps
 * @param expectedRoot - 32-byte expected root (Uint8Array or hex string)
 */
export function verifyMerkleProof(
  leaf: Uint8Array | string,
  proof: MerkleProof,
  expectedRoot: Uint8Array | string
): boolean {
  let current = typeof leaf === 'string' ? Buffer.from(leaf, 'hex') : leaf;
  if (current.length !== 32) {
    throw new Error('Leaf hash must be 32 bytes');
  }

  for (const step of proof) {
    const sibling = Buffer.from(step.hash, 'hex');
    if (sibling.length !== 32) {
      throw new Error(`Proof step hash must be 32 bytes, got ${sibling.length}`);
    }

    if (step.side === 'left') {
      current = hashInternalNode(sibling, current);
    } else if (step.side === 'right') {
      current = hashInternalNode(current, sibling);
    } else {
      throw new Error(`Invalid proof step side: ${(step as any).side}`);
    }
  }

  const expectedRootBuf =
    typeof expectedRoot === 'string'
      ? Buffer.from(expectedRoot, 'hex')
      : expectedRoot;

  if (expectedRootBuf.length !== 32) {
    throw new Error('Expected root must be 32 bytes');
  }

  return Buffer.from(current).equals(expectedRootBuf);
}

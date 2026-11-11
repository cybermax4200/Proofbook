import { eq } from 'drizzle-orm';
import type { AppDatabase } from './index.js';
import { merkleNodes } from './schema.js';
import type { MerkleProof } from '@proofbook/crypto';

/**
 * Reconstructs a PB1 Merkle proof for a record using the persisted
 * Merkle sibling nodes in the database.
 */
export async function extractMerkleProofFromDb(
  db: AppDatabase,
  checkpointId: string,
  leafIndex: number
): Promise<MerkleProof> {
  // Query all nodes stored for this checkpoint ordered by level, idx
  const allNodes = await db
    .select()
    .from(merkleNodes)
    .where(eq(merkleNodes.checkpointId, checkpointId));

  if (allNodes.length === 0) {
    throw new Error(`No Merkle nodes found for checkpoint "${checkpointId}"`);
  }

  // Index nodes by level and idx
  const nodeMap = new Map<string, string>();
  let maxLevel = 0;
  for (const node of allNodes) {
    nodeMap.set(`${node.level}:${node.idx}`, node.hash);
    if (node.level > maxLevel) {
      maxLevel = node.level;
    }
  }

  const proof: MerkleProof = [];
  let currentIndex = leafIndex;

  for (let level = 0; level < maxLevel; level++) {
    const isEven = currentIndex % 2 === 0;

    if (isEven) {
      const siblingHash = nodeMap.get(`${level}:${currentIndex + 1}`);
      if (siblingHash) {
        proof.push({
          side: 'right',
          hash: siblingHash,
        });
      }
      // If no right sibling, node was promoted unchanged (odd-node promotion)
    } else {
      const siblingHash = nodeMap.get(`${level}:${currentIndex - 1}`);
      if (!siblingHash) {
        throw new Error(`Missing expected left sibling at level ${level}, idx ${currentIndex - 1}`);
      }
      proof.push({
        side: 'left',
        hash: siblingHash,
      });
    }

    currentIndex = Math.floor(currentIndex / 2);
  }

  return proof;
}

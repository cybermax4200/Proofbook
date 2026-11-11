import crypto from 'node:crypto';
import { eq, and, isNull, asc, desc } from 'drizzle-orm';
import * as StellarSdk from '@stellar/stellar-sdk';
import {
  AppDatabase,
  checkpoints,
  checkpointRecords,
  merkleNodes,
  records,
  orgs,
} from '@proofbook/api';
import { buildMerkleTree, MerkleProof, MerkleProofStep } from '@proofbook/crypto';
import { SorobanAnchorClient } from './soroban.js';

export interface CheckpointBuildOptions {
  db: AppDatabase;
  orgId: string;
  anchorClient: SorobanAnchorClient;
  orgKeypair?: StellarSdk.Keypair;
  feePayerKeypair?: StellarSdk.Keypair;
}

export interface CheckpointBuildResult {
  checkpointId: string;
  onchainId: number;
  orgId: string;
  root: string;
  prevRoot: string;
  recordCount: number;
  periodStart: string;
  periodEnd: string;
  txHash: string;
  ledger: number;
  recordsCount: number;
  leafRecordIds: string[];
}

/**
 * Builds a PB1 Merkle tree for uncheckpointed approved records,
 * anchors the checkpoint on-chain via Soroban, and persists
 * the checkpoint, record links, and sibling Merkle nodes in the database.
 */
export async function buildAndAnchorCheckpoint(
  options: CheckpointBuildOptions
): Promise<CheckpointBuildResult | null> {
  const { db, orgId, anchorClient } = options;

  // 1. Fetch organization details
  const orgRows = await db.select().from(orgs).where(eq(orgs.id, orgId));
  if (orgRows.length === 0) {
    throw new Error(`Organization "${orgId}" not found`);
  }
  const org = orgRows[0];

  // 2. Fetch approved records since previous checkpoint (uncheckpointed)
  const uncheckpointed = await db
    .select({
      id: records.id,
      orgId: records.orgId,
      leafHash: records.leafHash,
      seqNo: records.seqNo,
      createdAt: records.createdAt,
    })
    .from(records)
    .leftJoin(checkpointRecords, eq(records.id, checkpointRecords.recordId))
    .where(
      and(
        eq(records.orgId, orgId),
        eq(records.status, 'approved'),
        isNull(checkpointRecords.recordId)
      )
    )
    .orderBy(asc(records.seqNo));

  if (uncheckpointed.length === 0) {
    return null; // Nothing to anchor
  }

  // 3. Retrieve latest checkpoint for org to establish continuity
  const prevCheckpoints = await db
    .select()
    .from(checkpoints)
    .where(eq(checkpoints.orgId, orgId))
    .orderBy(desc(checkpoints.anchoredAt), desc(checkpoints.onchainId))
    .limit(1);

  const prevCp = prevCheckpoints[0] || null;
  const prevRoot = prevCp ? prevCp.root : '00'.repeat(32);
  const prevRecordCount = prevCp ? prevCp.recordCount : 0;
  const cumulativeRecordCount = prevRecordCount + uncheckpointed.length;

  // 4. Calculate period_start and period_end
  const earliestRecordSec = Math.floor(new Date(uncheckpointed[0].createdAt).getTime() / 1000);
  const latestRecordSec = Math.floor(
    new Date(uncheckpointed[uncheckpointed.length - 1].createdAt).getTime() / 1000
  );
  const nowSec = Math.floor(Date.now() / 1000);

  let prevEndSec = 0;
  if (prevCp?.periodEnd) {
    const parsed = Date.parse(prevCp.periodEnd);
    prevEndSec = isNaN(parsed) ? Number(prevCp.periodEnd) : Math.floor(parsed / 1000);
  }

  const periodStartSec = prevEndSec > 0 ? Math.max(earliestRecordSec, prevEndSec) : earliestRecordSec;
  const periodEndSec = Math.max(latestRecordSec, periodStartSec, nowSec);

  const periodStartStr = new Date(periodStartSec * 1000).toISOString();
  const periodEndStr = new Date(periodEndSec * 1000).toISOString();

  // 5. Build Merkle tree using @proofbook/crypto
  const leaves = uncheckpointed.map((r, i) => {
    const buf = Buffer.from(r.leafHash, 'hex');
    if (buf.length !== 32) {
      throw new Error(`Record ${r.id} (index ${i}) leaf_hash is not 32 bytes`);
    }
    return new Uint8Array(buf);
  });

  const merkleTree = buildMerkleTree(leaves);
  const rootHex = merkleTree.rootHex;

  // 6. Resolve org keypair and register on-chain if needed
  let orgKeypair = options.orgKeypair;
  if (!orgKeypair) {
    if (org.stellarAddress) {
      if (options.feePayerKeypair && options.feePayerKeypair.publicKey() === org.stellarAddress) {
        orgKeypair = options.feePayerKeypair;
      }
    }
  }

  if (!orgKeypair) {
    // Derive deterministic keypair from orgId if not explicitly provided
    const orgSeed = crypto.createHash('sha256').update(`proofbook:org:${orgId}`).digest();
    orgKeypair = StellarSdk.Keypair.fromRawEd25519Seed(orgSeed);
    if (!org.stellarAddress) {
      await db
        .update(orgs)
        .set({ stellarAddress: orgKeypair.publicKey() })
        .where(eq(orgs.id, orgId));
    }
  }

  // Ensure organization is registered in smart contract
  await anchorClient.registerOrg(orgKeypair, options.feePayerKeypair);

  // 7. Invoke anchor_checkpoint on-chain
  const anchorResult = await anchorClient.anchorCheckpoint({
    orgKeypair,
    rootHex,
    recordCount: cumulativeRecordCount,
    periodStart: periodStartSec,
    periodEnd: periodEndSec,
    feePayerKeypair: options.feePayerKeypair,
  });

  // 8. Persist Checkpoint, CheckpointRecords, and MerkleNodes
  const checkpointId = 'cp_' + crypto.randomUUID().replace(/-/g, '');
  const now = new Date();

  await db.transaction(async (tx) => {
    // Insert checkpoint
    await tx.insert(checkpoints).values({
      id: checkpointId,
      orgId,
      onchainId: anchorResult.checkpointId,
      root: rootHex,
      prevRoot,
      recordCount: cumulativeRecordCount,
      periodStart: periodStartStr,
      periodEnd: periodEndStr,
      txHash: anchorResult.txHash,
      ledger: anchorResult.ledger,
      anchoredAt: now,
    });

    // Insert checkpoint_records
    const cpRecords = uncheckpointed.map((rec, leafIndex) => ({
      checkpointId,
      recordId: rec.id,
      leafIndex,
    }));
    await tx.insert(checkpointRecords).values(cpRecords);

    // Insert all Merkle tree nodes across levels
    const nodeRows: Array<{
      checkpointId: string;
      level: number;
      idx: number;
      hash: string;
    }> = [];

    for (let level = 0; level < merkleTree.levels.length; level++) {
      const levelNodes = merkleTree.levels[level];
      for (let idx = 0; idx < levelNodes.length; idx++) {
        nodeRows.push({
          checkpointId,
          level,
          idx,
          hash: Buffer.from(levelNodes[idx]).toString('hex'),
        });
      }
    }

    if (nodeRows.length > 0) {
      await tx.insert(merkleNodes).values(nodeRows);
    }
  });

  return {
    checkpointId,
    onchainId: anchorResult.checkpointId,
    orgId,
    root: rootHex,
    prevRoot,
    recordCount: cumulativeRecordCount,
    periodStart: periodStartStr,
    periodEnd: periodEndStr,
    txHash: anchorResult.txHash,
    ledger: anchorResult.ledger,
    recordsCount: uncheckpointed.length,
    leafRecordIds: uncheckpointed.map((r) => r.id),
  };
}

export { extractMerkleProofFromDb } from '@proofbook/api';


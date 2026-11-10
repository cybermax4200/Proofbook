import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  createDatabase,
  DatabaseHandle,
  orgs,
  users,
  userKeys,
  records,
  recordSignatures,
  checkpoints,
  checkpointRecords,
  merkleNodes,
} from '@proofbook/api';
import {
  computeRecordLeafHex,
  generateEd25519Keypair,
  sign,
  verifyMerkleProof,
} from '@proofbook/crypto';
import { MockSorobanAnchorClient } from '../src/soroban.js';
import {
  buildAndAnchorCheckpoint,
  extractMerkleProofFromDb,
} from '../src/builder.js';

describe('Checkpoint Builder & Merkle Persistence', () => {
  let dbHandle: DatabaseHandle;
  let mockAnchor: MockSorobanAnchorClient;
  let orgId: string;
  let userId: string;
  let keyId: string;
  let keyPair: ReturnType<typeof generateEd25519Keypair>;

  beforeEach(async () => {
    dbHandle = await createDatabase();
    mockAnchor = new MockSorobanAnchorClient();

    // 1. Seed user and key
    userId = 'usr_' + crypto.randomUUID().replace(/-/g, '');
    keyPair = generateEd25519Keypair();
    keyId = 'key_' + crypto.randomUUID().replace(/-/g, '');

    await dbHandle.db.insert(users).values({
      id: userId,
      email: `${userId}@example.com`,
      passwordHash: 'dummy_hash',
    });

    await dbHandle.db.insert(userKeys).values({
      id: keyId,
      userId,
      publicKey: keyPair.publicKeyHex,
      kind: 'ed25519',
    });

    // 2. Seed organization
    orgId = 'org_' + crypto.randomUUID().replace(/-/g, '');
    await dbHandle.db.insert(orgs).values({
      id: orgId,
      name: 'Acme Test Corp',
      stellarAddress: null,
    });
  });

  afterEach(async () => {
    await dbHandle.close();
  });

  async function createRecord(options: {
    seqNo: number;
    status: 'draft' | 'pending' | 'approved' | 'rejected';
    createdAt?: string;
  }) {
    const recordId = 'rec_' + crypto.randomUUID().replace(/-/g, '');
    const createdAt = options.createdAt || new Date(Date.now() - 1000 * (100 - options.seqNo)).toISOString();
    const fieldRoot = crypto.randomBytes(32).toString('hex');
    const leafHash = computeRecordLeafHex({
      recordId,
      createdAt,
      author: keyPair.publicKeyHex,
      fieldRoot,
    });
    const sig = Buffer.from(sign(Buffer.from(leafHash, 'hex'), keyPair.secretKeyHex)).toString('hex');

    await dbHandle.db.insert(records).values({
      id: recordId,
      orgId,
      type: 'invoice',
      authorKeyId: keyId,
      status: options.status,
      leafHash,
      fieldRoot,
      ciphertextRef: `storage://${recordId}`,
      seqNo: options.seqNo,
      createdAt,
      approvedAt: options.status === 'approved' ? new Date() : null,
    });

    await dbHandle.db.insert(recordSignatures).values({
      id: 'sig_' + crypto.randomUUID().replace(/-/g, ''),
      recordId,
      keyId,
      kind: 'author',
      signature: sig,
    });

    return { recordId, leafHash, createdAt };
  }

  test('returns null when there are no approved uncheckpointed records', async () => {
    // Only pending and draft records exist
    await createRecord({ seqNo: 1, status: 'draft' });
    await createRecord({ seqNo: 2, status: 'pending' });

    const result = await buildAndAnchorCheckpoint({
      db: dbHandle.db,
      orgId,
      anchorClient: mockAnchor,
    });

    assert.equal(result, null);
  });

  test('anchors approved records, calculates cumulative count, and links checkpoint records', async () => {
    // Create mix of records
    await createRecord({ seqNo: 1, status: 'draft' });
    const rec1 = await createRecord({ seqNo: 2, status: 'approved' });
    await createRecord({ seqNo: 3, status: 'rejected' });
    const rec2 = await createRecord({ seqNo: 4, status: 'approved' });
    const rec3 = await createRecord({ seqNo: 5, status: 'approved' });

    // Anchor first batch (3 approved records)
    const result1 = await buildAndAnchorCheckpoint({
      db: dbHandle.db,
      orgId,
      anchorClient: mockAnchor,
    });

    assert.ok(result1);
    assert.equal(result1.recordsCount, 3);
    assert.equal(result1.recordCount, 3);
    assert.equal(result1.onchainId, 1);
    assert.equal(result1.prevRoot, '00'.repeat(32));
    assert.ok(result1.root.length === 64);
    assert.ok(result1.txHash.startsWith('tx_anchor_'));
    assert.ok(result1.ledger > 0);
    assert.deepEqual(result1.leafRecordIds, [rec1.recordId, rec2.recordId, rec3.recordId]);

    // Check database state
    const cpRows = await dbHandle.db.select().from(checkpoints);
    assert.equal(cpRows.length, 1);
    assert.equal(cpRows[0].id, result1.checkpointId);
    assert.equal(cpRows[0].recordCount, 3);
    assert.equal(cpRows[0].onchainId, 1);

    const cpRecRows = await dbHandle.db.select().from(checkpointRecords);
    assert.equal(cpRecRows.length, 3);
    assert.equal(cpRecRows[0].leafIndex, 0);
    assert.equal(cpRecRows[1].leafIndex, 1);
    assert.equal(cpRecRows[2].leafIndex, 2);

    // Now add 2 more approved records
    const rec4 = await createRecord({ seqNo: 6, status: 'approved' });
    const rec5 = await createRecord({ seqNo: 7, status: 'approved' });

    // Anchor second batch
    const result2 = await buildAndAnchorCheckpoint({
      db: dbHandle.db,
      orgId,
      anchorClient: mockAnchor,
    });

    assert.ok(result2);
    assert.equal(result2.recordsCount, 2);
    assert.equal(result2.recordCount, 5); // Cumulative count: 3 + 2 = 5
    assert.equal(result2.onchainId, 2);
    assert.equal(result2.prevRoot, result1.root); // Monotonic chain continuity
    assert.deepEqual(result2.leafRecordIds, [rec4.recordId, rec5.recordId]);

    // Subsequent call should have nothing to anchor
    const result3 = await buildAndAnchorCheckpoint({
      db: dbHandle.db,
      orgId,
      anchorClient: mockAnchor,
    });
    assert.equal(result3, null);
  });

  test('persists Merkle tree sibling nodes and allows fast proof extraction from database', async () => {
    // Create 5 approved records (odd number to test odd-node promotion)
    const recs: Array<{ recordId: string; leafHash: string; createdAt: string }> = [];
    for (let i = 1; i <= 5; i++) {
      recs.push(await createRecord({ seqNo: i, status: 'approved' }));
    }

    const checkpoint = await buildAndAnchorCheckpoint({
      db: dbHandle.db,
      orgId,
      anchorClient: mockAnchor,
    });

    assert.ok(checkpoint);

    // Verify merkle_nodes table contains nodes for this checkpoint
    const nodes = await dbHandle.db.select().from(merkleNodes);
    assert.ok(nodes.length > 5, 'Should persist leaves and intermediate parent nodes');

    // Extract proof for each leaf directly from the database and verify against expected root
    for (let leafIdx = 0; leafIdx < recs.length; leafIdx++) {
      const dbProof = await extractMerkleProofFromDb(dbHandle.db, checkpoint.checkpointId, leafIdx);
      const leafHex = recs[leafIdx].leafHash;

      const isValid = verifyMerkleProof(leafHex, dbProof, checkpoint.root);
      assert.equal(isValid, true, `Proof verification failed for leaf at index ${leafIdx}`);
    }
  });
});

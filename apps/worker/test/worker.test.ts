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
} from '@proofbook/api';
import { computeRecordLeafHex, generateEd25519Keypair } from '@proofbook/crypto';
import { MockSorobanAnchorClient } from '../src/soroban.js';
import { CheckpointWorker } from '../src/worker.js';

describe('CheckpointWorker Multi-Org & Interval Runner', () => {
  let dbHandle: DatabaseHandle;
  let mockAnchor: MockSorobanAnchorClient;
  let worker: CheckpointWorker;
  let orgAId: string;
  let orgBId: string;
  let keyPair: ReturnType<typeof generateEd25519Keypair>;
  let keyId: string;

  beforeEach(async () => {
    dbHandle = await createDatabase();
    mockAnchor = new MockSorobanAnchorClient();

    worker = new CheckpointWorker({
      db: dbHandle.db,
      dbHandle,
      anchorClient: mockAnchor,
    });

    const userId = 'usr_' + crypto.randomUUID().replace(/-/g, '');
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
    });

    orgAId = 'org_a_' + crypto.randomUUID().replace(/-/g, '');
    orgBId = 'org_b_' + crypto.randomUUID().replace(/-/g, '');

    await dbHandle.db.insert(orgs).values([
      { id: orgAId, name: 'Org Alpha' },
      { id: orgBId, name: 'Org Beta' },
    ]);
  });

  afterEach(async () => {
    await worker.close();
  });

  async function addApprovedRecord(orgId: string, seqNo: number) {
    const recordId = 'rec_' + crypto.randomUUID().replace(/-/g, '');
    const createdAt = new Date().toISOString();
    const leafHash = computeRecordLeafHex({
      recordId,
      createdAt,
      author: keyPair.publicKeyHex,
      fieldRoot: crypto.randomBytes(32).toString('hex'),
    });

    await dbHandle.db.insert(records).values({
      id: recordId,
      orgId,
      type: 'evidence',
      authorKeyId: keyId,
      status: 'approved',
      leafHash,
      fieldRoot: '00'.repeat(32),
      ciphertextRef: `storage://${recordId}`,
      seqNo,
      createdAt,
      approvedAt: new Date(),
    });
  }

  test('processAllOrgs anchors checkpoints across multiple orgs independently', async () => {
    // Add 2 records to Org A, 3 records to Org B
    await addApprovedRecord(orgAId, 1);
    await addApprovedRecord(orgAId, 2);

    await addApprovedRecord(orgBId, 1);
    await addApprovedRecord(orgBId, 2);
    await addApprovedRecord(orgBId, 3);

    const results = await worker.processAllOrgs();
    assert.equal(results.length, 2);

    const resA = results.find((r) => r.orgId === orgAId);
    const resB = results.find((r) => r.orgId === orgBId);

    assert.ok(resA);
    assert.equal(resA.recordsCount, 2);
    assert.equal(resA.recordCount, 2);
    assert.equal(resA.onchainId, 1);

    assert.ok(resB);
    assert.equal(resB.recordsCount, 3);
    assert.equal(resB.recordCount, 3);
    assert.equal(resB.onchainId, 1);

    // Running again without new approved records yields empty results
    const secondRun = await worker.processAllOrgs();
    assert.equal(secondRun.length, 0);

    // Status metrics
    const status = worker.getStatus();
    assert.equal(status.totalAnchored, 2);
    assert.ok(status.lastRunAt);
  });

  test('interval runner starts and stops cleanly', async () => {
    worker.startInterval(10);
    assert.equal(worker.getStatus().active, true);

    worker.stopInterval();
    assert.equal(worker.getStatus().active, false);
  });
});

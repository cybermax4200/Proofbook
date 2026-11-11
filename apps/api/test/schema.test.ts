import { test, describe, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  createDatabase,
  DatabaseHandle,
  users,
  userKeys,
  orgs,
  memberships,
  records,
  recordSignatures,
  evidence,
  checkpoints,
  checkpointRecords,
  merkleNodes,
  engagements,
  checkpointWitnesses,
} from '../src/db/index.js';
import { eq, isNull } from 'drizzle-orm';

describe('Schema & Relation Constraints', () => {
  let dbHandle: DatabaseHandle;

  afterEach(async () => {
    if (dbHandle) await dbHandle.close();
  });

  test('handles user key creation and revocation', async () => {
    dbHandle = await createDatabase();
    const db = dbHandle.db;

    const userId = 'usr_revoke_test';
    await db.insert(users).values({
      id: userId,
      email: 'revocation@example.com',
      passwordHash: 'hashed_pw',
    });

    const keyId = 'key_1';
    await db.insert(userKeys).values({
      id: keyId,
      userId,
      publicKey: '11'.repeat(32),
      kind: 'ed25519',
    });

    // Active keys query
    const activeBefore = await db
      .select()
      .from(userKeys)
      .where(eq(userKeys.userId, userId));
    assert.equal(activeBefore.length, 1);
    assert.equal(activeBefore[0].revokedAt, null);

    // Revoke key
    const revokedAt = new Date();
    await db
      .update(userKeys)
      .set({ revokedAt })
      .where(eq(userKeys.id, keyId));

    const activeAfter = await db
      .select()
      .from(userKeys)
      .where(eq(userKeys.userId, userId));
    assert.ok(activeAfter[0].revokedAt instanceof Date || typeof activeAfter[0].revokedAt === 'string');
  });

  test('creates checkpoints, links records, and stores Merkle tree nodes', async () => {
    dbHandle = await createDatabase();
    const db = dbHandle.db;

    const orgId = 'org_merkle';
    await db.insert(orgs).values({ id: orgId, name: 'Merkle Org' });

    const userId = 'usr_1';
    await db.insert(users).values({ id: userId, email: 'usr1@example.com', passwordHash: 'hash' });

    const keyId = 'key_usr_1';
    await db.insert(userKeys).values({ id: keyId, userId, publicKey: '22'.repeat(32) });

    const recordId = 'rec_1';
    await db.insert(records).values({
      id: recordId,
      orgId,
      authorKeyId: keyId,
      status: 'approved',
      leafHash: 'aa'.repeat(32),
      fieldRoot: 'bb'.repeat(32),
      ciphertextRef: 'storage://c1',
      seqNo: 1,
      createdAt: '2026-11-08T10:00:00Z',
    });

    // Evidence
    await db.insert(evidence).values({
      id: 'ev_1',
      recordId,
      sha256: 'ee'.repeat(32),
      ciphertextRef: 'storage://ev1',
    });

    // Checkpoint
    const checkpointId = 'cp_1';
    await db.insert(checkpoints).values({
      id: checkpointId,
      orgId,
      onchainId: 1,
      root: 'ff'.repeat(32),
      prevRoot: '00'.repeat(32),
      recordCount: 1,
      periodStart: '2026-11-08T00:00:00Z',
      periodEnd: '2026-11-08T23:59:59Z',
      txHash: '0x1234',
      ledger: 100,
    });

    await db.insert(checkpointRecords).values({
      checkpointId,
      recordId,
      leafIndex: 0,
    });

    await db.insert(merkleNodes).values({
      checkpointId,
      level: 0,
      idx: 0,
      hash: 'ff'.repeat(32),
    });

    const cpList = await db.select().from(checkpoints).where(eq(checkpoints.orgId, orgId));
    assert.equal(cpList.length, 1);
    assert.equal(cpList[0].root, 'ff'.repeat(32));

    const nodes = await db.select().from(merkleNodes).where(eq(merkleNodes.checkpointId, checkpointId));
    assert.equal(nodes.length, 1);
    assert.equal(nodes[0].hash, 'ff'.repeat(32));
  });

  test('cascades deletion on org removal', async () => {
    dbHandle = await createDatabase();
    const db = dbHandle.db;

    const orgId = 'org_delete';
    await db.insert(orgs).values({ id: orgId, name: 'To Delete' });

    const userId = 'usr_delete';
    await db.insert(users).values({ id: userId, email: 'del@example.com', passwordHash: 'hash' });

    await db.insert(memberships).values({
      orgId,
      userId,
      role: 'admin',
    });

    // Delete org
    await db.delete(orgs).where(eq(orgs.id, orgId));

    // Membership should be deleted
    const memberRows = await db.select().from(memberships).where(eq(memberships.orgId, orgId));
    assert.equal(memberRows.length, 0);
  });

  test('creates engagements and checkpoint witnesses', async () => {
    dbHandle = await createDatabase();
    const db = dbHandle.db;

    const orgId = 'org_eng_test';
    await db.insert(orgs).values({ id: orgId, name: 'Audit Test Org' });

    const auditorUserId = 'usr_auditor_1';
    await db.insert(users).values({ id: auditorUserId, email: 'auditor@auditfirm.com', passwordHash: 'hash' });

    const engagementId = 'eng_1';
    await db.insert(engagements).values({
      id: engagementId,
      orgId,
      auditorId: auditorUserId,
      auditorAddress: 'GBHTYTJUH6BFBVER5OHDLLYYW4KOYH6J6L7WZVIAWH74H7FSOQCEZHI5',
      title: 'FY2026 Audit',
      scope: JSON.stringify({ recordTypes: ['grant_disbursement'], status: 'approved' }),
      status: 'active',
    });

    const checkpointId = 'cp_witness_test';
    await db.insert(checkpoints).values({
      id: checkpointId,
      orgId,
      onchainId: 1,
      root: '11'.repeat(32),
      prevRoot: '00'.repeat(32),
      recordCount: 5,
      periodStart: '2026-11-01T00:00:00Z',
      periodEnd: '2026-11-08T00:00:00Z',
    });

    const witnessId = 'wit_1';
    await db.insert(checkpointWitnesses).values({
      id: witnessId,
      checkpointId,
      engagementId,
      auditorAddress: 'GBHTYTJUH6BFBVER5OHDLLYYW4KOYH6J6L7WZVIAWH74H7FSOQCEZHI5',
      txHash: 'tx_wit_123',
      ledger: 10005,
    });

    const engRows = await db.select().from(engagements).where(eq(engagements.id, engagementId));
    assert.equal(engRows.length, 1);
    assert.equal(engRows[0].title, 'FY2026 Audit');
    assert.deepEqual(JSON.parse(engRows[0].scope), { recordTypes: ['grant_disbursement'], status: 'approved' });

    const witRows = await db.select().from(checkpointWitnesses).where(eq(checkpointWitnesses.checkpointId, checkpointId));
    assert.equal(witRows.length, 1);
    assert.equal(witRows[0].auditorAddress, 'GBHTYTJUH6BFBVER5OHDLLYYW4KOYH6J6L7WZVIAWH74H7FSOQCEZHI5');
    assert.equal(witRows[0].ledger, 10005);
  });
});

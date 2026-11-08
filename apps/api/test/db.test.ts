import { test, describe, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createDatabase, DatabaseHandle, users, userKeys, orgs, memberships, records, recordSignatures } from '../src/db/index.js';
import { eq } from 'drizzle-orm';

describe('Database & Schema Initialization', () => {
  let dbHandle: DatabaseHandle;

  afterEach(async () => {
    if (dbHandle) {
      await dbHandle.close();
    }
  });

  test('initializes schema on PGlite successfully', async () => {
    dbHandle = await createDatabase();
    assert.equal(dbHandle.isPgLite, true);

    // Verify querying empty users table
    const allUsers = await dbHandle.db.select().from(users);
    assert.deepEqual(allUsers, []);
  });

  test('inserts and retrieves users and user keys', async () => {
    dbHandle = await createDatabase();

    const userId = 'usr_' + Date.now();
    await dbHandle.db.insert(users).values({
      id: userId,
      email: 'alice@example.com',
      passwordHash: 'dummy_hash',
    });

    const keyId = 'key_' + Date.now();
    await dbHandle.db.insert(userKeys).values({
      id: keyId,
      userId,
      publicKey: '0102030405060708091011121314151617181920212223242526272829303132',
      kind: 'ed25519',
    });

    const userRows = await dbHandle.db.select().from(users).where(eq(users.id, userId));
    assert.equal(userRows.length, 1);
    assert.equal(userRows[0].email, 'alice@example.com');

    const keyRows = await dbHandle.db.select().from(userKeys).where(eq(userKeys.userId, userId));
    assert.equal(keyRows.length, 1);
    assert.equal(keyRows[0].publicKey, '0102030405060708091011121314151617181920212223242526272829303132');
  });

  test('inserts orgs, memberships, records, and signatures', async () => {
    dbHandle = await createDatabase();

    const userId = 'usr_maker';
    await dbHandle.db.insert(users).values({
      id: userId,
      email: 'maker@example.com',
      passwordHash: 'dummy_hash',
    });

    const keyId = 'key_maker';
    await dbHandle.db.insert(userKeys).values({
      id: keyId,
      userId,
      publicKey: 'aa'.repeat(32),
      kind: 'ed25519',
    });

    const orgId = 'org_acme';
    await dbHandle.db.insert(orgs).values({
      id: orgId,
      name: 'Acme Corp',
      stellarAddress: 'GBHTYTJU7S52LOM3M6R63B346Y5A5R5Y63RGL7Y5R7E4P6Y3J3Y6EXAMPLE',
    });

    await dbHandle.db.insert(memberships).values({
      orgId,
      userId,
      role: 'maker',
    });

    const recordId = 'rec_1001';
    await dbHandle.db.insert(records).values({
      id: recordId,
      orgId,
      type: 'expense',
      authorKeyId: keyId,
      status: 'pending',
      leafHash: 'bb'.repeat(32),
      fieldRoot: 'cc'.repeat(32),
      ciphertextRef: 'records/rec_1001.bin',
      seqNo: 1,
      createdAt: '2026-11-08T12:00:00Z',
    });

    await dbHandle.db.insert(recordSignatures).values({
      id: 'sig_1',
      recordId,
      keyId,
      kind: 'author',
      signature: 'dd'.repeat(64),
    });

    const recordList = await dbHandle.db.select().from(records).where(eq(records.orgId, orgId));
    assert.equal(recordList.length, 1);
    assert.equal(recordList[0].id, recordId);
    assert.equal(recordList[0].status, 'pending');

    const sigList = await dbHandle.db.select().from(recordSignatures).where(eq(recordSignatures.recordId, recordId));
    assert.equal(sigList.length, 1);
    assert.equal(sigList[0].kind, 'author');
  });
});

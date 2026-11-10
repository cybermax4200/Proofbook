import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { FastifyInstance } from 'fastify';
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
import { buildWorkerServer } from '../src/server.js';

describe('Worker HTTP Trigger Server', () => {
  let dbHandle: DatabaseHandle;
  let worker: CheckpointWorker;
  let server: FastifyInstance;
  let orgId: string;
  let keyPair: ReturnType<typeof generateEd25519Keypair>;
  let keyId: string;

  beforeEach(async () => {
    dbHandle = await createDatabase();
    const mockAnchor = new MockSorobanAnchorClient();

    worker = new CheckpointWorker({
      db: dbHandle.db,
      dbHandle,
      anchorClient: mockAnchor,
    });

    server = await buildWorkerServer({ worker });

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

    orgId = 'org_' + crypto.randomUUID().replace(/-/g, '');
    await dbHandle.db.insert(orgs).values({ id: orgId, name: 'Trigger Corp' });
  });

  afterEach(async () => {
    await server.close();
    await worker.close();
  });

  async function addRecord() {
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
      type: 'test',
      authorKeyId: keyId,
      status: 'approved',
      leafHash,
      fieldRoot: '00'.repeat(32),
      ciphertextRef: `storage://${recordId}`,
      seqNo: 1,
      createdAt,
      approvedAt: new Date(),
    });
  }

  test('GET /health returns 200 with service info', async () => {
    const res = await server.inject({ method: 'GET', url: '/health' });
    assert.equal(res.statusCode, 200);
    const body = res.json();
    assert.equal(body.status, 'ok');
    assert.equal(body.service, 'proofbook-worker');
  });

  test('GET /checkpoints/status returns metrics', async () => {
    const res = await server.inject({ method: 'GET', url: '/checkpoints/status' });
    assert.equal(res.statusCode, 200);
    const body = res.json();
    assert.equal(typeof body.totalAnchored, 'number');
    assert.equal(body.active, false);
  });

  test('POST /checkpoints/run executes manual trigger and returns checkpoints', async () => {
    await addRecord();

    const res = await server.inject({
      method: 'POST',
      url: '/checkpoints/run',
      payload: {},
    });

    assert.equal(res.statusCode, 200);
    const body = res.json();
    assert.equal(body.success, true);
    assert.equal(body.count, 1);
    assert.equal(body.checkpoints[0].orgId, orgId);
    assert.equal(body.checkpoints[0].recordsCount, 1);
  });

  test('POST /checkpoints/run with specific orgId targets only that organization', async () => {
    await addRecord();

    const res = await server.inject({
      method: 'POST',
      url: '/checkpoints/run',
      payload: { orgId },
    });

    assert.equal(res.statusCode, 200);
    const body = res.json();
    assert.equal(body.success, true);
    assert.equal(body.orgId, orgId);
    assert.equal(body.anchored, true);
    assert.equal(body.checkpoint.orgId, orgId);
  });
});

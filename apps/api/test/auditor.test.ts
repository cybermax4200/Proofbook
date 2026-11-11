import { test, describe, afterEach, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import * as StellarSdk from '@stellar/stellar-sdk';
import {
  createDatabase,
  DatabaseHandle,
  checkpoints,
  checkpointRecords,
  merkleNodes,
  records,
  recordSignatures,
  checkpointWitnesses,
  engagements,
} from '../src/db/index.js';
import { buildFastifyApp } from '../src/app.js';
import { EncryptedFileStorageProvider } from '../src/records/storage.js';
import { MockSorobanAuditorClient } from '../src/auditor/soroban.js';
import { FastifyInstance } from 'fastify';
import {
  generateEd25519Keypair,
  computeRecordLeaf,
  sign,
  generateSalt,
  computeFieldRoot,
  buildMerkleTree,
} from '@proofbook/crypto';
import { verifyBundleOffline } from '@proofbook/verifier';
import { eq } from 'drizzle-orm';

describe('Auditor Workspace & Proof Bundler', () => {
  let dbHandle: DatabaseHandle;
  let app: FastifyInstance;
  let tmpStorageDir: string;
  let encryptedStorage: EncryptedFileStorageProvider;
  let mockSorobanClient: MockSorobanAuditorClient;

  beforeEach(async () => {
    tmpStorageDir = await fs.mkdtemp(path.join(os.tmpdir(), 'proofbook-auditor-'));
    encryptedStorage = new EncryptedFileStorageProvider(tmpStorageDir, 'auditor-test-master-key');
    mockSorobanClient = new MockSorobanAuditorClient();
    dbHandle = await createDatabase();
    app = await buildFastifyApp({
      dbHandle,
      storage: encryptedStorage,
      sorobanAuditorClient: mockSorobanClient,
    });
  });

  afterEach(async () => {
    if (app) await app.close();
    if (dbHandle) await dbHandle.close();
    if (tmpStorageDir) {
      await fs.rm(tmpStorageDir, { recursive: true, force: true });
    }
  });

  async function setupTestOrganization() {
    // 1. Admin setup
    const adminKeypair = generateEd25519Keypair();
    const adminReg = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: {
        email: 'admin@proofbook.org',
        password: 'password123',
        publicKey: adminKeypair.publicKeyHex,
      },
    });
    const { token: adminToken, user: adminUser } = JSON.parse(adminReg.body);

    const orgKeypair = StellarSdk.Keypair.random();
    const orgRes = await app.inject({
      method: 'POST',
      url: '/api/v1/orgs',
      headers: { authorization: `Bearer ${adminToken}` },
      payload: {
        name: 'Humanitarian Evidence Fund',
        stellarAddress: orgKeypair.publicKey(),
      },
    });
    const orgId = JSON.parse(orgRes.body).org.id;

    // 2. Maker setup
    const makerKeypair = generateEd25519Keypair();
    const makerReg = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: {
        email: 'maker@proofbook.org',
        password: 'password123',
        publicKey: makerKeypair.publicKeyHex,
      },
    });
    const { token: makerToken, key: makerKey } = JSON.parse(makerReg.body);

    await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/members`,
      headers: { authorization: `Bearer ${adminToken}` },
      payload: { email: 'maker@proofbook.org', role: 'maker' },
    });

    // 3. Checker setup
    const checkerKeypair = generateEd25519Keypair();
    const checkerReg = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: {
        email: 'checker@proofbook.org',
        password: 'password123',
        publicKey: checkerKeypair.publicKeyHex,
      },
    });
    const { token: checkerToken, key: checkerKey } = JSON.parse(checkerReg.body);

    await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/members`,
      headers: { authorization: `Bearer ${adminToken}` },
      payload: { email: 'checker@proofbook.org', role: 'checker' },
    });

    // 4. Auditor setup
    const auditorKeypair = generateEd25519Keypair();
    const auditorStellarKeypair = StellarSdk.Keypair.random();
    const auditorReg = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: {
        email: 'auditor@kpmg-audit.com',
        password: 'password123',
        publicKey: auditorKeypair.publicKeyHex,
      },
    });
    const { token: auditorToken, user: auditorUser } = JSON.parse(auditorReg.body);

    await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/members`,
      headers: { authorization: `Bearer ${adminToken}` },
      payload: { email: 'auditor@kpmg-audit.com', role: 'auditor' },
    });

    return {
      orgId,
      orgKeypair,
      admin: { token: adminToken, user: adminUser },
      maker: { token: makerToken, key: makerKey, keypair: makerKeypair },
      checker: { token: checkerToken, key: checkerKey, keypair: checkerKeypair },
      auditor: {
        token: auditorToken,
        user: auditorUser,
        keypair: auditorKeypair,
        stellarKeypair: auditorStellarKeypair,
      },
    };
  }

  /**
   * Helper to ingest and approve a record, and build a checkpoint with Merkle nodes.
   */
  async function ingestAndAnchorRecords(orgInfo: Awaited<ReturnType<typeof setupTestOrganization>>) {
    const { orgId, maker, checker } = orgInfo;

    // Record 1: 4 fields
    const recordId = '01HZX999AUDITPROOF1234567';
    const createdAt = '2026-11-08T12:00:00Z';
    const fields = {
      amount: '50000.00',
      currency: 'USD',
      payee: 'Emergency Shelter Operations',
      memo: 'Q4 Operations Aid',
    };
    const salts = {
      amount: generateSalt(),
      currency: generateSalt(),
      payee: generateSalt(),
      memo: generateSalt(),
    };

    const fieldRes = computeFieldRoot(fields, salts);
    const leafBytes = computeRecordLeaf({
      recordId,
      author: maker.keypair.publicKeyHex,
      createdAt,
      fieldRoot: fieldRes.rootHex,
    });
    const leafHex = Buffer.from(leafBytes).toString('hex');
    const authorSig = Buffer.from(sign(leafBytes, maker.keypair.secretKey)).toString('hex');

    // Ingest
    const ingestRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/records`,
      headers: { authorization: `Bearer ${maker.token}` },
      payload: {
        recordId,
        type: 'grant_disbursement',
        createdAt,
        fieldRoot: fieldRes.rootHex,
        leafHash: leafHex,
        authorKeyId: maker.key.id,
        authorSignature: authorSig,
        ciphertext: JSON.stringify({ fields, salts }),
      },
    });
    assert.equal(ingestRes.statusCode, 201);

    // Checker approves
    const checkerSig = Buffer.from(sign(leafBytes, checker.keypair.secretKey)).toString('hex');
    const approveRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/records/${recordId}/approve`,
      headers: { authorization: `Bearer ${checker.token}` },
      payload: {
        approverKeyId: checker.key.id,
        approverSignature: checkerSig,
      },
    });
    assert.equal(approveRes.statusCode, 200);

    // Anchor checkpoint with Merkle tree
    const tree = buildMerkleTree([leafBytes]);
    const checkpointId = 'cp_audit_test_1';
    const onchainId = 1;

    await dbHandle.db.insert(checkpoints).values({
      id: checkpointId,
      orgId,
      onchainId,
      root: tree.rootHex,
      prevRoot: '00'.repeat(32),
      recordCount: 1,
      periodStart: createdAt,
      periodEnd: createdAt,
      txHash: 'tx_anchor_123',
      ledger: 100001,
      anchoredAt: new Date(),
    });

    await dbHandle.db.insert(checkpointRecords).values({
      checkpointId,
      recordId,
      leafIndex: 0,
    });

    // Insert Merkle root node
    await dbHandle.db.insert(merkleNodes).values({
      checkpointId,
      level: 0,
      idx: 0,
      hash: tree.rootHex,
    });

    mockSorobanClient.registerCheckpointRoot(orgInfo.orgKeypair.publicKey(), onchainId, tree.rootHex);

    return {
      recordId,
      createdAt,
      fields,
      salts,
      fieldRes,
      leafHex,
      authorSig,
      checkerSig,
      checkpointId,
      onchainId,
      merkleRoot: tree.rootHex,
    };
  }

  test('POST /orgs/:id/proofs generates valid full-disclosure PB1 proof bundle', async () => {
    const orgInfo = await setupTestOrganization();
    const data = await ingestAndAnchorRecords(orgInfo);

    const proofRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgInfo.orgId}/proofs`,
      headers: { authorization: `Bearer ${orgInfo.maker.token}` },
      payload: {
        recordId: data.recordId,
        fields: data.fields,
        salts: data.salts,
      },
    });

    assert.equal(proofRes.statusCode, 200);
    const body = JSON.parse(proofRes.body);

    assert.ok(body.bundle);
    assert.equal(body.bundle.version, 'PB1');
    assert.equal(body.bundle.record.record_id, data.recordId);
    assert.equal(body.bundle.expected_root, data.merkleRoot);
    assert.equal(body.bundle.signatures.author, data.authorSig);
    assert.equal(body.bundle.signatures.approvers.length, 1);

    // Full disclosure: field_proofs is undefined or empty
    assert.equal(body.bundle.record.field_proofs, undefined);
    assert.equal(Object.keys(body.bundle.record.disclosed_fields).length, 4);

    // Standalone zero-network verification
    const offlineReport = verifyBundleOffline(body.bundle);
    assert.equal(offlineReport.valid, true, `Offline report errors: ${offlineReport.errors.join(', ')}`);
    assert.equal(offlineReport.authorVerified, true);
    assert.equal(offlineReport.approverCountVerified, 1);
  });

  test('POST /orgs/:id/proofs supports selective disclosure with Merkle field inclusion proofs', async () => {
    const orgInfo = await setupTestOrganization();
    const data = await ingestAndAnchorRecords(orgInfo);

    // Disclose ONLY 'amount' and 'currency', masking 'payee' and 'memo'
    const proofRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgInfo.orgId}/proofs`,
      headers: { authorization: `Bearer ${orgInfo.auditor.token}` },
      payload: {
        recordId: data.recordId,
        fields: data.fields,
        salts: data.salts,
        disclosedFields: ['amount', 'currency'],
      },
    });

    assert.equal(proofRes.statusCode, 200);
    const body = JSON.parse(proofRes.body);
    const bundle = body.bundle;

    // Check selective disclosure structure
    assert.equal(bundle.version, 'PB1');
    assert.deepEqual(Object.keys(bundle.record.disclosed_fields).sort(), ['amount', 'currency']);
    assert.equal(bundle.record.disclosed_fields.payee, undefined);
    assert.equal(bundle.record.disclosed_fields.memo, undefined);

    // Field proofs are generated for disclosed fields
    assert.ok(bundle.record.field_proofs);
    assert.ok(bundle.record.field_proofs.amount);
    assert.ok(bundle.record.field_proofs.currency);
    assert.equal(bundle.record.field_proofs.payee, undefined);

    // Standalone verification succeeds with selective disclosure
    const offlineReport = verifyBundleOffline(bundle);
    assert.equal(offlineReport.valid, true, `Selective verification failed: ${offlineReport.errors.join(', ')}`);
    assert.equal(offlineReport.recomputedFieldRoot.toLowerCase(), data.fieldRes.rootHex.toLowerCase());

    // Tampering check: altering a disclosed field invalidates the bundle
    const tamperedBundle = JSON.parse(JSON.stringify(bundle));
    tamperedBundle.record.disclosed_fields.amount = '999999.00';
    const tamperedReport = verifyBundleOffline(tamperedBundle);
    assert.equal(tamperedReport.valid, false);
    assert.ok(tamperedReport.errors.some((e: string) => e.includes('Merkle proof verification failed')));
  });

  test('POST /orgs/:id/proofs supports file download via ?download=true', async () => {
    const orgInfo = await setupTestOrganization();
    const data = await ingestAndAnchorRecords(orgInfo);

    const downloadRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgInfo.orgId}/proofs?download=true`,
      headers: { authorization: `Bearer ${orgInfo.admin.token}` },
      payload: {
        recordId: data.recordId,
        fields: data.fields,
        salts: data.salts,
      },
    });

    assert.equal(downloadRes.statusCode, 200);
    assert.ok(downloadRes.headers['content-disposition']?.includes('bundle-01HZX999AUDITPROOF1234567.json'));
    const parsedBundle = JSON.parse(downloadRes.body);
    assert.equal(parsedBundle.version, 'PB1');
    assert.equal(verifyBundleOffline(parsedBundle).valid, true);
  });

  test('POST /orgs/:id/engagements creates auditor engagement and configures scope', async () => {
    const orgInfo = await setupTestOrganization();
    const { orgId, admin, auditor } = orgInfo;

    const engRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/engagements`,
      headers: { authorization: `Bearer ${admin.token}` },
      payload: {
        auditorEmail: auditor.user.email,
        auditorAddress: auditor.stellarKeypair.publicKey(),
        title: 'Q4 2026 Comprehensive Audit',
        scope: {
          recordTypes: ['grant_disbursement', 'relief_supply'],
          status: 'approved',
          startDate: '2026-11-01T00:00:00Z',
          endDate: '2026-11-30T23:59:59Z',
        },
      },
    });

    assert.equal(engRes.statusCode, 201);
    const body = JSON.parse(engRes.body);
    assert.ok(body.engagement.id.startsWith('eng_'));
    assert.equal(body.engagement.title, 'Q4 2026 Comprehensive Audit');
    assert.equal(body.engagement.status, 'active');
    assert.deepEqual(body.engagement.scope.recordTypes, ['grant_disbursement', 'relief_supply']);
    assert.equal(body.auditor.id, auditor.user.id);
    assert.equal(body.auditor.address, auditor.stellarKeypair.publicKey());

    // Non-admin cannot create engagement
    const forbiddenRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/engagements`,
      headers: { authorization: `Bearer ${orgInfo.maker.token}` },
      payload: {
        auditorEmail: auditor.user.email,
        title: 'Unauthorized Audit',
      },
    });
    assert.equal(forbiddenRes.statusCode, 403);

    // List engagements
    const listRes = await app.inject({
      method: 'GET',
      url: `/api/v1/orgs/${orgId}/engagements`,
      headers: { authorization: `Bearer ${auditor.token}` },
    });
    assert.equal(listRes.statusCode, 200);
    const listBody = JSON.parse(listRes.body);
    assert.equal(listBody.count, 1);
    assert.equal(listBody.engagements[0].title, 'Q4 2026 Comprehensive Audit');
  });

  test('GET /engagements/:eid/records enforces engagement scope filtering', async () => {
    const orgInfo = await setupTestOrganization();
    const { orgId, admin, maker, checker, auditor } = orgInfo;

    // Create 3 records:
    // 1. Scoped match: grant_disbursement, approved, within date
    const rec1Id = '01HZX_MATCH_GRANT_APPROVED';
    const fieldRes1 = computeFieldRoot({ amount: '100.00' }, { amount: generateSalt() });
    const leaf1 = computeRecordLeaf({
      recordId: rec1Id,
      author: maker.keypair.publicKeyHex,
      createdAt: '2026-11-15T10:00:00Z',
      fieldRoot: fieldRes1.rootHex,
    });
    await dbHandle.db.insert(records).values({
      id: rec1Id,
      orgId,
      type: 'grant_disbursement',
      status: 'approved',
      authorKeyId: maker.key.id,
      leafHash: Buffer.from(leaf1).toString('hex'),
      fieldRoot: fieldRes1.rootHex,
      ciphertextRef: 'storage://ref1',
      seqNo: 1,
      createdAt: '2026-11-15T10:00:00Z',
    });

    // 2. Out of scope type: expense, approved
    const rec2Id = '01HZX_OUT_TYPE_EXPENSE';
    const fieldRes2 = computeFieldRoot({ amount: '200.00' }, { amount: generateSalt() });
    const leaf2 = computeRecordLeaf({
      recordId: rec2Id,
      author: maker.keypair.publicKeyHex,
      createdAt: '2026-11-16T10:00:00Z',
      fieldRoot: fieldRes2.rootHex,
    });
    await dbHandle.db.insert(records).values({
      id: rec2Id,
      orgId,
      type: 'expense',
      status: 'approved',
      authorKeyId: maker.key.id,
      leafHash: Buffer.from(leaf2).toString('hex'),
      fieldRoot: fieldRes2.rootHex,
      ciphertextRef: 'storage://ref2',
      seqNo: 2,
      createdAt: '2026-11-16T10:00:00Z',
    });

    // 3. Out of scope status: grant_disbursement, pending
    const rec3Id = '01HZX_OUT_STATUS_PENDING';
    const fieldRes3 = computeFieldRoot({ amount: '300.00' }, { amount: generateSalt() });
    const leaf3 = computeRecordLeaf({
      recordId: rec3Id,
      author: maker.keypair.publicKeyHex,
      createdAt: '2026-11-17T10:00:00Z',
      fieldRoot: fieldRes3.rootHex,
    });
    await dbHandle.db.insert(records).values({
      id: rec3Id,
      orgId,
      type: 'grant_disbursement',
      status: 'pending',
      authorKeyId: maker.key.id,
      leafHash: Buffer.from(leaf3).toString('hex'),
      fieldRoot: fieldRes3.rootHex,
      ciphertextRef: 'storage://ref3',
      seqNo: 3,
      createdAt: '2026-11-17T10:00:00Z',
    });

    // Create Engagement scoped to: grant_disbursement and approved
    const engRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/engagements`,
      headers: { authorization: `Bearer ${admin.token}` },
      payload: {
        auditorEmail: auditor.user.email,
        title: 'Grant Compliance Review',
        scope: {
          recordTypes: ['grant_disbursement'],
          status: 'approved',
          startDate: '2026-11-01T00:00:00Z',
          endDate: '2026-11-30T23:59:59Z',
        },
      },
    });
    const eid = JSON.parse(engRes.body).engagement.id;

    // Auditor queries records via GET /engagements/:eid/records
    const viewerRes = await app.inject({
      method: 'GET',
      url: `/api/v1/engagements/${eid}/records`,
      headers: { authorization: `Bearer ${auditor.token}` },
    });

    assert.equal(viewerRes.statusCode, 200);
    const viewerBody = JSON.parse(viewerRes.body);

    // Exactly 1 record matches scope
    assert.equal(viewerBody.count, 1);
    assert.equal(viewerBody.records[0].id, rec1Id);
    assert.equal(viewerBody.records[0].type, 'grant_disbursement');
    assert.equal(viewerBody.records[0].status, 'approved');

    // Unrelated user is forbidden
    const unrelatedKeypair = generateEd25519Keypair();
    const unrelatedReg = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: {
        email: 'unrelated@other.com',
        password: 'password123',
        publicKey: unrelatedKeypair.publicKeyHex,
      },
    });
    const unrelatedToken = JSON.parse(unrelatedReg.body).token;

    const unauthRes = await app.inject({
      method: 'GET',
      url: `/api/v1/engagements/${eid}/records`,
      headers: { authorization: `Bearer ${unrelatedToken}` },
    });
    assert.equal(unauthRes.statusCode, 403);
  });

  test('POST /engagements/:eid/witness executes on-chain checkpoint witnessing flow', async () => {
    const orgInfo = await setupTestOrganization();
    const data = await ingestAndAnchorRecords(orgInfo);
    const { orgId, admin, auditor } = orgInfo;

    // Create Engagement
    const engRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/engagements`,
      headers: { authorization: `Bearer ${admin.token}` },
      payload: {
        auditorEmail: auditor.user.email,
        auditorAddress: auditor.stellarKeypair.publicKey(),
        title: 'Year-End Assurance',
      },
    });
    const eid = JSON.parse(engRes.body).engagement.id;

    // 1. Prepare only mode
    const prepRes = await app.inject({
      method: 'POST',
      url: `/api/v1/engagements/${eid}/witness`,
      headers: { authorization: `Bearer ${auditor.token}` },
      payload: {
        checkpointId: data.onchainId,
        rootSeen: data.merkleRoot,
        prepareOnly: true,
      },
    });

    assert.equal(prepRes.statusCode, 200);
    const prepBody = JSON.parse(prepRes.body);
    assert.equal(prepBody.prepareOnly, true);
    assert.ok(prepBody.unsignedXdr);

    // 2. Witness on-chain with auditor keypair
    const witnessRes = await app.inject({
      method: 'POST',
      url: `/api/v1/engagements/${eid}/witness`,
      headers: { authorization: `Bearer ${auditor.token}` },
      payload: {
        checkpointId: data.onchainId,
        rootSeen: data.merkleRoot,
        auditorSecret: auditor.stellarKeypair.secret(),
      },
    });

    assert.equal(witnessRes.statusCode, 201);
    const witnessBody = JSON.parse(witnessRes.body);
    assert.equal(witnessBody.success, true);
    assert.equal(witnessBody.witness.checkpointId, data.onchainId);
    assert.equal(witnessBody.witness.auditorAddress, auditor.stellarKeypair.publicKey());
    assert.ok(witnessBody.witness.txHash);
    assert.ok(witnessBody.witness.ledger > 0);

    // Check database has witness record
    const witnessRows = await dbHandle.db
      .select()
      .from(checkpointWitnesses)
      .where(eq(checkpointWitnesses.checkpointId, data.checkpointId));
    assert.equal(witnessRows.length, 1);
    assert.equal(witnessRows[0].auditorAddress, auditor.stellarKeypair.publicKey());

    // 3. Duplicate witnessing attempt is rejected
    const dupRes = await app.inject({
      method: 'POST',
      url: `/api/v1/engagements/${eid}/witness`,
      headers: { authorization: `Bearer ${auditor.token}` },
      payload: {
        checkpointId: data.onchainId,
        rootSeen: data.merkleRoot,
        auditorSecret: auditor.stellarKeypair.secret(),
      },
    });
    assert.equal(dupRes.statusCode, 409);

    // 4. Root mismatch attempt is rejected
    const badRootRes = await app.inject({
      method: 'POST',
      url: `/api/v1/engagements/${eid}/witness`,
      headers: { authorization: `Bearer ${auditor.token}` },
      payload: {
        checkpointId: data.onchainId,
        rootSeen: 'ee'.repeat(32), // tampered root
        auditorAddress: StellarSdk.Keypair.random().publicKey(),
      },
    });
    assert.equal(badRootRes.statusCode, 400);
    assert.ok(JSON.parse(badRootRes.body).message.includes('RootMismatch'));
  });
});

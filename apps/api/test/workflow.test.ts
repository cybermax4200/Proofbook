import { test, describe, afterEach, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createDatabase, DatabaseHandle } from '../src/db/index.js';
import { buildFastifyApp } from '../src/app.js';
import { EncryptedFileStorageProvider } from '../src/records/storage.js';
import { FastifyInstance } from 'fastify';
import {
  generateEd25519Keypair,
  computeRecordLeaf,
  sign,
  generateSalt,
  computeFieldRoot,
  commitField,
  getFieldProof,
  verifyMerkleProof,
  computeEvidenceHash,
  bindEvidenceField,
} from '@proofbook/crypto';

describe('Maker-Checker Approvals, Rejection Audit Trail & Evidence Storage', () => {
  let dbHandle: DatabaseHandle;
  let app: FastifyInstance;
  let tmpStorageDir: string;
  let encryptedStorage: EncryptedFileStorageProvider;

  beforeEach(async () => {
    tmpStorageDir = await fs.mkdtemp(path.join(os.tmpdir(), 'proofbook-workflow-'));
    encryptedStorage = new EncryptedFileStorageProvider(tmpStorageDir, 'workflow-dev-master-key');
    dbHandle = await createDatabase();
    app = await buildFastifyApp({ dbHandle, storage: encryptedStorage });
  });

  afterEach(async () => {
    if (app) await app.close();
    if (dbHandle) await dbHandle.close();
    if (tmpStorageDir) {
      await fs.rm(tmpStorageDir, { recursive: true, force: true });
    }
  });

  async function setupOrgWithMakerAndChecker() {
    const makerKeypair = generateEd25519Keypair();
    const checkerKeypair = generateEd25519Keypair();

    // Register Maker (who creates the org as admin, or we add a dedicated maker & checker)
    const adminKeypair = generateEd25519Keypair();
    const adminReg = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: {
        email: 'admin@relief.org',
        password: 'password123',
        publicKey: adminKeypair.publicKeyHex,
      },
    });
    const { token: adminToken, key: adminKey, user: adminUser } = JSON.parse(adminReg.body);

    const orgRes = await app.inject({
      method: 'POST',
      url: '/api/v1/orgs',
      headers: { authorization: `Bearer ${adminToken}` },
      payload: { name: 'Relief Transparency Fund' },
    });
    const orgId = JSON.parse(orgRes.body).org.id;

    // Register Maker
    const makerReg = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: {
        email: 'maker@relief.org',
        password: 'password123',
        publicKey: makerKeypair.publicKeyHex,
      },
    });
    const { token: makerToken, key: makerKey, user: makerUser } = JSON.parse(makerReg.body);

    await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/members`,
      headers: { authorization: `Bearer ${adminToken}` },
      payload: { email: 'maker@relief.org', role: 'maker' },
    });

    // Register Checker
    const checkerReg = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: {
        email: 'checker@relief.org',
        password: 'password123',
        publicKey: checkerKeypair.publicKeyHex,
      },
    });
    const { token: checkerToken, key: checkerKey, user: checkerUser } = JSON.parse(checkerReg.body);

    await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/members`,
      headers: { authorization: `Bearer ${adminToken}` },
      payload: { email: 'checker@relief.org', role: 'checker' },
    });

    return {
      orgId,
      admin: { token: adminToken, key: adminKey, user: adminUser, keypair: adminKeypair },
      maker: { token: makerToken, key: makerKey, user: makerUser, keypair: makerKeypair },
      checker: { token: checkerToken, key: checkerKey, user: checkerUser, keypair: checkerKeypair },
    };
  }

  test('completes maker-checker approval workflow and prevents self-approval', async () => {
    const { orgId, admin, maker, checker } = await setupOrgWithMakerAndChecker();

    const recordId = '01HZXWORKFLOW0000000000001';
    const createdAt = '2026-11-09T10:00:00Z';

    const fields = {
      amount: '1250.00',
      currency: 'USD',
      payee: 'Acme Supplies Ltd',
    };
    const salts = {
      amount: generateSalt(),
      currency: generateSalt(),
      payee: generateSalt(),
    };
    const fieldResult = computeFieldRoot(fields, salts);

    // Admin (who has 'admin' role, which is allowed on /approve, AND is the author of this record)
    // creates a draft record first, then submits it to move status to 'pending'
    const leafBytes = computeRecordLeaf({
      recordId,
      author: admin.keypair.publicKeyHex,
      createdAt,
      fieldRoot: fieldResult.rootHex,
    });
    const leafHex = Buffer.from(leafBytes).toString('hex');
    const authorSigHex = Buffer.from(sign(leafBytes, admin.keypair.secretKey)).toString('hex');

    const createRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/records`,
      headers: { authorization: `Bearer ${admin.token}` },
      payload: {
        recordId,
        type: 'disbursement',
        status: 'draft',
        createdAt,
        fieldRoot: fieldResult.rootHex,
        leafHash: leafHex,
        authorKeyId: admin.key.id,
        authorSignature: authorSigHex,
        ciphertext: 'encrypted_disbursement_payload_bytes',
      },
    });
    assert.equal(createRes.statusCode, 201);
    assert.equal(JSON.parse(createRes.body).record.status, 'draft');

    // Submit record moves status to 'pending'
    const submitRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/records/${recordId}/submit`,
      headers: { authorization: `Bearer ${admin.token}` },
    });
    assert.equal(submitRes.statusCode, 200);
    assert.equal(JSON.parse(submitRes.body).record.status, 'pending');

    // 1. Author attempts to approve their own record -> MUST fail with 403 Forbidden
    const selfApproveRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/records/${recordId}/approve`,
      headers: { authorization: `Bearer ${admin.token}` },
      payload: {
        approverKeyId: admin.key.id,
        approverSignature: authorSigHex,
      },
    });
    assert.equal(selfApproveRes.statusCode, 403);
    assert.match(JSON.parse(selfApproveRes.body).message, /Author cannot approve their own record/i);

    // 2. Another Maker (without 'checker' role) attempts to approve -> MUST fail with 403 Forbidden
    const makerSigHex = Buffer.from(sign(leafBytes, maker.keypair.secretKey)).toString('hex');
    const unauthorizedRoleRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/records/${recordId}/approve`,
      headers: { authorization: `Bearer ${maker.token}` },
      payload: {
        approverKeyId: maker.key.id,
        approverSignature: makerSigHex,
      },
    });
    assert.equal(unauthorizedRoleRes.statusCode, 403);

    // 3. Checker attempts to approve with an invalid/forged signature -> MUST fail with 400 Bad Request
    const badApproveRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/records/${recordId}/approve`,
      headers: { authorization: `Bearer ${checker.token}` },
      payload: {
        approverKeyId: checker.key.id,
        approverSignature: authorSigHex, // wrong key's signature
      },
    });
    assert.equal(badApproveRes.statusCode, 400);
    assert.match(JSON.parse(badApproveRes.body).message, /Invalid approver signature/i);

    // 4. Checker signs leaf_hash and approves -> 200 OK, status becomes 'approved'
    const checkerSigHex = Buffer.from(sign(leafBytes, checker.keypair.secretKey)).toString('hex');
    const approveRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/records/${recordId}/approve`,
      headers: { authorization: `Bearer ${checker.token}` },
      payload: {
        approverKeyId: checker.key.id,
        approverSignature: checkerSigHex,
      },
    });
    assert.equal(approveRes.statusCode, 200);
    const approveBody = JSON.parse(approveRes.body);
    assert.equal(approveBody.record.status, 'approved');
    assert.ok(approveBody.record.approvedAt);
    assert.equal(approveBody.signature.kind, 'approver');
    assert.equal(approveBody.signature.signature, checkerSigHex);

    // 5. Verify GET /orgs/:id/records/:rid returns both author and approver signatures + audit trail
    const detailRes = await app.inject({
      method: 'GET',
      url: `/api/v1/orgs/${orgId}/records/${recordId}`,
      headers: { authorization: `Bearer ${checker.token}` },
    });
    assert.equal(detailRes.statusCode, 200);
    const detailBody = JSON.parse(detailRes.body);
    assert.equal(detailBody.signatures.length, 2);
    assert.deepEqual(
      detailBody.signatures.map((s: any) => s.kind).sort(),
      ['approver', 'author']
    );
    assert.ok(detailBody.auditLogs.some((l: any) => l.action === 'record.approved'));
  });

  test('executes rejection flow and logs audit reason', async () => {
    const { orgId, maker, checker } = await setupOrgWithMakerAndChecker();

    const recordId = '01HZXWORKFLOW0000000000002';
    const createdAt = '2026-11-09T10:15:00Z';
    const fieldResult = computeFieldRoot(
      { amount: '9500.00', payee: 'Unverified Vendor LLC' },
      { amount: generateSalt(), payee: generateSalt() }
    );

    const leafBytes = computeRecordLeaf({
      recordId,
      author: maker.keypair.publicKeyHex,
      createdAt,
      fieldRoot: fieldResult.rootHex,
    });
    const authorSigHex = Buffer.from(sign(leafBytes, maker.keypair.secretKey)).toString('hex');

    // Maker submits record (defaults to 'pending')
    const ingestRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/records`,
      headers: { authorization: `Bearer ${maker.token}` },
      payload: {
        recordId,
        createdAt,
        fieldRoot: fieldResult.rootHex,
        authorKeyId: maker.key.id,
        authorSignature: authorSigHex,
        ciphertext: 'encrypted_suspicious_vendor_record',
      },
    });
    assert.equal(ingestRes.statusCode, 201);
    assert.equal(JSON.parse(ingestRes.body).record.status, 'pending');

    // Reject without reason -> 400 Bad Request
    const missingReasonRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/records/${recordId}/reject`,
      headers: { authorization: `Bearer ${checker.token}` },
      payload: {},
    });
    assert.equal(missingReasonRes.statusCode, 400);

    // Checker rejects with audit reason
    const auditReason = 'Missing counter-signed vendor invoice and W-9 documentation';
    const rejectRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/records/${recordId}/reject`,
      headers: { authorization: `Bearer ${checker.token}` },
      payload: { reason: auditReason },
    });
    assert.equal(rejectRes.statusCode, 200);
    const rejectBody = JSON.parse(rejectRes.body);
    assert.equal(rejectBody.record.status, 'rejected');
    assert.equal(rejectBody.record.rejectionReason, auditReason);
    assert.equal(rejectBody.record.rejectedByUserId, checker.user.id);
    assert.ok(rejectBody.record.rejectedAt);
    assert.equal(rejectBody.auditLog.action, 'record.rejected');
    assert.equal(rejectBody.auditLog.reason, auditReason);

    // Rejecting or approving an already rejected record returns 409 Conflict
    const approveAfterRejectRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/records/${recordId}/approve`,
      headers: { authorization: `Bearer ${checker.token}` },
      payload: {
        approverKeyId: checker.key.id,
        approverSignature: Buffer.from(sign(leafBytes, checker.keypair.secretKey)).toString('hex'),
      },
    });
    assert.equal(approveAfterRejectRes.statusCode, 409);
  });

  test('binds evidence_hash: sha256:... into canonical record fields and stores encrypted attachment', async () => {
    const { orgId, maker, checker } = await setupOrgWithMakerAndChecker();

    const recordId = '01HZXWORKFLOW0000000000003';
    const createdAt = '2026-11-09T11:00:00Z';

    // 1. Raw attachment document (e.g. receipt / invoice PDF bytes)
    const rawAttachmentContent = 'INVOICE #2026-991 | Vendor: Clean Water Co | Total: 4200.00 USD';
    const expectedEvidenceHash = computeEvidenceHash(rawAttachmentContent);
    assert.ok(expectedEvidenceHash.startsWith('sha256:'));

    // 2. Bind evidence_hash into canonical record fields
    const canonicalFields = bindEvidenceField(
      {
        amount: '4200.00',
        currency: 'USD',
        payee: 'Clean Water Co',
      },
      rawAttachmentContent
    );
    assert.equal(canonicalFields.evidence_hash, expectedEvidenceHash);

    const salts = {
      amount: generateSalt(),
      currency: generateSalt(),
      evidence_hash: generateSalt(),
      payee: generateSalt(),
    };
    const fieldResult = computeFieldRoot(canonicalFields, salts);

    const leafBytes = computeRecordLeaf({
      recordId,
      author: maker.keypair.publicKeyHex,
      createdAt,
      fieldRoot: fieldResult.rootHex,
    });
    const authorSigHex = Buffer.from(sign(leafBytes, maker.keypair.secretKey)).toString('hex');

    // 3. Submit record
    const createRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/records`,
      headers: { authorization: `Bearer ${maker.token}` },
      payload: {
        recordId,
        createdAt,
        fieldRoot: fieldResult.rootHex,
        authorKeyId: maker.key.id,
        authorSignature: authorSigHex,
        ciphertext: 'encrypted_record_body_v1',
      },
    });
    assert.equal(createRes.statusCode, 201);

    // 4. Upload evidence attachment via POST /orgs/:id/records/:rid/evidence
    const clientEncryptedAttachment = 'xchacha20poly1305:encrypted_invoice_pdf_bytes';
    const evRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/records/${recordId}/evidence`,
      headers: { authorization: `Bearer ${maker.token}` },
      payload: {
        id: 'ev_invoice_991',
        sha256: expectedEvidenceHash,
        content: rawAttachmentContent,
        ciphertext: clientEncryptedAttachment,
      },
    });
    assert.equal(evRes.statusCode, 201);
    const evBody = JSON.parse(evRes.body);
    assert.equal(evBody.evidence.id, 'ev_invoice_991');
    assert.equal(evBody.evidence.sha256, expectedEvidenceHash);
    assert.ok(evBody.evidence.ciphertextRef.startsWith('encrypted-fs://'));

    // 5. Verify local file on disk is encrypted by EncryptedFileStorageProvider
    const diskPath = encryptedStorage.resolvePath(evBody.evidence.ciphertextRef);
    const rawDiskContents = await fs.readFile(diskPath, 'utf8');
    assert.ok(rawDiskContents.startsWith('pb1enc:v1:'));
    assert.equal(rawDiskContents.includes(clientEncryptedAttachment), false);

    // 6. Checker retrieves evidence, verifies evidence_hash in Merkle field tree, and approves
    const getEvRes = await app.inject({
      method: 'GET',
      url: `/api/v1/orgs/${orgId}/records/${recordId}/evidence/ev_invoice_991`,
      headers: { authorization: `Bearer ${checker.token}` },
    });
    assert.equal(getEvRes.statusCode, 200);
    const getEvBody = JSON.parse(getEvRes.body);
    assert.equal(getEvBody.ciphertext, clientEncryptedAttachment);
    assert.equal(getEvBody.evidence.sha256, expectedEvidenceHash);

    // Verify Merkle inclusion proof of `evidence_hash` against record's `fieldRoot`
    const { proof } = getFieldProof(fieldResult, 'evidence_hash');
    const evCommitment = commitField('evidence_hash', getEvBody.evidence.sha256, salts.evidence_hash);
    assert.equal(verifyMerkleProof(evCommitment, proof, fieldResult.root), true);
  });
});

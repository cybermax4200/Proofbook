import { test, describe, afterEach, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createDatabase, DatabaseHandle } from '../src/db/index.js';
import { buildFastifyApp } from '../src/app.js';
import { FastifyInstance } from 'fastify';
import {
  generateEd25519Keypair,
  generateSalt,
  computeFieldRoot,
  computeRecordLeaf,
  sign,
} from '@proofbook/crypto';

describe('Organization & Membership Routes', () => {
  let dbHandle: DatabaseHandle;
  let app: FastifyInstance;

  beforeEach(async () => {
    dbHandle = await createDatabase();
    app = await buildFastifyApp({ dbHandle });
  });

  afterEach(async () => {
    if (app) await app.close();
    if (dbHandle) await dbHandle.close();
  });

  test('creates org, lists orgs, and adds member with role', async () => {
    // 1. Register admin user
    const adminReg = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: { email: 'admin@acme.org', password: 'password123' },
    });
    const { token: adminToken } = JSON.parse(adminReg.body);

    // 2. Register second user
    const makerReg = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: { email: 'maker@acme.org', password: 'password123' },
    });
    const { token: makerToken, user: makerUser } = JSON.parse(makerReg.body);

    // 3. Admin creates org
    const createOrgRes = await app.inject({
      method: 'POST',
      url: '/api/v1/orgs',
      headers: { authorization: `Bearer ${adminToken}` },
      payload: {
        name: 'Acme Non-Profit',
        stellarAddress: 'GBHTYTJU7S52LOM3M6R63B346Y5A5R5Y63RGL7Y5R7E4P6Y3J3Y6EXAMPLE',
      },
    });
    assert.equal(createOrgRes.statusCode, 201);
    const orgId = JSON.parse(createOrgRes.body).org.id;

    // 4. Admin lists orgs
    const listOrgRes = await app.inject({
      method: 'GET',
      url: '/api/v1/orgs',
      headers: { authorization: `Bearer ${adminToken}` },
    });
    assert.equal(listOrgRes.statusCode, 200);
    const orgs = JSON.parse(listOrgRes.body).orgs;
    assert.equal(orgs.length, 1);
    assert.equal(orgs[0].id, orgId);
    assert.equal(orgs[0].role, 'admin');

    // 5. Maker cannot access org before being added
    const deniedRes = await app.inject({
      method: 'GET',
      url: `/api/v1/orgs/${orgId}`,
      headers: { authorization: `Bearer ${makerToken}` },
    });
    assert.equal(deniedRes.statusCode, 403);

    // 6. Admin adds maker to org
    const addMemberRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/members`,
      headers: { authorization: `Bearer ${adminToken}` },
      payload: {
        email: 'maker@acme.org',
        role: 'maker',
      },
    });
    assert.equal(addMemberRes.statusCode, 200);
    assert.equal(JSON.parse(addMemberRes.body).member.role, 'maker');

    // 7. Maker can now access org
    const makerAccessRes = await app.inject({
      method: 'GET',
      url: `/api/v1/orgs/${orgId}`,
      headers: { authorization: `Bearer ${makerToken}` },
    });
    assert.equal(makerAccessRes.statusCode, 200);
    const accessBody = JSON.parse(makerAccessRes.body);
    assert.equal(accessBody.myRole, 'maker');
    assert.equal(accessBody.members.length, 2);

    // 8. Maker cannot add other members (requires admin)
    const unauthorizedAdd = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/members`,
      headers: { authorization: `Bearer ${makerToken}` },
      payload: {
        email: 'admin@acme.org',
        role: 'admin',
      },
    });
    assert.equal(unauthorizedAdd.statusCode, 403);

    // 9. Admin updates member role via PATCH /orgs/:id/members/:uid and registers org signer
    const patchRes = await app.inject({
      method: 'PATCH',
      url: `/api/v1/orgs/${orgId}/members/${makerUser.id}`,
      headers: { authorization: `Bearer ${adminToken}` },
      payload: { role: 'checker' },
    });
    assert.equal(patchRes.statusCode, 200);
    assert.equal(JSON.parse(patchRes.body).member.role, 'checker');

    const signerKeys = generateEd25519Keypair();
    const signerRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/signers`,
      headers: { authorization: `Bearer ${adminToken}` },
      payload: { publicKey: signerKeys.publicKeyHex },
    });
    assert.equal(signerRes.statusCode, 201);
    assert.ok(JSON.parse(signerRes.body).signer.stellarAddress.startsWith('G'));
  });

  test('supports checkpoints, public verification, crypto-shredding, reconciliation, and engagement findings/reports', async () => {
    const makerKeys = generateEd25519Keypair();
    const checkerKeys = generateEd25519Keypair();

    // Register admin/maker, checker, and auditor
    const makerReg = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: {
        email: 'maker2@acme.org',
        password: 'password123',
        publicKey: makerKeys.publicKeyHex,
      },
    });
    const { token: makerToken, key: makerKey } = JSON.parse(makerReg.body);

    const checkerReg = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: {
        email: 'checker2@acme.org',
        password: 'password123',
        publicKey: checkerKeys.publicKeyHex,
      },
    });
    const { token: checkerToken, key: checkerKey } = JSON.parse(checkerReg.body);

    const auditorReg = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: { email: 'auditor2@firm.org', password: 'password123' },
    });
    const { token: auditorToken } = JSON.parse(auditorReg.body);

    // Create org and add checker
    const orgRes = await app.inject({
      method: 'POST',
      url: '/api/v1/orgs',
      headers: { authorization: `Bearer ${makerToken}` },
      payload: {
        name: 'Acme Ops',
        stellarAddress: 'GDGZW7GAZNBP4NGIPRUTHTIE6JRUEAWNOEXKMSXK6XYWQPRAQP2HHMRQ',
      },
    });
    const orgId = JSON.parse(orgRes.body).org.id;

    await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/members`,
      headers: { authorization: `Bearer ${makerToken}` },
      payload: { email: 'checker2@acme.org', role: 'checker' },
    });

    // Create 2 records and approve both
    for (let i = 1; i <= 2; i++) {
      const recordId = `rec_test_0${i}`;
      const createdAt = `2026-11-02T09:1${i}:00Z`;
      const fields = { amount: `${i}00.00`, currency: 'USD', payee: `Vendor ${i}` };
      const salts = {
        amount: Buffer.from(generateSalt()).toString('hex'),
        currency: Buffer.from(generateSalt()).toString('hex'),
        payee: Buffer.from(generateSalt()).toString('hex'),
      };
      const fieldRoot = computeFieldRoot(fields, salts);
      const leaf = computeRecordLeaf({
        recordId,
        author: makerKeys.publicKeyHex,
        createdAt,
        fieldRoot: fieldRoot.rootHex,
      });
      const authorSig = Buffer.from(sign(leaf, makerKeys.secretKey)).toString('hex');

      const createRecRes = await app.inject({
        method: 'POST',
        url: `/api/v1/orgs/${orgId}/records`,
        headers: { authorization: `Bearer ${makerToken}` },
        payload: {
          recordId,
          createdAt,
          fieldRoot: fieldRoot.rootHex,
          ciphertext: JSON.stringify({ fields, salts }),
          authorKeyId: makerKey.id,
          authorSignature: authorSig,
        },
      });
      assert.equal(createRecRes.statusCode, 201);

      const approverSig = Buffer.from(sign(leaf, checkerKeys.secretKey)).toString('hex');
      const approveRes = await app.inject({
        method: 'POST',
        url: `/api/v1/orgs/${orgId}/records/${recordId}/approve`,
        headers: { authorization: `Bearer ${checkerToken}` },
        payload: {
          approverKeyId: checkerKey.id,
          approverSignature: approverSig,
        },
      });
      assert.equal(approveRes.statusCode, 200);
    }

    // Trigger checkpoint via POST /api/v1/orgs/:id/checkpoints/run
    const cpRunRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/checkpoints/run`,
      headers: { authorization: `Bearer ${makerToken}` },
    });
    assert.equal(cpRunRes.statusCode, 201);
    const cpBody = JSON.parse(cpRunRes.body);
    assert.equal(cpBody.triggered, true);
    assert.equal(cpBody.recordsAnchored, 2);

    // List checkpoints
    const listCpRes = await app.inject({
      method: 'GET',
      url: `/api/v1/orgs/${orgId}/checkpoints`,
      headers: { authorization: `Bearer ${makerToken}` },
    });
    assert.equal(listCpRes.statusCode, 200);
    assert.equal(JSON.parse(listCpRes.body).checkpoints.length, 1);

    // Public verification endpoint GET /api/v1/verify/:orgAddress/:checkpointId
    const pubVerifyCp = await app.inject({
      method: 'GET',
      url: `/api/v1/verify/GDGZW7GAZNBP4NGIPRUTHTIE6JRUEAWNOEXKMSXK6XYWQPRAQP2HHMRQ/1`,
    });
    assert.equal(pubVerifyCp.statusCode, 200);
    assert.equal(JSON.parse(pubVerifyCp.body).verified, true);

    // Generate proof for record 1, then crypto-shred record 2 and verify record 1's proof still verifies!
    const proofRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/proofs`,
      headers: { authorization: `Bearer ${makerToken}` },
      payload: { recordId: 'rec_test_01' },
    });
    assert.equal(proofRes.statusCode, 200);
    const { bundle } = JSON.parse(proofRes.body);

    const shredRes = await app.inject({
      method: 'DELETE',
      url: `/api/v1/orgs/${orgId}/records/rec_test_02`,
      headers: { authorization: `Bearer ${makerToken}` },
      payload: { reason: 'GDPR erasure request' },
    });
    assert.equal(shredRes.statusCode, 200);
    assert.equal(JSON.parse(shredRes.body).shredded, true);

    // Verify record 2 ciphertext is now null
    const getShredded = await app.inject({
      method: 'GET',
      url: `/api/v1/orgs/${orgId}/records/rec_test_02`,
      headers: { authorization: `Bearer ${makerToken}` },
    });
    assert.equal(JSON.parse(getShredded.body).ciphertext, null);

    // Verify record 1 bundle via public POST /api/v1/verify/bundle still passes after sibling was shredded!
    const verifyBundleRes = await app.inject({
      method: 'POST',
      url: '/api/v1/verify/bundle',
      payload: bundle,
    });
    assert.equal(verifyBundleRes.statusCode, 200);
    assert.equal(JSON.parse(verifyBundleRes.body).valid, true);

    // Test CSV Import & Reconciliation
    const importRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/imports`,
      headers: { authorization: `Bearer ${makerToken}` },
      payload: {
        source: 'bank_csv',
        csv: 'date,amount,currency,description\n2026-11-02,100.00,USD,Vendor 1\n2026-11-03,999.00,USD,Unknown Charge',
      },
    });
    assert.equal(importRes.statusCode, 201);
    const importBody = JSON.parse(importRes.body);
    assert.equal(importBody.matchedCount, 1);
    assert.equal(importBody.unmatchedCount, 1);
    assert.equal(importBody.flags.length, 1);

    // Resolve reconciliation flag
    const resolveFlagRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/flags/${importBody.flags[0].id}/resolve`,
      headers: { authorization: `Bearer ${checkerToken}` },
      payload: { note: 'Verified bank fee' },
    });
    assert.equal(resolveFlagRes.statusCode, 200);

    // Test Auditor Engagement Requests, Findings, and Report
    const engRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/engagements`,
      headers: { authorization: `Bearer ${makerToken}` },
      payload: {
        auditorEmail: 'auditor2@firm.org',
        title: 'FY2026 Audit',
      },
    });
    assert.equal(engRes.statusCode, 201);
    const engId = JSON.parse(engRes.body).engagement.id;

    const reqCreate = await app.inject({
      method: 'POST',
      url: `/api/v1/engagements/${engId}/requests`,
      headers: { authorization: `Bearer ${auditorToken}` },
      payload: { text: 'Provide invoice for Vendor 1' },
    });
    assert.equal(reqCreate.statusCode, 201);

    const fndCreate = await app.inject({
      method: 'POST',
      url: `/api/v1/engagements/${engId}/findings`,
      headers: { authorization: `Bearer ${auditorToken}` },
      payload: { severity: 'low', text: 'Minor date formatting note', recordId: 'rec_test_01' },
    });
    assert.equal(fndCreate.statusCode, 201);

    const reportRes = await app.inject({
      method: 'POST',
      url: `/api/v1/engagements/${engId}/report`,
      headers: { authorization: `Bearer ${auditorToken}` },
    });
    assert.equal(reportRes.statusCode, 200);
    const reportBody = JSON.parse(reportRes.body).report;
    assert.equal(reportBody.requests.length, 1);
    assert.equal(reportBody.findings.length, 1);
    assert.ok(reportBody.digest.startsWith('sha256:'));
  });
});

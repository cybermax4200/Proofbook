import { test, describe, afterEach, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createDatabase, DatabaseHandle, userKeys } from '../src/db/index.js';
import { buildFastifyApp } from '../src/app.js';
import { FastifyInstance } from 'fastify';
import {
  generateEd25519Keypair,
  computeRecordLeaf,
  sign,
  generateSalt,
  computeFieldRoot,
} from '@proofbook/crypto';
import { eq } from 'drizzle-orm';

describe('Encrypted Record Ingestion & Retrieval Routes', () => {
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

  test('ingests signed encrypted record with field commitments and Ed25519 author signature', async () => {
    // 1. Author registers and registers Ed25519 key
    const authorKeypair = generateEd25519Keypair();
    const regRes = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: {
        email: 'maker@aidorg.org',
        password: 'password123',
        publicKey: authorKeypair.publicKeyHex,
      },
    });
    assert.equal(regRes.statusCode, 201);
    const { token: makerToken, key: authorKey } = JSON.parse(regRes.body);

    // 2. Create organization
    const orgRes = await app.inject({
      method: 'POST',
      url: '/api/v1/orgs',
      headers: { authorization: `Bearer ${makerToken}` },
      payload: { name: 'Global Aid Fund' },
    });
    const orgId = JSON.parse(orgRes.body).org.id;

    // 3. Client prepares record fields, salts, commitments, and field root
    const recordId = '01HZX6789ABCDEF0123456789A';
    const createdAt = '2026-11-08T14:30:00Z';

    const saltAmount = generateSalt();
    const saltPayee = generateSalt();
    const fieldResult = computeFieldRoot(
      { amount: '1500.00', payee: 'Clean Water Initiative' },
      { amount: saltAmount, payee: saltPayee }
    );
    const fieldRootHex = fieldResult.rootHex;

    // 4. Client computes record leaf and signs it
    const leafBytes = computeRecordLeaf({
      recordId,
      author: authorKeypair.publicKeyHex,
      createdAt,
      fieldRoot: fieldRootHex,
    });
    const leafHex = Buffer.from(leafBytes).toString('hex');
    const signatureBytes = sign(leafBytes, authorKeypair.secretKey);
    const signatureHex = Buffer.from(signatureBytes).toString('hex');

    // 5. Encrypted ciphertext payload (simulated XChaCha20-Poly1305 ciphertext)
    const ciphertext = 'base64:xchacha20poly1305_ciphertext_sample_payload_bytes';

    // 6. Ingest record via POST /orgs/:id/records
    const ingestRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/records`,
      headers: { authorization: `Bearer ${makerToken}` },
      payload: {
        recordId,
        type: 'grant_disbursement',
        createdAt,
        fieldRoot: fieldRootHex,
        leafHash: leafHex,
        authorKeyId: authorKey.id,
        authorSignature: signatureHex,
        ciphertext,
      },
    });

    assert.equal(ingestRes.statusCode, 201);
    const ingestBody = JSON.parse(ingestRes.body);
    assert.equal(ingestBody.record.id, recordId);
    assert.equal(ingestBody.record.seqNo, 1);
    assert.equal(ingestBody.record.status, 'pending');
    assert.equal(ingestBody.record.leafHash, leafHex);
    assert.equal(ingestBody.signature.kind, 'author');
    assert.equal(ingestBody.signature.signature, signatureHex);

    // 7. Verify retrieval of record via GET /orgs/:id/records/:rid
    const getRes = await app.inject({
      method: 'GET',
      url: `/api/v1/orgs/${orgId}/records/${recordId}`,
      headers: { authorization: `Bearer ${makerToken}` },
    });
    assert.equal(getRes.statusCode, 200);
    const getBody = JSON.parse(getRes.body);
    assert.equal(getBody.record.id, recordId);
    assert.equal(getBody.ciphertext, ciphertext);
    assert.equal(getBody.authorKey.publicKey, authorKeypair.publicKeyHex);
    assert.equal(getBody.signatures.length, 1);
    assert.equal(getBody.signatures[0].signature, signatureHex);

    // 8. Ingest a second record to verify monotonic sequence increment (seqNo = 2)
    const secondRecordId = '01HZX6789ABCDEF0123456789B';
    const leaf2Bytes = computeRecordLeaf({
      recordId: secondRecordId,
      author: authorKeypair.publicKeyHex,
      createdAt,
      fieldRoot: fieldRootHex,
    });
    const sig2Hex = Buffer.from(sign(leaf2Bytes, authorKeypair.secretKey)).toString('hex');

    const ingest2Res = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/records`,
      headers: { authorization: `Bearer ${makerToken}` },
      payload: {
        recordId: secondRecordId,
        type: 'grant_disbursement',
        createdAt,
        fieldRoot: fieldRootHex,
        authorKeyId: authorKey.id,
        authorSignature: sig2Hex,
        ciphertext: 'base64:second_record_ciphertext',
      },
    });
    assert.equal(ingest2Res.statusCode, 201);
    assert.equal(JSON.parse(ingest2Res.body).record.seqNo, 2);

    // 9. Query records list via GET /orgs/:id/records
    const listRes = await app.inject({
      method: 'GET',
      url: `/api/v1/orgs/${orgId}/records?status=pending`,
      headers: { authorization: `Bearer ${makerToken}` },
    });
    assert.equal(listRes.statusCode, 200);
    const listBody = JSON.parse(listRes.body);
    assert.equal(listBody.count, 2);
  });

  test('rejects forged signature or mismatched leaf hash', async () => {
    const keypair = generateEd25519Keypair();
    const otherKeypair = generateEd25519Keypair();

    const regRes = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: {
        email: 'forger@acme.org',
        password: 'password123',
        publicKey: keypair.publicKeyHex,
      },
    });
    const { token, key } = JSON.parse(regRes.body);

    const orgRes = await app.inject({
      method: 'POST',
      url: '/api/v1/orgs',
      headers: { authorization: `Bearer ${token}` },
      payload: { name: 'Secured Org' },
    });
    const orgId = JSON.parse(orgRes.body).org.id;

    const recordId = 'rec_forged_test';
    const createdAt = '2026-11-08T15:00:00Z';
    const fieldRoot = 'aa'.repeat(32);

    const leafBytes = computeRecordLeaf({
      recordId,
      author: keypair.publicKeyHex,
      createdAt,
      fieldRoot,
    });

    // Signature signed by a DIFFERENT key than registered author key
    const forgedSigHex = Buffer.from(sign(leafBytes, otherKeypair.secretKey)).toString('hex');

    const forgedRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/records`,
      headers: { authorization: `Bearer ${token}` },
      payload: {
        recordId,
        createdAt,
        fieldRoot,
        authorKeyId: key.id,
        authorSignature: forgedSigHex,
        ciphertext: 'encrypted_content',
      },
    });
    assert.equal(forgedRes.statusCode, 400);
    assert.match(JSON.parse(forgedRes.body).message, /signature/i);

    // Mismatched leafHash test
    const validSigHex = Buffer.from(sign(leafBytes, keypair.secretKey)).toString('hex');
    const badLeafRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/records`,
      headers: { authorization: `Bearer ${token}` },
      payload: {
        recordId,
        createdAt,
        fieldRoot,
        leafHash: 'bb'.repeat(32), // wrong leaf hash
        authorKeyId: key.id,
        authorSignature: validSigHex,
        ciphertext: 'encrypted_content',
      },
    });
    assert.equal(badLeafRes.statusCode, 400);
    assert.match(JSON.parse(badLeafRes.body).message, /does not match recomputed leaf/i);
  });

  test('rejects ingestion with revoked signing key', async () => {
    const keypair = generateEd25519Keypair();
    const regRes = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: {
        email: 'revoked_signer@acme.org',
        password: 'password123',
        publicKey: keypair.publicKeyHex,
      },
    });
    const { token, key } = JSON.parse(regRes.body);

    const orgRes = await app.inject({
      method: 'POST',
      url: '/api/v1/orgs',
      headers: { authorization: `Bearer ${token}` },
      payload: { name: 'Revocation Org' },
    });
    const orgId = JSON.parse(orgRes.body).org.id;

    // Revoke key
    await app.inject({
      method: 'DELETE',
      url: `/api/v1/auth/keys/${key.id}`,
      headers: { authorization: `Bearer ${token}` },
    });

    const recordId = 'rec_revoked_key';
    const createdAt = '2026-11-08T15:00:00Z';
    const fieldRoot = 'cc'.repeat(32);
    const leafBytes = computeRecordLeaf({
      recordId,
      author: keypair.publicKeyHex,
      createdAt,
      fieldRoot,
    });
    const signatureHex = Buffer.from(sign(leafBytes, keypair.secretKey)).toString('hex');

    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/records`,
      headers: { authorization: `Bearer ${token}` },
      payload: {
        recordId,
        createdAt,
        fieldRoot,
        authorKeyId: key.id,
        authorSignature: signatureHex,
        ciphertext: 'encrypted_content',
      },
    });
    assert.equal(res.statusCode, 400);
    assert.match(JSON.parse(res.body).message, /revoked/i);
  });
});

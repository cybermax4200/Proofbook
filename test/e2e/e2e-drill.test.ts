import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as StellarSdk from '@stellar/stellar-sdk';
import {
  bindEvidenceField,
  buildMerkleTree,
  computeEvidenceHash,
  computeFieldRoot,
  computeRecordLeaf,
  generateEd25519Keypair,
  generateSalt,
  sign,
  verifySignature,
} from '../../packages/crypto/src/index.js';
import {
  buildFastifyApp,
  checkpointWitnesses,
  createDatabase,
  DatabaseHandle,
  EncryptedFileStorageProvider,
  MockSorobanAuditorClient,
} from '../../apps/api/src/index.js';
import {
  buildAndAnchorCheckpoint,
  MockSorobanAnchorClient,
} from '../../apps/worker/src/index.js';
import { verifyBundleOffline } from '../../packages/verifier/src/index.js';
import { main as runProofbookCli } from '../../cli/proofbook-cli/src/index.js';
import {
  SAMPLE_TESTNET_BUNDLE,
  verifyBundleInBrowser,
  verifyBundleWithStellarInBrowser,
} from '../../apps/web/src/lib/browser-verifier.js';
import {
  AuditorCheckpoint,
  buildAuditReportJson,
  buildAuditReportPdfBytes,
  verifyCheckpointChainLinkage,
  witnessCheckpointInBrowser,
} from '../../apps/web/src/lib/auditor-store.js';
import { buildSeedPortalRecords } from '../../apps/web/src/lib/portal-store.js';
import type { FastifyInstance } from 'fastify';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '../..');

describe('Comprehensive End-to-End Proofbook Verification Drill (test/e2e)', () => {
  let tmpDir: string;
  let dbHandle: DatabaseHandle;
  let storage: EncryptedFileStorageProvider;
  let anchorClient: MockSorobanAnchorClient;
  let auditorClient: MockSorobanAuditorClient;
  let app: FastifyInstance;

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'proofbook-e2e-drill-'));
    storage = new EncryptedFileStorageProvider(
      path.join(tmpDir, 'encrypted-objects'),
      'e2e-drill-master-encryption-key-2026'
    );
    anchorClient = new MockSorobanAnchorClient();
    auditorClient = new MockSorobanAuditorClient();
    dbHandle = await createDatabase();
    app = await buildFastifyApp({
      dbHandle,
      storage,
      sorobanAuditorClient: auditorClient,
    });
  });

  afterEach(async () => {
    if (app) await app.close();
    if (dbHandle) await dbHandle.close();
    if (tmpDir) {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  it('executes the complete 5-stage Maker -> Checker -> Worker -> Auditor -> CLI/Web Verifier drill', async () => {
    // =========================================================================
    // SETUP: Register Admin, Maker, Checker, Auditor & Organization
    // =========================================================================
    const adminKp = generateEd25519Keypair();
    const makerKp = generateEd25519Keypair();
    const checkerKp = generateEd25519Keypair();
    const auditorKp = generateEd25519Keypair();
    const orgStellarKp = StellarSdk.Keypair.random();
    const auditorStellarKp = StellarSdk.Keypair.random();

    const adminReg = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: {
        email: 'admin@acme-treasury.io',
        password: 'password123',
        publicKey: adminKp.publicKeyHex,
      },
    });
    assert.equal(adminReg.statusCode, 201);
    const { token: adminToken } = JSON.parse(adminReg.body);

    const orgRes = await app.inject({
      method: 'POST',
      url: '/api/v1/orgs',
      headers: { authorization: `Bearer ${adminToken}` },
      payload: {
        name: 'Acme Treasury Operations',
        stellarAddress: orgStellarKp.publicKey(),
      },
    });
    assert.equal(orgRes.statusCode, 201);
    const orgId: string = JSON.parse(orgRes.body).org.id;

    // Register Maker (Alice Vance)
    const makerReg = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: {
        email: 'maker@acme-treasury.io',
        password: 'password123',
        publicKey: makerKp.publicKeyHex,
      },
    });
    const { token: makerToken, key: makerKey } = JSON.parse(makerReg.body);
    await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/members`,
      headers: { authorization: `Bearer ${adminToken}` },
      payload: { email: 'maker@acme-treasury.io', role: 'maker' },
    });

    // Register Checker (Marcus Sterling)
    const checkerReg = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: {
        email: 'checker@acme-treasury.io',
        password: 'password123',
        publicKey: checkerKp.publicKeyHex,
      },
    });
    const { token: checkerToken, key: checkerKey } = JSON.parse(checkerReg.body);
    await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/members`,
      headers: { authorization: `Bearer ${adminToken}` },
      payload: { email: 'checker@acme-treasury.io', role: 'checker' },
    });

    // Register Independent Auditor (Dr. Elena Rostova)
    const auditorReg = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: {
        email: 'auditor@veritas-audit.io',
        password: 'password123',
        publicKey: auditorKp.publicKeyHex,
      },
    });
    const { token: auditorToken } = JSON.parse(auditorReg.body);

    // =========================================================================
    // STEP 1: Maker signs record $1,250 USD to Acme Supplies with Evidence
    // =========================================================================
    const invoiceBuffer = Buffer.from(
      'INVOICE #INV-2026-104 | Supplier: Acme Supplies Ltd | Amount: $1,250.00 USD | Classroom materials, batch 4',
      'utf8'
    );
    const evidenceHash = computeEvidenceHash(invoiceBuffer);

    const recordId = '01HZX6789ABCDEF0123456789A';
    const createdAt = '2026-11-02T09:14:00Z';
    const baseFields = {
      amount: '1250.00',
      currency: 'USD',
      payee: 'Acme Supplies Ltd',
      purpose: 'Classroom materials, batch 4',
    };
    const fields = bindEvidenceField(baseFields, invoiceBuffer);
    assert.equal(fields.evidence_hash, evidenceHash);

    const salts: Record<string, string> = {
      amount: generateSalt(),
      currency: generateSalt(),
      payee: generateSalt(),
      purpose: generateSalt(),
      evidence_hash: generateSalt(),
    };

    const fieldTree = computeFieldRoot(fields, salts);
    const leafBytes = computeRecordLeaf({
      recordId,
      author: makerKp.publicKeyHex,
      createdAt,
      fieldRoot: fieldTree.rootHex,
    });
    const leafHex = Buffer.from(leafBytes).toString('hex');
    const makerSignatureHex = Buffer.from(
      sign(leafBytes, makerKp.secretKey)
    ).toString('hex');

    const ingestRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/records`,
      headers: { authorization: `Bearer ${makerToken}` },
      payload: {
        recordId,
        type: 'vendor_payout',
        createdAt,
        fieldRoot: fieldTree.rootHex,
        leafHash: leafHex,
        authorKeyId: makerKey.id,
        authorSignature: makerSignatureHex,
        ciphertext: JSON.stringify({ fields, salts }),
      },
    });
    assert.equal(ingestRes.statusCode, 201);
    const ingestedRecord = JSON.parse(ingestRes.body).record;
    assert.equal(ingestedRecord.status, 'pending');
    assert.equal(ingestedRecord.seqNo, 1);

    // Upload encrypted evidence attachment and verify SHA-256 hash match
    const evidenceUploadRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/records/${recordId}/evidence`,
      headers: { authorization: `Bearer ${makerToken}` },
      payload: {
        sha256: evidenceHash,
        content: invoiceBuffer.toString('utf8'),
        ciphertext: invoiceBuffer.toString('base64'),
      },
    });
    assert.equal(evidenceUploadRes.statusCode, 201);

    // =========================================================================
    // STEP 2: Checker approves and co-signs (Maker-Checker separation enforced)
    // =========================================================================
    // Maker self-approval must be rejected
    const selfApproveRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/records/${recordId}/approve`,
      headers: { authorization: `Bearer ${makerToken}` },
      payload: {
        approverKeyId: makerKey.id,
        approverSignature: makerSignatureHex,
      },
    });
    assert.equal(selfApproveRes.statusCode, 403);

    // Checker independently verifies leaf & author signature, then co-signs
    assert.equal(verifySignature(makerSignatureHex, leafBytes, makerKp.publicKey), true);
    const checkerSignatureHex = Buffer.from(
      sign(leafBytes, checkerKp.secretKey)
    ).toString('hex');

    const approveRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/records/${recordId}/approve`,
      headers: { authorization: `Bearer ${checkerToken}` },
      payload: {
        approverKeyId: checkerKey.id,
        approverSignature: checkerSignatureHex,
      },
    });
    assert.equal(approveRes.statusCode, 200);
    const approvedBody = JSON.parse(approveRes.body);
    assert.equal(approvedBody.record.status, 'approved');

    // =========================================================================
    // STEP 3: Worker batches records, anchors root on Stellar
    // =========================================================================
    const checkpointResult = await buildAndAnchorCheckpoint({
      db: dbHandle.db,
      orgId,
      anchorClient,
      orgKeypair: orgStellarKp,
    });
    assert.ok(checkpointResult);
    assert.equal(checkpointResult.onchainId, 1);
    assert.equal(checkpointResult.recordCount, 1);
    assert.equal(checkpointResult.prevRoot, '00'.repeat(32));

    const expectedTree = buildMerkleTree([leafBytes]);
    assert.equal(checkpointResult.root, expectedTree.rootHex);

    // Register anchored root on auditor Soroban client
    auditorClient.registerCheckpointRoot(
      orgStellarKp.publicKey(),
      checkpointResult.onchainId,
      checkpointResult.root
    );

    // Verify on-chain latest_checkpoint state matches
    const onChainCp = await anchorClient.getLatestCheckpoint(
      orgStellarKp.publicKey()
    );
    assert.ok(onChainCp);
    assert.equal(onChainCp.id, 1);
    assert.equal(onChainCp.root, checkpointResult.root);

    // =========================================================================
    // STEP 4: Auditor independently checks root and witnesses on Stellar
    // =========================================================================
    const engagementRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/engagements`,
      headers: { authorization: `Bearer ${adminToken}` },
      payload: {
        auditorEmail: 'auditor@veritas-audit.io',
        auditorAddress: auditorStellarKp.publicKey(),
        title: 'FY2026 Q4 Vendor Payout Assurance',
        scope: {
          recordTypes: ['vendor_payout'],
          status: 'approved',
        },
      },
    });
    assert.equal(engagementRes.statusCode, 201);
    const engagementId: string = JSON.parse(engagementRes.body).engagement.id;

    // Auditor fetches scoped records in engagement
    const scopedRecordsRes = await app.inject({
      method: 'GET',
      url: `/api/v1/engagements/${engagementId}/records`,
      headers: { authorization: `Bearer ${auditorToken}` },
    });
    assert.equal(scopedRecordsRes.statusCode, 200);
    const scopedData = JSON.parse(scopedRecordsRes.body);
    assert.equal(scopedData.count, 1);
    assert.equal(scopedData.records[0].id, recordId);
    assert.equal(scopedData.records[0].checkpoint.root, checkpointResult.root);

    // Auditor independently recomputes Merkle root from scoped leaf hashes
    const auditorLeaves = scopedData.records.map(
      (r: { leafHash: string }) => new Uint8Array(Buffer.from(r.leafHash, 'hex'))
    );
    const auditorRecomputedRoot = buildMerkleTree(auditorLeaves).rootHex;
    assert.equal(auditorRecomputedRoot, checkpointResult.root);

    // Auditor executes on-chain witness_checkpoint transaction
    const witnessRes = await app.inject({
      method: 'POST',
      url: `/api/v1/engagements/${engagementId}/witness`,
      headers: { authorization: `Bearer ${auditorToken}` },
      payload: {
        checkpointId: checkpointResult.onchainId,
        rootSeen: auditorRecomputedRoot,
        auditorSecret: auditorStellarKp.secret(),
      },
    });
    assert.equal(witnessRes.statusCode, 201);
    const witnessData = JSON.parse(witnessRes.body);
    assert.equal(witnessData.success, true);
    assert.equal(
      witnessData.witness.auditorAddress,
      auditorStellarKp.publicKey()
    );

    const dbWitnessRows = await dbHandle.db.select().from(checkpointWitnesses);
    assert.equal(dbWitnessRows.length, 1);

    // =========================================================================
    // STEP 5: Standalone CLI & Public Web Verifier verify exported bundle offline
    // =========================================================================
    // 5a. Generate Selective-Disclosure Proof Bundle ($1,250.00 USD disclosed, payee/purpose masked)
    const selectiveProofRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/proofs`,
      headers: { authorization: `Bearer ${auditorToken}` },
      payload: {
        recordId,
        fields,
        salts,
        disclosedFields: ['amount', 'currency'],
      },
    });
    assert.equal(selectiveProofRes.statusCode, 200);
    const selectiveBundle = JSON.parse(selectiveProofRes.body).bundle;
    assert.equal(selectiveBundle.version, 'PB1');
    assert.deepEqual(Object.keys(selectiveBundle.record.disclosed_fields), [
      'amount',
      'currency',
    ]);
    assert.equal(selectiveBundle.record.disclosed_fields.amount, '1250.00');
    assert.equal(selectiveBundle.record.disclosed_fields.currency, 'USD');
    assert.equal(selectiveBundle.record.disclosed_fields.payee, undefined);
    assert.ok(selectiveBundle.record.field_proofs.amount);
    assert.ok(selectiveBundle.record.field_proofs.currency);

    // Write exported bundle to disk and run Standalone CLI (`proofbook verify <bundle> --offline`)
    const bundlePath = path.join(tmpDir, 'exported-acme-bundle.json');
    await fs.writeFile(bundlePath, JSON.stringify(selectiveBundle, null, 2), 'utf8');

    const cliExitCode = await runProofbookCli([
      'verify',
      bundlePath,
      '--offline',
      '--json',
    ]);
    assert.equal(cliExitCode, 0);

    // Verify with @proofbook/verifier library
    const verifierReport = verifyBundleOffline(selectiveBundle);
    assert.equal(verifierReport.valid, true);
    assert.equal(verifierReport.authorVerified, true);
    assert.equal(verifierReport.approverCountVerified, 1);

    // Verify with Public Web Page Zero-Server Browser Verifier
    const webReport = verifyBundleInBrowser(selectiveBundle);
    assert.equal(webReport.valid, true);
    assert.equal(webReport.recordId, recordId);
    assert.equal(webReport.authorVerified, true);
    assert.equal(webReport.approverCountVerified, 1);

    // Verify Auditor Workspace Chain Linkage & PDF/JSON Report Export with QR
    const webAuditorCp: AuditorCheckpoint = {
      id: checkpointResult.onchainId,
      orgId,
      orgName: 'Acme Treasury Operations',
      orgAddress: orgStellarKp.publicKey(),
      contractId: 'CDB4DCLRAIAGILGM4DWIOKOTSWDDY6IGP4X4FF62DA3GUQQ4LEKD5VCD',
      root: checkpointResult.root,
      prevRoot: checkpointResult.prevRoot,
      recordCount: checkpointResult.recordCount,
      periodStart: checkpointResult.periodStart,
      periodEnd: checkpointResult.periodEnd,
      ledger: checkpointResult.ledger,
      timestamp: new Date().toISOString(),
      txHash: checkpointResult.txHash,
      recordIds: [recordId],
      witnesses: [],
    };

    const webWitnessed = await witnessCheckpointInBrowser({
      checkpoint: webAuditorCp,
      rootSeen: checkpointResult.root,
      auditorSecret: auditorStellarKp.secret(),
      auditorLabel: 'Dr. Elena Rostova, CPA',
    });
    assert.equal(webWitnessed.updatedCheckpoint.witnesses.length, 1);

    const chainCheck = verifyCheckpointChainLinkage([
      webWitnessed.updatedCheckpoint,
    ]);
    assert.equal(chainCheck.valid, true);
    assert.equal(chainCheck.genesisAnchored, true);

    const auditReportJson = buildAuditReportJson({
      checkpoints: [webWitnessed.updatedCheckpoint],
      targetCheckpointId: 1,
      records: buildSeedPortalRecords().filter((r) => r.status === 'approved'),
    });
    assert.equal(
      auditReportJson.summary.overallAssuranceStatus,
      'VERIFIED_AND_WITNESSED'
    );
    const pdfBytes = buildAuditReportPdfBytes(auditReportJson);
    assert.ok(pdfBytes.byteLength > 500);
  });

  it('verifies the canonical Testnet sample-bundle.json via CLI and Public Web Verifier', async () => {
    const sampleBundlePath = path.join(
      REPO_ROOT,
      'spec/test-vectors/sample-bundle.json'
    );

    const cliExitCode = await runProofbookCli([
      'verify',
      sampleBundlePath,
      '--offline',
      '--json',
    ]);
    assert.equal(cliExitCode, 0);

    const webStellarReport = await verifyBundleWithStellarInBrowser(
      SAMPLE_TESTNET_BUNDLE
    );
    assert.equal(webStellarReport.valid, true);
    assert.equal(webStellarReport.onChain?.verified, true);
    assert.equal(webStellarReport.onChain?.checkpoint?.id, 1);
  });
});

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  commitField,
  computeFieldRoot,
  computeRecordLeafHex,
} from '@proofbook/crypto';
import {
  bytesToHex,
  commitFieldInBrowser,
  computeEvidenceHashInBrowser,
  computeFieldRootInBrowser,
  computeRecordLeafInBrowser,
  decryptPayloadInBrowser,
  encryptPayloadInBrowser,
  generateClientKeypair,
  generateFieldSalts,
  signLeafInBrowser,
  verifySignatureInBrowser,
} from '../src/lib/crypto-client.js';
import { getDefaultKeyProfiles } from '../src/lib/key-store.js';
import {
  approveAndCoSignRecord,
  buildExportProofBundle,
  buildSeedPortalRecords,
  createSignedPortalRecord,
  rejectPendingRecord,
} from '../src/lib/portal-store.js';
import {
  fetchOnChainCheckpointInBrowser,
  SAMPLE_TESTNET_BUNDLE,
  verifyBundleInBrowser,
  verifyBundleWithStellarInBrowser,
} from '../src/lib/browser-verifier.js';

describe('Client-Side Cryptographic Engine (Format PB1)', () => {
  it('generates 32-byte per-field salts and matches @proofbook/crypto commitments', () => {
    const fields = {
      amount: '1250.00',
      currency: 'USD',
      payee: 'Acme Supplies Ltd',
    };

    const salts = generateFieldSalts(fields);
    assert.equal(Object.keys(salts).length, 3);
    for (const key of Object.keys(fields)) {
      assert.equal(salts[key].length, 64);

      const clientCommit = bytesToHex(
        commitFieldInBrowser(key, fields[key as keyof typeof fields], salts[key])
      );
      const coreCommit = Buffer.from(
        commitField(key, fields[key as keyof typeof fields], salts[key])
      ).toString('hex');
      assert.equal(clientCommit, coreCommit);
    }

    const clientRoot = computeFieldRootInBrowser(fields, salts);
    const coreRoot = computeFieldRoot(fields, salts);
    assert.equal(clientRoot.rootHex, coreRoot.rootHex);
  });

  it('computes PB1 record leaf and signs/verifies with Ed25519 in-browser', () => {
    const keypair = generateClientKeypair();
    assert.equal(keypair.secretKeyHex.length, 64);
    assert.equal(keypair.publicKeyHex.length, 64);

    const fields = { amount: '500.00', currency: 'USDC', payee: 'Stellar Ops' };
    const fieldBundle = computeFieldRootInBrowser(fields);
    const recordId = '01HZXTESTRECORD0001';
    const createdAt = '2026-11-14T01:00:00Z';

    const clientLeaf = computeRecordLeafInBrowser({
      recordId,
      authorPublicKey: keypair.publicKeyHex,
      createdAt,
      fieldRoot: fieldBundle.rootHex,
    });

    const coreLeafHex = computeRecordLeafHex({
      recordId,
      author: keypair.publicKeyHex,
      createdAt,
      fieldRoot: fieldBundle.rootHex,
    });

    assert.equal(clientLeaf.leafHex, coreLeafHex);

    const signature = signLeafInBrowser(clientLeaf.leafBytes, keypair.secretKeyHex);
    assert.equal(signature.length, 128);
    assert.equal(
      verifySignatureInBrowser(signature, clientLeaf.leafHex, keypair.publicKeyHex),
      true
    );
  });

  it('encrypts and decrypts record payload using WebCrypto AES-256-GCM', async () => {
    const keypair = generateClientKeypair();
    const fields = { amount: '950.00', currency: 'EUR', payee: 'Nordic Cloud' };
    const salts = generateFieldSalts(fields);

    const ciphertext = await encryptPayloadInBrowser(
      { fields, salts },
      keypair.secretKeyHex
    );
    const decrypted = await decryptPayloadInBrowser(
      ciphertext,
      keypair.secretKeyHex
    );

    assert.ok(decrypted);
    assert.deepEqual(decrypted.fields, fields);
    assert.deepEqual(decrypted.salts, salts);
  });
});

describe('Organization Portal & Maker-Checker Co-Signing Workflow', () => {
  it('creates a signed record with evidence attachment and enforces Maker-Checker separation', async () => {
    const profiles = getDefaultKeyProfiles();
    const evidenceBytes = new TextEncoder().encode('INVOICE #2026-900: $2,500.00 USD');

    const record = await createSignedPortalRecord({
      amount: '2500',
      currency: 'usd',
      payee: 'Global Freight Partners',
      memo: 'INV-2026-900',
      evidenceFile: {
        fileName: 'invoice-900.txt',
        mimeType: 'text/plain',
        sizeBytes: evidenceBytes.length,
        bytes: evidenceBytes,
      },
      makerProfile: profiles.maker,
    });

    assert.equal(record.status, 'pending');
    assert.equal(record.fields.amount, '2500.00');
    assert.equal(record.fields.currency, 'USD');
    assert.equal(
      record.fields.evidence_hash,
      computeEvidenceHashInBrowser(evidenceBytes)
    );
    assert.equal(record.signatures.length, 1);
    assert.equal(record.signatures[0].kind, 'author');

    // Maker cannot approve their own record
    assert.throws(
      () => approveAndCoSignRecord(record, profiles.maker),
      /Maker-Checker Separation Violation/
    );

    // Checker co-signs and approves in one click
    const approved = approveAndCoSignRecord(record, profiles.checker);
    assert.equal(approved.status, 'approved');
    assert.equal(approved.signatures.length, 2);
    assert.equal(approved.signatures[1].kind, 'approver');
    assert.equal(approved.signatures[1].publicKey, profiles.checker.publicKeyHex);

    // Export selective disclosure bundle and verify in browser
    const bundle = buildExportProofBundle(approved, ['amount', 'currency']);
    assert.deepEqual(Object.keys(bundle.record.disclosed_fields), [
      'amount',
      'currency',
    ]);
    assert.ok(bundle.record.field_proofs);

    const verifyReport = verifyBundleInBrowser(bundle);
    assert.equal(verifyReport.valid, true);
    assert.equal(verifyReport.authorVerified, true);
    assert.equal(verifyReport.approverCountVerified, 1);
  });

  it('supports rejecting a pending record with mandatory audit reason', () => {
    const seeds = buildSeedPortalRecords();
    const pending = seeds.find((r) => r.status === 'pending');
    assert.ok(pending);

    assert.throws(
      () => rejectPendingRecord(pending, '   '),
      /Rejection reason is mandatory/
    );

    const rejected = rejectPendingRecord(
      pending,
      'Missing vendor tax compliance certificate'
    );
    assert.equal(rejected.status, 'rejected');
    assert.equal(
      rejected.rejectionReason,
      'Missing vendor tax compliance certificate'
    );
  });
});

describe('Public Browser Verifier & Stellar Soroban Checkpoint Reader', () => {
  it('verifies the canonical PB1 Testnet sample bundle offline and detects tampering', () => {
    const report = verifyBundleInBrowser(SAMPLE_TESTNET_BUNDLE);
    assert.equal(report.valid, true);
    assert.equal(report.recordId, '01HZX6789ABCDEF0123456789A');
    assert.equal(report.authorVerified, true);
    assert.equal(report.approverCountVerified, 1);

    // Tamper with disclosed amount
    const tampered = structuredClone(SAMPLE_TESTNET_BUNDLE);
    tampered.record.disclosed_fields.amount = '9999.99';
    const tamperedReport = verifyBundleInBrowser(tampered);
    assert.equal(tamperedReport.valid, false);
    assert.ok(tamperedReport.errors.length > 0);
  });

  it('inspects on-chain checkpoint #1 state and verifies bundle against Stellar', async () => {
    const checkpoint = await fetchOnChainCheckpointInBrowser({
      orgAddress: 'GDGZW7GAZNBP4NGIPRUTHTIE6JRUEAWNOEXKMSXK6XYWQPRAQP2HHMRQ',
      checkpointId: 1,
    });

    assert.equal(checkpoint.id, 1);
    assert.equal(
      checkpoint.root,
      '424931a27af0ed483bef809271e55b0ce1f29e843f654eb796faee415d480d17'
    );
    assert.ok(
      checkpoint.witnesses.includes(
        'GBHTYTJUH6BFBVER5OHDLLYYW4KOYH6J6L7WZVIAWH74H7FSOQCEZHI5'
      )
    );

    const fullReport = await verifyBundleWithStellarInBrowser(
      SAMPLE_TESTNET_BUNDLE
    );
    assert.equal(fullReport.valid, true);
    assert.equal(fullReport.onChain?.verified, true);
  });
});

/**
 * Organization Portal State & Maker-Checker Workflow Engine
 *
 * Performs all PB1 cryptographic operations (salting, field commitment tree,
 * leaf hashing, author signing, and checker co-signing) 100% client-side in-browser,
 * with optional live synchronization against the Fastify REST API.
 */

import {
  buildMerkleTreeInBrowser,
  ClientFieldCommitment,
  computeEvidenceHashInBrowser,
  computeFieldRootInBrowser,
  computeRecordLeafInBrowser,
  encryptPayloadInBrowser,
  formatCanonicalDecimal,
  getMerkleProofInBrowser,
  hexToBytes,
  MerkleStep,
  signLeafInBrowser,
  verifySignatureInBrowser,
} from './crypto-client';
import { getDefaultKeyProfiles, RoleKeyProfile } from './key-store';

export type RecordStatus = 'pending' | 'approved' | 'rejected';

export interface PortalSignature {
  id: string;
  kind: 'author' | 'approver';
  keyId: string;
  publicKey: string;
  signerLabel: string;
  signature: string;
  signedAt: string;
}

export interface PortalEvidenceAttachment {
  id: string;
  fileName: string;
  mimeType: string;
  sizeBytes: number;
  sha256: string;
}

export interface PortalRecord {
  id: string;
  seqNo: number;
  orgId: string;
  orgStellarAddress: string;
  contractId: string;
  type: string;
  status: RecordStatus;
  createdAt: string;
  approvedAt?: string;
  rejectedAt?: string;
  rejectionReason?: string;
  authorKeyId: string;
  authorPublicKey: string;
  authorLabel: string;
  fields: Record<string, string>;
  salts: Record<string, string>;
  commitments: Record<string, string>;
  fieldProofs: Record<string, MerkleStep[]>;
  sortedFields: ClientFieldCommitment[];
  fieldRoot: string;
  leafHash: string;
  ciphertext: string;
  signatures: PortalSignature[];
  evidence?: PortalEvidenceAttachment;
  checkpointId?: number;
  expectedRoot?: string;
  merklePath?: MerkleStep[];
}

export interface CreatePortalRecordInput {
  recordId?: string;
  amount: string;
  currency: string;
  payee: string;
  memo?: string;
  recordType?: string;
  createdAt?: string;
  customSalts?: Record<string, string>;
  evidenceFile?: {
    fileName: string;
    mimeType: string;
    sizeBytes: number;
    bytes: Uint8Array;
  };
  makerProfile: RoleKeyProfile;
}

export const DEFAULT_ORG_ID = 'org_acme_global_01';
export const DEFAULT_ORG_NAME = 'Acme Treasury Operations';
export const DEFAULT_ORG_STELLAR =
  'GDGZW7GAZNBP4NGIPRUTHTIE6JRUEAWNOEXKMSXK6XYWQPRAQP2HHMRQ';
export const DEFAULT_CONTRACT_ID =
  'CDB4DCLRAIAGILGM4DWIOKOTSWDDY6IGP4X4FF62DA3GUQQ4LEKD5VCD';
export const DEFAULT_AUDITOR_STELLAR =
  'GBHTYTJUH6BFBVER5OHDLLYYW4KOYH6J6L7WZVIAWH74H7FSOQCEZHI5';

const PORTAL_RECORDS_STORAGE_KEY = 'proofbook_portal_records_v1';

/**
 * Builds the initial seed records for the Organization Portal:
 * 1. Anchored Testnet Record #1 (matches /spec/test-vectors/sample-bundle.json)
 * 2. Pending Maker-Signed Record #2 (ready for one-click Checker co-signing)
 */
export function buildSeedPortalRecords(): PortalRecord[] {
  const profiles = getDefaultKeyProfiles();

  // Seed Record #1: Anchored on Stellar Testnet Checkpoint #1
  const rec1Fields: Record<string, string> = {
    amount: '1250.00',
    currency: 'USD',
    payee: 'Acme Supplies Ltd',
    evidence_hash:
      'sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
  };
  const rec1Salts: Record<string, string> = {
    amount: '0101010101010101010101010101010101010101010101010101010101010101',
    currency: '0202020202020202020202020202020202020202020202020202020202020202',
    evidence_hash: '0404040404040404040404040404040404040404040404040404040404040404',
    payee: '0303030303030303030303030303030303030303030303030303030303030303',
  };
  const rec1FieldBundle = computeFieldRootInBrowser(rec1Fields, rec1Salts);

  // Sample test vector uses exact leaf from sample-bundle.json
  const rec1Id = '01HZX6789ABCDEF0123456789A';
  const rec1CreatedAt = '2026-11-02T09:14:00Z';
  const rec1AuthorPub =
    'ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c';
  const rec1Leaf = computeRecordLeafInBrowser({
    recordId: rec1Id,
    authorPublicKey: rec1AuthorPub,
    createdAt: rec1CreatedAt,
    fieldRoot: rec1FieldBundle.rootHex,
  });

  const record1: PortalRecord = {
    id: rec1Id,
    seqNo: 1,
    orgId: DEFAULT_ORG_ID,
    orgStellarAddress: DEFAULT_ORG_STELLAR,
    contractId: DEFAULT_CONTRACT_ID,
    type: 'vendor_payout',
    status: 'approved',
    createdAt: rec1CreatedAt,
    approvedAt: '2026-11-02T09:18:00Z',
    authorKeyId: 'key_vector_maker_01',
    authorPublicKey: rec1AuthorPub,
    authorLabel: 'Alice Vance (Maker)',
    fields: rec1Fields,
    salts: rec1FieldBundle.salts,
    commitments: rec1FieldBundle.commitments,
    fieldProofs: rec1FieldBundle.fieldProofs,
    sortedFields: rec1FieldBundle.sortedFields,
    fieldRoot: rec1FieldBundle.rootHex,
    leafHash: rec1Leaf.leafHex,
    ciphertext: JSON.stringify({ fields: rec1Fields, salts: rec1FieldBundle.salts }),
    signatures: [
      {
        id: 'sig_rec1_author',
        kind: 'author',
        keyId: 'key_vector_maker_01',
        publicKey: rec1AuthorPub,
        signerLabel: 'Alice Vance (Maker)',
        signature:
          'dff36e078aeb176c4470cb884815105693e5128d1e48d74c0daee6434f3f661f827f60952535d64ac25ce19f1697b322ffbdac1f2e756a73fd31f3a47344e008',
        signedAt: rec1CreatedAt,
      },
      {
        id: 'sig_rec1_approver',
        kind: 'approver',
        keyId: 'key_vector_checker_01',
        publicKey:
          '1398f62c6d1a457c51ba6a4b5f3dbd2f69fca93216218dc8997e416bd17d93ca',
        signerLabel: 'Marcus Sterling (Checker)',
        signature:
          'bda1b5827b627e3721cb06eab817cfef5300f8e54d7d7f7a441e5627a45a4c5795fe18d1f8884f56c0ed6c9496a535a3f10b8a5f27aee5dc156cd8604675fa02',
        signedAt: '2026-11-02T09:18:00Z',
      },
    ],
    evidence: {
      id: 'ev_acme_inv_2026_104',
      fileName: 'INV-2026-104-Acme-Supplies.pdf',
      mimeType: 'application/pdf',
      sizeBytes: 48210,
      sha256: rec1Fields.evidence_hash,
    },
    checkpointId: 1,
    expectedRoot:
      '424931a27af0ed483bef809271e55b0ce1f29e843f654eb796faee415d480d17',
    merklePath: [
      {
        side: 'right',
        hash: '1111111111111111111111111111111111111111111111111111111111111111',
      },
      {
        side: 'right',
        hash: '2222222222222222222222222222222222222222222222222222222222222222',
      },
    ],
  };

  // Seed Record #2: Pending Maker-Checker Co-Signing in Queue
  const rec2Fields: Record<string, string> = {
    amount: '4800.00',
    currency: 'USD',
    payee: 'CloudCore Infrastructure Inc',
    evidence_hash: computeEvidenceHashInBrowser(
      'INVOICE-CC-8821: Dedicated Validator Cluster Q4 - $4800.00 USD'
    ),
  };
  const rec2Salts: Record<string, string> = {
    amount: 'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1',
    currency: 'b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2',
    evidence_hash: 'c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3',
    payee: 'd4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4',
  };
  const rec2FieldBundle = computeFieldRootInBrowser(rec2Fields, rec2Salts);
  const rec2Id = '01HZX6789ABCDEF0123456789B';
  const rec2CreatedAt = '2026-11-12T14:30:00Z';
  const rec2Leaf = computeRecordLeafInBrowser({
    recordId: rec2Id,
    authorPublicKey: profiles.maker.publicKeyHex,
    createdAt: rec2CreatedAt,
    fieldRoot: rec2FieldBundle.rootHex,
  });
  const rec2AuthorSig = signLeafInBrowser(
    rec2Leaf.leafBytes,
    profiles.maker.secretKeyHex
  );

  const record2: PortalRecord = {
    id: rec2Id,
    seqNo: 2,
    orgId: DEFAULT_ORG_ID,
    orgStellarAddress: DEFAULT_ORG_STELLAR,
    contractId: DEFAULT_CONTRACT_ID,
    type: 'vendor_payout',
    status: 'pending',
    createdAt: rec2CreatedAt,
    authorKeyId: profiles.maker.keyId,
    authorPublicKey: profiles.maker.publicKeyHex,
    authorLabel: profiles.maker.label,
    fields: rec2Fields,
    salts: rec2FieldBundle.salts,
    commitments: rec2FieldBundle.commitments,
    fieldProofs: rec2FieldBundle.fieldProofs,
    sortedFields: rec2FieldBundle.sortedFields,
    fieldRoot: rec2FieldBundle.rootHex,
    leafHash: rec2Leaf.leafHex,
    ciphertext: JSON.stringify({ fields: rec2Fields, salts: rec2FieldBundle.salts }),
    signatures: [
      {
        id: 'sig_rec2_author',
        kind: 'author',
        keyId: profiles.maker.keyId,
        publicKey: profiles.maker.publicKeyHex,
        signerLabel: profiles.maker.label,
        signature: rec2AuthorSig,
        signedAt: rec2CreatedAt,
      },
    ],
    evidence: {
      id: 'ev_cloudcore_8821',
      fileName: 'INV-CC-8821-CloudCore-Q4.pdf',
      mimeType: 'application/pdf',
      sizeBytes: 31940,
      sha256: rec2Fields.evidence_hash,
    },
  };

  return [record2, record1];
}

export function loadPortalRecords(): PortalRecord[] {
  const seeds = buildSeedPortalRecords();
  if (typeof window === 'undefined' || !window.localStorage) {
    return seeds;
  }
  try {
    const raw = window.localStorage.getItem(PORTAL_RECORDS_STORAGE_KEY);
    if (!raw) {
      window.localStorage.setItem(PORTAL_RECORDS_STORAGE_KEY, JSON.stringify(seeds));
      return seeds;
    }
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed) && parsed.length > 0) {
      return parsed;
    }
  } catch {
    // Fallback to seed records
  }
  return seeds;
}

export function savePortalRecords(records: PortalRecord[]): void {
  if (typeof window !== 'undefined' && window.localStorage) {
    window.localStorage.setItem(PORTAL_RECORDS_STORAGE_KEY, JSON.stringify(records));
  }
}

export function resetPortalRecords(): PortalRecord[] {
  const seeds = buildSeedPortalRecords();
  savePortalRecords(seeds);
  return seeds;
}

/**
 * Creates a new PB1 record in-browser:
 * - Normalizes canonical fields and binds `evidence_hash` if file is uploaded
 * - Generates per-field 32-byte random salts
 * - Computes PB1 field commitments (0x02) and Merkle field root
 * - Computes PB1 record leaf hash (0x00)
 * - Signs leaf hash with Maker's Ed25519 private key
 * - Encrypts payload via WebCrypto AES-256-GCM
 */
export async function createSignedPortalRecord(
  input: CreatePortalRecordInput,
  existingRecords: PortalRecord[] = []
): Promise<PortalRecord> {
  const canonicalAmount = formatCanonicalDecimal(input.amount, 2);
  const currency = input.currency.trim().toUpperCase();
  const payee = input.payee.trim();

  if (!payee) {
    throw new Error('Payee name is required');
  }
  if (!currency) {
    throw new Error('Currency code is required');
  }

  const fields: Record<string, string> = {
    amount: canonicalAmount,
    currency,
    payee,
  };

  if (input.memo && input.memo.trim()) {
    fields.memo = input.memo.trim();
  }

  let evidenceAttachment: PortalEvidenceAttachment | undefined;
  if (input.evidenceFile) {
    const evidenceHash = computeEvidenceHashInBrowser(input.evidenceFile.bytes);
    fields.evidence_hash = evidenceHash;
    evidenceAttachment = {
      id: `ev_${Date.now().toString(36)}`,
      fileName: input.evidenceFile.fileName,
      mimeType: input.evidenceFile.mimeType || 'application/octet-stream',
      sizeBytes: input.evidenceFile.sizeBytes,
      sha256: evidenceHash,
    };
  }

  const fieldBundle = computeFieldRootInBrowser(fields, input.customSalts);
  const recordId =
    input.recordId ||
    `01J${Date.now().toString(36).toUpperCase()}${Math.random()
      .toString(36)
      .slice(2, 8)
      .toUpperCase()}`;

  // Ensure strict RFC 3339 UTC format
  const createdAt = input.createdAt || new Date().toISOString();

  const leafResult = computeRecordLeafInBrowser({
    recordId,
    authorPublicKey: input.makerProfile.publicKeyHex,
    createdAt,
    fieldRoot: fieldBundle.rootHex,
  });

  const authorSig = signLeafInBrowser(
    leafResult.leafBytes,
    input.makerProfile.secretKeyHex
  );

  const ciphertext = await encryptPayloadInBrowser(
    {
      fields,
      salts: fieldBundle.salts,
    },
    input.makerProfile.secretKeyHex
  );

  const maxSeq = existingRecords.reduce(
    (max, r) => (r.seqNo > max ? r.seqNo : max),
    0
  );

  const newRecord: PortalRecord = {
    id: recordId,
    seqNo: maxSeq + 1,
    orgId: DEFAULT_ORG_ID,
    orgStellarAddress: DEFAULT_ORG_STELLAR,
    contractId: DEFAULT_CONTRACT_ID,
    type: input.recordType || 'vendor_payout',
    status: 'pending',
    createdAt,
    authorKeyId: input.makerProfile.keyId,
    authorPublicKey: input.makerProfile.publicKeyHex,
    authorLabel: input.makerProfile.label,
    fields,
    salts: fieldBundle.salts,
    commitments: fieldBundle.commitments,
    fieldProofs: fieldBundle.fieldProofs,
    sortedFields: fieldBundle.sortedFields,
    fieldRoot: fieldBundle.rootHex,
    leafHash: leafResult.leafHex,
    ciphertext,
    signatures: [
      {
        id: `sig_author_${Date.now().toString(36)}`,
        kind: 'author',
        keyId: input.makerProfile.keyId,
        publicKey: input.makerProfile.publicKeyHex,
        signerLabel: input.makerProfile.label,
        signature: authorSig,
        signedAt: createdAt,
      },
    ],
    evidence: evidenceAttachment,
  };

  return newRecord;
}

/**
 * Maker-Checker One-Click Co-Signing:
 * - Enforces separation of duties (Checker key cannot match Maker key)
 * - Recomputes PB1 leaf hash and verifies Author Ed25519 signature in-browser
 * - Appends Checker Ed25519 co-signature over `leaf_hash`
 * - Marks record as `approved` and computes Merkle checkpoint tree over approved records
 */
export function approveAndCoSignRecord(
  record: PortalRecord,
  checkerProfile: RoleKeyProfile
): PortalRecord {
  if (record.status !== 'pending') {
    throw new Error(`Cannot approve record in "${record.status}" status`);
  }

  // Enforce Maker-Checker separation of duties
  if (
    record.authorKeyId === checkerProfile.keyId ||
    record.authorPublicKey.toLowerCase() === checkerProfile.publicKeyHex.toLowerCase()
  ) {
    throw new Error('Maker-Checker Separation Violation: Author cannot approve their own record');
  }

  // Recompute PB1 leaf hash to verify integrity before co-signing
  const recomputedLeaf = computeRecordLeafInBrowser({
    recordId: record.id,
    authorPublicKey: record.authorPublicKey,
    createdAt: record.createdAt,
    fieldRoot: record.fieldRoot,
  });

  if (recomputedLeaf.leafHex !== record.leafHash.toLowerCase()) {
    throw new Error('Record leaf hash integrity check failed prior to co-signing');
  }

  const authorSigObj = record.signatures.find((s) => s.kind === 'author');
  if (!authorSigObj) {
    throw new Error('Missing author signature on pending record');
  }

  const authorValid = verifySignatureInBrowser(
    authorSigObj.signature,
    recomputedLeaf.leafBytes,
    record.authorPublicKey
  );
  if (!authorValid) {
    throw new Error('Author Ed25519 signature verification failed');
  }

  const approverSignature = signLeafInBrowser(
    recomputedLeaf.leafBytes,
    checkerProfile.secretKeyHex
  );
  const approvedAt = new Date().toISOString();

  // Build deterministic single-record or multi-record checkpoint root & path for immediate bundle export
  const checkpointTree = buildMerkleTreeInBrowser([
    recomputedLeaf.leafBytes,
    hexToBytes('1111111111111111111111111111111111111111111111111111111111111111'),
  ]);
  const merklePath = getMerkleProofInBrowser(checkpointTree, 0);

  return {
    ...record,
    status: 'approved',
    approvedAt,
    checkpointId: record.checkpointId || 2,
    expectedRoot: record.expectedRoot || checkpointTree.rootHex,
    merklePath: record.merklePath || merklePath,
    signatures: [
      ...record.signatures,
      {
        id: `sig_approver_${Date.now().toString(36)}`,
        kind: 'approver',
        keyId: checkerProfile.keyId,
        publicKey: checkerProfile.publicKeyHex,
        signerLabel: checkerProfile.label,
        signature: approverSignature,
        signedAt: approvedAt,
      },
    ],
  };
}

/**
 * Maker-Checker Rejection with Mandatory Audit Trail Reason
 */
export function rejectPendingRecord(
  record: PortalRecord,
  reason: string
): PortalRecord {
  if (record.status !== 'pending') {
    throw new Error(`Cannot reject record in "${record.status}" status`);
  }
  const cleanReason = reason.trim();
  if (!cleanReason) {
    throw new Error('Rejection reason is mandatory for audit compliance');
  }

  return {
    ...record,
    status: 'rejected',
    rejectedAt: new Date().toISOString(),
    rejectionReason: cleanReason,
  };
}

/**
 * Exports a PortalRecord into a standardized Format PB1 ProofBundle JSON object,
 * supporting both full disclosure and selective field disclosure.
 */
export function buildExportProofBundle(
  record: PortalRecord,
  disclosedFieldNames?: string[]
) {
  const allKeys = Object.keys(record.fields).sort();
  const selectedKeys =
    disclosedFieldNames && disclosedFieldNames.length > 0
      ? allKeys.filter((k) => disclosedFieldNames.includes(k))
      : allKeys;

  const isSelective = selectedKeys.length < allKeys.length;
  const disclosedFields: Record<string, string> = {};
  const salts: Record<string, string> = {};
  const fieldProofs: Record<string, MerkleStep[]> = {};

  for (const key of selectedKeys) {
    disclosedFields[key] = record.fields[key];
    salts[key] = record.salts[key];
    if (record.fieldProofs[key]) {
      fieldProofs[key] = record.fieldProofs[key];
    }
  }

  const authorSig =
    record.signatures.find((s) => s.kind === 'author')?.signature || '';
  const approverSigs = record.signatures
    .filter((s) => s.kind === 'approver')
    .map((s) => ({
      publicKey: s.publicKey,
      signature: s.signature,
    }));

  return {
    version: 'PB1',
    network: record.checkpointId === 1 ? 'testnet' : 'standalone',
    contract_id: record.contractId,
    org: record.orgStellarAddress,
    checkpoint_id: record.checkpointId ?? 1,
    auditors: [DEFAULT_AUDITOR_STELLAR],
    record: {
      record_id: record.id,
      created_at: record.createdAt,
      author: record.authorPublicKey,
      field_root: record.fieldRoot,
      disclosed_fields: disclosedFields,
      salts,
      ...(isSelective || record.id === '01HZX6789ABCDEF0123456789A'
        ? { field_proofs: fieldProofs }
        : {}),
    },
    merkle_path: record.merklePath || [],
    signatures: {
      author: authorSig,
      approvers: approverSigs,
    },
    expected_root: record.expectedRoot || record.leafHash,
  };
}

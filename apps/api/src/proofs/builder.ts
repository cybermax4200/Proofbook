import { eq, and } from 'drizzle-orm';
import type { AppDatabase } from '../db/index.js';
import {
  records,
  userKeys,
  recordSignatures,
  checkpoints,
  checkpointRecords,
  orgs,
  engagements,
} from '../db/schema.js';
import { extractMerkleProofFromDb } from '../db/merkle.js';
import {
  computeFieldRoot,
  getFieldProof,
  MerkleProofStep,
} from '@proofbook/crypto';
import {
  ProofBundle,
  verifyBundleOffline,
  VerificationReport,
} from '@proofbook/verifier';
import type { StorageProvider } from '../records/storage.js';

export interface GenerateProofBundleOptions {
  db: AppDatabase;
  storage?: StorageProvider;
  orgId: string;
  recordId: string;
  fields?: Record<string, string>;
  salts?: Record<string, string>;
  disclosedFields?: string[];
  network?: string;
  contractId?: string;
  auditor?: string;
}

export interface GenerateProofBundleResult {
  bundle: ProofBundle;
  verification: VerificationReport;
}

/**
 * Generates a standardized PB1 Proof Bundle for an anchored record,
 * supporting full disclosure or selective disclosure with Merkle field inclusion proofs.
 */
export async function generateProofBundle(
  options: GenerateProofBundleOptions
): Promise<GenerateProofBundleResult> {
  const { db, orgId, recordId, storage } = options;

  // 1. Fetch Organization
  const orgRows = await db.select().from(orgs).where(eq(orgs.id, orgId));
  if (orgRows.length === 0) {
    throw new Error(`Organization "${orgId}" not found`);
  }
  const org = orgRows[0];

  // 2. Fetch Record
  const recordRows = await db
    .select()
    .from(records)
    .where(and(eq(records.id, recordId), eq(records.orgId, orgId)));
  if (recordRows.length === 0) {
    throw new Error(`Record "${recordId}" not found in organization "${orgId}"`);
  }
  const record = recordRows[0];

  // 3. Fetch Author Key
  const authorKeyRows = await db
    .select()
    .from(userKeys)
    .where(eq(userKeys.id, record.authorKeyId));
  if (authorKeyRows.length === 0) {
    throw new Error(`Author key "${record.authorKeyId}" not found`);
  }
  const authorPublicKey = authorKeyRows[0].publicKey;

  // 4. Fetch Record Signatures
  const sigRows = await db
    .select()
    .from(recordSignatures)
    .where(eq(recordSignatures.recordId, recordId));

  const authorSigRow = sigRows.find((s) => s.kind === 'author');
  if (!authorSigRow) {
    throw new Error(`Record "${recordId}" is missing an author signature`);
  }
  const authorSignature = authorSigRow.signature;

  const approverSigRows = sigRows.filter((s) => s.kind === 'approver');
  const approvers: Array<{ publicKey: string; signature: string }> = [];
  for (const appSig of approverSigRows) {
    const appKeyRows = await db
      .select()
      .from(userKeys)
      .where(eq(userKeys.id, appSig.keyId));
    if (appKeyRows.length > 0) {
      approvers.push({
        publicKey: appKeyRows[0].publicKey,
        signature: appSig.signature,
      });
    }
  }

  // 5. Fetch Checkpoint & Leaf Index
  const cpRecordRows = await db
    .select({
      checkpointId: checkpoints.id,
      onchainId: checkpoints.onchainId,
      root: checkpoints.root,
      leafIndex: checkpointRecords.leafIndex,
    })
    .from(checkpointRecords)
    .innerJoin(checkpoints, eq(checkpointRecords.checkpointId, checkpoints.id))
    .where(eq(checkpointRecords.recordId, recordId));

  if (cpRecordRows.length === 0) {
    throw new Error(`Record "${recordId}" has not been anchored in a checkpoint yet`);
  }
  const cp = cpRecordRows[0];

  // 6. Extract Merkle inclusion proof from persisted Merkle nodes
  const merklePath = await extractMerkleProofFromDb(db, cp.checkpointId, cp.leafIndex);

  // 7. Resolve Fields & Salts
  let resolvedFields = options.fields;
  let resolvedSalts = options.salts;

  if ((!resolvedFields || !resolvedSalts) && storage) {
    try {
      const rawCiphertext = await storage.get(record.ciphertextRef);
      if (rawCiphertext) {
        const parsed = JSON.parse(rawCiphertext);
        if (parsed.fields && parsed.salts) {
          resolvedFields = resolvedFields || parsed.fields;
          resolvedSalts = resolvedSalts || parsed.salts;
        } else if (parsed.data?.fields && parsed.data?.salts) {
          resolvedFields = resolvedFields || parsed.data.fields;
          resolvedSalts = resolvedSalts || parsed.data.salts;
        }
      }
    } catch {
      // Ciphertext is encrypted or non-JSON payload
    }
  }

  if (!resolvedFields || !resolvedSalts) {
    throw new Error('Fields and salts are required to generate proof bundle');
  }

  // 8. Verify field commitments & compute field root
  const fieldRootRes = computeFieldRoot(resolvedFields, resolvedSalts);
  if (fieldRootRes.rootHex.toLowerCase() !== record.fieldRoot.toLowerCase()) {
    throw new Error(
      `Field root mismatch: recomputed root "${fieldRootRes.rootHex}" does not match record field_root "${record.fieldRoot}"`
    );
  }

  // 9. Selective Disclosure vs Full Disclosure
  const allFieldNames = Object.keys(resolvedFields).sort();
  const requestedFields =
    options.disclosedFields && options.disclosedFields.length > 0
      ? options.disclosedFields
      : allFieldNames;

  const isSelective = requestedFields.length < allFieldNames.length;
  const disclosed_fields: Record<string, string> = {};
  const salts: Record<string, string> = {};
  let field_proofs: Record<string, MerkleProofStep[]> | undefined = undefined;

  if (isSelective) {
    field_proofs = {};
    for (const fname of requestedFields) {
      if (resolvedFields[fname] === undefined) {
        throw new Error(`Disclosed field "${fname}" does not exist in record`);
      }
      disclosed_fields[fname] = resolvedFields[fname];
      const saltVal = resolvedSalts[fname];
      salts[fname] = typeof saltVal === 'string' ? saltVal : Buffer.from(saltVal).toString('hex');

      const fp = getFieldProof(fieldRootRes, fname);
      field_proofs[fname] = fp.proof;
    }
  } else {
    for (const fname of allFieldNames) {
      disclosed_fields[fname] = resolvedFields[fname];
      const saltVal = resolvedSalts[fname];
      salts[fname] = typeof saltVal === 'string' ? saltVal : Buffer.from(saltVal).toString('hex');
    }
  }

  // 10. Fetch Active Auditor Addresses for this Org
  const activeEngs = await db
    .select({ auditorAddress: engagements.auditorAddress })
    .from(engagements)
    .where(and(eq(engagements.orgId, orgId), eq(engagements.status, 'active')));

  const auditorAddresses = activeEngs
    .map((e) => e.auditorAddress)
    .filter((a): a is string => Boolean(a && a.trim()));

  if (options.auditor && !auditorAddresses.includes(options.auditor)) {
    auditorAddresses.push(options.auditor);
  }

  // 11. Assemble PB1 Proof Bundle
  const bundle: ProofBundle = {
    version: 'PB1',
    network: options.network || process.env.STELLAR_NETWORK || 'testnet',
    contract_id: options.contractId || process.env.PROOFBOOK_CONTRACT_ID || undefined,
    org: org.stellarAddress || org.id,
    checkpoint_id: cp.onchainId ?? undefined,
    auditors: auditorAddresses.length > 0 ? auditorAddresses : undefined,
    record: {
      record_id: record.id,
      created_at: record.createdAt,
      author: authorPublicKey,
      field_root: record.fieldRoot,
      disclosed_fields,
      salts,
      field_proofs,
    },
    merkle_path: merklePath,
    signatures: {
      author: authorSignature,
      approvers: approvers.length > 0 ? approvers : undefined,
    },
    expected_root: cp.root,
  };

  // 12. Self-verify using PB1 offline verifier
  const verification = verifyBundleOffline(bundle);
  if (!verification.valid) {
    throw new Error(
      `Generated bundle failed PB1 verification: ${verification.errors.join('; ')}`
    );
  }

  return {
    bundle,
    verification,
  };
}

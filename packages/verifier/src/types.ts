import type { MerkleProofStep } from '@proofbook/crypto';

export interface DisclosedFields {
  [fieldName: string]: string;
}

export interface FieldSalts {
  [fieldName: string]: string;
}

export interface FieldProofs {
  [fieldName: string]: MerkleProofStep[];
}

export interface ApproverSignatureInfo {
  publicKey: string;
  signature: string;
}

export interface ProofBundleRecord {
  record_id: string;
  created_at: string;
  author: string; // Ed25519 pubkey (hex or G... or ed25519:...)
  field_root?: string; // 64-char hex
  disclosed_fields: DisclosedFields;
  salts: FieldSalts;
  field_proofs?: FieldProofs;
  approvers?: string[]; // Checker public keys if signatures.approvers is an array of raw signature strings
}

export interface ProofBundleSignatures {
  author: string; // 128-char hex signature
  approvers?: Array<string | ApproverSignatureInfo>;
}

export interface ProofBundle {
  version: 'PB1' | string;
  network?: 'testnet' | 'public' | 'standalone' | string;
  contract_id?: string;
  org?: string; // Stellar G... address
  checkpoint_id?: number;
  record: ProofBundleRecord;
  merkle_path: MerkleProofStep[];
  signatures: ProofBundleSignatures;
  expected_root: string;
}

export interface VerificationStep {
  name: string;
  passed: boolean;
  message: string;
  details?: Record<string, unknown>;
}

export interface OnChainCheckpointReport {
  verified: boolean;
  checkpointId: number;
  contractId: string;
  org: string;
  anchoredRoot: string;
  prevRoot: string;
  recordCount: bigint;
  periodStart: bigint;
  periodEnd: bigint;
  ledger: number;
  timestamp: bigint;
  witnesses: Array<{ auditor: string; ledger?: number }>;
  message?: string;
}

export interface VerificationReport {
  valid: boolean;
  version: string;
  recordId: string;
  recomputedFieldRoot: string;
  recomputedLeaf: string;
  recomputedMerkleRoot: string;
  expectedRoot: string;
  authorVerified: boolean;
  approverCountVerified: number;
  approverTotal: number;
  steps: VerificationStep[];
  onChain?: OnChainCheckpointReport;
  errors: string[];
}

export interface VerifyBundleOptions {
  skipBlockchain?: boolean;
  rpcUrl?: string;
  networkPassphrase?: string;
  contractId?: string;
  auditorsToCheck?: string[];
}

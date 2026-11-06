import {
  commitField,
  computeFieldRoot,
  computeRecordLeafHex,
  verifyMerkleProof,
  verifySignature,
  hashInternalNode,
} from '@proofbook/crypto';
import type {
  ProofBundle,
  VerificationReport,
  VerificationStep,
  ApproverSignatureInfo,
} from './types.js';

/**
 * Recomputes the Merkle root from a leaf and an inclusion proof path.
 */
export function evaluateMerklePath(
  leafHex: string,
  path: Array<{ side: 'left' | 'right'; hash: string }>
): string {
  let current = Buffer.from(leafHex.startsWith('0x') ? leafHex.slice(2) : leafHex, 'hex');

  for (const step of path) {
    const sibling = Buffer.from(step.hash.startsWith('0x') ? step.hash.slice(2) : step.hash, 'hex');
    if (step.side === 'left') {
      current = Buffer.from(hashInternalNode(sibling, current));
    } else {
      current = Buffer.from(hashInternalNode(current, sibling));
    }
  }

  return current.toString('hex');
}

/**
 * Performs standalone, zero-network verification of a Proofbook PB1 bundle.
 */
export function verifyBundleOffline(bundle: ProofBundle): VerificationReport {
  const steps: VerificationStep[] = [];
  const errors: string[] = [];

  // 1. PB1 Specification & Header Check
  if (!bundle || bundle.version !== 'PB1') {
    const msg = `Unsupported or missing format version: "${bundle?.version}" (expected "PB1")`;
    errors.push(msg);
    steps.push({ name: 'Format Version', passed: false, message: msg });
  } else {
    steps.push({ name: 'Format Version', passed: true, message: 'Format PB1 valid' });
  }

  const record = bundle.record;
  if (!record || !record.record_id || !record.created_at || !record.author) {
    const msg = 'Malformed bundle record: missing record_id, created_at, or author';
    errors.push(msg);
    steps.push({ name: 'Record Header', passed: false, message: msg });
  } else {
    steps.push({
      name: 'Record Header',
      passed: true,
      message: `Record ${record.record_id} header valid`,
    });
  }

  // 2. Field Commitments & Field Root
  let recomputedFieldRoot = '';
  const disclosedFields = record?.disclosed_fields || {};
  const salts = record?.salts || {};
  const fieldProofs = record?.field_proofs;
  const fieldNames = Object.keys(disclosedFields);

  if (fieldNames.length === 0) {
    const msg = 'Bundle contains zero disclosed fields';
    errors.push(msg);
    steps.push({ name: 'Field Commitments', passed: false, message: msg });
  } else {
    let allCommitmentsValid = true;

    // Check individual commitments
    for (const name of fieldNames) {
      const val = disclosedFields[name];
      const salt = salts[name];
      if (!salt) {
        const msg = `Missing salt for disclosed field: "${name}"`;
        errors.push(msg);
        allCommitmentsValid = false;
        continue;
      }

      try {
        const commitment = commitField(name, val, salt);
        const commitmentHex = Buffer.from(commitment).toString('hex');

        // If field proof is provided for this field, check it against record.field_root
        if (fieldProofs && fieldProofs[name]) {
          if (!record.field_root) {
            const msg = `Field proof provided for "${name}" but record.field_root is missing`;
            errors.push(msg);
            allCommitmentsValid = false;
          } else {
            const proofValid = verifyMerkleProof(commitment, fieldProofs[name], record.field_root);
            if (!proofValid) {
              const msg = `Merkle proof verification failed for field "${name}" against field root`;
              errors.push(msg);
              allCommitmentsValid = false;
            }
          }
        }
      } catch (err: any) {
        const msg = `Error computing commitment for field "${name}": ${err.message}`;
        errors.push(msg);
        allCommitmentsValid = false;
      }
    }

    // Determine field root
    if (fieldProofs && Object.keys(fieldProofs).length > 0) {
      // Selective disclosure with field proofs
      recomputedFieldRoot = record.field_root || '';
      steps.push({
        name: 'Field Commitments (Selective Disclosure)',
        passed: allCommitmentsValid && Boolean(recomputedFieldRoot),
        message: allCommitmentsValid
          ? `Verified ${fieldNames.length} disclosed field(s) against field root`
          : 'Field commitment verification failed',
      });
    } else {
      // Full disclosure: recompute entire field root
      try {
        const computed = computeFieldRoot(disclosedFields, salts);
        recomputedFieldRoot = computed.rootHex;

        if (record.field_root && record.field_root.toLowerCase() !== recomputedFieldRoot.toLowerCase()) {
          const msg = `Computed field root (${recomputedFieldRoot}) does not match expected record.field_root (${record.field_root})`;
          errors.push(msg);
          steps.push({ name: 'Field Root Match', passed: false, message: msg });
        } else {
          steps.push({
            name: 'Field Root',
            passed: allCommitmentsValid,
            message: `Field root recomputed: ${recomputedFieldRoot.slice(0, 16)}...`,
          });
        }
      } catch (err: any) {
        const msg = `Failed to compute field root: ${err.message}`;
        errors.push(msg);
        steps.push({ name: 'Field Root', passed: false, message: msg });
      }
    }
  }

  // 3. Recompute Record Leaf
  let recomputedLeaf = '';
  if (record && recomputedFieldRoot) {
    try {
      recomputedLeaf = computeRecordLeafHex({
        recordId: record.record_id,
        author: record.author,
        createdAt: record.created_at,
        fieldRoot: recomputedFieldRoot,
      });

      steps.push({
        name: 'Record Leaf',
        passed: true,
        message: `Recomputed leaf: ${recomputedLeaf.slice(0, 16)}...`,
      });
    } catch (err: any) {
      const msg = `Failed to recompute record leaf: ${err.message}`;
      errors.push(msg);
      steps.push({ name: 'Record Leaf', passed: false, message: msg });
    }
  }

  // 4. Merkle Path to Expected Checkpoint Root
  let recomputedMerkleRoot = '';
  const expectedRoot = (bundle.expected_root || '').toLowerCase();

  if (recomputedLeaf && bundle.merkle_path) {
    try {
      recomputedMerkleRoot = evaluateMerklePath(recomputedLeaf, bundle.merkle_path).toLowerCase();
      const pathValid = recomputedMerkleRoot === expectedRoot;

      if (!pathValid) {
        const msg = `Merkle path resulted in root ${recomputedMerkleRoot}, but expected ${expectedRoot}`;
        errors.push(msg);
        steps.push({ name: 'Merkle Path', passed: false, message: msg });
      } else {
        steps.push({
          name: 'Merkle Path',
          passed: true,
          message: `Merkle path to root OK (${bundle.merkle_path.length} steps)`,
        });
      }
    } catch (err: any) {
      const msg = `Error verifying Merkle path: ${err.message}`;
      errors.push(msg);
      steps.push({ name: 'Merkle Path', passed: false, message: msg });
    }
  }

  // 5. Signatures Check
  // 5a. Author Signature
  let authorVerified = false;
  if (recomputedLeaf && bundle.signatures?.author && record?.author) {
    try {
      authorVerified = verifySignature(bundle.signatures.author, recomputedLeaf, record.author);
      if (!authorVerified) {
        const msg = 'Author Ed25519 signature is INVALID for recomputed leaf';
        errors.push(msg);
        steps.push({ name: 'Author Signature', passed: false, message: msg });
      } else {
        steps.push({ name: 'Author Signature', passed: true, message: 'Author signature OK' });
      }
    } catch (err: any) {
      const msg = `Failed to verify author signature: ${err.message}`;
      errors.push(msg);
      steps.push({ name: 'Author Signature', passed: false, message: msg });
    }
  } else {
    const msg = 'Missing author signature or author public key';
    errors.push(msg);
    steps.push({ name: 'Author Signature', passed: false, message: msg });
  }

  // 5b. Checker / Approver Signatures
  let approverCountVerified = 0;
  const approvers = bundle.signatures?.approvers || [];
  const approverTotal = approvers.length;

  if (approverTotal > 0 && recomputedLeaf) {
    let allApproversValid = true;

    for (let i = 0; i < approverTotal; i++) {
      const item = approvers[i];
      let pubKey: string | undefined;
      let sig: string | undefined;

      if (typeof item === 'object' && 'publicKey' in item && 'signature' in item) {
        pubKey = item.publicKey;
        sig = item.signature;
      } else if (typeof item === 'string') {
        if (item.includes(':')) {
          // Format: "pubkey:signature" or "ed25519:pubkey:signature"
          const parts = item.split(':');
          if (parts.length === 2) {
            pubKey = parts[0];
            sig = parts[1];
          } else if (parts.length === 3 && parts[0] === 'ed25519') {
            pubKey = parts[1];
            sig = parts[2];
          }
        } else if (record.approvers && record.approvers[i]) {
          pubKey = record.approvers[i];
          sig = item;
        }
      }

      if (!pubKey || !sig) {
        const msg = `Approver signature at index ${i} is missing matching public key`;
        errors.push(msg);
        allApproversValid = false;
        continue;
      }

      const valid = verifySignature(sig, recomputedLeaf, pubKey);
      if (valid) {
        approverCountVerified++;
      } else {
        const msg = `Approver signature ${i + 1} (${pubKey.slice(0, 10)}...) is INVALID`;
        errors.push(msg);
        allApproversValid = false;
      }
    }

    steps.push({
      name: 'Approver Signatures',
      passed: allApproversValid && approverCountVerified === approverTotal,
      message: `Approver signatures OK (${approverCountVerified} of ${approverTotal} verified)`,
    });
  }

  const valid = errors.length === 0;

  return {
    valid,
    version: bundle.version || 'unknown',
    recordId: record?.record_id || 'unknown',
    recomputedFieldRoot,
    recomputedLeaf,
    recomputedMerkleRoot,
    expectedRoot,
    authorVerified,
    approverCountVerified,
    approverTotal,
    steps,
    errors,
  };
}

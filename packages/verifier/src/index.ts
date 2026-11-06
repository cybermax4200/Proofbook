/**
 * Proofbook Stateless Verifier Engine (PB1)
 */
import { verifyBundleOffline, evaluateMerklePath } from './verify-bundle.js';
import { verifyOnChainCheckpoint } from './stellar-reader.js';
import type {
  ProofBundle,
  VerificationReport,
  VerifyBundleOptions,
} from './types.js';

export * from './types.js';
export * from './verify-bundle.js';
export * from './stellar-reader.js';

/**
 * Verifies a Proofbook PB1 proof bundle both cryptographically and on Stellar.
 */
export async function verifyProofBundle(
  bundle: ProofBundle,
  options: VerifyBundleOptions = {}
): Promise<VerificationReport> {
  // 1. Standalone cryptographic verification
  const report = verifyBundleOffline(bundle);

  // If already invalid or offline verification requested, return early
  if (options.skipBlockchain || bundle.network === 'standalone') {
    return report;
  }

  // 2. On-chain verification via Stellar RPC
  if (!bundle.contract_id && !options.contractId) {
    report.steps.push({
      name: 'On-Chain Checkpoint',
      passed: true,
      message: 'Skipped on-chain verification (no contract_id specified)',
    });
    return report;
  }

  if (!bundle.org) {
    const msg = 'Cannot verify on-chain: missing org address in bundle';
    report.errors.push(msg);
    report.steps.push({
      name: 'On-Chain Checkpoint',
      passed: false,
      message: msg,
    });
    report.valid = false;
    return report;
  }

  try {
    const onChainReport = await verifyOnChainCheckpoint(bundle, {
      rpcUrl: options.rpcUrl,
      networkPassphrase: options.networkPassphrase,
      contractId: options.contractId,
      auditorsToCheck: options.auditorsToCheck,
    });

    report.onChain = onChainReport;

    if (!onChainReport.verified) {
      report.valid = false;
      const msg = onChainReport.message || 'On-chain checkpoint root does not match expected root';
      report.errors.push(msg);
      report.steps.push({
        name: 'On-Chain Checkpoint',
        passed: false,
        message: msg,
      });
    } else {
      report.steps.push({
        name: 'On-Chain Checkpoint',
        passed: true,
        message: `On-chain checkpoint #${onChainReport.checkpointId} root matches (ledger ${onChainReport.ledger})`,
      });
    }
  } catch (err: any) {
    report.valid = false;
    const msg = `On-chain verification error: ${err.message}`;
    report.errors.push(msg);
    report.steps.push({
      name: 'On-Chain Checkpoint',
      passed: false,
      message: msg,
    });
  }

  return report;
}

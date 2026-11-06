import dns from 'node:dns';
// Ensure IPv4 first to avoid unreachable IPv6 timeouts in certain environments
try {
  dns.setDefaultResultOrder('ipv4first');
} catch {
  // Ignore in environments where setDefaultResultOrder is unavailable
}

import * as StellarSdk from '@stellar/stellar-sdk';
import type { ProofBundle, OnChainCheckpointReport } from './types.js';

export const TESTNET_RPC_URL = 'https://soroban-testnet.stellar.org';
export const TESTNET_NETWORK_PASSPHRASE = 'Test SDF Network ; September 2015';
export const PUBLIC_RPC_URL = 'https://soroban.stellar.org';
export const PUBLIC_NETWORK_PASSPHRASE = 'Public Global Stellar Network ; September 2015';

// Zero-funded placeholder address for view-only simulation calls
const DUMMY_SOURCE_ACCOUNT = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF';

export interface StellarReaderOptions {
  rpcUrl?: string;
  networkPassphrase?: string;
  contractId?: string;
  auditorsToCheck?: string[];
}

export interface CheckpointData {
  id: number;
  root: string;
  prevRoot: string;
  recordCount: bigint;
  periodStart: bigint;
  periodEnd: bigint;
  ledger: number;
  timestamp: bigint;
}

/**
 * Safely decodes contract Checkpoint ScVal or JS object into CheckpointData.
 */
export function parseCheckpointData(raw: any): CheckpointData {
  const rootBuf = Buffer.isBuffer(raw.root)
    ? raw.root
    : raw.root instanceof Uint8Array
      ? Buffer.from(raw.root)
      : Buffer.from(raw.root || []);

  const prevRootBuf = Buffer.isBuffer(raw.prev_root)
    ? raw.prev_root
    : raw.prev_root instanceof Uint8Array
      ? Buffer.from(raw.prev_root)
      : Buffer.from(raw.prev_root || []);

  return {
    id: Number(raw.id),
    root: rootBuf.toString('hex'),
    prevRoot: prevRootBuf.toString('hex'),
    recordCount: BigInt(raw.record_count),
    periodStart: BigInt(raw.period_start),
    periodEnd: BigInt(raw.period_end),
    ledger: Number(raw.ledger),
    timestamp: BigInt(raw.timestamp),
  };
}

/**
 * Reads and verifies checkpoint state directly from Stellar Soroban RPC.
 */
export async function verifyOnChainCheckpoint(
  bundle: ProofBundle,
  options: StellarReaderOptions = {}
): Promise<OnChainCheckpointReport> {
  const isPublic = bundle.network === 'public' || bundle.network === 'mainnet';
  const rpcUrl =
    options.rpcUrl || (isPublic ? PUBLIC_RPC_URL : TESTNET_RPC_URL);
  const networkPassphrase =
    options.networkPassphrase ||
    (isPublic ? PUBLIC_NETWORK_PASSPHRASE : TESTNET_NETWORK_PASSPHRASE);
  const contractId = options.contractId || bundle.contract_id;
  const org = bundle.org;

  if (!contractId) {
    throw new Error('Missing contract_id in bundle and options');
  }
  if (!org) {
    throw new Error('Missing org address in bundle');
  }

  const server = new StellarSdk.rpc.Server(rpcUrl, { allowHttp: rpcUrl.startsWith('http://') });
  const contract = new StellarSdk.Contract(contractId);
  const dummyAccount = new StellarSdk.Account(DUMMY_SOURCE_ACCOUNT, '0');

  const orgAddressScVal = new StellarSdk.Address(org).toScVal();
  const checkpointId = bundle.checkpoint_id;

  // 1. Fetch Checkpoint via simulation
  let simTx: StellarSdk.Transaction;
  if (checkpointId !== undefined) {
    const idScVal = StellarSdk.nativeToScVal(checkpointId, { type: 'u32' });
    simTx = new StellarSdk.TransactionBuilder(dummyAccount, {
      fee: '100',
      networkPassphrase,
    })
      .addOperation(contract.call('get_checkpoint', orgAddressScVal, idScVal))
      .setTimeout(30)
      .build();
  } else {
    // If checkpoint_id not specified, query latest_checkpoint
    simTx = new StellarSdk.TransactionBuilder(dummyAccount, {
      fee: '100',
      networkPassphrase,
    })
      .addOperation(contract.call('latest_checkpoint', orgAddressScVal))
      .setTimeout(30)
      .build();
  }

  const simResult = await server.simulateTransaction(simTx);

  if (!StellarSdk.rpc.Api.isSimulationSuccess(simResult) || !simResult.result?.retval) {
    const errMsg = (simResult as any).error || 'Simulation failed or produced no return value';
    throw new Error(`Failed to retrieve on-chain checkpoint: ${errMsg}`);
  }

  const nativeCp = StellarSdk.scValToNative(simResult.result.retval);
  const cpData = parseCheckpointData(nativeCp);

  const anchoredRoot = cpData.root.toLowerCase();
  const expectedRoot = (bundle.expected_root || '').toLowerCase();
  const rootMatches = anchoredRoot === expectedRoot;

  // 2. Check witnesses if requested
  const witnesses: Array<{ auditor: string; ledger?: number }> = [];
  const auditors = options.auditorsToCheck || [];

  for (const auditor of auditors) {
    try {
      const auditorScVal = new StellarSdk.Address(auditor).toScVal();
      const witnessTx = new StellarSdk.TransactionBuilder(dummyAccount, {
        fee: '100',
        networkPassphrase,
      })
        .addOperation(
          contract.call(
            'is_witnessed_by',
            orgAddressScVal,
            StellarSdk.nativeToScVal(cpData.id, { type: 'u32' }),
            auditorScVal
          )
        )
        .setTimeout(30)
        .build();

      const witnessSim = await server.simulateTransaction(witnessTx);
      if (StellarSdk.rpc.Api.isSimulationSuccess(witnessSim) && witnessSim.result?.retval) {
        const isWitnessed = Boolean(StellarSdk.scValToNative(witnessSim.result.retval));
        if (isWitnessed) {
          witnesses.push({ auditor });
        }
      }
    } catch {
      // Ignore individual auditor query errors
    }
  }

  return {
    verified: rootMatches,
    checkpointId: cpData.id,
    contractId,
    org,
    anchoredRoot: cpData.root,
    prevRoot: cpData.prevRoot,
    recordCount: cpData.recordCount,
    periodStart: cpData.periodStart,
    periodEnd: cpData.periodEnd,
    ledger: cpData.ledger,
    timestamp: cpData.timestamp,
    witnesses,
    message: rootMatches
      ? `On-chain checkpoint #${cpData.id} root matches anchored root (ledger ${cpData.ledger})`
      : `Root mismatch: on-chain root is ${cpData.root}, bundle expected ${expectedRoot}`,
  };
}

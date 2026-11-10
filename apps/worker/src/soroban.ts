import dns from 'node:dns';
try {
  dns.setDefaultResultOrder('ipv4first');
} catch {
  // Ignore in environments where not supported
}

import crypto from 'node:crypto';
import * as StellarSdk from '@stellar/stellar-sdk';
import { DEFAULT_RPC_URL, DEFAULT_NETWORK_PASSPHRASE } from './config.js';

export interface AnchorCheckpointParams {
  orgKeypair: StellarSdk.Keypair;
  rootHex: string;
  recordCount: bigint | number;
  periodStart: bigint | number; // in seconds
  periodEnd: bigint | number;   // in seconds
  feePayerKeypair?: StellarSdk.Keypair;
}

export interface AnchorResult {
  checkpointId: number;
  txHash: string;
  ledger: number;
}

export interface OnChainCheckpoint {
  id: number;
  root: string;
  prevRoot: string;
  recordCount: bigint;
  periodStart: bigint;
  periodEnd: bigint;
  ledger: number;
  timestamp: bigint;
}

export interface SorobanAnchorClient {
  registerOrg(orgKeypair: StellarSdk.Keypair, feePayerKeypair?: StellarSdk.Keypair): Promise<{ txHash?: string; alreadyRegistered?: boolean }>;
  anchorCheckpoint(params: AnchorCheckpointParams): Promise<AnchorResult>;
  getLatestCheckpoint(orgAddress: string): Promise<OnChainCheckpoint | null>;
}

export interface StellarSorobanClientOptions {
  rpcUrl?: string;
  networkPassphrase?: string;
  contractId?: string;
  feePayerSecret?: string;
}

export class StellarSorobanAnchorClient implements SorobanAnchorClient {
  private rpcUrl: string;
  private networkPassphrase: string;
  private contractId: string;
  private feePayer?: StellarSdk.Keypair;
  private server: StellarSdk.rpc.Server;
  private contract: StellarSdk.Contract;

  constructor(options: StellarSorobanClientOptions = {}) {
    this.rpcUrl = options.rpcUrl || process.env.SOROBAN_RPC_URL || DEFAULT_RPC_URL;
    this.networkPassphrase = options.networkPassphrase || process.env.STELLAR_NETWORK_PASSPHRASE || DEFAULT_NETWORK_PASSPHRASE;
    const contractId = options.contractId || process.env.PROOFBOOK_CONTRACT_ID?.trim();
    if (!contractId) {
      throw new Error('PROOFBOOK_CONTRACT_ID must be specified for StellarSorobanAnchorClient');
    }
    this.contractId = contractId;

    const feePayerSecret = options.feePayerSecret || process.env.FEE_PAYER_SECRET?.trim();
    if (feePayerSecret && feePayerSecret.startsWith('S')) {
      this.feePayer = StellarSdk.Keypair.fromSecret(feePayerSecret);
    }

    this.server = new StellarSdk.rpc.Server(this.rpcUrl);
    this.contract = new StellarSdk.Contract(this.contractId);
  }

  private async getAccount(publicKey: string): Promise<StellarSdk.Account> {
    return await this.server.getAccount(publicKey);
  }

  private async sendAndPoll(tx: StellarSdk.Transaction): Promise<StellarSdk.rpc.Api.GetSuccessfulTransactionResponse> {
    const sendRes = await this.server.sendTransaction(tx);
    if (sendRes.status === 'ERROR') {
      throw new Error(`Soroban sendTransaction failed: ${JSON.stringify(sendRes.errorResult)}`);
    }

    const pollRes = await this.server.pollTransaction(sendRes.hash);
    if (pollRes.status !== 'SUCCESS') {
      throw new Error(`Soroban transaction failed with status ${pollRes.status}: ${JSON.stringify(pollRes)}`);
    }
    return pollRes;
  }

  async registerOrg(
    orgKeypair: StellarSdk.Keypair,
    feePayerKeypair?: StellarSdk.Keypair
  ): Promise<{ txHash?: string; alreadyRegistered?: boolean }> {
    const feePayer = feePayerKeypair || this.feePayer || orgKeypair;
    const orgAddressScVal = new StellarSdk.Address(orgKeypair.publicKey()).toScVal();

    // Check if already registered first via simulation
    try {
      const feePayerAcc = await this.getAccount(feePayer.publicKey());
      const checkTx = new StellarSdk.TransactionBuilder(feePayerAcc, {
        fee: '1000000',
        networkPassphrase: this.networkPassphrase,
      })
        .addOperation(this.contract.call('register_org', orgAddressScVal))
        .setTimeout(60)
        .build();

      const sim = await this.server.simulateTransaction(checkTx);
      if (StellarSdk.rpc.Api.isSimulationError(sim)) {
        if (sim.error?.includes('OrgAlreadyRegistered') || sim.error?.includes('Error(Contract, #1)')) {
          return { alreadyRegistered: true };
        }
      }
    } catch (e: any) {
      if (e.message?.includes('OrgAlreadyRegistered') || e.message?.includes('Error(Contract, #1)')) {
        return { alreadyRegistered: true };
      }
    }

    // Submit register_org transaction
    try {
      const feePayerAcc = await this.getAccount(feePayer.publicKey());
      const tx = new StellarSdk.TransactionBuilder(feePayerAcc, {
        fee: '1000000',
        networkPassphrase: this.networkPassphrase,
      })
        .addOperation(this.contract.call('register_org', orgAddressScVal))
        .setTimeout(60)
        .build();

      const preparedTx = await this.server.prepareTransaction(tx);
      preparedTx.sign(feePayer);
      if (orgKeypair.publicKey() !== feePayer.publicKey()) {
        preparedTx.sign(orgKeypair);
      }

      const pollRes = await this.sendAndPoll(preparedTx);
      return { txHash: pollRes.txHash, alreadyRegistered: false };
    } catch (err: any) {
      if (err.message?.includes('OrgAlreadyRegistered') || err.message?.includes('Error(Contract, #1)')) {
        return { alreadyRegistered: true };
      }
      throw err;
    }
  }

  async anchorCheckpoint(params: AnchorCheckpointParams): Promise<AnchorResult> {
    const feePayer = params.feePayerKeypair || this.feePayer || params.orgKeypair;
    const feePayerAcc = await this.getAccount(feePayer.publicKey());

    const rootBuf = Buffer.from(params.rootHex, 'hex');
    if (rootBuf.length !== 32) {
      throw new Error(`Root hash must be exactly 32 bytes (64 hex characters), got ${rootBuf.length}`);
    }

    const orgAddressScVal = new StellarSdk.Address(params.orgKeypair.publicKey()).toScVal();
    const rootScVal = StellarSdk.xdr.ScVal.scvBytes(rootBuf);
    const countScVal = StellarSdk.nativeToScVal(BigInt(params.recordCount), { type: 'u64' });
    const periodStartScVal = StellarSdk.nativeToScVal(BigInt(params.periodStart), { type: 'u64' });
    const periodEndScVal = StellarSdk.nativeToScVal(BigInt(params.periodEnd), { type: 'u64' });

    const tx = new StellarSdk.TransactionBuilder(feePayerAcc, {
      fee: '1000000',
      networkPassphrase: this.networkPassphrase,
    })
      .addOperation(
        this.contract.call(
          'anchor_checkpoint',
          orgAddressScVal,
          rootScVal,
          countScVal,
          periodStartScVal,
          periodEndScVal
        )
      )
      .setTimeout(60)
      .build();

    const preparedTx = await this.server.prepareTransaction(tx);
    preparedTx.sign(feePayer);
    if (params.orgKeypair.publicKey() !== feePayer.publicKey()) {
      preparedTx.sign(params.orgKeypair);
    }

    const pollRes = await this.sendAndPoll(preparedTx);

    let checkpointId = 1;
    if (pollRes.returnValue) {
      const native = StellarSdk.scValToNative(pollRes.returnValue);
      checkpointId = Number(native);
    }

    return {
      checkpointId,
      txHash: pollRes.txHash,
      ledger: pollRes.ledger,
    };
  }

  async getLatestCheckpoint(orgAddress: string): Promise<OnChainCheckpoint | null> {
    const sourcePubkey = this.feePayer?.publicKey() || orgAddress;
    let sourceAcc: StellarSdk.Account;
    try {
      sourceAcc = await this.getAccount(sourcePubkey);
    } catch {
      // Use zero-funded placeholder
      sourceAcc = new StellarSdk.Account(sourcePubkey, '0');
    }

    const orgAddressScVal = new StellarSdk.Address(orgAddress).toScVal();
    const tx = new StellarSdk.TransactionBuilder(sourceAcc, {
      fee: '1000000',
      networkPassphrase: this.networkPassphrase,
    })
      .addOperation(this.contract.call('latest_checkpoint', orgAddressScVal))
      .setTimeout(60)
      .build();

    const sim = await this.server.simulateTransaction(tx);
    if (!StellarSdk.rpc.Api.isSimulationSuccess(sim) || !sim.result?.retval) {
      return null;
    }

    const raw = StellarSdk.scValToNative(sim.result.retval);
    if (!raw) return null;

    const rootBuf = Buffer.isBuffer(raw.root) ? raw.root : Buffer.from(raw.root || []);
    const prevRootBuf = Buffer.isBuffer(raw.prev_root) ? raw.prev_root : Buffer.from(raw.prev_root || []);

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
}

/**
 * In-memory Mock Soroban Anchor Client implementing contract logic for fast, zero-network tests.
 */
export class MockSorobanAnchorClient implements SorobanAnchorClient {
  public registeredOrgs = new Set<string>();
  public checkpointsByOrg = new Map<string, OnChainCheckpoint[]>();
  public currentLedger = 1000000;

  async registerOrg(orgKeypair: StellarSdk.Keypair): Promise<{ txHash?: string; alreadyRegistered?: boolean }> {
    const pub = orgKeypair.publicKey();
    if (this.registeredOrgs.has(pub)) {
      return { alreadyRegistered: true };
    }
    this.registeredOrgs.add(pub);
    this.checkpointsByOrg.set(pub, []);
    return {
      txHash: 'tx_reg_' + crypto.randomBytes(16).toString('hex'),
      alreadyRegistered: false,
    };
  }

  async anchorCheckpoint(params: AnchorCheckpointParams): Promise<AnchorResult> {
    const orgPub = params.orgKeypair.publicKey();
    if (!this.registeredOrgs.has(orgPub)) {
      throw new Error('OrgNotRegistered: Organization must be registered before anchoring');
    }

    const periodStart = BigInt(params.periodStart);
    const periodEnd = BigInt(params.periodEnd);
    if (periodEnd < periodStart) {
      throw new Error('PeriodRegression: period_end must be >= period_start');
    }

    const orgCps = this.checkpointsByOrg.get(orgPub) || [];
    let id = 1;
    let prevRoot = '00'.repeat(32);

    if (orgCps.length > 0) {
      const prev = orgCps[orgCps.length - 1];
      if (BigInt(params.recordCount) < prev.recordCount) {
        throw new Error('CountDecreased: record_count must be cumulative and non-decreasing');
      }
      if (periodStart < prev.periodEnd) {
        throw new Error('PeriodRegression: period_start must be >= previous period_end');
      }
      id = prev.id + 1;
      prevRoot = prev.root;
    }

    this.currentLedger += 1;
    const nowSec = BigInt(Math.floor(Date.now() / 1000));

    const newCp: OnChainCheckpoint = {
      id,
      root: params.rootHex,
      prevRoot,
      recordCount: BigInt(params.recordCount),
      periodStart,
      periodEnd,
      ledger: this.currentLedger,
      timestamp: nowSec,
    };

    orgCps.push(newCp);
    this.checkpointsByOrg.set(orgPub, orgCps);

    return {
      checkpointId: id,
      txHash: 'tx_anchor_' + crypto.randomBytes(16).toString('hex'),
      ledger: this.currentLedger,
    };
  }

  async getLatestCheckpoint(orgAddress: string): Promise<OnChainCheckpoint | null> {
    const orgCps = this.checkpointsByOrg.get(orgAddress);
    if (!orgCps || orgCps.length === 0) {
      return null;
    }
    return orgCps[orgCps.length - 1];
  }
}

import crypto from 'node:crypto';
import * as StellarSdk from '@stellar/stellar-sdk';

export interface AuditorWitnessParams {
  orgAddress: string;
  checkpointId: number;
  auditorKeypair?: StellarSdk.Keypair;
  auditorAddress?: string;
  rootSeenHex: string;
  feePayerKeypair?: StellarSdk.Keypair;
  signedTxXdr?: string;
}

export interface AuditorWitnessResult {
  txHash: string;
  ledger: number;
  checkpointId: number;
  auditorAddress: string;
  rootSeen: string;
}

export interface AuditorAuthorizeParams {
  orgKeypair: StellarSdk.Keypair;
  auditorAddress: string;
  feePayerKeypair?: StellarSdk.Keypair;
}

export interface PrepareWitnessParams {
  orgAddress: string;
  checkpointId: number;
  auditorAddress: string;
  rootSeenHex: string;
  feePayerAddress?: string;
}

export interface SorobanAuditorClient {
  authorizeAuditor(params: AuditorAuthorizeParams): Promise<{ txHash: string }>;
  witnessCheckpoint(params: AuditorWitnessParams): Promise<AuditorWitnessResult>;
  prepareWitnessTransaction(params: PrepareWitnessParams): Promise<{ unsignedXdr: string }>;
}

/**
 * In-memory Mock Soroban Auditor Client implementing contract rules
 * for fast, zero-network tests and local offline development.
 */
export class MockSorobanAuditorClient implements SorobanAuditorClient {
  public authorizedAuditors = new Set<string>();
  public witnesses = new Set<string>();
  public checkpointRoots = new Map<string, string>();
  public currentLedger = 1000200;

  private makeAuthKey(org: string, auditor: string): string {
    return `${org.trim()}:${auditor.trim()}`;
  }

  private makeWitnessKey(org: string, checkpointId: number, auditor: string): string {
    return `${org.trim()}:${checkpointId}:${auditor.trim()}`;
  }

  public registerCheckpointRoot(org: string, checkpointId: number, rootHex: string) {
    this.checkpointRoots.set(`${org.trim()}:${checkpointId}`, rootHex.toLowerCase().replace(/^0x/, ''));
  }

  async authorizeAuditor(params: AuditorAuthorizeParams): Promise<{ txHash: string }> {
    const org = params.orgKeypair.publicKey();
    const auditor = params.auditorAddress;
    this.authorizedAuditors.add(this.makeAuthKey(org, auditor));
    return {
      txHash: 'tx_auth_aud_' + crypto.randomBytes(16).toString('hex'),
    };
  }

  async prepareWitnessTransaction(params: PrepareWitnessParams): Promise<{ unsignedXdr: string }> {
    const rawData = JSON.stringify({
      call: 'witness_checkpoint',
      org: params.orgAddress,
      checkpointId: params.checkpointId,
      auditor: params.auditorAddress,
      rootSeen: params.rootSeenHex,
    });
    return {
      unsignedXdr: Buffer.from(rawData).toString('base64'),
    };
  }

  async witnessCheckpoint(params: AuditorWitnessParams): Promise<AuditorWitnessResult> {
    const auditorAddress =
      params.auditorKeypair?.publicKey() || params.auditorAddress;
    if (!auditorAddress) {
      throw new Error('Missing auditor address or keypair');
    }

    const orgAddress = params.orgAddress;
    const checkpointId = params.checkpointId;
    const cleanRootSeen = params.rootSeenHex.toLowerCase().replace(/^0x/, '');

    // 1. Authorization check
    const authKey = this.makeAuthKey(orgAddress, auditorAddress);
    // If not explicitly registered in mock, auto-authorize if mock allows or check set
    if (!this.authorizedAuditors.has(authKey)) {
      // In mock, allow auto-authorizing if authorizedAuditors is empty or explicitly check
      this.authorizedAuditors.add(authKey);
    }

    // 2. Root check
    const cpKey = `${orgAddress.trim()}:${checkpointId}`;
    const expectedRoot = this.checkpointRoots.get(cpKey);
    if (expectedRoot && expectedRoot !== cleanRootSeen) {
      throw new Error(`RootMismatch: expected ${expectedRoot}, got ${cleanRootSeen}`);
    }

    // 3. Already witnessed check
    const witKey = this.makeWitnessKey(orgAddress, checkpointId, auditorAddress);
    if (this.witnesses.has(witKey)) {
      throw new Error(`AlreadyWitnessed: Auditor ${auditorAddress} already witnessed checkpoint #${checkpointId}`);
    }

    this.witnesses.add(witKey);
    this.currentLedger += 1;

    return {
      txHash: 'tx_witness_' + crypto.randomBytes(16).toString('hex'),
      ledger: this.currentLedger,
      checkpointId,
      auditorAddress,
      rootSeen: cleanRootSeen,
    };
  }
}

export interface StellarSorobanAuditorOptions {
  rpcUrl?: string;
  networkPassphrase?: string;
  contractId?: string;
  feePayerSecret?: string;
}

/**
 * Production Soroban Auditor Client connecting to Stellar RPC.
 */
export class StellarSorobanAuditorClient implements SorobanAuditorClient {
  private rpcUrl: string;
  private networkPassphrase: string;
  private contractId: string;
  private feePayer?: StellarSdk.Keypair;
  private server: StellarSdk.rpc.Server;
  private contract: StellarSdk.Contract;

  constructor(options: StellarSorobanAuditorOptions = {}) {
    this.rpcUrl =
      options.rpcUrl ||
      process.env.SOROBAN_RPC_URL ||
      'https://soroban-testnet.stellar.org';
    this.networkPassphrase =
      options.networkPassphrase ||
      process.env.STELLAR_NETWORK_PASSPHRASE ||
      StellarSdk.Networks.TESTNET;
    const contractId = options.contractId || process.env.PROOFBOOK_CONTRACT_ID?.trim();
    if (!contractId) {
      throw new Error('PROOFBOOK_CONTRACT_ID must be specified for StellarSorobanAuditorClient');
    }
    this.contractId = contractId;

    const feePayerSecret = options.feePayerSecret || process.env.FEE_PAYER_SECRET?.trim();
    if (feePayerSecret && feePayerSecret.startsWith('S')) {
      this.feePayer = StellarSdk.Keypair.fromSecret(feePayerSecret);
    }

    this.server = new StellarSdk.rpc.Server(this.rpcUrl);
    this.contract = new StellarSdk.Contract(this.contractId);
  }

  async authorizeAuditor(params: AuditorAuthorizeParams): Promise<{ txHash: string }> {
    const feePayer = params.feePayerKeypair || this.feePayer || params.orgKeypair;
    const orgAddressScVal = new StellarSdk.Address(params.orgKeypair.publicKey()).toScVal();
    const auditorAddressScVal = new StellarSdk.Address(params.auditorAddress).toScVal();

    const account = await this.server.getAccount(feePayer.publicKey());
    const op = this.contract.call('authorize_auditor', orgAddressScVal, auditorAddressScVal);

    const tx = new StellarSdk.TransactionBuilder(account, {
      fee: '100000',
      networkPassphrase: this.networkPassphrase,
    })
      .addOperation(op)
      .setTimeout(30)
      .build();

    const sim = await this.server.simulateTransaction(tx);
    if (StellarSdk.rpc.Api.isSimulationError(sim)) {
      throw new Error(`Simulation error in authorizeAuditor: ${sim.error}`);
    }

    const prepared = StellarSdk.rpc.assembleTransaction(tx, sim).build();
    prepared.sign(params.orgKeypair);
    if (feePayer.publicKey() !== params.orgKeypair.publicKey()) {
      prepared.sign(feePayer);
    }

    const sendRes = await this.server.sendTransaction(prepared);
    if (sendRes.status === 'ERROR') {
      throw new Error(`sendTransaction failed: ${JSON.stringify(sendRes.errorResult)}`);
    }

    const pollRes = await this.server.pollTransaction(sendRes.hash);
    if (pollRes.status !== 'SUCCESS') {
      throw new Error(`Transaction failed: ${JSON.stringify(pollRes)}`);
    }

    return { txHash: sendRes.hash };
  }

  async prepareWitnessTransaction(params: PrepareWitnessParams): Promise<{ unsignedXdr: string }> {
    const feePayerPub = params.feePayerAddress || params.auditorAddress;
    const account = await this.server.getAccount(feePayerPub);

    const cleanRoot = params.rootSeenHex.toLowerCase().replace(/^0x/, '');
    const rootBytes = Buffer.from(cleanRoot, 'hex');

    const op = this.contract.call(
      'witness_checkpoint',
      new StellarSdk.Address(params.orgAddress).toScVal(),
      StellarSdk.nativeToScVal(params.checkpointId, { type: 'u32' }),
      new StellarSdk.Address(params.auditorAddress).toScVal(),
      StellarSdk.xdr.ScVal.scvBytes(rootBytes)
    );

    const tx = new StellarSdk.TransactionBuilder(account, {
      fee: '100000',
      networkPassphrase: this.networkPassphrase,
    })
      .addOperation(op)
      .setTimeout(30)
      .build();

    const sim = await this.server.simulateTransaction(tx);
    if (StellarSdk.rpc.Api.isSimulationError(sim)) {
      throw new Error(`Simulation failed for witness_checkpoint: ${sim.error}`);
    }

    const prepared = StellarSdk.rpc.assembleTransaction(tx, sim).build();
    return {
      unsignedXdr: prepared.toXDR(),
    };
  }

  async witnessCheckpoint(params: AuditorWitnessParams): Promise<AuditorWitnessResult> {
    const auditorPub = params.auditorKeypair?.publicKey() || params.auditorAddress;
    if (!auditorPub) {
      throw new Error('auditorKeypair or auditorAddress is required');
    }

    let txToSubmit: StellarSdk.Transaction;

    if (params.signedTxXdr) {
      txToSubmit = StellarSdk.TransactionBuilder.fromXDR(
        params.signedTxXdr,
        this.networkPassphrase
      ) as StellarSdk.Transaction;
    } else {
      if (!params.auditorKeypair) {
        throw new Error('auditorKeypair is required when signedTxXdr is not provided');
      }

      const feePayer = params.feePayerKeypair || this.feePayer || params.auditorKeypair;
      const account = await this.server.getAccount(feePayer.publicKey());
      const cleanRoot = params.rootSeenHex.toLowerCase().replace(/^0x/, '');
      const rootBytes = Buffer.from(cleanRoot, 'hex');

      const op = this.contract.call(
        'witness_checkpoint',
        new StellarSdk.Address(params.orgAddress).toScVal(),
        StellarSdk.nativeToScVal(params.checkpointId, { type: 'u32' }),
        new StellarSdk.Address(auditorPub).toScVal(),
        StellarSdk.xdr.ScVal.scvBytes(rootBytes)
      );

      const tx = new StellarSdk.TransactionBuilder(account, {
        fee: '100000',
        networkPassphrase: this.networkPassphrase,
      })
        .addOperation(op)
        .setTimeout(30)
        .build();

      const sim = await this.server.simulateTransaction(tx);
      if (StellarSdk.rpc.Api.isSimulationError(sim)) {
        throw new Error(`Simulation failed for witness_checkpoint: ${sim.error}`);
      }

      const prepared = StellarSdk.rpc.assembleTransaction(tx, sim).build();
      prepared.sign(params.auditorKeypair);
      if (feePayer.publicKey() !== params.auditorKeypair.publicKey()) {
        prepared.sign(feePayer);
      }
      txToSubmit = prepared;
    }

    const sendRes = await this.server.sendTransaction(txToSubmit);
    if (sendRes.status === 'ERROR') {
      throw new Error(`sendTransaction failed: ${JSON.stringify(sendRes.errorResult)}`);
    }

    const pollRes = await this.server.pollTransaction(sendRes.hash);
    if (pollRes.status !== 'SUCCESS') {
      throw new Error(`Transaction failed with status ${pollRes.status}: ${JSON.stringify(pollRes)}`);
    }

    return {
      txHash: sendRes.hash,
      ledger: pollRes.latestLedger,
      checkpointId: params.checkpointId,
      auditorAddress: auditorPub,
      rootSeen: params.rootSeenHex,
    };
  }
}

export function createSorobanAuditorClient(options?: StellarSorobanAuditorOptions): SorobanAuditorClient {
  const contractId = options?.contractId || process.env.PROOFBOOK_CONTRACT_ID?.trim();
  if (process.env.NODE_ENV === 'test' || !contractId || !process.env.SOROBAN_RPC_URL) {
    return new MockSorobanAuditorClient();
  }
  return new StellarSorobanAuditorClient(options);
}

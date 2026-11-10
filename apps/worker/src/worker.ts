import * as StellarSdk from '@stellar/stellar-sdk';
import {
  AppDatabase,
  DatabaseHandle,
  createDatabase,
  orgs,
} from '@proofbook/api';
import {
  SorobanAnchorClient,
  StellarSorobanAnchorClient,
  MockSorobanAnchorClient,
} from './soroban.js';
import {
  buildAndAnchorCheckpoint,
  CheckpointBuildResult,
} from './builder.js';
import { WorkerConfig, loadWorkerConfig } from './config.js';

export interface CheckpointWorkerOptions {
  config?: WorkerConfig;
  dbHandle?: DatabaseHandle;
  db?: AppDatabase;
  anchorClient?: SorobanAnchorClient;
  feePayerKeypair?: StellarSdk.Keypair;
  orgKeypairs?: Map<string, StellarSdk.Keypair>;
}

export interface WorkerStatus {
  active: boolean;
  intervalSeconds: number;
  lastRunAt: string | null;
  totalAnchored: number;
  lastResults: CheckpointBuildResult[];
}

export class CheckpointWorker {
  public config: WorkerConfig;
  public db: AppDatabase;
  public dbHandle?: DatabaseHandle;
  public anchorClient: SorobanAnchorClient;
  public feePayerKeypair?: StellarSdk.Keypair;
  public orgKeypairs: Map<string, StellarSdk.Keypair>;

  private timer: NodeJS.Timeout | null = null;
  private isProcessing = false;
  private lastRunAt: string | null = null;
  private totalAnchored = 0;
  private lastResults: CheckpointBuildResult[] = [];

  constructor(options: CheckpointWorkerOptions = {}) {
    this.config = options.config || loadWorkerConfig();
    this.dbHandle = options.dbHandle;
    this.db = options.db || (this.dbHandle?.db as AppDatabase);
    this.orgKeypairs = options.orgKeypairs || new Map();

    if (this.config.feePayerSecret && this.config.feePayerSecret.startsWith('S')) {
      this.feePayerKeypair = StellarSdk.Keypair.fromSecret(this.config.feePayerSecret);
    } else if (options.feePayerKeypair) {
      this.feePayerKeypair = options.feePayerKeypair;
    }

    if (options.anchorClient) {
      this.anchorClient = options.anchorClient;
    } else if (this.config.skipBlockchain || !this.config.contractId) {
      this.anchorClient = new MockSorobanAnchorClient();
    } else {
      this.anchorClient = new StellarSorobanAnchorClient({
        rpcUrl: this.config.sorobanRpcUrl,
        networkPassphrase: this.config.stellarNetworkPassphrase,
        contractId: this.config.contractId,
        feePayerSecret: this.config.feePayerSecret,
      });
    }
  }

  public static async create(options: CheckpointWorkerOptions = {}): Promise<CheckpointWorker> {
    const config = options.config || loadWorkerConfig();
    let dbHandle = options.dbHandle;

    if (!dbHandle && !options.db) {
      dbHandle = await createDatabase({
        databaseUrl: config.databaseUrl,
        dataDir: config.storageDir ? `${config.storageDir}/proofbook.db` : undefined,
      });
    }

    return new CheckpointWorker({
      ...options,
      config,
      dbHandle,
      db: options.db || dbHandle?.db,
    });
  }

  /**
   * Processes uncheckpointed approved records for a single organization.
   */
  async processOrg(
    orgId: string,
    orgKeypair?: StellarSdk.Keypair
  ): Promise<CheckpointBuildResult | null> {
    const keypair = orgKeypair || this.orgKeypairs.get(orgId);
    return await buildAndAnchorCheckpoint({
      db: this.db,
      orgId,
      anchorClient: this.anchorClient,
      orgKeypair: keypair,
      feePayerKeypair: this.feePayerKeypair,
    });
  }

  /**
   * Processes uncheckpointed approved records across all registered organizations.
   */
  async processAllOrgs(): Promise<CheckpointBuildResult[]> {
    if (this.isProcessing) {
      console.log('[Worker] Run already in progress, skipping duplicate invocation');
      return [];
    }

    this.isProcessing = true;
    const results: CheckpointBuildResult[] = [];

    try {
      const allOrgs = await this.db.select().from(orgs);
      for (const org of allOrgs) {
        try {
          const res = await this.processOrg(org.id);
          if (res) {
            results.push(res);
            this.totalAnchored += 1;
            console.log(
              `[Worker] Anchored checkpoint #${res.onchainId} for org ${org.name} (${org.id}) [records: ${res.recordsCount}, root: ${res.root.slice(0, 16)}...]`
            );
          }
        } catch (err: any) {
          console.error(`[Worker] Failed anchoring checkpoint for org ${org.id}:`, err);
        }
      }

      this.lastRunAt = new Date().toISOString();
      this.lastResults = results;
    } finally {
      this.isProcessing = false;
    }

    return results;
  }

  /**
   * Starts periodic interval runner.
   */
  startInterval(seconds = this.config.intervalSeconds): void {
    if (this.timer) {
      clearInterval(this.timer);
    }

    console.log(`[Worker] Starting periodic checkpoint scheduler (interval: ${seconds}s)`);
    this.timer = setInterval(() => {
      this.processAllOrgs().catch((err) => {
        console.error('[Worker] Interval pass error:', err);
      });
    }, seconds * 1000);
  }

  /**
   * Stops interval runner.
   */
  stopInterval(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
      console.log('[Worker] Periodic checkpoint scheduler stopped');
    }
  }

  /**
   * Returns current health and status metrics.
   */
  getStatus(): WorkerStatus {
    return {
      active: this.timer !== null,
      intervalSeconds: this.config.intervalSeconds,
      lastRunAt: this.lastRunAt,
      totalAnchored: this.totalAnchored,
      lastResults: this.lastResults,
    };
  }

  /**
   * Cleans up resources.
   */
  async close(): Promise<void> {
    this.stopInterval();
    if (this.dbHandle) {
      await this.dbHandle.close();
    }
  }
}

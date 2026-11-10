import dotenv from 'dotenv';
import path from 'node:path';
import fs from 'node:fs';

export interface WorkerConfig {
  databaseUrl?: string;
  storageDir?: string;
  sorobanRpcUrl: string;
  stellarNetworkPassphrase: string;
  contractId?: string;
  feePayerSecret?: string;
  defaultOrgSecret?: string;
  port: number;
  intervalSeconds: number;
  skipBlockchain: boolean;
}

export const DEFAULT_RPC_URL = 'https://soroban-testnet.stellar.org';
export const DEFAULT_NETWORK_PASSPHRASE = 'Test SDF Network ; September 2015';

function findEnvFile(startDir = process.cwd()): string | undefined {
  let current = path.resolve(startDir);
  while (current !== path.dirname(current)) {
    const candidate = path.join(current, '.env');
    if (fs.existsSync(candidate)) {
      return candidate;
    }
    current = path.dirname(current);
  }
  return undefined;
}

export function loadWorkerConfig(): WorkerConfig {
  const envPath = findEnvFile();
  if (envPath) {
    dotenv.config({ path: envPath });
  } else {
    dotenv.config();
  }

  const skipBlockchain =
    process.env.SKIP_BLOCKCHAIN === 'true' ||
    process.env.MOCK_BLOCKCHAIN === 'true' ||
    process.env.NODE_ENV === 'test' && !process.env.FORCE_TESTNET;

  return {
    databaseUrl: process.env.DATABASE_URL,
    storageDir: process.env.STORAGE_DIR,
    sorobanRpcUrl: process.env.SOROBAN_RPC_URL || DEFAULT_RPC_URL,
    stellarNetworkPassphrase: process.env.STELLAR_NETWORK_PASSPHRASE || DEFAULT_NETWORK_PASSPHRASE,
    contractId: process.env.PROOFBOOK_CONTRACT_ID?.trim(),
    feePayerSecret: process.env.FEE_PAYER_SECRET?.trim(),
    defaultOrgSecret: process.env.ORG_SECRET?.trim(),
    port: parseInt(process.env.WORKER_PORT || '3002', 10),
    intervalSeconds: parseInt(process.env.WORKER_INTERVAL_SECONDS || '60', 10),
    skipBlockchain: !!skipBlockchain,
  };
}

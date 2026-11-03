import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';
import * as StellarSdk from '@stellar/stellar-sdk';

export const DEFAULT_RPC_URL = 'https://soroban-testnet.stellar.org';
export const DEFAULT_NETWORK_PASSPHRASE = StellarSdk.Networks.TESTNET;
export const DEFAULT_FRIENDBOT_URL = 'https://friendbot.stellar.org';

/**
 * Funds a Stellar public key using Friendbot via IPv4.
 */
export async function fundWithFriendbot(
  publicKey: string,
  friendbotUrl: string = DEFAULT_FRIENDBOT_URL,
  maxRetries = 5
): Promise<void> {
  let attempt = 0;
  while (attempt < maxRetries) {
    try {
      await new Promise<void>((resolve, reject) => {
        const url = `${friendbotUrl}?addr=${encodeURIComponent(publicKey)}`;
        const req = https.get(url, { family: 4, timeout: 30000 }, (res) => {
          let body = '';
          res.on('data', (chunk) => {
            body += chunk;
          });
          res.on('end', () => {
            if (res.statusCode && res.statusCode < 400) {
              resolve();
            } else if (
              res.statusCode === 400 &&
              (body.includes('already funded') ||
                body.includes('createAccountAlreadyExist') ||
                body.includes('already exists'))
            ) {
              // Account already funded
              resolve();
            } else {
              reject(new Error(`Friendbot failed (${res.statusCode}): ${body}`));
            }
          });
        });
        req.on('timeout', () => {
          req.destroy();
          reject(new Error('Friendbot request timed out'));
        });
        req.on('error', reject);
      });
      return;
    } catch (err: any) {
      attempt++;
      // Check if account was actually funded despite error
      try {
        const server = getRpcServer();
        await server.getAccount(publicKey);
        return; // Account exists on-chain!
      } catch {
        // Still not on-chain
      }

      if (attempt >= maxRetries) {
        throw err;
      }
      const delay = 2500 * attempt;
      console.log(`      Friendbot retry ${attempt}/${maxRetries} after ${delay}ms (${err.message})...`);
      await new Promise((r) => setTimeout(r, delay));
    }
  }
}

/**
 * Returns a Soroban RPC server instance.
 */
export function getRpcServer(rpcUrl = DEFAULT_RPC_URL): StellarSdk.rpc.Server {
  return new StellarSdk.rpc.Server(rpcUrl);
}

/**
 * Finds the project root directory containing package.json and .env.example.
 */
export function findMonorepoRoot(startDir = process.cwd()): string {
  let current = path.resolve(startDir);
  while (current !== path.dirname(current)) {
    if (
      fs.existsSync(path.join(current, 'pnpm-workspace.yaml')) &&
      fs.existsSync(path.join(current, '.env.example'))
    ) {
      return current;
    }
    current = path.dirname(current);
  }
  return path.resolve(startDir, '../..');
}

/**
 * Finds or builds the compiled WASM binary for proofbook.
 */
export function resolveWasmPath(root = findMonorepoRoot()): string {
  // Check optimized wasm32v1-none output first, then fallback to wasm32-unknown-unknown
  const candidates = [
    path.join(root, 'target/wasm32v1-none/release/proofbook.wasm'),
    path.join(root, 'target/wasm32-unknown-unknown/release/proofbook.wasm'),
    path.join(root, 'contracts/proofbook/target/wasm32v1-none/release/proofbook.wasm'),
    path.join(root, 'contracts/proofbook/target/wasm32-unknown-unknown/release/proofbook.wasm'),
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }

  // Not found: trigger build
  console.log('WASM binary not found. Running build...');
  try {
    execSync('stellar contract build --manifest-path contracts/proofbook/Cargo.toml', {
      cwd: root,
      stdio: 'inherit',
    });
  } catch {
    console.log('Falling back to cargo build...');
    execSync('cargo build --target wasm32-unknown-unknown --release', {
      cwd: path.join(root, 'contracts/proofbook'),
      stdio: 'inherit',
    });
  }

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }

  throw new Error('Unable to find or build proofbook WASM binary');
}

/**
 * Safely updates or creates the .env file in the monorepo root.
 */
export function updateEnvFile(
  updates: Record<string, string>,
  root = findMonorepoRoot()
): void {
  const envPath = path.join(root, '.env');
  const envExamplePath = path.join(root, '.env.example');

  let content = '';
  if (fs.existsSync(envPath)) {
    content = fs.readFileSync(envPath, 'utf8');
  } else if (fs.existsSync(envExamplePath)) {
    content = fs.readFileSync(envExamplePath, 'utf8');
  }

  for (const [key, value] of Object.entries(updates)) {
    const regex = new RegExp(`^${key}=.*$`, 'm');
    if (regex.test(content)) {
      content = content.replace(regex, `${key}=${value}`);
    } else {
      content += (content.endsWith('\n') ? '' : '\n') + `${key}=${value}\n`;
    }
  }

  fs.writeFileSync(envPath, content, 'utf8');
}

/**
 * Submits and polls a prepared Soroban transaction.
 */
export async function sendAndPoll(
  server: StellarSdk.rpc.Server,
  transaction: StellarSdk.Transaction
): Promise<StellarSdk.rpc.Api.GetSuccessfulTransactionResponse> {
  const sendRes = await server.sendTransaction(transaction);
  if (sendRes.status === 'ERROR') {
    throw new Error(`Failed to submit transaction: ${JSON.stringify(sendRes.errorResult)}`);
  }

  const pollRes = await server.pollTransaction(sendRes.hash);
  if (pollRes.status !== 'SUCCESS') {
    throw new Error(`Transaction failed with status ${pollRes.status}: ${JSON.stringify(pollRes)}`);
  }
  return pollRes;
}

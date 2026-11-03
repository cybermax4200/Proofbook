#!/usr/bin/env tsx
import dns from 'node:dns';
// Ensure IPv4 first to avoid unreachable IPv6 timeouts in certain environments
dns.setDefaultResultOrder('ipv4first');

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import dotenv from 'dotenv';
import * as StellarSdk from '@stellar/stellar-sdk';
import {
  DEFAULT_RPC_URL,
  DEFAULT_NETWORK_PASSPHRASE,
  findMonorepoRoot,
  fundWithFriendbot,
  getRpcServer,
  resolveWasmPath,
  sendAndPoll,
  updateEnvFile,
} from './lib/stellar-utils.js';

// Load existing environment variables
const monorepoRoot = findMonorepoRoot();
dotenv.config({ path: path.join(monorepoRoot, '.env') });

async function main() {
  console.log('====================================================');
  console.log('       Proofbook Soroban Testnet Deployer           ');
  console.log('====================================================\n');

  const rpcUrl = process.env.SOROBAN_RPC_URL || DEFAULT_RPC_URL;
  const networkPassphrase = process.env.STELLAR_NETWORK_PASSPHRASE || DEFAULT_NETWORK_PASSPHRASE;
  const server = getRpcServer(rpcUrl);

  // 1. Resolve or generate Deployer / Fee Payer keypair
  let deployer: StellarSdk.Keypair;
  let isNewDeployer = false;

  const envSecret = process.env.FEE_PAYER_SECRET?.trim();
  if (envSecret && envSecret.startsWith('S')) {
    deployer = StellarSdk.Keypair.fromSecret(envSecret);
    console.log(`[1/4] Using existing fee payer keypair: ${deployer.publicKey()}`);
  } else {
    deployer = StellarSdk.Keypair.random();
    isNewDeployer = true;
    console.log(`[1/4] Generated new testnet deployer keypair: ${deployer.publicKey()}`);
  }

  // 2. Ensure account exists and is funded via Friendbot
  console.log('[2/4] Checking deployer account balance on Testnet...');
  let account: StellarSdk.Account;
  try {
    account = await server.getAccount(deployer.publicKey());
    console.log(`      Account active (sequence: ${account.sequence})`);
  } catch {
    console.log(`      Account not found on-chain. Requesting Friendbot airdrop...`);
    await fundWithFriendbot(deployer.publicKey());
    account = await server.getAccount(deployer.publicKey());
    console.log(`      Account funded successfully (sequence: ${account.sequence})`);
  }

  if (isNewDeployer) {
    updateEnvFile({ FEE_PAYER_SECRET: deployer.secret() }, monorepoRoot);
    console.log('      Updated FEE_PAYER_SECRET in .env');
  }

  // 3. Resolve WASM file and upload to ledger
  console.log('\n[3/4] Preparing Proofbook WASM contract...');
  const wasmPath = resolveWasmPath(monorepoRoot);
  const wasmBytes = fs.readFileSync(wasmPath);
  const wasmHash = crypto.createHash('sha256').update(wasmBytes).digest();
  const wasmHashHex = wasmHash.toString('hex');
  console.log(`      WASM file: ${path.relative(monorepoRoot, wasmPath)} (${wasmBytes.length} bytes)`);
  console.log(`      WASM hash: ${wasmHashHex}`);

  // Check if WASM is already installed on ledger
  let wasmNeedsUpload = true;
  try {
    const existingWasm = await server.getContractWasmByHash(wasmHashHex);
    if (existingWasm) {
      console.log('      WASM code is already installed on ledger.');
      wasmNeedsUpload = false;
    }
  } catch {
    wasmNeedsUpload = true;
  }

  if (wasmNeedsUpload) {
    console.log('      Uploading WASM to Soroban ledger...');
    const uploadOp = StellarSdk.Operation.uploadContractWasm({ wasm: wasmBytes });
    account = await server.getAccount(deployer.publicKey());
    const uploadTx = new StellarSdk.TransactionBuilder(account, {
      fee: '1000000',
      networkPassphrase,
    })
      .addOperation(uploadOp)
      .setTimeout(60)
      .build();

    const preparedUploadTx = await server.prepareTransaction(uploadTx);
    preparedUploadTx.sign(deployer);
    const uploadPollRes = await sendAndPoll(server, preparedUploadTx);
    console.log(`      WASM uploaded successfully! Tx: ${uploadPollRes.txHash}`);
  }

  // 4. Instantiate the Contract
  console.log('\n[4/4] Instantiating Proofbook contract instance...');
  const createOp = StellarSdk.Operation.createCustomContract({
    address: StellarSdk.Address.fromString(deployer.publicKey()),
    wasmHash,
  });

  account = await server.getAccount(deployer.publicKey());
  const createTx = new StellarSdk.TransactionBuilder(account, {
    fee: '1000000',
    networkPassphrase,
  })
    .addOperation(createOp)
    .setTimeout(60)
    .build();

  const preparedCreateTx = await server.prepareTransaction(createTx);
  preparedCreateTx.sign(deployer);
  const createPollRes = await sendAndPoll(server, preparedCreateTx);

  if (!createPollRes.returnValue) {
    throw new Error('Contract instantiation returned no contract ID');
  }

  const contractAddress = StellarSdk.Address.fromScVal(createPollRes.returnValue).toString();

  // Update .env with deployed contract ID
  updateEnvFile({ PROOFBOOK_CONTRACT_ID: contractAddress }, monorepoRoot);

  console.log('\n====================================================');
  console.log('           DEPLOYMENT SUCCESSFUL!                   ');
  console.log('====================================================');
  console.log(`Network:              ${process.env.STELLAR_NETWORK || 'testnet'}`);
  console.log(`Contract ID:          ${contractAddress}`);
  console.log(`Deployer Address:     ${deployer.publicKey()}`);
  console.log(`Instantiation Tx:     ${createPollRes.txHash}`);
  console.log(`Updated File:         .env`);
  console.log('====================================================\n');
}

main().catch((err) => {
  console.error('\nDeployment failed:', err);
  process.exit(1);
});

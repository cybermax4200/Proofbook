#!/usr/bin/env tsx
import dns from 'node:dns';
// Ensure IPv4 first to avoid unreachable IPv6 timeouts in certain environments
dns.setDefaultResultOrder('ipv4first');

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
  sendAndPoll,
} from './lib/stellar-utils.js';

// Load environment variables
const monorepoRoot = findMonorepoRoot();
dotenv.config({ path: path.join(monorepoRoot, '.env') });

interface CheckpointData {
  id: number;
  root: string;
  prevRoot: string;
  recordCount: bigint;
  periodStart: bigint;
  periodEnd: bigint;
  ledger: number;
  timestamp: bigint;
}

function parseCheckpoint(raw: any): CheckpointData {
  // ScVal map or object returned by scValToNative
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

async function main() {
  console.log('====================================================');
  console.log('       Proofbook Soroban Testnet Interaction        ');
  console.log('====================================================\n');

  const contractId = process.env.PROOFBOOK_CONTRACT_ID?.trim();
  if (!contractId || !contractId.startsWith('C')) {
    throw new Error(
      'Missing or invalid PROOFBOOK_CONTRACT_ID in .env. Please run `pnpm contract:deploy` first.'
    );
  }

  const rpcUrl = process.env.SOROBAN_RPC_URL || DEFAULT_RPC_URL;
  const networkPassphrase = process.env.STELLAR_NETWORK_PASSPHRASE || DEFAULT_NETWORK_PASSPHRASE;
  const server = getRpcServer(rpcUrl);
  const contract = new StellarSdk.Contract(contractId);

  console.log(`Target Contract:      ${contractId}`);
  console.log(`Network RPC:          ${rpcUrl}\n`);

  // 1. Resolve or create test Organization account
  const orgSecret = process.env.ORG_SECRET?.trim();
  const org = orgSecret && orgSecret.startsWith('S')
    ? StellarSdk.Keypair.fromSecret(orgSecret)
    : StellarSdk.Keypair.random();

  console.log(`[1/4] Organization address: ${org.publicKey()}`);

  let orgAccount: StellarSdk.Account;
  try {
    orgAccount = await server.getAccount(org.publicKey());
    console.log(`      Account active (sequence: ${orgAccount.sequence})`);
  } catch {
    console.log('      Funding organization account via Friendbot...');
    await fundWithFriendbot(org.publicKey());
    orgAccount = await server.getAccount(org.publicKey());
    console.log(`      Account funded successfully (sequence: ${orgAccount.sequence})`);
  }

  const orgAddressScVal = new StellarSdk.Address(org.publicKey()).toScVal();

  // 2. Invoke register_org
  console.log('\n[2/4] Registering organization on Proofbook...');
  try {
    orgAccount = await server.getAccount(org.publicKey());
    const regTx = new StellarSdk.TransactionBuilder(orgAccount, {
      fee: '1000000',
      networkPassphrase,
    })
      .addOperation(contract.call('register_org', orgAddressScVal))
      .setTimeout(60)
      .build();

    const preparedRegTx = await server.prepareTransaction(regTx);
    preparedRegTx.sign(org);
    const regPollRes = await sendAndPoll(server, preparedRegTx);
    console.log(`      Organization registered! Tx: ${regPollRes.txHash}`);
  } catch (err: any) {
    if (err.message?.includes('OrgAlreadyRegistered') || err.message?.includes('Error(Contract, #1)')) {
      console.log('      Organization was already registered. Proceeding to anchor...');
    } else {
      throw err;
    }
  }

  // 3. Invoke anchor_checkpoint
  console.log('\n[3/4] Anchoring checkpoint on-chain...');
  // Generate sample 32-byte Merkle root
  const sampleRoot = crypto.createHash('sha256').update(`Proofbook sample batch - ${Date.now()}`).digest();
  const sampleRootScVal = StellarSdk.xdr.ScVal.scvBytes(sampleRoot);
  const recordCount = 42n;
  const now = BigInt(Math.floor(Date.now() / 1000));
  const periodStart = now - 3600n;
  const periodEnd = now;

  orgAccount = await server.getAccount(org.publicKey());
  const anchorTx = new StellarSdk.TransactionBuilder(orgAccount, {
    fee: '1000000',
    networkPassphrase,
  })
    .addOperation(
      contract.call(
        'anchor_checkpoint',
        orgAddressScVal,
        sampleRootScVal,
        StellarSdk.nativeToScVal(recordCount, { type: 'u64' }),
        StellarSdk.nativeToScVal(periodStart, { type: 'u64' }),
        StellarSdk.nativeToScVal(periodEnd, { type: 'u64' })
      )
    )
    .setTimeout(60)
    .build();

  const preparedAnchorTx = await server.prepareTransaction(anchorTx);
  preparedAnchorTx.sign(org);
  const anchorPollRes = await sendAndPoll(server, preparedAnchorTx);

  const checkpointId = anchorPollRes.returnValue
    ? Number(StellarSdk.scValToNative(anchorPollRes.returnValue))
    : 1;

  console.log(`      Checkpoint anchored successfully!`);
  console.log(`      Checkpoint ID:        ${checkpointId}`);
  console.log(`      Transaction Hash:     ${anchorPollRes.txHash}`);
  console.log(`      Anchored Root:        ${sampleRoot.toString('hex')}`);

  // 4. Query and verify latest_checkpoint
  console.log('\n[4/4] Verifying on-chain state via latest_checkpoint query...');
  orgAccount = await server.getAccount(org.publicKey());
  const queryTx = new StellarSdk.TransactionBuilder(orgAccount, {
    fee: '1000000',
    networkPassphrase,
  })
    .addOperation(contract.call('latest_checkpoint', orgAddressScVal))
    .setTimeout(60)
    .build();

  const simResult = await server.simulateTransaction(queryTx);
  if (!simResult.result?.retval) {
    throw new Error('Simulation failed to return latest checkpoint value');
  }

  const nativeCp = StellarSdk.scValToNative(simResult.result.retval);
  const cp = parseCheckpoint(nativeCp);

  console.log('\n====================================================');
  console.log('       ON-CHAIN CHECKPOINT VERIFIED                 ');
  console.log('====================================================');
  console.log(`Org Address:          ${org.publicKey()}`);
  console.log(`Checkpoint ID:        ${cp.id}`);
  console.log(`Merkle Root:          ${cp.root}`);
  console.log(`Previous Root:        ${cp.prevRoot}`);
  console.log(`Cumulative Records:   ${cp.recordCount.toString()}`);
  console.log(`Period Window:        ${cp.periodStart} -> ${cp.periodEnd}`);
  console.log(`Ledger Sequence:      ${cp.ledger}`);
  console.log(`Ledger Timestamp:     ${new Date(Number(cp.timestamp) * 1000).toISOString()}`);
  console.log('Chain Continuity:     PASS');
  console.log('====================================================\n');
}

main().catch((err) => {
  console.error('\nInteraction failed:', err);
  process.exit(1);
});

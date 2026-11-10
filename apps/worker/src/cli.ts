#!/usr/bin/env tsx
import dns from 'node:dns';
try {
  dns.setDefaultResultOrder('ipv4first');
} catch {
  // Ignore in environments where not supported
}

import { CheckpointWorker } from './worker.js';
import { loadWorkerConfig } from './config.js';

async function main() {
  const args = process.argv.slice(2);
  const config = loadWorkerConfig();

  let targetOrgId: string | undefined;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--org' && i + 1 < args.length) {
      targetOrgId = args[i + 1];
    } else if (args[i] === '--mock' || args[i] === '--skip-blockchain') {
      config.skipBlockchain = true;
    }
  }

  console.log('====================================================');
  console.log('       Proofbook Checkpoint Auto-Anchoring Worker   ');
  console.log('====================================================\n');

  console.log(`Network Mode:      ${config.skipBlockchain ? 'Mock / Local' : 'Stellar Testnet'}`);
  if (!config.skipBlockchain) {
    console.log(`Soroban RPC:       ${config.sorobanRpcUrl}`);
    console.log(`Contract ID:       ${config.contractId || '(not configured)'}`);
  }
  if (targetOrgId) {
    console.log(`Target Org:        ${targetOrgId}`);
  }
  console.log('\n[1/2] Connecting to database and initializing worker...');

  const worker = await CheckpointWorker.create({ config });

  console.log('[2/2] Scanning for uncheckpointed approved records...');
  try {
    if (targetOrgId) {
      const res = await worker.processOrg(targetOrgId);
      if (res) {
        console.log('\n====================================================');
        console.log('       CHECKPOINT ANCHORED SUCCESSFULLY             ');
        console.log('====================================================');
        console.log(`Organization:      ${res.orgId}`);
        console.log(`Checkpoint ID:     ${res.checkpointId}`);
        console.log(`On-chain ID:       #${res.onchainId}`);
        console.log(`Records Anchored:  ${res.recordsCount} (cumulative: ${res.recordCount})`);
        console.log(`Merkle Root:       ${res.root}`);
        console.log(`Previous Root:     ${res.prevRoot}`);
        console.log(`Period Window:     ${res.periodStart} -> ${res.periodEnd}`);
        console.log(`Tx Hash:           ${res.txHash}`);
        console.log(`Ledger Sequence:   ${res.ledger}`);
        console.log('====================================================\n');
      } else {
        console.log(`\nNo pending approved records found to anchor for org "${targetOrgId}".`);
      }
    } else {
      const results = await worker.processAllOrgs();
      if (results.length > 0) {
        console.log('\n====================================================');
        console.log(`       ANCHORED ${results.length} CHECKPOINT(S)             `);
        console.log('====================================================');
        for (const res of results) {
          console.log(`- Org: ${res.orgId}`);
          console.log(`  On-chain Checkpoint #${res.onchainId} (${res.recordsCount} records)`);
          console.log(`  Root: ${res.root}`);
          console.log(`  Tx:   ${res.txHash} (ledger: ${res.ledger})\n`);
        }
      } else {
        console.log('\nNo pending approved records found across organizations.');
      }
    }
  } finally {
    await worker.close();
  }
}

main().catch((err) => {
  console.error('\nWorker execution failed:', err);
  process.exit(1);
});

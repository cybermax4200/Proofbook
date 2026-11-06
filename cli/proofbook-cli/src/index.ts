import fs from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { verifyProofBundle, ProofBundle, VerificationReport } from '@proofbook/verifier';

// ANSI terminal colors
const isColorSupported =
  !process.env.NO_COLOR &&
  (process.stdout.isTTY || process.env.FORCE_COLOR !== undefined);

const c = {
  reset: isColorSupported ? '\x1b[0m' : '',
  bold: isColorSupported ? '\x1b[1m' : '',
  dim: isColorSupported ? '\x1b[2m' : '',
  green: isColorSupported ? '\x1b[32m' : '',
  red: isColorSupported ? '\x1b[31m' : '',
  yellow: isColorSupported ? '\x1b[33m' : '',
  blue: isColorSupported ? '\x1b[34m' : '',
  cyan: isColorSupported ? '\x1b[36m' : '',
  gray: isColorSupported ? '\x1b[90m' : '',
};

function printHelp() {
  console.log(`
${c.bold}Proofbook PB1 Verifier CLI${c.reset}

${c.bold}USAGE:${c.reset}
  proofbook verify <path-to-bundle.json> [options]

${c.bold}COMMANDS:${c.reset}
  verify <file>             Verifies a PB1 proof bundle and checks on-chain Stellar anchor

${c.bold}OPTIONS:${c.reset}
  -n, --network <name>      Stellar network ('testnet', 'public', or 'standalone')
  -c, --contract <id>       Override Soroban contract ID
  --rpc-url <url>           Override Soroban RPC URL
  --auditor <address>       Stellar auditor address to check witness record for
  --skip-blockchain         Perform offline cryptographic verification only
  --offline                 Alias for --skip-blockchain
  --json                    Output full verification report as JSON
  -v, --verbose             Print detailed intermediate proof values
  -h, --help                Show this help message

${c.bold}EXAMPLES:${c.reset}
  proofbook verify ./spec/test-vectors/sample-bundle.json --network testnet
  proofbook verify ./bundle.json --skip-blockchain
  proofbook verify ./bundle.json --network testnet --auditor GA...ABCD
`);
}

function formatLeader(label: string, totalWidth = 28): string {
  const dots = '.'.repeat(Math.max(2, totalWidth - label.length));
  return `${label} ${c.gray}${dots}${c.reset} `;
}

export function renderTerminalReport(
  report: VerificationReport,
  bundlePath: string,
  bundle: ProofBundle,
  options: { verbose?: boolean } = {}
): void {
  const shortRecord = bundle.record?.record_id || 'Unknown';
  const network = bundle.network || 'standalone';
  const checkpointId = report.onChain?.checkpointId ?? bundle.checkpoint_id ?? 1;

  console.log(`\n${c.bold}${c.cyan}Proofbook PB1 Audit Verifier${c.reset} ${c.dim}v0.1.0${c.reset}`);
  console.log(`${c.gray}Bundle:     ${c.reset}${path.resolve(bundlePath)}`);
  console.log(`${c.gray}Record ID:  ${c.reset}${shortRecord} ${c.gray}(Network: ${network})${c.reset}`);
  console.log(`${c.dim}${'─'.repeat(58)}${c.reset}`);

  // 1. Recomputed leaf
  const leafStatus = report.recomputedLeaf ? `${c.green}OK${c.reset}` : `${c.red}FAIL${c.reset}`;
  const leafPreview = report.recomputedLeaf
    ? ` ${c.gray}[${report.recomputedLeaf.slice(0, 8)}...${report.recomputedLeaf.slice(-6)}]${c.reset}`
    : '';
  console.log(`${formatLeader('Recomputed leaf')}${leafStatus}${leafPreview}`);

  // 2. Merkle path to root
  const merkleStep = report.steps.find((s) => s.name === 'Merkle Path');
  const merkleOk = merkleStep ? merkleStep.passed : false;
  const merkleStatus = merkleOk ? `${c.green}OK${c.reset}` : `${c.red}FAIL${c.reset}`;
  const pathDetail = bundle.merkle_path ? ` ${c.gray}(${bundle.merkle_path.length} steps)${c.reset}` : '';
  console.log(`${formatLeader('Merkle path to root')}${merkleStatus}${pathDetail}`);

  // 3. On-chain checkpoint
  if (report.onChain) {
    const cp = report.onChain;
    const cpOk = cp.verified;
    const cpLabel = `On-chain checkpoint #${cp.checkpointId}`;
    if (cpOk) {
      console.log(
        `${formatLeader(cpLabel)}${c.green}root matches${c.reset} ${c.gray}(ledger ${cp.ledger})${c.reset}`
      );
    } else {
      console.log(
        `${formatLeader(cpLabel)}${c.red}ROOT MISMATCH${c.reset} ${c.gray}(on-chain: ${cp.anchoredRoot.slice(0, 8)}...)${c.reset}`
      );
    }
  } else {
    const cpStep = report.steps.find((s) => s.name === 'On-Chain Checkpoint');
    const cpLabel = `On-chain checkpoint #${checkpointId}`;
    if (cpStep && !cpStep.passed) {
      console.log(`${formatLeader(cpLabel)}${c.red}FAIL${c.reset} ${c.gray}(${cpStep.message})${c.reset}`);
    } else {
      console.log(`${formatLeader(cpLabel)}${c.yellow}SKIPPED${c.reset} ${c.gray}(offline mode)${c.reset}`);
    }
  }

  // 4. Author signature
  const authorStatus = report.authorVerified ? `${c.green}OK${c.reset}` : `${c.red}FAIL${c.reset}`;
  const authorKey = bundle.record?.author ? ` ${c.gray}(${bundle.record.author.slice(0, 8)}...)${c.reset}` : '';
  console.log(`${formatLeader('Author signature')}${authorStatus}${authorKey}`);

  // 5. Approver signatures
  const appTotal = report.approverTotal;
  const appVerified = report.approverCountVerified;
  const approverOk = appTotal === 0 || appVerified === appTotal;
  const approverStatus = approverOk ? `${c.green}OK${c.reset}` : `${c.red}FAIL${c.reset}`;
  const approverDetail = ` ${c.gray}(${appVerified} of ${Math.max(1, appTotal)} required)${c.reset}`;
  console.log(`${formatLeader('Approver signatures')}${approverStatus}${approverDetail}`);

  // 6. Auditor witnesses
  const witnesses = report.onChain?.witnesses || [];
  const witnessCount = witnesses.length;
  const witnessPreview =
    witnessCount > 0
      ? ` ${c.gray}(${witnesses.map((w) => w.auditor.slice(0, 8) + '...').join(', ')})${c.reset}`
      : ` ${c.gray}(none recorded)${c.reset}`;
  console.log(`${formatLeader('Auditor witnesses')}${witnessCount}${witnessPreview}`);

  console.log(`${c.dim}${'─'.repeat(58)}${c.reset}`);

  // Final Result
  if (report.valid) {
    console.log(`${c.bold}RESULT: ${c.green}VERIFIED ✓${c.reset}\n`);
  } else {
    console.log(`${c.bold}RESULT: ${c.red}FAILED ✗${c.reset}\n`);
    if (report.errors.length > 0) {
      console.log(`${c.bold}${c.red}Audit Discrepancies:${c.reset}`);
      for (const err of report.errors) {
        console.log(`  ${c.red}•${c.reset} ${err}`);
      }
      console.log();
    }
  }

  if (options.verbose) {
    console.log(`${c.dim}Verification Steps Detail:${c.reset}`);
    for (const step of report.steps) {
      const mark = step.passed ? `${c.green}✓${c.reset}` : `${c.red}✗${c.reset}`;
      console.log(`  ${mark} ${c.bold}${step.name}:${c.reset} ${step.message}`);
    }
    console.log();
  }
}

export async function main(args: string[] = process.argv.slice(2)): Promise<number> {
  const optionsConfig = {
    network: { type: 'string' as const, short: 'n' },
    contract: { type: 'string' as const, short: 'c' },
    'rpc-url': { type: 'string' as const },
    auditor: { type: 'string' as const },
    'skip-blockchain': { type: 'boolean' as const, default: false },
    offline: { type: 'boolean' as const, default: false },
    json: { type: 'boolean' as const, default: false },
    verbose: { type: 'boolean' as const, short: 'v', default: false },
    help: { type: 'boolean' as const, short: 'h', default: false },
  };

  let parsed;
  try {
    parsed = parseArgs({
      args,
      options: optionsConfig,
      allowPositionals: true,
    });
  } catch (err: any) {
    console.error(`${c.red}Argument Error:${c.reset} ${err.message}`);
    printHelp();
    return 1;
  }

  if (parsed.values.help) {
    printHelp();
    return 0;
  }

  const positionals = parsed.positionals;
  let command = positionals[0];
  let bundleFilePath: string | undefined;

  if (command === 'verify') {
    bundleFilePath = positionals[1];
  } else if (command && fs.existsSync(command)) {
    // Convenient shortcut: `proofbook path/to/bundle.json`
    bundleFilePath = command;
    command = 'verify';
  } else {
    console.error(`${c.red}Error:${c.reset} Please provide a path to a PB1 proof bundle.`);
    printHelp();
    return 1;
  }

  if (!bundleFilePath) {
    console.error(`${c.red}Error:${c.reset} Missing path to bundle file.`);
    printHelp();
    return 1;
  }

  const resolvedPath = path.resolve(bundleFilePath);
  if (!fs.existsSync(resolvedPath)) {
    console.error(`${c.red}File Not Found:${c.reset} "${resolvedPath}" does not exist.`);
    return 1;
  }

  let bundle: ProofBundle;
  try {
    const rawContent = fs.readFileSync(resolvedPath, 'utf8');
    bundle = JSON.parse(rawContent) as ProofBundle;
  } catch (err: any) {
    console.error(`${c.red}JSON Parse Error:${c.reset} Failed to read bundle: ${err.message}`);
    return 1;
  }

  const network = parsed.values.network || bundle.network || 'testnet';
  const skipBlockchain =
    Boolean(parsed.values['skip-blockchain']) ||
    Boolean(parsed.values.offline) ||
    network === 'standalone';

  const auditorsToCheck: string[] = [];
  if (parsed.values.auditor) {
    auditorsToCheck.push(parsed.values.auditor);
  }

  const report = await verifyProofBundle(bundle, {
    skipBlockchain,
    contractId: parsed.values.contract,
    rpcUrl: parsed.values['rpc-url'],
    auditorsToCheck,
  });

  if (parsed.values.json) {
    console.log(JSON.stringify(report, (k, v) => (typeof v === 'bigint' ? v.toString() : v), 2));
  } else {
    renderTerminalReport(report, resolvedPath, bundle, {
      verbose: Boolean(parsed.values.verbose),
    });
  }

  return report.valid ? 0 : 1;
}

// Execute when invoked directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main().then((code) => {
    process.exit(code);
  });
}

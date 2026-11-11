import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { loadConfig } from './config.js';
import { createDatabase } from './db/index.js';
import { buildFastifyApp } from './app.js';

export * from './db/index.js';
export * from './config.js';
export * from './app.js';
export * from './records/storage.js';
export * from './proofs/builder.js';
export * from './proofs/routes.js';
export * from './auditor/soroban.js';
export * from './auditor/routes.js';

export async function runServer() {
  const config = loadConfig();
  const dbHandle = await createDatabase({
    databaseUrl: config.databaseUrl,
    dataDir: config.storageDir ? `${config.storageDir}/proofbook.db` : undefined,
  });

  const app = await buildFastifyApp({ dbHandle, config });

  try {
    const address = await app.listen({ port: config.port, host: config.host });
    console.log(`Proofbook API server listening on ${address}`);
    return { app, dbHandle };
  } catch (err) {
    console.error('Failed to start Proofbook API:', err);
    await dbHandle.close();
    process.exit(1);
  }
}

// Only auto-start when invoked directly from CLI
const isDirectRun =
  process.argv[1] &&
  (fileURLToPath(import.meta.url) === path.resolve(process.argv[1]) ||
    process.argv[1].endsWith('apps/api/src/index.ts') ||
    process.argv[1].endsWith('apps/api/dist/index.js'));

if (isDirectRun && process.env.NODE_ENV !== 'test') {
  runServer().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

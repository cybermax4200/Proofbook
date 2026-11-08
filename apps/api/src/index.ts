import { loadConfig } from './config.js';
import { createDatabase } from './db/index.js';
import { buildFastifyApp } from './app.js';

async function main() {
  const config = loadConfig();
  const dbHandle = await createDatabase({
    databaseUrl: config.databaseUrl,
    dataDir: config.storageDir ? `${config.storageDir}/proofbook.db` : undefined,
  });

  const app = await buildFastifyApp({ dbHandle, config });

  try {
    const address = await app.listen({ port: config.port, host: config.host });
    console.log(`Proofbook API server listening on ${address}`);
  } catch (err) {
    console.error('Failed to start Proofbook API:', err);
    await dbHandle.close();
    process.exit(1);
  }
}

if (process.env.NODE_ENV !== 'test') {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

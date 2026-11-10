import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { loadWorkerConfig } from './config.js';
import { CheckpointWorker } from './worker.js';
import { buildWorkerServer } from './server.js';

export * from './config.js';
export * from './soroban.js';
export * from './builder.js';
export * from './worker.js';
export * from './server.js';

export async function runDaemon() {
  const config = loadWorkerConfig();
  console.log('Starting Proofbook Checkpoint Worker service...');

  const worker = await CheckpointWorker.create({ config });
  worker.startInterval(config.intervalSeconds);

  const server = await buildWorkerServer({ worker });
  const address = await server.listen({ port: config.port, host: '0.0.0.0' });
  console.log(`Proofbook Worker trigger endpoint listening on ${address}`);

  const shutdown = async () => {
    console.log('\nShutting down Proofbook Worker...');
    await server.close();
    await worker.close();
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  return { worker, server };
}

const isDirectRun =
  process.argv[1] &&
  (fileURLToPath(import.meta.url) === path.resolve(process.argv[1]) ||
    process.argv[1].endsWith('apps/worker/src/index.ts') ||
    process.argv[1].endsWith('apps/worker/dist/index.js'));

if (isDirectRun && process.env.NODE_ENV !== 'test') {
  runDaemon().catch((err) => {
    console.error('Fatal worker daemon error:', err);
    process.exit(1);
  });
}

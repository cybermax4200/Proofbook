import fastify, { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import cors from '@fastify/cors';
import { CheckpointWorker } from './worker.js';

export interface BuildServerOptions {
  worker: CheckpointWorker;
}

export async function buildWorkerServer(options: BuildServerOptions): Promise<FastifyInstance> {
  const app = fastify({ logger: false });
  const worker = options.worker;

  await app.register(cors, { origin: true });

  // Health check
  app.get('/health', async () => {
    return {
      status: 'ok',
      service: 'proofbook-worker',
      timestamp: new Date().toISOString(),
    };
  });

  // Worker status
  app.get('/checkpoints/status', async () => {
    return worker.getStatus();
  });

  // Manual trigger endpoint
  app.post('/checkpoints/run', async (request: FastifyRequest, reply: FastifyReply) => {
    const body = (request.body as { orgId?: string }) || {};

    try {
      if (body.orgId) {
        const result = await worker.processOrg(body.orgId);
        return reply.status(200).send({
          success: true,
          orgId: body.orgId,
          anchored: result !== null,
          checkpoint: result,
        });
      } else {
        const results = await worker.processAllOrgs();
        return reply.status(200).send({
          success: true,
          count: results.length,
          checkpoints: results,
        });
      }
    } catch (err: any) {
      request.log.error(err);
      return reply.status(500).send({
        error: 'Internal Server Error',
        message: err.message || 'Failed to execute checkpoint run',
      });
    }
  });

  return app;
}

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

  function verifyWorkerAuth(request: FastifyRequest, reply: FastifyReply): boolean {
    const requiredKey = worker.config.workerApiKey;
    if (!requiredKey) {
      return true;
    }
    const authHeader = request.headers.authorization;
    const apiKeyHeader = request.headers['x-api-key'];
    const token =
      typeof authHeader === 'string' && authHeader.startsWith('Bearer ')
        ? authHeader.slice(7).trim()
        : typeof apiKeyHeader === 'string'
          ? apiKeyHeader.trim()
          : '';

    if (token !== requiredKey) {
      reply.status(401).send({
        error: 'Unauthorized',
        message: 'Valid worker API key is required for trigger endpoints',
      });
      return false;
    }
    return true;
  }

  // Manual trigger endpoint
  app.post('/checkpoints/run', async (request: FastifyRequest, reply: FastifyReply) => {
    if (!verifyWorkerAuth(request, reply)) return;
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

  // Manual TTL extension endpoint
  app.post('/checkpoints/extend-ttl', async (request: FastifyRequest, reply: FastifyReply) => {
    if (!verifyWorkerAuth(request, reply)) return;
    try {
      const extended = await worker.extendTtlForActiveOrgs();
      return reply.status(200).send({
        success: true,
        extended,
      });
    } catch (err: any) {
      request.log.error(err);
      return reply.status(500).send({
        error: 'Internal Server Error',
        message: err.message || 'Failed to extend checkpoint TTLs',
      });
    }
  });

  return app;
}

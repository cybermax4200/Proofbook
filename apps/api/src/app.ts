import Fastify, { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import cors from '@fastify/cors';
import jwt from '@fastify/jwt';
import { DatabaseHandle, AppDatabase } from './db/index.js';
import { AppConfig, loadConfig } from './config.js';

declare module 'fastify' {
  interface FastifyInstance {
    db: AppDatabase;
    authenticate: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }
  interface FastifyRequest {
    db: AppDatabase;
  }
}

export interface AppOptions {
  dbHandle: DatabaseHandle;
  config?: AppConfig;
}

export async function buildFastifyApp(options: AppOptions): Promise<FastifyInstance> {
  const config = options.config || loadConfig();
  const app = Fastify({
    logger: false,
  });

  // Attach database handle
  app.decorate('db', options.dbHandle.db);
  app.addHook('onRequest', async (req) => {
    req.db = options.dbHandle.db;
  });

  // CORS
  await app.register(cors, {
    origin: true,
    credentials: true,
  });

  // JWT
  await app.register(jwt, {
    secret: config.jwtSecret,
  });

  // Authentication decorator hook
  app.decorate('authenticate', async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      await request.jwtVerify();
    } catch (err) {
      reply.status(401).send({ error: 'Unauthorized', message: 'Invalid or missing authentication token' });
    }
  });

  // Basic Health Check
  app.get('/health', async () => {
    return {
      status: 'ok',
      version: '0.1.0',
      isPgLite: options.dbHandle.isPgLite,
      timestamp: new Date().toISOString(),
    };
  });

  return app;
}

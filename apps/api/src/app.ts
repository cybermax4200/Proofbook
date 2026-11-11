import Fastify, { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import cors from '@fastify/cors';
import jwt from '@fastify/jwt';
import { DatabaseHandle, AppDatabase } from './db/index.js';
import { AppConfig, loadConfig } from './config.js';
import { authRoutes } from './auth/routes.js';
import { orgRoutes } from './orgs/routes.js';
import { recordRoutes } from './records/routes.js';
import { proofRoutes } from './proofs/routes.js';
import { auditorRoutes } from './auditor/routes.js';
import {
  SorobanAuditorClient,
  createSorobanAuditorClient,
} from './auditor/soroban.js';
import { StorageProvider, createStorageProvider } from './records/storage.js';

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
  storage?: StorageProvider;
  sorobanAuditorClient?: SorobanAuditorClient;
}

export async function buildFastifyApp(options: AppOptions): Promise<FastifyInstance> {
  const config = options.config || loadConfig();
  const storage =
    options.storage ||
    createStorageProvider({
      storageProvider: config.storageProvider,
      storageDir: config.storageDir,
      storageEncryptionKey: config.storageEncryptionKey,
      s3: config.s3,
    });
  const sorobanAuditorClient =
    options.sorobanAuditorClient || createSorobanAuditorClient();

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
      const decoded = await request.jwtVerify<{ id?: string; sub: string; email: string }>();
      request.user = {
        id: decoded.id || decoded.sub,
        email: decoded.email,
      };
    } catch {
      return reply.status(401).send({ error: 'Unauthorized', message: 'Invalid or missing authentication token' });
    }
  });

  // Health check
  app.get('/health', async () => {
    return {
      status: 'ok',
      version: '0.1.0',
      isPgLite: options.dbHandle.isPgLite,
      timestamp: new Date().toISOString(),
    };
  });

  // API v1 routes
  await app.register(authRoutes, { prefix: '/api/v1/auth' });
  await app.register(orgRoutes, { prefix: '/api/v1' });
  await app.register(async (subApp) => {
    await recordRoutes(subApp, { storage });
    await proofRoutes(subApp, { storage });
    await auditorRoutes(subApp, { sorobanAuditorClient });
  }, { prefix: '/api/v1' });

  // Direct root route aliases for standard paths (/orgs/:id/proofs, /engagements/:eid/...)
  await app.register(async (subApp) => {
    await proofRoutes(subApp, { storage });
    await auditorRoutes(subApp, { sorobanAuditorClient });
  });

  return app;
}

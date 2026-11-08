import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import crypto from 'node:crypto';
import { eq, and, isNull } from 'drizzle-orm';
import { users, userKeys } from '../db/schema.js';
import { hashPassword, verifyPassword } from './password.js';
import { decodePublicKey } from '@proofbook/crypto';

export async function authRoutes(app: FastifyInstance) {
  // Register user
  app.post('/register', async (request: FastifyRequest, reply: FastifyReply) => {
    const body = request.body as {
      email?: string;
      password?: string;
      publicKey?: string;
      kind?: string;
    };

    if (!body?.email || !body?.password) {
      return reply.status(400).send({ error: 'Bad Request', message: 'Email and password are required' });
    }

    const email = body.email.trim().toLowerCase();
    if (!email.includes('@') || email.length < 5) {
      return reply.status(400).send({ error: 'Bad Request', message: 'Invalid email address' });
    }

    if (body.password.length < 8) {
      return reply.status(400).send({ error: 'Bad Request', message: 'Password must be at least 8 characters' });
    }

    // Check if user already exists
    const existing = await request.db.select().from(users).where(eq(users.email, email));
    if (existing.length > 0) {
      return reply.status(409).send({ error: 'Conflict', message: 'User with this email already exists' });
    }

    const userId = 'usr_' + crypto.randomUUID().replace(/-/g, '');
    const passwordHash = await hashPassword(body.password);

    await request.db.insert(users).values({
      id: userId,
      email,
      passwordHash,
    });

    let createdKey = null;
    if (body.publicKey) {
      try {
        // Validate public key format using @proofbook/crypto
        decodePublicKey(body.publicKey);
      } catch (err: any) {
        return reply.status(400).send({ error: 'Bad Request', message: `Invalid public key: ${err.message}` });
      }

      const keyId = 'key_' + crypto.randomUUID().replace(/-/g, '');
      const kind = body.kind || 'ed25519';

      await request.db.insert(userKeys).values({
        id: keyId,
        userId,
        publicKey: body.publicKey,
        kind,
      });

      createdKey = {
        id: keyId,
        publicKey: body.publicKey,
        kind,
      };
    }

    const token = app.jwt.sign({ id: userId, sub: userId, email });

    return reply.status(201).send({
      user: {
        id: userId,
        email,
      },
      token,
      key: createdKey,
    });
  });

  // Login user
  app.post('/login', async (request: FastifyRequest, reply: FastifyReply) => {
    const body = request.body as { email?: string; password?: string };

    if (!body?.email || !body?.password) {
      return reply.status(400).send({ error: 'Bad Request', message: 'Email and password are required' });
    }

    const email = body.email.trim().toLowerCase();
    const rows = await request.db.select().from(users).where(eq(users.email, email));
    if (rows.length === 0) {
      return reply.status(401).send({ error: 'Unauthorized', message: 'Invalid email or password' });
    }

    const user = rows[0];
    const valid = await verifyPassword(body.password, user.passwordHash);
    if (!valid) {
      return reply.status(401).send({ error: 'Unauthorized', message: 'Invalid email or password' });
    }

    const token = app.jwt.sign({ id: user.id, sub: user.id, email: user.email });

    return {
      user: {
        id: user.id,
        email: user.email,
      },
      token,
    };
  });

  // Get current user profile and keys
  app.get('/me', { preHandler: [app.authenticate] }, async (request: FastifyRequest) => {
    const userId = request.user.id;
    const userRows = await request.db.select().from(users).where(eq(users.id, userId));
    if (userRows.length === 0) {
      throw new Error('User not found');
    }

    const user = userRows[0];
    const keys = await request.db
      .select({
        id: userKeys.id,
        publicKey: userKeys.publicKey,
        kind: userKeys.kind,
        createdAt: userKeys.createdAt,
        revokedAt: userKeys.revokedAt,
      })
      .from(userKeys)
      .where(eq(userKeys.userId, userId));

    return {
      user: {
        id: user.id,
        email: user.email,
        createdAt: user.createdAt,
      },
      keys,
    };
  });

  // Register a new Ed25519 signing public key
  app.post('/keys', { preHandler: [app.authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const userId = request.user.id;
    const body = request.body as { publicKey?: string; kind?: string };

    if (!body?.publicKey) {
      return reply.status(400).send({ error: 'Bad Request', message: 'publicKey is required' });
    }

    try {
      decodePublicKey(body.publicKey);
    } catch (err: any) {
      return reply.status(400).send({ error: 'Bad Request', message: `Invalid public key: ${err.message}` });
    }

    const keyId = 'key_' + crypto.randomUUID().replace(/-/g, '');
    const kind = body.kind || 'ed25519';

    await request.db.insert(userKeys).values({
      id: keyId,
      userId,
      publicKey: body.publicKey,
      kind,
    });

    return reply.status(201).send({
      key: {
        id: keyId,
        userId,
        publicKey: body.publicKey,
        kind,
      },
    });
  });

  // Revoke a public key
  app.delete('/keys/:id', { preHandler: [app.authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const userId = request.user.id;
    const { id } = request.params as { id: string };

    const keyRows = await request.db
      .select()
      .from(userKeys)
      .where(and(eq(userKeys.id, id), eq(userKeys.userId, userId)));

    if (keyRows.length === 0) {
      return reply.status(404).send({ error: 'Not Found', message: 'Public key not found' });
    }

    const key = keyRows[0];
    if (key.revokedAt) {
      return reply.status(400).send({ error: 'Bad Request', message: 'Key is already revoked' });
    }

    const revokedAt = new Date();
    await request.db.update(userKeys).set({ revokedAt }).where(eq(userKeys.id, id));

    return {
      success: true,
      keyId: id,
      revokedAt,
    };
  });
}

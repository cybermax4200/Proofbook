import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import crypto from 'node:crypto';
import { eq, and } from 'drizzle-orm';
import { orgs, memberships, users, orgSigners } from '../db/schema.js';
import { requireOrgRole } from '../auth/middleware.js';
import { decodePublicKey, encodeStellarPublicKey } from '@proofbook/crypto';

const VALID_ROLES = ['admin', 'maker', 'checker', 'auditor'] as const;
type Role = (typeof VALID_ROLES)[number];

export async function orgRoutes(app: FastifyInstance) {
  // Create organization
  app.post('/orgs', { preHandler: [app.authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const userId = request.user.id;
    const body = request.body as { name?: string; stellarAddress?: string };

    if (!body?.name || body.name.trim().length === 0) {
      return reply.status(400).send({ error: 'Bad Request', message: 'Organization name is required' });
    }

    const orgId = 'org_' + crypto.randomUUID().replace(/-/g, '');
    const name = body.name.trim();
    const stellarAddress = body.stellarAddress?.trim() || null;

    await request.db.insert(orgs).values({
      id: orgId,
      name,
      stellarAddress,
    });

    await request.db.insert(memberships).values({
      orgId,
      userId,
      role: 'admin',
    });

    return reply.status(201).send({
      org: {
        id: orgId,
        name,
        stellarAddress,
      },
      role: 'admin',
    });
  });

  // List user's organizations
  app.get('/orgs', { preHandler: [app.authenticate] }, async (request: FastifyRequest) => {
    const userId = request.user.id;

    const userMemberships = await request.db
      .select({
        orgId: memberships.orgId,
        role: memberships.role,
        name: orgs.name,
        stellarAddress: orgs.stellarAddress,
        createdAt: orgs.createdAt,
      })
      .from(memberships)
      .innerJoin(orgs, eq(memberships.orgId, orgs.id))
      .where(eq(memberships.userId, userId));

    return {
      orgs: userMemberships.map((m) => ({
        id: m.orgId,
        name: m.name,
        stellarAddress: m.stellarAddress,
        role: m.role,
        createdAt: m.createdAt,
      })),
    };
  });

  // Get specific organization details
  app.get('/orgs/:id', { preHandler: [requireOrgRole([])] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const userId = request.user.id;
    const { id } = request.params as { id: string };

    const orgRows = await request.db.select().from(orgs).where(eq(orgs.id, id));
    if (orgRows.length === 0) {
      return reply.status(404).send({ error: 'Not Found', message: 'Organization not found' });
    }

    const org = orgRows[0];
    const memberRows = await request.db
      .select({
        userId: memberships.userId,
        email: users.email,
        role: memberships.role,
        createdAt: memberships.createdAt,
      })
      .from(memberships)
      .innerJoin(users, eq(memberships.userId, users.id))
      .where(eq(memberships.orgId, id));

    const currentUserMember = memberRows.find((m) => m.userId === userId);

    return {
      org,
      myRole: currentUserMember?.role,
      members: memberRows,
    };
  });

  // Add or update organization member (requires admin)
  app.post(
    '/orgs/:id/members',
    { preHandler: [requireOrgRole(['admin'])] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const { id } = request.params as { id: string };
      const body = request.body as { email?: string; role?: string };

      if (!body?.email || !body?.role) {
        return reply.status(400).send({ error: 'Bad Request', message: 'email and role are required' });
      }

      if (!VALID_ROLES.includes(body.role as Role)) {
        return reply.status(400).send({
          error: 'Bad Request',
          message: `Invalid role "${body.role}". Allowed roles: ${VALID_ROLES.join(', ')}`,
        });
      }

      const email = body.email.trim().toLowerCase();
      const userRows = await request.db.select().from(users).where(eq(users.email, email));
      if (userRows.length === 0) {
        return reply.status(404).send({
          error: 'Not Found',
          message: `User with email "${email}" not found. User must register first.`,
        });
      }

      const targetUser = userRows[0];

      // Check existing membership
      const existing = await request.db
        .select()
        .from(memberships)
        .where(and(eq(memberships.orgId, id), eq(memberships.userId, targetUser.id)));

      if (existing.length > 0) {
        await request.db
          .update(memberships)
          .set({ role: body.role })
          .where(and(eq(memberships.orgId, id), eq(memberships.userId, targetUser.id)));
      } else {
        await request.db.insert(memberships).values({
          orgId: id,
          userId: targetUser.id,
          role: body.role,
        });
      }

      return reply.status(200).send({
        success: true,
        member: {
          userId: targetUser.id,
          email: targetUser.email,
          role: body.role,
        },
      });
    }
  );

  // Update member role by userId (requires admin)
  app.patch(
    '/orgs/:id/members/:uid',
    { preHandler: [requireOrgRole(['admin'])] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const { id, uid } = request.params as { id: string; uid: string };
      const body = request.body as { role?: string };

      if (!body?.role || !VALID_ROLES.includes(body.role as Role)) {
        return reply.status(400).send({
          error: 'Bad Request',
          message: `Invalid role "${body?.role}". Allowed roles: ${VALID_ROLES.join(', ')}`,
        });
      }

      const existing = await request.db
        .select()
        .from(memberships)
        .where(and(eq(memberships.orgId, id), eq(memberships.userId, uid)));

      if (existing.length === 0) {
        return reply.status(404).send({
          error: 'Not Found',
          message: 'Organization member not found',
        });
      }

      await request.db
        .update(memberships)
        .set({ role: body.role })
        .where(and(eq(memberships.orgId, id), eq(memberships.userId, uid)));

      return {
        success: true,
        member: {
          orgId: id,
          userId: uid,
          role: body.role,
        },
      };
    }
  );

  // Register organization Stellar signer (requires admin)
  app.post(
    '/orgs/:id/signers',
    { preHandler: [requireOrgRole(['admin'])] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const { id } = request.params as { id: string };
      const body = request.body as { stellarAddress?: string; publicKey?: string };

      const inputKey = body?.stellarAddress || body?.publicKey;
      if (!inputKey) {
        return reply.status(400).send({
          error: 'Bad Request',
          message: 'stellarAddress or publicKey is required',
        });
      }

      let rawPubKey: Uint8Array;
      try {
        rawPubKey = decodePublicKey(inputKey);
      } catch (err: any) {
        return reply.status(400).send({
          error: 'Bad Request',
          message: `Invalid signer public key: ${err.message}`,
        });
      }

      const stellarAddress = body.stellarAddress?.startsWith('G')
        ? body.stellarAddress.trim()
        : encodeStellarPublicKey(rawPubKey);
      const publicKeyHex = Buffer.from(rawPubKey).toString('hex');

      const signerId = 'sigkey_' + crypto.randomUUID().replace(/-/g, '');
      await request.db.insert(orgSigners).values({
        id: signerId,
        orgId: id,
        stellarAddress,
        publicKey: publicKeyHex,
      });

      await request.db
        .update(orgs)
        .set({ stellarAddress })
        .where(eq(orgs.id, id));

      return reply.status(201).send({
        signer: {
          id: signerId,
          orgId: id,
          stellarAddress,
          publicKey: publicKeyHex,
        },
      });
    }
  );
}

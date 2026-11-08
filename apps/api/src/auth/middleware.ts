import { FastifyRequest, FastifyReply } from 'fastify';
import { memberships } from '../db/schema.js';
import { and, eq } from 'drizzle-orm';

export interface AuthUser {
  id: string;
  email: string;
}

declare module '@fastify/jwt' {
  interface FastifyJWT {
    payload: { id?: string; sub: string; email: string };
    user: AuthUser;
  }
}

/**
 * Middleware factory requiring user to belong to the specified organization
 * and have one of the required roles.
 */
export function requireOrgRole(allowedRoles: string[]) {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    // 1. Ensure user is authenticated
    try {
      const decoded = await request.jwtVerify<{ id?: string; sub: string; email: string }>();
      request.user = {
        id: decoded.id || decoded.sub,
        email: decoded.email,
      };
    } catch {
      return reply.status(401).send({ error: 'Unauthorized', message: 'Authentication required' });
    }

    const user = request.user;
    const params = request.params as Record<string, string>;
    const orgId = params.orgId || params.id;

    if (!orgId) {
      return reply.status(400).send({ error: 'Bad Request', message: 'Organization ID parameter missing' });
    }

    // 2. Query membership
    const memberRows = await request.db
      .select()
      .from(memberships)
      .where(and(eq(memberships.orgId, orgId), eq(memberships.userId, user.id)));

    if (memberRows.length === 0) {
      return reply.status(403).send({ error: 'Forbidden', message: 'User is not a member of this organization' });
    }

    const member = memberRows[0];
    if (allowedRoles.length > 0 && !allowedRoles.includes(member.role)) {
      return reply.status(403).send({
        error: 'Forbidden',
        message: `Role "${member.role}" is not authorized. Required: ${allowedRoles.join(', ')}`,
      });
    }
  };
}

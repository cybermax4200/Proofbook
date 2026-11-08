import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import crypto from 'node:crypto';
import { eq, and, desc } from 'drizzle-orm';
import { records, recordSignatures, userKeys, memberships } from '../db/schema.js';
import { requireOrgRole } from '../auth/middleware.js';
import { computeRecordLeaf, verifySignature, decodePublicKey } from '@proofbook/crypto';
import { StorageProvider } from './storage.js';

export interface RecordRoutesOptions {
  storage: StorageProvider;
}

export async function recordRoutes(app: FastifyInstance, options: RecordRoutesOptions) {
  const storage = options.storage;

  // Ingest encrypted record with cryptographic commitment and author signature
  app.post(
    '/orgs/:id/records',
    { preHandler: [requireOrgRole(['admin', 'maker'])] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const { id: orgId } = request.params as { id: string };
      const userId = request.user.id;

      const body = request.body as {
        recordId?: string;
        type?: string;
        createdAt?: string;
        fieldRoot?: string;
        ciphertext?: string;
        authorKeyId?: string;
        authorSignature?: string;
        leafHash?: string;
      };

      if (!body?.authorKeyId || !body?.fieldRoot || !body?.ciphertext || !body?.authorSignature) {
        return reply.status(400).send({
          error: 'Bad Request',
          message: 'Missing required fields: authorKeyId, fieldRoot, ciphertext, authorSignature',
        });
      }

      // 1. Validate author key exists, belongs to caller, and is not revoked
      const keyRows = await request.db
        .select()
        .from(userKeys)
        .where(and(eq(userKeys.id, body.authorKeyId), eq(userKeys.userId, userId)));

      if (keyRows.length === 0) {
        return reply.status(400).send({
          error: 'Bad Request',
          message: 'authorKeyId does not exist or does not belong to the authenticated user',
        });
      }

      const authorKey = keyRows[0];
      if (authorKey.revokedAt) {
        return reply.status(400).send({
          error: 'Bad Request',
          message: 'Signing key has been revoked',
        });
      }

      const recordId = body.recordId || 'rec_' + crypto.randomUUID().replace(/-/g, '');
      const createdAt = body.createdAt || new Date().toISOString();
      const type = body.type || 'default';

      // 2. Check if record ID already exists
      const existing = await request.db.select().from(records).where(eq(records.id, recordId));
      if (existing.length > 0) {
        return reply.status(409).send({ error: 'Conflict', message: `Record ${recordId} already exists` });
      }

      // 3. Compute PB1 Record Leaf Hash
      let leafBytes: Uint8Array;
      try {
        leafBytes = computeRecordLeaf({
          recordId,
          author: authorKey.publicKey,
          createdAt,
          fieldRoot: body.fieldRoot,
        });
      } catch (err: any) {
        return reply.status(400).send({
          error: 'Bad Request',
          message: `Failed to compute record leaf: ${err.message}`,
        });
      }

      const computedLeafHex = Buffer.from(leafBytes).toString('hex');

      // Verify supplied leafHash if client sent one
      if (body.leafHash) {
        const clientLeaf = body.leafHash.replace(/^0x/, '').toLowerCase();
        if (clientLeaf !== computedLeafHex) {
          return reply.status(400).send({
            error: 'Bad Request',
            message: `Provided leafHash "${body.leafHash}" does not match recomputed leaf "${computedLeafHex}"`,
          });
        }
      }

      // 4. Verify Ed25519 author signature over computed leaf hash
      let isValidSignature = false;
      try {
        isValidSignature = verifySignature(body.authorSignature, leafBytes, authorKey.publicKey);
      } catch (err: any) {
        return reply.status(400).send({
          error: 'Bad Request',
          message: `Signature verification error: ${err.message}`,
        });
      }

      if (!isValidSignature) {
        return reply.status(400).send({
          error: 'Bad Request',
          message: 'Invalid author signature: verification failed against author public key',
        });
      }

      // 5. Store ciphertext in storage provider
      const storageKey = `records/${orgId}/${recordId}.bin`;
      const ciphertextRef = await storage.put(storageKey, body.ciphertext);

      // 6. Monotonic sequence number for organization
      const lastRecord = await request.db
        .select({ seqNo: records.seqNo })
        .from(records)
        .where(eq(records.orgId, orgId))
        .orderBy(desc(records.seqNo))
        .limit(1);

      const seqNo = lastRecord.length > 0 ? lastRecord[0].seqNo + 1 : 1;

      // 7. Persist record
      await request.db.insert(records).values({
        id: recordId,
        orgId,
        type,
        authorKeyId: authorKey.id,
        status: 'pending',
        leafHash: computedLeafHex,
        fieldRoot: body.fieldRoot.replace(/^0x/, '').toLowerCase(),
        ciphertextRef,
        seqNo,
        createdAt,
      });

      // 8. Persist author signature
      const sigId = 'sig_' + crypto.randomUUID().replace(/-/g, '');
      const rawSig = body.authorSignature.replace(/^0x/, '').toLowerCase();
      await request.db.insert(recordSignatures).values({
        id: sigId,
        recordId,
        keyId: authorKey.id,
        kind: 'author',
        signature: rawSig,
      });

      return reply.status(201).send({
        record: {
          id: recordId,
          orgId,
          type,
          authorKeyId: authorKey.id,
          status: 'pending',
          leafHash: computedLeafHex,
          fieldRoot: body.fieldRoot,
          ciphertextRef,
          seqNo,
          createdAt,
        },
        signature: {
          id: sigId,
          kind: 'author',
          signature: rawSig,
          keyId: authorKey.id,
        },
      });
    }
  );

  // List records for an organization
  app.get(
    '/orgs/:id/records',
    { preHandler: [requireOrgRole([])] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const { id: orgId } = request.params as { id: string };
      const query = request.query as {
        status?: string;
        type?: string;
        limit?: string;
        offset?: string;
      };

      const limit = Math.min(parseInt(query.limit || '50', 10), 100);
      const offset = parseInt(query.offset || '0', 10);

      const conditions = [eq(records.orgId, orgId)];
      if (query.status) {
        conditions.push(eq(records.status, query.status));
      }
      if (query.type) {
        conditions.push(eq(records.type, query.type));
      }

      const rows = await request.db
        .select()
        .from(records)
        .where(and(...conditions))
        .orderBy(desc(records.seqNo))
        .limit(limit)
        .offset(offset);

      return {
        records: rows,
        count: rows.length,
        limit,
        offset,
      };
    }
  );

  // Get specific record with signatures and decrypted ciphertext ref
  app.get(
    '/orgs/:id/records/:rid',
    { preHandler: [requireOrgRole([])] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const { id: orgId, rid: recordId } = request.params as { id: string; rid: string };

      const rows = await request.db
        .select()
        .from(records)
        .where(and(eq(records.id, recordId), eq(records.orgId, orgId)));

      if (rows.length === 0) {
        return reply.status(404).send({ error: 'Not Found', message: 'Record not found' });
      }

      const record = rows[0];

      // Fetch signatures
      const signatures = await request.db
        .select()
        .from(recordSignatures)
        .where(eq(recordSignatures.recordId, recordId));

      // Fetch author key
      const keyRows = await request.db
        .select()
        .from(userKeys)
        .where(eq(userKeys.id, record.authorKeyId));

      // Fetch ciphertext from storage
      const ciphertext = await storage.get(record.ciphertextRef);

      return {
        record,
        authorKey: keyRows[0] || null,
        signatures,
        ciphertext,
      };
    }
  );
}

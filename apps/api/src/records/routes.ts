import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import crypto from 'node:crypto';
import { eq, and, desc, asc } from 'drizzle-orm';
import {
  records,
  recordSignatures,
  userKeys,
  evidence,
  auditLogs,
} from '../db/schema.js';
import { requireOrgRole } from '../auth/middleware.js';
import {
  computeRecordLeaf,
  verifySignature,
  computeEvidenceHash,
  verifyEvidenceHash,
} from '@proofbook/crypto';
import { StorageProvider } from './storage.js';

export interface RecordRoutesOptions {
  storage: StorageProvider;
}

export interface EvidenceInput {
  id?: string;
  sha256?: string;
  ciphertext: string;
  content?: string;
}

function normalizeCanonicalEvidenceHash(inputHash?: string, rawContent?: string): string {
  if (rawContent !== undefined) {
    const computed = computeEvidenceHash(rawContent);
    if (inputHash && !verifyEvidenceHash(rawContent, inputHash)) {
      throw new Error(
        `Evidence hash mismatch: provided "${inputHash}" does not match computed "${computed}"`
      );
    }
    return computed;
  }

  if (!inputHash) {
    throw new Error('Missing evidence sha256 hash or raw content');
  }

  const trimmed = inputHash.trim().toLowerCase();
  const hexPart = trimmed.startsWith('sha256:')
    ? trimmed.slice(7)
    : trimmed.replace(/^0x/, '');

  if (!/^[0-9a-f]{64}$/.test(hexPart)) {
    throw new Error('Invalid evidence sha256 digest: expected 64-character hex string or sha256:<hex>');
  }

  return `sha256:${hexPart}`;
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
        status?: 'draft' | 'pending';
        createdAt?: string;
        fieldRoot?: string;
        ciphertext?: string;
        authorKeyId?: string;
        authorSignature?: string;
        leafHash?: string;
        evidence?: EvidenceInput[];
      };

      if (!body?.authorKeyId || !body?.fieldRoot || !body?.ciphertext || !body?.authorSignature) {
        return reply.status(400).send({
          error: 'Bad Request',
          message: 'Missing required fields: authorKeyId, fieldRoot, ciphertext, authorSignature',
        });
      }

      const initialStatus = body.status === 'draft' ? 'draft' : 'pending';

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

      // Validate optional inline evidence before persisting
      const preparedEvidence: Array<{ id: string; sha256: string; ciphertext: string }> = [];
      if (Array.isArray(body.evidence)) {
        for (const item of body.evidence) {
          if (!item?.ciphertext) {
            return reply.status(400).send({
              error: 'Bad Request',
              message: 'Each evidence attachment requires a ciphertext field',
            });
          }
          try {
            const canonicalHash = normalizeCanonicalEvidenceHash(item.sha256, item.content);
            preparedEvidence.push({
              id: item.id || 'ev_' + crypto.randomUUID().replace(/-/g, ''),
              sha256: canonicalHash,
              ciphertext: item.ciphertext,
            });
          } catch (err: any) {
            return reply.status(400).send({
              error: 'Bad Request',
              message: err.message,
            });
          }
        }
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
        status: initialStatus,
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

      // 9. Persist any inline evidence attachments
      const savedEvidence = [];
      for (const ev of preparedEvidence) {
        const evStorageKey = `evidence/${orgId}/${recordId}/${ev.id}.bin`;
        const evCiphertextRef = await storage.put(evStorageKey, ev.ciphertext);
        await request.db.insert(evidence).values({
          id: ev.id,
          recordId,
          sha256: ev.sha256,
          ciphertextRef: evCiphertextRef,
        });
        savedEvidence.push({
          id: ev.id,
          recordId,
          sha256: ev.sha256,
          ciphertextRef: evCiphertextRef,
        });
      }

      // 10. Log audit trail entry
      await request.db.insert(auditLogs).values({
        id: 'aud_' + crypto.randomUUID().replace(/-/g, ''),
        orgId,
        recordId,
        actorId: userId,
        action: initialStatus === 'pending' ? 'record.submitted' : 'record.drafted',
      });

      return reply.status(201).send({
        record: {
          id: recordId,
          orgId,
          type,
          authorKeyId: authorKey.id,
          status: initialStatus,
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
        evidence: savedEvidence,
      });
    }
  );

  // Submit a draft record to transition status to 'pending'
  app.post(
    '/orgs/:id/records/:rid/submit',
    { preHandler: [requireOrgRole(['admin', 'maker'])] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const { id: orgId, rid: recordId } = request.params as { id: string; rid: string };
      const userId = request.user.id;

      const rows = await request.db
        .select()
        .from(records)
        .where(and(eq(records.id, recordId), eq(records.orgId, orgId)));

      if (rows.length === 0) {
        return reply.status(404).send({ error: 'Not Found', message: 'Record not found' });
      }

      const record = rows[0];
      if (record.status !== 'draft' && record.status !== 'pending') {
        return reply.status(409).send({
          error: 'Conflict',
          message: `Cannot submit record in "${record.status}" status`,
        });
      }

      await request.db
        .update(records)
        .set({ status: 'pending' })
        .where(eq(records.id, recordId));

      await request.db.insert(auditLogs).values({
        id: 'aud_' + crypto.randomUUID().replace(/-/g, ''),
        orgId,
        recordId,
        actorId: userId,
        action: 'record.submitted',
      });

      const updatedRows = await request.db.select().from(records).where(eq(records.id, recordId));

      return {
        record: updatedRows[0],
      };
    }
  );

  // Maker-checker approval: Checker verifies and adds co-signature over leaf_hash
  app.post(
    '/orgs/:id/records/:rid/approve',
    { preHandler: [requireOrgRole(['admin', 'checker'])] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const { id: orgId, rid: recordId } = request.params as { id: string; rid: string };
      const userId = request.user.id;

      const body = request.body as {
        approverKeyId?: string;
        keyId?: string;
        approverSignature?: string;
        signature?: string;
      };

      const approverKeyId = body?.approverKeyId || body?.keyId;
      const approverSignature = body?.approverSignature || body?.signature;

      if (!approverKeyId || !approverSignature) {
        return reply.status(400).send({
          error: 'Bad Request',
          message: 'Missing required fields: approverKeyId (or keyId), approverSignature (or signature)',
        });
      }

      // 1. Fetch record
      const recordRows = await request.db
        .select()
        .from(records)
        .where(and(eq(records.id, recordId), eq(records.orgId, orgId)));

      if (recordRows.length === 0) {
        return reply.status(404).send({ error: 'Not Found', message: 'Record not found' });
      }

      const record = recordRows[0];

      // 2. Ensure record is in 'pending' status
      if (record.status !== 'pending') {
        return reply.status(409).send({
          error: 'Conflict',
          message: `Record cannot be approved because its status is "${record.status}" (expected "pending")`,
        });
      }

      // 3. Enforce Maker-Checker separation: Author cannot approve their own record
      const authorKeyRows = await request.db
        .select()
        .from(userKeys)
        .where(eq(userKeys.id, record.authorKeyId));

      if (
        record.authorKeyId === approverKeyId ||
        (authorKeyRows.length > 0 && authorKeyRows[0].userId === userId)
      ) {
        return reply.status(403).send({
          error: 'Forbidden',
          message: 'Author cannot approve their own record',
        });
      }

      // 4. Validate approver key belongs to the authenticated checker and is active
      const checkerKeyRows = await request.db
        .select()
        .from(userKeys)
        .where(and(eq(userKeys.id, approverKeyId), eq(userKeys.userId, userId)));

      if (checkerKeyRows.length === 0) {
        return reply.status(400).send({
          error: 'Bad Request',
          message: 'approverKeyId does not exist or does not belong to the authenticated checker',
        });
      }

      const checkerKey = checkerKeyRows[0];
      if (checkerKey.revokedAt) {
        return reply.status(400).send({
          error: 'Bad Request',
          message: 'Approver signing key has been revoked',
        });
      }

      // 5. Verify Ed25519 signature over record.leafHash
      const leafBytes = Buffer.from(record.leafHash, 'hex');
      let isValidSignature = false;
      try {
        isValidSignature = verifySignature(approverSignature, leafBytes, checkerKey.publicKey);
      } catch (err: any) {
        return reply.status(400).send({
          error: 'Bad Request',
          message: `Signature verification error: ${err.message}`,
        });
      }

      if (!isValidSignature) {
        return reply.status(400).send({
          error: 'Bad Request',
          message: 'Invalid approver signature: verification failed against checker public key',
        });
      }

      // 6. Store approver co-signature and mark record as approved
      const sigId = 'sig_' + crypto.randomUUID().replace(/-/g, '');
      const rawSig = approverSignature.replace(/^0x/, '').toLowerCase();

      await request.db.insert(recordSignatures).values({
        id: sigId,
        recordId,
        keyId: checkerKey.id,
        kind: 'approver',
        signature: rawSig,
      });

      const approvedAt = new Date();
      await request.db
        .update(records)
        .set({ status: 'approved', approvedAt })
        .where(eq(records.id, recordId));

      await request.db.insert(auditLogs).values({
        id: 'aud_' + crypto.randomUUID().replace(/-/g, ''),
        orgId,
        recordId,
        actorId: userId,
        action: 'record.approved',
      });

      const updatedRecordRows = await request.db.select().from(records).where(eq(records.id, recordId));

      return reply.status(200).send({
        record: updatedRecordRows[0],
        signature: {
          id: sigId,
          recordId,
          keyId: checkerKey.id,
          kind: 'approver',
          signature: rawSig,
        },
      });
    }
  );

  // Maker-checker rejection flow with audit reason logged
  app.post(
    '/orgs/:id/records/:rid/reject',
    { preHandler: [requireOrgRole(['admin', 'checker'])] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const { id: orgId, rid: recordId } = request.params as { id: string; rid: string };
      const userId = request.user.id;

      const body = request.body as {
        reason?: string;
      };

      const reason = body?.reason?.trim();
      if (!reason) {
        return reply.status(400).send({
          error: 'Bad Request',
          message: 'Rejection reason is required for audit compliance',
        });
      }

      const recordRows = await request.db
        .select()
        .from(records)
        .where(and(eq(records.id, recordId), eq(records.orgId, orgId)));

      if (recordRows.length === 0) {
        return reply.status(404).send({ error: 'Not Found', message: 'Record not found' });
      }

      const record = recordRows[0];
      if (record.status !== 'pending') {
        return reply.status(409).send({
          error: 'Conflict',
          message: `Record cannot be rejected because its status is "${record.status}" (expected "pending")`,
        });
      }

      const rejectedAt = new Date();
      await request.db
        .update(records)
        .set({
          status: 'rejected',
          rejectedAt,
          rejectionReason: reason,
          rejectedByUserId: userId,
        })
        .where(eq(records.id, recordId));

      const auditLogId = 'aud_' + crypto.randomUUID().replace(/-/g, '');
      await request.db.insert(auditLogs).values({
        id: auditLogId,
        orgId,
        recordId,
        actorId: userId,
        action: 'record.rejected',
        reason,
      });

      const updatedRecordRows = await request.db.select().from(records).where(eq(records.id, recordId));
      const auditRows = await request.db.select().from(auditLogs).where(eq(auditLogs.id, auditLogId));

      return reply.status(200).send({
        record: updatedRecordRows[0],
        auditLog: auditRows[0],
      });
    }
  );

  // Attach encrypted evidence blob to a record
  app.post(
    '/orgs/:id/records/:rid/evidence',
    { preHandler: [requireOrgRole(['admin', 'maker'])] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const { id: orgId, rid: recordId } = request.params as { id: string; rid: string };
      const userId = request.user.id;

      const body = request.body as EvidenceInput;
      if (!body?.ciphertext) {
        return reply.status(400).send({
          error: 'Bad Request',
          message: 'Missing required field: ciphertext',
        });
      }

      const recordRows = await request.db
        .select()
        .from(records)
        .where(and(eq(records.id, recordId), eq(records.orgId, orgId)));

      if (recordRows.length === 0) {
        return reply.status(404).send({ error: 'Not Found', message: 'Record not found' });
      }

      let canonicalHash: string;
      try {
        canonicalHash = normalizeCanonicalEvidenceHash(body.sha256, body.content);
      } catch (err: any) {
        return reply.status(400).send({
          error: 'Bad Request',
          message: err.message,
        });
      }

      const evidenceId = body.id || 'ev_' + crypto.randomUUID().replace(/-/g, '');
      const storageKey = `evidence/${orgId}/${recordId}/${evidenceId}.bin`;
      const ciphertextRef = await storage.put(storageKey, body.ciphertext);

      await request.db.insert(evidence).values({
        id: evidenceId,
        recordId,
        sha256: canonicalHash,
        ciphertextRef,
      });

      await request.db.insert(auditLogs).values({
        id: 'aud_' + crypto.randomUUID().replace(/-/g, ''),
        orgId,
        recordId,
        actorId: userId,
        action: 'evidence.attached',
        reason: canonicalHash,
      });

      const evRows = await request.db.select().from(evidence).where(eq(evidence.id, evidenceId));

      return reply.status(201).send({
        evidence: evRows[0],
      });
    }
  );

  // Retrieve encrypted evidence blob for a record
  app.get(
    '/orgs/:id/records/:rid/evidence/:eid',
    { preHandler: [requireOrgRole([])] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const { id: orgId, rid: recordId, eid: evidenceId } = request.params as {
        id: string;
        rid: string;
        eid: string;
      };

      const recordRows = await request.db
        .select()
        .from(records)
        .where(and(eq(records.id, recordId), eq(records.orgId, orgId)));

      if (recordRows.length === 0) {
        return reply.status(404).send({ error: 'Not Found', message: 'Record not found' });
      }

      const evRows = await request.db
        .select()
        .from(evidence)
        .where(and(eq(evidence.id, evidenceId), eq(evidence.recordId, recordId)));

      if (evRows.length === 0) {
        return reply.status(404).send({ error: 'Not Found', message: 'Evidence attachment not found' });
      }

      const ev = evRows[0];
      const ciphertext = await storage.get(ev.ciphertextRef);

      return {
        evidence: ev,
        ciphertext,
      };
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

  // Get specific record with signatures, evidence, audit logs, and encrypted payload
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

      // Fetch evidence attachments
      const evidenceRows = await request.db
        .select()
        .from(evidence)
        .where(eq(evidence.recordId, recordId));

      // Fetch audit trail
      const logs = await request.db
        .select()
        .from(auditLogs)
        .where(eq(auditLogs.recordId, recordId))
        .orderBy(asc(auditLogs.createdAt));

      // Fetch ciphertext from storage
      const ciphertext = await storage.get(record.ciphertextRef);

      return {
        record,
        authorKey: keyRows[0] || null,
        signatures,
        evidence: evidenceRows,
        auditLogs: logs,
        ciphertext,
      };
    }
  );
}

import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import crypto from 'node:crypto';
import { eq, and, desc, inArray, gte, lte } from 'drizzle-orm';
import * as StellarSdk from '@stellar/stellar-sdk';
import {
  orgs,
  memberships,
  users,
  records,
  checkpoints,
  checkpointRecords,
  checkpointWitnesses,
  engagements,
  auditLogs,
  recordSignatures,
} from '../db/schema.js';
import { requireOrgRole } from '../auth/middleware.js';
import { SorobanAuditorClient } from './soroban.js';

export interface AuditorRoutesOptions {
  sorobanAuditorClient: SorobanAuditorClient;
}

export interface EngagementScope {
  recordTypes?: string[];
  startDate?: string;
  endDate?: string;
  status?: string | string[];
}

export async function auditorRoutes(app: FastifyInstance, options: AuditorRoutesOptions) {
  const sorobanClient = options.sorobanAuditorClient;

  // 1. POST /orgs/:id/engagements: Auditor invite and access scoping (requires org admin)
  const createEngagementHandler = async (request: FastifyRequest, reply: FastifyReply) => {
    const { id: orgId } = request.params as { id: string };
    const adminUserId = request.user.id;

    const body = request.body as {
      auditorEmail?: string;
      auditorUserId?: string;
      auditorAddress?: string;
      title?: string;
      scope?: EngagementScope;
    };

    if (!body?.title || body.title.trim().length === 0) {
      return reply.status(400).send({
        error: 'Bad Request',
        message: 'Missing required field: title',
      });
    }

    if (!body.auditorEmail && !body.auditorUserId) {
      return reply.status(400).send({
        error: 'Bad Request',
        message: 'Either auditorEmail or auditorUserId must be specified',
      });
    }

    // Look up auditor user
    let auditorUser: { id: string; email: string } | null = null;
    if (body.auditorUserId) {
      const userRows = await request.db
        .select({ id: users.id, email: users.email })
        .from(users)
        .where(eq(users.id, body.auditorUserId));
      if (userRows.length > 0) auditorUser = userRows[0];
    } else if (body.auditorEmail) {
      const email = body.auditorEmail.trim().toLowerCase();
      const userRows = await request.db
        .select({ id: users.id, email: users.email })
        .from(users)
        .where(eq(users.email, email));
      if (userRows.length > 0) auditorUser = userRows[0];
    }

    if (!auditorUser) {
      return reply.status(404).send({
        error: 'Not Found',
        message: 'Auditor user not found. The user must register first.',
      });
    }

    // Ensure user has membership with role 'auditor'
    const memberRows = await request.db
      .select()
      .from(memberships)
      .where(and(eq(memberships.orgId, orgId), eq(memberships.userId, auditorUser.id)));

    if (memberRows.length === 0) {
      await request.db.insert(memberships).values({
        orgId,
        userId: auditorUser.id,
        role: 'auditor',
      });
    } else if (memberRows[0].role !== 'admin' && memberRows[0].role !== 'auditor') {
      await request.db
        .update(memberships)
        .set({ role: 'auditor' })
        .where(and(eq(memberships.orgId, orgId), eq(memberships.userId, auditorUser.id)));
    }

    const engagementId = 'eng_' + crypto.randomUUID().replace(/-/g, '');
    const cleanScope = body.scope ? JSON.stringify(body.scope) : '{}';
    const auditorAddress = body.auditorAddress?.trim() || null;

    await request.db.insert(engagements).values({
      id: engagementId,
      orgId,
      auditorId: auditorUser.id,
      auditorAddress,
      title: body.title.trim(),
      scope: cleanScope,
      status: 'active',
    });

    await request.db.insert(auditLogs).values({
      id: 'aud_' + crypto.randomUUID().replace(/-/g, ''),
      orgId,
      actorId: adminUserId,
      action: 'engagement.created',
      reason: `Invited auditor ${auditorUser.email} for engagement "${body.title.trim()}"`,
    });

    const createdRows = await request.db
      .select()
      .from(engagements)
      .where(eq(engagements.id, engagementId));

    const eng = createdRows[0];
    return reply.status(201).send({
      engagement: {
        ...eng,
        scope: JSON.parse(eng.scope),
      },
      auditor: {
        id: auditorUser.id,
        email: auditorUser.email,
        address: auditorAddress,
      },
    });
  };

  // Register engagement creation on org
  app.post(
    '/orgs/:id/engagements',
    { preHandler: [requireOrgRole(['admin'])] },
    createEngagementHandler
  );

  // 2. GET /orgs/:id/engagements: List engagements for org
  app.get(
    '/orgs/:id/engagements',
    { preHandler: [requireOrgRole(['admin', 'auditor'])] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const { id: orgId } = request.params as { id: string };
      const engList = await request.db
        .select({
          id: engagements.id,
          orgId: engagements.orgId,
          auditorId: engagements.auditorId,
          auditorEmail: users.email,
          auditorAddress: engagements.auditorAddress,
          title: engagements.title,
          scope: engagements.scope,
          status: engagements.status,
          createdAt: engagements.createdAt,
        })
        .from(engagements)
        .innerJoin(users, eq(engagements.auditorId, users.id))
        .where(eq(engagements.orgId, orgId))
        .orderBy(desc(engagements.createdAt));

      return {
        engagements: engList.map((e) => ({
          ...e,
          scope: JSON.parse(e.scope),
        })),
        count: engList.length,
      };
    }
  );

  // Helper to verify caller has access to an engagement
  async function getAuthorizedEngagement(request: FastifyRequest, engagementId: string) {
    const callerId = request.user.id;
    const engRows = await request.db
      .select()
      .from(engagements)
      .where(eq(engagements.id, engagementId));

    if (engRows.length === 0) {
      return { error: 'Not Found', status: 404, message: 'Engagement not found' };
    }

    const eng = engRows[0];

    // Caller must be assigned auditor or org admin
    if (eng.auditorId !== callerId) {
      const adminMember = await request.db
        .select()
        .from(memberships)
        .where(
          and(
            eq(memberships.orgId, eng.orgId),
            eq(memberships.userId, callerId),
            eq(memberships.role, 'admin')
          )
        );

      if (adminMember.length === 0) {
        return {
          error: 'Forbidden',
          status: 403,
          message: 'Caller is neither the assigned auditor nor an organization administrator',
        };
      }
    }

    return { engagement: eng };
  }

  // 3. GET /engagements/:eid: View engagement details
  app.get(
    '/engagements/:eid',
    { preHandler: [app.authenticate] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const { eid } = request.params as { eid: string };
      const check = await getAuthorizedEngagement(request, eid);
      if (check.error || !check.engagement) {
        return reply.status(check.status || 403).send({ error: check.error, message: check.message });
      }

      const eng = check.engagement;
      return {
        engagement: {
          ...eng,
          scope: JSON.parse(eng.scope),
        },
      };
    }
  );

  // 4. GET /engagements/:eid/records: Read-only authorized record viewer enforcing scope
  const listEngagementRecordsHandler = async (request: FastifyRequest, reply: FastifyReply) => {
    const { eid } = request.params as { eid: string };
    const check = await getAuthorizedEngagement(request, eid);
    if (check.error || !check.engagement) {
      return reply.status(check.status || 403).send({ error: check.error, message: check.message });
    }

    const eng = check.engagement;
    if (eng.status === 'revoked') {
      return reply.status(403).send({
        error: 'Forbidden',
        message: 'This engagement has been revoked',
      });
    }

    const scope: EngagementScope = JSON.parse(eng.scope);
    const query = request.query as { limit?: string; offset?: string; type?: string; status?: string };
    const limit = Math.min(parseInt(query.limit || '50', 10), 100);
    const offset = parseInt(query.offset || '0', 10);

    // Build filter conditions based on organization and engagement scope
    const conditions = [eq(records.orgId, eng.orgId)];

    // Scoped Record Types
    if (scope.recordTypes && scope.recordTypes.length > 0) {
      conditions.push(inArray(records.type, scope.recordTypes));
    }
    if (query.type) {
      conditions.push(eq(records.type, query.type));
    }

    // Scoped Status (default 'approved' if not specified in scope)
    if (scope.status) {
      if (Array.isArray(scope.status)) {
        conditions.push(inArray(records.status, scope.status));
      } else {
        conditions.push(eq(records.status, scope.status));
      }
    } else if (query.status) {
      conditions.push(eq(records.status, query.status));
    } else {
      conditions.push(eq(records.status, 'approved'));
    }

    // Scoped Dates
    if (scope.startDate) {
      conditions.push(gte(records.createdAt, scope.startDate));
    }
    if (scope.endDate) {
      conditions.push(lte(records.createdAt, scope.endDate));
    }

    // Fetch records matching scope
    const recordRows = await request.db
      .select({
        id: records.id,
        orgId: records.orgId,
        type: records.type,
        status: records.status,
        leafHash: records.leafHash,
        fieldRoot: records.fieldRoot,
        seqNo: records.seqNo,
        createdAt: records.createdAt,
        approvedAt: records.approvedAt,
        checkpointId: checkpoints.id,
        onchainId: checkpoints.onchainId,
        checkpointRoot: checkpoints.root,
        txHash: checkpoints.txHash,
        ledger: checkpoints.ledger,
      })
      .from(records)
      .leftJoin(checkpointRecords, eq(records.id, checkpointRecords.recordId))
      .leftJoin(checkpoints, eq(checkpointRecords.checkpointId, checkpoints.id))
      .where(and(...conditions))
      .orderBy(desc(records.seqNo))
      .limit(limit)
      .offset(offset);

    // Fetch signatures for records
    const recordIds = recordRows.map((r) => r.id);
    let allSignatures: Array<{ recordId: string; kind: string; signature: string; keyId: string }> = [];
    if (recordIds.length > 0) {
      allSignatures = await request.db
        .select({
          recordId: recordSignatures.recordId,
          kind: recordSignatures.kind,
          signature: recordSignatures.signature,
          keyId: recordSignatures.keyId,
        })
        .from(recordSignatures)
        .where(inArray(recordSignatures.recordId, recordIds));
    }

    const signaturesByRecord = new Map<string, typeof allSignatures>();
    for (const sig of allSignatures) {
      const arr = signaturesByRecord.get(sig.recordId) || [];
      arr.push(sig);
      signaturesByRecord.set(sig.recordId, arr);
    }

    const enrichedRecords = recordRows.map((rec) => ({
      id: rec.id,
      orgId: rec.orgId,
      type: rec.type,
      status: rec.status,
      leafHash: rec.leafHash,
      fieldRoot: rec.fieldRoot,
      seqNo: rec.seqNo,
      createdAt: rec.createdAt,
      approvedAt: rec.approvedAt,
      checkpoint: rec.checkpointId
        ? {
            id: rec.checkpointId,
            onchainId: rec.onchainId,
            root: rec.checkpointRoot,
            txHash: rec.txHash,
            ledger: rec.ledger,
          }
        : null,
      signatures: signaturesByRecord.get(rec.id) || [],
    }));

    return {
      engagement: {
        id: eng.id,
        title: eng.title,
        orgId: eng.orgId,
        auditorId: eng.auditorId,
        status: eng.status,
        scope,
      },
      records: enrichedRecords,
      count: enrichedRecords.length,
      limit,
      offset,
    };
  };

  app.get('/engagements/:eid/records', { preHandler: [app.authenticate] }, listEngagementRecordsHandler);

  // 5. POST /engagements/:eid/witness: Prepares and relays on-chain witness_checkpoint transaction
  const witnessHandler = async (request: FastifyRequest, reply: FastifyReply) => {
    const { eid } = request.params as { eid: string };
    const check = await getAuthorizedEngagement(request, eid);
    if (check.error || !check.engagement) {
      return reply.status(check.status || 403).send({ error: check.error, message: check.message });
    }

    const eng = check.engagement;
    if (eng.status !== 'active') {
      return reply.status(403).send({
        error: 'Forbidden',
        message: `Cannot witness checkpoint on "${eng.status}" engagement`,
      });
    }

    const body = request.body as {
      checkpointId?: number | string;
      rootSeen?: string;
      auditorAddress?: string;
      auditorSecret?: string;
      signedTx?: string;
      prepareOnly?: boolean;
    };

    if (body?.checkpointId === undefined || body?.checkpointId === null) {
      return reply.status(400).send({
        error: 'Bad Request',
        message: 'Missing required field: checkpointId',
      });
    }

    // 1. Look up checkpoint for this org
    let cpRow: typeof checkpoints.$inferSelect | null = null;
    if (typeof body.checkpointId === 'number') {
      const rows = await request.db
        .select()
        .from(checkpoints)
        .where(and(eq(checkpoints.orgId, eng.orgId), eq(checkpoints.onchainId, body.checkpointId)));
      if (rows.length > 0) cpRow = rows[0];
    } else {
      const rows = await request.db
        .select()
        .from(checkpoints)
        .where(
          and(
            eq(checkpoints.orgId, eng.orgId),
            eq(checkpoints.id, body.checkpointId)
          )
        );
      if (rows.length > 0) cpRow = rows[0];
    }

    if (!cpRow) {
      return reply.status(404).send({
        error: 'Not Found',
        message: `Checkpoint "${body.checkpointId}" not found for organization "${eng.orgId}"`,
      });
    }

    // 2. Validate root seen matches checkpoint root
    const cleanCheckpointRoot = cpRow.root.toLowerCase().replace(/^0x/, '');
    if (body.rootSeen) {
      const cleanRootSeen = body.rootSeen.toLowerCase().replace(/^0x/, '');
      if (cleanRootSeen !== cleanCheckpointRoot) {
        return reply.status(400).send({
          error: 'Bad Request',
          message: `RootMismatch: provided rootSeen "${cleanRootSeen}" does not match checkpoint root "${cleanCheckpointRoot}"`,
        });
      }
    }

    // 3. Determine auditor Stellar address and keypair
    let auditorAddress = body.auditorAddress || eng.auditorAddress;
    let auditorKeypair: StellarSdk.Keypair | undefined = undefined;

    if (body.auditorSecret) {
      try {
        auditorKeypair = StellarSdk.Keypair.fromSecret(body.auditorSecret);
        auditorAddress = auditorKeypair.publicKey();
      } catch (err: any) {
        return reply.status(400).send({
          error: 'Bad Request',
          message: `Invalid auditorSecret: ${err.message}`,
        });
      }
    }

    if (!auditorAddress) {
      return reply.status(400).send({
        error: 'Bad Request',
        message: 'Auditor Stellar address is required to witness checkpoint on-chain',
      });
    }

    // 4. Fetch org stellar address
    const orgRows = await request.db.select().from(orgs).where(eq(orgs.id, eng.orgId));
    const orgAddress = orgRows[0]?.stellarAddress || eng.orgId;

    // 5. Check if already witnessed in DB
    const existingWitness = await request.db
      .select()
      .from(checkpointWitnesses)
      .where(
        and(
          eq(checkpointWitnesses.checkpointId, cpRow.id),
          eq(checkpointWitnesses.auditorAddress, auditorAddress)
        )
      );

    if (existingWitness.length > 0) {
      return reply.status(409).send({
        error: 'Conflict',
        message: `Checkpoint #${cpRow.onchainId} has already been witnessed by auditor "${auditorAddress}"`,
      });
    }

    const onchainId = cpRow.onchainId || 1;

    // 6. Handle prepareOnly mode
    if (body.prepareOnly) {
      try {
        const prep = await sorobanClient.prepareWitnessTransaction({
          orgAddress,
          checkpointId: onchainId,
          auditorAddress,
          rootSeenHex: cleanCheckpointRoot,
        });

        return reply.status(200).send({
          prepareOnly: true,
          unsignedXdr: prep.unsignedXdr,
          checkpoint: {
            id: cpRow.id,
            onchainId,
            root: cleanCheckpointRoot,
          },
          auditorAddress,
        });
      } catch (err: any) {
        return reply.status(400).send({
          error: 'Bad Request',
          message: `Failed to prepare witness transaction: ${err.message}`,
        });
      }
    }

    // 7. Relay on-chain witness transaction
    let relayRes;
    try {
      relayRes = await sorobanClient.witnessCheckpoint({
        orgAddress,
        checkpointId: onchainId,
        auditorAddress,
        auditorKeypair,
        rootSeenHex: cleanCheckpointRoot,
        signedTxXdr: body.signedTx,
      });
    } catch (err: any) {
      if (err.message?.includes('AlreadyWitnessed')) {
        return reply.status(409).send({
          error: 'Conflict',
          message: err.message,
        });
      }
      return reply.status(400).send({
        error: 'Bad Request',
        message: `Soroban witness transaction failed: ${err.message}`,
      });
    }

    // 8. Persist witness record in database
    const witnessId = 'wit_' + crypto.randomUUID().replace(/-/g, '');
    const now = new Date();

    await request.db.insert(checkpointWitnesses).values({
      id: witnessId,
      checkpointId: cpRow.id,
      engagementId: eng.id,
      auditorAddress,
      txHash: relayRes.txHash,
      ledger: relayRes.ledger,
      witnessedAt: now,
    });

    // 9. Log audit trail
    await request.db.insert(auditLogs).values({
      id: 'aud_' + crypto.randomUUID().replace(/-/g, ''),
      orgId: eng.orgId,
      actorId: request.user.id,
      action: 'checkpoint.witnessed',
      reason: `Auditor ${auditorAddress} witnessed checkpoint #${onchainId} (tx: ${relayRes.txHash})`,
    });

    return reply.status(201).send({
      success: true,
      witness: {
        id: witnessId,
        checkpointId: onchainId,
        dbCheckpointId: cpRow.id,
        orgId: eng.orgId,
        auditorAddress,
        rootSeen: cleanCheckpointRoot,
        txHash: relayRes.txHash,
        ledger: relayRes.ledger,
        witnessedAt: now.toISOString(),
      },
    });
  };

  app.post('/engagements/:eid/witness', { preHandler: [app.authenticate] }, witnessHandler);
}

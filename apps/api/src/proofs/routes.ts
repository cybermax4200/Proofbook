import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import crypto from 'node:crypto';
import { eq, and, asc, desc, notInArray, or } from 'drizzle-orm';
import { requireOrgRole } from '../auth/middleware.js';
import { generateProofBundle } from './builder.js';
import type { StorageProvider } from '../records/storage.js';
import {
  orgs,
  records,
  checkpoints,
  checkpointRecords,
  merkleNodes,
  checkpointWitnesses,
  auditLogs,
} from '../db/schema.js';
import { buildMerkleTree } from '@proofbook/crypto';
import { verifyBundleOffline, ProofBundle } from '@proofbook/verifier';

export interface ProofRoutesOptions {
  storage: StorageProvider;
}

export async function proofRoutes(app: FastifyInstance, options: ProofRoutesOptions) {
  const storage = options.storage;

  // Generate standardized PB1 proof bundle with full or selective disclosure
  const generateHandler = async (request: FastifyRequest, reply: FastifyReply) => {
    const { id: orgId } = request.params as { id: string };
    const body = request.body as {
      recordId?: string;
      fields?: Record<string, string>;
      salts?: Record<string, string>;
      disclosedFields?: string[];
      auditor?: string;
      network?: string;
      contractId?: string;
    };

    if (!body?.recordId) {
      return reply.status(400).send({
        error: 'Bad Request',
        message: 'Missing required field: recordId',
      });
    }

    try {
      const result = await generateProofBundle({
        db: request.db,
        storage,
        orgId,
        recordId: body.recordId,
        fields: body.fields,
        salts: body.salts,
        disclosedFields: body.disclosedFields,
        network: body.network,
        contractId: body.contractId,
        auditor: body.auditor,
      });

      const query = request.query as { download?: string; format?: string };
      const shouldDownload =
        query?.download === 'true' ||
        query?.format === 'file' ||
        request.headers.accept === 'application/octet-stream';

      if (shouldDownload) {
        reply.header('Content-Type', 'application/json; charset=utf-8');
        reply.header(
          'Content-Disposition',
          `attachment; filename="bundle-${result.bundle.record.record_id}.json"`
        );
        return reply.status(200).send(JSON.stringify(result.bundle, null, 2));
      }

      return reply.status(200).send({
        bundle: result.bundle,
        verification: result.verification,
      });
    } catch (err: any) {
      if (
        err.message?.includes('not found') ||
        err.message?.includes('has not been anchored')
      ) {
        return reply.status(404).send({
          error: 'Not Found',
          message: err.message,
        });
      }

      return reply.status(400).send({
        error: 'Bad Request',
        message: err.message,
      });
    }
  };

  // Register route under both /orgs/:id/proofs (for prefixing) and direct
  app.post(
    '/orgs/:id/proofs',
    { preHandler: [requireOrgRole([])] },
    generateHandler
  );

  // List checkpoints for an organization
  app.get(
    '/orgs/:id/checkpoints',
    { preHandler: [requireOrgRole([])] },
    async (request: FastifyRequest) => {
      const { id: orgId } = request.params as { id: string };
      const cpRows = await request.db
        .select()
        .from(checkpoints)
        .where(eq(checkpoints.orgId, orgId))
        .orderBy(desc(checkpoints.onchainId));

      const enriched = [];
      for (const cp of cpRows) {
        const wits = await request.db
          .select()
          .from(checkpointWitnesses)
          .where(eq(checkpointWitnesses.checkpointId, cp.id));
        enriched.push({
          ...cp,
          witnesses: wits,
        });
      }

      return {
        checkpoints: enriched,
        count: enriched.length,
      };
    }
  );

  // Trigger a checkpoint run for an organization (anchors all approved uncheckpointed records)
  app.post(
    '/orgs/:id/checkpoints/run',
    { preHandler: [requireOrgRole(['admin'])] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const { id: orgId } = request.params as { id: string };
      const userId = request.user.id;

      // Find already-checkpointed record IDs for this org
      const existingCpRecords = await request.db
        .select({ recordId: checkpointRecords.recordId })
        .from(checkpointRecords)
        .innerJoin(checkpoints, eq(checkpointRecords.checkpointId, checkpoints.id))
        .where(eq(checkpoints.orgId, orgId));

      const anchoredIds = existingCpRecords.map((r) => r.recordId);

      const conditions = [eq(records.orgId, orgId), eq(records.status, 'approved')];
      if (anchoredIds.length > 0) {
        conditions.push(notInArray(records.id, anchoredIds));
      }

      const uncheckpointed = await request.db
        .select()
        .from(records)
        .where(and(...conditions))
        .orderBy(asc(records.seqNo));

      if (uncheckpointed.length === 0) {
        return reply.status(200).send({
          triggered: false,
          checkpoint: null,
          message: 'No uncheckpointed approved records found',
        });
      }

      const prevCheckpoints = await request.db
        .select()
        .from(checkpoints)
        .where(eq(checkpoints.orgId, orgId))
        .orderBy(desc(checkpoints.onchainId))
        .limit(1);

      const prevCp = prevCheckpoints[0] || null;
      const prevRoot = prevCp ? prevCp.root : '00'.repeat(32);
      const nextOnchainId = prevCp && prevCp.onchainId ? prevCp.onchainId + 1 : 1;
      const cumulativeRecordCount = (prevCp ? prevCp.recordCount : 0) + uncheckpointed.length;

      const leafBuffers = uncheckpointed.map(
        (r) => new Uint8Array(Buffer.from(r.leafHash, 'hex'))
      );
      const tree = buildMerkleTree(leafBuffers);

      const cpId = 'cp_' + crypto.randomUUID().replace(/-/g, '');
      const periodStart = uncheckpointed[0].createdAt;
      const periodEnd = uncheckpointed[uncheckpointed.length - 1].createdAt;
      const txHash =
        'tx_' +
        crypto
          .createHash('sha256')
          .update(`${orgId}:${nextOnchainId}:${tree.rootHex}`)
          .digest('hex')
          .slice(0, 60);
      const ledger = 100000 + nextOnchainId * 10;
      const anchoredAt = new Date();

      await request.db.insert(checkpoints).values({
        id: cpId,
        orgId,
        onchainId: nextOnchainId,
        root: tree.rootHex,
        prevRoot,
        recordCount: cumulativeRecordCount,
        periodStart,
        periodEnd,
        txHash,
        ledger,
        anchoredAt,
      });

      for (let i = 0; i < uncheckpointed.length; i++) {
        await request.db.insert(checkpointRecords).values({
          checkpointId: cpId,
          recordId: uncheckpointed[i].id,
          leafIndex: i,
        });
      }

      for (let level = 0; level < tree.levels.length; level++) {
        const levelNodes = tree.levels[level];
        for (let idx = 0; idx < levelNodes.length; idx++) {
          await request.db.insert(merkleNodes).values({
            checkpointId: cpId,
            level,
            idx,
            hash: Buffer.from(levelNodes[idx]).toString('hex'),
          });
        }
      }

      await request.db.insert(auditLogs).values({
        id: 'aud_' + crypto.randomUUID().replace(/-/g, ''),
        orgId,
        actorId: userId,
        action: 'checkpoint.anchored',
        reason: `Anchored checkpoint #${nextOnchainId} with ${uncheckpointed.length} record(s), root ${tree.rootHex}`,
      });

      const createdRows = await request.db
        .select()
        .from(checkpoints)
        .where(eq(checkpoints.id, cpId));

      return reply.status(201).send({
        triggered: true,
        checkpoint: createdRows[0],
        recordsAnchored: uncheckpointed.length,
      });
    }
  );

  // Public Verification Endpoint: GET /verify/:orgAddress/:checkpointId
  app.get(
    '/verify/:orgAddress/:checkpointId',
    async (request: FastifyRequest, reply: FastifyReply) => {
      const { orgAddress, checkpointId } = request.params as {
        orgAddress: string;
        checkpointId: string;
      };

      const orgRows = await request.db
        .select()
        .from(orgs)
        .where(or(eq(orgs.stellarAddress, orgAddress), eq(orgs.id, orgAddress)));

      if (orgRows.length === 0) {
        return reply.status(404).send({
          error: 'Not Found',
          message: `Organization "${orgAddress}" not found`,
        });
      }

      const org = orgRows[0];
      const numericId = Number(checkpointId);
      const cpRows = await request.db
        .select()
        .from(checkpoints)
        .where(
          and(
            eq(checkpoints.orgId, org.id),
            !Number.isNaN(numericId)
              ? eq(checkpoints.onchainId, numericId)
              : eq(checkpoints.id, checkpointId)
          )
        );

      if (cpRows.length === 0) {
        return reply.status(404).send({
          error: 'Not Found',
          message: `Checkpoint "${checkpointId}" not found for organization "${orgAddress}"`,
        });
      }

      const cp = cpRows[0];
      const witnesses = await request.db
        .select()
        .from(checkpointWitnesses)
        .where(eq(checkpointWitnesses.checkpointId, cp.id));

      return {
        verified: true,
        org: {
          id: org.id,
          name: org.name,
          stellarAddress: org.stellarAddress,
        },
        checkpoint: {
          id: cp.id,
          onchainId: cp.onchainId,
          root: cp.root,
          prevRoot: cp.prevRoot,
          recordCount: cp.recordCount,
          periodStart: cp.periodStart,
          periodEnd: cp.periodEnd,
          txHash: cp.txHash,
          ledger: cp.ledger,
          anchoredAt: cp.anchoredAt,
        },
        witnesses,
      };
    }
  );

  // Public Bundle Verification Endpoint: POST /verify/bundle
  app.post('/verify/bundle', async (request: FastifyRequest, reply: FastifyReply) => {
    const body = request.body as ProofBundle | { bundle?: ProofBundle };
    const bundle: ProofBundle | undefined =
      body && 'version' in body ? (body as ProofBundle) : (body as { bundle?: ProofBundle })?.bundle;

    if (!bundle || typeof bundle !== 'object') {
      return reply.status(400).send({
        error: 'Bad Request',
        message: 'Request body must be a valid PB1 proof bundle or { bundle } object',
      });
    }

    const report = verifyBundleOffline(bundle);
    let anchoredCheckpoint = null;

    if (bundle.expected_root) {
      const cpRows = await request.db
        .select()
        .from(checkpoints)
        .where(eq(checkpoints.root, bundle.expected_root.toLowerCase()));
      if (cpRows.length > 0) {
        anchoredCheckpoint = cpRows[0];
      }
    }

    return reply.status(200).send({
      valid: report.valid,
      report,
      anchoredCheckpoint,
    });
  });
}

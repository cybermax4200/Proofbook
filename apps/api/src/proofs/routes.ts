import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { requireOrgRole } from '../auth/middleware.js';
import { generateProofBundle } from './builder.js';
import type { StorageProvider } from '../records/storage.js';

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
}

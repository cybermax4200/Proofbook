import { test, describe, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createDatabase, DatabaseHandle } from '../src/db/index.js';
import { buildFastifyApp } from '../src/app.js';
import { FastifyInstance } from 'fastify';

describe('Fastify App Initialization', () => {
  let dbHandle: DatabaseHandle;
  let app: FastifyInstance;

  afterEach(async () => {
    if (app) await app.close();
    if (dbHandle) await dbHandle.close();
  });

  test('GET /health returns 200 with ok status', async () => {
    dbHandle = await createDatabase();
    app = await buildFastifyApp({ dbHandle });

    const res = await app.inject({
      method: 'GET',
      url: '/health',
    });

    assert.equal(res.statusCode, 200);
    const json = JSON.parse(res.body);
    assert.equal(json.status, 'ok');
    assert.equal(json.version, '0.1.0');
    assert.equal(json.isPgLite, true);
  });
});

import { test, describe, afterEach, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createDatabase, DatabaseHandle } from '../src/db/index.js';
import { buildFastifyApp } from '../src/app.js';
import { FastifyInstance } from 'fastify';

describe('Organization & Membership Routes', () => {
  let dbHandle: DatabaseHandle;
  let app: FastifyInstance;

  beforeEach(async () => {
    dbHandle = await createDatabase();
    app = await buildFastifyApp({ dbHandle });
  });

  afterEach(async () => {
    if (app) await app.close();
    if (dbHandle) await dbHandle.close();
  });

  test('creates org, lists orgs, and adds member with role', async () => {
    // 1. Register admin user
    const adminReg = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: { email: 'admin@acme.org', password: 'password123' },
    });
    const { token: adminToken } = JSON.parse(adminReg.body);

    // 2. Register second user
    const makerReg = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: { email: 'maker@acme.org', password: 'password123' },
    });
    const { token: makerToken, user: makerUser } = JSON.parse(makerReg.body);

    // 3. Admin creates org
    const createOrgRes = await app.inject({
      method: 'POST',
      url: '/api/v1/orgs',
      headers: { authorization: `Bearer ${adminToken}` },
      payload: {
        name: 'Acme Non-Profit',
        stellarAddress: 'GBHTYTJU7S52LOM3M6R63B346Y5A5R5Y63RGL7Y5R7E4P6Y3J3Y6EXAMPLE',
      },
    });
    assert.equal(createOrgRes.statusCode, 201);
    const orgId = JSON.parse(createOrgRes.body).org.id;

    // 4. Admin lists orgs
    const listOrgRes = await app.inject({
      method: 'GET',
      url: '/api/v1/orgs',
      headers: { authorization: `Bearer ${adminToken}` },
    });
    assert.equal(listOrgRes.statusCode, 200);
    const orgs = JSON.parse(listOrgRes.body).orgs;
    assert.equal(orgs.length, 1);
    assert.equal(orgs[0].id, orgId);
    assert.equal(orgs[0].role, 'admin');

    // 5. Maker cannot access org before being added
    const deniedRes = await app.inject({
      method: 'GET',
      url: `/api/v1/orgs/${orgId}`,
      headers: { authorization: `Bearer ${makerToken}` },
    });
    assert.equal(deniedRes.statusCode, 403);

    // 6. Admin adds maker to org
    const addMemberRes = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/members`,
      headers: { authorization: `Bearer ${adminToken}` },
      payload: {
        email: 'maker@acme.org',
        role: 'maker',
      },
    });
    assert.equal(addMemberRes.statusCode, 200);
    assert.equal(JSON.parse(addMemberRes.body).member.role, 'maker');

    // 7. Maker can now access org
    const makerAccessRes = await app.inject({
      method: 'GET',
      url: `/api/v1/orgs/${orgId}`,
      headers: { authorization: `Bearer ${makerToken}` },
    });
    assert.equal(makerAccessRes.statusCode, 200);
    const accessBody = JSON.parse(makerAccessRes.body);
    assert.equal(accessBody.myRole, 'maker');
    assert.equal(accessBody.members.length, 2);

    // 8. Maker cannot add other members (requires admin)
    const unauthorizedAdd = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${orgId}/members`,
      headers: { authorization: `Bearer ${makerToken}` },
      payload: {
        email: 'admin@acme.org',
        role: 'admin',
      },
    });
    assert.equal(unauthorizedAdd.statusCode, 403);
  });
});

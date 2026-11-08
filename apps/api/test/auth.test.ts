import { test, describe, afterEach, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createDatabase, DatabaseHandle } from '../src/db/index.js';
import { buildFastifyApp } from '../src/app.js';
import { FastifyInstance } from 'fastify';
import { generateEd25519Keypair } from '@proofbook/crypto';

describe('Authentication & Key Management Routes', () => {
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

  test('registers a user successfully and issues JWT token', async () => {
    const keypair = generateEd25519Keypair();
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: {
        email: 'alice@example.com',
        password: 'password123',
        publicKey: keypair.publicKeyHex,
      },
    });

    assert.equal(res.statusCode, 201);
    const body = JSON.parse(res.body);
    assert.ok(body.token);
    assert.equal(body.user.email, 'alice@example.com');
    assert.ok(body.user.id.startsWith('usr_'));
    assert.equal(body.key.publicKey, keypair.publicKeyHex);
  });

  test('rejects registration with short password or duplicate email', async () => {
    // Short password
    const shortRes = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: {
        email: 'bob@example.com',
        password: '123',
      },
    });
    assert.equal(shortRes.statusCode, 400);

    // Initial registration
    await app.inject({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: {
        email: 'bob@example.com',
        password: 'password123',
      },
    });

    // Duplicate email
    const dupRes = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: {
        email: 'bob@example.com',
        password: 'password123',
      },
    });
    assert.equal(dupRes.statusCode, 409);
  });

  test('logs in registered user with correct credentials', async () => {
    await app.inject({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: {
        email: 'charlie@example.com',
        password: 'strongpassword2026',
      },
    });

    // Valid login
    const loginRes = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      payload: {
        email: 'charlie@example.com',
        password: 'strongpassword2026',
      },
    });
    assert.equal(loginRes.statusCode, 200);
    const loginBody = JSON.parse(loginRes.body);
    assert.ok(loginBody.token);
    assert.equal(loginBody.user.email, 'charlie@example.com');

    // Invalid password
    const badPwRes = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      payload: {
        email: 'charlie@example.com',
        password: 'wrongpassword',
      },
    });
    assert.equal(badPwRes.statusCode, 401);

    // Non-existent user
    const unknownRes = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      payload: {
        email: 'unknown@example.com',
        password: 'anypassword',
      },
    });
    assert.equal(unknownRes.statusCode, 401);
  });

  test('fetches current user and manages Ed25519 signing keys', async () => {
    const regRes = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: {
        email: 'dave@example.com',
        password: 'password123',
      },
    });
    const { token } = JSON.parse(regRes.body);

    // /me without token
    const unauthMe = await app.inject({
      method: 'GET',
      url: '/api/v1/auth/me',
    });
    assert.equal(unauthMe.statusCode, 401);

    // /me with token
    const meRes = await app.inject({
      method: 'GET',
      url: '/api/v1/auth/me',
      headers: { authorization: `Bearer ${token}` },
    });
    assert.equal(meRes.statusCode, 200);
    const meBody = JSON.parse(meRes.body);
    assert.equal(meBody.user.email, 'dave@example.com');
    assert.equal(meBody.keys.length, 0);

    // Add key
    const keypair = generateEd25519Keypair();
    const addKeyRes = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/keys',
      headers: { authorization: `Bearer ${token}` },
      payload: {
        publicKey: keypair.publicKeyHex,
      },
    });
    assert.equal(addKeyRes.statusCode, 201);
    const keyId = JSON.parse(addKeyRes.body).key.id;

    // Revoke key
    const revokeRes = await app.inject({
      method: 'DELETE',
      url: `/api/v1/auth/keys/${keyId}`,
      headers: { authorization: `Bearer ${token}` },
    });
    assert.equal(revokeRes.statusCode, 200);
    assert.equal(JSON.parse(revokeRes.body).success, true);

    // Revoke already revoked key
    const secondRevoke = await app.inject({
      method: 'DELETE',
      url: `/api/v1/auth/keys/${keyId}`,
      headers: { authorization: `Bearer ${token}` },
    });
    assert.equal(secondRevoke.statusCode, 400);
  });
});

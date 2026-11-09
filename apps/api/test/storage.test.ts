import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  MemoryStorageProvider,
  FileStorageProvider,
  EncryptedFileStorageProvider,
  S3StorageProvider,
  createStorageProvider,
} from '../src/records/storage.js';

describe('Storage Providers (Memory, Local Encrypted FS, and S3/MinIO)', () => {
  test('MemoryStorageProvider puts, gets, and deletes payloads', async () => {
    const provider = new MemoryStorageProvider();
    const ref = await provider.put('evidence/org1/rec1/ev1.bin', 'encrypted-blob-1');
    assert.equal(ref, 'memory://evidence/org1/rec1/ev1.bin');

    const loaded = await provider.get(ref);
    assert.equal(loaded, 'encrypted-blob-1');

    await provider.delete(ref);
    const afterDelete = await provider.get(ref);
    assert.equal(afterDelete, null);
  });

  test('EncryptedFileStorageProvider encrypts blobs at rest with AES-256-GCM and detects tampering', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'proofbook-encfs-'));
    try {
      const provider = new EncryptedFileStorageProvider(tmpDir, 'super-secret-dev-key-2026');
      const sensitivePayload = 'confidential-invoice-attachment-payload-1250-usd';

      const ref = await provider.put('evidence/org_1/rec_1/inv.bin', sensitivePayload);
      assert.equal(ref, 'encrypted-fs://evidence/org_1/rec_1/inv.bin');

      // Verify raw file on disk is encrypted and does not contain plaintext
      const rawDiskPath = provider.resolvePath(ref);
      const rawOnDisk = await fs.readFile(rawDiskPath, 'utf8');
      assert.ok(rawOnDisk.startsWith('pb1enc:v1:'));
      assert.equal(rawOnDisk.includes(sensitivePayload), false);

      // Verify transparent decryption via get()
      const decrypted = await provider.get(ref);
      assert.equal(decrypted, sensitivePayload);

      // Verify wrong key cannot decrypt
      const wrongKeyProvider = new EncryptedFileStorageProvider(tmpDir, 'wrong-key');
      const wrongResult = await wrongKeyProvider.get(ref);
      assert.equal(wrongResult, null);

      // Verify deletion
      await provider.delete(ref);
      assert.equal(await provider.get(ref), null);
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  test('S3StorageProvider signs requests with AWS Signature V4 and stores/retrieves objects', async () => {
    const mockBucketStore = new Map<string, string>();
    const capturedRequests: Array<{ method: string; url: string; headers: Record<string, string> }> = [];

    const mockFetch: typeof fetch = async (input, init) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method || 'GET';
      const headers = (init?.headers || {}) as Record<string, string>;
      capturedRequests.push({ method, url, headers });

      const parsedUrl = new URL(url);
      const objectKey = parsedUrl.pathname;

      if (method === 'PUT') {
        const bodyBuf = Buffer.from(init?.body as Uint8Array);
        mockBucketStore.set(objectKey, bodyBuf.toString('utf8'));
        return new Response('', { status: 200 });
      }
      if (method === 'GET') {
        const val = mockBucketStore.get(objectKey);
        if (val === undefined) {
          return new Response('Not Found', { status: 404 });
        }
        return new Response(val, { status: 200 });
      }
      if (method === 'DELETE') {
        mockBucketStore.delete(objectKey);
        return new Response(null, { status: 204 });
      }
      return new Response('Method Not Allowed', { status: 405 });
    };

    const s3 = new S3StorageProvider({
      endpoint: 'http://localhost:9000',
      bucket: 'proofbook-evidence',
      region: 'us-east-1',
      accessKeyId: 'minioadmin',
      secretAccessKey: 'minioadminsecret',
      forcePathStyle: true,
      fetchImpl: mockFetch,
    });

    const ref = await s3.put('evidence/org_1/rec_1/ev_1.bin', 's3-encrypted-evidence-data');
    assert.equal(ref, 's3://proofbook-evidence/evidence/org_1/rec_1/ev_1.bin');
    assert.equal(capturedRequests.length, 1);
    assert.equal(capturedRequests[0].method, 'PUT');
    assert.match(capturedRequests[0].headers.authorization, /^AWS4-HMAC-SHA256 Credential=minioadmin\//);

    const retrieved = await s3.get(ref);
    assert.equal(retrieved, 's3-encrypted-evidence-data');

    await s3.delete(ref);
    const missing = await s3.get(ref);
    assert.equal(missing, null);
  });

  test('createStorageProvider instantiates configured provider type', async () => {
    const mem = createStorageProvider();
    assert.ok(mem instanceof MemoryStorageProvider);

    const fsProv = createStorageProvider('/tmp/pb-test-fs');
    assert.ok(fsProv instanceof FileStorageProvider);

    const encFs = createStorageProvider({
      storageProvider: 'encrypted-fs',
      storageDir: '/tmp/pb-test-enc',
      storageEncryptionKey: 'key123',
    });
    assert.ok(encFs instanceof EncryptedFileStorageProvider);

    const s3 = createStorageProvider({
      storageProvider: 's3',
      s3: {
        endpoint: 'http://localhost:9000',
        bucket: 'bucket',
        accessKeyId: 'ak',
        secretAccessKey: 'sk',
      },
    });
    assert.ok(s3 instanceof S3StorageProvider);
  });
});

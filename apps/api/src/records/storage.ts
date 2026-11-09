import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

export interface StorageProvider {
  put(key: string, data: string | Buffer): Promise<string>;
  get(key: string): Promise<string | null>;
  delete(key: string): Promise<void>;
}

function normalizeStorageKey(key: string): string {
  return key
    .replace(/^(memory|file|storage|encrypted-fs):\/\//, '')
    .replace(/^s3:\/\/[^/]+\//, '');
}

export class MemoryStorageProvider implements StorageProvider {
  private store = new Map<string, string>();

  async put(key: string, data: string | Buffer): Promise<string> {
    const normalizedKey = normalizeStorageKey(key);
    const val = typeof data === 'string' ? data : data.toString('utf8');
    this.store.set(normalizedKey, val);
    return `memory://${normalizedKey}`;
  }

  async get(key: string): Promise<string | null> {
    const normalizedKey = normalizeStorageKey(key);
    return this.store.get(normalizedKey) ?? null;
  }

  async delete(key: string): Promise<void> {
    const normalizedKey = normalizeStorageKey(key);
    this.store.delete(normalizedKey);
  }
}

export class FileStorageProvider implements StorageProvider {
  private baseDir: string;

  constructor(baseDir: string) {
    this.baseDir = path.resolve(baseDir);
  }

  private resolvePath(key: string): string {
    const normalizedKey = normalizeStorageKey(key);
    return path.join(this.baseDir, normalizedKey);
  }

  async put(key: string, data: string | Buffer): Promise<string> {
    const normalizedKey = normalizeStorageKey(key);
    const filePath = this.resolvePath(normalizedKey);
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    await fs.writeFile(filePath, data);
    return `storage://${normalizedKey}`;
  }

  async get(key: string): Promise<string | null> {
    const filePath = this.resolvePath(key);
    try {
      const buf = await fs.readFile(filePath);
      return buf.toString('utf8');
    } catch {
      return null;
    }
  }

  async delete(key: string): Promise<void> {
    const filePath = this.resolvePath(key);
    try {
      await fs.unlink(filePath);
    } catch {
      // ignore if already deleted
    }
  }
}

/**
 * Local Encrypted File System provider for local development.
 * Encrypts all blobs at rest using AES-256-GCM with a unique 96-bit IV per write.
 */
export class EncryptedFileStorageProvider implements StorageProvider {
  private baseDir: string;
  private masterKey: Buffer;

  constructor(baseDir: string, encryptionSecret: string | Buffer = 'proofbook-local-dev-storage-key') {
    this.baseDir = path.resolve(baseDir);
    if (Buffer.isBuffer(encryptionSecret) && encryptionSecret.length === 32) {
      this.masterKey = Buffer.from(encryptionSecret);
    } else {
      this.masterKey = crypto.createHash('sha256').update(encryptionSecret).digest();
    }
  }

  resolvePath(key: string): string {
    const normalizedKey = normalizeStorageKey(key);
    return path.join(this.baseDir, normalizedKey);
  }

  async put(key: string, data: string | Buffer): Promise<string> {
    const normalizedKey = normalizeStorageKey(key);
    const filePath = this.resolvePath(normalizedKey);
    await fs.mkdir(path.dirname(filePath), { recursive: true });

    const plaintext = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.masterKey, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();

    const envelope = `pb1enc:v1:${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('base64')}`;
    await fs.writeFile(filePath, envelope, 'utf8');
    return `encrypted-fs://${normalizedKey}`;
  }

  async get(key: string): Promise<string | null> {
    const filePath = this.resolvePath(key);
    try {
      const raw = await fs.readFile(filePath, 'utf8');
      const parts = raw.split(':');
      if (parts.length !== 5 || parts[0] !== 'pb1enc' || parts[1] !== 'v1') {
        return null;
      }
      const iv = Buffer.from(parts[2], 'hex');
      const authTag = Buffer.from(parts[3], 'hex');
      const ciphertext = Buffer.from(parts[4], 'base64');

      const decipher = crypto.createDecipheriv('aes-256-gcm', this.masterKey, iv);
      decipher.setAuthTag(authTag);
      const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      return decrypted.toString('utf8');
    } catch {
      return null;
    }
  }

  async delete(key: string): Promise<void> {
    const filePath = this.resolvePath(key);
    try {
      await fs.unlink(filePath);
    } catch {
      // ignore if already deleted
    }
  }
}

export interface S3StorageOptions {
  endpoint: string;
  bucket: string;
  region?: string;
  accessKeyId: string;
  secretAccessKey: string;
  forcePathStyle?: boolean;
  fetchImpl?: typeof fetch;
}

function hmacSha256(key: Buffer | string, data: string): Buffer {
  return crypto.createHmac('sha256', key).update(data, 'utf8').digest();
}

function sha256Hex(data: string | Buffer): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * S3 / MinIO compatible object storage provider using AWS Signature Version 4.
 */
export class S3StorageProvider implements StorageProvider {
  private endpoint: URL;
  private bucket: string;
  private region: string;
  private accessKeyId: string;
  private secretAccessKey: string;
  private forcePathStyle: boolean;
  private fetchImpl: typeof fetch;

  constructor(options: S3StorageOptions) {
    this.endpoint = new URL(options.endpoint);
    this.bucket = options.bucket;
    this.region = options.region || 'us-east-1';
    this.accessKeyId = options.accessKeyId;
    this.secretAccessKey = options.secretAccessKey;
    this.forcePathStyle = options.forcePathStyle ?? true;
    this.fetchImpl = options.fetchImpl || globalThis.fetch.bind(globalThis);
  }

  private buildObjectUrl(key: string): URL {
    const normalizedKey = normalizeStorageKey(key);
    const encodedKey = normalizedKey
      .split('/')
      .map((segment) => encodeURIComponent(segment))
      .join('/');

    if (this.forcePathStyle) {
      const basePath = this.endpoint.pathname.replace(/\/$/, '');
      return new URL(`${basePath}/${encodeURIComponent(this.bucket)}/${encodedKey}`, this.endpoint.origin);
    }
    const url = new URL(this.endpoint.toString());
    url.hostname = `${this.bucket}.${url.hostname}`;
    url.pathname = `/${encodedKey}`;
    return url;
  }

  private signRequest(method: string, url: URL, body: Buffer = Buffer.alloc(0)): Record<string, string> {
    const now = new Date();
    const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
    const dateStamp = amzDate.slice(0, 8);
    const payloadHash = sha256Hex(body);
    const host = url.host;

    const canonicalHeaders =
      `host:${host}\n` +
      `x-amz-content-sha256:${payloadHash}\n` +
      `x-amz-date:${amzDate}\n`;
    const signedHeaders = 'host;x-amz-content-sha256;x-amz-date';

    const canonicalRequest = [
      method,
      url.pathname,
      '',
      canonicalHeaders,
      signedHeaders,
      payloadHash,
    ].join('\n');

    const credentialScope = `${dateStamp}/${this.region}/s3/aws4_request`;
    const stringToSign = [
      'AWS4-HMAC-SHA256',
      amzDate,
      credentialScope,
      sha256Hex(canonicalRequest),
    ].join('\n');

    const kDate = hmacSha256(`AWS4${this.secretAccessKey}`, dateStamp);
    const kRegion = hmacSha256(kDate, this.region);
    const kService = hmacSha256(kRegion, 's3');
    const kSigning = hmacSha256(kService, 'aws4_request');
    const signature = hmacSha256(kSigning, stringToSign).toString('hex');

    const authorization =
      `AWS4-HMAC-SHA256 Credential=${this.accessKeyId}/${credentialScope}, ` +
      `SignedHeaders=${signedHeaders}, Signature=${signature}`;

    return {
      host,
      'x-amz-date': amzDate,
      'x-amz-content-sha256': payloadHash,
      authorization,
    };
  }

  async put(key: string, data: string | Buffer): Promise<string> {
    const normalizedKey = normalizeStorageKey(key);
    const url = this.buildObjectUrl(normalizedKey);
    const body = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
    const headers = this.signRequest('PUT', url, body);

    const res = await this.fetchImpl(url.toString(), {
      method: 'PUT',
      headers: {
        ...headers,
        'content-type': 'application/octet-stream',
        'content-length': String(body.length),
      },
      body: new Uint8Array(body),
    });

    if (!res.ok) {
      throw new Error(`S3 PUT failed with status ${res.status}`);
    }

    return `s3://${this.bucket}/${normalizedKey}`;
  }

  async get(key: string): Promise<string | null> {
    const normalizedKey = normalizeStorageKey(key);
    const url = this.buildObjectUrl(normalizedKey);
    const headers = this.signRequest('GET', url);

    const res = await this.fetchImpl(url.toString(), {
      method: 'GET',
      headers,
    });

    if (res.status === 404) {
      return null;
    }
    if (!res.ok) {
      throw new Error(`S3 GET failed with status ${res.status}`);
    }

    return await res.text();
  }

  async delete(key: string): Promise<void> {
    const normalizedKey = normalizeStorageKey(key);
    const url = this.buildObjectUrl(normalizedKey);
    const headers = this.signRequest('DELETE', url);

    const res = await this.fetchImpl(url.toString(), {
      method: 'DELETE',
      headers,
    });

    if (!res.ok && res.status !== 404 && res.status !== 204) {
      throw new Error(`S3 DELETE failed with status ${res.status}`);
    }
  }
}

export interface StorageFactoryConfig {
  storageProvider?: 'memory' | 'fs' | 'encrypted-fs' | 's3';
  storageDir?: string;
  storageEncryptionKey?: string;
  s3?: S3StorageOptions;
}

export function createStorageProvider(config?: string | StorageFactoryConfig): StorageProvider {
  if (typeof config === 'string') {
    return new FileStorageProvider(config);
  }
  if (!config) {
    return new MemoryStorageProvider();
  }
  if (config.storageProvider === 's3' || config.s3) {
    if (!config.s3) {
      throw new Error('S3 storage configuration is required when storageProvider is "s3"');
    }
    return new S3StorageProvider(config.s3);
  }
  if (config.storageProvider === 'encrypted-fs' || (config.storageDir && config.storageEncryptionKey)) {
    const dir = config.storageDir || '.proofbook-storage';
    return new EncryptedFileStorageProvider(dir, config.storageEncryptionKey);
  }
  if (config.storageDir) {
    return new FileStorageProvider(config.storageDir);
  }
  return new MemoryStorageProvider();
}

import { S3StorageOptions } from './records/storage.js';

try {
  process.loadEnvFile?.();
} catch {
  // .env file is optional
}

export interface AppConfig {
  port: number;
  host: string;
  databaseUrl?: string;
  jwtSecret: string;
  storageProvider?: 'memory' | 'fs' | 'encrypted-fs' | 's3';
  storageDir?: string;
  storageEncryptionKey?: string;
  s3?: S3StorageOptions;
}

export function loadConfig(): AppConfig {
  const s3Endpoint = process.env.S3_ENDPOINT;
  const s3Bucket = process.env.S3_BUCKET;
  const s3AccessKeyId = process.env.S3_ACCESS_KEY_ID;
  const s3SecretAccessKey = process.env.S3_SECRET_ACCESS_KEY;

  const s3: S3StorageOptions | undefined =
    s3Endpoint && s3Bucket && s3AccessKeyId && s3SecretAccessKey
      ? {
          endpoint: s3Endpoint,
          bucket: s3Bucket,
          region: process.env.S3_REGION || 'us-east-1',
          accessKeyId: s3AccessKeyId,
          secretAccessKey: s3SecretAccessKey,
          forcePathStyle: process.env.S3_FORCE_PATH_STYLE !== 'false',
        }
      : undefined;

  return {
    port: parseInt(process.env.PORT || '3001', 10),
    host: process.env.HOST || '0.0.0.0',
    databaseUrl: process.env.DATABASE_URL,
    jwtSecret: process.env.JWT_SECRET || 'proofbook-dev-secret-key-change-in-production-2026',
    storageProvider: process.env.STORAGE_PROVIDER as AppConfig['storageProvider'],
    storageDir: process.env.STORAGE_DIR,
    storageEncryptionKey: process.env.STORAGE_ENCRYPTION_KEY,
    s3,
  };
}

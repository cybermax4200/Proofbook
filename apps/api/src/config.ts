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
  storageDir?: string;
}

export function loadConfig(): AppConfig {
  return {
    port: parseInt(process.env.PORT || '3001', 10),
    host: process.env.HOST || '0.0.0.0',
    databaseUrl: process.env.DATABASE_URL,
    jwtSecret: process.env.JWT_SECRET || 'proofbook-dev-secret-key-change-in-production-2026',
    storageDir: process.env.STORAGE_DIR,
  };
}

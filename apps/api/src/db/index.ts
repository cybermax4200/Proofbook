import { PGlite } from '@electric-sql/pglite';
import { drizzle as drizzlePglite } from 'drizzle-orm/pglite';
import { drizzle as drizzleNodePg } from 'drizzle-orm/node-postgres';
import pg from 'pg';
import * as schema from './schema.js';
import { initSchema } from './migrate.js';

export * from './schema.js';
export * from './migrate.js';

export interface DatabaseOptions {
  databaseUrl?: string;
  dataDir?: string;
}

export type AppDatabase = ReturnType<typeof drizzlePglite<typeof schema>>;

export interface DatabaseHandle {
  db: AppDatabase;
  close: () => Promise<void>;
  isPgLite: boolean;
}

/**
 * Initializes and configures the database connection.
 * If databaseUrl starts with postgres:// or postgresql://, uses node-postgres Pool.
 * Otherwise, uses in-process PGlite (ideal for zero-Docker setups and testing).
 */
export async function createDatabase(options: DatabaseOptions = {}): Promise<DatabaseHandle> {
  const databaseUrl = options.databaseUrl || process.env.DATABASE_URL;

  if (databaseUrl && (databaseUrl.startsWith('postgres://') || databaseUrl.startsWith('postgresql://'))) {
    const pool = new pg.Pool({ connectionString: databaseUrl });

    // Run schema creation DDL
    const execClient = {
      exec: async (sql: string) => {
        await pool.query(sql);
      },
    };
    await initSchema(execClient);

    const db = drizzleNodePg(pool, { schema }) as unknown as AppDatabase;

    return {
      db,
      close: async () => {
        await pool.end();
      },
      isPgLite: false,
    };
  }

  // Use PGlite in-memory or persisted
  const pgliteClient = options.dataDir ? new PGlite(options.dataDir) : new PGlite();
  await initSchema(pgliteClient);

  const db = drizzlePglite(pgliteClient, { schema });

  return {
    db,
    close: async () => {
      await pgliteClient.close();
    },
    isPgLite: true,
  };
}

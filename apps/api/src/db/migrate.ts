export const SCHEMA_DDL = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_keys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  public_key TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'ed25519',
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  revoked_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS orgs (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  stellar_address TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS memberships (
  org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (org_id, user_id)
);

CREATE TABLE IF NOT EXISTS records (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  type TEXT NOT NULL DEFAULT 'default',
  author_key_id TEXT NOT NULL REFERENCES user_keys(id),
  status TEXT NOT NULL DEFAULT 'pending',
  leaf_hash TEXT NOT NULL,
  field_root TEXT NOT NULL,
  ciphertext_ref TEXT NOT NULL,
  seq_no INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  approved_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS record_signatures (
  id TEXT PRIMARY KEY,
  record_id TEXT NOT NULL REFERENCES records(id) ON DELETE CASCADE,
  key_id TEXT NOT NULL REFERENCES user_keys(id),
  kind TEXT NOT NULL,
  signature TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS evidence (
  id TEXT PRIMARY KEY,
  record_id TEXT NOT NULL REFERENCES records(id) ON DELETE CASCADE,
  sha256 TEXT NOT NULL,
  ciphertext_ref TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS checkpoints (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  onchain_id INTEGER,
  root TEXT NOT NULL,
  prev_root TEXT NOT NULL,
  record_count INTEGER NOT NULL,
  period_start TEXT NOT NULL,
  period_end TEXT NOT NULL,
  tx_hash TEXT,
  ledger INTEGER,
  anchored_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS checkpoint_records (
  checkpoint_id TEXT NOT NULL REFERENCES checkpoints(id) ON DELETE CASCADE,
  record_id TEXT NOT NULL REFERENCES records(id) ON DELETE CASCADE,
  leaf_index INTEGER NOT NULL,
  PRIMARY KEY (checkpoint_id, record_id)
);

CREATE TABLE IF NOT EXISTS merkle_nodes (
  checkpoint_id TEXT NOT NULL REFERENCES checkpoints(id) ON DELETE CASCADE,
  level INTEGER NOT NULL,
  idx INTEGER NOT NULL,
  hash TEXT NOT NULL,
  PRIMARY KEY (checkpoint_id, level, idx)
);

CREATE INDEX IF NOT EXISTS idx_records_org_seq ON records(org_id, seq_no);
CREATE INDEX IF NOT EXISTS idx_records_org_status ON records(org_id, status);
CREATE INDEX IF NOT EXISTS idx_user_keys_user ON user_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_checkpoints_org ON checkpoints(org_id);
`;

export interface ExecutableClient {
  exec(sql: string): Promise<any>;
}

/**
 * Initializes the database tables and indexes if they do not exist.
 */
export async function initSchema(client: ExecutableClient): Promise<void> {
  await client.exec(SCHEMA_DDL);
}

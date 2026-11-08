import {
  pgTable,
  text,
  timestamp,
  integer,
  primaryKey,
} from 'drizzle-orm/pg-core';

export const users = pgTable('users', {
  id: text('id').primaryKey(),
  email: text('email').notNull().unique(),
  passwordHash: text('password_hash').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

export const userKeys = pgTable('user_keys', {
  id: text('id').primaryKey(),
  userId: text('user_id')
    .notNull()
    .references(() => users.id, { onDelete: 'cascade' }),
  publicKey: text('public_key').notNull(),
  kind: text('kind').notNull().default('ed25519'),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  revokedAt: timestamp('revoked_at', { withTimezone: true }),
});

export const orgs = pgTable('orgs', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  stellarAddress: text('stellar_address'),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

export const memberships = pgTable(
  'memberships',
  {
    orgId: text('org_id')
      .notNull()
      .references(() => orgs.id, { onDelete: 'cascade' }),
    userId: text('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    role: text('role').notNull(), // 'admin' | 'maker' | 'checker' | 'auditor'
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.orgId, table.userId] }),
  ]
);

export const records = pgTable('records', {
  id: text('id').primaryKey(),
  orgId: text('org_id')
    .notNull()
    .references(() => orgs.id, { onDelete: 'cascade' }),
  type: text('type').notNull().default('default'),
  authorKeyId: text('author_key_id')
    .notNull()
    .references(() => userKeys.id),
  status: text('status').notNull().default('pending'), // 'draft' | 'pending' | 'approved' | 'rejected' | 'shredded'
  leafHash: text('leaf_hash').notNull(),
  fieldRoot: text('field_root').notNull(),
  ciphertextRef: text('ciphertext_ref').notNull(),
  seqNo: integer('seq_no').notNull(),
  createdAt: text('created_at').notNull(), // RFC 3339 UTC string used for leaf hashing
  approvedAt: timestamp('approved_at', { withTimezone: true }),
});

export const recordSignatures = pgTable('record_signatures', {
  id: text('id').primaryKey(),
  recordId: text('record_id')
    .notNull()
    .references(() => records.id, { onDelete: 'cascade' }),
  keyId: text('key_id')
    .notNull()
    .references(() => userKeys.id),
  kind: text('kind').notNull(), // 'author' | 'approver'
  signature: text('signature').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;

export type UserKey = typeof userKeys.$inferSelect;
export type NewUserKey = typeof userKeys.$inferInsert;

export type Org = typeof orgs.$inferSelect;
export type NewOrg = typeof orgs.$inferInsert;

export type Membership = typeof memberships.$inferSelect;
export type NewMembership = typeof memberships.$inferInsert;

export type Record = typeof records.$inferSelect;
export type NewRecord = typeof records.$inferInsert;

export type RecordSignature = typeof recordSignatures.$inferSelect;
export type NewRecordSignature = typeof recordSignatures.$inferInsert;

# Proofbook: 10-Day Incremental Implementation Plan

This document outlines the 10-day roadmap to build, test, deploy, and verify **Proofbook**—a privacy-preserving, tamper-evident evidence trail anchored on Stellar / Soroban.

---

## Architecture Overview

```mermaid
flowchart TD
    subgraph Client["Client App (Next.js / TypeScript)"]
        UI[Capture & Approvals UI]
        CR[Crypto Engine: PB1 & Salts]
        KS[Client Key Store: Ed25519]
    end

    subgraph Backend["Proofbook Core"]
        API[REST API: Fastify / Node]
        DB[(PostgreSQL / PGlite via Drizzle)]
        ST[(Encrypted Object Storage / Local FS)]
        W[Worker: Checkpoint Builder & Relay]
    end

    subgraph Stellar["Stellar Network"]
        SC{{Soroban Contract: Proofbook}}
        RPC[Soroban RPC Testnet]
    end

    subgraph Verifier["Independent Verifier"]
        VCLI[proofbook-cli]
        PUB[Public Verify Page]
    end

    UI --> CR --> KS
    UI --> API
    API --> DB
    API --> ST
    W --> API
    W --> RPC --> SC
    VCLI -. reads .-> RPC
    PUB -. reads .-> RPC
```

---

## 10-Day Progress Dashboard

- [x] **Day 1: Monorepo Setup & Soroban Smart Contract** *(Completed)*
- [x] **Day 2: Testnet Deployment & Automation Scripts** *(Completed)*
- [ ] **Day 3: Cryptographic Engine (`packages/crypto`) — Format PB1**
- [ ] **Day 4: Stateless Verifier & CLI (`packages/verifier`, `cli/proofbook-cli`)**
- [ ] **Day 5: Database Schema & Records API (`apps/api`)**
- [ ] **Day 6: Maker-Checker Approvals & Evidence Storage**
- [ ] **Day 7: Checkpoint Worker & Auto-Anchoring (`apps/worker`)**
- [ ] **Day 8: Auditor Workspace & Proof Bundler**
- [ ] **Day 9: Web Application (`apps/web`)**
- [ ] **Day 10: Auditor UI, End-to-End Testing & Demo Drill**

---

## Daily Milestones & Deliverables

### Day 1: Monorepo Setup & Soroban Smart Contract ✅
- [x] Root workspaces: `pnpm-workspace.yaml`, `package.json`, root `Cargo.toml`.
- [x] Pinned `Cargo.lock` with Soroban SDK 22 and compatible `ed25519-dalek` 2.2.0.
- [x] Implemented Soroban contract in `contracts/proofbook/src/lib.rs`:
  - `register_org`, `anchor_checkpoint`, `witness_checkpoint`, `authorize_auditor`, `revoke_auditor`, `latest_checkpoint`, `is_witnessed_by`, `get_checkpoint`.
  - Persistent storage TTL extension helpers.
- [x] Comprehensive adversarial unit tests in `contracts/proofbook/src/test.rs` (5/5 tests passing).
- [x] WASM target build (`target/wasm32-unknown-unknown/release/proofbook.wasm` — 17.8 KB).

---

### Day 2: Testnet Deployment & Automation Scripts ✅
- [x] Install and configure Stellar TypeScript SDK (`@stellar/stellar-sdk`).
- [x] Create `contracts/proofbook/scripts/deploy-testnet.ts`:
  - Testnet account generation and Friendbot auto-funding with IPv4 fallback & retry strategy.
  - Contract WASM upload and instantiation via Soroban RPC.
  - Automatic update of `PROOFBOOK_CONTRACT_ID` and `FEE_PAYER_SECRET` in `.env`.
- [x] Create `contracts/proofbook/scripts/interact-testnet.ts`:
  - Live invocation of `register_org` and `anchor_checkpoint` with authorization.
  - On-chain simulation and verification of `latest_checkpoint` state and continuity.
- [x] Automated CI / npm scripts: `pnpm contract:deploy`, `pnpm contract:interact`, and `pnpm contract:test`.

**Verification:**
```bash
pnpm --filter @proofbook/contracts deploy:testnet
pnpm --filter @proofbook/contracts interact:testnet
```

---

### Day 3: Cryptographic Engine (`packages/crypto`) — Format PB1
- [ ] Initialize `packages/crypto` with TypeScript + Node.js/WebCrypto + `@noble/hashes` + `@noble/ed25519`.
- [ ] Implement PB1 canonical serialization (RFC 8785 subset, fixed precision, deterministic ordering).
- [ ] Implement salted field commitments:
  $$\text{commit}(k, v, s) = \text{SHA256}(0x02 \parallel \text{len\_u16\_be}(k) \parallel k \parallel \text{len\_u32\_be}(v) \parallel v \parallel s)$$
- [ ] Implement PB1 Merkle Tree builder:
  - Record leaf domain separation (`0x00`).
  - Internal node domain separation (`0x01`).
  - Odd-node promotion without duplicate hashing.
  - Merkle proof generator with side indicators (`left` / `right`).
- [ ] Test vectors suite matching `/spec/FORMAT.md`.

**Verification:**
```bash
pnpm --filter @proofbook/crypto test
```

---

### Day 4: Stateless Verifier & CLI (`packages/verifier`, `cli/proofbook-cli`)
- [ ] Initialize `packages/verifier`:
  - Standalone, zero-server dependency bundle verification.
  - Recompute field commitments and leaf hash.
  - Verify Merkle proof against expected root.
  - Check Ed25519 author and checker signatures.
  - Stellar RPC reader: verify on-chain checkpoint, ledger timestamp, and auditor witness records.
- [ ] Build `cli/proofbook-cli`:
  - Executable CLI: `proofbook verify <path-to-bundle.json> --network testnet`.
  - Colorized terminal report for audit compliance.

**Verification:**
```bash
pnpm --filter proofbook-cli build
./cli/proofbook-cli/bin/proofbook verify ./spec/test-vectors/sample-bundle.json --network testnet
```

---

### Day 5: Database Schema & Records API (`apps/api`)
- [ ] Setup Fastify/Node REST API in `apps/api`.
- [ ] Configure Drizzle ORM supporting both PostgreSQL (via `DATABASE_URL`) and in-process PGlite (`@electric-sql/pglite`) for zero-Docker setups.
- [ ] Database Schema:
  - `users`, `user_keys` (Ed25519 public keys)
  - `orgs`, `memberships` (roles: `admin`, `maker`, `checker`, `auditor`)
  - `records` (`status: draft|pending|approved|rejected|shredded`, `leaf_hash`, `field_root`, `ciphertext_ref`)
  - `record_signatures`
- [ ] Authentication endpoints & public key registration (`/auth/register`, `/auth/login`).
- [ ] Encrypted record ingestion endpoint: accepts signed ciphertext + commitment.

**Verification:**
```bash
pnpm --filter @proofbook/api test
```

---

### Day 6: Maker-Checker Approvals & Evidence Storage
- [ ] Maker-checker workflow:
  - Submit record moves status to `pending`.
  - Author cannot approve their own record.
  - Endpoint `POST /orgs/:id/records/:rid/approve`: Checker verifies and adds signature to `leaf_hash`.
  - Rejection flow with audit reason logged.
- [ ] Evidence attachment storage:
  - Abstract storage interface (`StorageProvider`).
  - Local Encrypted File System provider for local dev.
  - S3 / MinIO provider for production.
  - Calculates and binds `evidence_hash: sha256:...` into canonical record fields.

**Verification:**
```bash
pnpm --filter @proofbook/api test:workflow
```

---

### Day 7: Checkpoint Worker & Auto-Anchoring (`apps/worker`)
- [ ] Implement `apps/worker`:
  - Job runner (cron / interval / trigger endpoint).
  - Fetches approved records since previous checkpoint.
  - Calculates cumulative `record_count`.
  - Builds Merkle tree using `packages/crypto`.
  - Persists Merkle sibling tree nodes in database for fast path extraction.
  - Calls Soroban `anchor_checkpoint` on Stellar Testnet via fee-paying platform account + org authorization.
  - Records on-chain `tx_hash`, `ledger`, and `checkpoint_id` in database.

**Verification:**
```bash
pnpm --filter @proofbook/worker run:once
```

---

### Day 8: Auditor Workspace & Proof Bundler
- [ ] Proof bundle generator endpoint: `POST /orgs/:id/proofs`.
  - Supports selective disclosure: masks non-disclosed fields while preserving valid Merkle path.
  - Exports standardized `bundle.json`.
- [ ] Auditor engagement endpoints:
  - `POST /orgs/:id/engagements`: Auditor invite and access scoping.
  - `GET /engagements/:eid/records`: Read-only authorized record viewer.
  - `POST /engagements/:eid/witness`: Prepares and relays on-chain `witness_checkpoint` transaction signed by auditor address.

**Verification:**
```bash
pnpm --filter @proofbook/api test:auditor
```

---

### Day 9: Web Application (`apps/web`)
- [ ] Initialize Next.js app with Tailwind CSS.
- [ ] Client-side cryptographic helper:
  - Generates per-field salts and computes commitments in-browser.
  - Client-side Ed25519 signing using WebCrypto / `@noble/ed25519`.
- [ ] Organization portal:
  - Record entry form (amount, payee, currency, evidence upload).
  - Maker-checker approval queue with one-click co-signing.
- [ ] Public verification page:
  - `/verify/:orgAddress/:checkpointId`: inspect on-chain state directly from Stellar RPC.
  - Drag-and-drop bundle verification in browser with zero server reliance.

**Verification:**
```bash
pnpm --filter @proofbook/web dev
```

---

### Day 10: Auditor UI, End-to-End Testing & Demo Drill
- [ ] Auditor workspace UI:
  - View checkpoints, check chain linkage, review evidence.
  - One-click on-chain "Witness Checkpoint" integration with Stellar wallet / key.
  - Export audit report (PDF / JSON) with embedded QR code.
- [ ] Comprehensive End-to-End drill (`test/e2e`):
  1. Maker signs record $1,250 USD to Acme Supplies.
  2. Checker approves and co-signs.
  3. Worker batches records, anchors root on Stellar Testnet.
  4. Auditor independently checks root and witnesses on Stellar.
  5. Standalone CLI and Public Web page verify the exported bundle offline.
- [ ] Final documentation update, clean scripts, and demo recording guide.

---

## Tech Stack & Standards

| Layer | Technology |
|---|---|
| **Blockchain** | Stellar / Soroban (Protocol 22), Rust `soroban-sdk` |
| **Cryptography** | PB1 (SHA-256, Ed25519, XChaCha20-Poly1305, Domain-separated Merkle) |
| **Monorepo** | pnpm workspaces, Turbo / pnpm scripts, Cargo workspaces |
| **Backend API** | Fastify / Node.js 20+, TypeScript |
| **Database** | PostgreSQL / PGlite via Drizzle ORM |
| **Object Store** | Local Encrypted FS (Dev) / S3-compatible MinIO (Prod) |
| **Frontend** | Next.js 14/15, Tailwind CSS, Lucide icons |
| **Verifier CLI** | Node.js standalone binary, published as `@proofbook/cli` |

---

## Helpful Commands

```bash
# Contract Tests
cargo test --manifest-path contracts/proofbook/Cargo.toml

# Build WASM
cargo build --manifest-path contracts/proofbook/Cargo.toml --target wasm32-unknown-unknown --release

# Inspect Contract Interface
stellar contract inspect --wasm target/wasm32-unknown-unknown/release/proofbook.wasm

# Run Entire Monorepo Test Suite
pnpm test
```

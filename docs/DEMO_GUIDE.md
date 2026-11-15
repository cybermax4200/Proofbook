# Proofbook PB1 — Live Demo & Recording Guide

This guide provides a reproducible, step-by-step script for demonstrating **Proofbook** (Format `PB1`) end-to-end across the Stellar Soroban smart contract, Fastify API, Checkpoint Worker, Web Application, and Standalone Verifier CLI.

---

## 1. Pre-Flight Environment Check

Before starting your screen recording or live presentation, run the pre-flight verification commands from the repository root:

```bash
# 1. Verify PB1 cryptographic test vectors
pnpm test:vectors

# 2. Run the automated 5-stage End-to-End drill
pnpm demo:drill

# 3. Verify the live Stellar Testnet Checkpoint #1 bundle via CLI
pnpm cli:verify
```

To start the web application locally on `http://localhost:3000`:

```bash
pnpm web:dev
```

---

## 2. Demo Recording Script (5-Minute Walkthrough)

### Scene 1: Architecture & Zero-Trust Threat Model (`0:00 - 0:45`)
1. Open `http://localhost:3000` (**Overview Page**).
2. Highlight the core design principle:
   - **No private data is ever written on-chain.** Stellar Soroban stores only 32-byte SHA-256 checkpoint Merkle roots, cumulative record counts, period windows, and auditor witness attestations.
   - **Domain Separation (`PB1`)**:
     - `0x02`: Per-field salted commitments (`SHA256(0x02 || k || v || salt_32)`)
     - `0x00`: Canonical record leaf hash (`SHA256(0x00 || id || pubkey_32 || ts || field_root)`)
     - `0x01`: Internal Merkle tree nodes (`SHA256(0x01 || left || right)`)

---

### Scene 2: Organization Portal — Maker Capture & Checker Co-Signing (`0:45 - 2:00`)
1. Navigate to `http://localhost:3000/portal` (**Organization Portal**).
2. **Maker Role (`Alice Vance`)**:
   - Enter a disbursement record:
     - **Amount**: `1250.00`
     - **Currency**: `USD`
     - **Payee**: `Acme Supplies Ltd`
     - **Memo / Purpose**: `Classroom materials, batch 4`
   - Attach an invoice file (e.g., `INV-2026-104-Acme-Supplies.pdf`).
   - Point out the **Live PB1 Field Commitment Preview** updating in real time in the browser with 32-byte CSPRNG salts (`0x02`) and bound `evidence_hash: sha256:...`.
   - Click **Sign & Submit Record (Maker Ed25519)**.
3. **Separation of Duties & Checker Co-Signing (`Marcus Sterling`)**:
   - Switch active persona to **Checker** in the top role switcher.
   - In the **Maker-Checker Approval Queue**, click **Approve & Co-Sign (Ed25519)** on the pending record.
   - Show that the browser recomputes the `0x00` record leaf hash, verifies the Maker's Ed25519 signature, and appends the Checker's Ed25519 co-signature.
   - Click **Selective Disclosure Export**, uncheck `payee` to mask the supplier identity while keeping `amount` and `currency` checked, and export `bundle.json`.

---

### Scene 3: Auditor Workspace — Chain Continuity, On-Chain Witnessing & PDF/QR Report (`2:00 - 3:30`)
1. Navigate to `http://localhost:3000/auditor` (**Auditor Workspace**).
2. **Checkpoint Chain Continuity**:
   - Show **Checkpoint #1** (Genesis, `prev_root = 0000...0000`, Ledger `#5591134`) and **Checkpoint #2** (`prev_root` cryptographically linked to Checkpoint #1's `root`).
3. **Evidence & Commitment Inspection**:
   - Click **Inspect Evidence** on the audited record to show the per-field commitments (`0x02`), Maker & Checker Ed25519 signature checks, and bound SHA-256 invoice hash.
4. **One-Click On-Chain Witnessing**:
   - Select **Checkpoint #2** (status: *Awaiting Witness*).
   - Choose **Stellar Auditor Keypair** or **Stellar Wallet / Freighter**.
   - Click **One-Click Witness Checkpoint #2 on Stellar**.
   - Point out the resulting `witness_checkpoint` transaction hash, ledger sequence, and updated status badge (`Witnessed`).
5. **Export Audit Assurance Report (PDF & JSON) with Embedded QR Code**:
   - Point out the live SVG QR code encoding the public verification URL (`/verify/:orgAddress/:checkpointId`).
   - Click **Export PDF Report (.pdf)** and **Export JSON Report (.json)**.

---

### Scene 4: Zero-Server Public Verification & Tamper Detection (`3:30 - 5:00`)
1. Navigate to `http://localhost:3000/verify/GDGZW7GAZNBP4NGIPRUTHTIE6JRUEAWNOEXKMSXK6XYWQPRAQP2HHMRQ/1`.
2. Show the live Stellar Soroban RPC readout for **Checkpoint #1** on contract `CDB4DCLRAIAGILGM4DWIOKOTSWDDY6IGP4X4FF62DA3GUQQ4LEKD5VCD`:
   - Anchored Merkle root: `424931a27af0ed483bef809271e55b0ce1f29e843f654eb796faee415d480d17`
   - Verified on-chain auditor witness: `GBHTYTJUH6BFBVER5OHDLLYYW4KOYH6J6L7WZVIAWH74H7FSOQCEZHI5`
3. Drop the exported `bundle.json` (or click **Load Testnet Sample Bundle**) into the **Zero-Server Bundle Verifier** and show all cryptographic checks passing (`VERIFIED ✓`).
4. Click **Simulate Tampered Amount ($9,999.99)** to demonstrate immediate cryptographic detection of a modified field value (`VERIFICATION FAILED ✗`).
5. Switch to the terminal and run the standalone CLI verifier:
   ```bash
   ./cli/proofbook-cli/bin/proofbook verify ./spec/test-vectors/sample-bundle.json --network testnet
   ```
   Show the matching `RESULT: VERIFIED ✓` terminal report.

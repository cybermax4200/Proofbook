import React from 'react';
import Link from 'next/link';
import {
  ShieldCheck,
  Lock,
  KeyRound,
  FileCheck2,
  ArrowRight,
  GitCommitHorizontal,
  Layers,
  CheckCircle2,
  ExternalLink,
} from 'lucide-react';

export default function HomePage() {
  return (
    <div className="mx-auto max-w-7xl px-4 py-10 sm:px-6 lg:px-8">
      {/* Hero Banner */}
      <div className="relative overflow-hidden rounded-2xl border border-slate-800 bg-gradient-to-br from-slate-900 via-slate-950 to-indigo-950/40 p-8 sm:p-12">
        <div className="max-w-3xl space-y-5">
          <div className="inline-flex items-center gap-2 rounded-full border border-indigo-500/30 bg-indigo-500/10 px-3.5 py-1 text-xs font-medium text-indigo-300">
            <ShieldCheck className="h-3.5 w-3.5" />
            <span>Zero-Trust Audit Trail • Format PB1 • Stellar Soroban Testnet</span>
          </div>

          <h1 className="text-3xl font-extrabold tracking-tight text-white sm:text-5xl">
            Privacy-Preserving Evidence Anchored on{' '}
            <span className="bg-gradient-to-r from-indigo-400 to-emerald-400 bg-clip-text text-transparent">
              Stellar Soroban
            </span>
          </h1>

          <p className="text-base leading-relaxed text-slate-300 sm:text-lg">
            Generate per-field salted SHA-256 commitments in your browser, enforce
            cryptographic Maker-Checker Ed25519 co-signatures, and verify selective
            disclosure proof bundles directly against Stellar RPC with zero server
            dependency.
          </p>

          <div className="flex flex-wrap gap-3.5 pt-2">
            <Link
              href="/portal"
              className="inline-flex items-center gap-2 rounded-xl bg-indigo-600 px-5 py-3 text-sm font-semibold text-white shadow-lg shadow-indigo-600/25 hover:bg-indigo-500 transition"
            >
              <span>Open Organization Portal</span>
              <ArrowRight className="h-4 w-4" />
            </Link>

            <Link
              href="/verify"
              className="inline-flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-900/90 px-5 py-3 text-sm font-semibold text-slate-200 hover:border-slate-600 hover:bg-slate-800 transition"
            >
              <FileCheck2 className="h-4 w-4 text-emerald-400" />
              <span>Verify Proof Bundle</span>
            </Link>

            <Link
              href="/verify/GDGZW7GAZNBP4NGIPRUTHTIE6JRUEAWNOEXKMSXK6XYWQPRAQP2HHMRQ/1"
              className="inline-flex items-center gap-2 rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm font-medium text-emerald-300 hover:bg-emerald-500/20 transition"
            >
              <span>Inspect Live Checkpoint #1</span>
              <ExternalLink className="h-4 w-4" />
            </Link>
          </div>
        </div>
      </div>

      {/* Cryptographic Pipeline Cards */}
      <div className="mt-10 grid gap-6 md:grid-cols-3">
        <div className="rounded-xl border border-slate-800/90 bg-slate-900/50 p-6">
          <div className="mb-4 flex h-10 w-10 items-center justify-center rounded-lg bg-indigo-500/15 text-indigo-400 border border-indigo-500/30">
            <Lock className="h-5 w-5" />
          </div>
          <h2 className="text-lg font-semibold text-slate-100">
            1. In-Browser Salted Commitments
          </h2>
          <p className="mt-2 text-sm leading-relaxed text-slate-400">
            Every record field (<code className="text-indigo-300">amount</code>,{' '}
            <code className="text-indigo-300">payee</code>,{' '}
            <code className="text-indigo-300">currency</code>,{' '}
            <code className="text-indigo-300">evidence_hash</code>) is paired with
            32 bytes of CSPRNG entropy and hashed using PB1 domain separation (
            <code className="text-slate-300">0x02</code>).
          </p>
        </div>

        <div className="rounded-xl border border-slate-800/90 bg-slate-900/50 p-6">
          <div className="mb-4 flex h-10 w-10 items-center justify-center rounded-lg bg-amber-500/15 text-amber-400 border border-amber-500/30">
            <KeyRound className="h-5 w-5" />
          </div>
          <h2 className="text-lg font-semibold text-slate-100">
            2. Maker-Checker Co-Signing
          </h2>
          <p className="mt-2 text-sm leading-relaxed text-slate-400">
            Makers sign the canonical record leaf (
            <code className="text-slate-300">0x00</code>) with a client-side Ed25519
            keypair. Checkers independently verify the leaf hash and append a
            cryptographic co-signature before anchoring.
          </p>
        </div>

        <div className="rounded-xl border border-slate-800/90 bg-slate-900/50 p-6">
          <div className="mb-4 flex h-10 w-10 items-center justify-center rounded-lg bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
            <CheckCircle2 className="h-5 w-5" />
          </div>
          <h2 className="text-lg font-semibold text-slate-100">
            3. Stateless Stellar Verification
          </h2>
          <p className="mt-2 text-sm leading-relaxed text-slate-400">
            Auditors and third parties drop a <code className="text-emerald-300">bundle.json</code>{' '}
            into the public verifier to recompute commitments, evaluate Merkle
            paths, verify Ed25519 signatures, and query Soroban RPC directly.
          </p>
        </div>
      </div>

      {/* Format PB1 Domain Separation Reference */}
      <div className="mt-10 rounded-xl border border-slate-800 bg-slate-900/40 p-6">
        <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
          <div>
            <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
              <Layers className="h-4 w-4 text-indigo-400" />
              Format PB1 Cryptographic Specification
            </h3>
            <p className="mt-1 text-xs text-slate-400">
              Deterministic domain-separated hashing prevents second-preimage and cross-layer collisions.
            </p>
          </div>
          <span className="inline-flex items-center gap-1.5 rounded-md bg-slate-800 px-3 py-1 font-mono text-xs text-slate-300">
            <GitCommitHorizontal className="h-3.5 w-3.5 text-indigo-400" />
            RFC 8785 Canonical Subset
          </span>
        </div>

        <div className="mt-4 grid gap-4 md:grid-cols-3 font-mono text-xs">
          <div className="rounded-lg border border-slate-800 bg-slate-950/80 p-3.5">
            <div className="text-indigo-400 font-semibold mb-1">
              0x02 • Field Commitment
            </div>
            <div className="text-slate-300 break-all">
              SHA256(0x02 ∥ len_u16(k) ∥ k ∥ len_u32(v) ∥ v ∥ salt_32)
            </div>
          </div>

          <div className="rounded-lg border border-slate-800 bg-slate-950/80 p-3.5">
            <div className="text-amber-400 font-semibold mb-1">
              0x00 • Record Leaf Hash
            </div>
            <div className="text-slate-300 break-all">
              SHA256(0x00 ∥ len_u16(id) ∥ id ∥ pubkey_32 ∥ len_u16(ts) ∥ ts ∥ field_root)
            </div>
          </div>

          <div className="rounded-lg border border-slate-800 bg-slate-950/80 p-3.5">
            <div className="text-emerald-400 font-semibold mb-1">
              0x01 • Merkle Internal Node
            </div>
            <div className="text-slate-300 break-all">
              SHA256(0x01 ∥ left_32 ∥ right_32) (odd node promoted)
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

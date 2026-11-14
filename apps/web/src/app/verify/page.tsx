'use client';

import React, { useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  CheckCircle2,
  Search,
  ArrowRight,
  Terminal,
  Blocks,
} from 'lucide-react';
import { BundleDropzoneVerifier } from '@/components/verify/BundleDropzoneVerifier';
import { DEFAULT_ORG_STELLAR } from '@/lib/portal-store';

export default function PublicVerifyIndexPage() {
  const router = useRouter();
  const [orgAddress, setOrgAddress] = useState(DEFAULT_ORG_STELLAR);
  const [checkpointId, setCheckpointId] = useState('1');

  const handleInspectOnChain = (e: React.FormEvent) => {
    e.preventDefault();
    if (!orgAddress.trim() || !checkpointId.trim()) return;
    router.push(`/verify/${encodeURIComponent(orgAddress.trim())}/${encodeURIComponent(checkpointId.trim())}`);
  };

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8 space-y-8">
      {/* Header & On-Chain Checkpoint Lookup Bar */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
        <div className="flex flex-col justify-between gap-6 lg:flex-row lg:items-center">
          <div className="space-y-1.5">
            <div className="inline-flex items-center gap-2 rounded-full bg-emerald-500/10 px-3 py-0.5 text-xs font-semibold text-emerald-300 border border-emerald-500/30">
              <CheckCircle2 className="h-3.5 w-3.5" />
              <span>Zero-Server Browser Verifier</span>
            </div>
            <h1 className="text-2xl font-bold text-white">
              Independent Proof Bundle & Stellar Checkpoint Verifier
            </h1>
            <p className="text-xs text-slate-400">
              Verify exported <code className="text-indigo-300">bundle.json</code> files completely in your browser or inspect anchored checkpoints directly from Stellar Soroban RPC.
            </p>
          </div>

          {/* Direct On-Chain Route Lookup (/verify/:orgAddress/:checkpointId) */}
          <form
            onSubmit={handleInspectOnChain}
            className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2.5 rounded-xl border border-slate-800 bg-slate-950 p-2.5"
          >
            <div className="flex items-center gap-2 px-2">
              <Blocks className="h-4 w-4 text-indigo-400 shrink-0" />
              <input
                type="text"
                value={orgAddress}
                onChange={(e) => setOrgAddress(e.target.value)}
                placeholder="Stellar Org Address (G...)"
                className="w-full sm:w-56 bg-transparent font-mono text-xs text-white focus:outline-none"
              />
            </div>

            <div className="flex items-center gap-1.5 border-t sm:border-t-0 sm:border-l border-slate-800 pt-2 sm:pt-0 sm:pl-2.5">
              <span className="text-xs text-slate-500 font-mono">#</span>
              <input
                type="number"
                min={1}
                value={checkpointId}
                onChange={(e) => setCheckpointId(e.target.value)}
                className="w-16 bg-transparent font-mono text-xs text-white focus:outline-none"
              />
              <button
                type="submit"
                className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-emerald-500 transition whitespace-nowrap"
              >
                <Search className="h-3.5 w-3.5" />
                <span>Inspect On-Chain</span>
                <ArrowRight className="h-3 w-3" />
              </button>
            </div>
          </form>
        </div>
      </div>

      {/* Standalone Drag & Drop Verifier */}
      <BundleDropzoneVerifier initialAutoLoadSample={true} />

      {/* CLI Parity Footer Note */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-800/80 bg-slate-950/80 px-4 py-3 text-xs text-slate-400">
        <div className="flex items-center gap-2">
          <Terminal className="h-4 w-4 text-indigo-400" />
          <span>Equivalent CLI command:</span>
        </div>
        <code className="rounded bg-slate-900 px-2.5 py-1 font-mono text-[11px] text-emerald-300 border border-slate-800">
          ./cli/proofbook-cli/bin/proofbook verify ./spec/test-vectors/sample-bundle.json --network testnet
        </code>
      </div>
    </div>
  );
}

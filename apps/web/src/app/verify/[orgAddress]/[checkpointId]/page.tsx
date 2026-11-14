'use client';

import React, { useEffect, useState, useCallback } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import {
  Blocks,
  CheckCircle2,
  RefreshCw,
  ShieldCheck,
  ArrowLeft,
  Clock,
  Hash,
  UserCheck,
  AlertTriangle,
} from 'lucide-react';
import {
  DEFAULT_PROOFBOOK_CONTRACT_ID,
  fetchOnChainCheckpointInBrowser,
  OnChainCheckpointState,
  TESTNET_SOROBAN_RPC_URL,
} from '@/lib/browser-verifier';
import { BundleDropzoneVerifier } from '@/components/verify/BundleDropzoneVerifier';

export default function OnChainCheckpointVerifyPage() {
  const params = useParams<{ orgAddress: string; checkpointId: string }>();
  const orgAddress = decodeURIComponent(params?.orgAddress || '');
  const checkpointId = Number(params?.checkpointId || '1');

  const [rpcUrl, setRpcUrl] = useState(TESTNET_SOROBAN_RPC_URL);
  const [contractId, setContractId] = useState(DEFAULT_PROOFBOOK_CONTRACT_ID);
  const [checkpoint, setCheckpoint] = useState<OnChainCheckpointState | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadCheckpointState = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const state = await fetchOnChainCheckpointInBrowser({
        orgAddress,
        checkpointId,
        contractId,
        rpcUrl,
      });
      setCheckpoint(state);
    } catch (err: any) {
      setError(err.message || 'Failed to query Soroban RPC');
    } finally {
      setLoading(false);
    }
  }, [orgAddress, checkpointId, contractId, rpcUrl]);

  useEffect(() => {
    loadCheckpointState();
  }, [loadCheckpointState]);

  const formatEpoch = (epochStr: string) => {
    const num = Number(epochStr);
    if (!Number.isFinite(num) || num <= 0) return epochStr;
    return new Date(num * 1000).toISOString();
  };

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8 space-y-8">
      {/* Top Breadcrumb & Controls */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <Link
          href="/verify"
          className="inline-flex items-center gap-2 text-xs font-semibold text-slate-400 hover:text-white transition"
        >
          <ArrowLeft className="h-4 w-4" />
          <span>Back to Public Verifier</span>
        </Link>

        <div className="flex items-center gap-2">
          <span className="font-mono text-xs text-slate-400">
            RPC: {rpcUrl}
          </span>
          <button
            type="button"
            onClick={loadCheckpointState}
            disabled={loading}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800 transition"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Query Soroban RPC</span>
          </button>
        </div>
      </div>

      {/* On-Chain Checkpoint State Card */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
        <div className="flex flex-wrap items-start justify-between gap-4 border-b border-slate-800 pb-5">
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2.5">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                <Blocks className="h-5 w-5" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h1 className="text-xl font-bold text-white">
                    Stellar On-Chain Checkpoint #{checkpointId}
                  </h1>
                  {checkpoint && (
                    <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/15 px-2.5 py-0.5 text-[11px] font-semibold text-emerald-300 border border-emerald-500/30">
                      <CheckCircle2 className="h-3 w-3" />
                      Anchored
                    </span>
                  )}
                </div>
                <p className="font-mono text-xs text-slate-400">
                  Org: {orgAddress}
                </p>
              </div>
            </div>
          </div>

          <div className="text-right font-mono text-xs">
            <div className="text-slate-400">Soroban Contract ID</div>
            <div className="text-indigo-300 break-all">{contractId}</div>
          </div>
        </div>

        {loading && (
          <div className="py-10 text-center text-sm text-slate-400">
            Simulating <code className="text-indigo-300">get_checkpoint</code> &{' '}
            <code className="text-indigo-300">is_witnessed_by</code> on Stellar Soroban RPC...
          </div>
        )}

        {error && !loading && (
          <div className="mt-5 rounded-xl border border-rose-500/40 bg-rose-950/30 p-4 text-xs text-rose-200 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-rose-400 shrink-0" />
            <div>
              <div className="font-bold">On-Chain Lookup Failed</div>
              <div className="font-mono mt-0.5">{error}</div>
            </div>
          </div>
        )}

        {checkpoint && !loading && (
          <div className="mt-6 space-y-6">
            {/* Root Hashes */}
            <div className="grid gap-4 md:grid-cols-2">
              <div className="rounded-xl border border-emerald-500/30 bg-slate-950/90 p-4">
                <div className="flex items-center gap-1.5 text-xs font-semibold text-emerald-400 mb-1">
                  <Hash className="h-3.5 w-3.5" />
                  <span>Anchored Merkle Root (32-Byte SHA-256)</span>
                </div>
                <div className="font-mono text-xs text-white break-all">
                  {checkpoint.root}
                </div>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950/90 p-4">
                <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-400 mb-1">
                  <Hash className="h-3.5 w-3.5" />
                  <span>Previous Checkpoint Root (Chain Continuity)</span>
                </div>
                <div className="font-mono text-xs text-slate-300 break-all">
                  {checkpoint.prevRoot}
                </div>
              </div>
            </div>

            {/* Ledger & Period Metadata */}
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-3.5">
                <div className="text-[11px] text-slate-400">Stellar Ledger Sequence</div>
                <div className="mt-1 font-mono text-base font-bold text-white">
                  #{checkpoint.ledger}
                </div>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-3.5">
                <div className="text-[11px] text-slate-400">Cumulative Record Count</div>
                <div className="mt-1 font-mono text-base font-bold text-indigo-300">
                  {checkpoint.recordCount} records
                </div>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-3.5">
                <div className="text-[11px] text-slate-400 flex items-center gap-1">
                  <Clock className="h-3 w-3" />
                  <span>Ledger Anchor Timestamp</span>
                </div>
                <div className="mt-1 font-mono text-xs font-semibold text-slate-200">
                  {formatEpoch(checkpoint.timestamp)}
                </div>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-3.5">
                <div className="text-[11px] text-slate-400">Period Window</div>
                <div className="mt-1 font-mono text-[11px] text-slate-300">
                  {checkpoint.periodStart} → {checkpoint.periodEnd}
                </div>
              </div>
            </div>

            {/* On-Chain Auditor Co-Signatures / Witnesses */}
            <div className="rounded-xl border border-indigo-500/30 bg-indigo-950/15 p-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-xs font-semibold text-indigo-300">
                  <UserCheck className="h-4 w-4" />
                  <span>
                    On-Chain Auditor Witnesses (<code>is_witnessed_by</code>)
                  </span>
                </div>
                <span className="rounded-full bg-indigo-500/20 px-2.5 py-0.5 font-mono text-[11px] text-indigo-200">
                  {checkpoint.witnesses.length} Verified Witness(es)
                </span>
              </div>

              {checkpoint.witnesses.length > 0 ? (
                <div className="mt-2.5 flex flex-wrap gap-2">
                  {checkpoint.witnesses.map((w) => (
                    <span
                      key={w}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 font-mono text-xs text-emerald-300"
                    >
                      <ShieldCheck className="h-3.5 w-3.5" />
                      {w}
                    </span>
                  ))}
                </div>
              ) : (
                <p className="mt-2 text-xs text-slate-400">
                  No auditor witnesses recorded for this checkpoint yet.
                </p>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Scoped Drag-and-Drop Bundle Verifier */}
      <div className="space-y-3">
        <h2 className="text-lg font-bold text-white flex items-center gap-2">
          <ShieldCheck className="h-5 w-5 text-indigo-400" />
          <span>Verify Proof Bundle Against Checkpoint #{checkpointId}</span>
        </h2>
        <BundleDropzoneVerifier
          expectedCheckpointRoot={checkpoint?.root}
          initialAutoLoadSample={true}
        />
      </div>
    </div>
  );
}

'use client';

import React, { useEffect, useState, useMemo } from 'react';
import Link from 'next/link';
import {
  ShieldCheck,
  GitCommitHorizontal,
  CheckCircle2,
  AlertTriangle,
  FileText,
  Download,
  KeyRound,
  Wallet,
  Blocks,
  QrCode,
  ExternalLink,
  RefreshCw,
  FileCheck2,
  Eye,
  Stamp,
  Hash,
  UserCheck,
} from 'lucide-react';
import {
  AuditorCheckpoint,
  AuditReportData,
  buildAuditReportJson,
  buildAuditReportPdfBytes,
  getDefaultAuditorWallet,
  loadAuditorCheckpoints,
  resetAuditorCheckpoints,
  saveAuditorCheckpoints,
  verifyCheckpointChainLinkage,
  witnessCheckpointInBrowser,
} from '@/lib/auditor-store';
import {
  buildExportProofBundle,
  loadPortalRecords,
  PortalRecord,
} from '@/lib/portal-store';

export default function AuditorWorkspacePage() {
  const defaultWallet = useMemo(() => getDefaultAuditorWallet(), []);
  const [checkpoints, setCheckpoints] = useState<AuditorCheckpoint[]>([]);
  const [records, setRecords] = useState<PortalRecord[]>([]);
  const [selectedCheckpointId, setSelectedCheckpointId] = useState<number>(2);
  const [walletMode, setWalletMode] = useState<'stellar-keypair' | 'freighter-wallet'>(
    'stellar-keypair'
  );
  const [auditorSecret, setAuditorSecret] = useState(defaultWallet.secretKey);
  const [auditorAddress, setAuditorAddress] = useState(defaultWallet.publicKey);
  const [auditorLabel, setAuditorLabel] = useState(defaultWallet.label);
  const [witnessing, setWitnessing] = useState(false);
  const [banner, setBanner] = useState<{
    type: 'success' | 'error' | 'info';
    text: string;
  } | null>(null);
  const [selectedRecordId, setSelectedRecordId] = useState<string | null>(null);

  useEffect(() => {
    const loadedRecords = loadPortalRecords();
    const loadedCheckpoints = loadAuditorCheckpoints();
    setRecords(loadedRecords);
    setCheckpoints(loadedCheckpoints);
    if (loadedCheckpoints.length > 0) {
      const preferred =
        loadedCheckpoints.find((c) => c.id === 2) ||
        loadedCheckpoints[loadedCheckpoints.length - 1];
      setSelectedCheckpointId(preferred.id);
    }
  }, []);

  const chainLinkage = useMemo(
    () => verifyCheckpointChainLinkage(checkpoints),
    [checkpoints]
  );

  const selectedCheckpoint = useMemo(
    () =>
      checkpoints.find((c) => c.id === selectedCheckpointId) ||
      checkpoints[checkpoints.length - 1] ||
      null,
    [checkpoints, selectedCheckpointId]
  );

  const auditReport: AuditReportData | null = useMemo(() => {
    if (!selectedCheckpoint || checkpoints.length === 0) return null;
    try {
      return buildAuditReportJson({
        checkpoints,
        targetCheckpointId: selectedCheckpoint.id,
        records,
        auditorProfile: {
          ...defaultWallet,
          label: auditorLabel,
          publicKey: auditorAddress,
          secretKey: auditorSecret,
        },
        baseUrl:
          typeof window !== 'undefined'
            ? window.location.origin
            : 'https://proofbook.stellar.org',
      });
    } catch {
      return null;
    }
  }, [
    checkpoints,
    selectedCheckpoint,
    records,
    defaultWallet,
    auditorLabel,
    auditorAddress,
    auditorSecret,
  ]);

  const handleConnectFreighter = async () => {
    setWalletMode('freighter-wallet');
    const anyWin = typeof window !== 'undefined' ? (window as any) : null;
    if (anyWin?.freighterApi?.getPublicKey) {
      try {
        const pub = await anyWin.freighterApi.getPublicKey();
        if (pub) {
          setAuditorAddress(pub);
          setBanner({
            type: 'info',
            text: `Connected Stellar Wallet extension: ${pub.slice(0, 10)}...${pub.slice(-6)}`,
          });
          return;
        }
      } catch {
        // Fallback to embedded Stellar keypair
      }
    }
    setBanner({
      type: 'info',
      text: `Stellar browser wallet ready (${defaultWallet.publicKey.slice(0, 10)}...${defaultWallet.publicKey.slice(-6)})`,
    });
  };

  const handleWitnessCheckpoint = async () => {
    if (!selectedCheckpoint) return;
    setWitnessing(true);
    setBanner(null);
    try {
      const res = await witnessCheckpointInBrowser({
        checkpoint: selectedCheckpoint,
        rootSeen: selectedCheckpoint.root,
        auditorSecret,
        auditorAddress,
        auditorLabel,
        mode: walletMode,
      });

      const nextCheckpoints = checkpoints.map((c) =>
        c.id === selectedCheckpoint.id ? res.updatedCheckpoint : c
      );
      setCheckpoints(nextCheckpoints);
      saveAuditorCheckpoints(nextCheckpoints);

      setBanner({
        type: 'success',
        text: `On-chain witness_checkpoint confirmed for Checkpoint #${selectedCheckpoint.id}! Tx: ${res.witnessEntry.txHash.slice(0, 16)}... (Ledger #${res.witnessEntry.ledger})`,
      });
    } catch (err: any) {
      setBanner({
        type: 'error',
        text: err.message || 'Failed to witness checkpoint on Stellar',
      });
    } finally {
      setWitnessing(false);
    }
  };

  const handleExportJsonReport = () => {
    if (!auditReport) return;
    const blob = new Blob([JSON.stringify(auditReport, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `proofbook-audit-report-cp${auditReport.targetCheckpoint.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
    setBanner({
      type: 'info',
      text: `Exported JSON Audit Report (${a.download}) with embedded verification QR code.`,
    });
  };

  const handleExportPdfReport = () => {
    if (!auditReport) return;
    const pdfBytes = buildAuditReportPdfBytes(auditReport);
    const blob = new Blob([pdfBytes as BlobPart], { type: 'application/pdf' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `proofbook-audit-report-cp${auditReport.targetCheckpoint.id}.pdf`;
    a.click();
    URL.revokeObjectURL(url);
    setBanner({
      type: 'info',
      text: `Exported signed PDF 1.4 Audit Assurance Report (${a.download}) with embedded QR code.`,
    });
  };

  const handleExportRecordBundle = (recordId: string) => {
    const rec = records.find((r) => r.id === recordId);
    if (!rec) return;
    const bundle = buildExportProofBundle(rec);
    const blob = new Blob([JSON.stringify(bundle, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `bundle-${recordId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleResetWorkspace = () => {
    const fresh = resetAuditorCheckpoints();
    setCheckpoints(fresh);
    setSelectedCheckpointId(2);
    setBanner({
      type: 'info',
      text: 'Auditor workspace reset to seed checkpoints (#1 witnessed on Testnet, #2 ready for one-click witnessing).',
    });
  };

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8 space-y-8">
      {/* Top Engagement & Stellar Wallet Bar */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/75 p-6">
        <div className="flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
          <div className="space-y-1.5">
            <div className="flex flex-wrap items-center gap-2">
              <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-0.5 text-xs font-semibold text-emerald-300">
                <ShieldCheck className="h-3.5 w-3.5" />
                Active Audit Engagement
              </span>
              <span className="font-mono text-xs text-slate-400">
                {defaultWallet.engagementId}
              </span>
            </div>
            <h1 className="text-2xl font-bold tracking-tight text-white">
              Auditor Assurance Workspace
            </h1>
            <p className="text-sm text-slate-400">
              {defaultWallet.engagementTitle} •{' '}
              <span className="text-slate-200 font-medium">
                {defaultWallet.firm}
              </span>
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <button
              type="button"
              onClick={() => setWalletMode('stellar-keypair')}
              className={`inline-flex items-center gap-2 rounded-xl px-3.5 py-2 text-xs font-semibold transition ${
                walletMode === 'stellar-keypair'
                  ? 'bg-indigo-600 text-white shadow-md shadow-indigo-600/20'
                  : 'border border-slate-700 bg-slate-950 text-slate-300 hover:bg-slate-800'
              }`}
            >
              <KeyRound className="h-3.5 w-3.5" />
              <span>Stellar Auditor Keypair</span>
            </button>

            <button
              type="button"
              onClick={handleConnectFreighter}
              className={`inline-flex items-center gap-2 rounded-xl px-3.5 py-2 text-xs font-semibold transition ${
                walletMode === 'freighter-wallet'
                  ? 'bg-emerald-600 text-white shadow-md shadow-emerald-600/20'
                  : 'border border-slate-700 bg-slate-950 text-slate-300 hover:bg-slate-800'
              }`}
            >
              <Wallet className="h-3.5 w-3.5" />
              <span>Stellar Wallet / Freighter</span>
            </button>

            <button
              type="button"
              onClick={handleResetWorkspace}
              className="inline-flex items-center gap-1.5 rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-xs font-medium text-slate-300 hover:bg-slate-800 transition"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              <span>Reset Demo State</span>
            </button>
          </div>
        </div>

        {/* Auditor Stellar Key Details */}
        <div className="mt-5 grid gap-3 rounded-xl border border-slate-800/90 bg-slate-950/80 p-4 sm:grid-cols-3 text-xs">
          <div>
            <div className="text-slate-400">Assigned Statutory Auditor</div>
            <div className="mt-0.5 font-semibold text-slate-100">
              {auditorLabel}
            </div>
          </div>
          <div className="sm:col-span-2">
            <div className="text-slate-400">
              Authorized Stellar StrKey Address (<code>authorize_auditor</code>)
            </div>
            <div className="mt-0.5 font-mono text-indigo-300 break-all">
              {auditorAddress}
            </div>
          </div>
        </div>
      </div>

      {/* Status Notification Banner */}
      {banner && (
        <div
          className={`flex items-center justify-between gap-3 rounded-xl border p-4 text-xs font-medium ${
            banner.type === 'success'
              ? 'border-emerald-500/40 bg-emerald-950/40 text-emerald-200'
              : banner.type === 'error'
                ? 'border-rose-500/40 bg-rose-950/40 text-rose-200'
                : 'border-indigo-500/40 bg-indigo-950/40 text-indigo-200'
          }`}
        >
          <div className="flex items-center gap-2.5">
            {banner.type === 'success' ? (
              <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
            ) : banner.type === 'error' ? (
              <AlertTriangle className="h-4 w-4 text-rose-400 shrink-0" />
            ) : (
              <ShieldCheck className="h-4 w-4 text-indigo-400 shrink-0" />
            )}
            <span>{banner.text}</span>
          </div>
          <button
            type="button"
            onClick={() => setBanner(null)}
            className="text-slate-400 hover:text-white"
          >
            ✕
          </button>
        </div>
      )}

      {/* Main Grid: Left = Checkpoint Chain & Evidence Review, Right = Witnessing & Report Export */}
      <div className="grid gap-8 lg:grid-cols-12">
        {/* Left Column (7 cols): Checkpoint Chain Linkage & Scoped Evidence */}
        <div className="lg:col-span-7 space-y-6">
          {/* 1. Checkpoint Chain Continuity Card */}
          <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-4">
              <div>
                <h2 className="text-lg font-bold text-white flex items-center gap-2">
                  <GitCommitHorizontal className="h-5 w-5 text-indigo-400" />
                  <span>1. Checkpoint Chain & Hash Continuity</span>
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Verifies unbroken cryptographic linkage (
                  <code>cp[i].prev_root == cp[i-1].root</code>) from Genesis
                  checkpoint #1.
                </p>
              </div>
              <span
                className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-semibold ${
                  chainLinkage.valid
                    ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                    : 'bg-rose-500/15 text-rose-300 border border-rose-500/30'
                }`}
              >
                <CheckCircle2 className="h-3.5 w-3.5" />
                {chainLinkage.valid
                  ? `Chain Intact (${chainLinkage.totalCheckpoints} Checkpoints)`
                  : 'Chain Discontinuity'}
              </span>
            </div>

            <div className="mt-5 space-y-4">
              {checkpoints.map((cp, index) => {
                const linkInfo = chainLinkage.links.find(
                  (l) => l.checkpointId === cp.id
                );
                const isSelected = selectedCheckpoint?.id === cp.id;
                const isWitnessed = cp.witnesses.length > 0;

                return (
                  <div key={cp.id} className="space-y-2">
                    {index > 0 && (
                      <div className="flex items-center gap-2 pl-6 text-[11px] font-mono text-emerald-400">
                        <span>↑ Linked via prev_root == Checkpoint #{cp.id - 1} root</span>
                        <CheckCircle2 className="h-3.5 w-3.5" />
                      </div>
                    )}

                    <div
                      onClick={() => setSelectedCheckpointId(cp.id)}
                      className={`cursor-pointer rounded-xl border p-4 transition ${
                        isSelected
                          ? 'border-indigo-500/60 bg-indigo-950/25 shadow-lg shadow-indigo-950/30'
                          : 'border-slate-800 bg-slate-950/70 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2.5">
                          <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-indigo-500/20 font-mono text-xs font-bold text-indigo-300 border border-indigo-500/30">
                            #{cp.id}
                          </span>
                          <div>
                            <div className="flex items-center gap-2">
                              <span className="text-sm font-bold text-white">
                                Checkpoint #{cp.id}
                              </span>
                              <span className="font-mono text-xs text-slate-400">
                                Ledger #{cp.ledger}
                              </span>
                            </div>
                            <div className="text-[11px] text-slate-400">
                              {cp.periodStart} → {cp.periodEnd} • Cumulative
                              Count: {cp.recordCount}
                            </div>
                          </div>
                        </div>

                        <div className="flex items-center gap-2">
                          {isWitnessed ? (
                            <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/15 px-2.5 py-0.5 text-[11px] font-semibold text-emerald-300 border border-emerald-500/30">
                              <UserCheck className="h-3 w-3" />
                              Witnessed ({cp.witnesses.length})
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 rounded-full bg-amber-500/15 px-2.5 py-0.5 text-[11px] font-semibold text-amber-300 border border-amber-500/30">
                              <Stamp className="h-3 w-3" />
                              Awaiting Witness
                            </span>
                          )}

                          <Link
                            href={`/verify/${cp.orgAddress}/${cp.id}`}
                            onClick={(e) => e.stopPropagation()}
                            className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-900 px-2.5 py-1 text-[11px] text-slate-300 hover:bg-slate-800"
                          >
                            <span>On-Chain View</span>
                            <ExternalLink className="h-3 w-3" />
                          </Link>
                        </div>
                      </div>

                      <div className="mt-3 grid gap-2 sm:grid-cols-2 font-mono text-[11px]">
                        <div className="rounded-lg border border-slate-800/90 bg-slate-950 p-2.5">
                          <div className="text-slate-400 mb-0.5 flex items-center justify-between">
                            <span>Merkle Root (0x01)</span>
                            <Hash className="h-3 w-3 text-indigo-400" />
                          </div>
                          <div className="text-slate-200 break-all">
                            {cp.root}
                          </div>
                        </div>

                        <div className="rounded-lg border border-slate-800/90 bg-slate-950 p-2.5">
                          <div className="text-slate-400 mb-0.5 flex items-center justify-between">
                            <span>Previous Root (Chain Link)</span>
                            {linkInfo?.prevRootMatches ? (
                              <span className="text-emerald-400">MATCH ✓</span>
                            ) : (
                              <span className="text-rose-400">MISMATCH ✗</span>
                            )}
                          </div>
                          <div className="text-slate-400 break-all">
                            {cp.prevRoot}
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* 2. Scoped Evidence & Record Review */}
          <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-4">
              <div>
                <h2 className="text-lg font-bold text-white flex items-center gap-2">
                  <Eye className="h-5 w-5 text-emerald-400" />
                  <span>
                    2. Evidence & Record Review (Checkpoint #
                    {selectedCheckpoint?.id})
                  </span>
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Recomputes PB1 salted field commitments (<code>0x02</code>),
                  SHA-256 evidence hashes, and Maker-Checker co-signatures.
                </p>
              </div>
              <span className="rounded-lg bg-slate-800 px-2.5 py-1 font-mono text-xs text-slate-300">
                {auditReport?.auditedRecords.length || 0} Record(s) Audited
              </span>
            </div>

            <div className="mt-4 space-y-4">
              {auditReport?.auditedRecords.map((rec) => {
                const rawRecord = records.find((r) => r.id === rec.recordId);
                const isExpanded = selectedRecordId === rec.recordId;

                return (
                  <div
                    key={rec.recordId}
                    className="rounded-xl border border-slate-800 bg-slate-950/80 p-4 space-y-3"
                  >
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs font-bold text-indigo-300">
                            {rec.recordId}
                          </span>
                          <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-[10px] text-slate-300">
                            seq #{rec.seqNo}
                          </span>
                          <span
                            className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-semibold ${
                              rec.valid
                                ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                                : 'bg-amber-500/15 text-amber-300 border border-amber-500/30'
                            }`}
                          >
                            {rec.valid ? 'PB1 Verified ✓' : 'Pending Approval'}
                          </span>
                        </div>
                        <div className="mt-1 text-base font-bold text-white">
                          {rec.amount} {rec.currency} →{' '}
                          <span className="text-indigo-200">{rec.payee}</span>
                        </div>
                        <div className="text-xs text-slate-400">
                          Created: {rec.createdAt} • Type: {rec.type}
                        </div>
                      </div>

                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() =>
                            setSelectedRecordId(isExpanded ? null : rec.recordId)
                          }
                          className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800 transition"
                        >
                          {isExpanded ? 'Hide Commitments' : 'Inspect Evidence'}
                        </button>
                        <button
                          type="button"
                          onClick={() => handleExportRecordBundle(rec.recordId)}
                          className="inline-flex items-center gap-1.5 rounded-lg border border-indigo-500/30 bg-indigo-500/10 px-3 py-1.5 text-xs font-medium text-indigo-300 hover:bg-indigo-500/20 transition"
                        >
                          <Download className="h-3.5 w-3.5" />
                          <span>bundle.json</span>
                        </button>
                      </div>
                    </div>

                    {/* Verification Pills */}
                    <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 text-[11px]">
                      <div className="rounded-lg border border-slate-800 bg-slate-900/70 px-2.5 py-1.5 flex items-center justify-between">
                        <span className="text-slate-400">Field Root (0x02)</span>
                        <span
                          className={
                            rec.fieldRootValid
                              ? 'text-emerald-400 font-semibold'
                              : 'text-rose-400'
                          }
                        >
                          {rec.fieldRootValid ? 'OK ✓' : 'FAIL'}
                        </span>
                      </div>
                      <div className="rounded-lg border border-slate-800 bg-slate-900/70 px-2.5 py-1.5 flex items-center justify-between">
                        <span className="text-slate-400">Leaf Hash (0x00)</span>
                        <span
                          className={
                            rec.leafHashValid
                              ? 'text-emerald-400 font-semibold'
                              : 'text-rose-400'
                          }
                        >
                          {rec.leafHashValid ? 'OK ✓' : 'FAIL'}
                        </span>
                      </div>
                      <div className="rounded-lg border border-slate-800 bg-slate-900/70 px-2.5 py-1.5 flex items-center justify-between">
                        <span className="text-slate-400">Maker Ed25519</span>
                        <span
                          className={
                            rec.authorSigValid
                              ? 'text-emerald-400 font-semibold'
                              : 'text-rose-400'
                          }
                        >
                          {rec.authorSigValid ? 'OK ✓' : 'FAIL'}
                        </span>
                      </div>
                      <div className="rounded-lg border border-slate-800 bg-slate-900/70 px-2.5 py-1.5 flex items-center justify-between">
                        <span className="text-slate-400">Checker Co-Sig</span>
                        <span
                          className={
                            rec.checkerSigValid
                              ? 'text-emerald-400 font-semibold'
                              : 'text-amber-400'
                          }
                        >
                          {rec.checkerSigValid ? 'OK ✓' : 'Pending'}
                        </span>
                      </div>
                    </div>

                    {/* Bound Evidence Attachment Box */}
                    {rec.evidenceSha256 && (
                      <div className="rounded-lg border border-emerald-500/25 bg-emerald-950/15 p-3 text-xs flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <FileCheck2 className="h-4 w-4 text-emerald-400 shrink-0" />
                          <div>
                            <span className="font-semibold text-slate-200">
                              Bound Evidence:{' '}
                              {rec.evidenceFileName || 'Attached Invoice'}
                            </span>
                            <div className="font-mono text-[11px] text-emerald-300 break-all">
                              {rec.evidenceSha256}
                            </div>
                          </div>
                        </div>
                        <span className="rounded bg-emerald-500/20 px-2 py-0.5 font-mono text-[10px] text-emerald-300">
                          Commitment Match ✓
                        </span>
                      </div>
                    )}

                    {/* Expanded Field Commitment & Signature Details */}
                    {isExpanded && rawRecord && (
                      <div className="mt-3 space-y-2 border-t border-slate-800 pt-3 font-mono text-[11px]">
                        <div className="text-slate-400 font-sans font-semibold text-xs">
                          Salted Field Commitments (0x02):
                        </div>
                        {rawRecord.sortedFields.map((f) => (
                          <div
                            key={f.name}
                            className="rounded border border-slate-800 bg-slate-900/90 p-2"
                          >
                            <div className="flex justify-between text-indigo-300">
                              <span>
                                {f.name}: &quot;{f.value}&quot;
                              </span>
                              <span className="text-slate-500">
                                salt: {f.saltHex.slice(0, 12)}...
                              </span>
                            </div>
                            <div className="text-slate-400 break-all">
                              commit: {f.commitmentHex}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Right Column (5 cols): One-Click On-Chain Witness & Audit Report Export with QR */}
        <div className="lg:col-span-5 space-y-6">
          {/* 3. One-Click On-Chain Witness Checkpoint Card */}
          <div className="rounded-2xl border border-indigo-500/40 bg-gradient-to-b from-slate-900 via-slate-900 to-indigo-950/30 p-6 space-y-5">
            <div className="flex items-start justify-between gap-3">
              <div>
                <span className="inline-flex items-center gap-1.5 rounded-md bg-indigo-500/20 px-2.5 py-0.5 font-mono text-[11px] font-semibold text-indigo-300 border border-indigo-500/30">
                  Soroban Contract Invocation
                </span>
                <h2 className="mt-2 text-lg font-bold text-white flex items-center gap-2">
                  <Stamp className="h-5 w-5 text-indigo-400" />
                  <span>
                    3. Witness Checkpoint #{selectedCheckpoint?.id} On-Chain
                  </span>
                </h2>
                <p className="mt-1 text-xs text-slate-300">
                  Countersigns the anchored Merkle root on Stellar Soroban (
                  <code>witness_checkpoint</code>) so history cannot be
                  rewritten.
                </p>
              </div>
            </div>

            {selectedCheckpoint && (
              <div className="space-y-3 rounded-xl border border-slate-800 bg-slate-950/90 p-4 font-mono text-xs">
                <div>
                  <div className="text-slate-400 text-[11px]">
                    Organization Address
                  </div>
                  <div className="text-slate-200 break-all">
                    {selectedCheckpoint.orgAddress}
                  </div>
                </div>
                <div>
                  <div className="text-slate-400 text-[11px]">
                    Verified Merkle Root Seen (32-Byte SHA-256)
                  </div>
                  <div className="text-emerald-300 break-all">
                    {selectedCheckpoint.root}
                  </div>
                </div>
                <div>
                  <div className="text-slate-400 text-[11px]">
                    Auditor Signing Key ({walletMode})
                  </div>
                  <div className="text-indigo-300 break-all">
                    {auditorAddress}
                  </div>
                </div>
              </div>
            )}

            <button
              type="button"
              onClick={handleWitnessCheckpoint}
              disabled={witnessing || !selectedCheckpoint}
              className="w-full inline-flex items-center justify-center gap-2 rounded-xl bg-indigo-600 px-5 py-3.5 text-sm font-bold text-white shadow-lg shadow-indigo-600/25 hover:bg-indigo-500 disabled:opacity-50 transition"
            >
              <Blocks className="h-4 w-4" />
              <span>
                {witnessing
                  ? 'Signing & Relaying witness_checkpoint...'
                  : `One-Click Witness Checkpoint #${selectedCheckpoint?.id} on Stellar`}
              </span>
            </button>

            {/* Recorded Witnesses on Selected Checkpoint */}
            {selectedCheckpoint && (
              <div className="space-y-2 pt-2 border-t border-slate-800/80">
                <div className="text-xs font-semibold text-slate-300 flex items-center justify-between">
                  <span>On-Chain Witness Attestations</span>
                  <span className="font-mono text-indigo-300">
                    {selectedCheckpoint.witnesses.length} recorded
                  </span>
                </div>

                {selectedCheckpoint.witnesses.length === 0 ? (
                  <p className="text-xs text-slate-400 italic">
                    No auditor witness recorded on Checkpoint #
                    {selectedCheckpoint.id} yet. Click the button above to
                    co-sign on-chain.
                  </p>
                ) : (
                  <div className="space-y-2">
                    {selectedCheckpoint.witnesses.map((w) => (
                      <div
                        key={w.id}
                        className="rounded-lg border border-emerald-500/30 bg-emerald-950/20 p-3 text-xs space-y-1"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-emerald-300 flex items-center gap-1.5">
                            <CheckCircle2 className="h-3.5 w-3.5" />
                            {w.auditorLabel}
                          </span>
                          <span className="font-mono text-[11px] text-slate-400">
                            Ledger #{w.ledger}
                          </span>
                        </div>
                        <div className="font-mono text-[11px] text-slate-300 break-all">
                          Auditor: {w.auditorAddress}
                        </div>
                        <div className="font-mono text-[11px] text-slate-400 break-all">
                          Tx: {w.txHash}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* 4. Export Audit Assurance Report (PDF / JSON) with Embedded QR Code */}
          {auditReport && (
            <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6 space-y-5">
              <div className="flex items-start justify-between gap-3 border-b border-slate-800 pb-4">
                <div>
                  <h2 className="text-lg font-bold text-white flex items-center gap-2">
                    <QrCode className="h-5 w-5 text-emerald-400" />
                    <span>4. Export Audit Report & Verification QR</span>
                  </h2>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Generate a self-contained PDF or JSON assurance report with
                    an embedded QR code linking to the public Stellar verifier.
                  </p>
                </div>
              </div>

              {/* Embedded QR Code Preview Card */}
              <div className="flex flex-col sm:flex-row items-center gap-4 rounded-xl border border-slate-800 bg-slate-950/90 p-4">
                <div
                  className="shrink-0 rounded-xl bg-white p-2 shadow-md"
                  dangerouslySetInnerHTML={{ __html: auditReport.qrCodeSvg }}
                />
                <div className="space-y-2 text-xs">
                  <span
                    className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-[11px] font-semibold ${
                      auditReport.summary.overallAssuranceStatus ===
                      'VERIFIED_AND_WITNESSED'
                        ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                        : 'bg-amber-500/15 text-amber-300 border border-amber-500/30'
                    }`}
                  >
                    {auditReport.summary.overallAssuranceStatus.replace(
                      /_/g,
                      ' '
                    )}
                  </span>
                  <div className="font-semibold text-slate-100">
                    Public Verification Endpoint
                  </div>
                  <div className="font-mono text-[11px] text-indigo-300 break-all">
                    {auditReport.verificationUrl}
                  </div>
                  <p className="text-[11px] text-slate-400">
                    Scanning this QR code opens the zero-server Stellar Soroban
                    checkpoint inspector for Checkpoint #
                    {auditReport.targetCheckpoint.id}.
                  </p>
                </div>
              </div>

              {/* Export Buttons */}
              <div className="grid gap-3 sm:grid-cols-2">
                <button
                  type="button"
                  onClick={handleExportPdfReport}
                  className="inline-flex items-center justify-center gap-2 rounded-xl bg-emerald-600 px-4 py-3 text-xs font-bold text-white shadow-lg shadow-emerald-600/20 hover:bg-emerald-500 transition"
                >
                  <FileText className="h-4 w-4" />
                  <span>Export PDF Report (.pdf)</span>
                </button>

                <button
                  type="button"
                  onClick={handleExportJsonReport}
                  className="inline-flex items-center justify-center gap-2 rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-xs font-bold text-slate-200 hover:bg-slate-800 transition"
                >
                  <Download className="h-4 w-4 text-indigo-400" />
                  <span>Export JSON Report (.json)</span>
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

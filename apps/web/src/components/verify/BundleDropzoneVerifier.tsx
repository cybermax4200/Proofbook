'use client';

import React, { useState, useCallback } from 'react';
import {
  Upload,
  CheckCircle2,
  XCircle,
  ShieldCheck,
  Sparkles,
  FileJson,
  Bug,
  Layers,
  KeyRound,
  Cpu,
} from 'lucide-react';
import {
  BrowserVerificationReport,
  PB1ProofBundle,
  SAMPLE_TESTNET_BUNDLE,
  verifyBundleWithStellarInBrowser,
} from '@/lib/browser-verifier';

interface BundleDropzoneVerifierProps {
  expectedCheckpointRoot?: string;
  initialAutoLoadSample?: boolean;
}

export function BundleDropzoneVerifier({
  expectedCheckpointRoot,
  initialAutoLoadSample = true,
}: BundleDropzoneVerifierProps) {
  const [bundleText, setBundleText] = useState<string>(() =>
    initialAutoLoadSample ? JSON.stringify(SAMPLE_TESTNET_BUNDLE, null, 2) : ''
  );
  const [fileName, setFileName] = useState<string>(
    initialAutoLoadSample ? 'sample-bundle.json (Testnet Vector)' : ''
  );
  const [isDragging, setIsDragging] = useState(false);
  const [isVerifying, setIsVerifying] = useState(false);
  const [skipBlockchain, setSkipBlockchain] = useState(false);
  const [report, setReport] = useState<BrowserVerificationReport | null>(null);
  const [parseError, setParseError] = useState<string | null>(null);

  const runVerification = useCallback(
    async (rawJson: string, offlineMode = skipBlockchain) => {
      setParseError(null);
      setIsVerifying(true);
      try {
        const parsed: PB1ProofBundle = JSON.parse(rawJson);
        const res = await verifyBundleWithStellarInBrowser(parsed, {
          skipBlockchain: offlineMode,
        });

        // If scoped to an on-chain checkpoint page, also check against expectedCheckpointRoot
        if (
          expectedCheckpointRoot &&
          res.expectedRoot.toLowerCase() !== expectedCheckpointRoot.toLowerCase()
        ) {
          const msg = `Bundle expected_root (${res.expectedRoot}) does not match inspected checkpoint root (${expectedCheckpointRoot})`;
          res.valid = false;
          res.errors.push(msg);
          res.steps.push({
            name: 'Inspected Checkpoint Root Match',
            passed: false,
            message: msg,
          });
        }

        setReport(res);
      } catch (err: any) {
        setReport(null);
        setParseError(err.message || 'Invalid JSON bundle format');
      } finally {
        setIsVerifying(false);
      }
    },
    [expectedCheckpointRoot, skipBlockchain]
  );

  // Auto-verify initial sample bundle on mount
  React.useEffect(() => {
    if (initialAutoLoadSample && bundleText) {
      runVerification(bundleText, skipBlockchain);
    }
  }, []);

  const handleFileBuffer = async (file: File) => {
    const text = await file.text();
    setFileName(file.name);
    setBundleText(text);
    await runVerification(text, skipBlockchain);
  };

  const handleDrop = async (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      await handleFileBuffer(file);
    }
  };

  const handleFileInput = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      await handleFileBuffer(file);
    }
  };

  const handleLoadSample = async () => {
    const text = JSON.stringify(SAMPLE_TESTNET_BUNDLE, null, 2);
    setFileName('sample-bundle.json (Testnet Vector)');
    setBundleText(text);
    await runVerification(text, skipBlockchain);
  };

  const handleTamperSimulation = async () => {
    try {
      const parsed: PB1ProofBundle = JSON.parse(
        bundleText || JSON.stringify(SAMPLE_TESTNET_BUNDLE)
      );
      // Tamper with amount field without updating salt/signature to demonstrate tamper detection
      if (parsed.record?.disclosed_fields) {
        parsed.record.disclosed_fields.amount = '999999.00';
      }
      const tamperedText = JSON.stringify(parsed, null, 2);
      setFileName('tampered-bundle.json (Adversarial Bit-Flip)');
      setBundleText(tamperedText);
      await runVerification(tamperedText, skipBlockchain);
    } catch {
      // Ignore if invalid JSON
    }
  };

  return (
    <div className="space-y-6">
      {/* Drag-and-Drop Zone */}
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setIsDragging(true);
        }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={handleDrop}
        className={`relative rounded-2xl border-2 border-dashed p-6 transition ${
          isDragging
            ? 'border-indigo-400 bg-indigo-500/10'
            : 'border-slate-700 bg-slate-900/60 hover:border-slate-600'
        }`}
      >
        <div className="flex flex-col items-center justify-center text-center">
          <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-xl bg-indigo-500/15 text-indigo-400 border border-indigo-500/30">
            <Upload className="h-6 w-6" />
          </div>
          <h3 className="text-base font-bold text-white">
            Drag & Drop Proof Bundle (<code className="text-indigo-300">bundle.json</code>)
          </h3>
          <p className="mt-1 max-w-xl text-xs text-slate-400">
            100% browser-executed verification: recomputes PB1 salted field commitments (
            <code>0x02</code>), leaf hash (<code>0x00</code>), Merkle path (
            <code>0x01</code>), Ed25519 signatures, and Stellar RPC checkpoint root.
          </p>

          <div className="mt-4 flex flex-wrap items-center justify-center gap-3">
            <label className="inline-flex cursor-pointer items-center gap-2 rounded-xl bg-indigo-600 px-4 py-2 text-xs font-semibold text-white shadow hover:bg-indigo-500 transition">
              <FileJson className="h-4 w-4" />
              <span>Choose Bundle File</span>
              <input
                type="file"
                accept=".json,application/json"
                onChange={handleFileInput}
                className="hidden"
              />
            </label>

            <button
              type="button"
              onClick={handleLoadSample}
              className="inline-flex items-center gap-1.5 rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-3.5 py-2 text-xs font-semibold text-emerald-300 hover:bg-emerald-500/20 transition"
            >
              <Sparkles className="h-3.5 w-3.5" />
              <span>Load Valid Testnet Bundle</span>
            </button>

            <button
              type="button"
              onClick={handleTamperSimulation}
              className="inline-flex items-center gap-1.5 rounded-xl border border-rose-500/30 bg-rose-500/10 px-3.5 py-2 text-xs font-semibold text-rose-300 hover:bg-rose-500/20 transition"
            >
              <Bug className="h-3.5 w-3.5" />
              <span>Simulate Tampered Amount</span>
            </button>
          </div>
        </div>
      </div>

      {/* Verification Report & JSON Inspector Grid */}
      <div className="grid gap-6 lg:grid-cols-12">
        {/* Left: Raw Bundle JSON Editor */}
        <div className="lg:col-span-5 flex flex-col rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
          <div className="mb-3 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <FileJson className="h-4 w-4 text-indigo-400" />
              <span className="text-xs font-bold text-slate-200">
                {fileName || 'Bundle JSON Payload'}
              </span>
            </div>

            <label className="flex items-center gap-1.5 text-[11px] text-slate-400 cursor-pointer">
              <input
                type="checkbox"
                checked={skipBlockchain}
                onChange={(e) => {
                  const val = e.target.checked;
                  setSkipBlockchain(val);
                  if (bundleText) {
                    runVerification(bundleText, val);
                  }
                }}
                className="rounded border-slate-700 text-indigo-600"
              />
              <span>Offline Mode (Skip RPC)</span>
            </label>
          </div>

          <textarea
            value={bundleText}
            onChange={(e) => setBundleText(e.target.value)}
            rows={18}
            spellCheck={false}
            className="w-full flex-1 rounded-xl border border-slate-800 bg-slate-950 p-3 font-mono text-[11px] leading-relaxed text-slate-200 focus:border-indigo-500 focus:outline-none"
            placeholder="Paste PB1 bundle.json here..."
          />

          <button
            type="button"
            disabled={isVerifying}
            onClick={() => runVerification(bundleText, skipBlockchain)}
            className="mt-3 flex w-full items-center justify-center gap-2 rounded-xl bg-indigo-600 px-4 py-2.5 text-xs font-semibold text-white hover:bg-indigo-500 disabled:opacity-50 transition"
          >
            <Cpu className="h-4 w-4" />
            <span>
              {isVerifying
                ? 'Verifying Cryptographic Proofs...'
                : 'Re-Run Browser Verification'}
            </span>
          </button>
        </div>

        {/* Right: Cryptographic Verification Report */}
        <div className="lg:col-span-7 space-y-5">
          {parseError && (
            <div className="rounded-2xl border border-rose-500/40 bg-rose-950/30 p-5 text-xs text-rose-200">
              <div className="font-bold text-sm mb-1 flex items-center gap-2">
                <XCircle className="h-5 w-5 text-rose-400" />
                <span>Bundle Parse Error</span>
              </div>
              <p className="font-mono">{parseError}</p>
            </div>
          )}

          {report && (
            <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6 space-y-5">
              {/* Verdict Header */}
              <div
                className={`flex flex-wrap items-center justify-between gap-4 rounded-xl border p-4 ${
                  report.valid
                    ? 'border-emerald-500/40 bg-emerald-500/10'
                    : 'border-rose-500/40 bg-rose-500/10'
                }`}
              >
                <div className="flex items-center gap-3">
                  {report.valid ? (
                    <CheckCircle2 className="h-8 w-8 text-emerald-400 shrink-0" />
                  ) : (
                    <XCircle className="h-8 w-8 text-rose-400 shrink-0" />
                  )}
                  <div>
                    <div className="text-base font-extrabold tracking-tight text-white">
                      {report.valid
                        ? 'RESULT: VERIFIED ✓ (Tamper-Evident Proof Valid)'
                        : 'RESULT: VERIFICATION FAILED ✗ (Tampering or Mismatch)'}
                    </div>
                    <div className="font-mono text-xs text-slate-300">
                      Record ID: {report.recordId} • Format: {report.version}
                    </div>
                  </div>
                </div>

                <span className="rounded-lg bg-slate-950/80 px-3 py-1.5 font-mono text-[11px] text-slate-300 border border-slate-800">
                  Zero-Server Browser Engine
                </span>
              </div>

              {/* Step-by-Step Verification Checklist */}
              <div>
                <h4 className="mb-2.5 text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                  <ShieldCheck className="h-4 w-4 text-indigo-400" />
                  Verification Pipeline Steps
                </h4>
                <div className="space-y-2">
                  {report.steps.map((step, idx) => (
                    <div
                      key={idx}
                      className={`flex items-start justify-between gap-3 rounded-lg border px-3.5 py-2.5 text-xs ${
                        step.passed
                          ? 'border-slate-800 bg-slate-950/80 text-slate-200'
                          : 'border-rose-500/40 bg-rose-950/20 text-rose-200'
                      }`}
                    >
                      <div className="flex items-start gap-2.5">
                        {step.passed ? (
                          <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
                        ) : (
                          <XCircle className="h-4 w-4 text-rose-400 shrink-0 mt-0.5" />
                        )}
                        <div>
                          <div className="font-semibold">{step.name}</div>
                          <div className="text-[11px] text-slate-400 font-mono">
                            {step.message}
                          </div>
                        </div>
                      </div>
                      <span
                        className={`rounded px-2 py-0.5 font-mono text-[10px] font-bold ${
                          step.passed
                            ? 'bg-emerald-500/15 text-emerald-300'
                            : 'bg-rose-500/20 text-rose-300'
                        }`}
                      >
                        {step.passed ? 'OK' : 'FAIL'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Disclosed Field Commitments Breakdown */}
              {report.fieldDetails.length > 0 && (
                <div>
                  <h4 className="mb-2.5 text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                    <Layers className="h-4 w-4 text-indigo-400" />
                    Recomputed Salted Field Commitments (0x02)
                  </h4>
                  <div className="grid gap-2 sm:grid-cols-2">
                    {report.fieldDetails.map((fd) => (
                      <div
                        key={fd.name}
                        className={`rounded-lg border p-3 font-mono text-[11px] ${
                          fd.passed
                            ? 'border-slate-800 bg-slate-950/70'
                            : 'border-rose-500/40 bg-rose-950/20'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-indigo-300">
                            {fd.name}: {fd.value}
                          </span>
                          <span
                            className={
                              fd.passed ? 'text-emerald-400' : 'text-rose-400'
                            }
                          >
                            {fd.passed ? '✓ Valid' : '✗ Invalid'}
                          </span>
                        </div>
                        <div className="mt-1 truncate text-[10px] text-slate-500">
                          salt: {fd.saltHex}
                        </div>
                        <div className="truncate text-[10px] text-slate-300">
                          commit: {fd.commitmentHex}
                        </div>
                        {fd.proofSteps > 0 && (
                          <div className="mt-0.5 text-[10px] text-emerald-400/80">
                            Selective proof: {fd.proofSteps} Merkle step(s)
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Cryptographic Digests Summary */}
              <div className="rounded-xl border border-slate-800 bg-slate-950/90 p-3.5 font-mono text-[11px] space-y-1.5">
                <div className="flex justify-between gap-2">
                  <span className="text-slate-400">Recomputed field_root:</span>
                  <span className="truncate text-indigo-300">
                    {report.recomputedFieldRoot || '—'}
                  </span>
                </div>
                <div className="flex justify-between gap-2">
                  <span className="text-slate-400">Recomputed leaf (0x00):</span>
                  <span className="truncate text-amber-300">
                    {report.recomputedLeaf || '—'}
                  </span>
                </div>
                <div className="flex justify-between gap-2">
                  <span className="text-slate-400">Recomputed Merkle root:</span>
                  <span className="truncate text-emerald-300">
                    {report.recomputedMerkleRoot || '—'}
                  </span>
                </div>
                <div className="flex justify-between gap-2">
                  <span className="text-slate-400">Expected anchor root:</span>
                  <span className="truncate text-slate-200">
                    {report.expectedRoot || '—'}
                  </span>
                </div>
                <div className="flex justify-between gap-2 pt-1 border-t border-slate-800">
                  <span className="text-slate-400 flex items-center gap-1">
                    <KeyRound className="h-3 w-3 text-indigo-400" />
                    Ed25519 Signatures:
                  </span>
                  <span className="text-slate-200">
                    Author: {report.authorVerified ? 'OK' : 'FAIL'} • Checkers:{' '}
                    {report.approverCountVerified}/{report.approverTotal}
                  </span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

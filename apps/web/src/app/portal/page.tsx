'use client';

import React, { useState, useEffect, useMemo } from 'react';
import Link from 'next/link';
import {
  FilePlus2,
  CheckCircle2,
  XCircle,
  Clock,
  KeyRound,
  RefreshCw,
  Upload,
  FileText,
  Download,
  ShieldCheck,
  AlertTriangle,
  Lock,
  Sparkles,
  Check,
  Eye,
  ExternalLink,
} from 'lucide-react';
import {
  computeEvidenceHashInBrowser,
  computeFieldRootInBrowser,
  formatCanonicalDecimal,
  generateFieldSalts,
} from '@/lib/crypto-client';
import {
  loadKeyProfiles,
  PortalRole,
  resetDefaultKeyProfiles,
  RoleKeyProfile,
  rotateRoleKeypair,
} from '@/lib/key-store';
import {
  approveAndCoSignRecord,
  buildExportProofBundle,
  createSignedPortalRecord,
  DEFAULT_CONTRACT_ID,
  DEFAULT_ORG_NAME,
  DEFAULT_ORG_STELLAR,
  loadPortalRecords,
  PortalRecord,
  rejectPendingRecord,
  resetPortalRecords,
  savePortalRecords,
} from '@/lib/portal-store';

export default function OrganizationPortalPage() {
  const [activeRole, setActiveRole] = useState<PortalRole>('maker');
  const [profiles, setProfiles] = useState<Record<PortalRole, RoleKeyProfile>>(() =>
    loadKeyProfiles()
  );
  const [records, setRecords] = useState<PortalRecord[]>([]);
  const [statusFilter, setStatusFilter] = useState<'all' | 'pending' | 'approved' | 'rejected'>(
    'all'
  );
  const [expandedRecordId, setExpandedRecordId] = useState<string | null>(null);
  const [selectedDisclosedFields, setSelectedDisclosedFields] = useState<
    Record<string, Record<string, boolean>>
  >({});

  // Form state
  const [amount, setAmount] = useState('1250.00');
  const [currency, setCurrency] = useState('USD');
  const [payee, setPayee] = useState('Acme Supplies Ltd');
  const [memo, setMemo] = useState('INV-2026-Q4-019');
  const [evidenceFile, setEvidenceFile] = useState<{
    fileName: string;
    mimeType: string;
    sizeBytes: number;
    bytes: Uint8Array;
    sha256: string;
  } | null>(null);
  const [previewSalts, setPreviewSalts] = useState<Record<string, string>>({});

  // Reject modal / inline state
  const [rejectingId, setRejectingId] = useState<string | null>(null);
  const [rejectionReason, setRejectionReason] = useState('');

  // Status banner
  const [banner, setBanner] = useState<{
    type: 'success' | 'error' | 'info';
    message: string;
  } | null>(null);

  useEffect(() => {
    setProfiles(loadKeyProfiles());
    const loaded = loadPortalRecords();
    setRecords(loaded);
    if (loaded.length > 0) {
      setExpandedRecordId(loaded[0].id);
    }
  }, []);

  // Build live preview fields for the Record Entry Form
  const draftFields = useMemo(() => {
    let formattedAmount = '0.00';
    try {
      formattedAmount = formatCanonicalDecimal(amount || '0', 2);
    } catch {
      formattedAmount = amount || '0.00';
    }
    const f: Record<string, string> = {
      amount: formattedAmount,
      currency: (currency || 'USD').trim().toUpperCase(),
      payee: (payee || 'Unnamed Payee').trim(),
    };
    if (memo.trim()) {
      f.memo = memo.trim();
    }
    if (evidenceFile) {
      f.evidence_hash = evidenceFile.sha256;
    }
    return f;
  }, [amount, currency, payee, memo, evidenceFile]);

  // Ensure every draft field has a 32-byte salt in preview
  const liveFieldBundle = useMemo(() => {
    try {
      const mergedSalts: Record<string, string> = {};
      for (const k of Object.keys(draftFields)) {
        if (previewSalts[k] && previewSalts[k].length === 64) {
          mergedSalts[k] = previewSalts[k];
        }
      }
      return computeFieldRootInBrowser(draftFields, mergedSalts);
    } catch {
      return null;
    }
  }, [draftFields, previewSalts]);

  const handleRegenerateSalts = () => {
    const fresh = generateFieldSalts(draftFields);
    setPreviewSalts(fresh);
    setBanner({
      type: 'info',
      message: 'Regenerated fresh 32-byte CSPRNG salts for all record fields in-browser.',
    });
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const arrayBuffer = await file.arrayBuffer();
    const bytes = new Uint8Array(arrayBuffer);
    const sha256 = computeEvidenceHashInBrowser(bytes);
    setEvidenceFile({
      fileName: file.name,
      mimeType: file.type || 'application/octet-stream',
      sizeBytes: file.size,
      bytes,
      sha256,
    });
    setBanner({
      type: 'info',
      message: `Computed PB1 evidence commitment (${sha256.slice(0, 24)}...) in-browser.`,
    });
  };

  const handleAttachSampleInvoice = () => {
    const sampleText = `INVOICE #INV-${Date.now().toString().slice(-5)}\nPayee: ${payee}\nAmount: ${amount} ${currency}\nTimestamp: ${new Date().toISOString()}`;
    const bytes = new TextEncoder().encode(sampleText);
    const sha256 = computeEvidenceHashInBrowser(bytes);
    setEvidenceFile({
      fileName: `Invoice-${payee.replace(/\s+/g, '-')}.txt`,
      mimeType: 'text/plain',
      sizeBytes: bytes.length,
      bytes,
      sha256,
    });
  };

  const handleCreateRecord = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const created = await createSignedPortalRecord(
        {
          amount,
          currency,
          payee,
          memo,
          customSalts: liveFieldBundle?.salts,
          evidenceFile: evidenceFile || undefined,
          makerProfile: profiles.maker,
        },
        records
      );

      const updated = [created, ...records];
      setRecords(updated);
      savePortalRecords(updated);
      setExpandedRecordId(created.id);
      setPreviewSalts({});
      setBanner({
        type: 'success',
        message: `Record ${created.id} committed & signed with Maker Ed25519 key (${profiles.maker.publicKeyHex.slice(0, 12)}...). Ready for Checker co-signing.`,
      });
    } catch (err: any) {
      setBanner({
        type: 'error',
        message: err.message || 'Failed to create signed record',
      });
    }
  };

  const handleOneClickCoSign = (record: PortalRecord) => {
    try {
      // If the user is currently viewing as Maker with the same key, enforce or use Checker profile
      const signerProfile =
        activeRole === 'maker' &&
        record.authorPublicKey.toLowerCase() === profiles.maker.publicKeyHex.toLowerCase()
          ? profiles.checker
          : profiles[activeRole];

      const approved = approveAndCoSignRecord(record, signerProfile);
      const updated = records.map((r) => (r.id === record.id ? approved : r));
      setRecords(updated);
      savePortalRecords(updated);
      setActiveRole('checker');
      setBanner({
        type: 'success',
        message: `Co-signed record ${record.id} over leaf ${record.leafHash.slice(0, 14)}... with Checker Ed25519 key (${signerProfile.publicKeyHex.slice(0, 12)}...). Status: APPROVED.`,
      });
    } catch (err: any) {
      setBanner({
        type: 'error',
        message: err.message || 'Co-signing verification failed',
      });
    }
  };

  const handleRejectRecord = (record: PortalRecord) => {
    try {
      const rejected = rejectPendingRecord(record, rejectionReason);
      const updated = records.map((r) => (r.id === record.id ? rejected : r));
      setRecords(updated);
      savePortalRecords(updated);
      setRejectingId(null);
      setRejectionReason('');
      setBanner({
        type: 'info',
        message: `Record ${record.id} rejected and logged to audit trail.`,
      });
    } catch (err: any) {
      setBanner({
        type: 'error',
        message: err.message || 'Rejection requires a valid audit reason',
      });
    }
  };

  const handleExportBundle = (record: PortalRecord) => {
    const fieldMap = selectedDisclosedFields[record.id];
    const disclosedList = fieldMap
      ? Object.keys(fieldMap).filter((k) => fieldMap[k])
      : Object.keys(record.fields);

    const bundle = buildExportProofBundle(record, disclosedList);
    const jsonString = JSON.stringify(bundle, null, 2);
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `proofbook-bundle-${record.id}.json`;
    a.click();
    URL.revokeObjectURL(url);

    setBanner({
      type: 'success',
      message: `Exported PB1 Proof Bundle (${disclosedList.length}/${Object.keys(record.fields).length} fields disclosed) for record ${record.id}.`,
    });
  };

  const handleRotateKey = (role: PortalRole) => {
    const next = rotateRoleKeypair(role);
    setProfiles(next);
    setBanner({
      type: 'info',
      message: `Generated new client-side Ed25519 keypair for ${next[role].label}.`,
    });
  };

  const handleResetDemo = () => {
    const defaultProfiles = resetDefaultKeyProfiles();
    const defaultRecords = resetPortalRecords();
    setProfiles(defaultProfiles);
    setRecords(defaultRecords);
    setBanner({
      type: 'info',
      message: 'Reset Organization Portal keys and records to default Testnet demo state.',
    });
  };

  const toggleFieldDisclosure = (record: PortalRecord, fieldName: string) => {
    const current =
      selectedDisclosedFields[record.id] ||
      Object.fromEntries(Object.keys(record.fields).map((k) => [k, true]));
    const nextMap = {
      ...current,
      [fieldName]: !current[fieldName],
    };
    // Ensure at least 1 field stays disclosed
    if (Object.values(nextMap).every((v) => !v)) {
      return;
    }
    setSelectedDisclosedFields({
      ...selectedDisclosedFields,
      [record.id]: nextMap,
    });
  };

  const filteredRecords = records.filter((r) =>
    statusFilter === 'all' ? true : r.status === statusFilter
  );

  const pendingCount = records.filter((r) => r.status === 'pending').length;
  const approvedCount = records.filter((r) => r.status === 'approved').length;

  const activeProfile = profiles[activeRole];

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
      {/* Organization Header & Client-Side Key Store Bar */}
      <div className="mb-8 flex flex-col justify-between gap-4 rounded-2xl border border-slate-800 bg-slate-900/60 p-6 lg:flex-row lg:items-center">
        <div>
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="text-2xl font-bold text-white">{DEFAULT_ORG_NAME}</h1>
            <span className="rounded-md border border-indigo-500/30 bg-indigo-500/10 px-2.5 py-0.5 font-mono text-xs text-indigo-300">
              {DEFAULT_ORG_STELLAR.slice(0, 8)}...{DEFAULT_ORG_STELLAR.slice(-6)}
            </span>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            Client-side PB1 Salted Commitments • Ed25519 Maker-Checker Co-Signing • Soroban Contract{' '}
            <span className="font-mono text-slate-300">
              {DEFAULT_CONTRACT_ID.slice(0, 10)}...
            </span>
          </p>
        </div>

        {/* Persona Switcher & Client Key Controls */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex rounded-xl border border-slate-800 bg-slate-950 p-1">
            {(['maker', 'checker'] as PortalRole[]).map((role) => (
              <button
                key={role}
                type="button"
                onClick={() => setActiveRole(role)}
                className={`flex items-center gap-2 rounded-lg px-3.5 py-2 text-xs font-semibold transition ${
                  activeRole === role
                    ? role === 'maker'
                      ? 'bg-indigo-600 text-white shadow'
                      : 'bg-emerald-600 text-white shadow'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <KeyRound className="h-3.5 w-3.5" />
                <span>{role === 'maker' ? 'Maker (Author)' : 'Checker (Approver)'}</span>
              </button>
            ))}
          </div>

          <button
            type="button"
            onClick={() => handleRotateKey(activeRole)}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-xs font-medium text-slate-300 hover:bg-slate-800 transition"
            title="Generate a fresh random Ed25519 keypair in-browser"
          >
            <RefreshCw className="h-3.5 w-3.5 text-indigo-400" />
            <span>Rotate Key</span>
          </button>

          <button
            type="button"
            onClick={handleResetDemo}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-xs font-medium text-slate-400 hover:text-slate-200 transition"
          >
            <span>Reset Demo</span>
          </button>
        </div>
      </div>

      {/* Active Signing Identity Card */}
      <div className="mb-6 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-800/90 bg-slate-950/80 px-4 py-3 text-xs">
        <div className="flex flex-wrap items-center gap-3">
          <span className="font-semibold text-slate-300">
            Active Client Ed25519 Key ({activeProfile.label}):
          </span>
          <code className="rounded bg-slate-900 px-2 py-1 font-mono text-indigo-300 border border-slate-800">
            ed25519:{activeProfile.publicKeyHex}
          </code>
        </div>
        <div className="flex items-center gap-2 text-slate-400">
          <Lock className="h-3.5 w-3.5 text-emerald-400" />
          <span>Private seed stays in browser memory / WebCrypto</span>
        </div>
      </div>

      {/* Notification Banner */}
      {banner && (
        <div
          className={`mb-6 flex items-center justify-between rounded-xl border px-4 py-3 text-xs font-medium ${
            banner.type === 'success'
              ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200'
              : banner.type === 'error'
                ? 'border-rose-500/40 bg-rose-500/10 text-rose-200'
                : 'border-indigo-500/40 bg-indigo-500/10 text-indigo-200'
          }`}
        >
          <div className="flex items-center gap-2">
            {banner.type === 'success' ? (
              <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
            ) : banner.type === 'error' ? (
              <AlertTriangle className="h-4 w-4 text-rose-400 shrink-0" />
            ) : (
              <Sparkles className="h-4 w-4 text-indigo-400 shrink-0" />
            )}
            <span>{banner.message}</span>
          </div>
          <button
            type="button"
            onClick={() => setBanner(null)}
            className="ml-4 text-slate-400 hover:text-white"
          >
            ✕
          </button>
        </div>
      )}

      {/* Main Two-Column Portal Layout */}
      <div className="grid gap-8 lg:grid-cols-12">
        {/* Left Column: Maker Record Entry Form + Live Client Crypto Preview */}
        <div className="lg:col-span-5 space-y-6">
          <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
            <div className="mb-5 flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-indigo-500/15 text-indigo-400 border border-indigo-500/30">
                  <FilePlus2 className="h-5 w-5" />
                </div>
                <div>
                  <h2 className="text-base font-bold text-white">
                    New Evidence Record
                  </h2>
                  <p className="text-xs text-slate-400">
                    Salted & signed client-side in Format PB1
                  </p>
                </div>
              </div>
              <span className="rounded-full bg-indigo-500/15 px-2.5 py-0.5 text-[11px] font-semibold text-indigo-300 border border-indigo-500/30">
                Maker Entry
              </span>
            </div>

            <form onSubmit={handleCreateRecord} className="space-y-4">
              <div className="grid grid-cols-3 gap-3">
                <div className="col-span-2">
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Amount
                  </label>
                  <input
                    type="text"
                    required
                    value={amount}
                    onChange={(e) => setAmount(e.target.value)}
                    placeholder="1250.00"
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3.5 py-2 text-sm font-mono text-white focus:border-indigo-500 focus:outline-none"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Currency
                  </label>
                  <select
                    value={currency}
                    onChange={(e) => setCurrency(e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm font-mono text-white focus:border-indigo-500 focus:outline-none"
                  >
                    <option value="USD">USD</option>
                    <option value="USDC">USDC</option>
                    <option value="EUR">EUR</option>
                    <option value="GBP">GBP</option>
                    <option value="XLM">XLM</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Payee / Counterparty
                </label>
                <input
                  type="text"
                  required
                  value={payee}
                  onChange={(e) => setPayee(e.target.value)}
                  placeholder="Acme Supplies Ltd"
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3.5 py-2 text-sm text-white focus:border-indigo-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Invoice / Reference Memo (Optional)
                </label>
                <input
                  type="text"
                  value={memo}
                  onChange={(e) => setMemo(e.target.value)}
                  placeholder="INV-2026-Q4-019"
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3.5 py-2 text-sm font-mono text-white focus:border-indigo-500 focus:outline-none"
                />
              </div>

              {/* Evidence Upload */}
              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="block text-xs font-medium text-slate-300">
                    Evidence Attachment (SHA-256 Bound)
                  </label>
                  <button
                    type="button"
                    onClick={handleAttachSampleInvoice}
                    className="text-[11px] font-medium text-indigo-400 hover:text-indigo-300"
                  >
                    + Generate Sample Invoice
                  </button>
                </div>

                <label className="flex cursor-pointer flex-col items-center justify-center rounded-xl border border-dashed border-slate-700 bg-slate-950/70 px-4 py-4 text-center hover:border-indigo-500/60 hover:bg-slate-900/60 transition">
                  <Upload className="h-5 w-5 text-slate-400 mb-1.5" />
                  <span className="text-xs font-medium text-slate-300">
                    {evidenceFile
                      ? evidenceFile.fileName
                      : 'Click to upload invoice / receipt (PDF, JSON, PNG, TXT)'}
                  </span>
                  <span className="mt-0.5 text-[11px] text-slate-500">
                    {evidenceFile
                      ? `${evidenceFile.sizeBytes} bytes • Bound into PB1 field_root`
                      : 'Hashed in-browser via SHA-256 before encryption'}
                  </span>
                  <input
                    type="file"
                    onChange={handleFileUpload}
                    className="hidden"
                  />
                </label>

                {evidenceFile && (
                  <div className="mt-2 flex items-center justify-between rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-1.5 font-mono text-[11px] text-emerald-300">
                    <span className="truncate">{evidenceFile.sha256}</span>
                    <button
                      type="button"
                      onClick={() => setEvidenceFile(null)}
                      className="ml-2 text-slate-400 hover:text-white"
                    >
                      ✕
                    </button>
                  </div>
                )}
              </div>

              {/* Live Client-Side Cryptographic Preview */}
              {liveFieldBundle && (
                <div className="rounded-xl border border-slate-800 bg-slate-950/90 p-3.5 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] font-semibold uppercase tracking-wider text-indigo-400 flex items-center gap-1.5">
                      <ShieldCheck className="h-3.5 w-3.5" />
                      In-Browser PB1 Commitment Preview
                    </span>
                    <button
                      type="button"
                      onClick={handleRegenerateSalts}
                      className="inline-flex items-center gap-1 rounded bg-slate-800 px-2 py-0.5 text-[10px] font-medium text-slate-300 hover:bg-slate-700"
                    >
                      <RefreshCw className="h-2.5 w-2.5" />
                      New Salts
                    </button>
                  </div>

                  <div className="space-y-1.5 max-h-40 overflow-y-auto pr-1">
                    {liveFieldBundle.sortedFields.map((f) => (
                      <div
                        key={f.name}
                        className="rounded border border-slate-800/90 bg-slate-900/70 p-2 font-mono text-[10px]"
                      >
                        <div className="flex justify-between text-slate-200">
                          <span className="font-semibold text-indigo-300">{f.name}:</span>
                          <span className="truncate max-w-[180px]">{f.value}</span>
                        </div>
                        <div className="text-slate-500 truncate">
                          salt: {f.saltHex.slice(0, 20)}...
                        </div>
                        <div className="text-emerald-400/90 truncate">
                          0x02 commit: {f.commitmentHex.slice(0, 24)}...
                        </div>
                      </div>
                    ))}
                  </div>

                  <div className="border-t border-slate-800 pt-2 font-mono text-[11px]">
                    <div className="flex items-center justify-between text-slate-400">
                      <span>Computed field_root:</span>
                      <span className="text-indigo-300">
                        {liveFieldBundle.rootHex.slice(0, 18)}...
                      </span>
                    </div>
                  </div>
                </div>
              )}

              <button
                type="submit"
                className="flex w-full items-center justify-center gap-2 rounded-xl bg-indigo-600 px-4 py-3 text-sm font-semibold text-white shadow-lg shadow-indigo-600/25 hover:bg-indigo-500 transition"
              >
                <KeyRound className="h-4 w-4" />
                <span>Commit Fields & Sign as Maker (Ed25519)</span>
              </button>
            </form>
          </div>
        </div>

        {/* Right Column: Maker-Checker Approval Queue & Record Inspector */}
        <div className="lg:col-span-7 space-y-6">
          <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
            <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center mb-6">
              <div>
                <h2 className="text-lg font-bold text-white flex items-center gap-2">
                  <span>Maker-Checker Approval Queue</span>
                  {pendingCount > 0 && (
                    <span className="rounded-full bg-amber-500/20 px-2.5 py-0.5 text-xs font-semibold text-amber-300 border border-amber-500/30">
                      {pendingCount} Pending
                    </span>
                  )}
                </h2>
                <p className="text-xs text-slate-400">
                  Checkers verify the PB1 leaf hash and append a second Ed25519 signature.
                </p>
              </div>

              {/* Filter Tabs */}
              <div className="flex rounded-lg border border-slate-800 bg-slate-950 p-1 text-xs">
                {(['all', 'pending', 'approved', 'rejected'] as const).map((tab) => (
                  <button
                    key={tab}
                    type="button"
                    onClick={() => setStatusFilter(tab)}
                    className={`rounded-md px-2.5 py-1 font-medium capitalize transition ${
                      statusFilter === tab
                        ? 'bg-slate-800 text-white'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {tab}
                  </button>
                ))}
              </div>
            </div>

            {/* Queue Items */}
            <div className="space-y-4">
              {filteredRecords.map((record) => {
                const isExpanded = expandedRecordId === record.id;
                const disclosedMap =
                  selectedDisclosedFields[record.id] ||
                  Object.fromEntries(Object.keys(record.fields).map((k) => [k, true]));

                return (
                  <div
                    key={record.id}
                    className={`rounded-xl border transition ${
                      record.status === 'pending'
                        ? 'border-amber-500/30 bg-slate-950/90'
                        : record.status === 'approved'
                          ? 'border-emerald-500/30 bg-slate-950/80'
                          : 'border-rose-500/30 bg-slate-950/60'
                    } p-5`}
                  >
                    {/* Top Row */}
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div className="space-y-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-mono text-xs font-bold text-slate-400">
                            #{record.seqNo}
                          </span>
                          <span className="font-mono text-sm font-semibold text-white">
                            {record.id}
                          </span>
                          {record.status === 'pending' && (
                            <span className="inline-flex items-center gap-1 rounded-full bg-amber-500/15 px-2.5 py-0.5 text-[11px] font-semibold text-amber-300 border border-amber-500/30">
                              <Clock className="h-3 w-3" />
                              Pending Checker Co-Sign
                            </span>
                          )}
                          {record.status === 'approved' && (
                            <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/15 px-2.5 py-0.5 text-[11px] font-semibold text-emerald-300 border border-emerald-500/30">
                              <CheckCircle2 className="h-3 w-3" />
                              Approved (2/2 Signatures)
                            </span>
                          )}
                          {record.status === 'rejected' && (
                            <span className="inline-flex items-center gap-1 rounded-full bg-rose-500/15 px-2.5 py-0.5 text-[11px] font-semibold text-rose-300 border border-rose-500/30">
                              <XCircle className="h-3 w-3" />
                              Rejected
                            </span>
                          )}
                        </div>

                        <div className="text-base font-bold text-slate-100">
                          {record.fields.amount} {record.fields.currency}{' '}
                          <span className="font-normal text-slate-400">→</span>{' '}
                          <span>{record.fields.payee}</span>
                        </div>

                        <div className="flex flex-wrap items-center gap-3 text-[11px] text-slate-400 font-mono">
                          <span>Created: {record.createdAt}</span>
                          <span>•</span>
                          <span>Leaf: {record.leafHash.slice(0, 16)}...</span>
                        </div>
                      </div>

                      {/* Primary Action Buttons */}
                      <div className="flex flex-wrap items-center gap-2">
                        {record.status === 'pending' && (
                          <>
                            <button
                              type="button"
                              onClick={() => handleOneClickCoSign(record)}
                              className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-600 px-3.5 py-2 text-xs font-semibold text-white shadow-md shadow-emerald-600/20 hover:bg-emerald-500 transition"
                            >
                              <Check className="h-3.5 w-3.5" />
                              <span>One-Click Co-Sign & Approve</span>
                            </button>
                            <button
                              type="button"
                              onClick={() =>
                                setRejectingId(rejectingId === record.id ? null : record.id)
                              }
                              className="inline-flex items-center gap-1 rounded-lg border border-rose-500/30 bg-rose-500/10 px-2.5 py-2 text-xs font-medium text-rose-300 hover:bg-rose-500/20 transition"
                            >
                              <XCircle className="h-3.5 w-3.5" />
                              <span>Reject</span>
                            </button>
                          </>
                        )}

                        {record.status === 'approved' && (
                          <button
                            type="button"
                            onClick={() => handleExportBundle(record)}
                            className="inline-flex items-center gap-1.5 rounded-lg border border-indigo-500/30 bg-indigo-500/15 px-3 py-1.5 text-xs font-semibold text-indigo-300 hover:bg-indigo-500/25 transition"
                          >
                            <Download className="h-3.5 w-3.5" />
                            <span>Export PB1 Bundle</span>
                          </button>
                        )}

                        <button
                          type="button"
                          onClick={() =>
                            setExpandedRecordId(isExpanded ? null : record.id)
                          }
                          className="inline-flex items-center gap-1 rounded-lg border border-slate-800 bg-slate-900 px-2.5 py-1.5 text-xs text-slate-300 hover:bg-slate-800"
                        >
                          <Eye className="h-3.5 w-3.5" />
                          <span>{isExpanded ? 'Hide' : 'Inspect'}</span>
                        </button>
                      </div>
                    </div>

                    {/* Rejection Reason Input */}
                    {rejectingId === record.id && (
                      <div className="mt-4 flex items-center gap-2 rounded-lg border border-rose-500/30 bg-rose-950/20 p-3">
                        <input
                          type="text"
                          value={rejectionReason}
                          onChange={(e) => setRejectionReason(e.target.value)}
                          placeholder="Mandatory audit reason for rejection (e.g., Missing PO signature)..."
                          className="flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs text-white focus:border-rose-500 focus:outline-none"
                        />
                        <button
                          type="button"
                          onClick={() => handleRejectRecord(record)}
                          className="rounded-lg bg-rose-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-rose-500"
                        >
                          Confirm Reject
                        </button>
                      </div>
                    )}

                    {/* Rejection Reason Display */}
                    {record.status === 'rejected' && record.rejectionReason && (
                      <div className="mt-3 rounded-lg border border-rose-500/20 bg-rose-500/10 px-3 py-2 text-xs text-rose-300">
                        <span className="font-semibold">Audit Rejection Reason:</span>{' '}
                        {record.rejectionReason}
                      </div>
                    )}

                    {/* Signatures Bar */}
                    <div className="mt-3 flex flex-wrap gap-2">
                      {record.signatures.map((sig) => (
                        <div
                          key={sig.id}
                          className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 font-mono text-[11px] ${
                            sig.kind === 'author'
                              ? 'border-indigo-500/30 bg-indigo-500/10 text-indigo-300'
                              : 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                          }`}
                        >
                          <KeyRound className="h-3 w-3" />
                          <span className="font-semibold uppercase">{sig.kind}:</span>
                          <span>{sig.publicKey.slice(0, 10)}...</span>
                          <span className="text-slate-400">
                            (sig: {sig.signature.slice(0, 10)}...)
                          </span>
                        </div>
                      ))}
                    </div>

                    {/* Expanded Cryptographic & Selective Disclosure Inspector */}
                    {isExpanded && (
                      <div className="mt-4 space-y-3 border-t border-slate-800/80 pt-4 text-xs">
                        {record.evidence && (
                          <div className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-900/70 px-3 py-2">
                            <div className="flex items-center gap-2">
                              <FileText className="h-4 w-4 text-indigo-400" />
                              <span className="font-medium text-slate-200">
                                {record.evidence.fileName}
                              </span>
                              <span className="text-slate-500">
                                ({record.evidence.sizeBytes} B)
                              </span>
                            </div>
                            <code className="font-mono text-[11px] text-emerald-400">
                              {record.evidence.sha256.slice(0, 28)}...
                            </code>
                          </div>
                        )}

                        <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-3">
                          <div className="mb-2 flex items-center justify-between">
                            <span className="font-semibold text-slate-300">
                              PB1 Salted Field Commitments (Select fields to disclose on export)
                            </span>
                            <span className="font-mono text-[11px] text-indigo-300">
                              field_root: {record.fieldRoot.slice(0, 16)}...
                            </span>
                          </div>

                          <div className="grid gap-2 sm:grid-cols-2">
                            {record.sortedFields.map((f) => {
                              const checked = disclosedMap[f.name] !== false;
                              return (
                                <label
                                  key={f.name}
                                  className={`flex cursor-pointer items-start gap-2.5 rounded-lg border p-2.5 font-mono text-[11px] transition ${
                                    checked
                                      ? 'border-indigo-500/40 bg-indigo-950/20'
                                      : 'border-slate-800 bg-slate-950/60 opacity-60'
                                  }`}
                                >
                                  <input
                                    type="checkbox"
                                    checked={checked}
                                    onChange={() =>
                                      toggleFieldDisclosure(record, f.name)
                                    }
                                    className="mt-0.5 rounded border-slate-700 text-indigo-600 focus:ring-indigo-500"
                                  />
                                  <div className="min-w-0 flex-1">
                                    <div className="flex justify-between">
                                      <span className="font-bold text-indigo-300">
                                        {f.name}
                                      </span>
                                      <span className="text-[10px] text-slate-400">
                                        {checked ? 'Disclosed' : 'Masked (Proof Only)'}
                                      </span>
                                    </div>
                                    <div className="truncate text-slate-200">
                                      {f.value}
                                    </div>
                                    <div className="truncate text-[10px] text-slate-500">
                                      commit: {f.commitmentHex.slice(0, 22)}...
                                    </div>
                                  </div>
                                </label>
                              );
                            })}
                          </div>
                        </div>

                        {record.checkpointId && (
                          <div className="flex items-center justify-between rounded-lg border border-emerald-500/20 bg-emerald-500/5 px-3 py-2">
                            <span className="text-slate-300">
                              Anchored in Checkpoint{' '}
                              <strong className="text-emerald-300">
                                #{record.checkpointId}
                              </strong>
                            </span>
                            <Link
                              href={`/verify/${record.orgStellarAddress}/${record.checkpointId}`}
                              className="inline-flex items-center gap-1 text-emerald-400 hover:text-emerald-300 font-medium"
                            >
                              <span>Verify On-Chain</span>
                              <ExternalLink className="h-3 w-3" />
                            </Link>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

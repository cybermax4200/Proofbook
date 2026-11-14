import type { Metadata } from 'next';
import './globals.css';
import { Navbar } from '@/components/Navbar';

export const metadata: Metadata = {
  title: 'Proofbook — Tamper-Evident Evidence Trail on Stellar / Soroban',
  description:
    'Privacy-preserving financial and operational audit records using Format PB1 salted Merkle commitments, Maker-Checker Ed25519 co-signatures, and Soroban checkpoint anchoring.',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="antialiased selection:bg-indigo-500/30 selection:text-indigo-200">
        <div className="flex min-h-screen flex-col">
          <Navbar />
          <main className="flex-1">{children}</main>
          <footer className="border-t border-slate-800/80 bg-slate-950/60 py-6 text-xs text-slate-500">
            <div className="mx-auto flex max-w-7xl flex-col items-center justify-between gap-3 px-4 sm:flex-row sm:px-6 lg:px-8">
              <div className="flex items-center gap-2">
                <span className="font-semibold text-slate-400">Proofbook</span>
                <span>•</span>
                <span>Format PB1 Cryptographic Standard</span>
                <span>•</span>
                <span>Soroban Protocol 22</span>
              </div>
              <div className="font-mono text-[11px] text-slate-400">
                Contract: CDB4DCLRAIAGILGM4DWIOKOTSWDDY6IGP4X4FF62DA3GUQQ4LEKD5VCD
              </div>
            </div>
          </footer>
        </div>
      </body>
    </html>
  );
}

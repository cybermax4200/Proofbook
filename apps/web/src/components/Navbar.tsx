'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  ShieldCheck,
  FilePlus2,
  CheckCircle2,
  Blocks,
  Terminal,
  ExternalLink,
} from 'lucide-react';

export function Navbar() {
  const pathname = usePathname();

  const navItems = [
    {
      href: '/',
      label: 'Overview',
      icon: Blocks,
      active: pathname === '/',
    },
    {
      href: '/portal',
      label: 'Organization Portal',
      icon: FilePlus2,
      active: pathname?.startsWith('/portal'),
    },
    {
      href: '/verify',
      label: 'Public Verifier',
      icon: CheckCircle2,
      active: pathname?.startsWith('/verify'),
    },
  ];

  return (
    <header className="sticky top-0 z-40 border-b border-slate-800/80 bg-slate-950/85 backdrop-blur-md">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-3.5 sm:px-6 lg:px-8">
        <div className="flex items-center gap-6">
          <Link href="/" className="flex items-center gap-2.5 group">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-indigo-500/15 border border-indigo-500/30 text-indigo-400 group-hover:bg-indigo-500/25 transition">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-base font-bold tracking-tight text-slate-100">
                  Proofbook
                </span>
                <span className="rounded bg-indigo-500/15 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-indigo-300 border border-indigo-500/30">
                  PB1
                </span>
              </div>
              <p className="text-[11px] text-slate-400">
                Stellar / Soroban Evidence Trail
              </p>
            </div>
          </Link>

          <nav className="hidden md:flex items-center gap-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`flex items-center gap-2 rounded-lg px-3.5 py-2 text-sm font-medium transition ${
                    item.active
                      ? 'bg-indigo-500/15 text-indigo-300 border border-indigo-500/30'
                      : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
                  }`}
                >
                  <Icon className="h-4 w-4" />
                  {item.label}
                </Link>
              );
            })}
          </nav>
        </div>

        <div className="flex items-center gap-3">
          <Link
            href="/verify/GDGZW7GAZNBP4NGIPRUTHTIE6JRUEAWNOEXKMSXK6XYWQPRAQP2HHMRQ/1"
            className="hidden sm:inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-1.5 text-xs font-medium text-emerald-300 hover:bg-emerald-500/20 transition"
          >
            <Terminal className="h-3.5 w-3.5" />
            <span>Testnet Checkpoint #1</span>
            <ExternalLink className="h-3 w-3 opacity-75" />
          </Link>
        </div>
      </div>

      {/* Mobile Navigation */}
      <div className="flex md:hidden border-t border-slate-800/60 px-4 py-2 gap-2 overflow-x-auto">
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium whitespace-nowrap ${
                item.active
                  ? 'bg-indigo-500/15 text-indigo-300 border border-indigo-500/30'
                  : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
              }`}
            >
              <Icon className="h-3.5 w-3.5" />
              {item.label}
            </Link>
          );
        })}
      </div>
    </header>
  );
}

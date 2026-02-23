'use client';

import { useState } from 'react';
import dynamic from 'next/dynamic';
import Link from 'next/link';
import {
  Shield, AlertTriangle, Clock, Activity,
  TrendingDown, ChevronRight, Zap, ArrowUpRight,
  Database, Globe, Lock, Cpu, Radar, Info
} from 'lucide-react';
import { mockFindings, threatIntel, complianceSummary } from '@/lib/mock-data';
import { useAppStore } from '@/lib/store';
import clsx from 'clsx';

const RiskTrendChart = dynamic(() => import('@/components/charts/RiskTrendChart'), { ssr: false });

const severityConfig = {
  critical: { color: '#ef4444', label: 'CRITICAL' },
  high: { color: '#f59e0b', label: 'HIGH' },
  medium: { color: '#eab308', label: 'MEDIUM' },
  low: { color: '#10b981', label: 'LOW' },
};

export default function DashboardPage() {
  const { addToast } = useAppStore();
  const [scanning, setScanning] = useState(false);

  const handleScan = () => {
    setScanning(true);
    addToast('Threat Hunting Initiated...', 'info');
    setTimeout(() => {
      setScanning(false);
      addToast('Scan complete: 0 new anomalies detected.', 'success');
    }, 2500);
  };

  return (
    <div className="space-y-6 animate-fade-in pb-10">

      {/* Platform Header */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b border-slate-800 pb-6 mb-2">
        <div>
          <h2 className="text-2xl font-bold text-white tracking-tight">Security Posture Overview</h2>
          <p className="text-slate-500 text-sm mt-1">Real-time telemetry and threat intelligence feed for all cloud endpoints.</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="bg-slate-900 border border-slate-800 px-4 py-2 rounded-lg flex items-center gap-4">
            <div className="flex flex-col items-center">
              <span className="text-[10px] font-bold text-slate-500 uppercase">Agents</span>
              <span className="text-sm font-bold text-white">4,281</span>
            </div>
            <div className="h-6 w-px bg-slate-800" />
            <div className="flex flex-col items-center">
              <span className="text-[10px] font-bold text-slate-500 uppercase">Traffic</span>
              <span className="text-sm font-bold text-sky-400">12.4 GB/s</span>
            </div>
          </div>
          <button
            onClick={handleScan}
            disabled={scanning}
            className="bg-sky-500 hover:bg-sky-400 text-slate-950 px-4 py-2 rounded-lg text-sm font-bold flex items-center gap-2 transition-all shadow-[0_0_15px_rgba(56,189,248,0.3)] disabled:opacity-50"
          >
            {scanning ? <Radar size={16} className="animate-spin" /> : <Zap size={16} />}
            {scanning ? 'HUNTING...' : 'RUN GLOBAL SCAN'}
          </button>
        </div>
      </div>

      {/* High Density Stats & Security Score */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">

        {/* Security Score Dial (Microsoft Style) */}
        <div className="card-hover rounded-xl p-5 flex flex-col items-center justify-center text-center bg-slate-900/40 min-h-[180px]">
          <div className="relative w-28 h-28 flex items-center justify-center">
            <svg className="w-full h-full transform -rotate-90">
              <circle cx="56" cy="56" r="48" fill="transparent" stroke="currentColor" strokeWidth="8" className="text-slate-800" />
              <circle cx="56" cy="56" r="48" fill="transparent" stroke="currentColor" strokeWidth="8" strokeDasharray={301.59} strokeDashoffset={301.59 * (1 - 0.72)} className="text-sky-500 transition-all duration-1000" />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-3xl font-black text-white">72</span>
              <span className="text-[10px] uppercase font-bold text-slate-500 tracking-widest mt-[-4px]">Secure Score</span>
            </div>
          </div>
          <p className="mt-4 text-[10px] font-bold text-sky-500/80 uppercase tracking-widest">+4.2% THIS MONTH</p>
        </div>

        {/* Dynamic High-Density Tiles */}
        <div className="lg:col-span-3 grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: 'CRITICAL FINDINGS', value: '23', change: '+3', icon: AlertTriangle, color: 'text-red-500' },
            { label: 'ACTIVE THREATS', value: '12', change: '-2', icon: Radar, color: 'text-amber-500' },
            { label: 'AVG REMEDIATION', value: '21h', change: '-4h', icon: Clock, color: 'text-emerald-500' },
            { label: 'TOTAL ALERTS', value: '1,504', change: '+12%', icon: Activity, color: 'text-sky-500' },
            { label: 'CLOUD ASSETS', value: '842', change: '+12', icon: Globe, color: 'text-slate-400' },
            { label: 'IAM ROLES', value: '128', change: '0', icon: Lock, color: 'text-slate-400' },
            { label: 'DB INSTANCES', value: '45', change: '+2', icon: Database, color: 'text-slate-400' },
            { label: 'COMPUTE NODES', value: '312', change: '+15', icon: Cpu, color: 'text-slate-400' },
          ].map((stat, i) => (
            <div key={i} className="card-hover rounded-xl p-4 bg-slate-900/40">
              <div className="flex items-center gap-2 mb-2">
                <stat.icon size={14} className={stat.color} />
                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">{stat.label}</span>
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-xl font-bold text-white">{stat.value}</span>
                <span className={clsx("text-[10px] font-bold", stat.change.startsWith('+') ? 'text-red-400' : 'text-emerald-400')}>
                  {stat.change}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Main Analysis Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

        {/* Risk Trend (Sentinel Style) */}
        <div className="card-hover rounded-xl p-5 bg-slate-900/20">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h3 className="text-sm font-bold text-white uppercase tracking-widest flex items-center gap-2">
                <Activity size={16} className="text-sky-400" />
                Risk Exposure Over Time
              </h3>
              <p className="text-[10px] text-slate-500 mt-1 uppercase font-bold tracking-tighter">Rolling 30-day incident telemetry</p>
            </div>
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-1.5 text-[10px] font-bold text-slate-300">
                <span className="w-2 h-2 rounded-full bg-red-500" /> Critical
              </div>
              <div className="flex items-center gap-1.5 text-[10px] font-bold text-slate-300">
                <span className="w-2 h-2 rounded-full bg-amber-500" /> High
              </div>
            </div>
          </div>
          <RiskTrendChart />
        </div>

        {/* Threat Intelligence Feed (CrowdStrike Style) */}
        <div className="card-hover rounded-xl p-5 bg-slate-900/20 flex flex-col">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-sm font-bold text-white uppercase tracking-widest flex items-center gap-2">
              <Radar size={16} className="text-red-500 animate-pulse" />
              Threat Intel Feed
            </h3>
            <span className="text-[10px] bg-red-500/10 text-red-400 px-2 py-0.5 rounded-full font-bold uppercase tracking-widest border border-red-500/20">Active Hunting</span>
          </div>
          <div className="flex-1 space-y-3">
            {threatIntel.map((intel) => (
              <div key={intel.id} className="flex items-center gap-3 p-3 rounded-lg bg-slate-900/60 border border-slate-800/50 hover:border-slate-700 transition-colors group">
                <div className={clsx(
                  "w-8 h-8 rounded flex items-center justify-center flex-shrink-0",
                  intel.reputation === 'malicious' ? 'bg-red-500/10 text-red-500' : 'bg-amber-500/10 text-amber-500'
                )}>
                  <Shield size={16} />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-bold tracking-tight text-white font-mono truncate">{intel.value}</span>
                    <span className="text-[9px] text-slate-500 font-bold">{intel.lastSeen}</span>
                  </div>
                  <div className="flex items-center gap-2 mt-1">
                    <span className="text-[9px] uppercase font-bold text-slate-500">{intel.type}</span>
                    <div className="w-1 h-1 rounded-full bg-slate-700" />
                    <span className="text-[9px] uppercase font-bold text-sky-500">{intel.source}</span>
                  </div>
                </div>
                <ChevronRight size={14} className="text-slate-700 group-hover:text-slate-400 transition-colors" />
              </div>
            ))}
          </div>
          <button className="w-full mt-4 py-2 border border-slate-800 rounded-lg text-[10px] font-bold text-slate-400 hover:text-white hover:bg-slate-800 transition-colors uppercase tracking-widest">
            Explore Full Intel Cloud
          </button>
        </div>
      </div>

      {/* High-Impact Findings & Compliance */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">

        {/* MITRE ATT&CK Mapped Findings */}
        <div className="lg:col-span-3 card-hover rounded-xl p-5 bg-slate-900/20">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-sm font-bold text-white uppercase tracking-widest flex items-center gap-2">
              <AlertTriangle size={16} className="text-red-500" />
              Prioritized Threat Remediation
            </h3>
            <Link href="/scans" className="text-[10px] text-sky-400 font-bold hover:underline flex items-center gap-1 uppercase tracking-widest">
              View Fleet <ArrowUpRight size={10} />
            </Link>
          </div>
          <div className="space-y-2">
            {mockFindings.slice(0, 4).map((f) => {
              const cfg = severityConfig[f.severity];
              return (
                <div key={f.id} className="flex items-center gap-4 p-3 rounded-lg border border-slate-800/50 bg-slate-900/30 hover:border-slate-700 transition-all cursor-pointer group">
                  <div className="w-1.5 h-1.5 rounded-full" style={{ background: cfg.color }} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-bold text-slate-100 truncate group-hover:text-sky-400 transition-colors">{f.title}</span>
                    </div>
                    <div className="flex items-center gap-3 mt-1.5">
                      <span className="text-[9px] font-mono text-slate-500">{f.resource}</span>
                      {f.mitre && (
                        <div className="flex items-center gap-1.5">
                          <div className="w-1 h-1 rounded-full bg-slate-700" />
                          <span className="mitre-tag">{f.mitre.id}: {f.mitre.technique}</span>
                        </div>
                      )}
                    </div>
                  </div>
                  <div className="flex flex-col items-end gap-1.5 flex-shrink-0">
                    <span className={clsx('text-[10px] px-2 py-0.5 rounded font-black tracking-widest badge-' + f.severity)}>
                      {cfg.label}
                    </span>
                    <span className="text-[11px] font-mono font-bold text-slate-400">{f.riskScore.toFixed(1)}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Compliance Posture Matrix */}
        <div className="lg:col-span-2 card-hover rounded-xl p-5 bg-slate-900/20 flex flex-col">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-sm font-bold text-white uppercase tracking-widest flex items-center gap-2">
              <Shield size={16} className="text-sky-400" />
              Compliance Heatmap
            </h3>
            <div className="bg-slate-900 px-2 py-0.5 rounded border border-slate-800 flex items-center gap-1.5">
              <div className="w-1 h-1 rounded-full bg-emerald-500" />
              <span className="text-[9px] font-bold text-slate-400">AUDIT READY</span>
            </div>
          </div>

          <div className="space-y-6 flex-1">
            {[
              { name: 'HIPAA Security Rule', score: 85, color: 'bg-sky-500' },
              { name: 'NIST 800-53 r5', score: 84, color: 'bg-emerald-500' },
              { name: 'ISO 27001 Cloud', score: 86, color: 'bg-amber-500' },
            ].map((item) => (
              <div key={item.name}>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[11px] font-bold text-slate-300 uppercase tracking-tight">{item.name}</span>
                  <span className="text-xs font-mono font-bold text-white">{item.score}%</span>
                </div>
                <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                  <div className={clsx("h-full rounded-full transition-all duration-1000", item.color)} style={{ width: `${item.score}%` }} />
                </div>
              </div>
            ))}
          </div>

          <Link href="/compliance" className="mt-6 flex items-center justify-center gap-2 py-2.5 rounded-lg border border-sky-500/20 text-sky-400 hover:bg-sky-500/10 transition-all group font-bold text-[10px] uppercase tracking-widest">
            Download Audit Package
            <ArrowUpRight size={12} className="group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
          </Link>
        </div>
      </div>

    </div>
  );
}

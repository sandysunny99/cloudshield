'use client';

import { useState } from 'react';
import dynamic from 'next/dynamic';
import { useState, useMemo } from 'react';
import {
  Shield, ShieldAlert, ShieldCheck, Zap,
  ArrowUpRight, ArrowDownRight, Globe, Lock,
  Activity, Container, Server, Database, Radar
} from 'lucide-react';
import RiskTrendChart from '@/components/charts/RiskTrendChart';
import { mockFindings, complianceSummary, threatIntel } from '@/lib/mock-data';
import { useAppStore } from '@/lib/store';
import clsx from 'clsx';

export default function Dashboard() {
  const { addToast } = useAppStore();
  const [scanning, setScanning] = useState(false);

  const handleGlobalScan = () => {
    setScanning(true);
    addToast('GLOBAL FLEET DISCOVERY INITIATED...', 'info');
    setTimeout(() => {
      setScanning(false);
      addToast('SCAN COMPLETE: 12 new findings ingested.', 'success');
    }, 3000);
  };

  const criticalCount = mockFindings.filter(f => f.severity === 'critical').length;
  const highCount = mockFindings.filter(f => f.severity === 'high').length;

  return (
    <div className="space-y-6 animate-fade-in pb-10">

      {/* 1. SECURITY POSTURE OVERVIEW (2.0) */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <PostureCard label="CRITICAL FINDINGS" count={criticalCount} delta="+12%" deltaColor="text-red-400" icon={ShieldAlert} />
        <PostureCard label="HIGH SEVERITY" count={highCount} delta="-5%" deltaColor="text-emerald-400" icon={Shield} />
        <PostureCard label="ACTIVE ASSETS" count={5678} delta="+234" deltaColor="text-sky-400" icon={Server} />
        <PostureCard label="THREAT RADIUS" count="1.2k" delta="-8%" deltaColor="text-emerald-400" icon={Radar} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">

        {/* 2. REAL-TIME THREAT MAP (STUB) */}
        <div className="lg:col-span-8 rounded-2xl border border-slate-800 bg-slate-900/40 overflow-hidden relative glass min-h-[400px]">
          <div className="p-6 border-b border-slate-800 bg-slate-900/60 flex items-center justify-between">
            <div>
              <h3 className="text-sm font-black text-white tracking-widest uppercase flex items-center gap-2">
                <Globe size={18} className="text-sky-400" />
                Real-time Threat Map
              </h3>
              <p className="text-[10px] font-bold text-slate-500 uppercase mt-1">Live Ingress/Egress Telemetry & Attack Vectors</p>
            </div>
            <div className="flex items-center gap-4">
              <MapStat label="ACTIVE ATTACKS" val="1,234" color="text-red-500" />
              <MapStat label="BLOCKED" val="12.3k" color="text-emerald-500" />
            </div>
          </div>

          {/* Mock Map Canvas */}
          <div className="absolute inset-0 top-20 flex items-center justify-center opacity-40 pointer-events-none">
            <div className="w-full h-full relative" style={{ backgroundImage: 'radial-gradient(#1e293b 1px, transparent 1px)', backgroundSize: '40px 40px' }}>
              {/* Animated Attack Pulse */}
              <div className="absolute top-1/4 left-1/3 w-2 h-2 rounded-full bg-red-500 animate-ping" />
              <div className="absolute top-1/2 left-2/3 w-2 h-2 rounded-full bg-sky-500 animate-ping" style={{ animationDelay: '1s' }} />
              <div className="absolute top-3/4 left-1/2 w-2 h-2 rounded-full bg-red-500 animate-ping" style={{ animationDelay: '0.5s' }} />

              <svg className="absolute inset-0 w-full h-full text-slate-800" strokeDasharray="5,5">
                <line x1="33%" y1="25%" x2="50%" y2="75%" stroke="currentColor" strokeWidth="1" />
                <line x1="66%" y1="50%" x2="50%" y2="75%" stroke="currentColor" strokeWidth="1" />
              </svg>
            </div>
          </div>

          <div className="absolute bottom-6 left-6 flex items-center gap-3">
            <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-950/80 border border-slate-800 shadow-2xl">
              <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
              <span className="text-[10px] font-black text-white uppercase tracking-widest">High Intensity Area: US-EAST</span>
            </div>
          </div>
        </div>

        {/* 3. QUICK SCAN & FLEET STATUS */}
        <div className="lg:col-span-4 space-y-6">
          <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-6 glass h-full flex flex-col">
            <div className="flex items-center gap-3 mb-6">
              <Activity size={20} className="text-emerald-500" />
              <h3 className="text-sm font-black text-white tracking-widest uppercase">Fleet Telemetry</h3>
            </div>

            <div className="flex-1 space-y-4">
              <TelemetryRow icon={Container} label="K8s Workloads" val="542" />
              <TelemetryRow icon={Server} label="Instances" val="129" />
              <TelemetryRow icon={Database} label="Storage Buckets" val="86" />
              <TelemetryRow icon={Lock} label="IAM Policies" val="1.8k" />
            </div>

            <button
              onClick={handleGlobalScan}
              disabled={scanning}
              className={clsx(
                "w-full mt-8 py-4 px-6 rounded-xl text-[11px] font-black uppercase tracking-widest transition-all relative overflow-hidden group",
                scanning
                  ? "bg-slate-800 text-slate-500 cursor-not-allowed"
                  : "bg-sky-500 text-slate-950 hover:bg-sky-400 shadow-[0_0_30px_rgba(58,189,248,0.3)] hover:scale-[1.02]"
              )}
            >
              <span className="relative z-10 flex items-center justify-center gap-3">
                {scanning ? <Radar size={18} className="animate-spin" /> : <Zap size={18} />}
                {scanning ? "Analyzing Cloud Fabric..." : "Run Global Scan"}
              </span>
            </button>
          </div>
        </div>
      </div>

      {/* 4. FINDINGS & COMPLIANCE TRENDS */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-8 rounded-2xl border border-slate-800 bg-slate-900/20 p-6 glass">
          <div className="flex items-center justify-between mb-8">
            <div>
              <h3 className="text-sm font-black text-white tracking-widest uppercase flex items-center gap-2">
                <Activity size={18} className="text-amber-500" />
                Risk Intelligence Trend
              </h3>
            </div>
          </div>
          <div className="h-[300px]">
            <RiskTrendChart />
          </div>
        </div>

        <div className="lg:col-span-4 rounded-2xl border border-slate-800 bg-slate-900/20 p-6 glass">
          <h3 className="text-sm font-black text-white tracking-widest uppercase mb-6">Compliance Score</h3>
          <div className="space-y-6">
            <ComplianceItem label="HIPAA Security" progress={68} color="bg-red-400" />
            <ComplianceItem label="NIST 800-53" progress={85} color="bg-emerald-400" />
            <ComplianceItem label="ISO 27001" progress={72} color="bg-sky-400" />
          </div>
        </div>
      </div>

    </div>
  );
}

// ─── UI HELPERS ──────────────────────────────────────────────────────────────

function PostureCard({ label, count, delta, deltaColor, icon: Icon }: any) {
  return (
        <div className="rounded-2xl border border-slate-800 bg-slate-900/20 p-5 glass group hover:border-slate-700 transition-all">
            <div className="flex items-center justify-between mb-3 text-slate-500">
                <Icon size={18} className="group-hover:text-white transition-colors" />
                <span className={clsx("text-[10px] font-bold flex items-center gap-0.5", deltaColor)}>
                    {delta.startsWith('+') ? <ArrowUpRight size={10} /> : <ArrowDownRight size={10} />}
                    {delta}
                </span>
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
        </div >
      </div >

    {/* High-Impact Findings & Compliance */ }
    < div className = "grid grid-cols-1 lg:grid-cols-5 gap-4" >

      {/* MITRE ATT&CK Mapped Findings */ }
      < div className = "lg:col-span-3 card-hover rounded-xl p-5 bg-slate-900/20" >
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
        </div >

    {/* Compliance Posture Matrix */ }
    < div className = "lg:col-span-2 card-hover rounded-xl p-5 bg-slate-900/20 flex flex-col" >
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
        </div >
      </div >

    </div >
  );
}

'use client';

import { useState, useMemo } from 'react';
import Link from 'next/link';
import {
  Shield, ShieldAlert, Zap,
  ArrowUpRight, ArrowDownRight, Globe, Lock,
  Activity, Container, Server, Database, Radar,
  ChevronRight, AlertTriangle
} from 'lucide-react';
import RiskTrendChart from '@/components/charts/RiskTrendChart';
import { mockFindings, threatIntel } from '@/lib/mock-data';
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
    <div className="space-y-6 animate-fade-in pb-10 font-inter">

      {/* 1. SECURITY POSTURE OVERVIEW (2.0) */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <PostureCard label="CRITICAL FINDINGS" count={criticalCount} delta="+12%" deltaColor="text-red-400" icon={ShieldAlert} />
        <PostureCard label="HIGH SEVERITY" count={highCount} delta="-5%" deltaColor="text-emerald-400" icon={Shield} />
        <PostureCard label="ACTIVE ASSETS" count={5678} delta="+234" deltaColor="text-sky-400" icon={Server} />
        <PostureCard label="THREAT RADIUS" count="1.2k" delta="-8%" deltaColor="text-emerald-400" icon={Radar} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">

        {/* 2. REAL-TIME THREAT MAP */}
        <div className="lg:col-span-8 rounded-2xl border border-slate-800 bg-slate-900/40 overflow-hidden relative glass min-h-[400px]">
          <div className="p-6 border-b border-slate-800 bg-slate-900/60 flex items-center justify-between z-10 relative">
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

          {/* Map Content */}
          <div className="absolute inset-0 top-20 flex items-center justify-center opacity-40 pointer-events-none">
            <div className="w-full h-full relative" style={{ backgroundImage: 'radial-gradient(#1e293b 1px, transparent 1px)', backgroundSize: '40px 40px' }}>
              <div className="absolute top-1/4 left-1/3 w-2 h-2 rounded-full bg-red-500 animate-ping" />
              <div className="absolute top-1/2 left-2/3 w-2 h-2 rounded-full bg-sky-500 animate-ping" style={{ animationDelay: '1s' }} />
              <div className="absolute top-3/4 left-1/2 w-2 h-2 rounded-full bg-red-500 animate-ping" style={{ animationDelay: '0.5s' }} />
            </div>
          </div>

          <div className="absolute bottom-6 left-6 flex items-center gap-3">
            <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-950/80 border border-slate-800 shadow-2xl">
              <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
              <span className="text-[10px] font-black text-white uppercase tracking-widest">High Intensity Area: US-EAST</span>
            </div>
          </div>
        </div>

        {/* 3. THREAT INTEL FEED */}
        <div className="lg:col-span-4 rounded-2xl border border-slate-800 bg-slate-900/40 p-6 glass flex flex-col">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-sm font-black text-white tracking-widest uppercase flex items-center gap-2">
              <Radar size={16} className="text-red-500 animate-pulse" />
              Threat Intel
            </h3>
            <span className="text-[9px] bg-red-500/10 text-red-400 px-2 py-0.5 rounded-full font-bold uppercase border border-red-500/20">Active</span>
          </div>

          <div className="flex-1 space-y-3 overflow-y-auto max-h-[350px] pr-2 custom-scrollbar">
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
                    <span className="text-[10px] font-bold text-white font-mono truncate">{intel.value}</span>
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
          <button className="w-full mt-4 py-2 border border-slate-800 rounded-lg text-[9px] font-bold text-slate-400 hover:text-white uppercase tracking-widest transition-all">
            Explore All Intel
          </button>
        </div>
      </div>

      {/* 4. FLEET TELEMETRY & RISK TREND */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-8 rounded-2xl border border-slate-800 bg-slate-900/20 p-6 glass">
          <div className="flex items-center justify-between mb-8">
            <h3 className="text-sm font-black text-white tracking-widest uppercase flex items-center gap-2">
              <Activity size={18} className="text-amber-500" />
              Risk Intelligence Trend
            </h3>
          </div>
          <div className="h-[300px]">
            <RiskTrendChart />
          </div>
        </div>

        <div className="lg:col-span-4 space-y-6">
          <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-6 glass h-full flex flex-col">
            <h3 className="text-sm font-black text-white tracking-widest uppercase flex items-center gap-2 mb-6">
              <Activity size={18} className="text-emerald-500" />
              Fleet Status
            </h3>
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
                "w-full mt-6 py-4 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all",
                scanning ? "bg-slate-800 text-slate-500" : "bg-sky-500 text-slate-950 hover:bg-sky-400"
              )}
            >
              {scanning ? "Analyzing..." : "Scan Environment"}
            </button>
          </div>
        </div>
      </div>

      {/* 5. PRIORITIZED FINDINGS & COMPLIANCE */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
        <div className="lg:col-span-3 rounded-2xl border border-slate-800 bg-slate-900/20 p-6 glass">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-sm font-black text-white tracking-widest uppercase flex items-center gap-2">
              <AlertTriangle size={16} className="text-red-500" />
              Critical Remediation Queue
            </h3>
            <Link href="/scans" className="text-[10px] text-sky-400 font-bold hover:underline flex items-center gap-1 uppercase tracking-widest">
              Queue <ArrowUpRight size={10} />
            </Link>
          </div>
          <div className="space-y-2">
            {mockFindings.slice(0, 4).map((f) => (
              <div key={f.id} className="flex items-center gap-4 p-3 rounded-lg border border-slate-800/50 bg-slate-900/30 hover:border-slate-700 transition-all cursor-pointer group">
                <div className={clsx("w-1.5 h-1.5 rounded-full shadow-[0_0_5px_currentColor]", f.severity === 'critical' ? 'text-red-500 bg-red-500' : 'text-amber-500 bg-amber-500')} />
                <div className="flex-1 min-w-0">
                  <span className="text-xs font-bold text-slate-100 truncate block group-hover:text-sky-400 transition-colors">{f.title}</span>
                  <div className="flex items-center gap-2 mt-1">
                    <span className="text-[9px] font-mono text-slate-500">{f.resource}</span>
                    <div className="w-1 h-1 rounded-full bg-slate-800" />
                    <span className="text-[9px] font-bold text-slate-600 uppercase tracking-tighter">MITRE: {f.mitre?.id || 'T1566'}</span>
                  </div>
                </div>
                <div className="flex flex-col items-end flex-shrink-0">
                  <span className={clsx("text-[8px] px-1.5 py-0.5 rounded font-black uppercase mb-1", f.severity === 'critical' ? 'bg-red-500/10 text-red-500 border border-red-500/20' : 'bg-amber-500/10 text-amber-500 border border-amber-500/20')}>
                    {f.severity}
                  </span>
                  <span className="text-[10px] font-mono font-bold text-slate-400">{f.riskScore.toFixed(1)}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="lg:col-span-2 rounded-2xl border border-slate-800 bg-slate-900/20 p-6 glass flex flex-col">
          <h3 className="text-sm font-black text-white tracking-widest uppercase flex items-center gap-2 mb-6">
            <Lock size={16} className="text-sky-400" />
            Compliance Posture
          </h3>
          <div className="space-y-6 flex-1">
            <ComplianceItem label="NIST 800-53" progress={85} color="bg-emerald-500" />
            <ComplianceItem label="HIPAA Security" progress={68} color="bg-red-500" />
            <ComplianceItem label="SOC2 Type II" progress={92} color="bg-sky-500" />
          </div>
          <Link href="/compliance" className="mt-8 text-center py-3 rounded-xl border border-sky-500/20 text-sky-400 font-black text-[10px] uppercase tracking-widest hover:bg-sky-500/10 transition-all">
            Full Audit Workspace
          </Link>
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
      </div>
      <div className="text-2xl font-black text-white tracking-tight">{count}</div>
      <div className="text-[10px] font-black text-slate-500 uppercase tracking-widest mt-1">{label}</div>
    </div>
  );
}

function MapStat({ label, val, color }: any) {
  return (
    <div className="text-right">
      <div className="text-[9px] font-black text-slate-500 uppercase tracking-widest">{label}</div>
      <div className={clsx("text-sm font-black tracking-tight", color)}>{val}</div>
    </div>
  );
}

function TelemetryRow({ icon: Icon, label, val }: any) {
  return (
    <div className="flex items-center justify-between group">
      <div className="flex items-center gap-3">
        <div className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-500 group-hover:text-sky-400 group-hover:border-sky-500/30 transition-all">
          <Icon size={14} />
        </div>
        <span className="text-[11px] font-bold text-slate-400 uppercase tracking-tight">{label}</span>
      </div>
      <span className="text-xs font-mono font-black text-white">{val}</span>
    </div>
  );
}

function ComplianceItem({ label, progress, color }: any) {
  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <span className="text-[10px] font-black text-slate-400 uppercase tracking-widest">{label}</span>
        <span className="text-[10px] font-mono font-black text-white">{progress}%</span>
      </div>
      <div className="h-1.5 w-full bg-slate-800/50 rounded-full overflow-hidden">
        <div className={clsx("h-full rounded-full transition-all duration-1000", color)} style={{ width: `${progress}%` }} />
      </div>
    </div>
  );
}

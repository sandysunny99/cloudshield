'use client';

import { useState, useMemo } from 'react';
import {
    Shield, CheckCircle2, AlertTriangle, Search,
    Download, FileText, Filter, ChevronRight,
    Lock, Zap, Globe, Archive, Activity, BarChart3, Clock, ExternalLink
} from 'lucide-react';
import { complianceSummary } from '@/lib/mock-data';
import { useAppStore } from '@/lib/store';
import clsx from 'clsx';

export default function GRCPage() {
    const [activeFramework, setActiveFramework] = useState(complianceSummary[0].framework);
    const [search, setSearch] = useState('');

    const current = useMemo(() =>
        complianceSummary.find(f => f.framework === activeFramework) || complianceSummary[0]
        , [activeFramework]);

    const controls = useMemo(() => {
        if (!current.details) return [];
        return current.details.filter(c =>
            c.title.toLowerCase().includes(search.toLowerCase()) ||
            c.id.toLowerCase().includes(search.toLowerCase())
        );
    }, [current, search]);

    return (
        <div className="space-y-6 animate-fade-in pb-20 font-inter">

            {/* GRC 2.0 Header */}
            <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-6 border-b border-slate-800 pb-6">
                <div className="min-w-0 flex-1">
                    <h2 className="text-xl sm:text-2xl font-bold text-white tracking-tight flex items-center gap-3 flex-wrap break-words">
                        <Lock size={24} className="text-sky-400 flex-shrink-0" />
                        <span className="truncate sm:whitespace-normal">Governance & Risk Compliance 2.0</span>
                    </h2>
                    <p className="text-slate-500 text-[10px] sm:text-xs mt-1 uppercase font-bold tracking-tighter truncate sm:whitespace-normal underline decoration-sky-500/30 decoration-2 underline-offset-4">Continuous Audit & Evidence Orchestration</p>
                </div>
                <div className="flex items-center gap-3 overflow-x-auto pb-2 lg:pb-0">
                    <button className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-900 border border-slate-800 text-[10px] font-black text-slate-400 uppercase tracking-widest hover:text-white transition-all">
                        <BarChart3 size={14} /> Meta-Audit
                    </button>
                    <button className="flex items-center gap-2 px-4 py-2 rounded-lg bg-sky-500 text-slate-950 text-[10px] font-black uppercase tracking-widest hover:bg-sky-400 transition-all shadow-lg shadow-sky-500/20">
                        <Zap size={14} /> Sync Fabric
                    </button>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">

                {/* 1. Framework & Monitoring Sidebar */}
                <div className="lg:col-span-3 space-y-4">
                    <div className="p-1.5 rounded-xl border border-slate-800 bg-slate-900/40 glass">
                        <div className="px-3 py-2 text-[9px] font-black text-slate-500 uppercase tracking-widest border-b border-slate-800/50 mb-1">Frameworks</div>
                        {complianceSummary.map((c) => (
                            <button
                                key={c.framework}
                                onClick={() => setActiveFramework(c.framework)}
                                className={clsx(
                                    "w-full flex items-center justify-between p-3 rounded-lg transition-all group mb-1 last:mb-0",
                                    activeFramework === c.framework
                                        ? "bg-sky-500/10 border border-sky-500/30"
                                        : "hover:bg-slate-800/50 border border-transparent"
                                )}
                            >
                                <div className="text-left">
                                    <div className={clsx("text-[10px] font-black uppercase tracking-widest", activeFramework === c.framework ? "text-sky-400" : "text-slate-400 group-hover:text-slate-200")}>{c.framework}</div>
                                    <div className="text-[9px] font-bold text-slate-500 mt-0.5">{c.controls} CONTROLS</div>
                                </div>
                                <div className="text-right">
                                    <div className="text-xs font-mono font-black text-white">{c.score}%</div>
                                </div>
                            </button>
                        ))}
                    </div>

                    <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/20 glass">
                        <div className="flex items-center justify-between mb-4">
                            <h4 className="text-[9px] font-black text-slate-500 uppercase tracking-widest">Real-time Sensors</h4>
                            <Activity size={12} className="text-emerald-500 animate-pulse" />
                        </div>
                        <div className="space-y-3">
                            <MonitorRow label="CloudTrail Pulse" status="stable" />
                            <MonitorRow label="GuardDuty Ingest" status="stable" />
                            <MonitorRow label="Config Drift" status="alert" />
                        </div>
                    </div>
                </div>

                {/* 2. Audit Workspace */}
                <div className="lg:col-span-9 space-y-6">

                    {/* High-level Status */}
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                        <ControlStat label="COMPLIANT" count={controls.filter(c => c.status === 'compliant').length} color="text-emerald-500" />
                        <ControlStat label="NON-COMPLIANT" count={controls.filter(c => c.status === 'non-compliant').length} color="text-red-500" />
                        <ControlStat label="EXEMPT/NA" count={0} color="text-slate-500" />
                    </div>

                    {/* Evidence Locker Workspace */}
                    <div className="rounded-2xl border border-slate-800 bg-slate-900/40 overflow-hidden glass shadow-2xl relative">
                        <div className="p-5 border-b border-slate-800 bg-slate-900/60 flex items-center justify-between gap-4 flex-wrap">
                            <div className="flex items-center gap-3">
                                <Archive size={18} className="text-sky-400" />
                                <div>
                                    <h3 className="text-sm font-black text-white uppercase tracking-widest">Evidence Locker</h3>
                                    <p className="text-[10px] font-bold text-slate-500 uppercase tracking-tighter">Cryptographically Signed Audit Artifacts</p>
                                </div>
                            </div>
                            <div className="flex items-center gap-3 flex-1 min-w-[200px] max-w-sm">
                                <div className="relative w-full">
                                    <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                                    <input
                                        type="text"
                                        value={search}
                                        onChange={(e) => setSearch(e.target.value)}
                                        placeholder="SEARCH CONTROLS..."
                                        className="w-full bg-slate-950 border border-slate-800 rounded-lg py-1.5 pl-9 pr-3 text-[10px] font-bold text-white uppercase focus:border-sky-500/50 outline-none transition-all"
                                    />
                                </div>
                                <button className="p-2 bg-slate-900 border border-slate-800 rounded-lg text-slate-400 hover:text-white transition-all">
                                    <Filter size={14} />
                                </button>
                            </div>
                        </div>

                        <div className="overflow-x-auto custom-scrollbar">
                            <table className="w-full text-left border-collapse">
                                <thead className="bg-slate-950/80 border-b border-slate-800">
                                    <tr>
                                        <th className="px-6 py-4 text-[9px] font-black text-slate-500 uppercase tracking-widest">ID</th>
                                        <th className="px-6 py-4 text-[9px] font-black text-slate-500 uppercase tracking-widest">CONTROL OBJECTIVE</th>
                                        <th className="px-6 py-4 text-[9px] font-black text-slate-500 uppercase tracking-widest">VERIFIED EVIDENCE</th>
                                        <th className="px-6 py-4 text-[9px] font-black text-slate-500 uppercase tracking-widest">POSTURE</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-slate-800/50">
                                    {controls.map((ctrl, i) => (
                                        <tr key={i} className="hover:bg-sky-500/[0.02] transition-all group">
                                            <td className="px-6 py-4">
                                                <span className="text-[11px] font-mono font-black text-sky-400/80">{ctrl.id}</span>
                                            </td>
                                            <td className="px-6 py-4">
                                                <div className="text-[11px] font-bold text-slate-200 group-hover:text-white transition-colors">{ctrl.title}</div>
                                                <div className="flex items-center gap-2 mt-1">
                                                    <span className="text-[8px] font-black text-slate-600 uppercase tracking-tighter">Domain: {ctrl.domain}</span>
                                                    <div className="w-1 h-1 rounded-full bg-slate-800" />
                                                    <span className="text-[8px] font-black text-slate-600 uppercase tracking-tighter">Owner: SecOps</span>
                                                </div>
                                            </td>
                                            <td className="px-6 py-4">
                                                <div className="flex flex-col gap-1.5">
                                                    <div className="flex items-center gap-2 text-[9px] font-mono text-slate-500 group-hover:text-slate-300 transition-colors">
                                                        <Lock size={10} className="text-emerald-500" />
                                                        {Math.random().toString(16).slice(2, 10)}...sign
                                                        <Download size={10} className="hover:text-sky-400 cursor-pointer ml-1" />
                                                    </div>
                                                    <div className="flex items-center gap-1.5 text-[8px] text-slate-600 font-bold uppercase tracking-tighter">
                                                        <Clock size={8} /> Just now
                                                    </div>
                                                </div>
                                            </td>
                                            <td className="px-6 py-4">
                                                <span className={clsx(
                                                    "text-[10px] font-black px-2.5 py-0.5 rounded border uppercase tracking-widest",
                                                    ctrl.status === 'compliant'
                                                        ? "text-emerald-500 border-emerald-500/20 bg-emerald-500/5"
                                                        : "text-red-500 border-red-500/20 bg-red-500/10 animate-pulse"
                                                )}>
                                                    {ctrl.status === 'compliant' ? 'Verified' : 'Failing'}
                                                </span>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <div className="flex items-center justify-between">
                        <p className="text-[10px] font-bold text-slate-500 uppercase tracking-tighter italic">Total {current.controls} controls available in framework definition.</p>
                        <button className="flex items-center gap-2 text-[10px] font-black text-sky-400 hover:text-white uppercase tracking-widest transition-all">
                            View Full Audit Report <ExternalLink size={12} />
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
}

// ─── GRC 2.0 COMPONENTS ───────────────────────────────────────────────────────

function MonitorRow({ label, status }: { label: string; status: 'stable' | 'alert' }) {
    return (
        <div className="flex items-center justify-between text-[10px] font-bold group">
            <span className="text-slate-500 uppercase tracking-tighter group-hover:text-slate-300 transition-colors">{label}</span>
            <div className="flex items-center gap-2">
                <span className={clsx("text-[8px] uppercase font-black", status === 'stable' ? "text-emerald-500" : "text-amber-500")}>
                    {status === 'stable' ? 'LOCKED' : 'DRIFT'}
                </span>
                <div className={clsx("w-1.5 h-1.5 rounded-full shadow-[0_0_5px_currentColor]", status === 'stable' ? "text-emerald-500 bg-emerald-500" : "text-amber-500 bg-amber-500 animate-pulse")} />
            </div>
        </div>
    );
}

function ControlStat({ label, count, color }: { label: string; count: number; color: string }) {
    return (
        <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/20 glass group hover:border-slate-700 transition-all">
            <div className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-1.5">{label}</div>
            <div className={clsx("text-2xl font-black", color)}>{count}</div>
        </div>
    );
}

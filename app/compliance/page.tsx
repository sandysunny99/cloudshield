'use client';

import { useState } from 'react';
import {
    Shield, CheckCircle2, AlertCircle, FileText, Download,
    ChevronRight, ExternalLink, Filter, Search, BarChart3,
    Clock, Lock, Zap
} from 'lucide-react';
import { complianceSummary } from '@/lib/mock-data';
import { useAppStore } from '@/lib/store';
import clsx from 'clsx';

type Tab = 'hipaa' | 'nist' | 'iso';

const frameworkDetails: Record<Tab, {
    name: string;
    description: string;
    controls: number;
    lastAudit: string;
    nextAudit: string;
}> = {
    hipaa: {
        name: 'HIPAA Security Rule',
        description: 'Health Insurance Portability and Accountability Act - Security & Privacy Standards.',
        controls: 14,
        lastAudit: '2026-01-15',
        nextAudit: '2026-04-15',
    },
    nist: {
        name: 'NIST 800-53 r5',
        description: 'Security and Privacy Controls for Information Systems and Organizations.',
        controls: 53,
        lastAudit: '2026-02-10',
        nextAudit: '2026-05-10',
    },
    iso: {
        name: 'ISO/IEC 27001:2022',
        description: 'Information security, cybersecurity and privacy protection — Management systems.',
        controls: 35,
        lastAudit: '2025-12-20',
        nextAudit: '2026-06-20',
    }
};

export default function CompliancePage() {
    const { addToast } = useAppStore();
    const [activeTab, setActiveTab] = useState<Tab>('nist');
    const [exporting, setExporting] = useState(false);

    const handleExport = (format: string) => {
        setExporting(true);
        addToast(`Generating Compliance Package (${format.toUpperCase()})...`, 'info');
        setTimeout(() => {
            setExporting(false);
            addToast(`AUDIT EXPORT: ${activeTab.toUpperCase()} Package secured.`, 'success');
        }, 2000);
    };

    const current = frameworkDetails[activeTab];
    const stats = complianceSummary[activeTab];

    return (
        <div className="space-y-6 animate-fade-in pb-10">

            {/* GRC Header */}
            <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b border-slate-800 pb-6">
                <div>
                    <h2 className="text-2xl font-bold text-white tracking-tight flex items-center gap-3">
                        <Lock size={24} className="text-sky-400" />
                        Governance & Risk Compliance
                    </h2>
                    <p className="text-slate-500 text-sm mt-1 uppercase font-bold tracking-tighter">Enterprise Framework Audit & Control Monitoring</p>
                </div>
                <div className="flex items-center gap-3">
                    <button
                        onClick={() => handleExport('pdf')}
                        className="px-4 py-2 rounded-lg border border-slate-800 bg-slate-900/60 text-[10px] font-black text-slate-300 hover:text-white hover:border-slate-700 transition-all uppercase tracking-widest flex items-center gap-2"
                    >
                        <FileText size={14} /> Audit Package (PDF)
                    </button>
                    <button
                        onClick={() => handleExport('json')}
                        className="px-4 py-2 rounded-lg bg-sky-500 text-slate-950 text-[10px] font-black hover:bg-sky-400 transition-all uppercase tracking-widest flex items-center gap-2 shadow-[0_0_15px_rgba(56,189,248,0.2)]"
                    >
                        <Zap size={14} /> Data Export (JSON)
                    </button>
                </div>
            </div>

            {/* Framework Selector & Summary */}
            <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">

                {/* Framework Navigation */}
                <div className="lg:col-span-1 space-y-2">
                    {(['nist', 'hipaa', 'iso'] as Tab[]).map((tab) => (
                        <button
                            key={tab}
                            onClick={() => setActiveTab(tab)}
                            className={clsx(
                                "w-full flex flex-col p-4 rounded-xl border transition-all text-left group",
                                activeTab === tab
                                    ? "bg-sky-500/10 border-sky-500/50 shadow-[0_0_15px_rgba(56,189,248,0.1)]"
                                    : "bg-slate-900/40 border-slate-800 hover:border-slate-700 hover:bg-slate-900/60"
                            )}
                        >
                            <div className="flex items-center justify-between mb-2">
                                <span className={clsx(
                                    "text-[10px] font-black uppercase tracking-widest",
                                    activeTab === tab ? "text-sky-400" : "text-slate-500"
                                )}>
                                    {tab === 'iso' ? 'ISO 27001' : tab}
                                </span>
                                {activeTab === tab && <div className="w-1.5 h-1.5 rounded-full bg-sky-500 animate-pulse" />}
                            </div>
                            <div className={clsx(
                                "text-sm font-bold transition-colors mb-4",
                                activeTab === tab ? "text-white" : "text-slate-400 group-hover:text-slate-200"
                            )}>
                                {frameworkDetails[tab].name}
                            </div>
                            <div className="flex items-center justify-between mt-auto">
                                <div className="flex items-center gap-1.5">
                                    <div className="h-1 w-12 bg-slate-800 rounded-full overflow-hidden">
                                        <div
                                            className={clsx("h-full rounded-full transition-all duration-1000", activeTab === tab ? "bg-sky-500" : "bg-slate-600")}
                                            style={{ width: `${complianceSummary[tab].percentage}%` }}
                                        />
                                    </div>
                                    <span className="text-[10px] font-mono font-bold text-slate-500">
                                        {complianceSummary[tab].percentage}%
                                    </span>
                                </div>
                                <ChevronRight size={14} className={clsx("transition-transform", activeTab === tab ? "text-sky-400 translate-x-1" : "text-slate-700")} />
                            </div>
                        </button>
                    ))}
                </div>

                {/* Active Framework Deep Dive */}
                <div className="lg:col-span-3 space-y-4">

                    {/* Progress Matrix */}
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div className="card-hover rounded-xl p-5 bg-slate-900/20 border border-slate-800">
                            <div className="flex items-center gap-2 mb-4">
                                <BarChart3 size={16} className="text-sky-400" />
                                <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Global Status</span>
                            </div>
                            <div className="flex items-baseline gap-2">
                                <span className="text-2xl font-black text-white">{stats.percentage}%</span>
                                <span className="text-[10px] font-bold text-emerald-400 uppercase tracking-tighter">Compliant</span>
                            </div>
                            <div className="mt-4 h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                                <div className="h-full bg-sky-500 rounded-full animate-grow-width" style={{ width: `${stats.percentage}%` }} />
                            </div>
                        </div>
                        <div className="card-hover rounded-xl p-5 bg-slate-900/20 border border-slate-800">
                            <div className="flex items-center gap-2 mb-4">
                                <Shield size={16} className="text-emerald-500" />
                                <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Passed Controls</span>
                            </div>
                            <div className="flex items-baseline gap-2">
                                <span className="text-2xl font-black text-white">{stats.pass}</span>
                                <span className="text-sm font-bold text-slate-500 uppercase">/ {current.controls}</span>
                            </div>
                        </div>
                        <div className="card-hover rounded-xl p-5 bg-slate-900/20 border border-slate-800">
                            <div className="flex items-center gap-2 mb-4">
                                <AlertCircle size={16} className="text-red-500" />
                                <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Failed Controls</span>
                            </div>
                            <div className="flex items-baseline gap-2">
                                <span className="text-2xl font-black text-white">{stats.fail}</span>
                                <span className="text-[10px] font-bold text-red-400 uppercase tracking-widest ml-1 animate-pulse">Needs Review</span>
                            </div>
                        </div>
                    </div>

                    {/* Framework Intel Section */}
                    <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-6">
                        <div className="flex items-start justify-between mb-8">
                            <div>
                                <h3 className="text-lg font-bold text-white mb-1">{current.name}</h3>
                                <p className="text-xs text-slate-500 font-medium max-w-xl">{current.description}</p>
                            </div>
                            <div className="text-right">
                                <div className="flex items-center gap-2 text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-1.5">
                                    <Clock size={12} /> Last Ingested: {current.lastAudit}
                                </div>
                                <div className="flex items-center gap-2 text-[10px] font-bold text-slate-500 uppercase tracking-widest">
                                    <Clock size={12} /> Next Review: {current.nextAudit}
                                </div>
                            </div>
                        </div>

                        {/* High-density Control List */}
                        <div className="space-y-3">
                            <div className="flex items-center justify-between px-4 py-2 text-[10px] font-black text-slate-600 uppercase tracking-widest border-b border-slate-800">
                                <span>Control Identifier</span>
                                <div className="flex gap-20">
                                    <span className="w-16">MITRE</span>
                                    <span className="w-24">STATUS</span>
                                </div>
                            </div>

                            {[1, 2, 3, 4, 5].map((i) => (
                                <div key={i} className="group flex items-center justify-between p-4 rounded-lg bg-slate-950/50 border border-slate-900 hover:border-slate-800 hover:bg-slate-900/50 transition-all cursor-pointer">
                                    <div className="flex items-center gap-4">
                                        <div className={clsx(
                                            "w-2 h-2 rounded-full",
                                            i === 2 ? "bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.5)]" : "bg-emerald-500"
                                        )} />
                                        <div>
                                            <div className="text-xs font-bold text-slate-200 group-hover:text-white transition-colors uppercase tracking-tight">
                                                {activeTab.toUpperCase()}-{i === 1 ? 'AC-2' : i === 2 ? 'SC-7' : 'CM-3'} {i === 1 ? 'Account Management' : i === 2 ? 'Boundary Protection' : 'Configuration Change Control'}
                                            </div>
                                            <div className="text-[9px] font-mono text-slate-500 uppercase mt-1">Audit Group: System Architecture</div>
                                        </div>
                                    </div>

                                    <div className="flex items-center gap-12">
                                        <span className="mitre-tag tracking-tighter">T1{100 + i}</span>
                                        <div className="w-24 flex justify-end">
                                            {i === 2 ? (
                                                <div className="flex items-center gap-1.5 text-red-400">
                                                    <AlertCircle size={14} />
                                                    <span className="text-[9px] font-black uppercase tracking-widest">Failed</span>
                                                </div>
                                            ) : (
                                                <div className="flex items-center gap-1.5 text-emerald-400">
                                                    <CheckCircle2 size={14} />
                                                    <span className="text-[9px] font-black uppercase tracking-widest">Passed</span>
                                                </div>
                                            )}
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>

                        <button className="w-full mt-6 flex items-center justify-center gap-2 py-3 rounded-xl border border-slate-800 text-[10px] font-black text-slate-500 hover:text-white hover:bg-slate-800 transition-all uppercase tracking-widest">
                            View All {current.controls} Controls Analysis <ExternalLink size={12} />
                        </button>
                    </div>
                </div>
            </div>

        </div>
    );
}

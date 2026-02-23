'use client';

import { useState, useMemo } from 'react';
import {
    Zap, Shield, CheckCircle2, Clock, AlertTriangle,
    ArrowRight, Play, Eye, FileCode, Check, X,
    Container, Cloud, Key, Network, Database, Terminal
} from 'lucide-react';
import { mockFindings, type Finding } from '@/lib/mock-data';
import { useAppStore } from '@/lib/store';
import clsx from 'clsx';

type RemediationStatus = 'pending' | 'approving' | 'executing' | 'completed' | 'failed';

interface RemediationItem extends Finding {
    remStatus: RemediationStatus;
    approvalLevel: 1 | 2 | 3;
    lastValidated: string;
}

export default function RemediationPage() {
    const { addToast } = useAppStore();
    const [items, setItems] = useState<RemediationItem[]>(
        mockFindings.filter(f => f.remediationCommand || f.remediationTerraform).map(f => ({
            ...f,
            remStatus: 'pending',
            approvalLevel: f.severity === 'critical' ? 3 : f.severity === 'high' ? 2 : 1,
            lastValidated: new Date().toISOString()
        }))
    );

    const [selectedId, setSelectedId] = useState<string | null>(null);

    const activeItem = useMemo(() => items.find(i => i.id === selectedId), [items, selectedId]);

    const updateStatus = (id: string, status: RemediationStatus) => {
        setItems(prev => prev.map(item => item.id === id ? { ...item, remStatus: status } : item));
        setSelectedId(id);
    };

    const handleExecute = (id: string) => {
        updateStatus(id, 'executing');
        addToast('REMEDIATION PIPELINE INITIATED...', 'info');

        setTimeout(() => {
            updateStatus(id, 'completed');
            addToast('REMEDIATION SUCCESS: Patch applied and verified.', 'success');
        }, 3000);
    };

    return (
        <div className="space-y-6 animate-fade-in pb-10">

            {/* Orchestrator Header */}
            <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-6 border-b border-slate-800 pb-6">
                <div className="min-w-0 flex-1">
                    <h2 className="text-2xl font-bold text-white tracking-tight flex items-center gap-3">
                        <Zap size={24} className="text-amber-500 animate-pulse" />
                        Remediation Orchestrator
                    </h2>
                    <p className="text-slate-500 text-xs mt-1 uppercase font-bold tracking-tighter">Unified Approval Workflows & Automated Response Engine</p>
                </div>
                <div className="flex items-center gap-3 overflow-x-auto pb-2 lg:pb-0">
                    <StatBox label="OPEN" count={items.length} color="text-sky-400" />
                    <StatBox label="IN PROGRESS" count={items.filter(i => i.remStatus === 'executing').length} color="text-amber-500" />
                    <StatBox label="VERIFIED" count={items.filter(i => i.remStatus === 'completed').length} color="text-emerald-500" />
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">

                {/* Pending Workspace */}
                <div className="lg:col-span-7 space-y-4">
                    <div className="flex items-center justify-between px-1">
                        <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Active Remediation Queue</span>
                        <div className="flex gap-2 text-[9px] font-bold text-slate-500">
                            <span className="flex items-center gap-1"><div className="w-1.5 h-1.5 rounded-full bg-red-500" /> CRITICAL</span>
                            <span className="flex items-center gap-1"><div className="w-1.5 h-1.5 rounded-full bg-emerald-500" /> VERIFIED</span>
                        </div>
                    </div>

                    <div className="space-y-2 max-h-[700px] overflow-y-auto pr-2 custom-scrollbar">
                        {items.map((item) => (
                            <div
                                key={item.id}
                                onClick={() => setSelectedId(item.id)}
                                className={clsx(
                                    "p-4 rounded-xl border transition-all cursor-pointer relative overflow-hidden group",
                                    selectedId === item.id
                                        ? "bg-slate-800/40 border-sky-500/50"
                                        : "bg-slate-900/20 border-slate-800 hover:border-slate-700 hover:bg-slate-900/40"
                                )}
                            >
                                <div className="flex items-start justify-between gap-4">
                                    <div className="flex-1 min-w-0">
                                        <div className="flex items-center gap-2 mb-1.5">
                                            <span className={clsx("text-[9px] font-black px-1.5 py-0.5 rounded border uppercase", `badge-${item.severity}`)}>
                                                {item.severity}
                                            </span>
                                            <span className="text-[10px] font-mono text-slate-500 uppercase tracking-tighter">ID: {item.id.slice(0, 8)}</span>
                                        </div>
                                        <h4 className="text-xs font-bold text-white mb-1 truncate group-hover:text-sky-400 transition-colors">{item.title}</h4>
                                        <div className="flex items-center gap-3">
                                            <div className="flex items-center gap-1 text-[9px] font-bold text-slate-500 uppercase tracking-widest">
                                                <ResourceIcon type={item.resourceType} />
                                                {item.resource}
                                            </div>
                                            <div className="w-1 h-1 rounded-full bg-slate-800" />
                                            <span className="text-[9px] font-bold text-slate-500 uppercase tracking-widest">APPROVAL L{item.approvalLevel}</span>
                                        </div>
                                    </div>

                                    <div className="text-right flex-shrink-0">
                                        {item.remStatus === 'completed' ? (
                                            <div className="flex items-center gap-1.5 text-emerald-400">
                                                <CheckCircle2 size={14} />
                                                <span className="text-[10px] font-black uppercase tracking-widest">Patched</span>
                                            </div>
                                        ) : item.remStatus === 'executing' ? (
                                            <div className="flex items-center gap-1.5 text-amber-500 animate-pulse">
                                                <Clock size={14} />
                                                <span className="text-[10px] font-black uppercase tracking-widest">Applying</span>
                                            </div>
                                        ) : (
                                            <button
                                                onClick={(e) => { e.stopPropagation(); handleExecute(item.id); }}
                                                className="px-3 py-1.5 rounded bg-sky-500 text-slate-950 text-[10px] font-black uppercase tracking-widest hover:bg-sky-400 transition-all shadow-[0_0_10px_rgba(58,189,248,0.2)]"
                                            >
                                                Deploy
                                            </button>
                                        )}
                                    </div>
                                </div>
                                {selectedId === item.id && <div className="absolute left-0 top-0 bottom-0 w-1 bg-sky-500 shadow-[0_0_10px_rgba(56,189,248,0.5)]" />}
                            </div>
                        ))}
                    </div>
                </div>

                {/* Execution Detail Panel */}
                <div className="lg:col-span-5">
                    {activeItem ? (
                        <div className="h-full flex flex-col rounded-xl border border-slate-800 bg-slate-900/40 overflow-hidden glass shadow-2xl sticky top-6">
                            <div className="p-6 border-b border-slate-800 bg-slate-900/60">
                                <div className="flex items-center justify-between mb-4">
                                    <span className="text-[10px] font-black text-sky-400 uppercase tracking-widest flex items-center gap-2">
                                        <Eye size={14} />
                                        Remediation Intel
                                    </span>
                                    {activeItem.remStatus === 'pending' && (
                                        <span className="text-[9px] font-bold text-red-400 bg-red-400/10 px-2 py-0.5 rounded border border-red-400/20 uppercase tracking-widest animate-pulse">
                                            Awaiting Approval
                                        </span>
                                    )}
                                </div>
                                <h3 className="text-sm font-bold text-white mb-2 leading-tight">{activeItem.title}</h3>
                                <p className="text-xs text-slate-500 font-medium leading-relaxed">{activeItem.description}</p>
                            </div>

                            <div className="flex-1 overflow-y-auto p-6 space-y-6">
                                {/* Validation Box */}
                                <div className="p-4 rounded-lg bg-slate-950/80 border border-slate-800">
                                    <div className="flex items-center justify-between mb-4">
                                        <div className="flex items-center gap-2">
                                            <Shield size={14} className="text-sky-400" />
                                            <span className="text-[10px] font-black text-white uppercase tracking-widest tracking-tighter">Pre-flight Validation</span>
                                        </div>
                                        <div className="flex items-center gap-1 text-[9px] font-bold text-emerald-500 uppercase">
                                            <CheckCircle2 size={12} />
                                            Target Reachable
                                        </div>
                                    </div>
                                    <div className="space-y-2">
                                        <ValidationPoint label="Namespace Isolation" status="pass" />
                                        <ValidationPoint label="Privilege Level" status="pass" />
                                        <ValidationPoint label="IaC Consistency" status="warn" msg="Partial Drift Detected" />
                                    </div>
                                </div>

                                {/* Script / IaC Preview */}
                                <div className="space-y-4">
                                    <div className="flex items-center justify-between">
                                        <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Remediation Manifest</span>
                                        <div className="flex gap-2">
                                            <span className="text-[9px] font-bold text-sky-500 bg-sky-500/10 px-1.5 py-0.5 rounded border border-sky-500/20 uppercase">Bash</span>
                                            <span className="text-[9px] font-bold text-slate-500 bg-slate-800 px-1.5 py-0.5 rounded border border-slate-700 uppercase">HCL</span>
                                        </div>
                                    </div>
                                    <div className="rounded-lg bg-slate-950 border border-slate-800 overflow-hidden font-mono text-[11px]">
                                        <div className="p-3 border-b border-slate-900 bg-slate-900/40 text-[9px] font-bold text-slate-500 flex items-center gap-2">
                                            <FileCode size={12} /> execution_payload.sh
                                        </div>
                                        <pre className="p-4 text-sky-300 leading-relaxed overflow-x-auto">
                                            <code>{activeItem.remediationCommand || "// No automated command available"}</code>
                                        </pre>
                                    </div>
                                </div>
                            </div>

                            <div className="p-6 border-t border-slate-800 bg-slate-900/60 flex items-center justify-between gap-4">
                                <button className="flex-1 py-2.5 rounded-lg border border-slate-800 text-[10px] font-black text-slate-500 hover:text-white hover:bg-slate-800 transition-all uppercase tracking-widest">
                                    Modify Plan
                                </button>
                                <button
                                    onClick={() => handleExecute(activeItem.id)}
                                    disabled={activeItem.remStatus !== 'pending'}
                                    className="flex-1 py-2.5 rounded-lg bg-sky-500 text-slate-950 text-[10px] font-black uppercase tracking-widest hover:bg-sky-400 transition-all shadow-[0_0_20px_rgba(58,189,248,0.2)] disabled:opacity-50"
                                >
                                    Approve & Execute
                                </button>
                            </div>
                        </div>
                    ) : (
                        <div className="h-full flex flex-col items-center justify-center p-10 text-center rounded-xl border border-dashed border-slate-800 bg-slate-900/10">
                            <Zap size={48} className="text-slate-800 mb-6" />
                            <h3 className="text-lg font-bold text-slate-400 uppercase tracking-widest mb-2">Select a Candidate</h3>
                            <p className="text-[10px] text-slate-600 font-bold uppercase tracking-tighter max-w-xs">
                                Review pending remediation candidates from the orchestral queue to initiate approval cycles.
                            </p>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}

// ─── UI Helpers ──────────────────────────────────────────────────────────────

function StatBox({ label, count, color }: { label: string; count: number; color: string }) {
    return (
        <div className="px-5 py-2.5 rounded-xl border border-slate-800 bg-slate-900/40 flex flex-col items-center min-w-[100px]">
            <span className="text-[9px] font-black text-slate-500 uppercase tracking-widest mb-1">{label}</span>
            <span className={clsx("text-xl font-black", color)}>{count}</span>
        </div>
    );
}

function ResourceIcon({ type }: { type: string }) {
    switch (type) {
        case 'compute': return <Container size={12} />;
        case 'storage': return <Database size={12} />;
        case 'network': return <Network size={12} />;
        case 'iam': return <Key size={12} />;
        default: return <Shield size={12} />;
    }
}

function ValidationPoint({ label, status, msg }: { label: string; status: 'pass' | 'warn' | 'fail'; msg?: string }) {
    return (
        <div className="flex items-center justify-between text-[10px] font-bold">
            <span className="text-slate-400 uppercase tracking-tight">{label}</span>
            <div className="flex items-center gap-2">
                {msg && <span className={clsx("text-[8px] uppercase tracking-tighter", status === 'warn' ? "text-amber-500" : "text-red-500")}>{msg}</span>}
                {status === 'pass' ? <Check size={12} className="text-emerald-500" /> : status === 'warn' ? <AlertTriangle size={12} className="text-amber-500" /> : <X size={12} className="text-red-500" />}
            </div>
        </div>
    );
}

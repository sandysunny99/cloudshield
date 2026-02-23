'use client';

import { useState } from 'react';
import {
    Radar, Search, Terminal, Zap, Shield,
    ChevronRight, Save, Filter, Activity,
    Globe, Cpu, Database, AlertCircle, Sparkles
} from 'lucide-react';
import { threatIntel } from '@/lib/mock-data';
import { useAppStore } from '@/lib/store';
import clsx from 'clsx';

export default function HuntingPage() {
    const { addToast } = useAppStore();
    const [query, setQuery] = useState('');
    const [isHunting, setIsHunting] = useState(false);

    const handleHunt = () => {
        if (!query.trim()) return;
        setIsHunting(true);
        addToast('EXECUTING HEURISTIC THREAT CROSS-CORRELATION...', 'info');
        setTimeout(() => {
            setIsHunting(false);
            addToast('HUNT COMPLETE: No active lateral movement detected in selected cluster.', 'success');
        }, 3000);
    };

    return (
        <div className="space-y-6 animate-fade-in pb-10">

            {/* Hunting Header */}
            <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b border-slate-800 pb-6 mb-2">
                <div>
                    <h2 className="text-2xl font-bold text-white tracking-tight flex items-center gap-3">
                        <Radar size={24} className="text-red-500 animate-pulse" />
                        Threat Hunting Workspace
                    </h2>
                    <p className="text-slate-500 text-sm mt-1 uppercase font-bold tracking-tighter">Proactive Anomaly Correlation & Lateral Movement Detection</p>
                </div>
                <div className="flex items-center gap-3">
                    <span className="text-[10px] font-bold text-emerald-400 bg-emerald-400/10 px-3 py-1 rounded-full border border-emerald-400/20 uppercase tracking-widest">
                        Heuristic Engine: 4.2.1
                    </span>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">

                {/* Query Interface */}
                <div className="lg:col-span-3 space-y-4">
                    <div className="rounded-xl border border-slate-800 bg-slate-900/20 shadow-2xl overflow-hidden glass">
                        <div className="px-6 py-4 border-b border-slate-800 bg-slate-900/60 flex items-center justify-between">
                            <div className="flex items-center gap-2">
                                <Terminal size={14} className="text-sky-400" />
                                <span className="text-[10px] font-black text-white uppercase tracking-widest">Sentinel Query (S3QL)</span>
                            </div>
                            <div className="flex gap-2">
                                {['BEHAVIORAL', 'NETWORK', 'IDENTITY'].map(m => (
                                    <span key={m} className="text-[8px] font-bold text-slate-500 bg-slate-950 px-1.5 py-0.5 rounded border border-slate-900">{m}</span>
                                ))}
                            </div>
                        </div>
                        <div className="p-0 relative">
                            <textarea
                                value={query}
                                onChange={(e) => setQuery(e.target.value)}
                                placeholder="SELECT * FROM cluster_events WHERE event_type = 'LateralMovement' AND source_ip IN malicious_reputation..."
                                className="w-full h-40 bg-slate-950/80 p-6 text-sm font-mono text-sky-400 placeholder:text-slate-700 outline-none resize-none"
                            />
                            <div className="absolute bottom-4 right-4 flex items-center gap-3">
                                <button className="text-[10px] font-bold text-slate-500 hover:text-white uppercase tracking-widest transition-colors">Clear</button>
                                <button
                                    onClick={handleHunt}
                                    disabled={!query.trim() || isHunting}
                                    className="bg-red-500 hover:bg-red-400 text-slate-950 px-6 py-2 rounded-lg text-xs font-black uppercase tracking-widest flex items-center gap-2 transition-all shadow-[0_0_20px_rgba(239,68,68,0.2)] disabled:opacity-50"
                                >
                                    {isHunting ? <Activity size={14} className="animate-spin" /> : <Zap size={14} />}
                                    {isHunting ? 'CORRELATING...' : 'EXECUTE HUNT'}
                                </button>
                            </div>
                        </div>
                    </div>

                    {/* Hunt Results Placeholder */}
                    <div className="rounded-xl border border-slate-800 bg-slate-900/10 min-h-[300px] flex flex-col items-center justify-center p-10 text-center relative overflow-hidden">
                        <div className="absolute inset-0 bg-cyber-grid opacity-20" />
                        {!isHunting && !query ? (
                            <div className="relative z-10">
                                <Search size={48} className="text-slate-800 mx-auto mb-6" />
                                <h3 className="text-lg font-bold text-slate-400 uppercase tracking-widest mb-2">No Active Pipeline</h3>
                                <p className="text-[10px] text-slate-600 font-bold uppercase tracking-tighter max-w-xs mx-auto">
                                    Input a query or select a preset hunter package to begin real-time data correlation.
                                </p>
                            </div>
                        ) : isHunting ? (
                            <div className="relative z-10 w-full max-w-md space-y-4">
                                <div className="flex items-center justify-between text-[10px] font-mono font-bold text-sky-500 uppercase px-1">
                                    <span>Scanning Cluster Telemetry...</span>
                                    <span>{Math.floor(Math.random() * 100)}%</span>
                                </div>
                                <div className="h-1 w-full bg-slate-800 rounded-full overflow-hidden">
                                    <div className="h-full bg-sky-500 animate-[grow-width_3s_ease-in-out_infinite]" />
                                </div>
                                <div className="p-4 rounded-lg bg-slate-950 border border-slate-900 text-left font-mono text-[10px] text-slate-500 space-y-1">
                                    <p>[SENTINEL] Ingesting VPC Flow Logs...</p>
                                    <p>[SENTINEL] Correlating with MITRE T1078...</p>
                                    <p>[SENTINEL] Mapping threat actors: APT28, APT29...</p>
                                </div>
                            </div>
                        ) : (
                            <div className="relative z-10 w-full animate-fade-in">
                                <div className="flex items-center gap-3 justify-center mb-6">
                                    <Sparkles size={20} className="text-emerald-500" />
                                    <h3 className="text-lg font-bold text-emerald-400 uppercase tracking-widest">Hunt Result: Baseline Clean</h3>
                                </div>
                                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                                    {[
                                        { l: 'EVENTS ANALYZED', v: '1.2M' },
                                        { l: 'ANOMALIES', v: '0' },
                                        { l: 'CORRELATION DEPTH', v: '83%' },
                                        { l: 'THREAT MATCHES', v: '0' },
                                    ].map((s, i) => (
                                        <div key={i} className="p-4 rounded-xl border border-slate-800 bg-slate-900/60 text-center">
                                            <div className="text-[9px] font-black text-slate-500 uppercase tracking-widest mb-1">{s.l}</div>
                                            <div className="text-lg font-black text-white">{s.v}</div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                </div>

                {/* Intel Side-panel */}
                <div className="space-y-4">
                    <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-5">
                        <div className="flex items-center gap-2 mb-4 border-b border-slate-800 pb-3">
                            <Activity size={14} className="text-sky-400" />
                            <span className="text-[10px] font-black text-white uppercase tracking-widest">Active Hunter Packages</span>
                        </div>
                        <div className="space-y-2">
                            {[
                                { n: 'Lateral Movement Detection', active: true },
                                { n: 'Exfiltration Heuristics', active: true },
                                { n: 'Beaconing Pattern Analysis', active: false },
                                { n: 'DGA Domain Correlation', active: false },
                            ].map((p, i) => (
                                <div key={i} className="flex items-center justify-between p-2 rounded border border-slate-800 bg-slate-950/50">
                                    <span className="text-[9px] font-bold text-slate-400 uppercase tracking-tight">{p.n}</span>
                                    <div className={clsx("w-1.5 h-1.5 rounded-full", p.active ? "bg-emerald-500 shadow-[0_0_5px_rgba(16,185,129,0.5)]" : "bg-slate-700")} />
                                </div>
                            ))}
                        </div>
                    </div>

                    <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-5">
                        <div className="flex items-center gap-2 mb-4 border-b border-slate-800 pb-3">
                            <Shield size={14} className="text-red-500" />
                            <span className="text-[10px] font-black text-white uppercase tracking-widest">IOC Match Watchlist</span>
                        </div>
                        <div className="space-y-3">
                            {threatIntel.slice(0, 3).map((intel) => (
                                <div key={intel.id} className="group">
                                    <div className="flex items-center justify-between mb-1">
                                        <span className="text-[9px] font-mono text-slate-400 truncate w-32">{intel.value}</span>
                                        <span className="text-[8px] font-bold text-red-400">HIGH RISK</span>
                                    </div>
                                    <div className="h-1 w-full bg-slate-800 rounded-full overflow-hidden">
                                        <div className="h-full bg-red-500/50" style={{ width: '85%' }} />
                                    </div>
                                </div>
                            ))}
                        </div>
                        <button className="w-full mt-6 text-[9px] font-black text-slate-500 hover:text-white uppercase tracking-widest transition-colors py-2 border border-slate-800 rounded-lg">Update Intelligence</button>
                    </div>
                </div>
            </div>

        </div>
    );
}

'use client';

import { useState, useMemo, Fragment } from 'react';
import { mockFindings, type Finding, type Severity, type ResourceType, type FindingStatus } from '@/lib/mock-data';
import { useAppStore } from '@/lib/store';
import { Search, Filter, X, ChevronDown, ChevronUp, Terminal, Code2, ShieldAlert, Cpu, Database, Globe, Lock, Info } from 'lucide-react';
import clsx from 'clsx';

const severities: Severity[] = ['critical', 'high', 'medium', 'low'];
const resources: ResourceType[] = ['container', 'storage', 'iam', 'network', 'compute'];
const statuses: FindingStatus[] = ['open', 'in_progress', 'resolved'];

const statusMeta: Record<FindingStatus, { color: string; label: string }> = {
    open: { color: '#ef4444', label: 'ACTIVE' },
    in_progress: { color: '#38bdf8', label: 'INVESTIGATING' },
    resolved: { color: '#10b981', label: 'PATCHED' },
};

type SortKey = 'riskScore' | 'severity' | 'discoveredAt' | 'status';

export default function ScansPage() {
    const { addToast } = useAppStore();
    const [search, setSearch] = useState('');
    const [selSeverity, setSelSeverity] = useState<Severity[]>([]);
    const [selResource, setSelResource] = useState<ResourceType[]>([]);
    const [selStatus, setSelStatus] = useState<FindingStatus[]>([]);
    const [sortKey, setSortKey] = useState<SortKey>('riskScore');
    const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
    const [expanded, setExpanded] = useState<string | null>(null);

    const toggle = <T,>(arr: T[], val: T): T[] =>
        arr.includes(val) ? arr.filter(v => v !== val) : [...arr, val];

    const filtered = useMemo(() => {
        let list = mockFindings;
        if (search) list = list.filter(f =>
            f.title.toLowerCase().includes(search.toLowerCase()) ||
            f.resource.toLowerCase().includes(search.toLowerCase()) ||
            f.cve?.toLowerCase().includes(search.toLowerCase()) ||
            f.tags.some(t => t.includes(search.toLowerCase()))
        );
        if (selSeverity.length) list = list.filter(f => selSeverity.includes(f.severity));
        if (selResource.length) list = list.filter(f => selResource.includes(f.resourceType));
        if (selStatus.length) list = list.filter(f => selStatus.includes(f.status));

        return [...list].sort((a, b) => {
            const sevOrder: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };
            let cmp = 0;
            if (sortKey === 'riskScore') cmp = a.riskScore - b.riskScore;
            else if (sortKey === 'severity') cmp = sevOrder[a.severity] - sevOrder[b.severity];
            else if (sortKey === 'discoveredAt') cmp = new Date(a.discoveredAt).getTime() - new Date(b.discoveredAt).getTime();
            else if (sortKey === 'status') cmp = a.status.localeCompare(b.status);
            return sortDir === 'desc' ? -cmp : cmp;
        });
    }, [search, selSeverity, selResource, selStatus, sortKey, sortDir]);

    const handleSort = (key: SortKey) => {
        if (sortKey === key) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
        else { setSortKey(key); setSortDir('desc'); }
    };

    return (
        <div className="flex gap-6 animate-fade-in relative">

            {/* Intel Filters Sidebar */}
            <aside className="w-64 flex-shrink-0 sticky top-22 h-fit">
                <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-5 space-y-6">
                    <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                        <span className="text-[11px] font-black uppercase tracking-widest text-white flex items-center gap-2">
                            <Filter size={14} className="text-sky-400" />
                            INTEL FILTERS
                        </span>
                        {(selSeverity.length || selResource.length || selStatus.length) ? (
                            <button
                                onClick={() => { setSelSeverity([]); setSelResource([]); setSelStatus([]); }}
                                className="text-[10px] font-bold text-red-400 hover:text-red-300 transition-colors uppercase"
                            >RESET</button>
                        ) : null}
                    </div>

                    <FilterGroup label="Severity" items={severities} selected={selSeverity}
                        onToggle={v => setSelSeverity(toggle(selSeverity, v))} />

                    <FilterGroup label="Telemetry Type" items={resources} selected={selResource}
                        onToggle={v => setSelResource(toggle(selResource, v))} />

                    <FilterGroup label="Incident Status" items={statuses} selected={selStatus}
                        onToggle={v => setSelStatus(toggle(selStatus, v))} />

                    <div className="h-4" />
                    <div className="pt-4 border-t border-slate-800">
                        <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-3">Live Fleet Stats</p>
                        <div className="space-y-2">
                            {severities.map(s => (
                                <div key={s} className="flex items-center justify-between">
                                    <span className="text-[110px] font-bold text-slate-400 uppercase text-[10px]">{s}</span>
                                    <span className={clsx("text-[10px] font-mono font-bold px-1.5 rounded", `badge-${s}`)}>
                                        {mockFindings.filter(f => f.severity === s).length}
                                    </span>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            </aside>

            {/* Analysis Center */}
            <div className="flex-1 min-w-0 space-y-4">
                {/* Global Intel Search */}
                <div className="flex items-center gap-3 px-4 py-3 rounded-xl border border-slate-800 bg-slate-900/60 group focus-within:border-sky-500/50 transition-all shadow-2xl">
                    <Search size={16} className="text-slate-500 group-focus-within:text-sky-400 transition-colors" />
                    <input
                        value={search}
                        onChange={e => setSearch(e.target.value)}
                        placeholder="SEARCH INTELLIGENCE: CVE, RESOURCE, TAG OR MITRE ID..."
                        className="flex-1 text-[11px] font-bold bg-transparent outline-none text-white placeholder:text-slate-600 tracking-wider"
                    />
                    {search && <button onClick={() => setSearch('')}><X size={14} className="text-slate-500 hover:text-white" /></button>}
                </div>

                <div className="flex items-center justify-between text-[10px] uppercase font-bold tracking-widest text-slate-500 px-1">
                    <div>FOUND: {filtered.length} INCIDENTS</div>
                    <div className="text-sky-500">REAL-TIME TELEMETRY ACTIVE</div>
                </div>

                {/* Cyber Table */}
                <div className="rounded-xl border border-slate-800 bg-slate-900/20 overflow-hidden shadow-2xl backdrop-blur-sm">
                    <table className="w-full text-left border-collapse">
                        <thead>
                            <tr className="bg-slate-900/80 border-b border-slate-800">
                                {[
                                    { k: 'severity' as SortKey, label: 'SEVERITY', w: 'w-28' },
                                    { k: null, label: 'INCIDENT DETAILS', w: 'flex-1' },
                                    { k: null, label: 'RESOURCE', w: 'w-48' },
                                    { k: 'riskScore' as SortKey, label: 'RISK', w: 'w-20' },
                                    { k: 'status' as SortKey, label: 'STATUS', w: 'w-32' },
                                    { k: 'discoveredAt' as SortKey, label: 'DETECTED', w: 'w-28' },
                                    { k: null, label: '', w: 'w-10' },
                                ].map((col, i) => (
                                    <th
                                        key={i}
                                        className={clsx('px-4 py-4 text-[10px] font-black tracking-widest text-slate-400', col.w, col.k && 'cursor-pointer hover:text-white transition-colors')}
                                        onClick={() => col.k && handleSort(col.k)}
                                    >
                                        <div className="flex items-center gap-1.5">
                                            {col.label}
                                            {col.k === sortKey && (sortDir === 'desc' ? <ChevronDown size={10} /> : <ChevronUp size={10} />)}
                                        </div>
                                    </th>
                                ))}
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/50">
                            {filtered.map((f) => (
                                <Fragment key={f.id}>
                                    <tr
                                        className={clsx(
                                            "cursor-pointer transition-all hover:bg-slate-800/30",
                                            expanded === f.id ? "bg-slate-800/40" : "bg-transparent"
                                        )}
                                        onClick={() => setExpanded(expanded === f.id ? null : f.id)}
                                    >
                                        <td className="px-4 py-4">
                                            <span className={clsx('px-2 py-0.5 rounded text-[9px] font-black tracking-tighter border capitalize', `badge-${f.severity}`)}>
                                                {f.severity}
                                            </span>
                                        </td>
                                        <td className="px-4 py-4">
                                            <div className="flex items-center gap-2">
                                                {f.cve && <span className="text-[10px] font-bold font-mono text-sky-400">[{f.cve}]</span>}
                                                <span className="text-xs font-bold text-slate-100">{f.title}</span>
                                            </div>
                                            <div className="flex items-center gap-2 mt-1.5">
                                                {f.mitre && (
                                                    <span className="mitre-tag text-[9px] font-bold border-sky-500/30 text-sky-400/80 uppercase">
                                                        {f.mitre.id}: {f.mitre.technique}
                                                    </span>
                                                )}
                                                <div className="flex gap-1.5">
                                                    {f.tags.slice(0, 2).map(t => (
                                                        <span key={t} className="text-[9px] font-bold text-slate-500 uppercase tracking-tighter">#{t}</span>
                                                    ))}
                                                </div>
                                            </div>
                                        </td>
                                        <td className="px-4 py-4">
                                            <div className="flex items-center gap-2">
                                                <AssetIcon type={f.resourceType} />
                                                <span className="text-[10px] font-mono text-slate-400 truncate max-w-[140px]">{f.resource}</span>
                                            </div>
                                        </td>
                                        <td className="px-4 py-4">
                                            <span className="text-xs font-black font-mono" style={{ color: f.riskScore >= 9 ? '#ef4444' : f.riskScore >= 7 ? '#f59e0b' : '#10b981' }}>
                                                {f.riskScore.toFixed(1)}
                                            </span>
                                        </td>
                                        <td className="px-4 py-4">
                                            <div className="flex items-center gap-2">
                                                <div className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ background: statusMeta[f.status].color }} />
                                                <span className="text-[9px] font-black uppercase tracking-widest" style={{ color: statusMeta[f.status].color }}>
                                                    {statusMeta[f.status].label}
                                                </span>
                                            </div>
                                        </td>
                                        <td className="px-4 py-4 text-[10px] font-bold text-slate-500 font-mono uppercase">
                                            {new Date(f.discoveredAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false })}
                                        </td>
                                        <td className="px-4 py-4 text-slate-600">
                                            {expanded === f.id ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                                        </td>
                                    </tr>
                                    {expanded === f.id && (
                                        <tr key={f.id + '-exp'} className="bg-slate-900/60 border-b border-slate-800/80">
                                            <td colSpan={7} className="px-10 py-8">
                                                <FindingDetail finding={f} onToast={addToast} />
                                            </td>
                                        </tr>
                                    )}
                                </Fragment>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
}

// ─── Sub-components ──────────────────────────────────────────────────────────

function AssetIcon({ type }: { type: ResourceType }) {
    switch (type) {
        case 'compute': return <Cpu size={12} className="text-slate-400" />;
        case 'storage': return <Database size={12} className="text-slate-400" />;
        case 'network': return <Globe size={12} className="text-slate-400" />;
        case 'iam': return <Lock size={12} className="text-slate-400" />;
        case 'container': return <ShieldAlert size={12} className="text-slate-400" />;
        default: return null;
    }
}

function FilterGroup<T extends string>({
    label, items, selected, onToggle,
}: { label: string; items: T[]; selected: T[]; onToggle: (v: T) => void }) {
    return (
        <div className="space-y-3">
            <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">{label}</p>
            <div className="space-y-2">
                {items.map(item => (
                    <label key={item} className="flex items-center gap-2.5 cursor-pointer group">
                        <input
                            type="checkbox"
                            checked={selected.includes(item)}
                            onChange={() => onToggle(item)}
                            className="hidden"
                        />
                        <div className={clsx(
                            "w-3.5 h-3.5 rounded border border-slate-700 transition-all flex items-center justify-center",
                            selected.includes(item) ? "bg-sky-500 border-sky-500" : "bg-slate-950 group-hover:border-slate-500"
                        )}>
                            {selected.includes(item) && <X size={10} className="text-slate-950" />}
                        </div>
                        <span className={clsx(
                            "text-[11px] font-bold uppercase transition-colors tracking-tight",
                            selected.includes(item) ? "text-slate-100" : "text-slate-500 group-hover:text-slate-300"
                        )}>
                            {item.replace('_', ' ')}
                        </span>
                    </label>
                ))}
            </div>
        </div>
    );
}

function FindingDetail({ finding: f, onToast }: { finding: Finding; onToast: (msg: string, t?: 'success' | 'error' | 'info') => void }) {
    const copy = (text: string, label: string) => {
        navigator.clipboard.writeText(text);
        onToast(`TELEMETRY: ${label.toUpperCase()} SECURED TO CLIPBOARD`, 'success');
    };

    return (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-10 animate-fade-in">
            <div className="space-y-6">
                <div>
                    <div className="flex items-center gap-2 mb-3">
                        <Info size={14} className="text-sky-400" />
                        <h3 className="text-[11px] font-black text-white uppercase tracking-widest">Incident Intelligence</h3>
                    </div>
                    <p className="text-xs leading-relaxed text-slate-400 font-medium">{f.description}</p>
                </div>

                <div className="grid grid-cols-2 gap-4">
                    <div className="p-3 rounded bg-slate-950 border border-slate-800">
                        <p className="text-[9px] font-bold text-slate-500 uppercase tracking-widest mb-1">CVSS BASE</p>
                        <p className="text-sm font-black text-white">{f.cvssScore ?? 'N/A'}</p>
                    </div>
                    <div className="p-3 rounded bg-slate-950 border border-slate-800">
                        <p className="text-[9px] font-bold text-slate-500 uppercase tracking-widest mb-1">DETECTED BY</p>
                        <p className="text-sm font-black text-sky-400">SENTINEL-TRIVY</p>
                    </div>
                </div>

                <div className="space-y-3">
                    <p className="text-[9px] font-bold text-slate-500 uppercase tracking-widest">Compliance Mapping</p>
                    <div className="flex flex-wrap gap-2">
                        {f.framework.map(fw => (
                            <span key={fw} className="px-2 py-0.5 rounded bg-slate-800 text-[9px] font-black text-slate-300 uppercase border border-slate-700">{fw}-CONTROL</span>
                        ))}
                    </div>
                </div>
            </div>

            <div className="space-y-4">
                <div className="flex items-center gap-2 mb-1">
                    <Terminal size={14} className="text-emerald-400" />
                    <h3 className="text-[11px] font-black text-white uppercase tracking-widest">Remediation Telemetry</h3>
                </div>
                {f.remediationCommand && (
                    <CodeSnippet title="EXEC CLI PATH" icon={<Terminal size={12} />} code={f.remediationCommand} onCopy={() => copy(f.remediationCommand!, 'CLI payload')} />
                )}
                {f.remediationTerraform && (
                    <CodeSnippet title="IAC PATCH POLICY" icon={<Code2 size={12} />} code={f.remediationTerraform} onCopy={() => copy(f.remediationTerraform!, 'Terraform manifest')} />
                )}
            </div>
        </div>
    );
}

function CodeSnippet({ title, icon, code, onCopy }: { title: string; icon: React.ReactNode; code: string; onCopy: () => void }) {
    return (
        <div className="rounded-lg border border-slate-800 overflow-hidden bg-slate-950 group">
            <div className="flex items-center justify-between px-3 py-2 border-b border-slate-800 bg-slate-900/40">
                <span className="flex items-center gap-1.5 text-[10px] font-black text-slate-500 uppercase tracking-widest">{icon}{title}</span>
                <button onClick={onCopy} className="text-[9px] font-black text-sky-400 hover:text-sky-300 transition-colors uppercase tracking-widest">COPY INTEL</button>
            </div>
            <pre className="text-[11px] p-4 overflow-x-auto leading-relaxed text-slate-300 font-mono group-hover:text-white transition-colors">
                <code>{code}</code>
            </pre>
        </div>
    );
}

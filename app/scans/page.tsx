'use client';

import { useState, useMemo, Fragment } from 'react';
import { mockFindings, type Finding, type Severity, type ResourceType, type FindingStatus } from '@/lib/mock-data';
import { useAppStore } from '@/lib/store';
import { Search, Filter, X, ChevronDown, ChevronUp, ExternalLink, Terminal, Code2 } from 'lucide-react';
import clsx from 'clsx';

const severities: Severity[] = ['critical', 'high', 'medium', 'low'];
const resources: ResourceType[] = ['container', 'storage', 'iam', 'network', 'compute'];
const statuses: FindingStatus[] = ['open', 'in_progress', 'resolved'];

const sevColors: Record<Severity, string> = {
    critical: '#FF6B6B', high: '#F2994A', medium: '#F7D228', low: '#27AE60',
};
const statusColors: Record<FindingStatus, { bg: string; text: string; label: string }> = {
    open: { bg: 'rgba(255,107,107,0.12)', text: '#FF6B6B', label: 'Open' },
    in_progress: { bg: 'rgba(45,156,219,0.12)', text: '#2D9CDB', label: 'In Progress' },
    resolved: { bg: 'rgba(39,174,96,0.12)', text: '#27AE60', label: 'Resolved' },
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

    const SortIcon = ({ k }: { k: SortKey }) =>
        sortKey === k
            ? sortDir === 'desc' ? <ChevronDown size={12} /> : <ChevronUp size={12} />
            : null;

    return (
        <div className="max-w-7xl mx-auto flex gap-5 animate-fade-in">

            {/* Filter sidebar */}
            <aside className="w-56 flex-shrink-0 space-y-4">
                <div className="rounded-2xl border p-4 space-y-4" style={{ background: 'var(--card)', borderColor: 'var(--border)' }}>
                    <div className="flex items-center justify-between">
                        <span className="text-sm font-semibold flex items-center gap-1.5" style={{ color: 'var(--text)' }}>
                            <Filter size={13} /> Filters
                        </span>
                        {(selSeverity.length || selResource.length || selStatus.length) ? (
                            <button
                                onClick={() => { setSelSeverity([]); setSelResource([]); setSelStatus([]); }}
                                className="text-xs text-[#FF6B6B] hover:underline flex items-center gap-0.5"
                            ><X size={10} /> Clear</button>
                        ) : null}
                    </div>

                    <FilterGroup label="Severity" items={severities} selected={selSeverity}
                        onToggle={v => setSelSeverity(toggle(selSeverity, v))}
                        colors={sevColors} />
                    <FilterGroup label="Resource Type" items={resources} selected={selResource}
                        onToggle={v => setSelResource(toggle(selResource, v))} />
                    <FilterGroup label="Status" items={statuses} selected={selStatus}
                        onToggle={v => setSelStatus(toggle(selStatus, v))} />
                </div>

                {/* Summary */}
                <div className="rounded-2xl border p-4" style={{ background: 'var(--card)', borderColor: 'var(--border)' }}>
                    <p className="text-xs font-semibold mb-2" style={{ color: 'var(--text-muted)' }}>SUMMARY</p>
                    {severities.map(s => (
                        <div key={s} className="flex items-center justify-between py-1">
                            <div className="flex items-center gap-1.5">
                                <span className="w-2 h-2 rounded-full" style={{ background: sevColors[s] }} />
                                <span className="text-xs capitalize" style={{ color: 'var(--text)' }}>{s}</span>
                            </div>
                            <span className="text-xs font-semibold" style={{ color: sevColors[s] }}>
                                {mockFindings.filter(f => f.severity === s).length}
                            </span>
                        </div>
                    ))}
                </div>
            </aside>

            {/* Main table */}
            <div className="flex-1 min-w-0 space-y-4">
                {/* Search */}
                <div className="flex items-center gap-3 px-4 py-2.5 rounded-xl border" style={{ background: 'var(--card)', borderColor: 'var(--border)' }}>
                    <Search size={15} style={{ color: 'var(--text-muted)' }} />
                    <input
                        value={search}
                        onChange={e => setSearch(e.target.value)}
                        placeholder="Search by title, resource, CVE, or tag..."
                        className="flex-1 text-sm bg-transparent outline-none"
                        style={{ color: 'var(--text)' }}
                    />
                    {search && <button onClick={() => setSearch('')}><X size={13} style={{ color: 'var(--text-muted)' }} /></button>}
                </div>

                <div className="text-xs" style={{ color: 'var(--text-muted)' }}>
                    Showing <strong>{filtered.length}</strong> of {mockFindings.length} findings
                </div>

                {/* Table */}
                <div className="rounded-2xl border overflow-hidden" style={{ background: 'var(--card)', borderColor: 'var(--border)' }}>
                    <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                            <thead>
                                <tr style={{ background: 'var(--bg)', borderBottom: '1px solid var(--border)' }}>
                                    {[
                                        { k: 'severity' as SortKey, label: 'Severity' },
                                        { k: null, label: 'Finding' },
                                        { k: null, label: 'Resource' },
                                        { k: 'riskScore' as SortKey, label: 'Risk' },
                                        { k: 'status' as SortKey, label: 'Status' },
                                        { k: 'discoveredAt' as SortKey, label: 'Discovered' },
                                        { k: null, label: '' },
                                    ].map((col, i) => (
                                        <th
                                            key={i}
                                            className={clsx('px-4 py-3 text-left text-xs font-semibold', col.k && 'cursor-pointer hover:opacity-70')}
                                            style={{ color: 'var(--text-muted)' }}
                                            onClick={() => col.k && handleSort(col.k)}
                                        >
                                            <span className="flex items-center gap-1">
                                                {col.label}
                                                {col.k && <SortIcon k={col.k} />}
                                            </span>
                                        </th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody>
                                {filtered.map((f) => (
                                    <Fragment key={f.id}>
                                        <tr
                                            key={f.id}
                                            className="border-b cursor-pointer transition-colors hover:opacity-80"
                                            style={{ borderColor: 'var(--border)', background: expanded === f.id ? 'var(--bg)' : 'transparent' }}
                                            onClick={() => setExpanded(expanded === f.id ? null : f.id)}
                                        >
                                            <td className="px-4 py-3">
                                                <span className={clsx('text-xs px-2 py-0.5 rounded-full font-semibold capitalize badge-' + f.severity)}>
                                                    {f.severity}
                                                </span>
                                            </td>
                                            <td className="px-4 py-3 max-w-xs">
                                                <div className="font-medium text-sm truncate" style={{ color: 'var(--text)' }}>
                                                    {f.cve && <span className="mr-1 text-[#2D9CDB] font-mono text-xs">[{f.cve}]</span>}
                                                    {f.title}
                                                </div>
                                                <div className="flex gap-1 mt-1 flex-wrap">
                                                    {f.tags.slice(0, 2).map(t => (
                                                        <span key={t} className="text-xs px-1.5 py-0 rounded" style={{ background: 'var(--border)', color: 'var(--text-muted)' }}>
                                                            {t}
                                                        </span>
                                                    ))}
                                                </div>
                                            </td>
                                            <td className="px-4 py-3">
                                                <span className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>{f.resource.length > 35 ? f.resource.slice(0, 35) + '…' : f.resource}</span>
                                            </td>
                                            <td className="px-4 py-3">
                                                <span className="font-bold text-sm" style={{ color: f.riskScore >= 9 ? '#FF6B6B' : f.riskScore >= 7 ? '#F2994A' : '#27AE60' }}>
                                                    {f.riskScore.toFixed(1)}
                                                </span>
                                            </td>
                                            <td className="px-4 py-3">
                                                <span className="text-xs px-2 py-0.5 rounded-full font-medium" style={{ background: statusColors[f.status].bg, color: statusColors[f.status].text }}>
                                                    {statusColors[f.status].label}
                                                </span>
                                            </td>
                                            <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>
                                                {new Date(f.discoveredAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}
                                            </td>
                                            <td className="px-4 py-3">
                                                {expanded === f.id ? <ChevronUp size={14} style={{ color: 'var(--text-muted)' }} /> : <ChevronDown size={14} style={{ color: 'var(--text-muted)' }} />}
                                            </td>
                                        </tr>
                                        {expanded === f.id && (
                                            <tr key={f.id + '-exp'} style={{ background: 'var(--bg)' }}>
                                                <td colSpan={7} className="px-6 py-5">
                                                    <FindingDetail finding={f} onToast={addToast} />
                                                </td>
                                            </tr>
                                        )}
                                    </Fragment>
                                ))}
                            </tbody>
                        </table>
                    </div>
                    {filtered.length === 0 && (
                        <div className="text-center py-16" style={{ color: 'var(--text-muted)' }}>
                            <Search size={40} className="mx-auto mb-3 opacity-30" />
                            <p className="font-medium">No findings match your filters</p>
                            <p className="text-xs mt-1">Try adjusting your search or filter criteria</p>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}

// ─── Sub-components ──────────────────────────────────────────────────────────

function FilterGroup<T extends string>({
    label, items, selected, onToggle, colors,
}: { label: string; items: T[]; selected: T[]; onToggle: (v: T) => void; colors?: Record<string, string> }) {
    return (
        <div>
            <p className="text-xs font-semibold mb-2 uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>{label}</p>
            <div className="space-y-1">
                {items.map(item => (
                    <label key={item} className="flex items-center gap-2 cursor-pointer group">
                        <input
                            type="checkbox"
                            checked={selected.includes(item)}
                            onChange={() => onToggle(item)}
                            className="w-3.5 h-3.5 rounded accent-[#2D9CDB]"
                        />
                        <span className="text-xs capitalize flex items-center gap-1.5" style={{ color: 'var(--text)' }}>
                            {colors?.[item] && <span className="w-2 h-2 rounded-full" style={{ background: colors[item] }} />}
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
        onToast(`✅ ${label} copied to clipboard`, 'success');
    };

    return (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5 animate-fade-in">
            <div>
                <h3 className="text-sm font-semibold mb-2" style={{ color: 'var(--text)' }}>Description</h3>
                <p className="text-xs leading-relaxed" style={{ color: 'var(--text-muted)' }}>{f.description}</p>
                {f.cvssScore && (
                    <div className="mt-3 flex items-center gap-2">
                        <span className="text-xs" style={{ color: 'var(--text-muted)' }}>CVSS Score:</span>
                        <span className="text-xs font-bold" style={{ color: f.cvssScore >= 9 ? '#FF6B6B' : '#F2994A' }}>{f.cvssScore}</span>
                    </div>
                )}
                <div className="mt-3 flex flex-wrap gap-1.5">
                    {f.framework.map(fw => (
                        <span key={fw} className="badge-info text-xs px-2 py-0.5 rounded-full uppercase">{fw}</span>
                    ))}
                </div>
            </div>
            <div className="space-y-3">
                {f.remediationCommand && (
                    <CodeSnippet title="CLI Remediation" icon={<Terminal size={12} />} code={f.remediationCommand} onCopy={() => copy(f.remediationCommand!, 'CLI command')} />
                )}
                {f.remediationTerraform && (
                    <CodeSnippet title="Terraform Fix" icon={<Code2 size={12} />} code={f.remediationTerraform} onCopy={() => copy(f.remediationTerraform!, 'Terraform snippet')} />
                )}
            </div>
        </div>
    );
}

function CodeSnippet({ title, icon, code, onCopy }: { title: string; icon: React.ReactNode; code: string; onCopy: () => void }) {
    return (
        <div className="rounded-xl border overflow-hidden" style={{ borderColor: 'var(--border)' }}>
            <div className="flex items-center justify-between px-3 py-2" style={{ background: 'var(--primary)', color: 'rgba(255,255,255,0.7)' }}>
                <span className="flex items-center gap-1.5 text-xs">{icon}{title}</span>
                <button onClick={onCopy} className="text-xs px-2 py-0.5 rounded hover:opacity-80" style={{ background: 'rgba(255,255,255,0.1)' }}>Copy</button>
            </div>
            <pre className="text-xs p-3 overflow-x-auto leading-relaxed" style={{ background: '#0d1117', color: '#e6edf3', maxHeight: 160 }}>
                {code}
            </pre>
        </div>
    );
}

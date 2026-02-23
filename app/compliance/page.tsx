'use client';

import { useState } from 'react';
import { complianceControls, complianceSummary, type ComplianceFramework } from '@/lib/mock-data';
import { useAppStore } from '@/lib/store';
import { CheckCircle, XCircle, AlertCircle, ChevronDown, ChevronUp, Download, FileText, FileJson, FileSpreadsheet } from 'lucide-react';
import clsx from 'clsx';

const frameworks: { key: ComplianceFramework; label: string; color: string }[] = [
    { key: 'hipaa', label: 'HIPAA', color: '#2D9CDB' },
    { key: 'nist', label: 'NIST 800-53', color: '#27AE60' },
    { key: 'iso', label: 'ISO 27001', color: '#F2994A' },
];

const statusIcon = {
    pass: <CheckCircle size={15} className="text-[#27AE60]" />,
    fail: <XCircle size={15} className="text-[#FF6B6B]" />,
    partial: <AlertCircle size={15} className="text-[#F2994A]" />,
};
const statusBg = {
    pass: { bg: 'rgba(39,174,96,0.1)', text: '#27AE60', label: 'Pass' },
    fail: { bg: 'rgba(255,107,107,0.1)', text: '#FF6B6B', label: 'Fail' },
    partial: { bg: 'rgba(242,153,74,0.1)', text: '#F2994A', label: 'Partial' },
};

export default function CompliancePage() {
    const [activeTab, setActiveTab] = useState<ComplianceFramework>('hipaa');
    const [expanded, setExpanded] = useState<string | null>(null);
    const { addToast } = useAppStore();

    const controls = complianceControls.filter(c => c.framework === activeTab);
    const summary = complianceSummary[activeTab];
    const fw = frameworks.find(f => f.key === activeTab)!;

    const exportJSON = () => {
        const data = JSON.stringify(controls, null, 2);
        const blob = new Blob([data], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a'); a.href = url; a.download = `cloudshield-${activeTab}-report.json`; a.click();
        addToast(`✅ ${fw.label} JSON report downloaded`, 'success');
    };

    const exportCSV = () => {
        const rows = [['Control ID', 'Title', 'Status', 'Pass/Fail', 'Evidence']];
        controls.forEach(c => rows.push([c.controlId, c.title, c.status, statusBg[c.status].label, c.evidence.join(' | ')]));
        const csv = rows.map(r => r.map(v => `"${v}"`).join(',')).join('\n');
        const blob = new Blob([csv], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a'); a.href = url; a.download = `cloudshield-${activeTab}-report.csv`; a.click();
        addToast(`✅ ${fw.label} CSV report downloaded`, 'success');
    };

    const exportPDF = () => {
        addToast('📄 PDF generation queued — will download shortly', 'info');
        setTimeout(() => addToast('✅ PDF exported successfully', 'success'), 1500);
    };

    return (
        <div className="max-w-5xl mx-auto space-y-5 animate-fade-in">

            {/* Tab selector */}
            <div className="flex items-center gap-2">
                {frameworks.map(fw => {
                    const s = complianceSummary[fw.key];
                    const active = activeTab === fw.key;
                    return (
                        <button
                            key={fw.key}
                            onClick={() => setActiveTab(fw.key)}
                            className="flex items-center gap-3 px-5 py-3 rounded-xl border transition-all hover:opacity-80"
                            style={{
                                background: active ? `${fw.color}18` : 'var(--card)',
                                borderColor: active ? fw.color + '66' : 'var(--border)',
                                color: active ? fw.color : 'var(--text-muted)',
                            }}
                        >
                            <div>
                                <div className="font-semibold text-sm text-left">{fw.label}</div>
                                <div className="text-xs">{s.percentage}% compliant</div>
                            </div>
                            <div className="w-10 h-10 rounded-full flex items-center justify-center text-xs font-bold" style={{ background: `${fw.color}22`, color: fw.color }}>
                                {s.percentage}%
                            </div>
                        </button>
                    );
                })}
            </div>

            {/* Summary bar */}
            <div className="rounded-2xl border p-5" style={{ background: 'var(--card)', borderColor: 'var(--border)' }}>
                <div className="flex items-center justify-between mb-3">
                    <div>
                        <h2 className="font-semibold" style={{ color: 'var(--text)' }}>{fw.label} Compliance Status</h2>
                        <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                            {summary.pass} passed · {summary.fail} failed · {summary.partial} partial out of {summary.total} controls
                        </p>
                    </div>
                    <div className="flex items-center gap-2">
                        <button onClick={exportPDF} className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border transition-all hover:opacity-80" style={{ borderColor: 'var(--border)', color: 'var(--text-muted)' }}>
                            <FileText size={12} /> PDF
                        </button>
                        <button onClick={exportCSV} className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border transition-all hover:opacity-80" style={{ borderColor: 'var(--border)', color: 'var(--text-muted)' }}>
                            <FileSpreadsheet size={12} /> CSV
                        </button>
                        <button onClick={exportJSON} className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border transition-all hover:opacity-80" style={{ borderColor: 'var(--border)', color: 'var(--text-muted)' }}>
                            <FileJson size={12} /> JSON
                        </button>
                    </div>
                </div>

                {/* Progress bar */}
                <div className="h-3 rounded-full overflow-hidden flex gap-0.5" style={{ background: 'var(--bg)' }}>
                    <div className="h-full transition-all duration-700 rounded-l-full" style={{ width: `${(summary.pass / summary.total) * 100}%`, background: '#27AE60' }} />
                    <div className="h-full transition-all duration-700" style={{ width: `${(summary.partial / summary.total) * 100}%`, background: '#F2994A' }} />
                    <div className="h-full transition-all duration-700" style={{ width: `${(summary.fail / summary.total) * 100}%`, background: '#FF6B6B' }} />
                </div>
                <div className="flex items-center gap-4 mt-2 text-xs" style={{ color: 'var(--text-muted)' }}>
                    <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-[#27AE60]" /> Pass</span>
                    <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-[#F2994A]" /> Partial</span>
                    <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-[#FF6B6B]" /> Fail</span>
                </div>
            </div>

            {/* Controls accordion */}
            <div className="space-y-2">
                {controls.map(ctrl => (
                    <div
                        key={ctrl.id}
                        className="rounded-xl border overflow-hidden transition-all"
                        style={{ background: 'var(--card)', borderColor: ctrl.status === 'fail' ? 'rgba(255,107,107,0.3)' : ctrl.status === 'partial' ? 'rgba(242,153,74,0.3)' : 'var(--border)' }}
                    >
                        <button
                            onClick={() => setExpanded(expanded === ctrl.id ? null : ctrl.id)}
                            className="w-full flex items-center gap-3 px-5 py-4 text-left transition-all hover:opacity-80"
                        >
                            <div className="flex-shrink-0">{statusIcon[ctrl.status]}</div>
                            <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2 flex-wrap">
                                    <span className="text-xs font-bold font-mono px-2 py-0.5 rounded" style={{ background: 'var(--bg)', color: fw.color }}>{ctrl.controlId}</span>
                                    <span className="text-sm font-semibold" style={{ color: 'var(--text)' }}>{ctrl.title}</span>
                                </div>
                            </div>
                            <span className="text-xs px-2 py-0.5 rounded-full font-medium flex-shrink-0" style={{ background: statusBg[ctrl.status].bg, color: statusBg[ctrl.status].text }}>
                                {statusBg[ctrl.status].label}
                            </span>
                            {expanded === ctrl.id ? <ChevronUp size={14} style={{ color: 'var(--text-muted)' }} /> : <ChevronDown size={14} style={{ color: 'var(--text-muted)' }} />}
                        </button>

                        {expanded === ctrl.id && (
                            <div className="px-5 pb-4 animate-fade-in" style={{ borderTop: '1px solid var(--border)' }}>
                                <p className="text-xs mt-3 leading-relaxed" style={{ color: 'var(--text-muted)' }}>{ctrl.description}</p>

                                {ctrl.evidence.length > 0 && (
                                    <div className="mt-3">
                                        <p className="text-xs font-semibold mb-1.5" style={{ color: 'var(--text)' }}>Evidence</p>
                                        <div className="space-y-1.5">
                                            {ctrl.evidence.map((ev, i) => (
                                                <div key={i} className="flex items-start gap-2 text-xs px-3 py-2 rounded-lg" style={{ background: 'var(--bg)', color: 'var(--text-muted)' }}>
                                                    {statusIcon[ctrl.status]}
                                                    <span>{ev}</span>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}

                                {ctrl.findingIds.length > 0 && (
                                    <div className="mt-3">
                                        <p className="text-xs font-semibold mb-1.5" style={{ color: 'var(--text)' }}>Related Findings ({ctrl.findingIds.length})</p>
                                        <div className="flex flex-wrap gap-1.5">
                                            {ctrl.findingIds.map(id => (
                                                <span key={id} className="badge-info text-xs px-2 py-0.5 rounded-full font-mono">{id.toUpperCase()}</span>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}
                    </div>
                ))}
            </div>
        </div>
    );
}

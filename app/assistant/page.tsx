'use client';

import { useState, useRef, useEffect } from 'react';
import { useAppStore } from '@/lib/store';
import { mockFindings, type Finding } from '@/lib/mock-data';
import {
    Send, Bot, User, Trash2, Shield, Search,
    Sparkles, Terminal, ChevronRight, Zap, Info, ShieldAlert
} from 'lucide-react';
import clsx from 'clsx';

export default function AssistantPage() {
    const {
        selectedFindings,
        toggleFindingSelection,
        chatMessages,
        addMessage,
        clearMessages
    } = useAppStore();

    const [input, setInput] = useState('');
    const [isTyping, setIsTyping] = useState(false);
    const [search, setSearch] = useState('');
    const scrollRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (scrollRef.current) {
            scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
        }
    }, [chatMessages, isTyping]);

    const filteredFindings = mockFindings.filter(f =>
        f.title.toLowerCase().includes(search.toLowerCase()) ||
        f.resource.toLowerCase().includes(search.toLowerCase()) ||
        f.mitre?.id.toLowerCase().includes(search.toLowerCase())
    );

    const handleSend = () => {
        if (!input.trim()) return;

        const userMsg = input;
        setInput('');
        addMessage({ role: 'user', content: userMsg });

        setIsTyping(true);
        // Realistic AI response delay
        setTimeout(() => {
            setIsTyping(false);
            const response = getAIResponse(userMsg, selectedFindings);
            addMessage({ role: 'assistant', content: response });
        }, 1500);
    };

    return (
        <div className="flex h-[calc(100vh-140px)] gap-6 animate-fade-in">

            {/* Intel Selector Sidebar */}
            <aside className="w-80 flex flex-col gap-4">
                <div className="flex-1 rounded-xl border border-slate-800 bg-slate-900/40 flex flex-col overflow-hidden">
                    <div className="p-4 border-b border-slate-800 bg-slate-900/60">
                        <div className="flex items-center justify-between mb-4">
                            <h3 className="text-[11px] font-black text-white uppercase tracking-widest flex items-center gap-2">
                                <Search size={14} className="text-sky-400" />
                                CONTEXT INGESTION
                            </h3>
                            <span className="text-[10px] font-bold text-sky-500 bg-sky-500/10 px-2 rounded-full border border-sky-500/20 uppercase tracking-tighter">
                                {selectedFindings.length} LOADED
                            </span>
                        </div>
                        <div className="relative group">
                            <Search className="absolute left-3 top-2.5 text-slate-500 group-focus-within:text-sky-400 transition-colors" size={14} />
                            <input
                                value={search}
                                onChange={e => setSearch(e.target.value)}
                                placeholder="INTEL SEARCH..."
                                className="w-full bg-slate-950 border border-slate-800 rounded-lg py-2 pl-9 pr-3 text-[10px] font-bold text-white uppercase tracking-wider focus:border-sky-500/50 outline-none transition-all"
                            />
                        </div>
                    </div>

                    <div className="flex-1 overflow-y-auto p-3 space-y-2">
                        {filteredFindings.map((f) => {
                            const selected = selectedFindings.includes(f.id);
                            return (
                                <button
                                    key={f.id}
                                    onClick={() => toggleFindingSelection(f.id)}
                                    className={clsx(
                                        "w-full text-left p-3 rounded-lg border transition-all relative group overflow-hidden",
                                        selected
                                            ? "border-sky-500/50 bg-sky-500/5"
                                            : "border-slate-800 bg-slate-950 hover:border-slate-700 hover:bg-slate-900/50"
                                    )}
                                >
                                    <div className="flex items-center justify-between mb-1.5">
                                        <span className={clsx("text-[9px] font-black uppercase tracking-widest", `text-severity-${f.severity}`)} style={{ color: f.severity === 'critical' ? '#ef4444' : f.severity === 'high' ? '#f59e0b' : '#38bdf8' }}>
                                            {f.severity}
                                        </span>
                                        {selected && <Shield size={12} className="text-sky-400 animate-glow" />}
                                    </div>
                                    <div className="text-[11px] font-bold text-slate-100 mb-1 truncate">{f.title}</div>
                                    <div className="text-[9px] font-mono text-slate-500 truncate">{f.resource}</div>
                                    {f.mitre && (
                                        <div className="mt-2 text-[8px] font-bold text-sky-500/80 bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800 w-fit uppercase">
                                            {f.mitre.id}: {f.mitre.technique}
                                        </div>
                                    )}
                                    {selected && <div className="absolute left-0 top-0 bottom-0 w-1 bg-sky-500 shadow-[0_0_10px_rgba(56,189,248,0.5)]" />}
                                </button>
                            );
                        })}
                    </div>
                </div>

                <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4">
                    <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-2">Capabilities</div>
                    <div className="space-y-2">
                        {[
                            { label: 'IAC REMEDIATION', icon: Zap },
                            { label: 'THREAT CORRELATION', icon: ShieldAlert },
                            { label: 'ATT&CK MAPPING', icon: Terminal },
                        ].map((c, i) => (
                            <div key={i} className="flex items-center gap-2 text-[9px] font-bold text-slate-400 uppercase">
                                <c.icon size={12} className="text-sky-400" />
                                {c.label}
                            </div>
                        ))}
                    </div>
                </div>
            </aside>

            {/* Copilot Chat Interface */}
            <main className="flex-1 flex flex-col rounded-xl border border-slate-800 bg-slate-900/20 overflow-hidden shadow-2xl backdrop-blur-sm relative">

                {/* Copilot Header */}
                <div className="px-6 py-4 border-b border-slate-800 bg-slate-900/60 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-xl bg-sky-500 flex items-center justify-center shadow-[0_0_20px_rgba(56,189,248,0.3)] animate-glow">
                            <Bot size={22} className="text-slate-950" />
                        </div>
                        <div>
                            <div className="flex items-center gap-2">
                                <h2 className="text-sm font-black text-white uppercase tracking-widest">Security Copilot v2.4</h2>
                                <span className="text-[9px] bg-emerald-500/10 text-emerald-400 px-1.5 py-0.5 rounded font-bold uppercase tracking-widest border border-emerald-500/20">Active</span>
                            </div>
                            <p className="text-[10px] font-bold text-slate-500 uppercase tracking-tighter mt-0.5">Automated Intelligence & Remediation Engine</p>
                        </div>
                    </div>
                    <button
                        onClick={clearMessages}
                        className="text-slate-500 hover:text-red-400 transition-colors p-2 rounded hover:bg-red-400/5 group"
                        title="Clear Intel History"
                    >
                        <Trash2 size={16} className="group-hover:scale-110 transition-transform" />
                    </button>
                </div>

                {/* Messages Feed */}
                <div ref={scrollRef} className="flex-1 overflow-y-auto p-6 space-y-6 scroll-smooth bg-cyber-grid">
                    {chatMessages.length === 0 && (
                        <div className="h-full flex flex-col items-center justify-center text-center p-10">
                            <Sparkles size={48} className="text-slate-800 mb-6" />
                            <h3 className="text-xl font-bold text-slate-300 mb-2 uppercase tracking-wide">Ready for Security Ingestion</h3>
                            <p className="text-slate-500 max-w-sm text-xs font-medium leading-relaxed">
                                Select findings from the left panel to load context, then ask me to generate remediation plans,
                                explain MITRE tactics, or correlate telemetry.
                            </p>
                        </div>
                    )}
                    {chatMessages.map((m, i) => (
                        <div key={i} className={clsx("flex gap-4 animate-fade-in", m.role === 'user' ? "flex-row-reverse" : "flex-row")}>
                            <div className={clsx(
                                "w-9 h-9 rounded flex items-center justify-center flex-shrink-0 border shadow-lg",
                                m.role === 'user' ? "bg-slate-800 border-slate-700 text-sky-400" : "bg-sky-500 border-sky-400 text-slate-950"
                            )}>
                                {m.role === 'user' ? <User size={18} /> : <Bot size={18} />}
                            </div>
                            <div className={clsx(
                                "max-w-[85%] rounded-xl px-5 py-4 shadow-xl relative",
                                m.role === 'user'
                                    ? "bg-slate-800/80 text-white border border-slate-700 rounded-tr-none"
                                    : "bg-slate-950/80 text-slate-200 border border-sky-500/20 rounded-tl-none font-medium leading-relaxed text-sm glass"
                            )}>
                                {m.content.split('\n').map((line, li) => (
                                    <p key={li} className={clsx(line.startsWith('-') || line.startsWith('  ') ? "ml-4" : "mb-2")}>
                                        {line}
                                    </p>
                                ))}
                            </div>
                        </div>
                    ))}
                    {isTyping && (
                        <div className="flex gap-4 animate-fade-in">
                            <div className="w-9 h-9 rounded bg-sky-500 border border-sky-400 flex items-center justify-center text-slate-950 shadow-lg">
                                <Bot size={18} />
                            </div>
                            <div className="bg-slate-950/80 border border-sky-500/10 rounded-xl rounded-tl-none px-5 py-4 flex gap-1.5 items-center shadow-xl glass">
                                <div className="w-1.5 h-1.5 rounded-full bg-sky-500 animate-bounce" style={{ animationDelay: '0ms' }} />
                                <div className="w-1.5 h-1.5 rounded-full bg-sky-500 animate-bounce" style={{ animationDelay: '150ms' }} />
                                <div className="w-1.5 h-1.5 rounded-full bg-sky-500 animate-bounce" style={{ animationDelay: '300ms' }} />
                            </div>
                        </div>
                    )}
                </div>

                {/* Command Input */}
                <div className="p-6 border-t border-slate-800 bg-slate-900/40">
                    <div className="relative flex items-center">
                        <input
                            type="text"
                            value={input}
                            onChange={(e) => setInput(e.target.value)}
                            onKeyDown={(e) => e.key === 'Enter' && handleSend()}
                            placeholder={selectedFindings.length === 0 ? "SELECT FINDINGS TO START ANALYSIS..." : "ASK COPILOT FOR REMEDIATION INTEL..."}
                            className="w-full bg-slate-950 border border-slate-800 rounded-xl py-4 pl-5 pr-14 text-sm font-medium text-white placeholder:text-slate-600 focus:border-sky-500/50 focus:ring-1 focus:ring-sky-500/20 outline-none transition-all shadow-inner"
                        />
                        <button
                            onClick={handleSend}
                            disabled={!input.trim() || isTyping}
                            className="absolute right-3 p-2.5 rounded-lg bg-sky-500 text-slate-950 hover:bg-sky-400 disabled:opacity-50 disabled:bg-slate-800 disabled:text-slate-600 transition-all shadow-[0_0_10px_rgba(56,189,248,0.2)]"
                        >
                            <Send size={18} />
                        </button>
                    </div>
                    <div className="flex items-center gap-4 mt-3 px-1">
                        <div className="flex items-center gap-1 text-[9px] font-bold text-slate-500 uppercase tracking-widest leading-none">
                            <Info size={10} />
                            AI Insights use RAG on localized intel.
                        </div>
                        <div className="flex items-center gap-1 text-[9px] font-bold text-slate-500 uppercase tracking-widest leading-none">
                            <Zap size={10} className="text-amber-500" />
                            Accelerator: GPT-4o-Turbo
                        </div>
                    </div>
                </div>
            </main>
        </div>
    );
}

// ─── Logic ───────────────────────────────────────────────────────────────────

function getAIResponse(input: string, selectedIds: string[]): string {
    const findings = mockFindings.filter(f => selectedIds.includes(f.id));

    if (findings.length === 0) {
        return "⚠️ INTEL DEFICIT: Please select one or more findings from the 'Context Ingestion' panel for a targeted analysis.";
    }

    if (input.toLowerCase().includes('remediate') || input.toLowerCase().includes('fix')) {
        let resp = "🛡️ GENERATING STRATEGIC REMEDIATION PLAN...\n\n";
        findings.forEach(f => {
            resp += `>>> ANALYSIS: ${f.title.toUpperCase()}\n`;
            resp += `- SEVERITY: ${f.severity.toUpperCase()} (Risk Score: ${f.riskScore})\n`;
            if (f.mitre) resp += `- MITRE ALIGNMENT: ${f.mitre.id} (${f.mitre.technique})\n`;
            resp += `- REMEDIATION:\n  ${f.remediationCommand || 'Manual inspection required.'}\n\n`;
        });
        resp += "### SYSTEM RECOMMENDATION\nExecute the above CLI payloads in the order presented. Post-remediation scan is mandatory.";
        return resp;
    }

    return `I have ingested intel for ${findings.length} findings. Based on current telemetry:\n\n- Primary Vector: ${findings[0].resourceType.toUpperCase()}\n- Aggregate Risk: ${(findings.reduce((acc, f) => acc + f.riskScore, 0) / findings.length).toFixed(1)}\n\nWhat specific diagnostic or iAC manifest would you like me to generate?`;
}

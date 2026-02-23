'use client';

import { useState, useRef, useEffect } from 'react';
import {
    Bot, Send, User, Sparkles, Terminal, Shield,
    CheckCircle2, History, Cpu, Globe, Lock,
    Workflow, Zap, Code, Info
} from 'lucide-react';
import { mockFindings } from '@/lib/mock-data';
import { useAppStore } from '@/lib/store';
import clsx from 'clsx';

type AssistantMode = 'remediation' | 'investigation';

export default function SecurityCopilot() {
    const { chatMessages, addMessage, selectedFindings, toggleFindingSelection, clearMessages } = useAppStore();
    const [inputValue, setInputValue] = useState('');
    const [isTyping, setIsTyping] = useState(false);
    const [mode, setMode] = useState<AssistantMode>('remediation');
    const scrollRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (scrollRef.current) {
            scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
        }
    }, [chatMessages]);

    const activeFindings = mockFindings.filter(f => selectedFindings.includes(f.id));

    const handleSend = async () => {
        if (!inputValue.trim()) return;

        const userMsg = inputValue;
        setInputValue('');
        addMessage({ role: 'user', content: userMsg });
        setIsTyping(true);

        setTimeout(() => {
            let response = "";
            if (activeFindings.length > 0) {
                const finding = activeFindings[0];
                response = `**[SENTINEL-COPILOT-2.0] Analyzing Context...**\n\nI have ingested context for **${finding.resource}**. \n\n**REMEDIATION PLAN (DEEPSEEK-INGESTED):**\nThe vulnerability **${finding.title}** (${finding.id}) suggests ${finding.severity === 'critical' ? 'immediate isolation' : 'a standard patch'}.\n\n\`\`\`bash\n# DeepSeek Recommended Patch\n${finding.remediationCommand || "kubectl patch deployment " + finding.resource + " --type='json' -p='[{\"op\": \"replace\", \"path\": \"/spec/template/spec/containers/0/image\", \"value\":\"secured-image:v2\"}]' "}\n\`\`\`\n\n**VERIFICATION:**\nOnce applied, run \`check-compliance --finding ${finding.id}\` to verify closure.`;
            } else {
                response = "I am standing by. Please select findings from the **Context Engine** or provide a system query for analysis (e.g., 'How do I harden my EKS cluster?').";
            }

            addMessage({ role: 'assistant', content: response });
            setIsTyping(false);
        }, 1500);
    };

    return (
        <div className="flex flex-col lg:flex-row h-[calc(100vh-140px)] gap-6 animate-fade-in font-inter">

            {/* Context Panel */}
            <div className="w-full lg:w-80 flex flex-col gap-4 flex-shrink-0">
                <div className="flex-1 flex flex-col rounded-xl border border-slate-800 bg-slate-900/40 overflow-hidden glass shadow-xl">
                    <div className="p-4 border-b border-slate-800 bg-slate-900/60 flex items-center justify-between">
                        <span className="text-[10px] font-black text-sky-400 font-mono tracking-widest flex items-center gap-2">
                            <Workflow size={14} /> CONTEXT ENGINE
                        </span>
                        <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                    </div>

                    <div className="flex-1 overflow-y-auto p-4 space-y-4 custom-scrollbar">
                        <div>
                            <span className="text-[9px] font-bold text-slate-500 uppercase tracking-widest mb-3 block">Available Context ({selectedFindings.length})</span>
                            <div className="space-y-2">
                                {mockFindings.slice(0, 8).map(f => (
                                    <button
                                        key={f.id}
                                        onClick={() => toggleFindingSelection(f.id)}
                                        className={clsx(
                                            "w-full p-3 rounded-lg border text-left transition-all group relative overflow-hidden",
                                            selectedFindings.includes(f.id)
                                                ? "bg-sky-500/10 border-sky-500/40"
                                                : "bg-slate-950/40 border-slate-800 hover:border-slate-700"
                                        )}
                                    >
                                        <div className="flex items-center justify-between mb-1.5">
                                            <span className={clsx("text-[9px] font-black px-1.5 rounded uppercase border", `badge-${f.severity}`)}>{f.severity}</span>
                                            {selectedFindings.includes(f.id) && <CheckCircle2 size={12} className="text-sky-400" />}
                                        </div>
                                        <div className="text-[11px] font-bold text-slate-200 truncate group-hover:text-white">{f.title}</div>
                                        <div className="text-[9px] font-mono text-slate-600 mt-1 uppercase tracking-tighter">{f.resource}</div>
                                    </button>
                                ))}
                            </div>
                        </div>

                        {activeFindings.length > 0 && (
                            <div className="pt-4 border-t border-slate-800 animate-fade-in">
                                <span className="text-[9px] font-bold text-sky-500 uppercase tracking-widest mb-3 block">Asset Intel</span>
                                <MetadataItem icon={Cpu} label="Compute" value={activeFindings[0].resourceType} />
                                <MetadataItem icon={Globe} label="Namespace" value="prod-cluster-01" />
                                <MetadataItem icon={Lock} label="IAM Role" value="Admin-RW" />
                            </div>
                        )}
                    </div>
                </div>

                <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/20 flex items-center gap-3">
                    <History size={16} className="text-slate-500" />
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Logic Flow: DeepSeek-V2</span>
                </div>
            </div>

            {/* Chat Workspace */}
            <div className="flex-1 flex flex-col rounded-xl border border-slate-800 bg-slate-900/40 overflow-hidden relative glass shadow-2xl">

                {/* Header */}
                <div className="p-4 border-b border-slate-800 bg-slate-900/60 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-lg bg-sky-500/10 border border-sky-500/30 flex items-center justify-center text-sky-400 shadow-[0_0_15px_rgba(56,189,248,0.1)]">
                            <Bot size={22} className="animate-glow" />
                        </div>
                        <div>
                            <div className="text-sm font-black text-white tracking-tight uppercase flex items-center gap-2">
                                Sentinel Copilot <span className="text-[9px] bg-sky-500 text-slate-950 px-1.5 rounded animate-pulse">2.0</span>
                            </div>
                            <div className="text-[9px] font-bold text-slate-500 uppercase tracking-widest">Powered by DeepSeek AI Pipeline</div>
                        </div>
                    </div>

                    <div className="hidden sm:flex items-center gap-1 p-1 bg-slate-950/60 rounded-lg border border-slate-800">
                        <ModeBtn active={mode === 'remediation'} onClick={() => setMode('remediation')} icon={Zap} label="Patch" />
                        <ModeBtn active={mode === 'investigation'} onClick={() => setMode('investigation')} icon={Terminal} label="Probe" />
                    </div>
                </div>

                {/* Messages */}
                <div ref={scrollRef} className="flex-1 overflow-y-auto p-6 space-y-6 custom-scrollbar">
                    {chatMessages.length === 0 && (
                        <div className="h-full flex flex-col items-center justify-center p-10 text-center">
                            <Sparkles size={48} className="text-slate-800 mb-6" />
                            <h3 className="text-sm font-black text-slate-400 uppercase tracking-widest mb-2">Awaiting Context Ingestion</h3>
                            <p className="text-[10px] text-slate-600 font-bold uppercase tracking-tighter max-w-xs">
                                Select cloud-native findings to hydrate the RAG pipeline for localized remediation plans.
                            </p>
                        </div>
                    )}
                    {chatMessages.map((msg, i) => (
                        <div key={i} className={clsx("flex gap-4 animate-slide-up", msg.role === 'user' ? "flex-row-reverse" : "flex-row")}>
                            <div className={clsx(
                                "w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 border",
                                msg.role === 'user' ? "bg-slate-800 border-slate-700" : "bg-sky-500/10 border-sky-500/30 text-sky-400"
                            )}>
                                {msg.role === 'user' ? <User size={16} /> : <Bot size={16} />}
                            </div>
                            <div className={clsx(
                                "max-w-[85%] rounded-2xl px-5 py-4 text-sm leading-relaxed shadow-lg",
                                msg.role === 'user'
                                    ? "bg-slate-800 text-slate-100"
                                    : "bg-slate-900/80 border border-slate-800 text-slate-300 backdrop-blur-sm"
                            )}>
                                <div className="whitespace-pre-wrap">
                                    {msg.content}
                                </div>
                            </div>
                        </div>
                    ))}
                    {isTyping && (
                        <div className="flex gap-4 animate-pulse">
                            <div className="w-8 h-8 rounded-lg bg-sky-500/10 border border-sky-500/30 flex items-center justify-center text-sky-400">
                                <Bot size={16} />
                            </div>
                            <div className="bg-slate-900/40 rounded-2xl px-4 py-3 flex gap-1.5 items-center">
                                <div className="w-1.5 h-1.5 rounded-full bg-sky-500 animate-bounce" style={{ animationDelay: '0ms' }} />
                                <div className="w-1.5 h-1.5 rounded-full bg-sky-500 animate-bounce" style={{ animationDelay: '150ms' }} />
                                <div className="w-1.5 h-1.5 rounded-full bg-sky-500 animate-bounce" style={{ animationDelay: '300ms' }} />
                            </div>
                        </div>
                    )}
                </div>

                {/* Input */}
                <div className="p-4 border-t border-slate-800 bg-slate-900/60">
                    <div className="relative group">
                        <textarea
                            value={inputValue}
                            onChange={(e) => setInputValue(e.target.value)}
                            onKeyDown={(e) => {
                                if (e.key === 'Enter' && !e.shiftKey) {
                                    e.preventDefault();
                                    handleSend();
                                }
                            }}
                            placeholder={activeFindings.length > 0 ? `DeepSeek Analyze: ${activeFindings[0].title}...` : "Query the Security Copilot..."}
                            className="w-full bg-slate-950 border border-slate-800 rounded-xl px-5 py-5 pr-16 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-sky-500/50 transition-all min-h-[120px] resize-none"
                        />
                        <button
                            onClick={handleSend}
                            disabled={!inputValue.trim() || isTyping}
                            className="absolute right-4 bottom-4 p-2.5 bg-sky-500 text-slate-950 rounded-xl hover:bg-sky-400 transition-all disabled:opacity-50 shadow-xl"
                        >
                            <Send size={20} />
                        </button>
                    </div>
                    <div className="mt-4 flex items-center justify-between text-[10px] font-black uppercase tracking-widest text-slate-600">
                        <div className="flex items-center gap-4">
                            <span className="flex items-center gap-1.5"><Shield size={12} className="text-emerald-500 font-bold" /> E2E Encrypted</span>
                            <span className="flex items-center gap-1.5"><Code size={12} className="text-sky-400" /> RAG Enabled</span>
                        </div>
                        <button onClick={clearMessages} className="hover:text-red-400 transition-colors uppercase">Flush Buffer</button>
                    </div>
                </div>

                {/* Overlay Grid */}
                <div className="absolute inset-0 pointer-events-none opacity-[0.03]" style={{ backgroundImage: 'radial-gradient(#38bdf8 1px, transparent 1px)', backgroundSize: '30px 30px' }} />
            </div>
        </div>
    );
}

function MetadataItem({ icon: Icon, label, value }: { icon: any, label: string, value: string }) {
    return (
        <div className="flex items-center justify-between py-2.5 border-b border-slate-800/50 last:border-0 group">
            <div className="flex items-center gap-2.5">
                <Icon size={14} className="text-slate-500 group-hover:text-sky-400 transition-colors" />
                <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest">{label}</span>
            </div>
            <span className="text-[10px] font-mono text-slate-300 font-bold">{value}</span>
        </div>
    );
}

function ModeBtn({ active, onClick, icon: Icon, label }: { active: boolean, onClick: () => void, icon: any, label: string }) {
    return (
        <button
            onClick={onClick}
            className={clsx(
                "flex items-center gap-2 px-4 py-2 rounded-lg transition-all text-[10px] font-black uppercase tracking-widest",
                active ? "bg-sky-500 text-slate-950 shadow-lg shadow-sky-500/20 scale-[1.05]" : "text-slate-500 hover:text-white"
            )}
        >
            <Icon size={14} />
            {label}
        </button>
    );
}

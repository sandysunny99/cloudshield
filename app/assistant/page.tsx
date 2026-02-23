'use client';

import { useState, useRef, useEffect } from 'react';
import { mockFindings, type Finding } from '@/lib/mock-data';
import { useAppStore } from '@/lib/store';
import { Bot, Send, Trash2, Copy, Terminal, Code2, ChevronRight, Zap } from 'lucide-react';
import clsx from 'clsx';

const sevColors: Record<string, string> = {
    critical: '#FF6B6B', high: '#F2994A', medium: '#F7D228', low: '#27AE60',
};

// Mock AI response generator
function generateAIResponse(userMsg: string, finding: Finding | null): string {
    const f = finding;
    if (!f) {
        if (userMsg.toLowerCase().includes('hello') || userMsg.toLowerCase().includes('hi')) {
            return "Hello! I'm ready to help with security remediation. Select a finding from the list on the left to get specific guidance, or ask me anything about cloud security!";
        }
        return `I'd be happy to help! For the most accurate remediation guidance, I recommend selecting a specific finding from the panel on the left. That way I can provide:\n\n- **Contextual risk assessment** specific to your environment\n- **Step-by-step remediation commands** (CLI, Terraform, or console)\n- **Compliance impact analysis** (HIPAA/NIST/ISO)\n- **Verification steps** to confirm the fix\n\nYou can also ask me general questions like:\n- "What is CVE-2024-21626?"\n- "How do I harden an S3 bucket?"\n- "Explain IAM least-privilege principle"`;
    }

    return `## 🛡️ AI Analysis: ${f.title}\n\n**Risk Score:** ${f.riskScore}/10 | **Severity:** ${f.severity.toUpperCase()} | **CVSS:** ${f.cvssScore ?? 'N/A'}\n\n### Root Cause\n${f.description}\n\n### Compliance Impact\n${f.framework.map(fw => `- **${fw.toUpperCase()}**: This finding directly affects compliance with ${fw === 'hipaa' ? 'Section 164.312' : fw === 'nist' ? 'AC-3, SI-2 controls' : 'Annex A.12.6.1'}`).join('\n')}\n\n### Remediation Priority\nThis issue should be addressed **${f.riskScore >= 9 ? 'immediately (P0)' : f.riskScore >= 7 ? 'within 24-48 hours (P1)' : 'within this sprint (P2)'}** to prevent potential ${f.riskScore >= 9 ? 'breach or data exposure' : 'policy violations'}.\n\n### Verification Steps\nAfter applying the fix:\n1. Re-run CloudShield scan on the affected resource\n2. Confirm the finding status changes to "Resolved"\n3. Review audit logs for any unauthorized access during the exposure window\n4. Update your incident log with remediation evidence\n\n> 💡 **Tip:** Use the code snippets below the finding in the Scan Results view to copy exact remediation commands.`;
}

function renderMarkdown(text: string) {
    return text
        .replace(/^## (.+)$/gm, '<h3 class="font-bold text-sm mt-3 mb-1" style="color:var(--text)">$1</h3>')
        .replace(/^### (.+)$/gm, '<h4 class="font-semibold text-xs mt-2 mb-1" style="color:var(--text)">$1</h4>')
        .replace(/\*\*(.+?)\*\*/g, '<strong style="color:var(--text)">$1</strong>')
        .replace(/^- (.+)$/gm, '<li class="text-xs ml-3 mb-0.5 list-disc" style="color:var(--text-muted)">$1</li>')
        .replace(/^> 💡 (.+)$/gm, '<div class="badge-info text-xs px-3 py-1.5 rounded-lg mt-2">💡 $1</div>')
        .replace(/\n/g, '<br/>');
}

export default function AssistantPage() {
    const { chatMessages, addChatMessage, clearChat, selectedFinding, setSelectedFinding, addToast } = useAppStore();
    const [input, setInput] = useState('');
    const [loading, setLoading] = useState(false);
    const messagesEndRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [chatMessages]);

    const sendMessage = async () => {
        const msg = input.trim();
        if (!msg || loading) return;
        setInput('');
        addChatMessage('user', msg);
        setLoading(true);
        await new Promise(r => setTimeout(r, 1200 + Math.random() * 800));
        const reply = generateAIResponse(msg, selectedFinding);
        addChatMessage('assistant', reply);
        setLoading(false);
    };

    const openFindings = mockFindings.filter(f => f.status !== 'resolved').slice(0, 8);

    return (
        <div className="max-w-7xl mx-auto flex gap-5 h-[calc(100vh-124px)] animate-fade-in">

            {/* Finding selector */}
            <aside className="w-64 flex-shrink-0 rounded-2xl border overflow-hidden flex flex-col" style={{ background: 'var(--card)', borderColor: 'var(--border)' }}>
                <div className="px-4 py-3 border-b" style={{ borderColor: 'var(--border)' }}>
                    <h2 className="text-sm font-semibold" style={{ color: 'var(--text)' }}>Select Finding</h2>
                    <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>Get contextual AI guidance</p>
                </div>
                <div className="flex-1 overflow-y-auto p-2 space-y-1">
                    <button
                        onClick={() => setSelectedFinding(null)}
                        className={clsx('w-full text-left px-3 py-2 rounded-lg text-xs transition-all hover:opacity-80', !selectedFinding ? 'font-semibold' : '')}
                        style={{
                            background: !selectedFinding ? 'rgba(45,156,219,0.15)' : 'transparent',
                            color: !selectedFinding ? '#2D9CDB' : 'var(--text-muted)',
                            border: !selectedFinding ? '1px solid rgba(45,156,219,0.3)' : '1px solid transparent',
                        }}
                    >
                        <Zap size={11} className="inline mr-1.5" />
                        General Questions
                    </button>
                    {openFindings.map(f => (
                        <button
                            key={f.id}
                            onClick={() => {
                                setSelectedFinding(f);
                                addChatMessage('user', `Analyze and provide remediation for: ${f.title}`);
                                setLoading(true);
                                setTimeout(() => {
                                    addChatMessage('assistant', generateAIResponse('analyze', f));
                                    setLoading(false);
                                }, 1400);
                            }}
                            className={clsx('w-full text-left px-3 py-2.5 rounded-lg transition-all hover:opacity-80 border', selectedFinding?.id === f.id ? '' : 'border-transparent')}
                            style={{
                                background: selectedFinding?.id === f.id ? 'var(--bg)' : 'transparent',
                                borderColor: selectedFinding?.id === f.id ? sevColors[f.severity] + '44' : 'transparent',
                            }}
                        >
                            <div className="flex items-center gap-1.5 mb-1">
                                <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: sevColors[f.severity] }} />
                                <span className="text-xs capitalize font-medium" style={{ color: sevColors[f.severity] }}>{f.severity}</span>
                                <span className="ml-auto text-xs font-bold" style={{ color: sevColors[f.severity] }}>{f.riskScore}</span>
                            </div>
                            <p className="text-xs leading-tight" style={{ color: 'var(--text)' }}>{f.title}</p>
                        </button>
                    ))}
                </div>
            </aside>

            {/* Chat panel */}
            <div className="flex-1 rounded-2xl border flex flex-col overflow-hidden" style={{ background: 'var(--card)', borderColor: 'var(--border)' }}>

                {/* Chat header */}
                <div className="flex items-center justify-between px-5 py-3 border-b" style={{ background: 'var(--primary)', borderColor: 'rgba(255,255,255,0.08)' }}>
                    <div className="flex items-center gap-2.5">
                        <div className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ background: 'rgba(45,156,219,0.3)' }}>
                            <Bot size={16} className="text-[#4FC3F7]" />
                        </div>
                        <div>
                            <p className="text-sm font-semibold text-white">CloudShield AI</p>
                            <p className="text-xs" style={{ color: 'rgba(255,255,255,0.5)' }}>
                                {selectedFinding ? `Analyzing: ${selectedFinding.title.slice(0, 40)}…` : 'Ready to assist'}
                            </p>
                        </div>
                    </div>
                    <div className="flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full bg-[#27AE60] animate-pulse-slow" />
                        <span className="text-xs text-white/50">Online</span>
                        <button onClick={clearChat} className="ml-2 text-white/30 hover:text-white/60 transition-colors" title="Clear chat">
                            <Trash2 size={14} />
                        </button>
                    </div>
                </div>

                {/* Messages */}
                <div className="flex-1 overflow-y-auto p-4 space-y-4">
                    {chatMessages.map((msg, i) => (
                        <div key={i} className={clsx('flex', msg.role === 'user' ? 'justify-end' : 'justify-start')}>
                            {msg.role === 'assistant' && (
                                <div className="w-7 h-7 rounded-full flex items-center justify-center flex-shrink-0 mr-2 mt-1" style={{ background: 'rgba(45,156,219,0.2)' }}>
                                    <Bot size={14} className="text-[#4FC3F7]" />
                                </div>
                            )}
                            <div
                                className={clsx('max-w-[75%] px-4 py-3 rounded-2xl text-xs leading-relaxed', msg.role === 'user' ? 'rounded-tr-sm' : 'rounded-tl-sm')}
                                style={{
                                    background: msg.role === 'user' ? 'linear-gradient(135deg, #2D9CDB, #1a6fa8)' : 'var(--bg)',
                                    color: msg.role === 'user' ? 'white' : 'var(--text)',
                                    border: msg.role === 'assistant' ? '1px solid var(--border)' : 'none',
                                }}
                            >
                                {msg.role === 'assistant' ? (
                                    <div dangerouslySetInnerHTML={{ __html: renderMarkdown(msg.content) }} />
                                ) : (
                                    <p>{msg.content}</p>
                                )}
                                <p className="text-xs mt-1.5 opacity-50">
                                    {msg.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                                </p>
                            </div>
                        </div>
                    ))}
                    {loading && (
                        <div className="flex items-center gap-2">
                            <div className="w-7 h-7 rounded-full flex items-center justify-center" style={{ background: 'rgba(45,156,219,0.2)' }}>
                                <Bot size={14} className="text-[#4FC3F7]" />
                            </div>
                            <div className="px-4 py-3 rounded-2xl rounded-tl-sm" style={{ background: 'var(--bg)', border: '1px solid var(--border)' }}>
                                <div className="flex gap-1.5">
                                    {[0, 1, 2].map(i => (
                                        <span key={i} className="w-1.5 h-1.5 rounded-full bg-[#2D9CDB] animate-bounce" style={{ animationDelay: `${i * 0.15}s` }} />
                                    ))}
                                </div>
                            </div>
                        </div>
                    )}
                    <div ref={messagesEndRef} />
                </div>

                {/* Input */}
                <div className="p-4 border-t" style={{ borderColor: 'var(--border)' }}>
                    <div className="flex items-center gap-3 px-4 py-2.5 rounded-xl border" style={{ background: 'var(--bg)', borderColor: 'var(--border)' }}>
                        <input
                            value={input}
                            onChange={e => setInput(e.target.value)}
                            onKeyDown={e => e.key === 'Enter' && !e.shiftKey && sendMessage()}
                            placeholder="Ask about vulnerabilities, remediation steps, compliance impact..."
                            className="flex-1 text-sm bg-transparent outline-none"
                            style={{ color: 'var(--text)' }}
                        />
                        <button
                            onClick={sendMessage}
                            disabled={!input.trim() || loading}
                            className="w-8 h-8 rounded-lg flex items-center justify-center text-white transition-all hover:opacity-80 disabled:opacity-30"
                            style={{ background: 'linear-gradient(135deg, #2D9CDB, #1a6fa8)' }}
                        >
                            <Send size={14} />
                        </button>
                    </div>
                    <p className="text-xs mt-2 text-center" style={{ color: 'var(--text-muted)' }}>
                        AI responses are generated for demonstration. Always verify commands before executing in production.
                    </p>
                </div>
            </div>
        </div>
    );
}

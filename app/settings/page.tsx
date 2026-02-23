'use client';

import { useState } from 'react';
import { useAppStore } from '@/lib/store';
import { User, Bell, Key, Shield, ChevronRight, Eye, EyeOff, Check } from 'lucide-react';

const roles = [
    { key: 'admin', label: 'Admin', desc: 'Full system access, all settings', color: '#FF6B6B', emoji: '👑' },
    { key: 'security', label: 'Security Team', desc: 'View all findings, generate reports', color: '#2D9CDB', emoji: '🛡️' },
    { key: 'developer', label: 'Developer', desc: 'View own projects, execute remediations', color: '#27AE60', emoji: '💻' },
    { key: 'auditor', label: 'Auditor', desc: 'Read-only access to compliance reports', color: '#F2994A', emoji: '📋' },
] as const;

export default function SettingsPage() {
    const { userRole, setUserRole, userName, addToast } = useAppStore();
    const [showKey, setShowKey] = useState(false);
    const [notificationsEnabled, setNotificationsEnabled] = useState(true);
    const [emailDigest, setEmailDigest] = useState(true);
    const [slackAlerts, setSlackAlerts] = useState(false);

    const save = (msg: string) => addToast(`✅ ${msg}`, 'success');

    return (
        <div className="max-w-3xl mx-auto space-y-5 animate-fade-in">

            {/* Profile */}
            <section className="rounded-2xl border p-6" style={{ background: 'var(--card)', borderColor: 'var(--border)' }}>
                <h2 className="font-semibold text-sm mb-4 flex items-center gap-2" style={{ color: 'var(--text)' }}>
                    <User size={15} className="text-[#2D9CDB]" /> Profile
                </h2>
                <div className="flex items-center gap-4 mb-4">
                    <div className="w-14 h-14 rounded-2xl flex items-center justify-center text-white text-lg font-bold" style={{ background: 'linear-gradient(135deg, #2D9CDB, #0A1929)' }}>
                        SK
                    </div>
                    <div>
                        <p className="font-semibold" style={{ color: 'var(--text)' }}>{userName}</p>
                        <p className="text-sm" style={{ color: 'var(--text-muted)' }}>sandeep@cloudshield.io</p>
                        <span className="text-xs px-2 py-0.5 rounded-full badge-info capitalize mt-1 inline-block">{userRole}</span>
                    </div>
                </div>
                <div className="grid grid-cols-2 gap-3">
                    {(['Full Name', 'Email'] as const).map(label => (
                        <div key={label}>
                            <label className="text-xs font-medium block mb-1" style={{ color: 'var(--text-muted)' }}>{label}</label>
                            <input
                                defaultValue={label === 'Full Name' ? userName : 'sandeep@cloudshield.io'}
                                className="w-full px-3 py-2 text-sm rounded-lg border outline-none transition-all focus:ring-2 focus:ring-[#2D9CDB]/30"
                                style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--text)' }}
                            />
                        </div>
                    ))}
                </div>
                <button onClick={() => save('Profile updated')} className="mt-4 px-4 py-2 rounded-lg text-sm text-white font-medium hover:opacity-90 transition-all" style={{ background: 'linear-gradient(135deg, #2D9CDB, #1a6fa8)' }}>
                    Save Changes
                </button>
            </section>

            {/* RBAC Role */}
            <section className="rounded-2xl border p-6" style={{ background: 'var(--card)', borderColor: 'var(--border)' }}>
                <h2 className="font-semibold text-sm mb-4 flex items-center gap-2" style={{ color: 'var(--text)' }}>
                    <Shield size={15} className="text-[#2D9CDB]" /> Role & Permissions
                </h2>
                <div className="grid grid-cols-2 gap-3">
                    {roles.map(role => (
                        <button
                            key={role.key}
                            onClick={() => { setUserRole(role.key); save(`Role changed to ${role.label}`); }}
                            className="flex items-start gap-3 p-4 rounded-xl border text-left transition-all hover:opacity-80"
                            style={{
                                background: userRole === role.key ? `${role.color}12` : 'var(--bg)',
                                borderColor: userRole === role.key ? role.color + '55' : 'var(--border)',
                            }}
                        >
                            <span className="text-xl">{role.emoji}</span>
                            <div className="flex-1">
                                <div className="flex items-center gap-1.5">
                                    <span className="text-sm font-semibold" style={{ color: userRole === role.key ? role.color : 'var(--text)' }}>{role.label}</span>
                                    {userRole === role.key && <Check size={13} style={{ color: role.color }} />}
                                </div>
                                <p className="text-xs mt-0.5 leading-snug" style={{ color: 'var(--text-muted)' }}>{role.desc}</p>
                            </div>
                        </button>
                    ))}
                </div>
            </section>

            {/* Notifications */}
            <section className="rounded-2xl border p-6" style={{ background: 'var(--card)', borderColor: 'var(--border)' }}>
                <h2 className="font-semibold text-sm mb-4 flex items-center gap-2" style={{ color: 'var(--text)' }}>
                    <Bell size={15} className="text-[#2D9CDB]" /> Notifications
                </h2>
                <div className="space-y-3">
                    {[
                        { label: 'Push Notifications', sub: 'Critical findings and scan completions', val: notificationsEnabled, set: setNotificationsEnabled },
                        { label: 'Email Digest', sub: 'Daily summary of open issues', val: emailDigest, set: setEmailDigest },
                        { label: 'Slack Alerts', sub: 'Critical findings sent to #security channel', val: slackAlerts, set: setSlackAlerts },
                    ].map(item => (
                        <div key={item.label} className="flex items-center justify-between py-2 border-b last:border-0" style={{ borderColor: 'var(--border)' }}>
                            <div>
                                <p className="text-sm font-medium" style={{ color: 'var(--text)' }}>{item.label}</p>
                                <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{item.sub}</p>
                            </div>
                            <button
                                onClick={() => { item.set(!item.val); save(`${item.label} ${!item.val ? 'enabled' : 'disabled'}`); }}
                                className="relative w-11 h-6 rounded-full transition-all duration-300"
                                style={{ background: item.val ? '#2D9CDB' : 'var(--border)' }}
                            >
                                <span className="absolute top-0.5 w-5 h-5 bg-white rounded-full shadow transition-all duration-300" style={{ left: item.val ? '1.5rem' : '0.125rem' }} />
                            </button>
                        </div>
                    ))}
                </div>
            </section>

            {/* API Key */}
            <section className="rounded-2xl border p-6" style={{ background: 'var(--card)', borderColor: 'var(--border)' }}>
                <h2 className="font-semibold text-sm mb-4 flex items-center gap-2" style={{ color: 'var(--text)' }}>
                    <Key size={15} className="text-[#2D9CDB]" /> API Configuration
                </h2>
                <div className="space-y-3">
                    <div>
                        <label className="text-xs font-medium block mb-1" style={{ color: 'var(--text-muted)' }}>API Key</label>
                        <div className="flex items-center gap-2">
                            <input
                                readOnly
                                value={showKey ? 'cs_live_sk_4f8b3a2d9e1c7f0b6a5e8d3c2f1a9b4e' : '••••••••••••••••••••••••••••••••••••'}
                                className="flex-1 px-3 py-2 text-sm rounded-lg border font-mono outline-none"
                                style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--text)' }}
                            />
                            <button onClick={() => setShowKey(!showKey)} className="px-3 py-2 rounded-lg border" style={{ borderColor: 'var(--border)', color: 'var(--text-muted)' }}>
                                {showKey ? <EyeOff size={14} /> : <Eye size={14} />}
                            </button>
                            <button onClick={() => { navigator.clipboard.writeText('cs_live_sk_4f8b3a2d9e1c7f0b6a5e8d3c2f1a9b4e'); addToast('✅ API key copied', 'success'); }}
                                className="px-3 py-2 rounded-lg text-xs font-medium text-white" style={{ background: '#2D9CDB' }}>
                                Copy
                            </button>
                        </div>
                    </div>
                    <div>
                        <label className="text-xs font-medium block mb-1" style={{ color: 'var(--text-muted)' }}>OpenAI API Key (for AI features)</label>
                        <input
                            type="password"
                            defaultValue="sk-••••••••••••••••••••••"
                            className="w-full px-3 py-2 text-sm rounded-lg border font-mono outline-none"
                            style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--text)' }}
                        />
                    </div>
                </div>
                <button onClick={() => save('API settings saved')} className="mt-4 px-4 py-2 rounded-lg text-sm text-white font-medium hover:opacity-90 transition-all" style={{ background: 'linear-gradient(135deg, #2D9CDB, #1a6fa8)' }}>
                    Save API Settings
                </button>
            </section>
        </div>
    );
}

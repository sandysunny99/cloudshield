'use client';

import { usePathname } from 'next/navigation';
import { useAppStore } from '@/lib/store';
import { Bell, Moon, Sun, Menu, Shield, ChevronDown } from 'lucide-react';
import { useTheme } from 'next-themes';
import { useState, useEffect } from 'react';

const pageTitles: Record<string, { title: string; subtitle: string }> = {
    '/': { title: 'Security Dashboard', subtitle: 'Overview of your cloud security posture' },
    '/scans': { title: 'Scan Results', subtitle: 'All vulnerabilities and misconfigurations' },
    '/assistant': { title: 'AI Remediation', subtitle: 'AI-powered security remediation assistant' },
    '/compliance': { title: 'Compliance Reports', subtitle: 'HIPAA · NIST 800-53 · ISO 27001' },
    '/settings': { title: 'Settings', subtitle: 'Account, notifications, and configuration' },
};

const roleColors: Record<string, string> = {
    admin: '#FF6B6B',
    security: '#2D9CDB',
    developer: '#27AE60',
    auditor: '#F2994A',
};

export default function Header() {
    const pathname = usePathname();
    const { userRole, userName, toasts, removeToast } = useAppStore();
    const { theme, setTheme, resolvedTheme } = useTheme();
    const [mounted, setMounted] = useState(false);
    const [showUserMenu, setShowUserMenu] = useState(false);
    const pageInfo = pageTitles[pathname] ?? { title: 'CloudShield', subtitle: '' };

    useEffect(() => setMounted(true), []);

    return (
        <>
            <header
                className="h-16 flex items-center justify-between px-6 border-b sticky top-0 z-30"
                style={{ background: 'var(--card)', borderColor: 'var(--border)' }}
            >
                {/* Page title */}
                <div>
                    <h1 className="font-bold text-lg leading-tight" style={{ color: 'var(--text)' }}>
                        {pageInfo.title}
                    </h1>
                    <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{pageInfo.subtitle}</p>
                </div>

                {/* Right controls */}
                <div className="flex items-center gap-3">
                    {/* Dark mode toggle */}
                    {mounted && (
                        <button
                            onClick={() => setTheme(resolvedTheme === 'dark' ? 'light' : 'dark')}
                            className="w-9 h-9 rounded-lg flex items-center justify-center transition-all hover:scale-105"
                            style={{ background: 'var(--bg)', color: 'var(--text-muted)' }}
                            title="Toggle dark mode"
                        >
                            {resolvedTheme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
                        </button>
                    )}

                    {/* Notifications */}
                    <button
                        className="relative w-9 h-9 rounded-lg flex items-center justify-center transition-all hover:scale-105"
                        style={{ background: 'var(--bg)', color: 'var(--text-muted)' }}
                    >
                        <Bell size={16} />
                        <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-[#FF6B6B] animate-pulse-slow" />
                    </button>

                    {/* User menu */}
                    <div className="relative">
                        <button
                            onClick={() => setShowUserMenu(!showUserMenu)}
                            className="flex items-center gap-2.5 px-3 py-1.5 rounded-lg transition-all hover:opacity-80"
                            style={{ background: 'var(--bg)' }}
                        >
                            <div className="w-7 h-7 rounded-full flex items-center justify-center text-white text-xs font-bold"
                                style={{ background: `linear-gradient(135deg, ${roleColors[userRole]}, ${roleColors[userRole]}aa)` }}>
                                {userName.split(' ').map(n => n[0]).join('').slice(0, 2)}
                            </div>
                            <div className="text-left hidden sm:block">
                                <div className="text-xs font-semibold leading-tight" style={{ color: 'var(--text)' }}>{userName}</div>
                                <div className="text-xs capitalize" style={{ color: 'var(--text-muted)' }}>{userRole}</div>
                            </div>
                            <ChevronDown size={12} style={{ color: 'var(--text-muted)' }} />
                        </button>

                        {showUserMenu && (
                            <div
                                className="absolute right-0 top-full mt-2 w-48 rounded-xl shadow-xl border py-1 z-50"
                                style={{ background: 'var(--card)', borderColor: 'var(--border)' }}
                            >
                                {(['admin', 'security', 'developer', 'auditor'] as const).map(role => (
                                    <button
                                        key={role}
                                        onClick={() => { useAppStore.getState().setUserRole(role); setShowUserMenu(false); }}
                                        className="w-full text-left px-4 py-2 text-xs capitalize transition-colors hover:opacity-80"
                                        style={{
                                            color: userRole === role ? roleColors[role] : 'var(--text)',
                                            fontWeight: userRole === role ? 600 : 400,
                                        }}
                                    >
                                        {role === 'admin' ? '👑 ' : role === 'security' ? '🛡️ ' : role === 'developer' ? '💻 ' : '📋 '}{role}
                                    </button>
                                ))}
                            </div>
                        )}
                    </div>
                </div>
            </header>

            {/* Toast notifications */}
            <div className="toast-container">
                {toasts.map(toast => (
                    <div
                        key={toast.id}
                        className="flex items-center gap-3 px-4 py-3 rounded-xl shadow-xl border animate-fade-in min-w-64 max-w-sm"
                        style={{
                            background: 'var(--card)',
                            borderColor: toast.type === 'success' ? '#27AE60' : toast.type === 'error' ? '#FF6B6B' : '#2D9CDB',
                            borderLeftWidth: 4,
                        }}
                    >
                        <span className="text-sm flex-1" style={{ color: 'var(--text)' }}>{toast.message}</span>
                        <button onClick={() => removeToast(toast.id)} style={{ color: 'var(--text-muted)' }}>
                            <Shield size={14} />
                        </button>
                    </div>
                ))}
            </div>
        </>
    );
}

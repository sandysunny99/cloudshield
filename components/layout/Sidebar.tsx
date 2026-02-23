'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useAppStore } from '@/lib/store';
import {
    LayoutDashboard, Shield, Bot, FileCheck, Settings,
    ChevronLeft, ChevronRight, ShieldCheck, Bell, X
} from 'lucide-react';
import clsx from 'clsx';

const navItems = [
    { href: '/', label: 'Dashboard', icon: LayoutDashboard },
    { href: '/scans', label: 'Scan Results', icon: Shield },
    { href: '/assistant', label: 'AI Assistant', icon: Bot },
    { href: '/compliance', label: 'Compliance', icon: FileCheck },
    { href: '/settings', label: 'Settings', icon: Settings },
];

export default function Sidebar() {
    const pathname = usePathname();
    const { sidebarOpen, toggleSidebar } = useAppStore();

    return (
        <aside
            className={clsx(
                'fixed inset-y-0 left-0 z-40 flex flex-col transition-all duration-300 border-r',
                sidebarOpen ? 'w-64' : 'w-16'
            )}
            style={{ background: 'var(--primary)', borderColor: 'var(--border)' }}
        >
            {/* Logo */}
            <div className="flex items-center h-16 px-4 border-b" style={{ borderColor: 'var(--border)' }}>
                <div className="flex items-center gap-3 min-w-0">
                    <div className="flex-shrink-0 w-8 h-8 rounded-lg flex items-center justify-center animate-glow" style={{ background: 'linear-gradient(135deg, #38bdf8, #0ea5e9)' }}>
                        <ShieldCheck size={18} className="text-white" />
                    </div>
                </div>
                {sidebarOpen && (
                    <div className="ml-3 min-w-0 animate-fade-in">
                        <div className="font-bold text-slate-100 text-sm leading-tight tracking-tight uppercase">CloudShield</div>
                        <div className="text-[10px] uppercase font-bold text-sky-500/80 tracking-widest">Sentinel Core</div>
                    </div>
                )}
            </div>

            {/* Nav */}
            <nav className="flex-1 py-6 overflow-y-auto space-y-1">
                {navItems.map(({ href, label, icon: Icon }) => {
                    const active = pathname === href;
                    return (
                        <Link
                            key={href}
                            href={href}
                            className={clsx(
                                'flex items-center gap-3 mx-3 px-3 py-2 rounded-md transition-all duration-150 group relative',
                                active
                                    ? 'text-sky-400 bg-sky-400/5 font-semibold'
                                    : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/50'
                            )}
                            title={!sidebarOpen ? label : undefined}
                        >
                            <Icon size={18} className={clsx('flex-shrink-0 transition-colors', active ? 'text-sky-400' : 'group-hover:text-slate-200')} />
                            {sidebarOpen && <span className="text-sm truncate">{label}</span>}
                            {active && (
                                <div className="absolute left-0 top-1.5 bottom-1.5 w-1 bg-sky-400 rounded-r-full shadow-[0_0_8px_rgba(56,189,248,0.5)]" />
                            )}
                        </Link>
                    );
                })}
            </nav>

            {/* Version */}
            <div className="p-4 border-t" style={{ borderColor: 'var(--border)' }}>
                {sidebarOpen ? (
                    <div className="animate-fade-in">
                        <div className="text-[10px] font-mono font-bold tracking-tighter" style={{ color: 'var(--text-muted)' }}>V1.0.4-STABLE</div>
                        <div className="flex items-center gap-2 mt-1">
                            <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                            <span className="text-[10px] uppercase font-bold text-emerald-500/80">System Online</span>
                        </div>
                    </div>
                ) : (
                    <div className="flex items-center justify-center">
                        <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                    </div>
                )}
            </div>

            {/* Collapse button */}
            <button
                onClick={toggleSidebar}
                className="absolute -right-3 top-8 w-6 h-6 rounded border flex items-center justify-center bg-[#0f172a] border-slate-700 text-slate-400 hover:text-white hover:border-sky-500 transition-all z-50 shadow-xl"
                aria-label="Toggle sidebar"
            >
                {sidebarOpen ? <ChevronLeft size={10} /> : <ChevronRight size={10} />}
            </button>
        </aside>
    );
}

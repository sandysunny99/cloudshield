'use client';

import { usePathname } from 'next/navigation';
import { useAppStore } from '@/lib/store';
import { Bell, Moon, Sun, X, Search } from 'lucide-react';
import { useTheme } from 'next-themes';
import { useState, useEffect } from 'react';
import clsx from 'clsx';

const navItems = [
    { href: '/', label: 'Dashboard' },
    { href: '/scans', label: 'Scan Results' },
    { href: '/assistant', label: 'AI Assistant' },
    { href: '/compliance', label: 'Compliance' },
    { href: '/settings', label: 'Settings' },
];

export default function Header() {
    const pathname = usePathname();
    const { userRole, userName, toasts, removeToast } = useAppStore();
    const { theme, setTheme, resolvedTheme } = useTheme();
    const [mounted, setMounted] = useState(false);

    useEffect(() => setMounted(true), []);

    const getPageTitle = () => {
        const item = navItems.find(i => i.href === pathname);
        return item ? item.label : 'CloudShield';
    };

    return (
        <header className="h-16 border-b flex items-center justify-between px-6 sticky top-0 z-30 transition-all" style={{ background: 'var(--primary)', borderColor: 'var(--border)' }}>
            <div className="flex items-center gap-4">
                <h1 className="text-sm font-bold tracking-widest text-white uppercase">{getPageTitle()}</h1>
                <div className="h-4 w-px bg-slate-800" />
                <div className="flex items-center gap-2 text-[10px] uppercase font-bold text-slate-500 tracking-widest leading-none">
                    <div className="w-1 h-1 rounded-full bg-sky-500 animate-pulse" />
                    Live System
                </div>
            </div>

            <div className="flex items-center gap-4">
                {/* Search Container */}
                <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded bg-slate-900/50 border border-slate-800 text-slate-500 hover:border-slate-700 transition-colors cursor-text group">
                    <Search size={14} className="group-hover:text-slate-300 transition-colors" />
                    <span className="text-[11px] font-medium">Search Intel...</span>
                    <kbd className="text-[10px] font-mono bg-slate-800 px-1 rounded border border-slate-700 ml-2">⌘K</kbd>
                </div>

                <div className="flex items-center gap-1 border-l border-slate-800 pl-4">
                    {mounted && (
                        <button
                            onClick={() => setTheme(resolvedTheme === 'dark' ? 'light' : 'dark')}
                            className="p-2 rounded text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
                        >
                            {resolvedTheme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
                        </button>
                    )}

                    <button className="p-2 rounded text-slate-400 hover:text-white hover:bg-slate-800 transition-colors relative">
                        <Bell size={16} />
                        <span className="absolute top-2 right-2 w-1.5 h-1.5 bg-sky-500 rounded-full border border-slate-950" />
                    </button>

                    <div className="h-6 w-px bg-slate-800 mx-2" />

                    <div className="flex items-center gap-3 pl-1">
                        <div className="text-right hidden sm:block">
                            <div className="text-[11px] font-bold text-white leading-none whitespace-nowrap">{userName}</div>
                            <div className="text-[9px] font-bold text-sky-500 uppercase mt-1 leading-none tracking-widest">{userRole}</div>
                        </div>
                        <div className="w-8 h-8 rounded bg-slate-800 border border-slate-700 flex items-center justify-center text-[10px] font-bold text-sky-400 overflow-hidden relative group cursor-pointer hover:border-sky-500 transition-all">
                            SK
                            <div className="absolute inset-x-0 bottom-0 h-0.5 bg-sky-400 scale-x-0 group-hover:scale-x-100 transition-transform origin-left" />
                        </div>
                    </div>
                </div>
            </div>

            {/* Toast Container */}
            <div className="toast-container fixed bottom-6 right-6 z-50 flex flex-col gap-2">
                {toasts.map((toast) => (
                    <div
                        key={toast.id}
                        className={clsx(
                            'px-4 py-2.5 rounded border shadow-2xl flex items-center gap-3 animate-fade-in glass min-w-[280px]',
                            toast.type === 'success' && 'border-emerald-500/30 text-emerald-400',
                            toast.type === 'error' && 'border-red-500/30 text-red-400',
                            toast.type === 'info' && 'border-sky-500/30 text-sky-400'
                        )}
                    >
                        <span className="text-[11px] font-bold uppercase tracking-wider flex-1">{toast.message}</span>
                        <button onClick={() => removeToast(toast.id)} className="text-slate-500 hover:text-white transition-colors">
                            <X size={14} />
                        </button>
                    </div>
                ))}
            </div>
        </header>
    );
}

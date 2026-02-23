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
                'fixed inset-y-0 left-0 z-40 flex flex-col transition-all duration-300',
                sidebarOpen ? 'w-64' : 'w-16'
            )}
            style={{ background: 'var(--primary)' }}
        >
            {/* Logo */}
            <div className="flex items-center h-16 px-4 border-b" style={{ borderColor: 'rgba(255,255,255,0.08)' }}>
                <div className="flex items-center gap-3 min-w-0">
                    <div className="flex-shrink-0 w-8 h-8 rounded-lg flex items-center justify-center" style={{ background: 'linear-gradient(135deg, #2D9CDB, #1a6fa8)' }}>
                        <ShieldCheck size={18} className="text-white" />
                    </div>
                    {sidebarOpen && (
                        <div className="min-w-0 animate-fade-in">
                            <div className="font-bold text-white text-sm leading-tight">CloudShield</div>
                            <div className="text-xs" style={{ color: 'rgba(255,255,255,0.5)' }}>Security Platform</div>
                        </div>
                    )}
                </div>
            </div>

            {/* Nav */}
            <nav className="flex-1 py-4 overflow-y-auto">
                {navItems.map(({ href, label, icon: Icon }) => {
                    const active = pathname === href;
                    return (
                        <Link
                            key={href}
                            href={href}
                            className={clsx(
                                'flex items-center gap-3 mx-2 my-0.5 px-3 py-2.5 rounded-lg transition-all duration-200 group',
                                active
                                    ? 'text-white'
                                    : 'text-white/60 hover:text-white hover:bg-white/8'
                            )}
                            style={active ? { background: 'rgba(45,156,219,0.2)', borderLeft: '3px solid #2D9CDB' } : {}}
                            title={!sidebarOpen ? label : undefined}
                        >
                            <Icon size={18} className={clsx('flex-shrink-0', active ? 'text-[#4FC3F7]' : '')} />
                            {sidebarOpen && <span className="text-sm font-medium animate-fade-in">{label}</span>}
                            {sidebarOpen && active && (
                                <span className="ml-auto w-1.5 h-1.5 rounded-full bg-[#4FC3F7]" />
                            )}
                        </Link>
                    );
                })}
            </nav>

            {/* Version */}
            {sidebarOpen && (
                <div className="p-4 border-t animate-fade-in" style={{ borderColor: 'rgba(255,255,255,0.08)' }}>
                    <div className="text-xs" style={{ color: 'rgba(255,255,255,0.3)' }}>CloudShield v1.0.0</div>
                    <div className="text-xs mt-0.5" style={{ color: 'rgba(255,255,255,0.2)' }}>Enterprise Edition</div>
                </div>
            )}

            {/* Collapse button */}
            <button
                onClick={toggleSidebar}
                className="absolute -right-3 top-20 w-6 h-6 rounded-full border flex items-center justify-center bg-white shadow-md hover:shadow-lg transition-shadow z-50"
                style={{ borderColor: 'var(--border)' }}
                aria-label="Toggle sidebar"
            >
                {sidebarOpen ? <ChevronLeft size={12} className="text-gray-600" /> : <ChevronRight size={12} className="text-gray-600" />}
            </button>
        </aside>
    );
}

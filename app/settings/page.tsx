'use client';

import { useState } from 'react';
import {
    User, Shield, Bell, Key, Database, Globe,
    Lock, ChevronRight, Save, Zap, Info, ShieldCheck,
    Cpu, HardDrive, Terminal
} from 'lucide-react';
import { useAppStore } from '@/lib/store';
import clsx from 'clsx';

type Tab = 'profile' | 'security' | 'notifications' | 'api' | 'fleet';

export default function SettingsPage() {
    const { addToast, userRole, userName } = useAppStore();
    const [activeTab, setActiveTab] = useState<Tab>('security');
    const [saving, setSaving] = useState(false);

    const handleSave = () => {
        setSaving(true);
        addToast('SYNCING SETTINGS TO SENTINEL CORE...', 'info');
        setTimeout(() => {
            setSaving(false);
            addToast('CONFIGURATION UPDATED: Global policies synchronized.', 'success');
        }, 1500);
    };

    const sidebarItems = [
        { id: 'profile', label: 'Identity & Access', icon: User },
        { id: 'security', label: 'Platform Security', icon: Shield },
        { id: 'notifications', label: 'Intel Routing', icon: Bell },
        { id: 'api', label: 'API & Integrations', icon: Key },
        { id: 'fleet', label: 'Fleet Configuration', icon: Cpu },
    ];

    return (
        <div className="flex gap-6 animate-fade-in pb-10">

            {/* Control Plane Sidebar */}
            <aside className="w-64 flex-shrink-0">
                <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-2 space-y-1">
                    {sidebarItems.map((item) => (
                        <button
                            key={item.id}
                            onClick={() => setActiveTab(item.id as Tab)}
                            className={clsx(
                                "w-full flex items-center gap-3 px-4 py-3 rounded-lg text-left transition-all group",
                                activeTab === item.id
                                    ? "bg-sky-500/10 text-sky-400 border border-sky-500/20"
                                    : "text-slate-500 hover:text-slate-200 hover:bg-slate-800/50 border border-transparent"
                            )}
                        >
                            <item.icon size={16} className={clsx(
                                "transition-colors",
                                activeTab === item.id ? "text-sky-400" : "group-hover:text-slate-300"
                            )} />
                            <span className="text-[11px] font-black uppercase tracking-widest">{item.label}</span>
                            {activeTab === item.id && <ChevronRight size={14} className="ml-auto" />}
                        </button>
                    ))}
                </div>

                <div className="mt-6 rounded-xl border border-slate-800 bg-slate-900/40 p-5">
                    <div className="flex items-center gap-2 mb-4">
                        <ShieldCheck size={16} className="text-emerald-500" />
                        <span className="text-[10px] font-black text-white uppercase tracking-widest">Trust Center</span>
                    </div>
                    <p className="text-[10px] text-slate-500 leading-relaxed font-bold uppercase tracking-tighter">
                        Your account is currently operating under <span className="text-sky-400">{userRole.toUpperCase()}</span> policy constraints.
                    </p>
                </div>
            </aside>

            {/* Config Workspace */}
            <main className="flex-1 min-w-0">
                <div className="rounded-xl border border-slate-800 bg-slate-900/20 shadow-2xl overflow-hidden backdrop-blur-sm">

                    {/* Workspace Header */}
                    <div className="px-6 py-5 border-b border-slate-800 bg-slate-900/60 flex items-center justify-between">
                        <div>
                            <h3 className="text-lg font-bold text-white uppercase tracking-tight">
                                {sidebarItems.find(item => item.id === activeTab)?.label}
                            </h3>
                            <p className="text-[11px] text-slate-500 uppercase font-black tracking-widest mt-1">Global Configuration Partition</p>
                        </div>
                        <button
                            onClick={handleSave}
                            disabled={saving}
                            className="bg-sky-500 hover:bg-sky-400 text-slate-950 px-5 py-2 rounded-lg text-xs font-black uppercase tracking-widest flex items-center gap-2 transition-all shadow-[0_0_15px_rgba(56,189,248,0.2)] disabled:opacity-50"
                        >
                            <Save size={14} /> {saving ? 'SYNCING...' : 'SAVE CHANGES'}
                        </button>
                    </div>

                    {/* Workspace Content */}
                    <div className="p-8 space-y-10">
                        {activeTab === 'profile' && (
                            <section className="space-y-6">
                                <SettingGroup title="Operator Identity">
                                    <div className="grid grid-cols-2 gap-6">
                                        <SettingField label="Display Name" value={userName} />
                                        <SettingField label="Operator ID" value="SENTINEL-X892" />
                                        <SettingField label="Primary Region" value="US-EAST-1 (N. Virginia)" />
                                        <SettingField label="Auth Status" value="MFA PROTECTED" success />
                                    </div>
                                </SettingGroup>
                            </section>
                        )}

                        {activeTab === 'security' && (
                            <section className="space-y-6">
                                <SettingGroup title="Platform Hardening">
                                    <div className="space-y-4">
                                        <ToggleSetting label="Auto-Remediate Critical Anomalies" description="Sentinel Core will execute patching on detected zero-days immediately." active />
                                        <ToggleSetting label="Intelligent Threat Correlation" description="Use ML to link telemetry across VPC boundaries." active />
                                        <ToggleSetting label="Deep Packet Inspection" description="Enable intercept on all egress traffic for sensitive payloads." />
                                    </div>
                                </SettingGroup>

                                <SettingGroup title="Identity Access Management (IAM)">
                                    <div className="p-4 rounded-lg bg-slate-950 border border-slate-800">
                                        <div className="flex items-center gap-3 mb-4">
                                            <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                                            <span className="text-[10px] font-black text-white uppercase tracking-widest">Permission Scope: RESTRICTED</span>
                                        </div>
                                        <div className="text-[11px] text-slate-400 font-medium leading-relaxed">
                                            Your role (<span className="text-sky-400 font-bold">{userRole}</span>) is governed by cross-region IAM policies.
                                            Contact the Master Admin to elevate your security clearance.
                                        </div>
                                    </div>
                                </SettingGroup>
                            </section>
                        )}

                        {activeTab === 'api' && (
                            <section className="space-y-6">
                                <SettingGroup title="Sentinel Core API">
                                    <div className="p-4 rounded-lg bg-slate-950 border border-slate-900 border-dashed relative group">
                                        <p className="text-[9px] font-black text-slate-500 uppercase tracking-widest mb-2">ACTIVE API KEY</p>
                                        <p className="text-xs font-mono text-white tracking-widest">cs_live_9a2bc8********************f3e1</p>
                                        <button className="absolute top-4 right-4 p-2 rounded hover:bg-slate-800 transition-colors">
                                            <Zap size={14} className="text-sky-400" />
                                        </button>
                                    </div>
                                </SettingGroup>

                                <SettingGroup title="Telemetry Connectors">
                                    <div className="grid grid-cols-3 gap-4">
                                        {['AWS', 'Azure', 'GCP', 'Kubernetes', 'Splunk', 'CrowdStrike'].map(c => (
                                            <div key={c} className="p-3 rounded-lg border border-slate-800 bg-slate-950/50 flex items-center justify-between group hover:border-sky-500/50 transition-all">
                                                <span className="text-[11px] font-bold text-slate-400 group-hover:text-white uppercase">{c}</span>
                                                <div className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                                            </div>
                                        ))}
                                    </div>
                                </SettingGroup>
                            </section>
                        )}

                        {activeTab === 'fleet' && (
                            <section className="space-y-6 text-center py-10">
                                <Cpu size={48} className="text-slate-800 mx-auto mb-4" />
                                <h4 className="text-white font-black uppercase tracking-widest">Fleet Telemetry Partition</h4>
                                <p className="text-slate-500 text-xs max-w-sm mx-auto uppercase font-bold tracking-tighter">
                                    Accessing high-level fleet orchestration requires level 4 security clearance.
                                    Hardware identifiers and agent telemetry profiles are locked.
                                </p>
                            </section>
                        )}
                    </div>
                </div>
            </main>
        </div>
    );
}

// ─── UI Primitives ───────────────────────────────────────────────────────────

function SettingGroup({ title, children }: { title: string; children: React.ReactNode }) {
    return (
        <div className="space-y-4">
            <h4 className="text-[10px] font-black text-slate-500 uppercase tracking-widest border-l-2 border-sky-500/50 pl-3">{title}</h4>
            {children}
        </div>
    );
}

function SettingField({ label, value, success }: { label: string; value: string; success?: boolean }) {
    return (
        <div className="space-y-2">
            <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest">{label}</label>
            <div className={clsx(
                "w-full px-4 py-3 rounded-lg bg-slate-950 border border-slate-900 font-bold text-sm transition-all",
                success ? "text-emerald-400 border-emerald-500/10" : "text-white"
            )}>
                {value}
            </div>
        </div>
    );
}

function ToggleSetting({ label, description, active }: { label: string; description: string; active?: boolean }) {
    return (
        <div className="flex items-center justify-between p-4 rounded-xl border border-slate-800 bg-slate-900/40 hover:bg-slate-900/60 transition-all">
            <div className="flex-1 pr-10">
                <div className="text-xs font-black text-white uppercase tracking-tight mb-1">{label}</div>
                <div className="text-[10px] text-slate-500 font-bold uppercase tracking-tighter">{description}</div>
            </div>
            <button className={clsx(
                "w-12 h-6 rounded-full p-1 transition-all relative flex items-center",
                active ? "bg-sky-500" : "bg-slate-800"
            )}>
                <div className={clsx(
                    "w-4 h-4 rounded-full bg-white shadow-lg transition-transform",
                    active ? "translate-x-6" : "translate-x-0"
                )} />
            </button>
        </div>
    );
}

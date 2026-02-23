'use client';

import { create } from 'zustand';
import type { Finding, Severity, ResourceType, FindingStatus, ComplianceFramework } from './mock-data';

interface FilterState {
    severity: Severity[];
    resourceType: ResourceType[];
    framework: ComplianceFramework[];
    status: FindingStatus[];
}

interface AppState {
    // Auth
    userRole: 'admin' | 'security' | 'developer' | 'auditor';
    userName: string;
    setUserRole: (role: AppState['userRole']) => void;

    // Sidebar
    sidebarOpen: boolean;
    toggleSidebar: () => void;

    // Selected finding
    selectedFinding: Finding | null;
    setSelectedFinding: (f: Finding | null) => void;

    // Filters
    filters: FilterState;
    setFilter: <K extends keyof FilterState>(key: K, value: FilterState[K]) => void;
    resetFilters: () => void;

    // Toast
    toasts: { id: string; message: string; type: 'success' | 'error' | 'info' }[];
    addToast: (message: string, type?: 'success' | 'error' | 'info') => void;
    removeToast: (id: string) => void;

    // AI Chat
    chatMessages: { role: 'user' | 'assistant'; content: string; timestamp: Date }[];
    addChatMessage: (role: 'user' | 'assistant', content: string) => void;
    clearChat: () => void;
}

const defaultFilters: FilterState = {
    severity: [],
    resourceType: [],
    framework: [],
    status: [],
};

export const useAppStore = create<AppState>((set, get) => ({
    // Auth
    userRole: 'admin',
    userName: 'Sandeep Kumar',
    setUserRole: (role) => set({ userRole: role }),

    // Sidebar
    sidebarOpen: true,
    toggleSidebar: () => set((s) => ({ sidebarOpen: !s.sidebarOpen })),

    // Finding
    selectedFinding: null,
    setSelectedFinding: (f) => set({ selectedFinding: f }),

    // Filters
    filters: defaultFilters,
    setFilter: (key, value) => set((s) => ({ filters: { ...s.filters, [key]: value } })),
    resetFilters: () => set({ filters: defaultFilters }),

    // Toast
    toasts: [],
    addToast: (message, type = 'info') => {
        const id = Math.random().toString(36).slice(2);
        set((s) => ({ toasts: [...s.toasts, { id, message, type }] }));
        setTimeout(() => get().removeToast(id), 4000);
    },
    removeToast: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),

    // Chat
    chatMessages: [
        { role: 'assistant', content: "Hello! I'm **CloudShield AI**, your security remediation assistant. I can help you understand vulnerabilities, generate remediation commands, and assess compliance impact.\n\n**Try asking:**\n- \"How do I fix the runc vulnerability?\"\n- \"What's the HIPAA impact of the S3 finding?\"\n- \"Generate a Terraform snippet for the IAM fix\"\n\nOr select a finding from the list to get contextual guidance.", timestamp: new Date() },
    ],
    addChatMessage: (role, content) => set((s) => ({
        chatMessages: [...s.chatMessages, { role, content, timestamp: new Date() }],
    })),
    clearChat: () => set({ chatMessages: [] }),
}));

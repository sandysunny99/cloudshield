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

    // Selection
    selectedFindings: string[];
    toggleFindingSelection: (id: string) => void;
    clearSelectedFindings: () => void;

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
    addMessage: (message: { role: 'user' | 'assistant'; content: string }) => void;
    clearMessages: () => void;
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

    // Selection
    selectedFindings: [],
    toggleFindingSelection: (id) => set((s) => ({
        selectedFindings: s.selectedFindings.includes(id)
            ? s.selectedFindings.filter((i) => i !== id)
            : [...s.selectedFindings, id],
    })),
    clearSelectedFindings: () => set({ selectedFindings: [] }),

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
        { role: 'assistant', content: "SYSTEM: Sentinel Copilot Online. Analyzing fleet telemetry...\n\nI am your **Security Copilot**. Select findings for context ingestion or ask me to correlate telemetry.", timestamp: new Date() },
    ],
    addMessage: (msg) => set((s) => ({
        chatMessages: [...s.chatMessages, { ...msg, timestamp: new Date() }],
    })),
    clearMessages: () => set({ chatMessages: [] }),
}));

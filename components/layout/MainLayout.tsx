'use client';

import { useAppStore } from '@/lib/store';
import clsx from 'clsx';
import Sidebar from '@/components/layout/Sidebar';
import Header from '@/components/layout/Header';

export default function MainLayout({ children }: { children: React.ReactNode }) {
    const { sidebarOpen } = useAppStore();

    return (
        <div className="flex h-screen overflow-hidden bg-[#020617]"> {/* Slate 950 for enterprise look */}
            <Sidebar />

            <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
                <Header />
                <main className="flex-1 overflow-y-auto p-6 scroll-smooth">
                    <div className="max-w-[1600px] mx-auto">
                        {children}
                    </div>
                </main>
            </div>
        </div>
    );
}

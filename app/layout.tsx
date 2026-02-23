import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import './globals.css';
import { ThemeProvider } from 'next-themes';
import Sidebar from '@/components/layout/Sidebar';
import Header from '@/components/layout/Header';

const inter = Inter({ subsets: ['latin'], variable: '--font-inter' });

export const metadata: Metadata = {
  title: 'CloudShield – AI-Powered Cloud Security',
  description: 'Enterprise-grade cloud-native security misconfiguration detection, AI-powered remediation, and compliance reporting platform.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={inter.variable} suppressHydrationWarning>
        <ThemeProvider attribute="class" defaultTheme="dark" enableSystem>
          <div className="flex h-screen overflow-hidden">
            <Sidebar />
            {/* Main content — ml-64 when sidebar open, ml-16 when collapsed */}
            <div className="flex-1 flex flex-col min-w-0 ml-64 transition-all duration-300">
              <Header />
              <main className="flex-1 overflow-y-auto p-6" style={{ background: 'var(--bg)' }}>
                {children}
              </main>
            </div>
          </div>
        </ThemeProvider>
      </body>
    </html>
  );
}

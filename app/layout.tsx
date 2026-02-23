import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import './globals.css';
import { ThemeProvider } from 'next-themes';
import Sidebar from '@/components/layout/Sidebar';
import Header from '@/components/layout/Header';
import { Analytics } from '@vercel/analytics/next';

const inter = Inter({ subsets: ['latin'], variable: '--font-inter' });

export const metadata: Metadata = {
  title: 'CloudShield – AI-Powered Cloud Security',
  description: 'Enterprise-grade cloud-native security misconfiguration detection, AI-powered remediation, and compliance reporting platform.',
};

import MainLayout from '@/components/layout/MainLayout';

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={inter.variable} suppressHydrationWarning>
        <ThemeProvider attribute="class" defaultTheme="dark" enableSystem>
          <MainLayout>{children}</MainLayout>
        </ThemeProvider>
        <Analytics />
      </body>
    </html>
  );
}

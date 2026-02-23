'use client';

import { useState } from 'react';
import dynamic from 'next/dynamic';
import Link from 'next/link';
import {
  Shield, AlertTriangle, Clock, Activity,
  TrendingDown, ChevronRight, Zap, ArrowUpRight
} from 'lucide-react';
import { dashboardStats, mockFindings, complianceSummary } from '@/lib/mock-data';
import { useAppStore } from '@/lib/store';
import clsx from 'clsx';

const RiskTrendChart = dynamic(() => import('@/components/charts/RiskTrendChart'), { ssr: false });

const severityConfig = {
  critical: { color: '#FF6B6B', bg: 'rgba(255,107,107,0.1)', label: 'Critical' },
  high: { color: '#F2994A', bg: 'rgba(242,153,74,0.1)', label: 'High' },
  medium: { color: '#F7D228', bg: 'rgba(247,210,40,0.1)', label: 'Medium' },
  low: { color: '#27AE60', bg: 'rgba(39,174,96,0.1)', label: 'Low' },
};

const statCards = [
  {
    label: 'Total Scans',
    value: '1,500',
    change: '+12% vs last month',
    icon: Activity,
    iconColor: '#2D9CDB',
    iconBg: 'rgba(45,156,219,0.12)',
  },
  {
    label: 'Critical Findings',
    value: '23',
    change: '+3 since yesterday',
    icon: AlertTriangle,
    iconColor: '#FF6B6B',
    iconBg: 'rgba(255,107,107,0.12)',
    alert: true,
  },
  {
    label: 'Avg Remediation',
    value: '21h',
    change: '↓ 4h from last week',
    icon: Clock,
    iconColor: '#27AE60',
    iconBg: 'rgba(39,174,96,0.12)',
  },
  {
    label: 'Open Issues',
    value: '142',
    change: '38 resolved this week',
    icon: Shield,
    iconColor: '#F2994A',
    iconBg: 'rgba(242,153,74,0.12)',
  },
];

const topFindings = mockFindings
  .filter(f => f.status === 'open')
  .sort((a, b) => b.riskScore - a.riskScore)
  .slice(0, 5);

const complianceItems = [
  { name: 'HIPAA', ...complianceSummary.hipaa, color: '#2D9CDB' },
  { name: 'NIST 800-53', ...complianceSummary.nist, color: '#27AE60' },
  { name: 'ISO 27001', ...complianceSummary.iso, color: '#F2994A' },
];

export default function DashboardPage() {
  const { addToast } = useAppStore();
  const [scanning, setScanning] = useState(false);

  const handleScan = () => {
    setScanning(true);
    addToast('🔍 Scan initiated — CloudShield is analyzing your environment...', 'info');
    setTimeout(() => {
      setScanning(false);
      addToast('✅ Scan complete! 3 new findings detected.', 'success');
    }, 3000);
  };

  return (
    <div className="max-w-7xl mx-auto space-y-6 animate-fade-in">

      {/* Alert banner */}
      <div className="flex items-center gap-3 px-5 py-3 rounded-xl border" style={{ background: 'rgba(255,107,107,0.08)', borderColor: 'rgba(255,107,107,0.3)' }}>
        <AlertTriangle size={16} className="text-[#FF6B6B] flex-shrink-0" />
        <p className="text-sm" style={{ color: 'var(--text)' }}>
          <span className="font-semibold text-[#FF6B6B]">3 critical vulnerabilities</span> require immediate attention. CVE-2024-3094 (XZ Backdoor) detected in staging environment.
        </p>
        <Link href="/scans" className="ml-auto text-xs font-semibold text-[#2D9CDB] hover:underline whitespace-nowrap flex items-center gap-1">
          View all <ChevronRight size={12} />
        </Link>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {statCards.map((card) => (
          <div key={card.label} className="card-hover rounded-2xl border p-5" style={{ background: 'var(--card)', borderColor: 'var(--border)' }}>
            <div className="flex items-start justify-between mb-3">
              <div className="w-10 h-10 rounded-xl flex items-center justify-center" style={{ background: card.iconBg }}>
                <card.icon size={18} style={{ color: card.iconColor }} />
              </div>
              {card.alert && (
                <span className="text-xs px-2 py-0.5 rounded-full font-medium" style={{ background: 'rgba(255,107,107,0.12)', color: '#FF6B6B' }}>
                  Live
                </span>
              )}
            </div>
            <div className="text-2xl font-bold mb-1" style={{ color: 'var(--text)' }}>{card.value}</div>
            <div className="text-xs font-medium mb-1" style={{ color: 'var(--text-muted)' }}>{card.label}</div>
            <div className="text-xs" style={{ color: card.alert ? '#FF6B6B' : '#27AE60' }}>{card.change}</div>
          </div>
        ))}
      </div>

      {/* Risk trend chart */}
      <div className="rounded-2xl border p-6" style={{ background: 'var(--card)', borderColor: 'var(--border)' }}>
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="font-semibold" style={{ color: 'var(--text)' }}>Risk Trend</h2>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>Finding counts over last 30 days</p>
          </div>
          <div className="flex items-center gap-2">
            <TrendingDown size={14} className="text-[#27AE60]" />
            <span className="text-xs text-[#27AE60] font-medium">↓ 18% overall risk</span>
          </div>
        </div>
        <RiskTrendChart />
      </div>

      {/* Bottom two-column layout */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

        {/* Top Vulnerabilities */}
        <div className="rounded-2xl border p-5" style={{ background: 'var(--card)', borderColor: 'var(--border)' }}>
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-semibold" style={{ color: 'var(--text)' }}>Top Vulnerabilities</h2>
            <Link href="/scans" className="text-xs text-[#2D9CDB] hover:underline flex items-center gap-1">
              View all <ArrowUpRight size={10} />
            </Link>
          </div>
          <div className="space-y-2.5">
            {topFindings.map((f) => {
              const cfg = severityConfig[f.severity];
              return (
                <Link key={f.id} href="/scans" className="flex items-center gap-3 p-3 rounded-xl border transition-all hover:opacity-80" style={{ borderColor: 'var(--border)', background: 'var(--bg)' }}>
                  <div className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: cfg.color }} />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium truncate" style={{ color: 'var(--text)' }}>{f.title}</p>
                    <p className="text-xs truncate mt-0.5" style={{ color: 'var(--text-muted)' }}>{f.resource}</p>
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <span className={clsx('text-xs px-2 py-0.5 rounded-full font-medium badge-' + f.severity)}>
                      {cfg.label}
                    </span>
                    <span className="text-xs font-bold" style={{ color: cfg.color }}>{f.riskScore.toFixed(1)}</span>
                  </div>
                </Link>
              );
            })}
          </div>
        </div>

        {/* Compliance Status */}
        <div className="rounded-2xl border p-5" style={{ background: 'var(--card)', borderColor: 'var(--border)' }}>
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-semibold" style={{ color: 'var(--text)' }}>Compliance Status</h2>
            <Link href="/compliance" className="text-xs text-[#2D9CDB] hover:underline flex items-center gap-1">
              Reports <ArrowUpRight size={10} />
            </Link>
          </div>

          <div className="space-y-5">
            {complianceItems.map((item) => (
              <div key={item.name}>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-sm font-medium" style={{ color: 'var(--text)' }}>{item.name}</span>
                  <div className="flex items-center gap-3 text-xs" style={{ color: 'var(--text-muted)' }}>
                    <span className="text-[#27AE60]">{item.pass} pass</span>
                    <span className="text-[#FF6B6B]">{item.fail} fail</span>
                    <span className="font-bold" style={{ color: item.color }}>{item.percentage}%</span>
                  </div>
                </div>
                <div className="h-2 rounded-full overflow-hidden" style={{ background: 'var(--bg)' }}>
                  <div
                    className="h-full rounded-full transition-all duration-700"
                    style={{ width: `${item.percentage}%`, background: `linear-gradient(90deg, ${item.color}, ${item.color}cc)` }}
                  />
                </div>
              </div>
            ))}
          </div>

          <div className="mt-5 pt-4 border-t" style={{ borderColor: 'var(--border)' }}>
            <div className="flex items-center gap-2 text-xs" style={{ color: 'var(--text-muted)' }}>
              <Zap size={12} className="text-[#2D9CDB]" />
              Overall compliance score:
              <span className="font-bold text-[#2D9CDB]">72%</span>
            </div>
          </div>
        </div>
      </div>

      {/* Quick Scan button */}
      <div className="flex justify-end">
        <button
          onClick={handleScan}
          disabled={scanning}
          className="flex items-center gap-2 px-6 py-3 rounded-xl text-white font-semibold transition-all hover:opacity-90 hover:scale-105 disabled:opacity-60 disabled:scale-100"
          style={{ background: 'linear-gradient(135deg, #2D9CDB, #1a6fa8)' }}
        >
          {scanning ? (
            <>
              <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              Scanning...
            </>
          ) : (
            <>
              <Zap size={16} /> Run New Scan
            </>
          )}
        </button>
      </div>
    </div>
  );
}

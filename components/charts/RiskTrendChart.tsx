'use client';

import {
    LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer
} from 'recharts';
import { riskTrendData } from '@/lib/mock-data';

const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
        return (
            <div className="px-4 py-3 rounded-xl shadow-xl border" style={{ background: 'var(--card)', borderColor: 'var(--border)' }}>
                <p className="text-xs font-semibold mb-2" style={{ color: 'var(--text)' }}>{label}</p>
                {payload.map((p: any) => (
                    <div key={p.name} className="flex items-center gap-2 text-xs mb-1">
                        <span className="w-2 h-2 rounded-full" style={{ background: p.color }} />
                        <span style={{ color: 'var(--text-muted)' }}>{p.name}:</span>
                        <span className="font-semibold" style={{ color: 'var(--text)' }}>{p.value}</span>
                    </div>
                ))}
            </div>
        );
    }
    return null;
};

export default function RiskTrendChart() {
    return (
        <ResponsiveContainer width="100%" height={240}>
            <LineChart data={riskTrendData} margin={{ top: 5, right: 20, left: -10, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" strokeOpacity={0.5} />
                <XAxis
                    dataKey="date"
                    tick={{ fontSize: 11, fill: 'var(--text-muted)' }}
                    axisLine={false}
                    tickLine={false}
                />
                <YAxis
                    tick={{ fontSize: 11, fill: 'var(--text-muted)' }}
                    axisLine={false}
                    tickLine={false}
                />
                <Tooltip content={<CustomTooltip />} />
                <Legend
                    iconType="circle"
                    iconSize={8}
                    wrapperStyle={{ fontSize: 11, paddingTop: 16 }}
                />
                <Line type="monotone" dataKey="critical" stroke="#FF6B6B" strokeWidth={2.5} dot={false} activeDot={{ r: 5 }} name="Critical" />
                <Line type="monotone" dataKey="high" stroke="#F2994A" strokeWidth={2} dot={false} activeDot={{ r: 4 }} name="High" />
                <Line type="monotone" dataKey="medium" stroke="#F7D228" strokeWidth={2} dot={false} activeDot={{ r: 4 }} name="Medium" />
                <Line type="monotone" dataKey="low" stroke="#27AE60" strokeWidth={1.5} dot={false} activeDot={{ r: 4 }} name="Low" strokeDasharray="4 2" />
            </LineChart>
        </ResponsiveContainer>
    );
}

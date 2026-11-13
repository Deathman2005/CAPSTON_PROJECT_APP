import React from 'react';
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
} from 'recharts';
import { ThreatDistributionResponse } from '../services/api';

interface ThreatChartProps {
  distribution: ThreatDistributionResponse | null;
}

const CLASSIFICATION_COLORS: Record<string, string> = {
  SAFE: '#10b981',
  SUSPICIOUS: '#f59e0b',
  MALICIOUS: '#f43f5e',
  UNKNOWN: '#64748b',
};

export const ThreatChart: React.FC<ThreatChartProps> = ({ distribution }) => {
  const classifications = distribution?.classifications || [];
  const sources = distribution?.sources || [];

  const totalClassCount = classifications.reduce((acc, curr) => acc + curr.count, 0);

  if (totalClassCount === 0) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 text-center text-slate-400 space-y-2">
        <h3 className="text-white font-semibold text-base">Threat Intelligence Distribution</h3>
        <p className="text-sm text-slate-500">
          No security inquiries recorded yet. Run a scan from the Android app or manual scanner to populate real-time analytics.
        </p>
      </div>
    );
  }

  const pieData = classifications.map((item) => ({
    name: item.name,
    value: item.count,
    percentage: item.percentage,
  }));

  const barData = sources.map((item) => ({
    name: item.name.replace('_', ' '),
    count: item.count,
  }));

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* Classification Distribution */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h3 className="text-white font-semibold text-sm">Security Classification Breakdown</h3>
          <span className="text-xs text-slate-400">{totalClassCount} total inquiries</span>
        </div>
        <div className="h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={pieData}
                cx="50%"
                cy="50%"
                innerRadius={50}
                outerRadius={80}
                paddingAngle={4}
                dataKey="value"
                nameKey="name"
              >
                {pieData.map((entry) => (
                  <Cell
                    key={`cell-${entry.name}`}
                    fill={CLASSIFICATION_COLORS[entry.name] || '#94a3b8'}
                  />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  backgroundColor: '#0f172a',
                  borderColor: '#334155',
                  borderRadius: '0.5rem',
                  fontSize: '0.75rem',
                  color: '#f8fafc',
                }}
              />
              <Legend
                formatter={(value) => (
                  <span className="text-slate-300 text-xs font-medium">{value}</span>
                )}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Ingestion Channels Breakdown */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h3 className="text-white font-semibold text-sm">Detection Ingestion Channels</h3>
          <span className="text-xs text-slate-400">Sources</span>
        </div>
        <div className="h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={barData} margin={{ top: 10, right: 10, left: -20, bottom: 20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis
                dataKey="name"
                tick={{ fill: '#94a3b8', fontSize: 11 }}
                angle={-15}
                textAnchor="end"
              />
              <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} allowDecimals={false} />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#0f172a',
                  borderColor: '#334155',
                  borderRadius: '0.5rem',
                  fontSize: '0.75rem',
                  color: '#f8fafc',
                }}
              />
              <Bar dataKey="count" fill="#06b6d4" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
};


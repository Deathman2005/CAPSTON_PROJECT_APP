import React from 'react';
import {
  Database,
  Globe,
  Radio,
  Clock,
  ShieldCheck,
  AlertTriangle,
  Flame,
  CheckCircle2,
  Terminal,
} from 'lucide-react';
import {
  HealthResponse,
  ProvidersHealthResponse,
  DashboardStats,
  ThreatDistributionResponse,
  RecentScanItem,
} from '../services/api';
import { MetricCard } from '../components/MetricCard';
import { StatusBadge } from '../components/StatusBadge';
import { ThreatChart } from '../components/ThreatChart';
import { RecentScansTable } from '../components/RecentScansTable';

interface OverviewProps {
  health: HealthResponse | null;
  providers: ProvidersHealthResponse | null;
  stats: DashboardStats | null;
  distribution: ThreatDistributionResponse | null;
  recentScans: RecentScanItem[];
  error: string | null;
}

export const Overview: React.FC<OverviewProps> = ({
  health,
  providers,
  stats,
  distribution,
  recentScans,
  error,
}) => {
  return (
    <div className="space-y-6">
      {/* Top Banner / Error */}
      {error && (
        <div className="bg-rose-950/40 border border-rose-800/60 rounded-xl p-4 flex items-start space-x-3 text-rose-200">
          <AlertTriangle className="w-5 h-5 text-rose-400 flex-shrink-0 mt-0.5" />
          <div className="text-sm">
            <p className="font-semibold text-rose-300">Backend Connection Notice</p>
            <p className="text-rose-200/80 mt-0.5">{error}</p>
            <p className="text-xs text-rose-300/70 mt-1">
              Ensure the FastAPI backend is running (<code className="bg-rose-900/40 px-1 py-0.5 rounded font-mono">uvicorn app.main:app --port 8000</code>).
            </p>
          </div>
        </div>
      )}

      {/* Primary Metrics (Live data from backend) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Total Scans"
          value={stats?.total_scans ?? 0}
          subtitle="Real-time SMS & URL inquiries"
          icon={Radio}
        />
        <MetricCard
          title="Safe Messages"
          value={stats?.safe_scans ?? 0}
          subtitle="Verified authentic SMS"
          icon={CheckCircle2}
          variant="safe"
        />
        <MetricCard
          title="Suspicious Messages"
          value={stats?.suspicious_scans ?? 0}
          subtitle="Social engineering & fraud lures"
          icon={AlertTriangle}
          variant="warning"
        />
        <MetricCard
          title="Malicious URLs"
          value={stats?.malicious_scans ?? 0}
          subtitle="Active phishing & malware links"
          icon={Flame}
          variant="danger"
        />
      </div>

      {/* Visual Threat Charts (Recharts) */}
      <ThreatChart distribution={distribution} />

      {/* Recent Scans Audit Trail */}
      <RecentScansTable scans={recentScans} />

      {/* System Infrastructure Telemetry Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Backend & Database Telemetry */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div className="flex items-center space-x-2.5">
              <Database className="w-5 h-5 text-cyan-400" />
              <h2 className="font-semibold text-white">Database & Core Backend</h2>
            </div>
            {health ? (
              <StatusBadge status={health.database.status} />
            ) : (
              <StatusBadge status="disconnected" label="OFFLINE" />
            )}
          </div>

          <div className="space-y-3 text-sm">
            <div className="flex items-center justify-between py-1 border-b border-slate-800/40">
              <span className="text-slate-400">Application</span>
              <span className="text-slate-200 font-medium">{health?.app_name || 'SMS Shield Backend'}</span>
            </div>
            <div className="flex items-center justify-between py-1 border-b border-slate-800/40">
              <span className="text-slate-400">Backend Version</span>
              <span className="text-slate-200 font-mono">{health?.version || '0.1.0'}</span>
            </div>
            <div className="flex items-center justify-between py-1 border-b border-slate-800/40">
              <span className="text-slate-400">Environment</span>
              <span className="text-slate-200 capitalize">{health?.environment || 'development'}</span>
            </div>
            <div className="flex items-center justify-between py-1 border-b border-slate-800/40">
              <span className="text-slate-400">Database Engine</span>
              <span className="text-slate-200 font-mono">{health?.database.dialect.toUpperCase() || 'POSTGRESQL / SQLITE'}</span>
            </div>
            <div className="flex items-center justify-between py-1">
              <span className="text-slate-400">Query Ping Latency</span>
              <span className="text-emerald-400 font-mono font-medium">
                {health?.database.latency_ms !== null && health?.database.latency_ms !== undefined
                  ? `${health.database.latency_ms} ms`
                  : 'N/A'}
              </span>
            </div>
          </div>
        </div>

        {/* Threat Intelligence Providers Status */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div className="flex items-center space-x-2.5">
              <Globe className="w-5 h-5 text-cyan-400" />
              <h2 className="font-semibold text-white">Threat Intelligence Adapters</h2>
            </div>
            <span className="text-xs text-cyan-400 font-mono">LIVE CONNECTIVITY</span>
          </div>

          <div className="space-y-3">
            {providers?.providers.map((p) => (
              <div
                key={p.name}
                className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 flex items-start justify-between space-x-3"
              >
                <div>
                  <p className="text-sm font-medium text-white capitalize">
                    {p.name.replace(/_/g, ' ')}
                  </p>
                  <p className="text-xs text-slate-400 mt-0.5">{p.message}</p>
                </div>
                <StatusBadge status={p.status} />
              </div>
            )) || (
              <div className="text-center py-6 text-slate-500 text-sm">
                Awaiting backend connection to inspect threat intelligence adapters.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Engineering Architecture & Privacy Guarantee */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
        <div className="flex items-center space-x-2.5 pb-4 border-b border-slate-800">
          <Terminal className="w-5 h-5 text-cyan-400" />
          <h2 className="font-semibold text-white">Security & Privacy Assurance Ledger</h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
          <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800">
            <div className="flex items-center space-x-2 text-cyan-400 mb-2">
              <ShieldCheck className="w-4 h-4" />
              <h3 className="font-medium text-sm text-white">Zero Raw SMS Retention</h3>
            </div>
            <p className="text-xs text-slate-400">
              Message bodies and OTP codes are strictly parsed in memory and never stored in the database, log files, or audit tables.
            </p>
          </div>

          <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800">
            <div className="flex items-center space-x-2 text-cyan-400 mb-2">
              <Clock className="w-4 h-4" />
              <h3 className="font-medium text-sm text-white">Dual ML Pipeline</h3>
            </div>
            <p className="text-xs text-slate-400">
              Real-time SMS NLP classifier combined with URL lexical feature model and multi-feed threat intelligence aggregator.
            </p>
          </div>

          <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800">
            <div className="flex items-center space-x-2 text-cyan-400 mb-2">
              <Globe className="w-4 h-4" />
              <h3 className="font-medium text-sm text-white">SSRF & Anti-Abuse Isolation</h3>
            </div>
            <p className="text-xs text-slate-400">
              Zero automated network crawling of suspect targets. Protected against private IP space SSRF and DNS rebinding attacks.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

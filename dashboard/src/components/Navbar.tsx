import React from 'react';
import { Shield, Activity, RefreshCw } from 'lucide-react';
import { StatusBadge } from './StatusBadge';

interface NavbarProps {
  backendStatus: 'healthy' | 'degraded' | 'unhealthy' | 'checking';
  onRefresh: () => void;
  isRefreshing: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({ backendStatus, onRefresh, isRefreshing }) => {
  return (
    <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="bg-cyan-500/10 border border-cyan-500/30 p-2 rounded-lg text-cyan-400">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-bold text-lg text-white tracking-tight">SMS SHIELD</span>
              <span className="text-xs uppercase px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800 font-mono">
                v1.0.0
              </span>
            </div>
            <p className="text-xs text-slate-400 hidden sm:block">AI Threat Intelligence & Malicious URL Shield</p>
          </div>
        </div>

        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2 bg-slate-900 border border-slate-800 px-3 py-1.5 rounded-lg text-xs">
            <Activity className="w-3.5 h-3.5 text-slate-400" />
            <span className="text-slate-400">Backend API:</span>
            {backendStatus === 'checking' ? (
              <span className="text-slate-400 animate-pulse font-mono">CHECKING...</span>
            ) : (
              <StatusBadge status={backendStatus} />
            )}
          </div>

          <button
            onClick={onRefresh}
            disabled={isRefreshing}
            className="p-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 transition disabled:opacity-50"
            title="Refresh System Telemetry"
          >
            <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`} />
          </button>
        </div>
      </div>
    </header>
  );
};

import React from 'react';
import { Shield, ExternalLink, AlertOctagon, CheckCircle, HelpCircle, Lock } from 'lucide-react';
import { RecentScanItem } from '../services/api';

interface RecentScansTableProps {
  scans: RecentScanItem[];
}

export const RecentScansTable: React.FC<RecentScansTableProps> = ({ scans }) => {
  const getBadge = (classification: string) => {
    switch (classification.toUpperCase()) {
      case 'SAFE':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-emerald-950/80 text-emerald-400 border border-emerald-800">
            <CheckCircle className="w-3 h-3 mr-1" /> SAFE
          </span>
        );
      case 'SUSPICIOUS':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-amber-950/80 text-amber-400 border border-amber-800">
            <AlertOctagon className="w-3 h-3 mr-1" /> SUSPICIOUS
          </span>
        );
      case 'MALICIOUS':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-rose-950/80 text-rose-400 border border-rose-800">
            <Shield className="w-3 h-3 mr-1" /> MALICIOUS
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-slate-800 text-slate-300 border border-slate-700">
            <HelpCircle className="w-3 h-3 mr-1" /> UNKNOWN
          </span>
        );
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden space-y-3 p-5">
      <div className="flex items-center justify-between pb-3 border-b border-slate-800">
        <div className="flex items-center space-x-2">
          <Shield className="w-5 h-5 text-cyan-400" />
          <h3 className="text-white font-semibold text-sm">Audit Scan History</h3>
        </div>
        <div className="flex items-center space-x-1.5 text-xs text-slate-400 bg-slate-950 px-2.5 py-1 rounded-md border border-slate-800">
          <Lock className="w-3.5 h-3.5 text-cyan-400" />
          <span>Zero-Raw-SMS Retention Enforced</span>
        </div>
      </div>

      {scans.length === 0 ? (
        <div className="py-8 text-center text-slate-500 text-sm">
          No scan records found. Run manual or notification scans to view live audit activity.
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase tracking-wider font-semibold">
                <th className="py-2.5 px-3">Timestamp / ID</th>
                <th className="py-2.5 px-3">Channel</th>
                <th className="py-2.5 px-3">Verdict</th>
                <th className="py-2.5 px-3">Risk Score</th>
                <th className="py-2.5 px-3">Triggered Indicators</th>
                <th className="py-2.5 px-3">Recommended Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {scans.map((scan) => {
                const dateStr = new Date(scan.timestamp).toLocaleString();
                const score = scan.risk_score !== null ? Math.round(scan.risk_score) : null;

                return (
                  <tr key={scan.scan_id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3 px-3">
                      <div className="text-slate-200 font-medium">{dateStr}</div>
                      <div className="text-[10px] text-slate-500 font-mono">
                        {scan.scan_id.slice(0, 8)}...
                      </div>
                    </td>
                    <td className="py-3 px-3">
                      <span className="capitalize text-slate-300">
                        {scan.source_category.replace('_', ' ')}
                      </span>
                      {scan.url_count > 0 && (
                        <div className="text-[10px] text-cyan-400 flex items-center mt-0.5">
                          <ExternalLink className="w-2.5 h-2.5 mr-0.5" />
                          {scan.url_count} URL(s)
                        </div>
                      )}
                    </td>
                    <td className="py-3 px-3">{getBadge(scan.classification)}</td>
                    <td className="py-3 px-3">
                      {score !== null ? (
                        <div className="flex items-center space-x-2">
                          <div className="w-16 bg-slate-800 rounded-full h-1.5 overflow-hidden">
                            <div
                              className={`h-full rounded-full ${
                                score >= 70
                                  ? 'bg-rose-500'
                                  : score >= 40
                                  ? 'bg-amber-500'
                                  : 'bg-emerald-500'
                              }`}
                              style={{ width: `${Math.min(score, 100)}%` }}
                            />
                          </div>
                          <span className="font-mono text-slate-300">{score}/100</span>
                        </div>
                      ) : (
                        <span className="text-slate-500 italic">N/A</span>
                      )}
                    </td>
                    <td className="py-3 px-3 max-w-xs">
                      {scan.detection_reasons.length > 0 ? (
                        <div className="flex flex-wrap gap-1">
                          {scan.detection_reasons.map((r, i) => (
                            <span
                              key={i}
                              className="bg-slate-800/80 text-slate-300 px-1.5 py-0.5 rounded text-[10px] border border-slate-700/60"
                            >
                              {r}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span className="text-slate-500">None detected</span>
                      )}
                    </td>
                    <td className="py-3 px-3 text-slate-400 max-w-xs truncate" title={scan.recommendation || ''}>
                      {scan.recommendation || 'Standard caution'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};


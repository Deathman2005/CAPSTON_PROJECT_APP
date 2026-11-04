import React from 'react';
import { LucideIcon } from 'lucide-react';

interface MetricCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  variant?: 'default' | 'safe' | 'warning' | 'danger';
}

export const MetricCard: React.FC<MetricCardProps> = ({
  title,
  value,
  subtitle,
  icon: Icon,
  variant = 'default',
}) => {
  const getIconColor = () => {
    switch (variant) {
      case 'safe':
        return 'text-emerald-400 bg-emerald-950/60 border-emerald-800/50';
      case 'warning':
        return 'text-amber-400 bg-amber-950/60 border-amber-800/50';
      case 'danger':
        return 'text-rose-400 bg-rose-950/60 border-rose-800/50';
      default:
        return 'text-cyan-400 bg-cyan-950/60 border-cyan-800/50';
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg shadow-black/20 hover:border-slate-700 transition">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-slate-400">{title}</p>
          <p className="text-2xl font-bold text-white mt-1">{value}</p>
          {subtitle && <p className="text-xs text-slate-500 mt-1">{subtitle}</p>}
        </div>
        <div className={`p-3 rounded-lg border ${getIconColor()}`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
    </div>
  );
};

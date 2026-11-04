import React from 'react';

interface StatusBadgeProps {
  status:
    | 'healthy'
    | 'degraded'
    | 'unhealthy'
    | 'available'
    | 'unconfigured'
    | 'unavailable'
    | 'connected'
    | 'disconnected';
  label?: string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, label }) => {
  const displayLabel = label || status.toUpperCase();

  const getColors = () => {
    switch (status) {
      case 'healthy':
      case 'connected':
      case 'available':
        return 'bg-emerald-950 text-emerald-400 border-emerald-800';
      case 'degraded':
      case 'unconfigured':
        return 'bg-amber-950 text-amber-400 border-amber-800';
      case 'unhealthy':
      case 'disconnected':
      default:
        return 'bg-rose-950 text-rose-400 border-rose-800';
    }
  };

  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold border ${getColors()}`}
    >
      <span
        className={`w-1.5 h-1.5 mr-1.5 rounded-full ${
          status === 'healthy' || status === 'connected' || status === 'available'
            ? 'bg-emerald-400'
            : status === 'degraded' || status === 'unconfigured'
            ? 'bg-amber-400'
            : 'bg-rose-400'
        }`}
      />
      {displayLabel}
    </span>
  );
};

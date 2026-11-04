import { useState, useEffect, useCallback } from 'react';
import { Navbar } from './components/Navbar';
import { Overview } from './pages/Overview';
import { fetchHealth, fetchProvidersHealth, HealthResponse, ProvidersHealthResponse } from './services/api';

export function App() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [providers, setProviders] = useState<ProvidersHealthResponse | null>(null);
  const [backendStatus, setBackendStatus] = useState<'healthy' | 'degraded' | 'unhealthy' | 'checking'>('checking');
  const [error, setError] = useState<string | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const loadTelemetry = useCallback(async () => {
    setIsRefreshing(true);
    try {
      const [healthData, providersData] = await Promise.all([
        fetchHealth(),
        fetchProvidersHealth().catch(() => null),
      ]);
      setHealth(healthData);
      setProviders(providersData);
      setBackendStatus(healthData.status);
      setError(null);
    } catch (err) {
      setBackendStatus('unhealthy');
      setError(err instanceof Error ? err.message : 'Unable to connect to backend server');
    } finally {
      setIsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadTelemetry();
    const interval = setInterval(loadTelemetry, 15000);
    return () => clearInterval(interval);
  }, [loadTelemetry]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      <Navbar
        backendStatus={backendStatus}
        onRefresh={loadTelemetry}
        isRefreshing={isRefreshing}
      />
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <Overview health={health} providers={providers} error={error} />
      </main>
      <footer className="border-t border-slate-900 bg-slate-950/40 py-6 text-center text-xs text-slate-500">
        <p>SMS Shield — AI-Powered Real-Time SMS Scam and Malicious URL Detection &copy; {new Date().getFullYear()}</p>
        <p className="mt-1">Zero-raw-SMS retention &bull; Privacy-first architecture &bull; Phase 0 Foundation</p>
      </footer>
    </div>
  );
}

export default App;

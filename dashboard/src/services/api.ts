/**
 * API service for fetching backend system telemetry and health status.
 */

export interface DatabaseHealth {
  status: 'connected' | 'disconnected' | 'unhealthy';
  dialect: string;
  latency_ms: number | null;
  error?: string | null;
}

export interface HealthResponse {
  status: 'healthy' | 'degraded' | 'unhealthy';
  app_name: string;
  version: string;
  environment: string;
  timestamp: string;
  database: DatabaseHealth;
}

export interface ProviderHealthItem {
  name: string;
  status: 'available' | 'unconfigured' | 'unavailable';
  latency_ms: number | null;
  message: string;
}

export interface ProvidersHealthResponse {
  providers: ProviderHealthItem[];
  timestamp: string;
}

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

export async function fetchHealth(): Promise<HealthResponse> {
  const response = await fetch(`${API_BASE_URL}/health`);
  if (!response.ok) {
    throw new Error(`Health check returned HTTP ${response.status}`);
  }
  return response.json();
}

export async function fetchProvidersHealth(): Promise<ProvidersHealthResponse> {
  const response = await fetch(`${API_BASE_URL}/api/v1/health/providers`);
  if (!response.ok) {
    throw new Error(`Threat providers check returned HTTP ${response.status}`);
  }
  return response.json();
}

/**
 * API service for fetching backend system telemetry, health status, and scan analytics.
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

export interface DashboardStats {
  total_scans: number;
  safe_scans: number;
  suspicious_scans: number;
  malicious_scans: number;
  unknown_scans: number;
  total_urls_scanned: number;
  avg_risk_score: number;
  timestamp: string;
}

export interface RecentScanItem {
  scan_id: string;
  timestamp: string;
  source_category: string;
  source_package: string | null;
  classification: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';
  risk_score: number | null;
  confidence: number;
  url_count: number;
  detection_reasons: string[];
  recommendation: string | null;
}

export interface RecentScansResponse {
  total_returned: number;
  items: RecentScanItem[];
}

export interface ThreatDistributionCategory {
  name: string;
  count: number;
  percentage: number;
}

export interface ThreatDistributionResponse {
  classifications: ThreatDistributionCategory[];
  sources: ThreatDistributionCategory[];
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

export async function fetchDashboardStats(): Promise<DashboardStats> {
  const response = await fetch(`${API_BASE_URL}/api/v1/dashboard/stats`);
  if (!response.ok) {
    throw new Error(`Dashboard stats returned HTTP ${response.status}`);
  }
  return response.json();
}

export async function fetchRecentScans(limit: number = 10): Promise<RecentScansResponse> {
  const response = await fetch(`${API_BASE_URL}/api/v1/dashboard/recent-scans?limit=${limit}`);
  if (!response.ok) {
    throw new Error(`Recent scans returned HTTP ${response.status}`);
  }
  return response.json();
}

export async function fetchThreatDistribution(): Promise<ThreatDistributionResponse> {
  const response = await fetch(`${API_BASE_URL}/api/v1/dashboard/threat-distribution`);
  if (!response.ok) {
    throw new Error(`Threat distribution returned HTTP ${response.status}`);
  }
  return response.json();
}

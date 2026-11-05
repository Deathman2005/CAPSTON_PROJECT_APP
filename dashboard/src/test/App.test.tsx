import { render, screen, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import App from '../App';

describe('SMS Shield Dashboard App Component', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('renders application brand title, stats, and audit history', async () => {
    // Mock global fetch to return responses for all 5 dashboard endpoints
    vi.spyOn(globalThis, 'fetch').mockImplementation((url: RequestInfo | URL | string) => {
      const urlStr = typeof url === 'string' ? url : url.toString();

      if (urlStr.includes('/health/providers')) {
        return Promise.resolve({
          ok: true,
          json: async () => ({
            providers: [
              { name: 'urlhaus', status: 'available', latency_ms: 10, message: 'Active' },
              { name: 'google_safe_browsing', status: 'available', latency_ms: 22, message: 'Active' },
            ],
            timestamp: new Date().toISOString(),
          }),
        } as Response);
      }

      if (urlStr.includes('/dashboard/stats')) {
        return Promise.resolve({
          ok: true,
          json: async () => ({
            total_scans: 42,
            safe_scans: 30,
            suspicious_scans: 8,
            malicious_scans: 4,
            unknown_scans: 0,
            total_urls_scanned: 15,
            avg_risk_score: 24.5,
            timestamp: new Date().toISOString(),
          }),
        } as Response);
      }

      if (urlStr.includes('/dashboard/recent-scans')) {
        return Promise.resolve({
          ok: true,
          json: async () => ({
            total_returned: 1,
            items: [
              {
                scan_id: '12345678-abcd-ef01-2345-6789abcdef01',
                timestamp: new Date().toISOString(),
                source_category: 'notification_auto',
                source_package: 'com.google.android.apps.messaging',
                classification: 'MALICIOUS',
                risk_score: 95.0,
                confidence: 0.95,
                url_count: 1,
                detection_reasons: ['Phishing link', 'Bank impersonation'],
                recommendation: 'Do not click links or provide credentials.',
              },
            ],
          }),
        } as Response);
      }

      if (urlStr.includes('/dashboard/threat-distribution')) {
        return Promise.resolve({
          ok: true,
          json: async () => ({
            classifications: [
              { name: 'SAFE', count: 30, percentage: 71.4 },
              { name: 'SUSPICIOUS', count: 8, percentage: 19.0 },
              { name: 'MALICIOUS', count: 4, percentage: 9.6 },
              { name: 'UNKNOWN', count: 0, percentage: 0.0 },
            ],
            sources: [
              { name: 'notification_auto', count: 35, percentage: 83.3 },
              { name: 'manual_paste', count: 7, percentage: 16.7 },
            ],
            timestamp: new Date().toISOString(),
          }),
        } as Response);
      }

      // Default health response
      return Promise.resolve({
        ok: true,
        json: async () => ({
          status: 'healthy',
          app_name: 'SMS Shield AI Backend',
          version: '1.0.0',
          environment: 'production',
          timestamp: new Date().toISOString(),
          database: {
            status: 'connected',
            dialect: 'postgresql',
            latency_ms: 1.5,
          },
        }),
      } as Response);
    });

    render(<App />);

    expect(screen.getByText('SMS SHIELD')).toBeInTheDocument();
    expect(screen.getByText('v1.0.0')).toBeInTheDocument();
    expect(screen.getByText('Total Scans')).toBeInTheDocument();
    expect(screen.getByText('Safe Messages')).toBeInTheDocument();
    expect(screen.getByText('Suspicious Messages')).toBeInTheDocument();
    expect(screen.getByText('Malicious URLs')).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText('Audit Scan History')).toBeInTheDocument();
      expect(screen.getByText('Zero-Raw-SMS Retention Enforced')).toBeInTheDocument();
      expect(screen.getByText('MALICIOUS')).toBeInTheDocument();
    });
  });
});

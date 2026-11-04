import { render, screen, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import App from '../App';

describe('SMS Shield Dashboard App Component', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('renders application brand title and phase badge', async () => {
    // Mock global fetch to return healthy backend response
    vi.spyOn(globalThis, 'fetch').mockImplementation((url: RequestInfo | URL | string) => {
      if (typeof url === 'string' && url.includes('/health/providers')) {
        return Promise.resolve({
          ok: true,
          json: async () => ({
            providers: [
              { name: 'urlhaus', status: 'available', latency_ms: 10, message: 'Active' },
            ],
            timestamp: new Date().toISOString(),
          }),
        } as Response);
      }
      return Promise.resolve({
        ok: true,
        json: async () => ({
          status: 'healthy',
          app_name: 'SMS Shield AI Backend',
          version: '0.1.0',
          environment: 'development',
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
    expect(screen.getByText('Phase 0')).toBeInTheDocument();
    expect(screen.getByText('Total Scans')).toBeInTheDocument();
    expect(screen.getByText('Safe Messages')).toBeInTheDocument();
    expect(screen.getByText('Suspicious Messages')).toBeInTheDocument();
    expect(screen.getByText('Malicious URLs')).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText('Database & Core Backend')).toBeInTheDocument();
    });
  });
});

# SMS Shield — REST API Specification

Version: `1.0.0`  
Base URL: `/api/v1`

All responses are formatted in JSON and include UTC ISO-8601 timestamps.

---

## 1. System & Health Endpoints

### 1.1 Root Health Check
`GET /health`

Verifies that the API service is alive and checks live database connectivity.

**Response `200 OK`**:
```json
{
  "status": "healthy",
  "app_name": "SMS Shield AI Backend",
  "version": "0.1.0",
  "environment": "development",
  "timestamp": "2026-11-04T15:20:00Z",
  "database": {
    "status": "connected",
    "dialect": "postgresql",
    "latency_ms": 1.25
  }
}
```

### 1.2 Threat Intelligence Providers Health
`GET /api/v1/health/providers`

Reports operational status and quota availability of threat intelligence adapters.

**Response `200 OK`**:
```json
{
  "providers": [
    {
      "name": "google_safe_browsing",
      "status": "available",
      "latency_ms": 182,
      "message": "API key configured and responding"
    },
    {
      "name": "urlhaus",
      "status": "available",
      "latency_ms": 95,
      "message": "Public feed operational"
    },
    {
      "name": "virustotal",
      "status": "unconfigured",
      "latency_ms": null,
      "message": "Optional provider API key not supplied"
    }
  ]
}
```

---

## 2. Scanning Endpoints (Phase 3 - 6)

### 2.1 Combined SMS & URL Scan
`POST /api/v1/scan/combined`

**Request Body**:
```json
{
  "message_text": "Urgent: Your SBI account is blocked due to incomplete KYC. Update immediately at http://sbi-kyc-update.xyz",
  "extracted_urls": ["http://sbi-kyc-update.xyz"],
  "source_package": "com.google.android.apps.messaging",
  "scan_mode": "notification_auto"
}
```

**Response `200 OK`**:
```json
{
  "scan_id": "c56a4180-65aa-42ec-a945-5fd21dec0538",
  "timestamp": "2026-11-04T15:21:00Z",
  "overall_classification": "MALICIOUS",
  "risk_score": 96.5,
  "confidence": 0.94,
  "recommendation": "Do not click the link or provide credentials. SBI never requests KYC updates via unverified links.",
  "detection_reasons": [
    "Bank impersonation with urgent account suspension threat",
    "URL hosted on suspicious newly registered TLD (.xyz)",
    "Confirmed phishing domain by threat intelligence provider (URLhaus)"
  ],
  "sms_analysis": {
    "classification": "scam",
    "confidence": 0.92,
    "top_triggers": ["urgent", "account is blocked", "kyc", "update immediately"],
    "model_version": "sms_v1_tfidf_logistic_20261104"
  },
  "url_analyses": [
    {
      "url": "http://sbi-kyc-update.xyz",
      "domain": "sbi-kyc-update.xyz",
      "classification": "malicious",
      "risk_score": 98.0,
      "reputation_status": "blacklisted",
      "provider_results": {
        "urlhaus": "malicious_phishing",
        "google_safe_browsing": "malicious"
      },
      "feature_score": 0.91
    }
  ]
}
```

---

## 3. Dashboard Endpoints (Phase 7)

- `GET /api/v1/dashboard/summary`: Aggregate counts of scans, safe, suspicious, malicious, and unknown incidents.
- `GET /api/v1/dashboard/trends`: Time-series incident distribution and classification history.
- `GET /api/v1/scan/history`: Paginated scan metadata history (no raw SMS content).
- `DELETE /api/v1/scan/history`: User-initiated purge of all persisted telemetry.

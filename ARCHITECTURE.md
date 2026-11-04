# SMS Shield — System Architecture & Design Specification

## 1. Architectural Overview

SMS Shield is engineered using a modular, defense-in-depth architecture. It decouples client-side interception, data transport, text classification, URL reputation, and analytical reporting.

```text
+-------------------------------------------------------------+
|                 Android Client Layer                        |
|                                                             |
|  [SMS Notification]              [Manual Share / Paste]     |
|          |                                   |              |
|          v                                   |              |
|  [SupportedSmsApps Registry]                 |              |
|  (Package verification)                      |              |
|          |                                   |              |
|          v                                   |              |
|  [Content Extraction & Sanitization]         |              |
|  (OTP exclusion, privacy filter)             |              |
|          |                                   |              |
|          v                                   |              |
|  [URL Extraction Engine] <-------------------+              |
|  (RFC 3986 normalization, unshortening prep)                |
|          |                                                  |
|          v                                                  |
|  [Local Deduplication Cache]                                |
|          |                                                  |
|          v                                                  |
|  [Retrofit / OkHttp Client (TLS 1.3)]                       |
+-------------------------------------------------------------+
                           |
                     HTTPS JSON API
                           |
+-------------------------------------------------------------+
|                 FastAPI Backend Layer                       |
|                                                             |
|  [API Gateway & Rate Limiter]                               |
|  - Ingestion Validation (Pydantic v2)                       |
|  - Sensitive Data Redaction Filter                          |
|          |                                                  |
|          +-------------------+                              |
|          |                   |                              |
|          v                   v                              |
|  [Module A: NLP Engine]  [Module B: URL Engine]             |
|  - Preprocessing         - Feature Extraction (Lexical)     |
|  - TF-IDF + Classifier   - Threat Intelligence Adapters:    |
|  - Token Attribution       * Google Safe Browsing           |
|                            * URLhaus                        |
|                            * VirusTotal                     |
|                            - URL Classifier (XGBoost)       |
|          |                   |                              |
|          +---------+---------+                              |
|                    |                                        |
|                    v                                        |
|         [Combined Risk Engine]                              |
|         - Weighted calibrated scoring (0 - 100)             |
|         - Explanatory reasons generator                     |
|         - Status: SAFE | SUSPICIOUS | MALICIOUS | UNKNOWN   |
|                    |                                        |
|                    +------------------+                     |
|                    |                  |                     |
|                    v                  v                     |
|         [Database Persistence]   [Immediate Response]       |
|         - Minimal metadata       - Risk level & advice      |
|         - No raw SMS text        - Android notification     |
|         (PostgreSQL 16)                                     |
+-------------------------------------------------------------+
                           |
+-------------------------------------------------------------+
|                 React Dashboard Layer                       |
|  - Real-time incident telemetry                             |
|  - Model drift, false-positive metrics, PR-AUC              |
|  - Threat intelligence provider latency & uptime            |
+-------------------------------------------------------------+
```

---

## 2. Component Boundaries & Responsibilities

### 2.1 Android Client
- **NotificationListenerService**: Operates on a dedicated background thread. Filters incoming system events against `SupportedSmsApps` whitelist (e.g., Google Messages, Samsung Messages).
- **Zero Inbox Permission**: Does NOT declare or request `READ_SMS` or `RECEIVE_SMS`.
- **Local Redaction**: Redacts standard 4-8 digit numeric OTP sequences before transmitting payload to backend.
- **Manual Scanning**: Supports Android Sharesheet (`ACTION_SEND`) and clipboard paste.

### 2.2 FastAPI Backend
- **Stateless Ingestion**: Evaluates scan requests concurrently.
- **Circuit Breakers**: External threat intelligence queries are protected with timeouts (maximum 3.0 seconds) and circuit breakers. Failures return `CHECK_UNAVAILABLE` rather than defaulting to `SAFE`.
- **Combined Risk Synthesis**: Ensures that a confirmed malicious URL cannot be masked by benign SMS text.

### 2.3 Machine Learning Pipeline
- **Dual Pipeline Separation**: SMS NLP model and URL Tabular model are isolated. They are trained, versioned, and evaluated independently.
- **Reproducibility**: Model weights and transformers are persisted as versioned artifacts with complete pipeline configuration.

---

## 3. Threat Model & Security Boundaries

1. **Untrusted URL Handling**: URLs extracted from messages are never fetched, rendered, or opened inside the client application. Backend URL inspection runs in an isolated network sandbox without binary execution or JavaScript evaluation.
2. **SSRF Mitigation**: Any server-side HTTP probing strictly blocks private IP address ranges (RFC 1918, RFC 3927), localhost, loopback interfaces, and cloud metadata endpoints (`169.254.169.254`).
3. **Audit Trail**: Every scan logs model version, rule trigger, and provider response metadata with zero sensitive user data.

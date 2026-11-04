# SMS Shield — Database Architecture & Schema Specification

Database Engine: PostgreSQL 16  
ORM: SQLAlchemy 2.0  
Migrations: Alembic

---

## 1. Privacy-Preserving Storage Policy

- **No Raw SMS Storage**: By default, full message text is never persisted to disk. Only an HMAC-SHA256 signature (for duplicate suppression) and high-level extracted entity tokens are kept.
- **Sensitive Parameter Redaction**: Query string parameters in URLs (e.g. `?token=`, `?session=`, `?auth=`) are redacted before database writes.
- **User Purge Capability**: Full GDPR/CCPA-compliant user history deletion via single API invocation.

---

## 2. Table Specifications

### 2.1 `scan_records`
Primary audit log for incoming scan inquiries.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | UUID | PRIMARY KEY | Unique scan event identifier |
| `timestamp` | TIMESTAMPTZ | NOT NULL, DEFAULT NOW() | Ingestion timestamp |
| `source_category` | VARCHAR(64) | NOT NULL | `notification_auto`, `manual_paste`, `manual_share` |
| `source_package` | VARCHAR(128) | NULL | Android package name of detected SMS app |
| `classification` | VARCHAR(32) | NOT NULL | `SAFE`, `SUSPICIOUS`, `MALICIOUS`, `UNKNOWN` |
| `risk_score` | FLOAT | NULL | Combined risk score (0.0 - 100.0) |
| `confidence` | FLOAT | NOT NULL | Model & threat confidence |
| `url_count` | INTEGER | NOT NULL, DEFAULT 0 | Count of URLs identified |
| `sms_model_version` | VARCHAR(64) | NOT NULL | Active SMS model version |
| `message_hash` | VARCHAR(64) | NOT NULL | SHA-256 hash for deduplication |

**Indexes**:
- `CREATE INDEX ix_scan_records_timestamp ON scan_records (timestamp DESC);`
- `CREATE INDEX ix_scan_records_classification ON scan_records (classification);`
- `CREATE INDEX ix_scan_records_message_hash ON scan_records (message_hash);`

### 2.2 `url_scan_results`
Stores detailed inspection records for URLs associated with scans.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | UUID | PRIMARY KEY | Unique record identifier |
| `scan_id` | UUID | FOREIGN KEY -> `scan_records.id` ON DELETE CASCADE | Associated scan |
| `normalized_url` | TEXT | NOT NULL | URL with tracking params redacted |
| `domain` | VARCHAR(255) | NOT NULL | Hostname or IP address |
| `is_ip_address` | BOOLEAN | NOT NULL | Whether hostname is raw IP |
| `is_shortened` | BOOLEAN | NOT NULL | Whether domain is known shortener |
| `classification` | VARCHAR(32) | NOT NULL | `benign`, `phishing`, `malware`, `suspicious`, `unknown` |
| `feature_risk_score`| FLOAT | NOT NULL | Score from ML classifier |
| `reputation_status` | VARCHAR(32) | NOT NULL | Overall threat reputation result |

### 2.3 `threat_provider_results`
Audit log of individual threat intelligence provider responses.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | UUID | PRIMARY KEY | Unique record identifier |
| `url_scan_id` | UUID | FOREIGN KEY -> `url_scan_results.id` ON DELETE CASCADE | Associated URL record |
| `provider_name` | VARCHAR(64) | NOT NULL | `google_safe_browsing`, `urlhaus`, `virustotal` |
| `status` | VARCHAR(32) | NOT NULL | `clean`, `malicious`, `suspicious`, `unavailable`, `unknown` |
| `latency_ms` | INTEGER | NULL | Upstream response latency in milliseconds |
| `raw_response_tag` | VARCHAR(128) | NULL | Upstream threat categorization tag |
| `checked_at` | TIMESTAMPTZ | NOT NULL | Timestamp of upstream check |

### 2.4 `model_versions`
Audit ledger of active machine learning models and performance baselines.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | VARCHAR(64) | PRIMARY KEY | Model artifact version identifier |
| `model_type` | VARCHAR(32) | NOT NULL | `sms_classifier` or `url_classifier` |
| `algorithm` | VARCHAR(64) | NOT NULL | e.g. `TF-IDF + LogisticRegression`, `XGBoost` |
| `precision` | FLOAT | NOT NULL | Validation precision |
| `recall` | FLOAT | NOT NULL | Validation recall |
| `f1_score` | FLOAT | NOT NULL | Validation F1-score |
| `pr_auc` | FLOAT | NOT NULL | Precision-Recall AUC |
| `deployed_at` | TIMESTAMPTZ | NOT NULL | Timestamp when loaded into runtime |
| `is_active` | BOOLEAN | NOT NULL | Whether model is active for inference |

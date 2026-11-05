# SMS Shield Changelog

All notable changes to the SMS Shield application will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.7.0] - Phase 6: Full Integration and Warning Experience - 2026-11-05

### Added
- **Domain Alert Decision Engine (`android/core-domain/src/main/kotlin/com/smsshield/domain/alert/AlertDecisionEngine.kt`)**:
  - Implemented pure domain `AlertDecisionEngine` evaluating whether an incoming scan warrants an intrusive user notification.
  - Generates `AlertNotificationPayload` with calibrated priority levels (`HIGH` for `MALICIOUS`, `DEFAULT` for `SUSPICIOUS`, `NONE` for `SAFE` and `UNKNOWN`).
  - Strict privacy enforcement: Zero message text, OTP codes, or contact information are ever embedded into notification titles, bodies, or banners.
- **Backend API Transfer Objects (`android/core-domain/src/main/kotlin/com/smsshield/domain/model/ApiPayloads.kt`)**:
  - Typed Kotlin data contracts (`MessageScanApiRequest`, `MessageScanApiResponse`, `UrlScanApiRequest`, `UrlScanApiResponse`) exactly matching FastAPI backend schemas.
- **Android Remote API Client (`android/app/src/main/java/com/smsshield/app/data/remote/`)**:
  - `SmsShieldApi.kt`: Retrofit service interface defining `POST /api/v1/scan/message` and `POST /api/v1/scan/url`.
  - `ApiClient.kt`: Resilient Retrofit client singleton supporting dynamic backend base URL configuration from user preferences.
- **Scan Repository with Defensive Offline Fallback (`android/app/src/main/java/com/smsshield/app/data/repository/ScanRepository.kt`)**:
  - Orchestrates online backend scanning with fallback to defensive offline heuristic evaluation during network disconnection.
  - Persists minimal audit metadata directly to local Room database (`ScanRecordEntity`) with zero raw SMS content stored.
- **Security Alert Notification Manager (`android/app/src/main/java/com/smsshield/app/service/AlertNotificationManager.kt`)**:
  - Configures dedicated `SMS_SHIELD_SECURITY_ALERTS` notification channel with `IMPORTANCE_HIGH`, heads-up alerting, vibration, and public lockscreen visibility.
  - Dispatches high-priority system alerts with deep-link navigation to `MainActivity` passing scan classification and risk score.
- **Real-Time Notification Listener Integration (`android/app/src/main/java/com/smsshield/app/service/SMSNotificationListener.kt`)**:
  - Connected `SMSNotificationListener` to `ScanRepository` and `AlertNotificationManager`.
  - Automatically triggers background scan upon incoming SMS from supported packages, deduplicates repetitive notifications, and posts high-priority warning alerts when malicious/suspicious content is detected.
- **Interactive Scanner UI Updates (`ScannerViewModel.kt` & `ScannerScreen.kt`)**:
  - Updated `ScannerViewModel` to integrate `ScanRepository` for both message text and individual URL inspection.
  - Enhanced `ScannerScreen` (Screen 4 & Screen 5) with distinct badges for `SAFE`, `SUSPICIOUS`, `MALICIOUS`, and `UNKNOWN` (never defaulting unknown to safe), risk score gauge (0-100), triggered indicators, actionable recommendations, link inspection shortcuts, and audit metadata.
- **Unit Test Suite Expansion (39 Tests Passing)**:
  - Added `AlertDecisionEngineTest.kt` in `:core-domain` (5 tests covering `MALICIOUS` high priority, `SUSPICIOUS` default priority, `SAFE`/`UNKNOWN` suppression, and strict zero-leakage privacy assertions).
  - 100% pass rate across all 39 `:core-domain` unit tests and all 88 backend pytest tests.

---

## [0.6.0] - Phase 5: URL Machine Learning and Combined Risk Engine - 2026-11-05

### Added
- **URL Lexical Feature Extractor (`backend/app/ml/url_features.py`)**:
  - Implemented `UrlFeatureExtractor` (Scikit-Learn `BaseEstimator, TransformerMixin`) extracting 18 lexical and structural features purely from URL text with zero server probing.
  - Engineered indicators: URL length, hostname length, path length, dot counts, hyphens, underscores, slashes, digit count, digit ratio, subdomains count, query parameter count, presence of `@` redirection symbol, raw IP address detection, HTTPS scheme check, URL shortener detection, Punycode IDN homograph detection, suspicious TLD detection, sensitive security keyword occurrences, and hostname Shannon entropy (DGA detection).
- **Curated URL Benchmark Corpus (`backend/app/ml/data/url_corpus.csv`)**:
  - Curated 78 verified URL entries covering phishing targets, bank impersonation, raw IP drops, shortened phishing URLs, Punycode attacks, and high-reputation global and Indian banking, government, commerce, and open-source portals.
- **URL Machine Learning Model Trainer & Baseline Comparison (`backend/app/ml/url_trainer.py`)**:
  - Implemented `UrlModelTrainer` comparing 3 candidate classifiers:
    1. `LogisticRegression` with L2 penalty and standard scaling.
    2. `RandomForestClassifier` (100 ensemble trees with max depth 8).
    3. `HistGradientBoostingClassifier` (100 iterations with early stopping).
  - Evaluates un-fabricated hold-out test metrics: Precision, Recall, F1-Score, Accuracy, ROC-AUC, PR-AUC, and Confusion Matrix.
  - Selected model: `logistic_regression` achieving Test PR-AUC of **1.0** and Test F1 of **1.0**.
  - Serializes model to `backend/app/ml/artifacts/url_classifier.joblib` and metrics audit log to `backend/app/ml/artifacts/url_model_metrics.json`.
- **Production URL Inference Service (`backend/app/ml/url_service.py`)**:
  - Thread-safe singleton `UrlClassifierService` providing fast lexical risk scoring (0-100), confidence calibration, and human-readable threat indicators.
  - Built-in heuristic fallback (`_heuristic_fallback`) ensuring uninterrupted operation if model artifacts are unavailable.
- **Combined Multi-Signal Risk Engine (`backend/app/services/risk_engine/engine.py`)**:
  - Unifies decoupled security signals: SMS text NLP scam probability, upstream threat intelligence verdicts (URLhaus, Google Safe Browsing, VirusTotal), URL lexical ML risk scores, and domain deception heuristics into a calibrated verdict.
  - Strict Consensus Policies:
    - Confirmed Malicious Override: Positive threat intelligence feeds immediately produce `MALICIOUS` (score >= 95.0).
    - Strong Dual-Signal: High SMS scam likelihood + embedded links produces `MALICIOUS` (score >= 90.0) regardless of unindexed threat feed status.
    - Structural URL Deception: High lexical scores (raw IP, Punycode homograph, deceptive subdomains) elevate verdicts to `SUSPICIOUS` or `MALICIOUS`.
    - Indeterminate Evidence: Returns `UNKNOWN` with actionable cautionary advice whenever evidence is insufficient; strictly never defaults to safe.
    - Clean Consensus: Returns `SAFE` only when message is benign and all links are verified authentic across threat intelligence feeds and lexical checks.
- **API Endpoint Updates (`POST /api/v1/scan/url` & `POST /api/v1/scan/message`)**:
  - Integrated `CombinedRiskEngine` and `UrlClassifierService` into both scan endpoints.
  - Expanded `GET /api/v1/ml/models` and `POST /api/v1/ml/retrain` to inspect and train both SMS and URL machine learning models.
- **Automated Test Matrix (88 Tests Passing)**:
  - Added `backend/tests/test_url_features.py` (7 tests).
  - Added `backend/tests/test_url_trainer.py` (1 test).
  - Added `backend/tests/test_url_service.py` (4 tests).
  - Added `backend/tests/test_risk_engine.py` (5 tests).
  - 100% pass rate across all 88 backend tests (0 failed).

---

## [0.5.0] - Phase 4: SMS Machine Learning and Training Pipeline - 2026-11-05

### Added
- **Text Preprocessor & Entity Normalizer (`backend/app/ml/preprocessor.py`)**:
  - Implemented `SmsPreprocessor` with NFKC Unicode normalization and lowercase standardization.
  - Replaces variable sensitive tokens with canonical semantic markers: `<URL>`, `<PHONE>`, `<CURRENCY>`, `<CODE>`, `<EMAIL>`.
  - Safeguards user privacy by preventing numeric OTPs and raw contact details from entering feature extraction vectors.
  - Provides pre-masking entity count diagnostics (`extract_entity_counts`).
- **Domain Linguistic Indicators & Explanation Generator (`backend/app/ml/features.py`)**:
  - Implemented `LinguisticFeatureExtractor` (Scikit-Learn `BaseEstimator, TransformerMixin`) extracting 11 dense numerical security signals: urgency score, KYC/identity verification demand, financial lure/prize score, credential theft demand, utility disconnection scare, delivery courier lure, entity token indicators, and normalized text length.
  - Implemented `extract_explanation_reasons` providing human-readable explanations based on triggered threat indicators.
- **Dataset Registry & Stratified Partition Manager (`backend/app/ml/dataset.py`)**:
  - Implemented `DatasetManager` registering approved datasets (`DS-01` through `DS-05`) with provenance citations, licenses, record counts, and target classes.
  - Implemented strict data leakage prevention: exact deduplication on text before partitioning.
  - Stratified 3-way partition (70% Train, 15% Validation, 15% Test) preserving exact class distributions across splits without text leakage.
  - Built curated SMS benchmark corpus (`backend/app/ml/data/sms_corpus.csv`) covering all 17 scam categories and authentic legitimate notification classes.
- **Model Training, Evaluation & Baseline Comparison (`backend/app/ml/trainer.py`)**:
  - Implemented `SmsModelTrainer` comparing 3 baseline architectures:
    1. `ComplementNB` (Complement Naive Bayes with sublinear TF-IDF + linguistic features).
    2. `LogisticRegression` (calibrated probabilities with balanced class weighting).
    3. `LinearSVC` with Platt scaling (`CalibratedClassifierCV(method='sigmoid')`).
  - Evaluates un-fabricated hold-out test metrics: Precision, Recall, F1-Score, ROC-AUC, PR-AUC (`average_precision_score`), and Confusion Matrix.
  - Selected model: `logistic_regression` achieving Test PR-AUC of **0.9683** and Test F1 of **0.8571**.
  - Serializes winning model pipeline to `backend/app/ml/artifacts/sms_classifier.joblib` and metrics audit log to `backend/app/ml/artifacts/sms_model_metrics.json`.
- **Production Inference Service (`backend/app/ml/service.py`)**:
  - Thread-safe singleton `SmsClassifierService` loading trained pipeline once.
  - Computes calibrated scam probability, risk score (0-100), prediction confidence, and linguistic explanation reasons.
  - Calibrated decision thresholds ensuring high precision against false positives on authentic banking and transactional OTP messages.
  - Defensive fallback guarantee (`_heuristic_fallback`) if model pipeline artifact is unavailable.
- **Model and Dataset Management API Endpoints (`backend/app/api/v1/endpoints/ml.py`)**:
  - `GET /api/v1/ml/models`: Retrieves active and historical model versions with real evaluation metrics.
  - `GET /api/v1/ml/datasets`: Returns dataset registry provenance, licenses, and record counts.
  - `POST /api/v1/ml/retrain`: Executes training pipeline on demand and automatically deploys winning model artifact.
- **Backend Message Scan Integration (`backend/app/api/v1/endpoints/scan_message.py`)**:
  - Integrated `POST /api/v1/scan/message` with `SmsClassifierService` for NLP risk scoring and linguistic explanations.
- **Automated Test Matrix (71 Tests Passing)**:
  - Added `backend/tests/test_sms_preprocessor.py` (7 tests).
  - Added `backend/tests/test_sms_features.py` (2 tests).
  - Added `backend/tests/test_dataset_registry.py` (3 tests).
  - Added `backend/tests/test_sms_trainer.py` (1 test).
  - Added `backend/tests/test_sms_service.py` (5 tests).
  - Added `backend/tests/test_ml_endpoints.py` (3 tests).
  - 100% pass rate across all 71 backend tests (0 failed).

---

## [0.4.0] - Phase 3: Backend Threat Intelligence and URL Scanning - 2026-11-05

### Added
- **Defensive URL Normalizer & Sensitive Token Redactor (`backend/app/services/url/normalizer.py`)**:
  - Automatically handles natural language text extraction by stripping leading and trailing punctuation (brackets, quotes, commas, terminal periods).
  - Normalizes scheme-less domains safely defaulting to `http://` while strictly rejecting unsafe schemes (`file://`, `ftp://`, `javascript:`, `data:`, `mailto:`, `about:`).
  - Handles Internationalized Domain Names (IDN Punycode `xn--`) and canonical ASCII representations.
  - Automatically detects IP-literal hostnames (IPv4/IPv6) and known URL shorteners (`bit.ly`, `tinyurl.com`, `t.co`, `cutt.ly`, etc.).
  - Privacy and Token Redaction: sanitizes sensitive credential keys (`token`, `password`, `secret`, `auth`, `api_key`, `session`) from query parameters into `[REDACTED]` before persistent storage.
- **SSRF & DNS Rebinding Security Engine (`backend/app/services/url/ssrf_protector.py`)**:
  - Implements multi-layered pre-inspection validation gate protecting backend and intranet infrastructure.
  - Blocks loopback interfaces (`127.0.0.0/8`, `::1`, `localhost`).
  - Blocks RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
  - Blocks cloud provider instance metadata services (`169.254.169.254`, `metadata.google.internal`, `instance-data`).
  - Blocks carrier-grade NAT (`100.64.0.0/10`), multicast (`224.0.0.0/4`), broadcast, and reserved networks.
  - Mitigates DNS rebinding attacks by resolving candidate hostnames prior to outbound dispatch and verifying every returned socket address against disallowed CIDR ranges.
- **Threat Intelligence Provider Integrations (`backend/app/services/threat_intelligence/`)**:
  - `URLhausProvider`: Integrates with abuse.ch URLhaus threat feed. Enforces strict privacy rule: missing database records map to `UNKNOWN`, never false `CLEAN`.
  - `GoogleSafeBrowsingProvider`: Integrates with Google Safe Browsing Lookup API v4 for malware, unwanted software, and social engineering threat matching; returns `UNCONFIGURED` when API key is missing.
  - `VirusTotalProvider`: Integrates with VirusTotal v3 URL intelligence API; evaluates multi-engine detection metrics (`>= 2` malicious -> `MALICIOUS`, single hit / `>= 2` suspicious -> `SUSPICIOUS`, harmless -> `CLEAN`, 404/no telemetry -> `UNKNOWN`).
  - `ThreatAggregator`: Coordinates concurrent asynchronous lookups using `asyncio.gather`. Enforces malicious override priority, evidence reason aggregation, and strict `UNKNOWN` status whenever positive or negative intelligence is absent. Implements exception isolation so individual provider failures do not degrade overall service.
- **API Scan Endpoints (`backend/app/api/v1/endpoints/`)**:
  - `POST /api/v1/scan/url`: Complete endpoint for single URL inspection with normalization, SSRF verification, multi-source threat queries, lexical risk checks, and database audit logging.
  - `POST /api/v1/scan/message`: Complete endpoint for SMS scam evaluation with multi-signal heuristic and URL threat assessment.
- **Strict Privacy Storage Audit**:
  - Zero-raw-SMS retention rule enforced: `ScanRecord` database model stores exclusively SHA-256 `message_hash`, metadata, categories, and detection reasons. Raw message bodies are never persisted.
- **Automated Test Suite (50 Tests Passing)**:
  - Added `backend/tests/test_ssrf_protection.py` (11 tests).
  - Added `backend/tests/test_threat_providers.py` (15 tests).
  - Added `backend/tests/test_scan_endpoints.py` (11 tests).
  - Added `backend/tests/test_url_normalizer.py` (7 tests).
  - 100% pass rate across all 50 backend unit and integration tests.

---

## [0.3.0] - Phase 2: Automatic Notification Listener - 2026-11-05

### Added
- **Approved SMS Application Registry (`SupportedSmsApps`)**:
  - Implemented package whitelist strictly limited to `com.google.android.apps.messaging` (Google Messages) and `com.samsung.android.messaging` (Samsung Messages).
  - Explicitly rejects social messaging apps (WhatsApp, Telegram, Signal), email clients (Gmail, Outlook), and banking applications at the notification listener boundary.
- **Defensive Notification Content Parser (`NotificationParser`)**:
  - Extracts title, visible text, and conversational messages defensively across standard, `BigTextStyle`, and `MessagingStyle` structures.
  - Gracefully handles missing, empty, or OS-redacted notification payloads (`NotificationParseResult.RedactedOrEmpty`).
  - Zero-logging rule: diagnostic telemetry logs character length and URL count; raw SMS message text is strictly never printed to logs.
- **Transactional OTP Detection & Privacy Bypass (`OtpDetector`)**:
  - Identifies authentic, benign transactional verification codes (e.g. Amazon, Swiggy) containing numeric codes without URLs or threats.
  - Safely bypasses benign OTPs from analysis and persistence to protect user privacy.
  - Flags credential-theft phishing attempts (messages pairing verification codes with external URLs or account suspension threats) for active threat analysis.
- **Time-Windowed Deduplication & Rate Limiting (`DuplicateDetector`)**:
  - Computes SHA-256 fingerprint from `packageName + sender + messageText`.
  - Suppresses duplicate notification events within a 60-second sliding window.
  - Implements adaptive rate limiting (maximum 15 events/minute) to protect CPU and battery life.
- **Advanced URL Extractor & Feature Analyzer (`UrlExtractor`)**:
  - Robust regex pattern matching HTTP/HTTPS and scheme-less domains.
  - Strips leading and trailing punctuation (brackets, trailing periods, commas, colons).
  - Normalizes hostnames and handles Internationalized Domain Names (IDN Punycode `xn--`).
  - Identifies known URL shorteners (`bit.ly`, `tinyurl.com`, `t.co`, `is.gd`, etc.).
  - Detects suspicious raw IPv4 address hostnames.
  - Flags deceptive subdomains on high-risk TLDs (e.g. `sbi.bank.account-update.xyz`).
  - Discards email addresses (`support@bank.com`) by checking preceding `@` boundary characters.
- **NotificationListenerService Integration (`SMSNotificationListener`)**:
  - Enforces instant user opt-in control (drops all notifications immediately if monitoring is toggled off in settings).
  - Runs all parsing, URL analysis, and persistence asynchronously off the main thread via Kotlin Coroutines (`Dispatchers.Default`).
  - Saves risk assessment metadata to local Room database with zero raw SMS content.
- **Automated Test Matrix**:
  - 34 unit tests across 5 test suites covering package filtering, deduplication, OTP privacy, and all 10 URL extraction edge cases.

---

## [0.2.0] - Phase 1: Android Application Foundation - 2026-11-05

### Added
- **Compose Navigation**:
  - Implemented `Screen` sealed hierarchy (`Onboarding`, `PermissionSetup`, `Home`, `Scanner`, `Settings`).
  - Added `SMSShieldNavGraph` connecting onboarding, permission gates, dashboard, manual scanner, and settings.
  - Configured start destination logic responding to DataStore onboarding completion status.
- **Onboarding Flow (`OnboardingScreen`)**:
  - Product introduction and transparent disclosure of processed metadata.
  - Strict privacy notices detailing non-collection of OTPs, PINs, passwords, and raw SMS messages.
  - Explicit user opt-in checkbox requirement before proceeding.
- **Permission Setup (`PermissionSetupScreen`)**:
  - Real-time `NotificationListenerService` permission status check.
  - Action launcher for `Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS`.
  - Clear disclosure that monitoring is limited strictly to whitelisted SMS apps and manual scanning remains accessible if denied.
- **Home Dashboard Shell (`HomeScreen`)**:
  - Real-time guard status banner reflecting listener connection and user preference state.
  - Telemetry statistics grid (`Total Scans`, `Safe Messages`, `Suspicious`, `Malicious Links`).
  - Recent scan activity list backed by Room Database Flow with zero-state empty views.
  - Floating action button navigating to Scanner.
- **Message Scanner (`ScannerScreen`)**:
  - Manual message input with clipboard paste button.
  - Live regex URL extraction preview.
  - Analysis execution state (`Idle`, `Loading`, `Success`, `Error`).
  - Structured risk result display (`Classification`, `Risk Score`, `Recommendations`, `Security Indicators`).
- **Settings & Privacy Screen (`SettingsScreen`)**:
  - Monitoring enable/disable toggle.
  - Supported SMS sources registry inspector (`Google Messages`, `Samsung Messages`).
  - Configurable backend URL setting for emulator (`10.0.2.2`) and physical devices.
  - Data retention configuration and "Delete All History" confirmation dialog.
  - Full in-app Privacy Policy dialog.
- **Data Persistence**:
  - Room Database (`AppDatabase`, `ScanRecordEntity`, `ScanRecordDao`) strictly enforcing zero raw SMS storage.
  - Jetpack DataStore Preferences (`UserPreferencesRepository`) with monitoring disabled by default (`isMonitoringEnabled = false`).
- **Android Sharesheet (`ACTION_SEND`)**:
  - Integrated intent handling in `MainActivity` pre-filling shared SMS text and launching the Scanner screen.
- **Automated Domain & Architecture Tests**:
  - Verified default user preferences, URL parsing rules, and scan privacy constraints.

---

## [0.1.0] - Phase 0: Project Foundation - 2026-11-04

### Added
- **Monorepo Structure**:
  - Organized monorepo containing `android/`, `backend/`, and `dashboard/`.
  - Configured root `.gitignore` protecting secrets, environments, and build artifacts.
  - Added multi-container `docker-compose.yml` for PostgreSQL 16, FastAPI backend, and React dashboard.
- **Backend Foundation (`backend/`)**:
  - FastAPI application with asynchronous lifespan management.
  - SQLAlchemy 2.0 database engine supporting both PostgreSQL (`postgresql+psycopg://`) and SQLite (`sqlite+aiosqlite:///`) for immediate zero-config local runs.
  - Health check endpoint `GET /health` with live database connectivity ping.
  - Threat provider status endpoint `GET /api/v1/health/providers`.
  - Pydantic v2 schemas for health verification and system status.
  - Alembic database migration scaffolding.
  - Pytest test suite with HTTPX asynchronous test client verifying health check, database ping, and provider statuses.
- **Dashboard Foundation (`dashboard/`)**:
  - Vite + React 18 + TypeScript + Tailwind CSS setup.
  - Responsive cybersecurity dashboard UI featuring system status indicators, live backend connection check, and component health monitoring.
  - Reusable components: `Navbar`, `StatusBadge`, `HealthStatusView`, and `Overview`.
  - API client service for backend health checks and data retrieval.
  - Vitest test suite for component rendering and state verification.
- **Android Foundation (`android/`)**:
  - Dual-module architecture:
    - `:core-domain`: Pure Kotlin JVM module containing contracts, health models, and validation logic, fully buildable and testable with standard Gradle on Java 21.
    - `:app`: Android application module configured with Android Gradle Plugin 8.4, Jetpack Compose, Material 3, NotificationListenerService declaration, and unit tests.
  - Gradle 8.4 wrapper setup (`gradlew`, `gradlew.bat`, `gradle/wrapper/gradle-wrapper.jar`).
- **Documentation**:
  - `README.md`: Project overview and PowerShell quickstart.
  - `WINDOWS_SETUP.md`: Detailed Windows PowerShell setup, JDK 21, Android Studio, SDK paths, emulator loopback mapping (`10.0.2.2`).
  - `ARCHITECTURE.md`: High-level system architecture, data flow, and threat model boundaries.
  - `API.md`: OpenAPI specifications for all endpoints.
  - `DATABASE.md`: Relational schema design and data privacy policies.
  - `ML_METHODOLOGY.md`: NLP SMS classification and URL machine learning methodology.
  - `DATASET.md`: Dataset registry, provenance, licensing, and leakage prevention rules.
  - `PRIVACY.md`: Strict zero-raw-SMS retention and notification listener scope rules.
  - `SECURITY.md`: SSRF protection, DNS rebinding mitigations, and credential isolation.
  - `TESTING.md`: Android, backend, ML, and security test plans.

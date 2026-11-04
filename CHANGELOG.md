# SMS Shield Changelog

All notable changes to the SMS Shield application will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

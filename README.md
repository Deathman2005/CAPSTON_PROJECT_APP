# SMS Shield — AI-Powered Real-Time SMS Scam and Malicious URL Detection

[![Version](https://img.shields.io/badge/Version-1.0.0%20(Production)-blue.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Android%20%7C%20FastAPI%20%7C%20React-green.svg)]()
[![License](https://img.shields.io/badge/License-Apache--2.0-orange.svg)]()
[![Tests](https://img.shields.io/badge/Tests-132%20Passed%20(100%25)-brightgreen.svg)]()

SMS Shield is a privacy-first, Android security application and enterprise AI backend engineered to identify suspicious SMS messages, phishing attempts, financial fraud, and malicious URLs in real time.

---

## 1. System Vision & Architecture

When a supported SMS notification arrives, SMS Shield:
1. Detects the notification source via opt-in `NotificationListenerService`.
2. Verifies the package against an approved SMS application registry.
3. Extracts visible notification content defensively (strictly ignoring unrelated applications).
4. Normalizes text and extracts URLs.
5. Sends minimal metadata to the FastAPI backend.
6. Analyzes text using ML classifiers and inspects URLs using threat intelligence and lexical feature models.
7. Produces a calibrated composite risk score (`SAFE`, `SUSPICIOUS`, `MALICIOUS`, or `UNKNOWN`).
8. Triggers Android warning notifications when risk warrants it.
9. Provides a manual share/paste alternative for zero-permission manual scanning.

---

## 2. Monorepo Structure

```text
CP2/
├── android/               # Android Client (Kotlin, Jetpack Compose, Material 3, Gradle)
│   ├── app/               # Android application module (UI, Service, Room, Retrofit)
│   ├── core-domain/       # Pure Kotlin JVM domain module (Contracts, Validation, Tests)
│   └── gradle/wrapper/    # Gradle wrapper 8.4
├── backend/               # FastAPI Backend (Python 3.12, SQLAlchemy 2, Alembic, Pydantic v2)
│   ├── app/
│   │   ├── api/           # API routes & v1 endpoints (Health, Scan, Dashboard)
│   │   ├── core/          # Config, Database engine, Logging
│   │   ├── models/        # SQLAlchemy ORM models
│   │   └── schemas/       # Pydantic schemas
│   ├── tests/             # Pytest automated test suite
│   └── alembic/           # Database migrations
├── dashboard/             # React Analytics Dashboard (TypeScript, Vite, Tailwind CSS, Recharts)
│   ├── src/               # UI components, pages, services, tests
│   └── tests/             # Vitest test suite
├── docker-compose.yml     # Multi-container orchestration (PostgreSQL 16, Backend, Dashboard)
├── ARCHITECTURE.md        # Architectural decisions, data flow, component boundaries
├── API.md                 # REST API endpoints & contracts
├── DATABASE.md            # PostgreSQL schemas, indexing & privacy policies
├── ML_METHODOLOGY.md      # NLP text classification & URL ML pipeline
├── DATASET.md             # Dataset registry, provenance & leakage prevention
├── PRIVACY.md             # Privacy constraints & zero-raw-SMS retention rules
├── SECURITY.md            # Threat model, SSRF protection & safe URL inspection
├── TESTING.md             # Android, Backend, ML & Security test matrices
├── WINDOWS_SETUP.md       # Step-by-step PowerShell setup for Windows
└── CHANGELOG.md           # Progress and phase release tracking
```

---

## 3. Technology Stack

- **Android Client**: Kotlin, Jetpack Compose, Material 3, Coroutines, Flow, Retrofit, Room, DataStore, NotificationListenerService.
- **AI Backend**: Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2.0, Alembic, Uvicorn, Asyncpg / Psycopg.
- **Machine Learning**: Scikit-learn, XGBoost, Pandas, NumPy, Joblib, SHAP.
- **Frontend Dashboard**: React 18, TypeScript, Vite, Tailwind CSS, Lucide Icons, Recharts, Vitest.
- **Database & Infrastructure**: PostgreSQL 16, Docker Compose, Git.

---

## 4. Implementation Phase Status

- [x] **Phase 0: Architecture, Setup, and Monorepo** (FastAPI, SQLite/PostgreSQL, React, Gradle setup).
- [x] **Phase 1: Android Foundation and Privacy-First UI** (5 Compose screens, Room DB, DataStore, Sharesheet).
- [x] **Phase 2: Android Notification Monitoring and Extraction** (NotificationListenerService, Google/Samsung whitelist, OtpDetector, DuplicateDetector).
- [x] **Phase 3: Backend Threat Intelligence and URL Scanning** (URL normalizer, SSRF protection, URLhaus, Google Safe Browsing, VirusTotal).
- [x] **Phase 4: SMS Machine Learning and Training Pipeline** (SMS preprocessor, linguistic features, dataset registry, model training & baseline comparison, inference service).
- [x] **Phase 5: URL Machine Learning and Combined Risk Engine** (Lexical feature extraction, URL model training, CombinedRiskEngine multi-signal consensus).
- [x] **Phase 6: Full Integration and Warning Experience** (AlertDecisionEngine, Retrofit ApiClient, ScanRepository, AlertNotificationManager high-priority alerts).
- [x] **Phase 7: Dashboard, Security Hardening, and Final Delivery** (Recharts threat distribution & source charts, live audit log, dashboard stats API, 100% test pass rate).

---

## 5. Quickstart (Windows PowerShell)

### Backend

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -r requirements-dev.txt
Copy-Item .env.example .env
pytest -v
uvicorn app.main:app --reload --port 8000
```

### Dashboard

```powershell
cd dashboard
npm install
npm test
npm run dev
```

### Android

```powershell
cd android
.\gradlew.bat :core-domain:test
```

Detailed setup instructions, including emulator networking (`10.0.2.2`) and physical phone testing, are documented in [WINDOWS_SETUP.md](file:///c:/Users/anura/OneDrive/Desktop/CP2/WINDOWS_SETUP.md).

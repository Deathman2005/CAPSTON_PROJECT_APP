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

- [x] **Phase 1: Backend Groq AI & Structured XAI Service** (Groq API `llama-3.3-70b-versatile`, anti-hallucination prompt envelope, 12 Indian fraud templates, deterministic offline fallback, bilingual English + Hindi translations).
- [x] **Phase 2: Enhanced ML Model & TreeSHAP Token Attribution Engine** (Curated corpus expanded across all 12 fraud archetypes, calibrated classifier, exact Linear Shapley & TreeSHAP word attribution with character offsets).
- [x] **Phase 3: QR Code Decoder & UPI Intent Parsing Engine** (NPCI UPI parser for `pa`, `pn`, `am`, `tn`, `mc`, `tr` across 32+ PSP handles, deceptive credit/refund trap analyzer, payee impersonation detector, `POST /api/v1/scan/qr`).
- [x] **Phase 4: Android QR Scanner UI & Dual Mode** (Interactive SMS vs UPI/QR mode switcher, auto-routing from Android Sharesheet, offline QR heuristic fallback).
- [x] **Phase 5: Android Explainable AI UI & Real-Time Notification Guard** (`buildHighlightedAnnotatedString` inline word attribution, Groq AI Card with `[EN / हिंदी]` live toggle, `UpiPaymentIntentCard` displaying NPCI UPI debit rule warning, Xiaomi MIUI / HyperOS autostart & battery optimization protection).
- [x] **Phase 6: Full Integration Flow, Web Dashboard Sync & Final Release** (End-to-end integration test suite `test_e2e_full_flow.py`, 100% test pass rate, production React dashboard build, release ProGuard rules).

---

## 5. Supported Indian Financial Fraud Scenarios (12 Categories)

1. **Fake Payment Confirmation**: Fraudulent payment-success SMS claiming money was received without bank credit.
2. **Fake UPI Collect Request**: Deceptive collect requests urging victims to "Approve to receive payment".
3. **QR-Code Payment Scam**: Deceptive QR codes claiming scanning credits refunds/prizes (NPCI rule: QR codes *only* debit money).
4. **Fake Refund Scam**: Claims of failed transactions with requests to approve payment for refund release.
5. **Duplicate Payment Scam**: Claims that an earlier transaction failed, coercing repeated payment.
6. **Fake KYC Update SMS**: Threatens bank account suspension unless KYC is updated via phishing link.
7. **Bank Account Suspension Scam**: Threatens immediate blocking of account, netbanking, or debit card.
8. **Fake Customer-Care Scam**: Impersonates bank or payment support, requesting OTPs or remote access apps (AnyDesk, RustDesk).
9. **Cashback and Reward Scam**: Unsolicited prize and scratch card lures with phishing claims.
10. **SIM-Blocking Scam**: Threatens mobile number disconnection unless urgent e-KYC is completed.
11. **Electricity Bill Disconnection Scam**: Urgent demands for electricity payment to prevent imminent disconnection.
12. **Fake Delivery Fee Scam**: Demands unpaid customs or parcel dispatch fees via external tracking links.

---

## 6. Quickstart (Windows PowerShell)

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

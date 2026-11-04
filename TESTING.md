# SMS Shield — Testing Strategy & Verification Protocols

SMS Shield enforces comprehensive automated testing across all sub-projects.

---

## 1. Test Matrices

### 1.1 Android Application (`android/`)
- **Unit Tests**:
  - `SupportedSmsApps` package filtering (verifies whitelisted SMS apps accepted, unrelated apps rejected).
  - Notification parsing and fallback extraction.
  - URL extraction engine (handling punctuation, query params, IP addresses, non-URL text, shortened links).
  - Redaction of numeric OTP patterns.
- **Integration & UI**:
  - Navigation state flow between Onboarding, Permission Setup, Dashboard, and Scanner.
  - Manual share intent receiver (`ACTION_SEND`).
  - Network error handling and offline graceful degradation.

### 1.2 FastAPI Backend (`backend/`)
- **Health & Readiness**:
  - `/health` endpoint verification with active database ping.
  - `/api/v1/health/providers` threat intelligence adapter status checks.
- **Scanning Endpoints**:
  - Valid message with URLs.
  - Message with no URLs.
  - Empty or excessively large message inputs.
  - Threat intelligence provider timeout simulation (ensuring response degrades to `CHECK_UNAVAILABLE` / `UNKNOWN`, never false `SAFE`).
  - Combined risk scoring edge cases.
- **Security & SSRF**:
  - URL inspection against `127.0.0.1`, `169.254.169.254`, and private RFC 1918 addresses must be blocked immediately.

### 1.3 React Dashboard (`dashboard/`)
- **Component Tests (Vitest)**:
  - Header & navigation bar rendering.
  - System health badge status changes (`healthy`, `degraded`, `unreachable`).
  - Telemetry summary card metrics rendering.
  - Responsive design verification.

---

## 2. Running Automated Tests on Windows PowerShell

### Backend Tests
```powershell
cd backend
.\.venv\Scripts\Activate.ps1
pytest -v --tb=short
```

### Dashboard Tests
```powershell
cd dashboard
npm test
```

### Android Core Domain Tests
```powershell
cd android
.\gradlew.bat :core-domain:test
```

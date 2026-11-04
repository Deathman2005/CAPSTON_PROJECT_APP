# SMS Shield — Windows PowerShell Development Setup Guide

This guide provides step-by-step instructions for developing, testing, and running **SMS Shield** on Windows 11 / Windows 10 using PowerShell.

---

## 1. Prerequisites Overview

| Component | Minimum Version | Tested Environment |
|---|---|---|
| **OS** | Windows 10 / 11 64-bit | Windows 11 Build 22631+ |
| **Java JDK** | OpenJDK 17 or 21 | Oracle JDK 21 (`E:\Program Files\Java\jdk-21`) |
| **Python** | 3.11 or 3.12 | Python 3.12 (`E:\Python312\python.exe`) |
| **Node.js** | 18+ LTS | Node.js v24.22.1 / npm 11.6+ |
| **Android SDK** | API Level 34 (Android 14) | Android Studio Hedgehog/Iguana/Jellyfish |
| **Docker (Optional)**| Docker Desktop 4+ | Docker Compose v2 (or local SQLite fallback) |

---

## 2. Environment Variables Configuration

Set your environment variables in PowerShell or via Windows System Properties:

```powershell
# Set Java Home (Example path - adjust to your JDK installation)
[System.Environment]::SetEnvironmentVariable("JAVA_HOME", "E:\Program Files\Java\jdk-21", "User")

# Set Android SDK Root (adjust to your Android SDK location)
[System.Environment]::SetEnvironmentVariable("ANDROID_HOME", "$env:LOCALAPPDATA\Android\Sdk", "User")

# Add tools to User PATH
$currentPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
$newPaths = @(
    "$env:JAVA_HOME\bin",
    "$env:ANDROID_HOME\platform-tools",
    "$env:ANDROID_HOME\cmdline-tools\latest\bin"
) -join ";"

if ($currentPath -notlike "*Android*") {
    [System.Environment]::SetEnvironmentVariable("Path", "$currentPath;$newPaths", "User")
}
```

Verify in a new PowerShell terminal:
```powershell
java -version
python --version
node -v
npm -v
```

---

## 3. Python Backend Setup

### A. Create Virtual Environment

Navigate to the `backend/` directory:
```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell restricts script execution, run:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.\.venv\Scripts\Activate.ps1
```

### B. Install Dependencies

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### C. Configure Environment Variables

Copy `.env.example` to `.env`:
```powershell
Copy-Item .env.example .env
```

By default, the `.env` is configured to connect to PostgreSQL if available, or fall back to local SQLite:
```ini
ENVIRONMENT=development
DEBUG=True
DATABASE_URL=sqlite+aiosqlite:///./sms_shield.db
# For PostgreSQL:
# DATABASE_URL=postgresql+psycopg://smsshield:smsshield_dev_secret_change_in_prod@localhost:5432/smsshield
```

### D. Run Database Migrations & Health Check

```powershell
# Run health check tests
pytest -v
```

### E. Start Backend Development Server

```powershell
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```
- API Docs: `http://localhost:8000/docs`
- Health Endpoint: `http://localhost:8000/health`

---

## 4. React Dashboard Setup

### A. Install Dependencies

Open a new PowerShell window:
```powershell
cd dashboard
npm install
```

### B. Configure Environment Variables

```powershell
Copy-Item .env.example .env
```
Ensure `VITE_API_BASE_URL=http://localhost:8000` is set.

### C. Run Tests & Start Dashboard

```powershell
# Run tests
npm test

# Start development server
npm run dev
```
Dashboard will be available at: `http://localhost:5173`

---

## 5. Android Application Setup

### A. Android Studio Installation

1. Download and install [Android Studio](https://developer.android.com/studio).
2. During setup, ensure **Android SDK**, **Android SDK Command-line Tools**, and **Android Virtual Device (AVD)** are checked.
3. Open Android Studio -> **Settings** -> **Build, Execution, Deployment** -> **Build Tools** -> **Gradle** -> Set **Gradle JDK** to Java 17 or 21.

### B. Building with Gradle Wrapper

From the `android/` directory:
```powershell
cd android

# Build the core domain module (validates architecture and domain logic)
.\gradlew.bat :core-domain:test

# Build Android debug APK (requires Android SDK installed)
.\gradlew.bat assembleDebug
```

---

## 6. Network Topology: Emulator vs Physical Device

> [!IMPORTANT]
> The Android emulator and a physical Android device have different network routes to your development machine:

### A. Android Emulator
The Android emulator runs inside a virtual network. To reach your Windows backend:
- **Host Address**: `10.0.2.2` (maps directly to `127.0.0.1` on your Windows PC).
- In the Android app settings or `.env`: set Backend URL to `http://10.0.2.2:8000`.

### B. Physical Android Device
A physical phone connected via Wi-Fi cannot access `127.0.0.1` or `10.0.2.2`.
1. Ensure your PC and phone are on the same Wi-Fi network.
2. Find your PC's local IP address:
   ```powershell
   Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -match "Wi-Fi|Ethernet" } | Select-Object IPAddress
   ```
3. Allow inbound connections on port 8000 in Windows Firewall:
   ```powershell
   New-NetFirewallRule -DisplayName "SMS Shield Backend Port 8000" -Direction Inbound -LocalPort 8000 -Protocol TCP -Action Allow
   ```
4. Set Backend URL in the Android app to: `http://<YOUR_LOCAL_IP>:8000`.
5. Alternatively, use ADB reverse port forwarding over USB cable:
   ```powershell
   adb reverse tcp:8000 tcp:8000
   ```
   Now the physical phone can access `http://localhost:8000`!

---

## 7. Docker Compose (Full Stack)

If Docker Desktop is running on Windows:
```powershell
# Start PostgreSQL, Backend, and Dashboard together:
docker compose up --build -d

# Check status:
docker compose ps

# View logs:
docker compose logs -f

# Shutdown:
docker compose down
```

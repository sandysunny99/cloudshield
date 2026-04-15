# 🛡️ CloudShield — Unified Cloud EDR & CSPM Platform

<div align="center">

![CloudShield Banner](https://img.shields.io/badge/CloudShield-v3.0--SaaS-blue?style=for-the-badge&logo=shield&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.x-000000?style=for-the-badge&logo=flask&logoColor=white)
![Vercel](https://img.shields.io/badge/Frontend-Vercel-000000?style=for-the-badge&logo=vercel&logoColor=white)
![Render](https://img.shields.io/badge/Backend-Render-46E3B7?style=for-the-badge&logo=render&logoColor=white)

**Real-time Cloud Security Posture Management + Endpoint Detection & Response**

[🌐 Live Dashboard](https://cloudshield-vtah.vercel.app) · [📡 API Docs](#api-reference) · [🚀 Deploy Agent](#deploy-agent-quickstart) · [📖 Full Docs](docs/DOCUMENTATION.md)

</div>

---

## ✨ What is CloudShield?

CloudShield is a **production-grade, open-source SaaS security platform** that combines:

| Capability | Description |
|---|---|
| **EDR (Endpoint Detection & Response)** | Lightweight Python agent that streams real-time CPU, RAM, open ports, and Trivy CVE data from any endpoint |
| **CSPM (Cloud Security Posture Management)** | Scans AWS/Azure/GCP configurations for misconfigurations and policy violations |
| **Unified Risk Engine** | Correlates CVEs + misconfigurations + network exposure into a single risk score |
| **Compliance Mapping** | Auto-maps findings to NIST 800-53, ISO 27001, and HIPAA frameworks |
| **Real-time Dashboard** | Live fleet view with per-agent telemetry, charts, SOC event timeline, and scan history |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        CloudShield Platform                          │
│                                                                       │
│  ┌──────────────┐    HTTPS/HMAC-SHA256     ┌──────────────────────┐  │
│  │   ENDPOINT   │ ──── agent-scan API ───► │   FLASK BACKEND      │  │
│  │              │                           │   (Render Cloud)     │  │
│  │  agent.py    │ ◄── 200 OK / 403 ──────  │                      │  │
│  │              │                           │  ┌────────────────┐  │  │
│  │  • psutil    │                           │  │  AGENT_CACHE   │  │  │
│  │  • Trivy fs  │                           │  │  (in-memory)   │  │  │
│  │  • HMAC sign │                           │  └───────┬────────┘  │  │
│  └──────────────┘                           │          │            │  │
│                                             │  ┌───────▼────────┐  │  │
│  ┌──────────────┐                           │  │  PIPELINE      │  │  │
│  │  start_agent │                           │  │  • Scanner     │  │  │
│  │  .bat        │                           │  │  • Policy Eng  │  │  │
│  │  (Windows bg)│                           │  │  • Correlation │  │  │
│  └──────────────┘                           │  │  • Risk Engine │  │  │
│                                             │  │  • Remediation │  │  │
│  ┌──────────────────────────────────┐       │  │  • Compliance  │  │  │
│  │       VERCEL FRONTEND            │       │  └────────────────┘  │  │
│  │                                  │       └──────────────────────┘  │
│  │  index.html + dashboard.js       │                │                 │
│  │                                  │   REST API  ◄──┘                 │
│  │  • Fleet Telemetry Panel         │   /api/agent-status              │
│  │  • Real-time Charts              │   /api/scan                      │
│  │  • Deploy Agent Modal  ──────────┼──► /api/download-agent          │
│  │  • Run Scan (live CVEs)          │   /api/demo                      │
│  │  • Demo Scan (sample data)       │   /api/check-storage             │
│  │  • SOC Timeline                  │   /api/soc-timeline              │
│  │  • Export Report                 │   /api/scan-config               │
│  │  • Scan History                  │                                  │
│  └──────────────────────────────────┘                                  │
└─────────────────────────────────────────────────────────────────────────┘
```

### Core Component Blocks

```
┌─────────── AGENT BLOCK ───────────┐   ┌─────────── BACKEND BLOCK ──────────┐
│                                   │   │                                     │
│  1. Collect System Telemetry      │   │  1. HMAC-SHA256 Signature Verify    │
│     • cpu_percent (psutil)        │   │  2. Anti-Replay Nonce Cache         │
│     • ram_percent (psutil)        │   │  3. Timestamp TTL Check (60s)       │
│     • top_processes (psutil)      │   │  4. AGENT_CACHE Store               │
│     • open_ports (psutil)         │   │  5. Risk Score Calculator           │
│                                   │   │     sys_risk + net_risk + cve_risk  │
│  2. Background Trivy CVE Scan     │   │  6. /api/scan → Agent CVE Pipeline  │
│     (every 20 min, ~/ dir only)   │   │  7. /api/download-agent → .exe     │
│     • VulnerabilityID             │   │  8. /api/agent-keys → API key      │
│     • PkgName, Severity, Title    │   │                                     │
│     • Cached in memory (max 50)   │   └─────────────────────────────────────┘
│                                   │
│  3. HMAC-SHA256 Payload Signing   │   ┌─────────── PIPELINE BLOCK ──────────┐
│     POST\n/api/agent-scan\n       │   │                                     │
│     {timestamp}\n{nonce}\n{body}  │   │  scanner.py   → CVE findings        │
│                                   │   │  policy_engine.py → IAM/S3 checks   │
│  4. Telemetry Loop (every 30s)    │   │  correlation.py → cross-source      │
│     Adaptive: +30s if CPU > 80%   │   │  risk_engine.py → final_score       │
│                                   │   │  remediation.py → fix actions       │
│  5. Persistent Agent ID           │   │  compliance.py → NIST/ISO/HIPAA    │
│     uuid5(NAMESPACE_DNS, MAC)     │   │                                     │
└───────────────────────────────────┘   └─────────────────────────────────────┘
```

---

## 🚀 Deploy Agent Quickstart

CloudShield ships a **downloadable standalone agent** — no Python required on the target machine.

### Option A: From the Dashboard (Recommended)
1. Go to [https://cloudshield-vtah.vercel.app](https://cloudshield-vtah.vercel.app)
2. Click **🚀 Deploy Agent** in the top navigation
3. Download `cloudshield-agent.exe`
4. Run it and enter your Dashboard API Key when prompted

### Option B: PowerShell One-Liner
```powershell
Invoke-WebRequest "https://cloudshield-tya3.onrender.com/api/download-agent" -OutFile cloudshield-agent.exe
.\cloudshield-agent.exe --key YOUR_API_KEY
```

### Option C: CLI with Key
```powershell
.\cloudshield-agent.exe --key default-agent-key-123
```

### Option D: Background (Silent, Auto-Restart)
Double-click `start_agent.bat` — runs `pythonw` invisibly, auto-restarts if it crashes.

> **Note:** Install [Trivy](https://github.com/aquasecurity/trivy/releases) on the endpoint to enable real vulnerability scanning. Without it, the agent still reports system metrics but CVE fields will be empty.

---

## 📁 Project Structure

```
cloudshield/
├── agent/
│   ├── agent.py              # EDR Agent — telemetry + Trivy + HMAC signing
│   ├── start_agent.bat       # Windows background runner (pythonw, auto-restart)
│   └── test_edr.py           # Agent unit tests
│
├── backend/
│   ├── app.py                # Flask API — all endpoints + AGENT_CACHE
│   ├── main.py               # Pipeline orchestrator (run_pipeline, run_demo)
│   ├── scanner.py            # Trivy CVE parser
│   ├── policy_engine.py      # OPA-style policy checks (IAM, S3, encryption)
│   ├── correlation.py        # Cross-source finding correlator
│   ├── risk_engine.py        # Risk scoring (CVE + network + system streams)
│   ├── remediation.py        # Auto-remediation suggestions
│   ├── compliance.py         # NIST / ISO 27001 / HIPAA mapper
│   ├── dist/
│   │   └── cloudshield-agent.exe   # Precompiled agent (served via /api/download-agent)
│   ├── policies/             # YAML policy rules
│   ├── sample_data/          # Demo scan sample configs
│   └── requirements.txt
│
├── frontend/
│   ├── index.html            # Single-page dashboard app
│   └── src/
│       ├── dashboard.js      # All UI logic, API calls, charts
│       └── style.css         # Dark glassmorphism theme
│
├── render.yaml               # Render deployment config
└── .gitignore
```

---

## 🔌 API Reference

All endpoints are hosted at `https://cloudshield-tya3.onrender.com`

### Agent Telemetry

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/agent-scan` | Receive signed agent telemetry payload |
| `GET`  | `/api/agent-status` | Get all connected agents with health scores |

**Agent telemetry payload:**
```json
{
  "agentId": "uuid-derived-from-mac",
  "agentVersion": "2.0.0-EDR-PRO",
  "timestamp": 1713200000.0,
  "nonce": "uuid4-random",
  "hostname": "DESKTOP-ABC123",
  "os": "Windows/Unknown",
  "cpu_percent": 9.7,
  "ram_percent": 77.0,
  "top_processes": [{"pid": 1234, "name": "chrome.exe", "cpu": 5.2}],
  "open_ports": [{"port": 80, "ip": "127.0.0.1"}],
  "vulnerabilities": [
    {"id": "CVE-2024-1234", "pkg": "openssl", "severity": "HIGH", "title": "Buffer overflow"}
  ]
}
```

**Required headers:**
```
Content-Type: application/json
x-agent-signature: <HMAC-SHA256>
x-agent-timestamp: <unix epoch>
x-agent-nonce: <uuid4>
x-agent-key: <api-key>
```

### Scanning

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scan` | Run scan — uses live agent CVEs if agent online, else returns error |
| `POST` | `/api/demo` | Demo scan — before/after comparison using sample data |
| `POST` | `/api/scan-config` | Scan a pasted JSON/YAML cloud config |
| `POST` | `/api/check-storage` | Check AWS S3 / Azure Blob / GCP bucket exposure |

### Agent Distribution

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/api/download-agent` | Download `cloudshield-agent.exe` |
| `GET`  | `/api/agent-keys` | Get dashboard API key + download URL |

### Dashboard Data

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/api/results` | Latest cached pipeline results |
| `GET`  | `/api/security-metrics` | Aggregated fleet security metrics |
| `GET`  | `/api/soc-timeline` | SOC event stream |

---

## 🔒 Security Model

### HMAC-SHA256 5-Part Payload Signing
Every agent request is signed with:
```
HMAC-SHA256(
  "POST\n/api/agent-scan\n{timestamp}\n{nonce}\n{json_body}"
)
```

### Anti-Replay Protection
- Nonces are cached for 120 seconds
- Timestamps must be within ±60 seconds of server time
- Replayed requests return `403 Replay attack detected`

### Agent Key Rotation
Set `AGENT_KEYS` environment variable as a comma-separated list of valid keys:
```
AGENT_KEYS=key-prod-001,key-prod-002
```

### Rate Limiting
- `/api/agent-scan` — 30 requests/minute per IP
- `/api/check-storage` — 10/minute, 100/day

---

## 🛠️ Local Development

### Prerequisites
- Python 3.12+
- Node.js 18+
- [Trivy](https://github.com/aquasecurity/trivy/releases) (optional, for CVE scanning)

### Backend
```bash
cd backend
pip install -r requirements.txt
python app.py
# Runs on http://localhost:5000
```

### Frontend
```bash
cd frontend
npm install
npm run dev
# Runs on http://localhost:5173
```

### Agent
```bash
cd agent
pip install psutil requests
python agent.py --key default-agent-key-123
```

### Environment Variables
```env
# Backend (set on Render)
CLOUDSHIELD_API_URL=https://cloudshield-tya3.onrender.com/api/agent-scan
AGENT_KEYS=default-agent-key-123
ALLOWED_ORIGINS=https://cloudshield-vtah.vercel.app,http://localhost:5173
AZURE_STORAGE_CONNECTION_STRING=...
CF_API_TOKEN=...
CF_ZONE_ID=...

# Frontend (set on Vercel)
VITE_API_URL=https://cloudshield-tya3.onrender.com
```

---

## 📦 Build Agent Executable (PyInstaller)

```bash
cd agent
pip install pyinstaller
pyinstaller --onefile --noconsole agent.py
# Output: agent/dist/agent.exe

# Copy to backend for serving
cp agent/dist/agent.exe backend/dist/cloudshield-agent.exe
```

---

## 🌐 Deployment

### Backend → Render
Configured via `render.yaml`. Auto-deploys on every push to `main`.

```yaml
services:
  - type: web
    name: cloudshield-backend
    runtime: python
    buildCommand: pip install -r backend/requirements.txt
    startCommand: gunicorn wsgi:app
```

### Frontend → Vercel
Auto-deploys on every push to `main`. Set `VITE_API_URL` in Vercel environment variables.

---

## 🧪 Pipeline Flow

```
User clicks "Run Scan"
        │
        ▼
POST /api/scan
        │
        ├─── Agent Online? ──YES──► Use agent.vulnerabilities
        │                                    │
        │                           scanner findings
        │                                    │
        └─── Agent Offline? ──────► 400 "No active agents connected"
                                             │
                              ┌──────────────▼──────────────┐
                              │     run_pipeline()           │
                              │                              │
                              │  scanner.py (CVEs)          │
                              │       ↓                      │
                              │  policy_engine.py           │
                              │       ↓                      │
                              │  correlation.py             │
                              │       ↓                      │
                              │  risk_engine.py             │
                              │       ↓                      │
                              │  remediation.py             │
                              │       ↓                      │
                              │  compliance.py              │
                              └──────────────┬──────────────┘
                                             │
                                    JSON result → frontend
                                    renderResults() → charts + tables
```

---

## 📊 Dashboard Features

| Feature | Description |
|---|---|
| **Fleet Overview** | Real-time agent status (online/stale/offline), risk scores, health |
| **Run Scan** | Triggers live pipeline scan using connected agent CVE data |
| **Demo Scan** | Before/after comparison scan using sample misconfigured configs |
| **Paste & Scan** | Paste raw JSON/YAML cloud config for instant analysis |
| **Storage Check** | Public exposure audit for AWS S3, Azure Blob, GCP buckets |
| **Endpoints Panel** | Per-agent telemetry: CPU, RAM, ports, processes, CVE density |
| **Deploy Agent** | One-click agent download + API key display + PowerShell install commands |
| **Export Report** | Downloads JSON report with hostname, IP, timestamp, findings, compliance |
| **SOC Timeline** | Live event stream of all security events |
| **Scan History** | Local (localStorage) history of last 10 scans with reload |

---

## 🏷️ Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Vanilla JS, Chart.js, CSS Glassmorphism |
| Backend | Python 3.12, Flask, Flask-Limiter, Flask-CORS |
| Agent | Python, psutil, requests, Trivy |
| Packaging | PyInstaller (standalone .exe) |
| Hosting | Vercel (frontend), Render (backend) |
| Security | HMAC-SHA256, rate limiting, anti-replay, nonce cache |
| Compliance | NIST 800-53, ISO 27001, HIPAA |

---

## 📄 License

MIT License — See [LICENSE](LICENSE) for details.

---

<div align="center">
Built with ❤️ as an enterprise-grade open-source DevSecOps platform.
</div>

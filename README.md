# 🛡️ CloudShield — AI-Augmented Cloud & Container Security Platform

**CloudShield** is a real-time, AI-augmented unified security platform combining EDR (Endpoint Detection & Response), CSPM (Cloud Security Posture Management), and container vulnerability scanning into a single production-grade dashboard.

[![Deploy on Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com)

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         CLOUDSHIELD PLATFORM                        │
├───────────────────────────┬─────────────────────────────────────────┤
│   FRONTEND (Vercel)       │         BACKEND (Render / Docker)       │
│   Vite + Vanilla JS       │         Flask + Gunicorn                │
│                           │                                         │
│  ┌─────────────────────┐  │  ┌────────────────────────────────────┐ │
│  │   Dashboard UI      │  │  │             app.py (Flask)         │ │
│  │  - Risk Score Bar   │◄─┼─►│  /api/scan     /api/scan/container │ │
│  │  - Alert Notifs     │  │  │  /api/scan/aws /api/scan/cloud     │ │
│  │  - Container Scan   │  │  │  /api/analyze/risk /api/alerts     │ │
│  │  - AI Analysis      │  │  │  /api/agent/report                 │ │
│  │  - Compliance Map   │  │  │  /api/risk/score                   │ │
│  └─────────────────────┘  │  └────────────────┬───────────────────┘ │
│                           │                   │                     │
│                           │  ┌────────────────▼───────────────────┐ │
│                           │  │         SERVICES LAYER              │ │
│                           │  │                                     │ │
│                           │  │  trivy_service.py    ◄── Trivy CLI  │ │
│                           │  │  aws_service.py      ◄── boto3      │ │
│                           │  │  opa_service.py       ◄── OPA/Rego  │ │
│                           │  │  ai_service.py        ◄── OpenAI    │ │
│                           │  │  correlation_service.py             │ │
│                           │  │  compliance_service.py              │ │
│                           │  │  scheduler_service.py ◄── APSched.  │ │
│                           │  │  alert_service.py    ◄── SMTP       │ │
│                           │  │  db_service.py        ◄── MongoDB   │ │
│                           │  └────────────────────────────────────┘ │
└───────────────────────────┴─────────────────────────────────────────┘
         ▲
         │
┌────────┴────────┐
│  CloudShield    │  agent/agent.py
│  EDR Agent      │  - Live CPU/RAM/process telemetry
│  (.exe / .py)   │  - Trivy filesystem scans
│                 │  - Running Docker containers
│  HMAC-SHA256    │  - HMAC-SHA256 signed payloads
│  signed payloads│  - Adaptive polling (30s-60s)
└─────────────────┘
         │
         └─► POST /api/agent-scan  (primary telemetry)
             POST /api/agent/report (extended + docker)
```

---

## ✨ Features

### 🔍 Real-Time Scanning
| Feature | Technology | Details |
|---|---|---|
| Container CVE Scanning | **Trivy CLI** | Scans any Docker image for CVEs. Returns CVSS scores + fix versions |
| Cloud Posture (AWS) | **boto3 + OPA** | Live-fetches S3, IAM, EC2 SGs and evaluates via OPA Rego policies |
| Filesystem Scan | **Trivy (agent)** | Agent runs a home-directory Trivy scan every 20 mins in background |
| Config Paste & Scan | **OPA Fallback** | Paste any AWS/GCP/Azure JSON config and evaluate instantly |

### 🤖 AI-Powered Risk Analysis
- **Deterministic engine**: CVSS-based scores with weighted formula
- **OpenAI GPT-4o-mini** (optional): narrative analysis, attack vectors, blast radius
- **Graceful fallback**: deterministic rules if no OpenAI key is configured

### 📋 Compliance Mapping
Automatically maps all findings to:
- **CIS Controls v8**
- **NIST 800-53**
- **ISO 27001:2022**
- **HIPAA**

### ⏰ Automated Monitoring
- **APScheduler** runs cloud + container scans every **6 hours**
- Results stored automatically in MongoDB
- Critical findings trigger immediate **SMTP alerts**

### 📡 EDR Agent
- Downloadable `.exe` (built via PyInstaller)
- Cross-platform telemetry (Windows/Linux/macOS)
- HMAC-SHA256 signed + API key authentication
- Docker container visibility
- Adaptive CPU-throttled polling

---

## 🚀 Quick Start

### Prerequisites
- Python 3.12+
- Node.js 18+
- [Trivy](https://aquasecurity.github.io/trivy/) in system PATH
- MongoDB (optional — falls back to in-memory)
- OPA (optional — built-in fallback rules included)

### Local Development

**1. Backend:**
```bash
cd backend
pip install -r requirements.txt
python app.py
```

**2. Frontend:**
```bash
cd frontend
npm install
npm run dev
```

**3. Agent:**
```bash
cd agent
pip install psutil requests
python agent.py --key <YOUR_API_KEY>
```

### Docker (Full Stack)
```bash
docker compose up --build
```
This starts:
- Flask backend (port 5000) with Trivy pre-installed
- MongoDB (port 27017)
- OPA Policy Agent (port 8181)

---

## ⚙️ Environment Variables

### Backend (Render / Docker)
| Variable | Required | Description |
|---|---|---|
| `AGENT_KEYS` | ✅ | Comma-separated API keys for agents |
| `ALLOWED_ORIGINS` | ✅ | Comma-separated allowed CORS origins |
| `MONGODB_URI` | Optional | MongoDB connection string |
| `OPENAI_API_KEY` | Optional | For AI risk analysis (GPT-4o-mini) |
| `OPENAI_MODEL` | Optional | Defaults to `gpt-4o-mini` |
| `OPA_SERVER_URL` | Optional | OPA server URL (default: `http://localhost:8181`) |
| `AWS_ACCESS_KEY_ID` | Optional | For live AWS cloud scanning |
| `AWS_SECRET_ACCESS_KEY` | Optional | For live AWS cloud scanning |
| `SMTP_HOST` | Optional | SMTP server for email alerts |
| `SMTP_PORT` | Optional | SMTP port (default: 587) |
| `SMTP_USER` | Optional | SMTP login username |
| `SMTP_PASS` | Optional | SMTP login password |
| `ALERT_EMAIL` | Optional | Recipient email for critical alerts |
| `MONITOR_IMAGES` | Optional | Comma-separated Docker images for scheduled scans |

### Agent
| Variable | Description |
|---|---|
| `CLOUDSHIELD_API_URL` | Backend URL (default: Render URL) |

---

## 🌐 API Reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/scan` | Full pipeline scan (uses live agent data) |
| `POST` | `/api/demo` | Before/After demonstration scan |
| `POST` | `/api/scan/container` | Scan a Docker image with Trivy |
| `POST` | `/api/scan/cloud` | Evaluate cloud config JSON via OPA |
| `POST` | `/api/scan/aws` | Live AWS environment scan via boto3 |
| `POST` | `/api/analyze/risk` | AI-powered risk analysis |
| `POST` | `/api/report/unified` | Full unified security report |
| `POST` | `/api/agent-scan` | Agent telemetry receiver (primary) |
| `POST` | `/api/agent/report` | Agent telemetry receiver (extended + Docker) |
| `GET`  | `/api/alerts` | Get recent system alerts |
| `GET`  | `/api/risk/score` | Get global aggregated risk score (0–100) |
| `GET`  | `/api/db/health` | Database connection status |
| `GET`  | `/api/fleet` | All connected agent fleet status |
| `GET`  | `/api/security-metrics` | Aggregated metrics |

### Request Example — Container Scan
```bash
curl -X POST https://your-backend.onrender.com/api/scan/container \
  -H "Content-Type: application/json" \
  -d '{"image": "nginx:latest"}'
```

### Request Example — AWS Cloud Scan
```bash
# With local AWS credentials configured:
curl -X POST https://your-backend.onrender.com/api/scan/aws
```

---

## 🔐 Security Architecture

### HMAC-SHA256 Agent Signing
Every agent payload is signed with a 5-part HMAC:
```
HMAC = SHA256(METHOD + \n + PATH + \n + TIMESTAMP + \n + NONCE + \n + BODY)
```
- Replay attack protection via nonce + timestamp validation
- Per-agent API key identity
- Mutual validation on every request

### Risk Scoring Formula
```
Risk Score (0-100) =
  (CVSS Severity Score  × 0.50) +
  (Cloud Exposure Score × 0.30) +
  (Compliance Impact    × 0.20)

Labels: CRITICAL ≥85 | HIGH ≥70 | MEDIUM ≥40 | LOW <40
```

---

## 🗂️ Project Structure

```
cloudshield/
├── backend/
│   ├── app.py                  # Main Flask API
│   ├── risk_engine.py          # 0-100 risk scoring engine
│   ├── correlation.py          # Cross-stream finding correlator
│   ├── policy_engine.py        # Built-in cloud policy evaluator
│   ├── compliance.py           # Compliance mapping
│   ├── requirements.txt
│   └── services/
│       ├── aws_service.py      # Live AWS S3/IAM/EC2 scanning
│       ├── trivy_service.py    # Container image vulnerability scanning
│       ├── opa_service.py      # Policy evaluation (OPA + Python fallback)
│       ├── ai_service.py       # AI risk analysis (OpenAI + deterministic)
│       ├── correlation_service.py  # Advanced cross-stream correlator
│       ├── compliance_service.py   # CIS/NIST/ISO/HIPAA mapping
│       ├── scheduler_service.py    # Automated 6-hour periodic scans
│       ├── alert_service.py        # Email/console alert system
│       └── db_service.py           # MongoDB persistence layer
├── frontend/
│   ├── index.html              # Dashboard HTML
│   └── src/
│       ├── dashboard.js        # Full dashboard logic
│       └── style.css           # Dark glassmorphism UI
├── agent/
│   ├── agent.py                # EDR agent (telemetry + Trivy + Docker)
│   └── start_agent.bat         # Windows launcher
├── policies/
│   └── cloudshield.rego        # OPA Rego policies (S3/IAM/SG/ECS/RDS/VPC)
├── Dockerfile                  # Backend container with Trivy bundled
├── docker-compose.yml          # Full stack: Flask + MongoDB + OPA
└── README.md
```

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit: `git commit -m "feat: add my feature"`
4. Push: `git push origin feature/my-feature`
5. Open a Pull Request on GitHub

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

*Built with ❤️ for real-world cloud security operations.*

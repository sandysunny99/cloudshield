# CloudShield 🛡️

**AI-Powered Multi-Cloud Security Analysis Platform**

[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Status](https://img.shields.io/badge/status-Production%20Ready-success)]()
[![Backend](https://img.shields.io/badge/backend-Render-purple)]()
[![Frontend](https://img.shields.io/badge/frontend-Vercel-black)]()
[![Python](https://img.shields.io/badge/python-3.12-blue)]()

CloudShield is a production-grade, enterprise-ready DevSecOps platform integrating Endpoint Detection & Response (EDR), Cloud Security Posture Management (CSPM), and container vulnerability scanning into a single, real-time interface. It combines deterministic security policy engines with optional AI risk synthesis to translate complex security signals into actionable intelligence.

> 🚀 **Live Demo:**
> - Frontend: https://cloudshield-vtah.vercel.app
> - Backend API: https://cloudshield-tya3.onrender.com

---

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Setup Instructions](#-setup-instructions)
- [Environment Variables](#-environment-variables)
- [API Endpoints](#-api-endpoints)
- [Demo Flow](#-demo-flow)
- [Project Structure](#-project-structure)
- [Technology Stack](#-technology-stack)
- [Fault Tolerance](#-fault-tolerance)

---

## 🌟 Features

| Feature | Description |
|---------|-------------|
| 🐳 **Container Vulnerability Scanner** | Trivy-powered CVE detection with demo-mode fallback for PAAS environments |
| ☁️ **Cloud Misconfiguration Detection** | OPA policy evaluation + deterministic Python fallback across AWS/GCP/Azure configs |
| 🔍 **Multi-Cloud Storage Security Check** | Live HTTPS probing of S3, Azure Blob, and GCP Storage buckets for public exposure |
| 🧠 **AI Risk Analysis** | GPT-4 synthesis of cross-layer findings with rule-based fallback |
| 📡 **EDR Agent Telemetry** | HMAC-SHA256 signed real-time host monitoring with fleet dashboard |
| 📊 **Risk Scoring** | 0–100 weighted score (CVSS 50% + Cloud Exposure 30% + Compliance 20%) |
| ✅ **Compliance Mapping** | Auto-maps findings to CIS v8, NIST 800-53, ISO 27001, HIPAA |
| 🛡️ **Never Falter Design** | Every endpoint returns valid JSON — zero HTTP 500 errors under any failure |

---

## 🏗️ Architecture

```
User → Frontend (Vercel) → Backend API (Render)
                                │
              ┌─────────────────┼──────────────────┐
              │                 │                  │
           Trivy             OPA/Policy        Storage
           Scanner            Engine            Check
              │                 │                  │
         [Fallback]        [Fallback]         [HTTP Probe]
         Demo CVEs       Python Evaluator    AWS/Azure/GCP
              │                 │                  │
              └─────────────────┴──────────────────┘
                                │
                         AI Risk Engine
                          (GPT-4 / Fallback)
                                │
                         SOC Dashboard + Alerts
```

For the full Mermaid diagram and component breakdown, see [docs/architecture.md](docs/architecture.md).

---

## 🚀 Setup Instructions

### Prerequisites
- Python 3.12+
- Node.js 18+
- Git

### Option 1: Local Development

```bash
# 1. Clone the repository
git clone https://github.com/sandysunny99/cloudshield.git
cd cloudshield

# 2. Backend setup
cd backend
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Linux/macOS
pip install -r requirements.txt

# 3. Configure environment
cp ../.env.example .env
# Edit .env and add your API keys

# 4. Run backend
python wsgi.py

# 5. In a new terminal — Frontend setup
cd ../frontend
npm install
npm run dev
```

Dashboard will be available at `http://localhost:5173`.

### Option 2: Docker Compose

```bash
docker compose up --build -d
```

The backend binds to `:5001` and the frontend to `:5173`.

---

## 🔑 Environment Variables

Copy `.env.example` to `backend/.env` and fill in your values:

| Variable | Required | Description |
|----------|----------|-------------|
| `AGENT_KEYS` | **Yes** | Comma-separated HMAC keys for EDR agents |
| `ALLOWED_ORIGINS` | **Yes** | CORS-allowed frontend origins |
| `OPENAI_API_KEY` | No | GPT-4 key — falls back to rule engine if absent |
| `MONGODB_URI` | No | Persistent storage — falls back to in-memory |
| `AWS_ACCESS_KEY_ID` | No | Live AWS scans — falls back to demo mode |
| `AWS_SECRET_ACCESS_KEY` | No | Live AWS scans |
| `AZURE_STORAGE_CONNECTION_STRING` | No | Live Azure scans |
| `GCP_CREDENTIALS_JSON` | No | Live GCP scans (JSON string) |
| `SMTP_USER` | No | Email SOC alerts |
| `SMTP_PASS` | No | Email SOC alerts |

> ⚠️ **Never commit your `.env` file.** It is listed in `.gitignore`.

---

## 📡 API Endpoints

### Security Scanning
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scan/container` | Container image CVE scan |
| `POST` | `/api/scan/cloud` | Cloud config misconfiguration evaluation |
| `POST` | `/api/storage/check` | Multi-cloud bucket exposure check |
| `POST` | `/api/analyze/risk` | AI risk narrative synthesis |
| `POST` | `/api/report/unified` | Full compound security report |
| `POST` | `/api/scan/aws` | Live AWS infrastructure discovery |

### EDR / Fleet
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/agent-scan` | HMAC-signed telemetry receiver |
| `GET`  | `/api/agent-status` | Fleet health and telemetry |
| `GET`  | `/api/security-metrics` | Aggregated attack metrics |
| `GET`  | `/api/soc-timeline` | Real-time SOC event stream |
| `GET`  | `/api/risk/score` | Global 0–100 infrastructure risk score |

### Utility
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/api/download-agent` | Download pre-compiled EDR agent |
| `GET`  | `/api/agent-keys` | Agent API key and deployment info |
| `GET`  | `/api/db/health` | Database connectivity status |

---

## 🎥 Demo Flow

Follow this sequence for a complete stakeholder demonstration:

**Step 1 — Container Threat Detection**
- Navigate to the **Container Scanner** panel
- Enter `nginx:1.14.0` and click **Scan**
- Observe CVE cards populated with CRITICAL and HIGH severity findings
- AI Risk summary auto-generates in the risk panel

**Step 2 — Cloud Misconfiguration**
- Navigate to the **Cloud Config** panel
- Paste the following vulnerable configuration:
```json
{
  "s3_buckets": [{"public": true, "encryption": false}],
  "iam_roles": [{"policy": "*:*"}],
  "security_groups": [{"inbound": [{"port": 22}, {"port": 80}]}]
}
```
- Click **Analyze** — observe ≥4 violations detected and mapped to the alert board

**Step 3 — Storage Exposure Check**
- Navigate to **Storage Security**
- Select **AWS** and enter `commoncrawl`
- Observe `🔴 PUBLIC` badge and AI risk analysis triggered

**Step 4 — EDR Live Monitoring**
- Click **Deploy Agent** to download the agent binary
- Run it locally: `.\cloudshield-agent.exe --key default-agent-key-123`
- Watch the Fleet Dashboard populate with real-time host telemetry

**Step 5 — Risk Aggregation**
- The global Risk Dial now reflects cross-layer findings
- Export a unified JSON security report from the top toolbar

---

## 📁 Project Structure

```
cloudshield/
├── agent/                    # EDR agent source + compiled binary
│   ├── agent.py
│   └── build/
├── backend/                  # Flask API
│   ├── app.py                # Route definitions + endpoint logic
│   ├── main.py               # Scan pipeline orchestrator
│   ├── scanner.py            # Trivy output parser
│   ├── policy_engine.py      # Cloud config evaluator
│   ├── risk_engine.py        # Weighted risk scoring
│   ├── correlation.py        # Cross-layer finding correlation
│   ├── remediation.py        # Fix recommendations generator
│   ├── compliance.py         # CIS/NIST/ISO/HIPAA mapper
│   ├── services/
│   │   ├── trivy_service.py  # Container scanner + demo fallback
│   │   ├── opa_service.py    # OPA engine + built-in fallback
│   │   ├── storage_service.py # Multi-cloud storage prober
│   │   ├── ai_service.py     # GPT-4 + rule-based AI engine
│   │   └── aws_service.py    # Live AWS boto3 scanner
│   ├── requirements.txt
│   └── wsgi.py
├── frontend/                 # Vite SPA dashboard
│   ├── index.html
│   └── src/
│       └── dashboard.js
├── docs/                     # Technical documentation
│   ├── architecture.md
│   ├── project_documentation.md
│   └── DOCUMENTATION.md
├── policies/                 # OPA Rego policy files
├── docker-compose.yml
├── .env.example
└── README.md
```

---

## 🛠️ Technology Stack

| Layer | Technology |
|-------|-----------|
| Backend Language | Python 3.12 |
| Web Framework | Flask 3.0 |
| WSGI Server | Gunicorn |
| Container Scanner | Trivy (Aqua Security) |
| Policy Engine | OPA (Open Policy Agent) |
| AI | OpenAI GPT-4 API |
| AWS SDK | boto3 |
| Azure SDK | azure-storage-blob |
| GCP SDK | google-cloud-storage |
| Frontend Build | Vite |
| Charts | Chart.js |
| Agent Packaging | PyInstaller |
| Database | MongoDB / in-memory |
| Rate Limiting | Flask-Limiter |
| Auth | HMAC-SHA256 |
| Backend Hosting | Render |
| Frontend Hosting | Vercel |

---

## 🛡️ Fault Tolerance

CloudShield enforces a **"Never Falter"** design principle:

- ✅ Trivy absent → Demo CVE payload auto-activates
- ✅ OPA unreachable → Python built-in evaluator takes over
- ✅ OpenAI API down → Rule-based narrative engine produces output
- ✅ MongoDB missing → In-memory arrays used transparently
- ✅ AWS credentials absent → Demo/mock responses with `demo: true` flag
- ✅ Network timeouts on storage check → Safe `public: false` response
- ✅ Any unhandled exception → Global `try/except` returns structured JSON, HTTP 200

**No endpoint returns HTTP 500 under any failure condition.**

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.

---

*Built by the CloudShield Open Source Team.*

# 🛡️ CloudShield — Unified Cloud Security & EDR Platform

CloudShield is a production-grade **DevSecOps** platform providing real-time **Endpoint Detection & Response (EDR)**, **Cloud Security Posture Management (CSPM)**, **Container Vulnerability Scanning**, and **Threat Hunting** — all from a single, unified dashboard.

Built with enterprise compliance in mind: **CIS Benchmarks**, **NIST 800-53**, **ISO 27001**, and **HIPAA** mapping are natively integrated.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   CloudShield Dashboard                  │
│         (Vite SPA — Vercel Production)                  │
├────────────┬────────────┬────────────┬──────────────────┤
│  SOC/SIEM  │   Cloud    │  Threat    │    Malware       │
│  Overview  │  Security  │  Hunting   │    Sandbox       │
│            │ ┌────────┐ │  (VQL)     │   (ANY.RUN)      │
│  Attack    │ │ CSPM   │ │            │                  │
│  Dashboard │ │ CtrVuln│ │            │                  │
│  Agents    │ │ S3 Aud │ │            │                  │
│            │ └────────┘ │            │                  │
└─────┬──────┴─────┬──────┴─────┬──────┴────────┬─────────┘
      │            │            │               │
      ▼            ▼            ▼               ▼
┌──────────────────────────────────────────────────────────┐
│              Flask API (Gunicorn — Render)                │
│  /api/scan/cloud  /api/scan/container  /api/hunt         │
│  /api/agent-scan  /api/check-storage   /api/analyze/risk │
│  /api/soc-timeline  /api/agent-status  /api/alerts       │
├──────────────────────────────────────────────────────────┤
│  SQLAlchemy (SQLite/Postgres)  │  Redis Pub/Sub         │
│  Correlation Engine            │  Rate Limiter           │
└──────────────────────────────────────────────────────────┘
      ▲                              ▲
      │ HMAC-signed telemetry        │ Trivy scan results
┌─────┴──────┐               ┌──────┴───────┐
│ EDR Agent  │               │ Trivy Server │
│ (Endpoint) │               │ (Container)  │
└────────────┘               └──────────────┘
```

---

## 🌟 Key Features

### ☁️ Cloud Security (Unified Panel)
- **Misconfiguration Scanner (CSPM)** — Analyze AWS/GCP/Azure configs against CIS policies with AI-powered remediation
- **Container Vulnerability Scanner** — Scan Docker/OCI images for CVEs using Trivy
- **S3 / Storage Audit** — Assess bucket ACLs, encryption status, and public exposure

### 🔬 SOC & Threat Intelligence
- **Threat Hunting (VQL)** — Advanced VQL syntax parser (e.g. `SELECT * FROM ... WHERE ...`) mapping over SQLite and OpenSearch.
- **Attack Dashboard** — Real-time WAF edge blocks and spoofing origin tracking.
- **SOC Event Stream** — Live security event log with severity-coded timeline.
- **Security Alerts** — Correlated alerts from agent telemetry and cloud scans.

### 💻 Endpoint Detection & Response
- **EDR Agent** — Lightweight Python agent with rich execution path anomaly detection.
- **HMAC-Signed Telemetry** — Cryptographically verified agent-to-backend communication.
- **Fleet Management** — Monitor all connected endpoints with health scoring.
- **Trivy Integration** — Background CVE scanning on agent hosts.

### ☢️ Malware Sandbox
- **Detonation Engine** — Analyze suspicious URLs, IPs, and file hashes
- **Process Tree Mapping** — Visualize execution chains
- **IOC Extraction** — Automatic indicator of compromise identification

---

## 🚀 Quick Start

### 1. Backend (Flask API)
```bash
cd backend
pip install -r requirements.txt
python app.py
```
> API available at `http://localhost:5000`

### 2. Frontend (Vite)
```bash
cd frontend
npm install
npm run dev
```
> Dashboard available at `http://localhost:5173`

### 3. EDR Agent
```bash
cd agent
pip install psutil requests
python cloudshield_agent.py
```
> Agent auto-connects to the production backend. Set `CLOUDSHIELD_API_URL` to override.

### 4. Full Agent (with HMAC + Trivy)
```powershell
cd agent
$env:CLOUDSHIELD_API_KEY = "default-agent-key-123"
python agent.py
```

---

## 🐳 Docker Compose

```bash
# Core services (API + Redis + Trivy)
docker-compose up

# Full SOC stack (OpenSearch + Wazuh + Suricata + Filebeat)
docker-compose --profile prod up
```

---

## 🔧 Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | SQLite fallback |
| `REDIS_URL` | Redis connection for pub/sub | `redis://localhost:6379` |
| `CLOUDSHIELD_API_URL` | Agent target API endpoint | `https://cloudshield-tya3.onrender.com/api/agent-scan` |
| `AGENT_KEYS` | Comma-separated trusted agent keys | `default-agent-key-123` |
| `CF_API_TOKEN` | Cloudflare API token for edge bans | — |
| `CF_ZONE_ID` | Cloudflare zone identifier | — |
| `OPENSEARCH_URL` | OpenSearch endpoint (prod profile) | `http://opensearch:9200` |

---

## 📡 API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/agent-scan` | HMAC-verified agent telemetry receiver |
| `POST` | `/api/scan/cloud` | Cloud misconfiguration policy scan |
| `POST` | `/api/scan/container` | Container image vulnerability scan |
| `POST` | `/api/check-storage` | S3/GCS bucket security audit |
| `POST` | `/api/hunt` | Threat hunting query execution |
| `POST` | `/api/analyze/risk` | AI-powered risk analysis |
| `GET`  | `/api/agent-status` | Connected agent fleet status |
| `GET`  | `/api/security-metrics` | WAF attack metrics |
| `GET`  | `/api/soc-timeline` | SOC event stream |
| `GET`  | `/api/alerts` | Security alerts feed |
| `GET`  | `/api/report/unified` | Full security posture report |

---

## 🏛️ Compliance Frameworks

All findings are automatically mapped to:
- **CIS Controls v8** — Center for Internet Security
- **NIST 800-53** — National Institute of Standards and Technology
- **ISO 27001** — International Organization for Standardization
- **HIPAA** — Health Insurance Portability and Accountability Act

---

## 📂 Project Structure

```
cloudshield/
├── backend/
│   ├── app.py                    # Flask API (all endpoints)
│   ├── requirements.txt          # Python dependencies
│   ├── services/
│   │   ├── correlation_engine.py # Event correlation & alerting
│   │   ├── opensearch_service.py # Threat hunt query engine
│   │   ├── sandbox_service.py    # Malware detonation
│   │   └── threat_intel_service.py
│   └── scripts/
│       └── init_opensearch_ilm.py
├── frontend/
│   ├── index.html                # Dashboard UI
│   ├── src/
│   │   ├── dashboard.js          # Core JS logic
│   │   └── style.css             # Design system
│   └── vite.config.js
├── agent/
│   ├── agent.py                  # Full EDR agent (HMAC + Trivy)
│   └── cloudshield_agent.py      # Lightweight process monitor
└── docker-compose.yml            # Full stack orchestration
```

---

## 🌐 Live Deployment & CI/CD

| Component | Architecture | URL |
|-----------|--------------|-----|
| **Dashboard** | `Vercel` (Serverless Edge) | [cloudshield-vtah.vercel.app](https://cloudshield-vtah.vercel.app) |
| **API** | `Render` (Gunicorn/Flask) | [cloudshield-tya3.onrender.com](https://cloudshield-tya3.onrender.com) |

> Note: A global `vercel.json` is included in the root directory to properly route GitHub push triggers into the `/frontend` directory. This ensures multiple hooked projects build successfully without path confusion.

---

## 📄 License

MIT License — See [LICENSE](./LICENSE) for details.

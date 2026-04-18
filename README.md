# CloudShield

CloudShield is a production-grade DevSecOps platform and SaaS Engine providing Zero-Trust Endpoint Detection & Response (EDR), Cloud Resource auditing, and intelligent web-application firewalls (WAF). 

## 🌟 Key Features
- **Endpoint Agent**: Standalone EDR loop utilizing Trivy container parsing and resource scraping logic payload generation.
- **SaaS Backend (Flask)**: Secure cryptographic receiver using HMAC hashes and anti-replay nonce tracking. Uses SQLAlchemy for permanent telemetry state storage (PostgreSQL).
- **Global Firewall Engine**: Interfaces with Edge Providers (Cloudflare) natively dropping traffic spoofing signatures globally instantly to defend infrastructure stability.
- **Web Dashboard**: An extreme cyber-aesthetic reactive portal written natively using fast modern Javascript built on top of Vite logic mapping over robust HTML/Vanill-CSS logic.

## 🚀 Setup & Execution

### 1. Backend (Flask API)
The backend dynamically falls back to an embedded SQLite database if running locally. To use Postgres, provide `DATABASE_URL`.

```bash
cd backend
pip install -r requirements.txt
python app.py
```
*Access API natively on `http://127.0.0.1:5000`*

### 2. Frontend (Vite)
```bash
cd frontend
npm install
npm run dev
```

### 3. Executing Telemetry Node Agent
Provide your explicit SaaS Edge identifier:
```bash
cd agent
$env:CLOUDSHIELD_API_KEY="default-agent-key-123"
$env:CLOUDSHIELD_API_URL="http://127.0.0.1:5000/api/agent-scan"
python agent.py
```
> [!NOTE]  
> If deployed via `.exe` natively lacking a shell, a GUI prompt will inherently catch and recover standard sys.stdin loss gracefully!

---

## 🔒 Configuration Variables

Copy `.env.example` -> `.env`
- `CLOUDSHIELD_API_URL`: Root path executing remote signals
- `AGENT_KEYS`: A comma-separated string mapping trusted signatures for backend.
- `DATABASE_URL`: Your Render/Heroku PSQL target URL.
- `CF_API_TOKEN` & `CF_ZONE_ID`: Authorizes edge ban propagation.

## 📡 Essential Endpoints
| HTTP | Path | Objective |
| ----------- | ----------- | ----------- |
| `POST` | `/api/agent-scan` | Receiver port enforcing HMAC logic accepting telemetry. |
| `GET` | `/api/dashboard-summary` | Bundled total aggregation. Capped below 100KB for Vite frontend. |
| `GET` | `/api/security-metrics` | Shows IP attack/ban rate thresholds. |

## 📚 Technical Documentation
Explore deep system architecture models below:
- [Technology Stack](./docs/stack.md)
- [Architecture & Flow Diagram](./docs/architecture.md)

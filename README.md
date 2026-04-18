# CloudShield 🛡️

**AI-Powered Multi-Cloud & Container Security Analysis Platform**

CloudShield is a production-grade DevSecOps platform integrating Endpoint Detection & Response (EDR), Cloud Security Posture Management (CSPM), and container vulnerability scanning into a single, real-time interface. It utilizes a "Never Falter" design principle with robust fallback mechanisms for all core services.

## 🚀 Features

- **🐳 Container Vulnerability Scanner**: Real-time CVE detection using Trivy CLI with simulated fallback.
- **☁️ Cloud Misconfiguration Detection**: Policy evaluation using OPA (Open Policy Agent) with a built-in Python rule engine fallback.
- **🔍 Multi-Cloud Storage Security Check**: Active HTTPS probing of S3, Azure Blob, and GCP Storage for public exposure.
- **🧠 AI Risk Analysis**: GPT-4 powered security narrative generation using OpenAI, with a deterministic rule-based fallback.
- **📡 EDR Agent Telemetry**: Real-time host monitoring (CPU, RAM, Filesystem) with HMAC-SHA256 signed reporting.
- **📊 Unified Risk Scoring**: Weighted risk calculation across container, cloud, and endpoint findings.
- **✅ Compliance Mapping**: Automated mapping of findings to CIS v8, NIST 800-53, ISO 27001, and HIPAA.

## 🛠️ Tech Stack

| Component | Technology | Version | Purpose |
|-----------|------------|---------|---------|
| **Backend** | Flask | 3.0+ | API & Logic Orchestration |
| **Frontend** | Vanilla JS / Vite | 5.0+ | Real-time Dashboard UI |
| **Database** | MongoDB | 4.6+ | Result Persistence (with In-Memory fallback) |
| **Policy Engine** | OPA | 1.0+ | Cloud Policy Evaluation (REST API) |
| **Scanner** | Trivy | Latest | Container & FS Vulnerability Scanning |
| **AI Engine** | OpenAI | GPT-4o-mini | Risk Synthesis & Remediation Logic |

## 📋 Prerequisites

- **Python**: 3.12+
- **Node.js**: 18+
- **Docker**: Required for MongoDB and OPA (optional if using fallback mode)
- **Trivy CLI**: Required for live container scans

## 🔧 Installation

```bash
# 1. Clone the repository
git clone https://github.com/sandysunny99/cloudshield.git
cd cloudshield

# 2. Backend Setup
cd backend
python -m venv venv
source venv/bin/activate  # venv\Scripts\activate on Windows
pip install -r requirements.txt

# 3. Frontend Setup
cd ../frontend
npm install
```

## 🏃 Running the Application

### Option 1: Local Development (Manual)
1. **Start Backend**:
   ```bash
   cd backend
   python app.py  # Runs on http://localhost:5000
   ```
2. **Start Frontend**:
   ```bash
   cd frontend
   npm run dev    # Runs on http://localhost:5173
   ```

### Option 2: Docker Compose
```bash
docker compose up --build -d
```
*Services: Backend (:5000), MongoDB (:27017), OPA (:8181)*

## 📁 Project Structure

```text
cloudshield/
├── agent/            # EDR implementation (telemetry reporting)
├── backend/          # Flask API and Security Services
│   ├── services/     # Core logic (AI, OPA, Trivy, DB)
│   └── app.py        # API routing
├── frontend/         # Vite Dashboard (HTML/JS/CSS)
├── policies/         # Rego policy files for OPA
└── docker-compose.yml
```

## 🔌 API Endpoints

- `POST /api/scan/container`: Trigger Trivy image scan.
- `POST /api/scan/cloud`: Evaluate cloud config JSON.
- `POST /api/agent-scan`: Endpoint for EDR agent telemetry.
- `GET  /api/agent-status`: Retrieve fleet health status.
- `GET  /api/risk/score`: Unified infrastructure risk score.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

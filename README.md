# CloudShield 🛡️

**AI-Augmented Unified Cloud & Container Security Platform**

CloudShield is a production-grade, enterprise-ready DevSecOps platform integrating Endpoint Detection & Response (EDR), Cloud Security Posture Management (CSPM), and container vulnerability scanning into a single, real-time interface. By combining deterministic policy evaluation with optional Large Language Model (LLM) risk analysis, CloudShield translates complex system alerts into actionable, explainable security intelligence.

![License](https://img.shields.io/badge/license-MIT-blue) ![Status](https://img.shields.io/badge/status-Production%20Ready-success) ![Build](https://img.shields.io/badge/tests-30%2F30%20passed-brightgreen)

---

## 🌟 Key Features

*   🐳 **Container Scanning (Trivy):** Deep filesystem and OS-level vulnerability checking. Generates deterministic CVE alerts with required fix versions and severity mappings.
*   ☁️ **Cloud Scanning (AWS + OPA):** Live AWS telemetry (`boto3`) natively fetching active components (S3, IAM, EC2) and enforcing predefined security posture rules via an Open Policy Agent (OPA) compatibility layer.
*   🧠 **AI Risk Analysis:** Integrates OpenAI GPT-4 models to synthesize disparate threat streams into human-readable executive summaries, mapping attack vectors across the kill chain. (Fully functional via deterministic fallback if AI is disabled).
*   📊 **Risk Scoring & Alerts:** Computes a strict 0-100 weighted risk score based on CVSS (50%), Cloud Exposure (30%), and Compliance Impact (20%). Triggers real-time email SOC alerts.
*   ✅ **Compliance Mapping:** Auto-maps runtime findings to major compliance benchmarks: **CIS Controls v8**, **NIST 800-53**, **ISO 27001**, and **HIPAA**.

---

## 🏗️ Architecture Overview

The system strictly decouples the data ingestion layer from the rules engine and display layer.

*   **Endpoint Sensors:** Python-based Edge Agents running on target hosts collecting `docker` container data, CPU strain, and open ports. Payloads are heavily guarded with a 5-part **HMAC-SHA256 signature** to prevent replay attacks.
*   **Security API:** A robust Flask 3.0 API wrapped with Cloudflare auto-ban integration, multi-threaded request handlers, and native rate limiting.
*   **Correlation Engine:** Merges discrete container vulnerabilities with cloud policy violations to infer lateral movement risks (e.g., *Critical container CVE + Open IAM Port = High Correlation Score*). 

For a complete deep-dive, read the [Architecture Document](docs/architecture.md).

---

## 🚀 Setup Guide

### Option 1: Local Development (Source)

**Prerequisites:** Python 3.12+ and Node.js 18+.

1. **Clone the repository:**
   ```bash
   git clone https://github.com/sandysunny99/cloudshield.git
   cd cloudshield
   ```
2. **Setup Backend:**
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```
3. **Configure Environment:**
   Create a `.env` file in the `backend/` directory (see Environment Variables below).
4. **Run Backend:**
   ```bash
   python wsgi.py
   ```
5. **Start Frontend:**
   ```bash
   cd ../frontend
   npm install
   npm run dev
   ```

### Option 2: Docker Compose (Production)

The entire platform is containerized for zero-dependency deployments.
```bash
docker compose up --build -d
```
The API will bind to `:5001` and the dashboard to `:5173`.

### Environment Variables (.env)

| Variable | Description | Required | Default / Fallback |
| :--- | :--- | :--- | :--- |
| `ALLOWED_ORIGINS` | CORS domains | Yes | `http://localhost:5173` |
| `AGENT_KEYS` | Comma-separated EDR auth keys | Yes | *None* |
| `OPENAI_API_KEY` | GPT key for risk analysis | No | Deterministic engine |
| `MONGODB_URI` | Persistent scan metrics store | No | In-memory arrays |
| `AWS_ACCESS_KEY_ID` | AWS ID for live cloud scans | No | Static JSON overrides |

*(Note: Never commit your `.env` file to version control).*

---

## 📡 API Documentation

CloudShield exposes 14 strictly validated endpoints.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| **POST** | `/api/scan/container` | Trivy image scan returning CVSS severities. |
| **POST** | `/api/scan/cloud` | OPA policy evaluation against provided or live cloud JSON. |
| **POST** | `/api/analyze/risk` | AI/rule-based synthesis of findings into human summaries. |
| **POST** | `/api/report/unified` | Ultimate compound report merging Trivy, OPA, and AI factors. |
| **POST** | `/api/agent-scan` | HMAC-SHA256 telemetry receiver for EDR agents. |
| **POST** | `/api/scan/aws` | Explicit trigger forcing a live local AWS discovery pass. |
| **GET** | `/api/risk/score` | Retrieves the 0-100 global infrastructure score. |
| **GET** | `/api/db/health` | Diagnostic check reporting MongoDB vs In-Memory status. |

---

## 🎥 Demo Flow (Step-by-Step)

If demonstrating the system for stakeholders, follow this ideal flow to display the full capability set:

1. **Start System:** Launch backend and frontend. The risk dial on the global dashboard will read `0 / LOW`.
2. **Container Breach:** Inject a vulnerable image payload (e.g. `nginx:1.14.0`) via the Container Scanning module. Watch Trivy populate Critical CVEs.
3. **Cloud Misconfig:** Trigger a Cloud Posture Scan against an AWS environment featuring a Public S3 Bucket and open Port 22 Security Group.
4. **AI Synthesis:** Trigger the AI Correlation step. Show how the engine synthesizes the Container RCE from Step 2 with the open SSH port from Step 3 to escalate the global threat dial.
5. **Agent Deployment:** Expand the `/api/download-agent` modal and launch the Edge Python `.exe` locally. Verify telemetry streams updating the host node graph.

---

## 🔮 Future Work

- **Multi-Cloud Integrations:** Expanding live `boto3` posture evaluation parity to `azure-core` and Google Cloud SDKs.
- **Enterprise SSO:** Introducing SAML/OIDC wrappers around the React interface.
- **Self-Healing:** Enabling local agents to auto-patch iptables drops on active threat detection without polling the SOC.

---
*Maintained by the CloudShield Open Source Team.*

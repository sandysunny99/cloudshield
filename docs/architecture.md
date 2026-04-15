# CloudShield Technical Architecture

This document serves as the high-level technical reference and data flow mapping for the CloudShield platform.

---

## 🏗️ System Overview

CloudShield is fundamentally a **micro-service orchestrated orchestration layer**. Rather than building vulnerability scanners from scratch, the platform unifies best-in-class open-source binaries (Trivy), policy mechanisms (OPA), and LLM heuristics into a single API surface and deterministic correlation engine.

The platform is divided into three physical tiers:
1. **Edge Sensoring:** Disconnected or containerized agents reporting host health.
2. **Platform Gateway (Backend):** The stateless Flask aggregation layer that invokes modules based on the scan context.
3. **Intelligence Dashboards:** React-based UI consuming aggregate findings.

---

## 🧩 Component Breakdown

### 1. Agent (`agent/agent.py`)
A standalone Python executable that can be distributed as a `.exe` via PyInstaller.
*   **Responsibility:** Periodically queries host telemetry (CPU, RAM, Open Ports, running Docker containers).
*   **Mechanics:** Uses the local `docker` CLI or `psutil` libraries. 
*   **Security:** Cryptographically signs every POST request to the backend with an HMAC-SHA256 hash preventing replay and spoofing attacks.

### 2. Backend API Services (`backend/app.py` & `backend/services/`)
The traffic control center for all data streams. The core services are heavily decoupled:
*   `trivy_service`: Handles subprocess calls to system-installed Trivy instances. **Wrapped in a strict `try/except` engine**, any subprocess timeouts or missing binaries cleanly cascade into an exact structural mock-data array rather than blocking the UI, guaranteeing a "Never Falter" demo state.
*   `aws_service`: Direct IAM integrations via `boto3`. Automatically intercepts `0.0.0.0/0` ingress rules and public S3 ACLs.
*   `opa_service`: Native Rego wrapper coupled directly with a **deterministic Python fallback evaluator (`_evaluate_builtin`)**. Bypasses internal OPA crashes ensuring robust reporting directly to `json.violations`.
*   `ai_service`: Bridges payload events into OpenAI prompts via `dashboard.js` pipelines natively injecting unified violations, falling back to cached or deterministic proxy rules if upstream models are unavailable.
*   `db_service`: Handles fast disk persistence (MongoDB) or pure in-memory mode depending entirely on environment states.

### 3. Database
*   **Protocol:** MongoDB collections (`vulnerabilities`, `cloud_findings`, `risk_reports`, `agent_reports`).
*   **Performance:** Uses descending time series `ts` indexes for fast snapshot pagination.

### 4. Dashboards (Frontend)
*   **Technology Stack:** Javascript / React ecosystem (Vite server).
*   **Polling:** Background auto-fetch mechanics on `15000ms` intervals to query the `/api/risk/score` and display visual alert modals for administrators without requiring F5 refreshes.

---

## 🔄 End-to-End Data Flow

The following describes the exact technical path of the **Unified Report Lifecycle**:

1.  **Ingestion:** The user triggers a request against `/api/report/unified` containing a target container image and hypothetical cloud structure payload.
2.  **Parallel Execution:** 
    *   The `Trivy` process spawns silently in the OS, streaming live vulnerability structures back to `/services/`.
    *   The `OPA` service evaluates the JSON config matching structural anomalies.
3.  **Correlation Fusion:** The `correlate_all()` engine mathematically evaluates overlapping tags between the two discrete parallel tasks.
4.  **AI Invocation:** The reduced list of core findings is synthesized into natural language steps.
5.  **Compliance Cross-walk:** Native findings are hard-mapped to CIS, NIST 800-53, ISO-27001, and HIPAA definitions.
6.  **Persistence:** The final monolithic artifact is committed to the local `db_service` and cache memory.
7.  **Delivery:** Clean JSON is parsed synchronously back to the requesting dashboard.

---

## 🔐 Security Model & Trust Boundaries

*   **API Origin Lock:** `ALLOWED_ORIGINS` prevents global CORS scraping out of the box.
*   **Anti-Spoofing:** Flask-Limiter inherently drops connection attempts exceeding typical usage bounds. Any malformed HMAC payload on the `/api/agent-scan` route permanently auto-blocks the requesting Origin IP.
*   **Graceful Degradation:** CloudShield **never stops evaluating**. If AI fails, it generates offline models. If Auth fails, it runs in-memory arrays. If Trivy isn't installed, it evaluates the Cloud arrays instead of crashing.

---

### 5. Deployment Model

Due to internal subprocess executions (Trivy), specific CI/CD setups are required. 
*   **PAAS (Render/Vercel):** The system fully supports stateless native deployments. Render instances that cannot utilize native APT-get Trivy installations will seamlessly activate the internal **Demo Fallback Engines**, enabling successful E2E risk correlation without localized binaries.
*   **Containerized (Docker):** By binding custom binaries inside the Docker context via `docker compose up --build`, we entirely decouple CloudShield's capabilities from the limitations of the host architecture for full production scanning capabilities.

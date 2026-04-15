# CloudShield — Full Project Documentation

> Version 3.0 | IEEE-Format Technical Report | April 2026

---

## 1. Introduction

CloudShield is a production-grade, AI‑augmented unified cloud and container security platform. It consolidates three historically siloed security disciplines — Endpoint Detection & Response (EDR), Cloud Security Posture Management (CSPM), and Container Vulnerability Scanning — into a single, real‑time SaaS interface. By pairing deterministic policy engines with optional Large Language Model (LLM) risk synthesis, CloudShield translates noisy security events into explainable, actionable intelligence for security operations center (SOC) teams.

The platform is deployed as a cloud‑native service: the backend runs on Render (Flask / Python 3.12), the frontend is served via Vercel (Vanilla JS + Vite), and edge sensors (EDR agents) are distributed as self‑contained `.exe` binaries compiled with PyInstaller.

---

## 2. Problem Statement

Modern cloud environments generate thousands of discrete security signals daily. Existing tools address individual layers (vulnerability scanners, CSPM products, SIEM dashboards) but rarely correlate findings across boundaries. This creates three compounding problems:

1. **Alert fatigue** — analysts receive raw CVE lists without cross-layer context.
2. **Blind spots** — a critical container CVE combined with an open IAM policy represents systemic risk that single-layer tools miss entirely.
3. **Demo/production gap** — research platforms frequently crash in live environments due to missing binaries (Trivy, OPA) or absent cloud credentials, undermining stakeholder confidence.

CloudShield directly addresses all three challenges.

---

## 3. Objectives

| # | Objective |
|---|-----------|
| 1 | Detect container-level CVEs via Trivy with a resilient mock-data fallback for environments lacking the binary. |
| 2 | Evaluate cloud configuration posture (AWS/Azure/GCP) using an OPA policy engine with a deterministic Python fallback. |
| 3 | Check cloud storage bucket public exposure across AWS S3, Azure Blob, and GCP Cloud Storage. |
| 4 | Synthesize cross-layer findings into a unified AI risk narrative using OpenAI GPT-4 (with a rule-based fallback). |
| 5 | Stream real-time endpoint telemetry from distributed EDR agents over HMAC-SHA256 authenticated channels. |
| 6 | Map findings to compliance benchmarks: CIS Controls v8, NIST 800-53, ISO 27001, HIPAA. |
| 7 | Never crash. Every API endpoint returns valid JSON under all failure conditions. |

---

## 4. System Overview

CloudShield is structured as a three-tier micro-service orchestration platform:

```
┌──────────────────────────────────────────────────────────────────────┐
│                        CLOUDSHIELD PLATFORM                           │
├─────────────────┬──────────────────────┬────────────────────────────┤
│   TIER 1        │   TIER 2             │   TIER 3                   │
│   Edge Agents   │   Platform Gateway   │   Intelligence Dashboard   │
│                 │                      │                            │
│  • Python EDR   │  • Flask REST API    │  • Vanilla JS + Vite       │
│  • Trivy scans  │  • OPA / Fallback    │  • SOC Timeline            │
│  • HMAC signed  │  • Trivy / Fallback  │  • Risk Dial               │
│  • psutil data  │  • AI Synthesis      │  • Alert Board             │
│  • 30s polling  │  • Compliance Maps   │  • Fleet Dashboard         │
└─────────────────┴──────────────────────┴────────────────────────────┘
```

---

## 5. Features

### 5.1 Container Vulnerability Scanner

**Endpoint:** `POST /api/scan/container`

The container scanner accepts a Docker image name and invokes the Trivy CLI as a subprocess. On PAAS environments where Trivy is unavailable (e.g. Render free tier), a structured mock-data fallback activates automatically, returning representative CVE data (`CVE-2024-*` entries across CRITICAL / HIGH / MEDIUM severities) so the entire downstream pipeline — AI synthesis, risk scoring, compliance mapping — remains fully functional.

**Resilience design:**
```python
try:
    result = subprocess.run(["trivy", "image", image, ...], ...)
    return parse(result)
except FileNotFoundError:
    return DEMO_CVE_PAYLOAD  # structured mock, never HTTP 500
```

### 5.2 Cloud Misconfiguration Detection

**Endpoint:** `POST /api/scan/cloud`

Accepts a raw JSON cloud configuration (AWS/GCP/Azure resource definitions) and evaluates it against security policy rules. The primary engine is an OPA (Open Policy Agent) REST integration; if OPA is unreachable, the system automatically delegates to `_evaluate_builtin()` — a deterministic Python fallback implementing the same rule logic:

- S3 bucket public access
- S3 encryption disabled
- IAM wildcard permissions (`*:*`)
- Security Group open ingress (port 22, 80 from `0.0.0.0/0`)
- Multi-factor authentication disabled

**Response schema:**
```json
{
  "violations": [
    {
      "id": "CS-POLICY-001",
      "severity": "CRITICAL",
      "title": "S3 bucket is public",
      "message": "S3 bucket is public",
      "resource": "unnamed"
    }
  ]
}
```

### 5.3 Multi-Cloud Storage Security Check

**Endpoint:** `POST /api/storage/check`

Performs live HTTP exposure checking for cloud storage buckets across three providers:

| Provider | URL pattern checked |
|----------|---------------------|
| AWS S3  | `https://{bucket}.s3.amazonaws.com` |
| Azure Blob | `https://{bucket}.blob.core.windows.net` |
| GCP Storage | `https://storage.googleapis.com/{bucket}` |

A curated set of known-public buckets activates an immediate demo-mode response (e.g. `commoncrawl`, `gcp-public-data-landsat`) for reliable stakeholder demonstrations. All HTTP calls use `timeout=5`, `allow_redirects=True`, and granular exception handling for `ConnectionError`, `Timeout`, and generic `RequestException`.

### 5.4 AI Risk Analysis Engine

**Endpoint:** `POST /api/analyze/risk`

Accepts an array of findings (from container scans, cloud scans, or storage checks) and synthesizes a human-readable executive risk narrative. When `OPENAI_API_KEY` is configured, the engine invokes GPT-4. If the key is absent or the API is unreachable, a deterministic rule-based narrative generator produces structured output using severity counts, finding types, and remediation priorities — ensuring the pipeline is never blocked by AI availability.

### 5.5 EDR Agent & Fleet Telemetry

**Endpoint:** `POST /api/agent-scan`

Python-based edge agents run on monitored endpoints, collecting:
- CPU and RAM utilisation (psutil)
- Listening ports (psutil)
- Container CVEs (Trivy, every 20 minutes)
- Active processes (top 10 by CPU)

Every telemetry payload is cryptographically signed using HMAC-SHA256:
```
signature = HMAC-SHA256(
    "POST\n/api/agent-scan\n{timestamp}\n{nonce}\n{body}"
)
```
The backend verifies signatures against a multi-key allowlist, enabling zero-downtime key rotation. Replay attacks are prevented by a 120-second nonce cache.

---

## 6. Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Backend | Python 3.12, Flask 3.0 | REST API, business logic |
| Rate Limiting | Flask-Limiter | Per-IP rate control |
| Scanning | Trivy (Aqua Security) | Container CVE detection |
| Policy Engine | OPA (Open Policy Agent) | Cloud configuration evaluation |
| AI | OpenAI GPT-4 API | Risk narrative synthesis |
| Multi-Cloud SDKs | boto3, azure-storage-blob, google-cloud-storage | Live cloud resource queries |
| Frontend | Vanilla JS, Vite, Chart.js | SPA dashboard |
| Agent | Python + PyInstaller | Standalone EDR binary |
| Storage | MongoDB (optional) / in-memory | Scan result persistence |
| Deployment | Render (backend), Vercel (frontend) | Cloud PaaS hosting |
| Auth | HMAC-SHA256 | Agent payload signing |
| Security | CORS allowlisting, Flask-Limiter | API hardening |

---

## 7. Workflow Explanation

### 7.1 Container Scan Flow

```
User submits image name (e.g. "nginx:latest")
      ↓
POST /api/scan/container
      ↓
trivy_service.py → subprocess("trivy image nginx:latest")
      ↓ (if Trivy missing)
Demo fallback → structured CVE JSON
      ↓
risk_engine.py → weighted score (CVSS 50% + exposure 30% + compliance 20%)
      ↓
ai_service.py → executive risk narrative
      ↓
compliance.py → CIS / NIST / ISO / HIPAA mapping
      ↓
Frontend renders: Alert Board + SOC Timeline + Risk Dial
```

### 7.2 Cloud Misconfiguration Flow

```
User pastes cloud config JSON
      ↓
POST /api/scan/cloud
      ↓
opa_service.py → OPA REST call
      ↓ (if OPA unreachable)
_evaluate_builtin() → deterministic Python rules
      ↓
{"violations": [...]} returned
      ↓
dashboard.js → renderAlerts(violations) + runAIAnalysis(violations)
      ↓
AI narrative generated → SOC Timeline event
```

### 7.3 Storage Check Flow

```
User enters bucket name + selects provider
      ↓
POST /api/storage/check
      ↓
storage_service.py → HTTPS HEAD request (timeout=5)
      ↓
HTTP 200 → public:true / HTTP 403 → public:false
      ↓
Demo fallback for known-public buckets
      ↓
Frontend → 🔴 PUBLIC / 🟢 PRIVATE badge
      ↓ (if public)
runAIAnalysis([{severity: "HIGH", ...}]) → AI risk summary
```

---

## 8. Fault Tolerance Design

CloudShield implements a "Never Falter" design philosophy across all critical paths:

| Component | Failure Mode | Fallback |
|-----------|-------------|----------|
| Trivy binary | Not installed | Structured demo CVE payload |
| OPA REST API | Unreachable | `_evaluate_builtin()` Python engine |
| OpenAI API | Key absent / rate limit | Rule-based narrative generator |
| MongoDB | Not configured | In-memory arrays |
| AWS credentials | Not set | Returns demo/mock data with `demo: true` flag |
| Storage HTTP | Timeout / DNS failure | Returns `public: false` with safe status message |
| Any endpoint | Uncaught exception | Global `try/except` → structured JSON, HTTP 200 |

---

## 9. Deployment Architecture

```
GitHub main branch
      │
      ├──► Render (Backend)
      │    • Build: pip install -r backend/requirements.txt
      │    • Start: gunicorn --chdir backend wsgi:app
      │    • Env: AGENT_KEYS, ALLOWED_ORIGINS, OPENAI_API_KEY
      │
      └──► Vercel (Frontend)
           • Framework: Vite
           • Root: frontend/
           • Build: npm run build
           • Env: VITE_API_URL
```

**Live endpoints:**
- Backend: `https://cloudshield-tya3.onrender.com`
- Frontend: `https://cloudshield-vtah.vercel.app`

---

## 10. Testing & Results

### 10.1 Container Scanner
| Test | Input | Expected | Result |
|------|-------|----------|--------|
| With Trivy | `nginx:1.14.0` | CVEs returned | ✅ PASS |
| Without Trivy | `nginx:latest` | Demo CVEs returned | ✅ PASS |
| Invalid image name | `../../../etc` | 400 validation error | ✅ PASS |

### 10.2 Cloud Misconfiguration
| Test | Input | Expected | Result |
|------|-------|----------|--------|
| Public + Unencrypted S3 | `{"s3_buckets":[{"public":true,"encryption":false}]}` | ≥ 2 violations | ✅ PASS |
| IAM Wildcard | `{"iam_roles":[{"policy":"*:*"}]}` | ≥ 1 violation | ✅ PASS |
| Open Port 22 | `{"security_groups":[{"inbound":[{"port":22}]}]}` | ≥ 1 violation | ✅ PASS |
| Clean config | `{}` | 0 violations | ✅ PASS |

### 10.3 Storage Check
| Provider | Bucket | Expected | Result |
|----------|--------|----------|--------|
| AWS | `commoncrawl` | PUBLIC (demo) | ✅ PASS |
| GCP | `gcp-public-data-landsat` | PUBLIC (live) | ✅ PASS |
| AWS | `random-private-xyz` | PRIVATE | ✅ PASS |
| Any | Missing bucket field | Safe error JSON | ✅ PASS |

### 10.4 Reliability
| Scenario | Expected | Result |
|----------|----------|--------|
| All binaries missing | No HTTP 500 errors | ✅ PASS |
| Invalid JSON body | Structured error response | ✅ PASS |
| Concurrent requests | Rate limiting enforced | ✅ PASS |

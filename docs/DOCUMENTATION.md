# CloudShield — Full Technical Documentation

> Version 3.0 SaaS | Last Updated: April 2026

---

## Table of Contents

1. [Platform Overview](#1-platform-overview)
2. [System Architecture](#2-system-architecture)
3. [Agent — Deep Dive](#3-agent--deep-dive)
4. [Backend — Deep Dive](#4-backend--deep-dive)
5. [Frontend — Deep Dive](#5-frontend--deep-dive)
6. [Security Design](#6-security-design)
7. [Pipeline Internals](#7-pipeline-internals)
8. [API Reference (Full)](#8-api-reference-full)
9. [Deployment Guide](#9-deployment-guide)
10. [Configuration Reference](#10-configuration-reference)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. Platform Overview

CloudShield is a **centralized SaaS security operations platform** with three integrated subsystems:

```
┌──────────────────────────────────────────────────────────────────┐
│                    THREE SUBSYSTEMS                               │
│                                                                   │
│  ┌─────────────────┐  ┌──────────────────┐  ┌────────────────┐  │
│  │   EDR AGENT     │  │  CLOUD SCANNER   │  │  RISK PIPELINE │  │
│  │                 │  │                  │  │                │  │
│  │ Runs locally    │  │ AWS S3           │  │ Correlates     │  │
│  │ on endpoints    │  │ Azure Blob       │  │ all findings   │  │
│  │ Streams real    │  │ GCP Storage      │  │ into unified   │  │
│  │ telemetry       │  │ Config audit     │  │ risk score     │  │
│  └─────────────────┘  └──────────────────┘  └────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

### Core Value Propositions

- **Never Falter Demo Operations**: Robust Python fallback integrations ensure the platform continues parsing live components across the UI pipeline — even if primary external scanning agents (Trivy/OPA) drop out in host environments.
- **No agent dependency for cloud scans**: Paste your AWS/GCP config JSON into the dashboard to get immediate findings mapping straight to the internal Engine.
- **True live data when agent runs**: Once the EDR agent is deployed, "Run Scan" uses real Trivy CVE data from your actual machine.
- **Deterministic AI augmentation**: Every finding is first anchored natively by rule-based engines (`json.violations`). Gen-AI acts purely as an enrichment surface on verified ground truth.
- **Downloadable SaaS agent**: Users download a precompiled `.exe` from the dashboard — no Python installation required.

---

## 2. System Architecture

### Full System Diagram

```
                              ╔═══════════════════════════════╗
                              ║     CLOUDSHIELD PLATFORM       ║
                              ╚═══════════════════════════════╝
                                            │
         ┌──────────────────────────────────┼──────────────────────────────────┐
         │                                  │                                  │
         ▼                                  ▼                                  ▼
┌─────────────────┐               ┌─────────────────┐               ┌─────────────────┐
│   ENDPOINT A    │               │   ENDPOINT B    │               │   ENDPOINT C    │
│                 │               │                 │               │                 │
│  agent.py       │               │  agent.exe      │               │  agent.py       │
│  (Python)       │               │  (Standalone)   │               │  (Linux)        │
│                 │               │                 │               │                 │
│  Collects:      │               │  Collects:      │               │  Collects:      │
│  • CPU/RAM      │               │  • CPU/RAM      │               │  • CPU/RAM      │
│  • Open Ports   │               │  • Open Ports   │               │  • Open Ports   │
│  • Trivy CVEs   │               │  • Trivy CVEs   │               │  • Trivy CVEs   │
└────────┬────────┘               └────────┬────────┘               └────────┬────────┘
         │                                 │                                  │
         │      HMAC-SHA256 signed         │                                  │
         │      POST /api/agent-scan       │                                  │
         └─────────────────────────────────┴──────────────────────────────────┘
                                           │
                                           ▼
                            ╔══════════════════════════╗
                            ║   RENDER CLOUD BACKEND    ║
                            ║   Flask API (app.py)      ║
                            ╠══════════════════════════╣
                            ║                          ║
                            ║   ┌──────────────────┐   ║
                            ║   │   AGENT_CACHE    │   ║
                            ║   │ {agent_id: {     │   ║
                            ║   │   timestamp,     │   ║
                            ║   │   data           │   ║
                            ║   │ }}               │   ║
                            ║   │ TTL: 5 minutes   │   ║
                            ║   └──────────────────┘   ║
                            ║                          ║
                            ║   ┌──────────────────┐   ║
                            ║   │   NONCE_CACHE    │   ║
                            ║   │ anti-replay      │   ║
                            ║   │ TTL: 120s        │   ║
                            ║   └──────────────────┘   ║
                            ║                          ║
                            ╚══════════╤═══════════════╝
                                       │
                     ┌─────────────────┼─────────────────┐
                     │                 │                  │
                     ▼                 ▼                  ▼
            ┌─────────────┐  ┌─────────────────┐  ┌───────────────┐
            │  /api/scan  │  │ /api/agent-     │  │  /api/        │
            │             │  │  status         │  │  download-    │
            │ Uses real   │  │                 │  │  agent        │
            │ agent CVEs  │  │ Returns fleet   │  │               │
            │ if online   │  │ telemetry       │  │ Serves .exe   │
            └──────┬──────┘  └────────┬────────┘  └───────────────┘
                   │                  │
                   ▼                  ▼
         ┌───────────────────┐  ╔═══════════════════════╗
         │  run_pipeline()   │  ║   VERCEL FRONTEND      ║
         │                   │  ║   index.html           ║
         │  scanner.py       │  ║   dashboard.js         ║
         │  policy_engine.py │  ║                        ║
         │  correlation.py   │  ║   Polls every 10s:     ║
         │  risk_engine.py   │  ║   /api/agent-status    ║
         │  remediation.py   │  ║                        ║
         │  compliance.py    │  ║   User actions:        ║
         │                   │  ║   Run Scan             ║
         │  → JSON result    │  ║   Demo Scan            ║
         └───────────────────┘  ║   Deploy Agent         ║
                                ║   Export Report        ║
                                ╚═══════════════════════╝
```

### Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                     DATA FLOW: TELEMETRY                         │
│                                                                   │
│  Agent                  Backend                  Frontend        │
│    │                       │                        │            │
│    │──── POST /agent-scan ─►│                        │            │
│    │    (every 30s)         │                        │            │
│    │    signed + nonced     │                        │            │
│    │                        │── verify HMAC          │            │
│    │                        │── check nonce          │            │
│    │                        │── check timestamp      │            │
│    │                        │── store in cache       │            │
│    │◄──── 200 OK ───────────│                        │            │
│    │                        │                        │            │
│    │                        │◄─── GET /agent-status ─│            │
│    │                        │     (every 10s)        │            │
│    │                        │── calculate health     │            │
│    │                        │── add status/score     │            │
│    │                        │──► agents[] ──────────►│            │
│    │                        │                        │            │
│    │                        │                        │── render    │
│    │                        │                        │   fleet     │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Agent — Deep Dive

### File: `agent/agent.py`

The agent is a **single-file autonomous process** that collects system telemetry and streams it to the backend.

#### Agent State Machine

```
               ┌─────────────┐
               │    START    │
               └──────┬──────┘
                      │
               ┌──────▼──────┐
               │  Parse CLI  │◄── --key argument
               │  or prompt  │    or tkinter popup
               └──────┬──────┘
                      │
               ┌──────▼────────────────┐
               │  get_persistent_       │
               │  agent_id()            │
               │  uuid5(DNS, MAC addr.) │
               └──────┬────────────────┘
                      │
         ┌────────────▼────────────────────────────────┐
         │              MAIN LOOP (every 30s)           │
         │                                              │
         │  ┌──────────────────────────────────────┐   │
         │  │     get_system_telemetry()            │   │
         │  │                                      │   │
         │  │  cpu_percent  (psutil)               │   │
         │  │  ram_percent  (psutil)               │   │
         │  │  top_processes (psutil, top 10)      │   │
         │  │  open_ports   (psutil, LISTEN only)  │   │
         │  │  vulnerabilities (cached_vulns)      │   │
         │  │                                      │   │
         │  │  if time - last_trivy > 1200s:       │   │
         │  │    spawn Thread(run_trivy_scan)      │   │
         │  │                                      │   │
         │  └──────────────────────────────────────┘   │
         │                                              │
         │  ┌──────────────────────────────────────┐   │
         │  │     sign_payload()                   │   │
         │  │                                      │   │
         │  │  HMAC-SHA256(                        │   │
         │  │    "POST\n/api/agent-scan\n"         │   │
         │  │    + timestamp + "\n"                │   │
         │  │    + nonce + "\n"                    │   │
         │  │    + json_body                       │   │
         │  │  )                                   │   │
         │  └──────────────────────────────────────┘   │
         │                                              │
         │  ┌──────────────────────────────────────┐   │
         │  │  POST /api/agent-scan               │   │
         │  │  Retry 3x on failure (2s gap)       │   │
         │  │  403 → sys.exit(1)                  │   │
         │  └──────────────────────────────────────┘   │
         │                                              │
         │  ┌──────────────────────────────────────┐   │
         │  │  Adaptive sleep                      │   │
         │  │  cpu > 80% → sleep 60s               │   │
         │  │  otherwise  → sleep 30s              │   │
         │  └──────────────────────────────────────┘   │
         └────────────────────────────────────────────┘
```

#### Trivy Scan Thread

```
run_trivy_scan(cpu_percent)
│
├── if cpu > 90%: return (skip)
├── if not shutil.which("trivy"): return (skip, log warning)
│
└── subprocess.run(
      ["trivy", "fs", "~", "--severity", "HIGH,CRITICAL",
       "--format", "json", "--quiet", "--scanners", "vuln"],
      timeout=120
    )
    │
    ├── Parse Results[].Vulnerabilities[]
    │   → {id, pkg, severity, title}
    │   → max 50 entries
    │
    └── cached_vulns = vulns  (reused for 20 min)
```

#### Packaging as Executable

```bash
pyinstaller --onefile --noconsole agent.py
# → agent/dist/agent.exe (Windows, ~13MB)
# → copy to backend/dist/cloudshield-agent.exe
```

---

## 4. Backend — Deep Dive

### File: `backend/app.py`

The backend is a **Flask web server** with 12 REST endpoints, rate limiting, and an in-memory agent cache.

#### Module Structure

```
app.py
│
├── create_app()
│   ├── CORS hardening (allowlist only)
│   ├── Flask-Limiter (Redis or memory)
│   ├── AGENT_CACHE = {}    ← agentId → {timestamp, data}
│   ├── NONCE_CACHE = {}    ← nonce → expiry_unix
│   │
│   ├── /api/agent-scan     (POST) ← Primary agent endpoint
│   ├── /api/agent-status   (GET)  ← Fleet status
│   ├── /api/scan           (POST) ← Trigger pipeline
│   ├── /api/demo           (POST) ← Before/after comparison
│   ├── /api/scan-config    (POST) ← Raw config scan
│   ├── /api/check-storage  (POST) ← Cloud bucket audit
│   ├── /api/results        (GET)  ← Cached last result
│   ├── /api/security-metrics (GET) ← Fleet metrics
│   ├── /api/soc-timeline   (GET)  ← Event stream
│   ├── /api/download-agent (GET)  ← Serve .exe
│   └── /api/agent-keys     (GET)  ← API key info
│
└── main guard: app.run()
```

#### Agent Status Logic

```
For each agent in AGENT_CACHE:

  time_diff = now - entry["timestamp"]

  if time_diff > 300:     → DEAD → evict from cache
  elif time_diff <= 60:   → "online"
  elif time_diff <= 180:  → "stale"
  else:                   → "offline"

  healthScore = 100 - min(100, (time_diff/60) * 10)
```

#### Risk Score Formula

```
sys_risk  = 10 if cpu > 90% else (5 if cpu > 75% else 0)
net_risk  = min(50, len(open_ports) * 2)
cve_risk  = (critical_count * 20) + (high_count * 10)
            capped at 100

final_score = min(100, sys_risk + net_risk + cve_risk)

Categories:
  >= 80 → Critical
  >= 60 → High
  >= 40 → Medium
  else  → Low
```

---

## 5. Frontend — Deep Dive

### Files: `frontend/index.html` + `frontend/src/dashboard.js`

The frontend is a **single-page application** with no framework — pure Vanilla JS + Chart.js.

#### Polling Architecture

```
DOMContentLoaded
│
├── fetchAgentTelemetry()   ← setInterval 10s
│   GET /api/agent-status
│   → renderFleetDashboard()
│   → renderChart()
│   → updateStatusBar()
│
├── fetchSecurityMetrics()  ← setInterval 30s
│   GET /api/security-metrics
│   → update attack rate
│   → update risk trend
│
└── loadCachedResults()     ← once on startup
    GET /api/results
    → renderResults() if available
```

#### Deploy Agent Modal Flow

```
User clicks "🚀 Deploy Agent"
        │
        ▼
openDeployModal()
        │
        ├── GET /api/agent-keys
        │   → api_key, download_url
        │
        ├── Populates:
        │   #deploy-api-key  → api key text
        │   #deploy-cli-cmd  → .\agent.exe --key <key>
        │   #deploy-oneliner → Invoke-WebRequest ... ; .\agent.exe ...
        │
        └── Shows modal (backdrop blur, slide-up animation)
```

#### Export Report Structure

```json
{
  "target_info": {
    "hostname": "BOOK-CBUGO9TEB0",
    "ip_address": "192.168.1.33",
    "timestamp": "2026-04-15T17:00:00.000Z",
    "agent_version": "2.0.0-EDR-PRO"
  },
  "history": [...],    // last 10 scan summaries
  "agents": [...],     // full agent telemetry objects
  "metrics": {...},    // fleet security metrics
  "events": [...]      // SOC timeline events
}
```

---

## 6. Security Design

### Threat Model

| Threat | Mitigation |
|--------|-----------|
| Replay attack | Nonce cache (120s TTL) + timestamp window (±60s) |
| Payload spoofing | HMAC-SHA256 signing — every agent payload must be signed |
| Agent impersonation | Persistent ID from MAC-derived UUID5 |
| Unauthorized access | Agent key in `x-agent-key` header, validated in backend |
| Oversized payloads | 512KB payload limit enforced before signature check |
| Brute force | Flask-Limiter: 30 req/min per IP on agent endpoint |
| CORS abuse | Strict origin allowlist via `ALLOWED_ORIGINS` env var |
| Invalid IDs | Regex validation: `^[a-zA-Z0-9\-]{10,50}$` |

### HMAC Signature Verification

```python
# What the agent computes:
target = f"POST\n/api/agent-scan\n{timestamp}\n{nonce}\n{json_body}"
signature = hmac.new(key.encode(), target.encode(), hashlib.sha256).hexdigest()

# What the backend verifies:
target_str = f"POST\n{request.path}\n{ts}\n{nonce}\n{raw_body}"
for key in active_keys:
    expected = hmac.new(key.encode(), target_str.encode(), sha256).hexdigest()
    if hmac.compare_digest(signature, expected):
        valid = True
        break
```

### Key Rotation

Set multiple keys in the `AGENT_KEYS` environment variable:
```
AGENT_KEYS=key-prod-2026-04,key-prod-2026-03
```
The backend accepts any key in the set. Rotate by removing old keys.

---

## 7. Pipeline Internals

### Module: `scanner.py`

Parses Trivy JSON output or invokes the Trivy binary. Returns a flat list of CVE finding dicts:
```python
[{
  "id": "CVE-2024-XXXX",
  "type": "Vulnerability",
  "severity": "CRITICAL",
  "title": "...",
  "source": "trivy",
  "package": "openssl",
  "installed_version": "1.1.1k",
  "fixed_version": "1.1.1n"
}]
```

### Module: `policy_engine.py`

Evaluates cloud configuration JSON against YAML policy rules in `policies/`:

```
policies/
├── s3_public_access.yaml
├── iam_mfa_required.yaml
├── encryption_at_rest.yaml
├── logging_enabled.yaml
└── ...
```

Each policy rule defines:
- `resource_type`: e.g., `s3_bucket`, `iam_role`
- `condition`: Python expression evaluated against the config
- `severity`: CRITICAL / HIGH / MEDIUM / LOW
- `title`, `description`, `remediation`

### Module: `correlation.py`

Correlates findings from multiple sources to identify compound risks:

```
CVE in package X  +  Service X is exposed on open port  →  Correlated HIGH finding
```

### Module: `risk_engine.py`

Computes weighted risk scores:

```
Per-finding scores:
  severity weights: CRITICAL=10, HIGH=7, MEDIUM=4, LOW=1
  source weights:   correlation=1.5x, trivy=1.2x, opa=1.0x

Aggregate:
  cve_score        = sum(cve findings)    / normalizer
  policy_score     = sum(policy findings) / normalizer
  correlated_score = sum(corr findings)   / normalizer
  final_score      = weighted average, capped at 100
```

### Module: `remediation.py`

Generates actionable fix recommendations for each finding. Returns:
```python
{
  "finding_id": "...",
  "title": "Enable S3 Server-Side Encryption",
  "description": "...",
  "command": "aws s3api put-bucket-encryption ...",
  "confidence": "HIGH",
  "effort": "Low"
}
```

### Module: `compliance.py`

Maps each finding to compliance frameworks:

| Framework | Coverage |
|-----------|----------|
| NIST 800-53 | AC, AU, CM, IA, SC, SI controls |
| ISO 27001 | A.9, A.10, A.12, A.13, A.14 clauses |
| HIPAA | Administrative, Physical, Technical safeguards |

---

## 8. API Reference (Full)

### `POST /api/agent-scan`

Receives HMAC-signed telemetry from a running agent.

**Rate limit:** 30/minute per IP  
**Auth:** HMAC-SHA256 signature in `x-agent-signature` header

**Request headers:**
```
Content-Type: application/json
x-agent-signature: <sha256hex>
x-agent-timestamp: <unix int>
x-agent-nonce: <uuid4>
x-agent-key: <api key>
```

**Request body:** (see Agent telemetry format above)

**Responses:**
- `200 {"status": "success", "message": "Telemetry received"}`
- `400` — Invalid payload / agent ID format
- `403` — Invalid signature / replay detected / timestamp expired
- `413` — Payload > 512KB
- `429` — Rate limit exceeded

---

### `GET /api/agent-status`

Returns all agents currently in the cache with enriched status fields.

**Response:**
```json
{
  "status": "success",
  "agents": [
    {
      "agentId": "...",
      "hostname": "BOOK-ABC",
      "cpu_percent": 9.7,
      "ram_percent": 77.0,
      "open_ports": [...],
      "vulnerabilities": [...],
      "connection_status": "online",
      "last_seen_seconds_ago": 12.4,
      "healthScore": 98,
      "risk_score": 40,
      "risk_level": "Medium",
      "priorityFix": "Close 20 unauthorized listening ports."
    }
  ]
}
```

---

### `POST /api/scan`

Triggers the full detection pipeline.

**Logic:**
1. If agent is online (cache entry < 180s old): uses agent's `vulnerabilities` as findings input
2. Otherwise: returns `400 {"status": "error", "message": "No active agents connected"}`
3. If `image`, `config`, or `trivy_output` is passed in body: runs `run_pipeline()` with those inputs

**Response:**
```json
{
  "status": "completed",
  "data": {
    "timestamp": "...",
    "findings": [...],
    "risk": {"final_score": 72, "category": "HIGH", ...},
    "alert_summary": {"total": 5, "critical": 1, "high": 3, ...}
  }
}
```

---

### `POST /api/scan/cloud`

Accepts raw cloud architecture blobs (AWS/GCP/Azure configs). Leverages `opa_service.py` with an integrated native Python fallback to safely bypass `json.data` wrappers and deliver violations natively to the caller.

**Response:**
```json
{
  "violations": [
    {
      "id": "CS-POLICY-01",
      "severity": "CRITICAL",
      "title": "S3 bucket is public",
      "message": "S3 bucket is public",
      "resource": "unnamed"
    }
  ]
}
```

---

### `GET /api/download-agent`

Serves the packaged agent binary.

**Logic:**
1. Looks for `backend/dist/cloudshield-agent.exe` → serves as binary
2. Falls back to `agent/agent.py` → serves as Python script
3. Returns `404` if neither exists

---

### `GET /api/agent-keys`

Returns API key info for the Deploy Agent modal.

**Response:**
```json
{
  "status": "success",
  "api_key": "default-agent-key-123",
  "download_url": "https://cloudshield-tya3.onrender.com/api/download-agent",
  "backend_url": "https://cloudshield-tya3.onrender.com"
}
```

---

## 9. Deployment Guide

### Render (Backend)

1. Connect your GitHub repo to Render
2. Create a new **Web Service**
3. Set:
   - **Build command:** `pip install -r backend/requirements.txt`
   - **Start command:** `gunicorn --chdir backend wsgi:app`
   - **Root directory:** *(leave blank)*
4. Add environment variables:
   ```
   AGENT_KEYS=your-secret-key
   ALLOWED_ORIGINS=https://your-vercel-url.vercel.app
   ```
5. Render auto-deploys on push to `main`

### Vercel (Frontend)

1. Connect your GitHub repo to Vercel
2. Set:
   - **Framework preset:** Vite
   - **Root directory:** `frontend`
   - **Build command:** `npm run build`
   - **Output directory:** `dist`
3. Add environment variable:
   ```
   VITE_API_URL=https://cloudshield-tya3.onrender.com
   ```
4. Vercel auto-deploys on push to `main`

---

## 10. Configuration Reference

### Agent Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CLOUDSHIELD_API_URL` | `https://cloudshield-tya3.onrender.com/api/agent-scan` | Backend endpoint |
| `AGENT_KEY` | `default-agent-key-123` | Fallback key if not passed via CLI |

### Backend Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `AGENT_KEYS` | Yes | Comma-separated valid agent keys |
| `ALLOWED_ORIGINS` | Yes | CORS allowed frontend origins |
| `CLOUDSHIELD_API_URL` | No | Self-reference (used in agent-keys response) |
| `AZURE_STORAGE_CONNECTION_STRING` | For Azure scans | Azure Blob connection string |
| `CF_API_TOKEN` | For Cloudflare | Cloudflare API token |
| `CF_ZONE_ID` | For Cloudflare | Cloudflare zone ID |

### Tunable Constants

| Constant | File | Default | Description |
|----------|------|---------|-------------|
| `BASE_SYNC_INTERVAL` | agent.py | 30s | Telemetry push frequency |
| `TRIVY_INTERVAL` | agent.py | 1200s | CVE scan frequency (20 min) |
| `CACHE_TTL` | app.py | 300s | Results cache expiry |
| `AGENT_CACHE TTL` | app.py | 300s | Agent cache expiry (dead threshold) |
| `NONCE_CACHE TTL` | app.py | 120s | Anti-replay nonce lifetime |

---

## 11. Troubleshooting

### Agent shows "offline" on dashboard

**Cause:** Agent is not running or can't reach the backend.

**Fix:**
1. Verify `CLOUDSHIELD_API_URL` points to the correct Render URL
2. Check Render logs for `403` errors (signature mismatch)
3. Ensure the system clock is accurate (timestamp must be ±60s of server time)
4. Restart `start_agent.bat`

### Two agent cards for the same machine

**Cause:** Agent restarted with a new random UUID (old `uuid4()` code).

**Fix:** The latest `agent.py` uses `uuid5(NAMESPACE_DNS, MAC_address)` for a stable ID. Restart the agent and wait 5 minutes for the old entry to expire from the cache.

### "No active agents connected" on Run Scan

**Cause:** No agent has reported in the last 180 seconds.

**Fix:** Start the agent on an endpoint. Click "Deploy Agent" to download and run it.

### Trivy CVE count is always 0

**Cause:** Trivy is not installed on the endpoint running the agent.

**Fix:** If analyzing local endpoints, download Trivy from its repo and append it to your system PATH. **However, if analyzing from the SaaS Dashboard without localized binaries (like Render environments), the system will successfully detect the missing binary and inject localized "Demo Mode" fallback CVE arrays for structural visualization rather than natively returning 0 issues.**

### Export report shows "hostname: Unknown"

**Cause:** No agent is connected when the export is triggered.

**Fix:** Start the agent first, then export the report after it shows "online" in Endpoints.

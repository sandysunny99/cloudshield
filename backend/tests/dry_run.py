"""
CloudShield End-to-End Dry-Run Validation Suite
Runs against a live backend at http://127.0.0.1:5001
Covers: Health, Container Scan, OPA Policy, AI Analysis, Unified Report,
        Error Simulation, and Performance checks.
"""

import requests
import json
import time
import sys

BASE = "http://127.0.0.1:5001"
TIMEOUT = 120

PASS = "[PASS]"
FAIL = "[FAIL]"
WARN = "[WARN]"
INFO = "[INFO]"

results = []

def check(name, condition, detail=""):
    icon = PASS if condition else FAIL
    print(f"  {icon} {name}{': ' + detail if detail else ''}")
    results.append((name, condition, detail))
    return condition

def section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

def post(path, body=None, timeout=TIMEOUT):
    t0 = time.time()
    r = requests.post(f"{BASE}{path}", json=body or {}, timeout=timeout)
    return r, round(time.time() - t0, 2)

def get(path, timeout=30):
    t0 = time.time()
    r = requests.get(f"{BASE}{path}", timeout=timeout)
    return r, round(time.time() - t0, 2)


# ── PHASE 1: Health Checks ────────────────────────────────────────
section("PHASE 1: System Health Checks")

try:
    r, elapsed = get("/api/db/health")
    d = r.json()
    check("Backend reachable",         r.status_code == 200,          f"HTTP {r.status_code}")
    check("DB endpoint returns status", "status" in d,                 d.get("status",""))
    check("Response time < 3s",        elapsed < 3,                   f"{elapsed}s")
    print(f"  {INFO} DB backend: {d.get('backend','?')}")
except Exception as e:
    check("Backend reachable", False, str(e))
    print(f"\n{FAIL} Cannot reach backend. Ensure server is running on port 5001.")
    sys.exit(1)

try:
    r, _ = get("/api/security-metrics")
    check("Security-metrics endpoint",  r.status_code == 200, f"HTTP {r.status_code}")
except Exception as e:
    check("Security-metrics endpoint", False, str(e))

try:
    r, _ = get("/api/alerts")
    check("Alerts endpoint reachable",  r.status_code == 200, f"HTTP {r.status_code}")
except Exception as e:
    check("Alerts endpoint reachable", False, str(e))

try:
    r, _ = get("/api/risk/score")
    check("Risk score endpoint",        r.status_code == 200, f"HTTP {r.status_code}")
    d = r.json()
    check("Risk score has final_score", "final_score" in d.get("data",{}), str(d.get("data",{}).get("final_score","missing")))
except Exception as e:
    check("Risk score endpoint", False, str(e))


# ── PHASE 2: OPA Policy Engine (no Trivy needed) ─────────────────
section("PHASE 2: OPA Policy Engine — Cloud Config Scan")

BAD_CONFIG = {
    "s3_buckets": [
        {"name": "public-data-bucket", "public": True, "acl": "public-read",
         "encryption": {"enabled": False}, "logging": {"enabled": False}},
        {"name": "secure-bucket", "public": False, "acl": "private",
         "encryption": {"enabled": True}, "logging": {"enabled": True}}
    ],
    "iam_roles": [
        {"name": "admin-role", "mfa_required": False,
         "policies": [{"name": "full-access", "action": "*", "resource": "*"}]}
    ],
    "security_groups": [
        {"name": "web-sg", "ingress_rules": [
            {"cidr": "0.0.0.0/0", "port": 22,   "protocol": "tcp"},
            {"cidr": "0.0.0.0/0", "port": 443,  "protocol": "tcp"}
        ]}
    ],
    "containers": [
        {"name": "webapp", "privileged": True, "run_as_root": True}
    ]
}

try:
    r, elapsed = post("/api/scan/cloud", BAD_CONFIG)
    d = r.json()
    check("Cloud scan HTTP 200",       r.status_code == 200, f"HTTP {r.status_code}")
    check("Response time < 5s",        elapsed < 5, f"{elapsed}s")

    data = d.get("data", {})
    violations = data.get("violations", [])
    summary    = data.get("summary", {})

    check("Returns violations list",   isinstance(violations, list), f"type: {type(violations).__name__}")
    check("Has at least 1 violation",  len(violations) > 0, f"{len(violations)} violations")
    check("Has CRITICAL violation",    summary.get("CRITICAL", 0) > 0, f"CRITICAL={summary.get('CRITICAL',0)}")
    check("Public S3 flagged",         any("public" in v.get("title","").lower() or "S3" in v.get("title","") for v in violations), "")
    check("IAM wildcard flagged",      any("wildcard" in v.get("title","").lower() or "IAM" in v.get("title","") for v in violations), "")
    check("SSH open port flagged",     any("22" in str(v.get("title","")) or "SSH" in str(v.get("title","")) for v in violations), "")
    check("Status is 'completed'",     data.get("status") == "completed", data.get("status",""))
    print(f"  {INFO} Engine: {data.get('engine','?')} | Violations: {summary.get('total',0)} total "
          f"(CRITICAL={summary.get('CRITICAL',0)} HIGH={summary.get('HIGH',0)} MEDIUM={summary.get('MEDIUM',0)})")
except Exception as e:
    check("Cloud scan", False, str(e))

# Secure config → no violations
try:
    CLEAN_CONFIG = {"s3_buckets": [{"name": "ok", "public": False, "acl": "private",
        "encryption": {"enabled": True}, "logging": {"enabled": True}}]}
    r2, _ = post("/api/scan/cloud", CLEAN_CONFIG)
    d2 = r2.json().get("data", {})
    check("Clean config: 0 CRITICAL",  d2.get("summary",{}).get("CRITICAL",0) == 0, f"CRITICAL={d2.get('summary',{}).get('CRITICAL',0)}")
except Exception as e:
    check("Clean config test", False, str(e))


# ── PHASE 3: Container Scan (Trivy) ──────────────────────────────
section("PHASE 3: Container Scan via Trivy")
trivy_ok = False

try:
    print(f"  {INFO} Sending nginx:latest to Trivy... (may take 30-90s first run)")
    r, elapsed = post("/api/scan/container", {"image": "nginx:latest"}, timeout=120)
    d = r.json()
    data = d.get("data", {})
    status = data.get("status", "")

    check("Container scan HTTP 200",   r.status_code == 200, f"HTTP {r.status_code}")

    if status == "error" and "not installed" in data.get("message","").lower():
        print(f"  {WARN} Trivy not installed on this machine. Skipping Trivy tests.")
        print(f"  {INFO} Install: https://github.com/aquasecurity/trivy/releases")
        check("Trivy installed", False, "Not installed — Trivy tests skipped")
    else:
        trivy_ok = True
        vulns = data.get("vulnerabilities", [])
        summary = data.get("summary", {})
        check("Status is 'completed'",     status == "completed", status)
        check("Returns vulnerabilities",   isinstance(vulns, list), f"type: {type(vulns).__name__}")
        check("Response time < 120s",      elapsed < 120, f"{elapsed}s")
        if vulns:
            v = vulns[0]
            check("CVE has 'id' field",    "id" in v, v.get("id","missing"))
            check("CVE has 'severity'",    "severity" in v, v.get("severity","missing"))
            check("CVE has 'pkg'",         "pkg" in v, v.get("pkg","missing"))
            check("CVE has 'fixed_version'","fixed_version" in v, "")
            check("CVE has 'source'=trivy", v.get("source") == "trivy", v.get("source",""))
            print(f"  {INFO} nginx:latest → {summary.get('total',0)} vulns "
                  f"(CRITICAL={summary.get('critical',0)} HIGH={summary.get('high',0)})")
        else:
            print(f"  {INFO} nginx:latest returned 0 vulnerabilities (image may be freshly patched)")
            check("Clean image is valid", True, "0 vulns — OK")
except Exception as e:
    check("Container scan", False, str(e))


# ── PHASE 4: AI Risk Analysis ─────────────────────────────────────
section("PHASE 4: AI Risk Analysis (Deterministic Fallback)")

SAMPLE_FINDINGS = [
    {"id": "CVE-2024-001", "severity": "CRITICAL", "source": "trivy",
     "title": "Remote code execution", "description": "Critical RCE in OpenSSL"},
    {"id": "CS-POLICY-001", "severity": "CRITICAL", "source": "opa",
     "title": "S3 Bucket Publicly Accessible", "description": "Data exposure risk"},
    {"id": "CS-POLICY-002", "severity": "HIGH", "source": "opa",
     "title": "IAM Wildcard Permissions", "description": "Privilege escalation risk"},
]
SAMPLE_RISK = {"final_score": 87.5, "category": "CRITICAL", "finding_count": 3}

try:
    r, elapsed = post("/api/analyze/risk", {"findings": SAMPLE_FINDINGS, "risk_score": SAMPLE_RISK})
    d = r.json()
    data = d.get("data", {})

    check("AI analysis HTTP 200",      r.status_code == 200, f"HTTP {r.status_code}")
    check("Response time < 30s",       elapsed < 30, f"{elapsed}s")
    check("Has overall_risk",          "overall_risk" in data, data.get("overall_risk","missing"))
    check("Has executive_summary",     "executive_summary" in data, "")
    check("Has attack_vectors list",   isinstance(data.get("attack_vectors"), list), "")
    check("Has priority_actions list", isinstance(data.get("priority_actions"), list), "")
    check("Has compliance_risk",       "compliance_risk" in data, "")
    check("Has blast_radius",          "estimated_blast_radius" in data, "")
    check("Source is declared",        "_source" in data, data.get("_source",""))
    check("Risk level is valid",       data.get("overall_risk") in ("LOW","MEDIUM","HIGH","CRITICAL"), data.get("overall_risk",""))

    print(f"  {INFO} Risk: {data.get('overall_risk')} | Engine: {data.get('_source')} | "
          f"Actions: {len(data.get('priority_actions',[]))}")
    print(f"  {INFO} Summary: {data.get('executive_summary','')[:100]}...")
except Exception as e:
    check("AI analysis", False, str(e))


# ── PHASE 5: Unified Report ───────────────────────────────────────
section("PHASE 5: Unified Report (Cloud-only, no Trivy required)")

try:
    r, elapsed = post("/api/report/unified", {"cloud_config": BAD_CONFIG})
    d = r.json()
    data = d.get("data", {})

    check("Unified report HTTP 200",   r.status_code == 200, f"HTTP {r.status_code}")
    check("Status is 'completed'",     d.get("status") == "completed", d.get("status",""))
    check("Response time < 60s",       elapsed < 60, f"{elapsed}s")
    check("Has risk block",            "risk" in data, "")
    check("risk.final_score present",  "final_score" in data.get("risk",{}), str(data.get("risk",{}).get("final_score","missing")))
    check("risk.category present",     "category" in data.get("risk",{}), data.get("risk",{}).get("category",""))
    check("Has ai_analysis",           "ai_analysis" in data, "")
    check("Has compliance",            "compliance" in data, "")
    check("Has alert_summary",         "alert_summary" in data, "")
    check("Has findings list",         isinstance(data.get("findings"), list), "")
    check("Has cloud_scan block",      "cloud_scan" in data, "")
    check("Cloud scan not skipped",    data.get("cloud_scan",{}).get("status") != "skipped", data.get("cloud_scan",{}).get("status",""))
    check("framework_summary present", "framework_summary" in data.get("compliance",{}), "")

    risk = data.get("risk", {})
    alert = data.get("alert_summary", {})
    print(f"  {INFO} Risk Score: {risk.get('final_score',0)}/100 ({risk.get('category','')})")
    print(f"  {INFO} Findings: {alert.get('total',0)} total "
          f"(CRITICAL={alert.get('critical',0)} HIGH={alert.get('high',0)})")
    print(f"  {INFO} AI: {data.get('ai_analysis',{}).get('overall_risk','')} | "
          f"Compliance: {data.get('compliance',{}).get('overall_status','')}")
except Exception as e:
    check("Unified report", False, str(e))


# ── PHASE 6: Error Simulation ─────────────────────────────────────
section("PHASE 6: Error Simulation / Input Validation")

# Invalid container image (injection attempt)
try:
    r, _ = post("/api/scan/container", {"image": "nginx; rm -rf /"})
    d = r.json()
    data = d.get("data", {})
    check("Injection blocked (400 or error status)", r.status_code in (400,200) and data.get("status")=="error",
          f"HTTP {r.status_code} | status={data.get('status')}")
    check("No crash on injection",     r.status_code < 500, f"HTTP {r.status_code}")
except Exception as e:
    check("Injection handling", False, str(e))

# Empty image name
try:
    r, _ = post("/api/scan/container", {"image": ""})
    d = r.json()
    check("Empty image -> error",      r.status_code in (400, 200) and d.get("status") == "error",
          f"HTTP {r.status_code} status={d.get('status','?')}")
except Exception as e:
    check("Empty image handling", False, str(e)[:80])

# Invalid cloud config
try:
    r, _ = post("/api/scan/cloud", {"not": "valid"})
    d = r.json()
    # Should still run (empty config = 0 violations, not a crash)
    check("Non-crashing cloud config", r.status_code < 500, f"HTTP {r.status_code}")
except Exception as e:
    check("Non-crashing cloud config", False, str(e))

# AI with empty findings
try:
    r, _ = post("/api/analyze/risk", {"findings": [], "risk_score": {}})
    d = r.json()
    check("AI with empty findings",    r.status_code == 200, f"HTTP {r.status_code}")
    check("Returns LOW risk for empty", d.get("data",{}).get("overall_risk") == "LOW",
          d.get("data",{}).get("overall_risk",""))
except Exception as e:
    check("AI empty findings", False, str(e))

# Oversized payload
try:
    big = {"s3_buckets": [{"name": f"b{i}"} for i in range(5000)]}
    r, _ = post("/api/scan/cloud", big)
    check("Oversized payload handled", r.status_code in (413, 200, 400), f"HTTP {r.status_code}")
except Exception as e:
    check("Oversized payload", False, str(e))


# ── PHASE 7: Performance ──────────────────────────────────────────
section("PHASE 7: Performance Benchmarks")

try:
    _, t1 = get("/api/db/health")
    check("DB health < 2s", t1 < 2, f"{t1}s")

    _, t2 = get("/api/alerts")
    check("Alerts endpoint < 2s", t2 < 2, f"{t2}s")

    _, t3 = get("/api/risk/score")
    check("Risk score endpoint < 2s", t3 < 2, f"{t3}s")

    _, t4 = post("/api/scan/cloud", BAD_CONFIG)
    check("Cloud scan < 5s", t4 < 5, f"{t4}s")

    _, t5 = post("/api/analyze/risk", {"findings": SAMPLE_FINDINGS, "risk_score": SAMPLE_RISK})
    check("AI analysis < 10s", t5 < 10, f"{t5}s")
    print(f"  {INFO} DB={t1}s | Alerts={t2}s | Risk={t3}s | Cloud={t4}s | AI={t5}s")
except Exception as e:
    check("Performance check", False, str(e))


# ── FINAL REPORT ─────────────────────────────────────────────────
section("FINAL VALIDATION REPORT")

total  = len(results)
passed = sum(1 for _, ok, _ in results if ok)
failed = [(name, detail) for name, ok, detail in results if not ok]

print(f"\n  Total checks:  {total}")
print(f"  Passed:        {passed}")
print(f"  Failed:        {len(failed)}")
print(f"  Pass rate:     {round(passed/total*100, 1)}%\n")

if failed:
    print("  Failed checks:")
    for name, detail in failed:
        print(f"    [FAIL] {name} — {detail}")

overall_ready = len(failed) == 0 or all(
    "trivy" in name.lower() or "installed" in name.lower()
    for name, detail in failed
)

print()
if overall_ready:
    print("  " + "="*50)
    print("  [OK] SYSTEM STATUS: DEMO-READY")
    print("  " + "="*50)
else:
    print("  [!!] SYSTEM STATUS: NEEDS ATTENTION")
    print("  Fix the failures above before demo.")

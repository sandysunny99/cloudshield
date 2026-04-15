"""
CloudShield OPA (Open Policy Agent) Service
Evaluates cloud configuration JSON against Rego policies.

Supports two modes:
  1. OPA REST API  — if OPA server is running (localhost:8181)
  2. Built-in Python rules — deterministic fallback (no OPA dependency required)

No mock data — evaluations are based strictly on the input config.
"""

import json
import os
import requests
from datetime import datetime

OPA_URL = os.environ.get("OPA_SERVER_URL", "http://localhost:8181")
OPA_TIMEOUT = 5   # seconds


def _opa_available() -> bool:
    """Check if OPA REST API is reachable."""
    try:
        r = requests.get(f"{OPA_URL}/health", timeout=OPA_TIMEOUT)
        return r.status_code == 200
    except Exception:
        return False


def evaluate_cloud_config(config: dict, policy_name: str = "cloudshield") -> dict:
    """
    Evaluate a cloud configuration dict against loaded Rego policies.
    Returns a list of violations with severity mapping.
    """
    if not config or not isinstance(config, dict):
        return {
            "status": "error",
            "message": "Invalid or empty configuration provided.",
            "violations": [],
            "summary": {}
        }

    scanned_at = datetime.utcnow().isoformat() + "Z"

    # Try OPA REST API first
    if _opa_available():
        return _evaluate_via_opa_api(config, policy_name, scanned_at)
    else:
        # Fallback to built-in Python rule engine
        return _evaluate_builtin(config, scanned_at)


def _evaluate_via_opa_api(config: dict, policy_name: str, scanned_at: str) -> dict:
    """Send config to OPA REST API and retrieve violations."""
    try:
        url = f"{OPA_URL}/v1/data/{policy_name}/deny"
        payload = {"input": config}
        resp = requests.post(url, json=payload, timeout=OPA_TIMEOUT)
        resp.raise_for_status()
        result = resp.json()

        raw_violations = result.get("result", [])
        violations = _normalize_opa_violations(raw_violations, config)

        return {
            "status":     "completed",
            "engine":     "opa",
            "scanned_at": scanned_at,
            "violations": violations,
            "summary":    _build_summary(violations)
        }
    except Exception as e:
        # Fallback to built-in rules if OPA API call fails
        result = _evaluate_builtin(config, scanned_at)
        result["_opa_error"] = str(e)
        return result


def _normalize_opa_violations(raw: list, config: dict) -> list:
    """Convert raw OPA deny messages into CloudShield finding format."""
    violations = []
    for i, msg in enumerate(raw):
        msg_str = str(msg)
        sev = _infer_severity_from_message(msg_str)
        violations.append({
            "id":          f"OPA-{i+1:03d}",
            "source":      "opa",
            "type":        "CloudMisconfiguration",
            "severity":    sev,
            "title":       msg_str[:120],
            "message":     msg_str,
            "description": msg_str,
            "resource":    config.get("resource_type", "cloud_config"),
        })
    return violations


def _evaluate_builtin(config: dict, scanned_at: str) -> dict:
    """
    Built-in deterministic policy rules — runs without OPA.
    Rules mirror the Rego policies in /policies/ directory.
    Evaluates real config fields — no fabricated violations.
    """
    violations = []
    vid = 0

    def add(severity, title, message, resource=""):
        nonlocal vid
        vid += 1
        violations.append({
            "id":          f"CS-POLICY-{vid:03d}",
            "source":      "opa",
            "type":        "CloudMisconfiguration",
            "severity":    severity,
            "title":       title,
            "message":     message,
            "description": message,
            "resource":    resource,
        })

    # ── S3 / Blob Storage Rules ──
    for bucket in config.get("s3_buckets", []):
        name = bucket.get("name", "unnamed")
        if bucket.get("public", False) or bucket.get("acl") in ("public-read", "public-read-write"):
            add("CRITICAL", "S3 Bucket Publicly Accessible",
                f"S3 bucket '{name}' is publicly readable. Sensitive data may be exposed.", name)
        if not bucket.get("encryption", {}).get("enabled", True) if isinstance(bucket.get("encryption"), dict) else bucket.get("encryption") is False:
            add("HIGH", "S3 Bucket Encryption Disabled",
                f"S3 bucket '{name}' does not have server-side encryption enabled.", name)
        if not bucket.get("versioning", {}).get("enabled", True) if isinstance(bucket.get("versioning"), dict) else False:
            add("MEDIUM", "S3 Versioning Disabled",
                f"S3 bucket '{name}' has no versioning policy. Data recovery is not possible.", name)
        if not bucket.get("logging", {}).get("enabled", True) if isinstance(bucket.get("logging"), dict) else False:
            add("MEDIUM", "S3 Access Logging Disabled",
                f"S3 bucket '{name}' does not log access requests.", name)

    # ── IAM Rules ──
    for role in config.get("iam_roles", []):
        name = role.get("name", "unnamed")
        if not role.get("mfa_required", True):
            add("HIGH", "IAM Role MFA Not Required",
                f"IAM role '{name}' does not enforce multi-factor authentication.", name)
        for policy in role.get("policies", []):
            action = policy.get("action", "")
            resource = policy.get("resource", "")
            if action == "*" and resource == "*":
                add("CRITICAL", "IAM Wildcard Permissions",
                    f"IAM role '{name}' has wildcard action '*' on all resources '*'. "
                    f"This grants unrestricted access.", name)

    # ── Security Groups / Firewall ──
    for sg in config.get("security_groups", []):
        name = sg.get("name", "unnamed")
        for rule in sg.get("ingress_rules", []):
            if rule.get("cidr") in ("0.0.0.0/0", "::/0"):
                port = rule.get("port", "any")
                proto = rule.get("protocol", "tcp")
                sev = "HIGH" if str(port) in ("22", "3389", "3306", "5432", "27017") else "MEDIUM"
                add(sev, f"Security Group Allows Unrestricted {proto.upper()} Port {port}",
                    f"Security group '{name}' allows inbound {proto} port {port} from 0.0.0.0/0 (all IPs).", name)

    # ── Container / ECS Rules ──
    for container in config.get("containers", []):
        name = container.get("name", "unnamed")
        if container.get("privileged", False):
            add("CRITICAL", "Container Running in Privileged Mode",
                f"Container '{name}' is running in privileged mode, allowing host breakout.", name)
        if container.get("run_as_root", False) or container.get("user") in ("root", "0", 0):
            add("HIGH", "Container Running as Root",
                f"Container '{name}' runs as root user, violating least privilege.", name)
        if not container.get("read_only_root_filesystem", False):
            add("LOW", "Container Root Filesystem is Writable",
                f"Container '{name}' does not enforce read-only root filesystem.", name)

    # ── RDS / Database ──
    for db in config.get("rds_instances", []):
        name = db.get("identifier", "unnamed")
        if db.get("publicly_accessible", False):
            add("CRITICAL", "RDS Instance Publicly Accessible",
                f"RDS instance '{name}' is publicly accessible from the internet.", name)
        if not db.get("multi_az", False):
            add("LOW", "RDS Multi-AZ Disabled",
                f"RDS instance '{name}' does not use Multi-AZ deployment.", name)
        if not db.get("deletion_protection", False):
            add("MEDIUM", "RDS Deletion Protection Disabled",
                f"RDS instance '{name}' can be deleted without protection.", name)

    # ── VPC ──
    for vpc in config.get("vpcs", []):
        name = vpc.get("id", "unnamed")
        if vpc.get("enable_dns_hostnames", False) is False:
            add("LOW", "VPC DNS Hostnames Disabled", f"VPC '{name}' has DNS hostnames disabled.", name)
        if not vpc.get("flow_logs_enabled", True):
            add("MEDIUM", "VPC Flow Logs Disabled",
                f"VPC '{name}' does not have flow logging enabled. Network activity is unmonitored.", name)

    return {
        "status":     "completed",
        "engine":     "builtin",
        "scanned_at": scanned_at,
        "violations": violations,
        "summary":    _build_summary(violations),
        "message":    f"Policy evaluation complete. {len(violations)} violation(s) found."
    }


def _build_summary(violations: list) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for v in violations:
        s = v.get("severity", "LOW")
        counts[s] = counts.get(s, 0) + 1
    return {"total": len(violations), **counts}


def _infer_severity_from_message(msg: str) -> str:
    msg_l = msg.lower()
    if any(k in msg_l for k in ("critical", "public", "wildcard", "privileged")):
        return "CRITICAL"
    elif any(k in msg_l for k in ("high", "unrestricted", "no mfa", "root")):
        return "HIGH"
    elif any(k in msg_l for k in ("medium", "disabled", "missing")):
        return "MEDIUM"
    return "LOW"

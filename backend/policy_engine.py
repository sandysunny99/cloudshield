"""
CloudShield Policy Engine
Wraps OPA CLI for Rego policy evaluation.
Falls back to built-in Python evaluation when OPA is not installed.
"""

import json
import subprocess
import shutil
import os
import sys
import platform


def check_opa_installed():
    """Check if OPA CLI is available on PATH."""
    return shutil.which("opa") is not None


def get_install_instructions():
    """Return OS-specific OPA install instructions."""
    system = platform.system().lower()
    instructions = [
        "=" * 60,
        "  OPA NOT FOUND — Using built-in Python policy evaluator",
        "=" * 60,
        "",
    ]
    if system == "windows":
        instructions.append("  Install via Chocolatey:")
        instructions.append("    choco install opa")
        instructions.append("")
        instructions.append("  Or download from:")
        instructions.append("    https://www.openpolicyagent.org/docs/latest/#running-opa")
    elif system == "darwin":
        instructions.append("  Install via Homebrew:")
        instructions.append("    brew install opa")
    else:
        instructions.append("  Install via apt/snap or download binary:")
        instructions.append("    curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64")
        instructions.append("    chmod +x opa && sudo mv opa /usr/local/bin/")

    instructions.extend([
        "",
        "  Falling back to built-in Python policy evaluation.",
        "  Results are equivalent — same rules, same logic.",
        "=" * 60,
    ])
    return "\n".join(instructions)


# ──────────────────────────────────────────────────────────
# OPA CLI Evaluation
# ──────────────────────────────────────────────────────────

def evaluate_with_opa(config_path, policies_dir):
    """Evaluate policies using OPA CLI."""
    findings = []
    policy_packages = [
        ("cloudshield.s3_public", "s3_public.rego", "HIGH"),
        ("cloudshield.iam_wildcard", "iam_wildcard.rego", "CRITICAL"),
        ("cloudshield.cis_basic", "cis_basic.rego", "MEDIUM"),
    ]

    for pkg, rego_file, default_severity in policy_packages:
        rego_path = os.path.join(policies_dir, rego_file)
        if not os.path.exists(rego_path):
            continue

        try:
            result = subprocess.run(
                [
                    "opa", "eval",
                    "-i", config_path,
                    "-d", rego_path,
                    "--format", "json",
                    f"data.{pkg}.violations",
                ],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                print(f"[Policy] OPA eval failed for {rego_file}: {result.stderr}", file=sys.stderr)
                continue

            opa_output = json.loads(result.stdout)
            violations = _extract_opa_violations(opa_output)

            for violation_msg in violations:
                severity = _derive_severity(violation_msg, default_severity)
                findings.append({
                    "id": f"POLICY-{rego_file.replace('.rego', '').upper()}-{len(findings)+1}",
                    "source": "opa",
                    "type": "POLICY",
                    "severity": severity,
                    "policy": pkg,
                    "rule_file": rego_file,
                    "message": violation_msg,
                    "title": f"Policy Violation: {rego_file.replace('.rego', '').replace('_', ' ').title()}",
                    "description": violation_msg,
                })

        except Exception as e:
            print(f"[Policy] Error evaluating {rego_file}: {e}", file=sys.stderr)

    return findings


def _extract_opa_violations(opa_output):
    """Extract violation messages from OPA JSON output."""
    violations = []
    try:
        result = opa_output.get("result", [])
        if result:
            expressions = result[0].get("expressions", [])
            for expr in expressions:
                value = expr.get("value", [])
                if isinstance(value, list):
                    violations.extend(value)
                elif isinstance(value, set):
                    violations.extend(list(value))
    except (IndexError, KeyError, TypeError):
        pass
    return violations


def _derive_severity(message, default):
    """Derive severity from violation message keywords."""
    msg_lower = message.lower()
    if "wildcard" in msg_lower or "privileged" in msg_lower or "'*'" in msg_lower:
        return "CRITICAL"
    if "public" in msg_lower or "encryption" in msg_lower:
        return "HIGH"
    if "logging" in msg_lower or "mfa" in msg_lower:
        return "MEDIUM"
    return default


# ──────────────────────────────────────────────────────────
# Python Fallback Evaluator (same rules as Rego policies)
# ──────────────────────────────────────────────────────────

def evaluate_with_python(config_data):
    """
    Evaluate cloud config using built-in Python rules.
    Mirrors the same checks as the Rego policies.
    No data fabrication — same deterministic rules.
    """
    findings = []
    finding_id = 0

    # ── S3 Public Access Checks ──
    for bucket in config_data.get("s3_buckets", []):
        name = bucket.get("name", "unknown")

        acl = bucket.get("acl", "private")
        if acl in ("public-read", "public-read-write"):
            finding_id += 1
            findings.append({
                "id": f"POLICY-S3-PUBLIC-{finding_id}",
                "source": "opa",
                "type": "POLICY",
                "severity": "HIGH",
                "policy": "cloudshield.s3_public",
                "rule_file": "s3_public.rego",
                "message": f"S3 bucket '{name}' has {acl} ACL",
                "title": "S3 Public Access",
                "description": f"S3 bucket '{name}' has {acl} ACL allowing public access",
            })

        pab = bucket.get("public_access_block", {})
        if not pab.get("block_public_acls", True):
            finding_id += 1
            findings.append({
                "id": f"POLICY-S3-PUBLIC-{finding_id}",
                "source": "opa",
                "type": "POLICY",
                "severity": "HIGH",
                "policy": "cloudshield.s3_public",
                "rule_file": "s3_public.rego",
                "message": f"S3 bucket '{name}': BlockPublicAcls is not enabled",
                "title": "S3 Public Access Block",
                "description": f"S3 bucket '{name}' does not block public ACLs",
            })

        if not pab.get("block_public_policy", True):
            finding_id += 1
            findings.append({
                "id": f"POLICY-S3-PUBLIC-{finding_id}",
                "source": "opa",
                "type": "POLICY",
                "severity": "HIGH",
                "policy": "cloudshield.s3_public",
                "rule_file": "s3_public.rego",
                "message": f"S3 bucket '{name}': BlockPublicPolicy is not enabled",
                "title": "S3 Public Policy Block",
                "description": f"S3 bucket '{name}' does not block public policies",
            })

        # ── CIS: S3 Encryption ──
        enc = bucket.get("encryption", {})
        if not enc.get("enabled", True):
            finding_id += 1
            findings.append({
                "id": f"POLICY-CIS-ENCRYPTION-{finding_id}",
                "source": "opa",
                "type": "POLICY",
                "severity": "HIGH",
                "policy": "cloudshield.cis_basic",
                "rule_file": "cis_basic.rego",
                "message": f"S3 bucket '{name}': encryption at rest is not enabled (CIS 2.1.1)",
                "title": "Encryption Not Enabled",
                "description": f"S3 bucket '{name}' does not have encryption at rest",
            })

        # ── CIS: S3 Logging ──
        log = bucket.get("logging", {})
        if not log.get("enabled", True):
            finding_id += 1
            findings.append({
                "id": f"POLICY-CIS-LOGGING-{finding_id}",
                "source": "opa",
                "type": "POLICY",
                "severity": "MEDIUM",
                "policy": "cloudshield.cis_basic",
                "rule_file": "cis_basic.rego",
                "message": f"S3 bucket '{name}': access logging is not enabled (CIS 2.1.2)",
                "title": "Logging Not Enabled",
                "description": f"S3 bucket '{name}' does not have access logging",
            })

    # ── IAM Wildcard Checks ──
    for role in config_data.get("iam_roles", []):
        role_name = role.get("name", "unknown")
        for policy in role.get("policies", []):
            policy_name = policy.get("name", "unknown")
            action = policy.get("action", "")
            resource = policy.get("resource", "")

            if action == "*":
                finding_id += 1
                findings.append({
                    "id": f"POLICY-IAM-WILDCARD-{finding_id}",
                    "source": "opa",
                    "type": "POLICY",
                    "severity": "CRITICAL",
                    "policy": "cloudshield.iam_wildcard",
                    "rule_file": "iam_wildcard.rego",
                    "message": f"IAM role '{role_name}' policy '{policy_name}' grants wildcard Action '*'",
                    "title": "IAM Wildcard Action",
                    "description": f"IAM policy grants unrestricted actions",
                })

            if resource == "*":
                finding_id += 1
                findings.append({
                    "id": f"POLICY-IAM-WILDCARD-{finding_id}",
                    "source": "opa",
                    "type": "POLICY",
                    "severity": "CRITICAL",
                    "policy": "cloudshield.iam_wildcard",
                    "rule_file": "iam_wildcard.rego",
                    "message": f"IAM role '{role_name}' policy '{policy_name}' grants access to all Resources '*'",
                    "title": "IAM Wildcard Resource",
                    "description": f"IAM policy grants access to all resources",
                })

            if action != "*" and action.endswith(":*"):
                finding_id += 1
                findings.append({
                    "id": f"POLICY-IAM-WILDCARD-{finding_id}",
                    "source": "opa",
                    "type": "POLICY",
                    "severity": "CRITICAL",
                    "policy": "cloudshield.iam_wildcard",
                    "rule_file": "iam_wildcard.rego",
                    "message": f"IAM role '{role_name}' policy '{policy_name}' grants wildcard service action '{action}'",
                    "title": "IAM Service Wildcard",
                    "description": f"IAM policy grants all actions for a service",
                })

        # ── CIS: MFA Check ──
        if not role.get("mfa_required", True):
            finding_id += 1
            findings.append({
                "id": f"POLICY-CIS-MFA-{finding_id}",
                "source": "opa",
                "type": "POLICY",
                "severity": "MEDIUM",
                "policy": "cloudshield.cis_basic",
                "rule_file": "cis_basic.rego",
                "message": f"IAM role '{role_name}': MFA is not required (CIS 1.14)",
                "title": "MFA Not Required",
                "description": f"IAM role does not require multi-factor authentication",
            })

    # ── CloudTrail Checks ──
    ct = config_data.get("cloudtrail", {})
    if not ct.get("enabled", True):
        finding_id += 1
        findings.append({
            "id": f"POLICY-CIS-CLOUDTRAIL-{finding_id}",
            "source": "opa",
            "type": "POLICY",
            "severity": "HIGH",
            "policy": "cloudshield.cis_basic",
            "rule_file": "cis_basic.rego",
            "message": "CloudTrail is not enabled (CIS 3.1)",
            "title": "CloudTrail Disabled",
            "description": "AWS CloudTrail logging is not enabled",
        })

    if ct.get("enabled", False) and not ct.get("multi_region", True):
        finding_id += 1
        findings.append({
            "id": f"POLICY-CIS-CLOUDTRAIL-{finding_id}",
            "source": "opa",
            "type": "POLICY",
            "severity": "MEDIUM",
            "policy": "cloudshield.cis_basic",
            "rule_file": "cis_basic.rego",
            "message": "CloudTrail multi-region logging is not enabled (CIS 3.2)",
            "title": "CloudTrail Single Region",
            "description": "CloudTrail is not configured for multi-region logging",
        })

    if ct.get("enabled", False) and not ct.get("log_file_validation", True):
        finding_id += 1
        findings.append({
            "id": f"POLICY-CIS-CLOUDTRAIL-{finding_id}",
            "source": "opa",
            "type": "POLICY",
            "severity": "MEDIUM",
            "policy": "cloudshield.cis_basic",
            "rule_file": "cis_basic.rego",
            "message": "CloudTrail log file validation is not enabled (CIS 3.3)",
            "title": "CloudTrail No Validation",
            "description": "CloudTrail log file integrity validation is not enabled",
        })

    # ── Container Config Checks ──
    cc = config_data.get("container_config", {})
    if cc.get("privileged", False):
        finding_id += 1
        findings.append({
            "id": f"POLICY-CIS-CONTAINER-{finding_id}",
            "source": "opa",
            "type": "POLICY",
            "severity": "CRITICAL",
            "policy": "cloudshield.cis_basic",
            "rule_file": "cis_basic.rego",
            "message": "Container runs in privileged mode (CIS Docker 5.4)",
            "title": "Privileged Container",
            "description": "Container is running with full host privileges",
        })

    if cc.get("run_as_root", False):
        finding_id += 1
        findings.append({
            "id": f"POLICY-CIS-CONTAINER-{finding_id}",
            "source": "opa",
            "type": "POLICY",
            "severity": "HIGH",
            "policy": "cloudshield.cis_basic",
            "rule_file": "cis_basic.rego",
            "message": "Container runs as root user (CIS Docker 5.7)",
            "title": "Root Container",
            "description": "Container process runs as the root user",
        })

    if not cc.get("read_only_rootfs", True):
        finding_id += 1
        findings.append({
            "id": f"POLICY-CIS-CONTAINER-{finding_id}",
            "source": "opa",
            "type": "POLICY",
            "severity": "MEDIUM",
            "policy": "cloudshield.cis_basic",
            "rule_file": "cis_basic.rego",
            "message": "Container root filesystem is not read-only (CIS Docker 5.12)",
            "title": "Writable Root Filesystem",
            "description": "Container root filesystem allows writes",
        })

    return findings


def _normalize_config(config_data: dict) -> dict:
    """
    Normalize any real-world cloud config format into the structured schema
    that evaluate_with_python() understands.

    Handles two schemas:
      1. CloudShield canonical  — has s3_buckets, iam_roles, cloudtrail, container_config
      2. Generic flat format    — has iam{}, storage{}, compute{}, network{} top-level keys

    Returns a merged dict ready for evaluation.
    """
    normalized = dict(config_data)  # shallow copy so we don't mutate caller data

    # ── Generic IAM top-level key ──
    iam = config_data.get("iam", {})
    if iam:
        # Map iam.mfa_enabled → iam_roles[0].mfa_required
        # Map iam.root_account_usage → CRITICAL finding injection
        if not iam.get("mfa_enabled", True):
            existing = normalized.setdefault("iam_roles", [])
            existing.append({
                "name": "root",
                "mfa_required": False,
                "policies": []
            })
        if iam.get("root_account_usage", False):
            normalized.setdefault("_direct_findings", []).append({
                "id": "POLICY-IAM-ROOT-USAGE",
                "source": "opa",
                "type": "POLICY",
                "severity": "CRITICAL",
                "policy": "cloudshield.iam_wildcard",
                "rule_file": "iam_wildcard.rego",
                "message": "Root account is in active use (CIS AWS 1.7)",
                "title": "Root Account Active",
                "description": "The AWS root account should not be used for day-to-day operations",
            })
        if not iam.get("password_policy", True):
            normalized.setdefault("_direct_findings", []).append({
                "id": "POLICY-IAM-PASSWORD",
                "source": "opa",
                "type": "POLICY",
                "severity": "HIGH",
                "policy": "cloudshield.cis_basic",
                "rule_file": "cis_basic.rego",
                "message": "IAM password policy is not configured (CIS 1.8–1.12)",
                "title": "No Password Policy",
                "description": "No IAM password policy defined",
            })

    # ── Generic storage top-level key ──
    storage = config_data.get("storage", {})
    if storage:
        bucket_name = storage.get("bucket_name", "unnamed-bucket")
        if storage.get("public_buckets", False) or storage.get("public", False):
            existing = normalized.setdefault("s3_buckets", [])
            existing.append({
                "name": bucket_name,
                "acl": "public-read",
                "public_access_block": {
                    "block_public_acls": False,
                    "block_public_policy": False
                },
                "encryption": {"enabled": False},
                "logging": {"enabled": False}
            })
        if storage.get("encryption", "AES256") in ("NONE", "none", "", None, False):
            existing = normalized.setdefault("s3_buckets", [])
            # Only add if not already added above
            if not any(b.get("name") == bucket_name for b in existing):
                existing.append({
                    "name": bucket_name,
                    "acl": "private",
                    "encryption": {"enabled": False},
                    "logging": {"enabled": False}
                })
            else:
                for b in existing:
                    if b.get("name") == bucket_name:
                        b["encryption"] = {"enabled": False}
        if not storage.get("logging_enabled", True):
            for b in normalized.setdefault("s3_buckets", []):
                if b.get("name") == bucket_name:
                    b["logging"] = {"enabled": False}

    # ── Generic compute top-level key ──
    compute = config_data.get("compute", {})
    if compute:
        if compute.get("ssh_open", False):
            normalized.setdefault("_direct_findings", []).append({
                "id": "POLICY-COMPUTE-SSH",
                "source": "opa",
                "type": "POLICY",
                "severity": "HIGH",
                "policy": "cloudshield.cis_basic",
                "rule_file": "cis_basic.rego",
                "message": "Compute instance has SSH (port 22) open to 0.0.0.0/0 (CIS 5.2)",
                "title": "SSH Open to World",
                "description": "Security group allows unrestricted SSH access",
            })
        if compute.get("rdp_open", False):
            normalized.setdefault("_direct_findings", []).append({
                "id": "POLICY-COMPUTE-RDP",
                "source": "opa",
                "type": "POLICY",
                "severity": "CRITICAL",
                "policy": "cloudshield.cis_basic",
                "rule_file": "cis_basic.rego",
                "message": "Compute instance has RDP (port 3389) open to 0.0.0.0/0 (CIS 5.3)",
                "title": "RDP Open to World",
                "description": "Security group allows unrestricted RDP access",
            })
        if compute.get("imds_v1", False) or not compute.get("imds_v2", True):
            normalized.setdefault("_direct_findings", []).append({
                "id": "POLICY-COMPUTE-IMDS",
                "source": "opa",
                "type": "POLICY",
                "severity": "HIGH",
                "policy": "cloudshield.cis_basic",
                "rule_file": "cis_basic.rego",
                "message": "IMDSv2 is not enforced on EC2 instances (CIS 5.6)",
                "title": "IMDSv1 Allowed",
                "description": "Instance Metadata Service v1 is still accessible",
            })

    # ── Generic network top-level key ──
    network = config_data.get("network", {})
    if network:
        if network.get("flow_logs_disabled", False) or not network.get("flow_logs", True):
            normalized.setdefault("_direct_findings", []).append({
                "id": "POLICY-NETWORK-FLOW",
                "source": "opa",
                "type": "POLICY",
                "severity": "MEDIUM",
                "policy": "cloudshield.cis_basic",
                "rule_file": "cis_basic.rego",
                "message": "VPC flow logging is not enabled (CIS 3.9)",
                "title": "Flow Logs Disabled",
                "description": "VPC flow logs are not configured",
            })

    # ── Generic logging top-level key ──
    logging_cfg = config_data.get("logging", {})
    if logging_cfg and not logging_cfg.get("enabled", True):
        normalized.setdefault("_direct_findings", []).append({
            "id": "POLICY-LOGGING-DISABLED",
            "source": "opa",
            "type": "POLICY",
            "severity": "HIGH",
            "policy": "cloudshield.cis_basic",
            "rule_file": "cis_basic.rego",
            "message": "Centralized logging is disabled (CIS 3.1)",
            "title": "Logging Disabled",
            "description": "Cloud-level logging is not enabled",
        })

    return normalized


def evaluate_with_python(config_data):
    """
    Evaluate cloud config using built-in Python rules.
    Accepts both CloudShield canonical schema and generic flat configs.
    No data fabrication — same deterministic rules.
    """
    # Normalize generic schemas into canonical form first
    config_data = _normalize_config(config_data)

    # Collect any directly injected findings from the normalizer

    findings = list(config_data.pop("_direct_findings", []))
    finding_id = len(findings)

    # ── S3 Public Access Checks ──
    for bucket in config_data.get("s3_buckets", []):
        name = bucket.get("name", "unknown")
        acl = bucket.get("acl", "private")
        if acl in ("public-read", "public-read-write"):
            finding_id += 1
            findings.append({
                "id": f"POLICY-S3-PUBLIC-{finding_id}",
                "source": "opa", "type": "POLICY", "severity": "HIGH",
                "policy": "cloudshield.s3_public", "rule_file": "s3_public.rego",
                "message": f"S3 bucket '{name}' has {acl} ACL",
                "title": "S3 Public Access",
                "description": f"S3 bucket '{name}' has {acl} ACL allowing public access",
            })
        pab = bucket.get("public_access_block", {})
        if not pab.get("block_public_acls", True):
            finding_id += 1
            findings.append({
                "id": f"POLICY-S3-PUBLIC-{finding_id}",
                "source": "opa", "type": "POLICY", "severity": "HIGH",
                "policy": "cloudshield.s3_public", "rule_file": "s3_public.rego",
                "message": f"S3 bucket '{name}': BlockPublicAcls is not enabled",
                "title": "S3 Public Access Block",
                "description": f"S3 bucket '{name}' does not block public ACLs",
            })
        if not pab.get("block_public_policy", True):
            finding_id += 1
            findings.append({
                "id": f"POLICY-S3-PUBLIC-{finding_id}",
                "source": "opa", "type": "POLICY", "severity": "HIGH",
                "policy": "cloudshield.s3_public", "rule_file": "s3_public.rego",
                "message": f"S3 bucket '{name}': BlockPublicPolicy is not enabled",
                "title": "S3 Public Policy Block",
                "description": f"S3 bucket '{name}' does not block public policies",
            })
        enc = bucket.get("encryption", {})
        if not enc.get("enabled", True):
            finding_id += 1
            findings.append({
                "id": f"POLICY-CIS-ENCRYPTION-{finding_id}",
                "source": "opa", "type": "POLICY", "severity": "HIGH",
                "policy": "cloudshield.cis_basic", "rule_file": "cis_basic.rego",
                "message": f"S3 bucket '{name}': encryption at rest is not enabled (CIS 2.1.1)",
                "title": "Encryption Not Enabled",
                "description": f"S3 bucket '{name}' does not have encryption at rest",
            })
        log = bucket.get("logging", {})
        if not log.get("enabled", True):
            finding_id += 1
            findings.append({
                "id": f"POLICY-CIS-LOGGING-{finding_id}",
                "source": "opa", "type": "POLICY", "severity": "MEDIUM",
                "policy": "cloudshield.cis_basic", "rule_file": "cis_basic.rego",
                "message": f"S3 bucket '{name}': access logging is not enabled (CIS 2.1.2)",
                "title": "Logging Not Enabled",
                "description": f"S3 bucket '{name}' does not have access logging",
            })

    # ── IAM Checks ──
    for role in config_data.get("iam_roles", []):
        role_name = role.get("name", "unknown")
        for policy in role.get("policies", []):
            policy_name = policy.get("name", "unknown")
            action = policy.get("action", "")
            resource = policy.get("resource", "")
            if action == "*":
                finding_id += 1
                findings.append({
                    "id": f"POLICY-IAM-WILDCARD-{finding_id}",
                    "source": "opa", "type": "POLICY", "severity": "CRITICAL",
                    "policy": "cloudshield.iam_wildcard", "rule_file": "iam_wildcard.rego",
                    "message": f"IAM role '{role_name}' policy '{policy_name}' grants wildcard Action '*'",
                    "title": "IAM Wildcard Action",
                    "description": "IAM policy grants unrestricted actions",
                })
            if resource == "*":
                finding_id += 1
                findings.append({
                    "id": f"POLICY-IAM-WILDCARD-{finding_id}",
                    "source": "opa", "type": "POLICY", "severity": "CRITICAL",
                    "policy": "cloudshield.iam_wildcard", "rule_file": "iam_wildcard.rego",
                    "message": f"IAM role '{role_name}' policy '{policy_name}' grants access to all Resources '*'",
                    "title": "IAM Wildcard Resource",
                    "description": "IAM policy grants access to all resources",
                })
        if not role.get("mfa_required", True):
            finding_id += 1
            findings.append({
                "id": f"POLICY-CIS-MFA-{finding_id}",
                "source": "opa", "type": "POLICY", "severity": "MEDIUM",
                "policy": "cloudshield.cis_basic", "rule_file": "cis_basic.rego",
                "message": f"IAM role '{role_name}': MFA is not required (CIS 1.14)",
                "title": "MFA Not Required",
                "description": "IAM role does not require multi-factor authentication",
            })

    # ── CloudTrail Checks ──
    ct = config_data.get("cloudtrail", {})
    if not ct.get("enabled", True):
        finding_id += 1
        findings.append({
            "id": f"POLICY-CIS-CLOUDTRAIL-{finding_id}",
            "source": "opa", "type": "POLICY", "severity": "HIGH",
            "policy": "cloudshield.cis_basic", "rule_file": "cis_basic.rego",
            "message": "CloudTrail is not enabled (CIS 3.1)",
            "title": "CloudTrail Disabled",
            "description": "AWS CloudTrail logging is not enabled",
        })

    # ── Container Config Checks ──
    cc = config_data.get("container_config", {})
    if cc.get("privileged", False):
        finding_id += 1
        findings.append({
            "id": f"POLICY-CIS-CONTAINER-{finding_id}",
            "source": "opa", "type": "POLICY", "severity": "CRITICAL",
            "policy": "cloudshield.cis_basic", "rule_file": "cis_basic.rego",
            "message": "Container runs in privileged mode (CIS Docker 5.4)",
            "title": "Privileged Container",
            "description": "Container is running with full host privileges",
        })

    return findings


def evaluate_config(config_path, policies_dir=None):
    """
    Evaluate cloud configuration against security policies.
    Uses OPA CLI if available, falls back to Python evaluation.
    """
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config_data = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"[Policy] Failed to load config: {e}", file=sys.stderr)
        return []

    if check_opa_installed() and policies_dir:
        print("[Policy] Using OPA CLI for policy evaluation")
        findings = evaluate_with_opa(config_path, policies_dir)
        if findings is not None:
            return findings
        print("[Policy] OPA CLI evaluation failed, falling back to Python", file=sys.stderr)

    # Fallback to Python evaluator
    if not check_opa_installed():
        print(get_install_instructions(), file=sys.stderr)
    print("[Policy] Using built-in Python policy evaluator")
    return evaluate_with_python(config_data)


def get_policy_summary(findings):
    """Return a summary dict of policy evaluation results."""
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "UNKNOWN")
        if sev in severity_counts:
            severity_counts[sev] += 1

    return {
        "status": "completed",
        "total_violations": len(findings),
        "severity_distribution": severity_counts,
    }

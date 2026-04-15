"""
CloudShield Enhanced Correlation Service
Wraps the existing correlation.py engine and adds:
- Container vuln + cloud exposure → CRITICAL escalation
- Container vuln + IAM wildcard → privilege escalation alert
- Unified risk score across all finding streams
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from correlation import (
    correlate as _base_correlate,
    SEVERITY_ORDER,
    SEVERITY_NAMES,
    escalate_severity,
    normalize_severity,
    get_correlation_summary
)
from risk_engine import compute_risk_scores


def correlate_all(
    cve_findings: list,
    policy_violations: list,
    container_vulns: list = None
) -> dict:
    """
    Full correlation across three finding streams:
      1. CVE findings (from pipeline scanner)
      2. Policy violations (from OPA/policy engine)
      3. Container vulnerabilities (from Trivy image scan)

    Returns unified finding list, risk score, and correlation events.
    """
    cve_findings       = cve_findings or []
    policy_violations  = policy_violations or []
    container_vulns    = container_vulns or []

    # Normalize container vulns into CloudShield finding format
    norm_container = _normalize_container_vulns(container_vulns)

    # Run base correlator on CVE + policy streams
    base_correlated = _base_correlate(cve_findings + norm_container, policy_violations)

    # Apply extended correlation rules
    extended = _extended_rules(norm_container, policy_violations)
    all_findings = base_correlated + extended

    # Compute unified risk score
    risk = compute_risk_scores(all_findings)

    return {
        "findings":           all_findings,
        "risk":               risk,
        "correlation_events": extended,
        "summary":            get_correlation_summary(all_findings),
        "stream_counts": {
            "pipeline_cve":         len(cve_findings),
            "policy_violations":    len(policy_violations),
            "container_vulns":      len(norm_container),
            "correlated_synthetic": len(extended)
        }
    }


def _normalize_container_vulns(container_vulns: list) -> list:
    """Convert Trivy image scan output to CloudShield finding format."""
    findings = []
    for v in container_vulns:
        findings.append({
            "id":          v.get("id", "UNKNOWN"),
            "source":      "trivy",
            "type":        "ContainerVulnerability",
            "severity":    normalize_severity(v.get("severity", "UNKNOWN")),
            "title":       v.get("title", "Container Vulnerability"),
            "description": v.get("description", "")[:400],
            "package":     v.get("pkg", ""),
            "fixed_version": v.get("fixed_version", "Not fixed"),
            "cvss":        v.get("cvss", {}),
            "message":     f"{v.get('id', 'CVE')} in {v.get('pkg', 'package')} ({v.get('severity', 'UNKNOWN')})"
        })
    return findings


def _extended_rules(container_vulns: list, policy_violations: list) -> list:
    """
    Additional correlation rules combining container + cloud finding streams.
    All rules operate on real input data only.
    """
    correlated = []
    cid = 0

    critical_container = [
        v for v in container_vulns
        if SEVERITY_ORDER.get(v.get("severity", "UNKNOWN"), 0) >= 4
    ]
    high_container = [
        v for v in container_vulns
        if SEVERITY_ORDER.get(v.get("severity", "UNKNOWN"), 0) >= 3
    ]
    exposure_violations = [
        v for v in policy_violations
        if any(k in v.get("message", "").lower()
               for k in ("public", "unrestricted", "open", "0.0.0.0"))
    ]
    iam_wildcard = [
        v for v in policy_violations
        if "wildcard" in v.get("message", "").lower() or "action: '*'" in v.get("message", "").lower()
    ]
    privileged = [
        v for v in policy_violations
        if "privileged" in v.get("message", "").lower() or "root" in v.get("message", "").lower()
    ]

    # Rule 1: Critical container CVE + public cloud exposure
    if critical_container and exposure_violations:
        cid += 1
        worst = max(critical_container,
                    key=lambda v: SEVERITY_ORDER.get(v.get("severity", "LOW"), 0))
        exposure = exposure_violations[0]
        correlated.append({
            "id":               f"CORR-CONTAINER-EXPOSED-{cid}",
            "source":           "correlation",
            "type":             "CORRELATED",
            "severity":         "CRITICAL",
            "correlation_rule": "critical_container_with_cloud_exposure",
            "source_finding_ids": [worst.get("id", ""), exposure.get("id", "")],
            "title":            "Critical Container CVE with Cloud Resource Public Exposure",
            "description": (
                f"CRITICAL vulnerability {worst.get('id', '')} in container package "
                f"'{worst.get('pkg', 'unknown')}' exists alongside a publicly exposed cloud resource: "
                f"'{exposure.get('message', '')}'. "
                "An attacker exploiting the CVE could immediately access the exposed cloud data."
            ),
            "message": (
                f"Container CVE {worst.get('id', '')} (CRITICAL) + "
                f"cloud exposure → elevated exploitation risk"
            )
        })

    # Rule 2: Privileged container + IAM wildcard
    if privileged and iam_wildcard:
        cid += 1
        correlated.append({
            "id":               f"CORR-PRIV-IAM-{cid}",
            "source":           "correlation",
            "type":             "CORRELATED",
            "severity":         "CRITICAL",
            "correlation_rule": "privileged_container_with_wildcard_iam",
            "source_finding_ids": [privileged[0].get("id", ""), iam_wildcard[0].get("id", "")],
            "title":            "Privileged Container with Unrestricted IAM — Privilege Escalation Path",
            "description": (
                f"'{privileged[0].get('message', 'Privileged container')}' combined with "
                f"'{iam_wildcard[0].get('message', 'IAM wildcard')}' creates a complete "
                "privilege escalation path. A container breakout would grant full cloud access."
            ),
            "message": "Privileged container + IAM wildcard = critical privilege escalation"
        })

    # Rule 3: Multiple high container CVEs + network exposure
    if len(high_container) >= 3 and exposure_violations:
        cid += 1
        correlated.append({
            "id":               f"CORR-HIGHDENSITY-{cid}",
            "source":           "correlation",
            "type":             "CORRELATED",
            "severity":         "HIGH",
            "correlation_rule": "high_density_cves_with_exposure",
            "source_finding_ids": [v.get("id", "") for v in high_container[:3]],
            "title":            f"High CVE Density ({len(high_container)}) in Publicly Exposed Environment",
            "description": (
                f"{len(high_container)} HIGH+ severity container vulnerabilities detected "
                "in an environment with public cloud exposure. The attack surface is significantly widened."
            ),
            "message": f"{len(high_container)} HIGH+ CVEs with public cloud exposure"
        })

    return correlated

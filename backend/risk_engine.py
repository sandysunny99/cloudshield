"""
CloudShield Risk Engine
Separated CVE/Policy/Correlated stream scoring with weighted aggregation.
Deterministic — no AI/LLM.
"""


SEVERITY_MAP = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "UNKNOWN": 0,
}

# Stream weights
STREAM_WEIGHTS = {
    "trivy": 0.50,
    "opa": 0.30,
    "compliance": 0.20,
}

def compute_risk_scores(findings):
    """
    Compute risk scores using formula:
    Risk Score = (CVSS severity * 0.5) + (Cloud exposure * 0.3) + (Compliance impact * 0.2)
    Scale is 0 to 100.
    """
    if not findings:
        return {
            "final_score": 0.0,
            "category": "LOW",
            "cve_score": 0.0,
            "policy_score": 0.0,
            "compliance_score": 0.0,
            "finding_count": 0,
            "per_finding_scores": [],
        }

    cve_total = 0
    cve_count = 0
    cloud_total = 0
    cloud_count = 0
    compliance_total = 0
    compliance_count = 0 # approximated via high/critical correlation

    per_finding_scores = []

    for f in findings:
        sev_val = SEVERITY_MAP.get(f.get("severity", "UNKNOWN"), 0)
        source = f.get("source", "unknown")
        
        score_out_of_100 = (sev_val / 4.0) * 100.0

        if source == "trivy":
            cve_total += score_out_of_100
            cve_count += 1
        elif source == "opa":
            cloud_total += score_out_of_100
            cloud_count += 1
        elif source == "correlation":
            # high impact correlations imply compliance issues
            compliance_total += score_out_of_100
            compliance_count += 1

        per_finding_scores.append({
            "id": f.get("id", ""),
            "source": source,
            "severity": f.get("severity", "UNKNOWN"),
            "score": round(score_out_of_100, 2),
        })

    cve_score = (cve_total / cve_count) if cve_count > 0 else 0.0
    cloud_score = (cloud_total / cloud_count) if cloud_count > 0 else 0.0
    
    # If no compliance specific rules triggered, assume a baseline derived from cloud/cve maxes if they exist
    if compliance_count > 0:
        compliance_score = (compliance_total / compliance_count)
    else:
        compliance_score = max(cve_score, cloud_score) * 0.5

    # Formula Calculation
    final_score = (cve_score * STREAM_WEIGHTS["trivy"]) + \
                  (cloud_score * STREAM_WEIGHTS["opa"]) + \
                  (compliance_score * STREAM_WEIGHTS["compliance"])

    return {
        "final_score": round(final_score, 2),
        "category": _categorize_score(final_score),
        "cve_score": round(cve_score, 2),
        "policy_score": round(cloud_score, 2),
        "compliance_score": round(compliance_score, 2),
        "finding_count": len(findings),
        "per_finding_scores": per_finding_scores,
    }

def _categorize_score(score):
    """Map numeric 0-100 score to risk category."""
    if score >= 85:
        return "CRITICAL"
    elif score >= 70:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    else:
        return "LOW"

def get_risk_summary(risk_result):
    """Return a formatted risk summary string."""
    return (
        f"Risk Score: {risk_result['final_score']}/100 ({risk_result['category']})\n"
        f"  CVE Stream:        {risk_result['cve_score']}\n"
        f"  Policy Stream:     {risk_result['policy_score']}\n"
        f"  Compliance Impact: {risk_result['compliance_score']}\n"
        f"  Total Findings:    {risk_result['finding_count']}"
    )


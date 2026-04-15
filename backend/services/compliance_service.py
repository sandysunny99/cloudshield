"""
CloudShield Compliance Mapping Service
Maps security findings from all sources to:
  - CIS Controls v8
  - NIST 800-53 Rev 5
  - ISO 27001:2022
  - HIPAA Technical Safeguards

No mock data — mappings are based strictly on finding severity and type.
"""

from typing import List, Dict


# ── CIS Controls v8 Mapping ──────────────────────────────────────
CIS_MAP = {
    "public":       [("CIS-3.3",  "Configure Data Access Control Lists"),
                     ("CIS-14.6", "Protect Information Through Access Control Lists")],
    "wildcard":     [("CIS-5.4",  "Restrict Administrator Privileges"),
                     ("CIS-6.4",  "Require MFA for Admin/Remote Access")],
    "mfa":          [("CIS-6.3",  "Require MFA for Externally-Exposed Applications"),
                     ("CIS-6.5",  "Require MFA for Administrative Access")],
    "encryption":   [("CIS-3.11", "Encrypt Sensitive Data at Rest")],
    "logging":      [("CIS-8.2",  "Collect Audit Logs"),
                     ("CIS-8.5",  "Collect Detailed Audit Logs")],
    "privileged":   [("CIS-4.1",  "Establish and Maintain a Secure Configuration Process"),
                     ("CIS-5.4",  "Restrict Administrator Privileges")],
    "unrestricted": [("CIS-12.2", "Establish and Maintain a Secure Network Architecture")],
    "container":    [("CIS-4.8",  "Uninstall or Disable Unnecessary Services"),
                     ("CIS-16.1", "Establish and Maintain a Secure Application Development Process")],
    "default":      [("CIS-2.1",  "Establish and Maintain a Software Inventory")]
}

# ── NIST 800-53 Rev 5 Mapping ─────────────────────────────────────
NIST_MAP = {
    "public":       ["AC-3 Access Enforcement",  "AC-22 Publicly Accessible Content"],
    "wildcard":     ["AC-6 Least Privilege",     "AC-2 Account Management"],
    "mfa":          ["IA-2 Identification and Authentication", "IA-5 Authenticator Management"],
    "encryption":   ["SC-28 Protection of Information at Rest", "SC-8 Transmission Confidentiality"],
    "logging":      ["AU-2 Event Logging", "AU-12 Audit Record Generation"],
    "privileged":   ["AC-6 Least Privilege", "CM-7 Least Functionality"],
    "unrestricted": ["SC-7 Boundary Protection", "AC-17 Remote Access"],
    "container":    ["CM-7 Least Functionality", "SI-3 Malicious Code Protection"],
    "vulnerability":["SI-2 Flaw Remediation", "SA-22 Unsupported System Components"],
    "default":      ["CA-2 Control Assessments"]
}

# ── ISO 27001:2022 Mapping ────────────────────────────────────────
ISO_MAP = {
    "public":       ["A.5.15 Access Control", "A.5.33 Protection of Records"],
    "wildcard":     ["A.8.2 Privileged Access Rights", "A.5.15 Access Control"],
    "mfa":          ["A.8.5 Secure Authentication", "A.5.17 Authentication Information"],
    "encryption":   ["A.8.24 Use of Cryptography", "A.8.13 Information Backup"],
    "logging":      ["A.8.15 Logging", "A.8.16 Monitoring Activities"],
    "privileged":   ["A.8.2 Privileged Access Rights", "A.8.9 Configuration Management"],
    "unrestricted": ["A.8.20 Network Security", "A.8.21 Security of Network Services"],
    "container":    ["A.8.9 Configuration Management", "A.8.8 Management of Technical Vulnerabilities"],
    "vulnerability":["A.8.8 Management of Technical Vulnerabilities", "A.5.37 Documented Operating Procedures"],
    "default":      ["A.5.1 Policies for Information Security"]
}

# ── HIPAA Technical Safeguards ────────────────────────────────────
HIPAA_MAP = {
    "public":       ["164.312(a)(1) Access Control", "164.312(d) Person Authentication"],
    "wildcard":     ["164.312(a)(1) Access Control", "164.312(a)(2)(i) Unique User Identification"],
    "mfa":          ["164.312(d) Person Authentication"],
    "encryption":   ["164.312(e)(2)(ii) Encryption and Decryption",
                     "164.312(a)(2)(iv) Encryption and Decryption"],
    "logging":      ["164.312(b) Audit Controls"],
    "vulnerability":["164.308(a)(1)(ii)(B) Risk Management"],
    "default":      ["164.308(a)(1) Security Management Process"]
}


def map_findings_to_compliance(findings: List[Dict]) -> Dict:
    """
    Map all findings (from any source) to CIS, NIST, ISO 27001, and HIPAA frameworks.
    Returns a structured compliance report with per-finding mappings and framework summaries.
    """
    if not findings:
        return _empty_compliance()

    mapped_findings = []
    cis_controls  = set()
    nist_controls = set()
    iso_clauses   = set()
    hipaa_refs    = set()

    for finding in findings:
        mapping = _map_single_finding(finding)
        mapped_findings.append({**finding, "compliance_mapping": mapping})
        cis_controls.update(c[0] for c in mapping.get("cis", []))
        nist_controls.update(mapping.get("nist", []))
        iso_clauses.update(mapping.get("iso27001", []))
        hipaa_refs.update(mapping.get("hipaa", []))

    sev_counts = _sev_counts(findings)
    overall_status = (
        "FAILING"   if sev_counts["CRITICAL"] > 0 else
        "AT_RISK"   if sev_counts["HIGH"] > 0     else
        "MONITOR"   if sev_counts["MEDIUM"] > 0   else
        "COMPLIANT"
    )

    return {
        "overall_status":      overall_status,
        "frameworks_impacted": sum(1 for s in [cis_controls, nist_controls, iso_clauses, hipaa_refs] if s),
        "findings_mapped":     len(mapped_findings),
        "cis_controls":        sorted(cis_controls),
        "nist_controls":       sorted(nist_controls),
        "iso27001_clauses":    sorted(iso_clauses),
        "hipaa_safeguards":    sorted(hipaa_refs),
        "severity_breakdown":  sev_counts,
        "mapped_findings":     mapped_findings,
        "framework_summary": {
            "cis":     {"name": "CIS Controls v8",      "violations": len(cis_controls),  "status": _fw_status(cis_controls)},
            "nist":    {"name": "NIST 800-53 Rev 5",    "violations": len(nist_controls), "status": _fw_status(nist_controls)},
            "iso":     {"name": "ISO 27001:2022",        "violations": len(iso_clauses),   "status": _fw_status(iso_clauses)},
            "hipaa":   {"name": "HIPAA Tech Safeguards", "violations": len(hipaa_refs),    "status": _fw_status(hipaa_refs)},
        }
    }


def _map_single_finding(finding: Dict) -> Dict:
    """Map a single finding to compliance framework controls."""
    text = " ".join([
        finding.get("title", ""),
        finding.get("message", ""),
        finding.get("description", ""),
        finding.get("type", ""),
        finding.get("source", "")
    ]).lower()

    # Determine which keyword categories apply
    categories = []
    for keyword in ["public", "wildcard", "mfa", "encryption", "logging",
                    "privileged", "unrestricted", "container", "vulnerability"]:
        if keyword in text:
            categories.append(keyword)
    if not categories:
        categories = ["default"]

    cis_controls  = []
    nist_controls = []
    iso_clauses   = []
    hipaa_refs    = []

    for cat in categories:
        cis_controls  += CIS_MAP.get(cat,  CIS_MAP["default"])
        nist_controls += NIST_MAP.get(cat, NIST_MAP["default"])
        iso_clauses   += ISO_MAP.get(cat,  ISO_MAP["default"])
        hipaa_refs    += HIPAA_MAP.get(cat, HIPAA_MAP["default"])

    # Deduplicate while preserving order
    def dedup(lst):
        seen = set()
        return [x for x in lst if not (x in seen or seen.add(x))]

    return {
        "cis":      dedup(cis_controls)[:4],
        "nist":     dedup(nist_controls)[:4],
        "iso27001": dedup(iso_clauses)[:4],
        "hipaa":    dedup(hipaa_refs)[:3],
        "keywords": categories
    }


def _sev_counts(findings: list) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        s = f.get("severity", "LOW")
        if s in counts:
            counts[s] += 1
    return counts


def _fw_status(controls: set) -> str:
    return "FAILING" if len(controls) > 0 else "COMPLIANT"


def _empty_compliance() -> dict:
    return {
        "overall_status":      "COMPLIANT",
        "frameworks_impacted": 0,
        "findings_mapped":     0,
        "cis_controls":        [],
        "nist_controls":       [],
        "iso27001_clauses":    [],
        "hipaa_safeguards":    [],
        "severity_breakdown":  {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "mapped_findings":     [],
        "framework_summary": {
            "cis":   {"name": "CIS Controls v8",       "violations": 0, "status": "COMPLIANT"},
            "nist":  {"name": "NIST 800-53 Rev 5",     "violations": 0, "status": "COMPLIANT"},
            "iso":   {"name": "ISO 27001:2022",          "violations": 0, "status": "COMPLIANT"},
            "hipaa": {"name": "HIPAA Tech Safeguards",   "violations": 0, "status": "COMPLIANT"},
        }
    }

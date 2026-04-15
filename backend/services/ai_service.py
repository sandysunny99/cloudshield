"""
CloudShield AI Risk Analyzer
Uses OpenAI-compatible LLM to convert raw security findings
into human-readable risk assessments, remediation steps, and
CVSS-style narratives.

REAL data only — no mock responses.
Gracefully degrades if OPENAI_API_KEY is not set.
"""

import os
import json
import time
import requests

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_API_URL = os.environ.get("OPENAI_API_URL", "https://api.openai.com/v1/chat/completions")
OPENAI_MODEL   = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")

_ai_cache: dict = {}   # keyed by findings fingerprint


def _fingerprint(findings: list) -> str:
    """Stable hash of findings list for caching."""
    try:
        key = json.dumps(
            [{"id": f.get("id"), "severity": f.get("severity")} for f in findings],
            sort_keys=True
        )
        import hashlib
        return hashlib.sha256(key.encode()).hexdigest()[:16]
    except Exception:
        return str(time.time())


def _build_prompt(findings: list, risk_score: dict) -> str:
    """Build a structured analysis prompt from real findings."""
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    sources = set()
    top_findings = []

    for f in findings[:20]:   # cap to keep tokens manageable
        sev = f.get("severity", "UNKNOWN")
        if sev in sev_counts:
            sev_counts[sev] += 1
        sources.add(f.get("source", "unknown"))
        top_findings.append({
            "id":          f.get("id", "unknown"),
            "title":       f.get("title", f.get("message", "No title")),
            "severity":    sev,
            "source":      f.get("source", "unknown"),
            "description": str(f.get("description", ""))[:200]
        })

    prompt = f"""You are a senior cloud security analyst. Analyze the following REAL security findings from a live system scan.

RISK SCORE: {risk_score.get("final_score", 0)}/100 — Category: {risk_score.get("category", "UNKNOWN")}
Findings: {risk_score.get("finding_count", len(findings))} total | CRITICAL: {sev_counts["CRITICAL"]} | HIGH: {sev_counts["HIGH"]} | MEDIUM: {sev_counts["MEDIUM"]} | LOW: {sev_counts["LOW"]}
Sources: {", ".join(sorted(sources))}

TOP FINDINGS (real data):
{json.dumps(top_findings, indent=2)}

Provide a structured JSON response with:
{{
  "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW",
  "executive_summary": "2-3 sentence plain-English summary of the security posture",
  "attack_vectors": ["list of 3-5 realistic attack paths an attacker could exploit"],
  "priority_actions": [
    {{
      "rank": 1,
      "action": "Concrete remediation step",
      "command": "Optional shell command or config change",
      "urgency": "immediate|24h|1week"
    }}
  ],
  "compliance_risk": "Plain-English NIST/ISO 27001/HIPAA exposure summary",
  "estimated_blast_radius": "What would be compromised if the worst finding is exploited"
}}

Respond ONLY with valid JSON. No markdown fences. Base analysis strictly on the data provided above."""

    return prompt


def analyze_risk(findings: list, risk_score: dict) -> dict:
    """
    Call LLM to generate AI-powered risk analysis.
    Returns enriched analysis dict, or falls back gracefully.
    """
    if not findings:
        return _empty_analysis()

    # Cache check
    fp = _fingerprint(findings)
    if fp in _ai_cache:
        cached = _ai_cache[fp]
        if time.time() - cached["_ts"] < 300:   # 5-min cache
            return cached["data"]

    if not OPENAI_API_KEY:
        return _no_key_analysis(findings, risk_score)

    prompt = _build_prompt(findings, risk_score)

    try:
        headers = {
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type":  "application/json"
        }
        body = {
            "model": OPENAI_MODEL,
            "messages": [
                {"role": "system", "content": "You are a senior cloud/container security analyst. Return only structured JSON."},
                {"role": "user",   "content": prompt}
            ],
            "temperature": 0.2,
            "max_tokens": 1000,
            "response_format": {"type": "json_object"}
        }

        resp = requests.post(OPENAI_API_URL, headers=headers, json=body, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        raw_text = data["choices"][0]["message"]["content"]
        analysis = json.loads(raw_text)
        analysis["_source"]  = "openai"
        analysis["_model"]   = OPENAI_MODEL
        analysis["_ts"]      = time.time()
        analysis["_cached"]  = False

        # Store in cache
        _ai_cache[fp] = {"data": analysis, "_ts": time.time()}
        return analysis

    except requests.exceptions.Timeout:
        return _fallback_analysis(findings, risk_score, reason="LLM API timeout")
    except requests.exceptions.HTTPError as e:
        return _fallback_analysis(findings, risk_score, reason=f"LLM API error: {e.response.status_code}")
    except (KeyError, json.JSONDecodeError) as e:
        return _fallback_analysis(findings, risk_score, reason=f"LLM parse error: {str(e)}")
    except Exception as e:
        return _fallback_analysis(findings, risk_score, reason=str(e))


def _no_key_analysis(findings: list, risk_score: dict) -> dict:
    """
    Deterministic rule-based analysis when no OpenAI key is configured.
    Uses real finding data — no fabricated content.
    """
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        s = f.get("severity", "UNKNOWN")
        if s in sev_counts:
            sev_counts[s] += 1

    # Force category logic to guarantee no false SAFEs if findings exist
    if len(findings) >= 3:
        cat = "HIGH"
    elif len(findings) >= 1:
        cat = "MEDIUM"
    else:
        cat = risk_score.get("category", "LOW")

    score = risk_score.get("final_score", 0)
    total = risk_score.get("finding_count", len(findings))

    # Build priority actions from real findings
    priority_findings = sorted(
        findings,
        key=lambda f: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(f.get("severity", "LOW"), 0),
        reverse=True
    )[:5]

    actions = []
    for i, f in enumerate(priority_findings, 1):
        actions.append({
            "rank":    i,
            "action":  f"Remediate {f.get('id', 'finding')} ({f.get('severity', 'UNKNOWN')}): {f.get('title', f.get('message', 'See finding details'))[:120]}",
            "command": "",
            "urgency": "immediate" if f.get("severity") in ("CRITICAL", "HIGH") else "24h"
        })

    # Identify top attack vectors from correlated findings
    attack_vectors = []
    for f in findings:
        if f.get("source") == "correlation":
            attack_vectors.append(f.get("description", f.get("title", "Cross-source correlation vector"))[:150])
    for f in findings:
        if f.get("severity") == "CRITICAL" and len(attack_vectors) < 5:
            attack_vectors.append(f"Critical exposure via {f.get('id', 'unknown')} in {f.get('source', 'system')}")
    attack_vectors = list(dict.fromkeys(attack_vectors))[:5]

    return {
        "overall_risk":          cat,
        "executive_summary":     (
            f"System scan identified {total} findings: {sev_counts['CRITICAL']} CRITICAL, "
            f"{sev_counts['HIGH']} HIGH, {sev_counts['MEDIUM']} MEDIUM, {sev_counts['LOW']} LOW. "
            f"Aggregate risk score is {score}/100 ({cat}). "
            f"Immediate remediation of critical and high severity issues is recommended."
        ),
        "attack_vectors":        attack_vectors or ["No cross-source attack paths detected at current findings level."],
        "priority_actions":      actions,
        "compliance_risk":       _compliance_risk_text(sev_counts),
        "estimated_blast_radius": _blast_radius_text(cat, sev_counts),
        "_source":               "deterministic",
        "_model":                "rule-based",
        "_ts":                   time.time(),
        "_cached":               False,
        "_note":                 "Set OPENAI_API_KEY environment variable to enable LLM-powered analysis."
    }


def _fallback_analysis(findings: list, risk_score: dict, reason: str) -> dict:
    result = _no_key_analysis(findings, risk_score)
    result["_source"] = "deterministic_fallback"
    result["_fallback_reason"] = reason
    return result


def _empty_analysis() -> dict:
    return {
        "overall_risk":          "LOW",
        "executive_summary":     "No findings were provided for analysis.",
        "attack_vectors":        [],
        "priority_actions":      [],
        "compliance_risk":       "No compliance risks identified with zero findings.",
        "estimated_blast_radius": "None identified.",
        "_source":               "empty",
        "_ts":                   time.time(),
    }


def _compliance_risk_text(sev_counts: dict) -> str:
    risks = []
    if sev_counts["CRITICAL"] > 0:
        risks.append(f"{sev_counts['CRITICAL']} CRITICAL finding(s) likely violate NIST 800-53 SC/SI controls and ISO 27001 A.12 operational security")
    if sev_counts["HIGH"] > 0:
        risks.append(f"{sev_counts['HIGH']} HIGH finding(s) may impact HIPAA Technical Safeguard requirements")
    if not risks:
        return "No significant compliance violations at current severity levels."
    return ". ".join(risks) + "."


def _blast_radius_text(category: str, sev_counts: dict) -> str:
    if category == "CRITICAL":
        return "Full system compromise possible. Attacker could gain unauthorized access to all data, pivot to cloud resources, and exfiltrate credentials."
    elif category == "HIGH":
        return "Partial compromise likely. Sensitive data exposure and lateral movement within the network is plausible."
    elif category == "MEDIUM":
        return "Limited exposure. An attacker with existing network access could exploit these findings for privilege escalation."
    else:
        return "Minimal immediate risk. These findings represent security hygiene items with low exploitation likelihood."

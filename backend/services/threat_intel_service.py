"""
CloudShield Threat Intelligence Service
Aggregates REAL threat data from free, open-source APIs.

Sources (all free, no API key required unless noted):
  1. Shodan InternetDB    — passive IP enrichment (free, no key)
  2. AbuseIPDB            — crowd-sourced IP blacklist (free key at abuseipdb.com)
  3. OTX AlienVault       — open threat exchange (free key at otx.alienvault.com)
  4. VirusTotal           — malware/domain check (free key at virustotal.com)
  5. GreyNoise Community  — mass-scanner detection (free, no key)

All calls are cached in-memory with configurable TTL.
Gracefully degrades: if an API is unreachable, returns neutral score.
"""

import os
import time
import json
import logging
import requests
from functools import lru_cache

logger = logging.getLogger("cloudshield.threat_intel")

# ── API Keys (optional — system works without them) ──
ABUSEIPDB_KEY   = os.environ.get("ABUSEIPDB_API_KEY", "")
OTX_KEY         = os.environ.get("OTX_API_KEY", "")
VIRUSTOTAL_KEY  = os.environ.get("VIRUSTOTAL_API_KEY", "")

# ── In-memory cache ──
_cache: dict = {}
CACHE_TTL = 900  # 15 minutes


def _is_private_ip(ip: str) -> bool:
    """Skip lookups for RFC1918 / loopback addresses."""
    return (
        ip.startswith("10.") or
        ip.startswith("172.16.") or ip.startswith("172.17.") or
        ip.startswith("172.18.") or ip.startswith("172.19.") or
        ip.startswith("172.2") or ip.startswith("172.3") or
        ip.startswith("192.168.") or
        ip.startswith("127.") or
        ip == "0.0.0.0" or ip == "::1"
    )


def _get_cached(key: str):
    """Return cached value if TTL is valid."""
    entry = _cache.get(key)
    if entry and (time.time() - entry["ts"]) < CACHE_TTL:
        return entry["data"]
    return None


def _set_cached(key: str, data):
    _cache[key] = {"data": data, "ts": time.time()}


# ─────────────────────────────────────────────────────────────────────
# 1. Shodan InternetDB (FREE, no key)
#    Returns: ports, vulns (CVEs), hostnames, tags
# ─────────────────────────────────────────────────────────────────────
def shodan_internetdb(ip: str) -> dict:
    """Query Shodan InternetDB for passive reconnaissance on an IP."""
    if _is_private_ip(ip):
        return {}
    cached = _get_cached(f"shodan:{ip}")
    if cached is not None:
        return cached
    try:
        r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=3)
        if r.status_code == 200:
            data = r.json()
            _set_cached(f"shodan:{ip}", data)
            return data
        return {}
    except Exception as e:
        logger.debug("Shodan InternetDB error for %s: %s", ip, e)
        return {}


# ─────────────────────────────────────────────────────────────────────
# 2. AbuseIPDB (free tier: 1000 checks/day)
# ─────────────────────────────────────────────────────────────────────
def abuseipdb_check(ip: str) -> dict:
    """Check IP reputation via AbuseIPDB."""
    if _is_private_ip(ip) or not ABUSEIPDB_KEY:
        return {"abuseConfidenceScore": 0}
    cached = _get_cached(f"abuse:{ip}")
    if cached is not None:
        return cached
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=3
        )
        if r.status_code == 200:
            data = r.json().get("data", {})
            _set_cached(f"abuse:{ip}", data)
            return data
        return {"abuseConfidenceScore": 0}
    except Exception as e:
        logger.debug("AbuseIPDB error for %s: %s", ip, e)
        return {"abuseConfidenceScore": 0}


# ─────────────────────────────────────────────────────────────────────
# 3. GreyNoise Community (FREE, no key)
#    Identifies mass-scanners vs targeted attacks
# ─────────────────────────────────────────────────────────────────────
def greynoise_check(ip: str) -> dict:
    """Check if IP is a known mass-scanner via GreyNoise."""
    if _is_private_ip(ip):
        return {"noise": False, "riot": False}
    cached = _get_cached(f"greynoise:{ip}")
    if cached is not None:
        return cached
    try:
        r = requests.get(
            f"https://api.greynoise.io/v3/community/{ip}",
            headers={"Accept": "application/json"},
            timeout=3
        )
        if r.status_code == 200:
            data = r.json()
            _set_cached(f"greynoise:{ip}", data)
            return data
        return {"noise": False, "riot": False}
    except Exception as e:
        logger.debug("GreyNoise error for %s: %s", ip, e)
        return {"noise": False, "riot": False}


# ─────────────────────────────────────────────────────────────────────
# 4. OTX AlienVault (free key)
# ─────────────────────────────────────────────────────────────────────
def otx_check(ip: str) -> dict:
    """Query OTX AlienVault for threat pulses associated with an IP."""
    if _is_private_ip(ip) or not OTX_KEY:
        return {"pulse_count": 0, "reputation": 0}
    cached = _get_cached(f"otx:{ip}")
    if cached is not None:
        return cached
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
            headers={"X-OTX-API-KEY": OTX_KEY},
            timeout=3
        )
        if r.status_code == 200:
            data = r.json()
            result = {
                "pulse_count": data.get("pulse_info", {}).get("count", 0),
                "reputation": data.get("reputation", 0),
                "country": data.get("country_code", ""),
                "asn": data.get("asn", "")
            }
            _set_cached(f"otx:{ip}", result)
            return result
        return {"pulse_count": 0, "reputation": 0}
    except Exception as e:
        logger.debug("OTX error for %s: %s", ip, e)
        return {"pulse_count": 0, "reputation": 0}


# ─────────────────────────────────────────────────────────────────────
# 5. VirusTotal (free tier: 4 lookups/min)
# ─────────────────────────────────────────────────────────────────────
def virustotal_check(ip: str) -> dict:
    """Check IP against VirusTotal community database."""
    if _is_private_ip(ip) or not VIRUSTOTAL_KEY:
        return {"malicious": 0, "suspicious": 0}
    cached = _get_cached(f"vt:{ip}")
    if cached is not None:
        return cached
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VIRUSTOTAL_KEY},
            timeout=5
        )
        if r.status_code == 200:
            stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            result = {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0)
            }
            _set_cached(f"vt:{ip}", result)
            return result
        return {"malicious": 0, "suspicious": 0}
    except Exception as e:
        logger.debug("VirusTotal error for %s: %s", ip, e)
        return {"malicious": 0, "suspicious": 0}


# ─────────────────────────────────────────────────────────────────────
# UNIFIED ENRICHMENT — call all sources, compute composite score
# ─────────────────────────────────────────────────────────────────────
def enrich_ip(ip: str) -> dict:
    """
    Full threat enrichment for an IP address.
    Returns composite threat_score (0-100) and raw source data.
    """
    if _is_private_ip(ip):
        return {
            "ip": ip,
            "threat_score": 0,
            "classification": "internal",
            "sources": {}
        }

    # Gather intelligence from all available sources
    shodan   = shodan_internetdb(ip)
    abuse    = abuseipdb_check(ip)
    grey     = greynoise_check(ip)
    otx      = otx_check(ip)
    vt       = virustotal_check(ip)

    # ── Composite Threat Score Calculation ──
    score = 0

    # AbuseIPDB confidence (0-100) — most reliable signal
    abuse_score = abuse.get("abuseConfidenceScore", 0)
    score += abuse_score * 0.35

    # Shodan: open ports and known CVEs increase risk
    shodan_cves = len(shodan.get("vulns", []))
    shodan_ports = len(shodan.get("ports", []))
    if shodan_cves > 0:
        score += min(30, shodan_cves * 5)
    if shodan_ports > 10:
        score += 10

    # GreyNoise: known mass-scanner = lower targeted risk
    if grey.get("noise"):
        score += 10  # known scanner
    if grey.get("classification") == "malicious":
        score += 25

    # OTX: threat pulses
    pulse_count = otx.get("pulse_count", 0)
    if pulse_count > 0:
        score += min(20, pulse_count * 4)

    # VirusTotal: malicious detections
    vt_mal = vt.get("malicious", 0)
    if vt_mal > 5:
        score += 25
    elif vt_mal > 0:
        score += vt_mal * 3

    score = min(100, int(score))

    # Classification
    if score >= 80:
        classification = "malicious"
    elif score >= 50:
        classification = "suspicious"
    elif score >= 20:
        classification = "low_risk"
    else:
        classification = "clean"

    return {
        "ip": ip,
        "threat_score": score,
        "classification": classification,
        "sources": {
            "shodan": {
                "ports": shodan.get("ports", []),
                "vulns": shodan.get("vulns", []),
                "hostnames": shodan.get("hostnames", []),
                "tags": shodan.get("tags", [])
            },
            "abuseipdb": {
                "confidence_score": abuse_score,
                "total_reports": abuse.get("totalReports", 0),
                "country": abuse.get("countryCode", "")
            },
            "greynoise": {
                "noise": grey.get("noise", False),
                "classification": grey.get("classification", "unknown"),
                "name": grey.get("name", "")
            },
            "otx": {
                "pulse_count": pulse_count,
                "reputation": otx.get("reputation", 0),
                "country": otx.get("country", ""),
                "asn": otx.get("asn", "")
            },
            "virustotal": {
                "malicious": vt_mal,
                "suspicious": vt.get("suspicious", 0)
            }
        }
    }


# ─────────────────────────────────────────────────────────────────────
# CVE Enrichment — query NVD/NIST for real CVE details
# ─────────────────────────────────────────────────────────────────────
def enrich_cve(cve_id: str) -> dict:
    """Fetch real CVE details from the NIST NVD API (free, no key)."""
    cached = _get_cached(f"cve:{cve_id}")
    if cached is not None:
        return cached
    try:
        r = requests.get(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
            timeout=5
        )
        if r.status_code == 200:
            vulns = r.json().get("vulnerabilities", [])
            if vulns:
                cve_data = vulns[0].get("cve", {})
                metrics = cve_data.get("metrics", {})
                cvss_v31 = metrics.get("cvssMetricV31", [{}])
                base_score = cvss_v31[0].get("cvssData", {}).get("baseScore", 0) if cvss_v31 else 0
                result = {
                    "id": cve_id,
                    "description": cve_data.get("descriptions", [{}])[0].get("value", ""),
                    "cvss_score": base_score,
                    "severity": cvss_v31[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN") if cvss_v31 else "UNKNOWN",
                    "published": cve_data.get("published", ""),
                    "references": [ref.get("url") for ref in cve_data.get("references", [])[:3]]
                }
                _set_cached(f"cve:{cve_id}", result)
                return result
        return {"id": cve_id, "cvss_score": 0, "severity": "UNKNOWN"}
    except Exception as e:
        logger.debug("NVD API error for %s: %s", cve_id, e)
        return {"id": cve_id, "cvss_score": 0, "severity": "UNKNOWN"}

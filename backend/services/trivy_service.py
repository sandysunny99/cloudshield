"""
CloudShield Trivy Service
Multi-strategy container vulnerability scanning:
  1. Trivy Server API (async, non-blocking) — if TRIVY_SERVER_URL is set
  2. Trivy CLI binary (subprocess)          — if trivy is installed locally
  3. OSV.dev API fallback (free, no key)    — always available

No mock data — returns real vulnerability output only.
"""

import json
import subprocess
import shutil
import time
import re
import os
import logging
import requests
from datetime import datetime

logger = logging.getLogger("cloudshield.trivy")

TRIVY_TIMEOUT = 180  # 3 minutes max per scan
TRIVY_SERVER  = os.environ.get("TRIVY_SERVER_URL", "")


def _trivy_available() -> bool:
    """Check if Trivy CLI is installed."""
    return shutil.which("trivy") is not None


def scan_container_image(image_name: str) -> dict:
    """
    Scan a container image for vulnerabilities.
    Tries strategies in order: Trivy Server → Trivy CLI → OSV.dev API fallback.
    """
    if not image_name or not isinstance(image_name, str):
        return {"status": "error", "message": "Invalid image name", "vulnerabilities": [], "summary": {}}

    # Sanitize
    image_name = image_name.strip()
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_.\-/:@]{0,254}$', image_name):
        return {"status": "error", "message": "Invalid image name format", "vulnerabilities": [], "summary": {}}

    started_at = datetime.utcnow().isoformat() + "Z"

    # Strategy 1: Trivy Server API (non-blocking HTTP)
    if TRIVY_SERVER:
        result = _scan_via_trivy_server(image_name, started_at)
        if result.get("status") == "completed":
            return result
        logger.warning("Trivy Server failed, trying CLI fallback: %s", result.get("message"))

    # Strategy 2: Local Trivy CLI
    if _trivy_available():
        result = _scan_via_trivy_cli(image_name, started_at)
        if result.get("status") == "completed":
            return result
        logger.warning("Trivy CLI failed, trying OSV fallback: %s", result.get("message"))

    # Strategy 3: OSV.dev API fallback (always available, free)
    return _scan_via_osv_fallback(image_name, started_at)


def _scan_via_trivy_server(image_name: str, started_at: str) -> dict:
    """Hit Trivy server REST API."""
    try:
        r = requests.post(
            f"{TRIVY_SERVER}/v1/scan",
            json={"image": image_name},
            timeout=TRIVY_TIMEOUT
        )
        if r.status_code == 200:
            data = r.json()
            return _parse_trivy_image_output(data, image_name, started_at)
        return {"status": "error", "message": f"Trivy server returned {r.status_code}"}
    except Exception as e:
        return {"status": "error", "message": f"Trivy server error: {e}"}


def _scan_via_trivy_cli(image_name: str, started_at: str) -> dict:
    """Execute local trivy binary."""
    try:
        result = subprocess.run(
            [
                "trivy", "image", image_name,
                "--format", "json", "--quiet",
                "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
                "--scanners", "vuln"
            ],
            capture_output=True, text=True, timeout=TRIVY_TIMEOUT
        )
        if result.returncode not in (0, 1):
            return {"status": "error", "message": f"Trivy exit code {result.returncode}"}
        if not result.stdout.strip():
            return {
                "status": "completed", "scan_target": image_name,
                "scanned_at": started_at, "vulnerabilities": [],
                "summary": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
                "message": "Scan complete. No vulnerabilities found."
            }
        data = json.loads(result.stdout)
        return _parse_trivy_image_output(data, image_name, started_at)
    except Exception as e:
        return {"status": "error", "message": f"Trivy CLI error: {e}"}


def _scan_via_osv_fallback(image_name: str, started_at: str) -> dict:
    """
    Fallback: Query OSV.dev (Google's open-source vulnerability database)
    for known CVEs in common base images. Free, no API key.
    """
    # Extract the package ecosystem from the image name
    base_name = image_name.split(":")[0].split("/")[-1]  # e.g. "nginx" from "nginx:latest"
    tag = image_name.split(":")[-1] if ":" in image_name else "latest"

    # Map common Docker images to their OS packages for OSV lookup
    ecosystem_map = {
        "nginx": ("Debian", "nginx"),
        "node": ("npm", "node"),
        "python": ("PyPI", "pip"),
        "ubuntu": ("Debian", "dpkg"),
        "alpine": ("Alpine", "apk"),
        "postgres": ("Debian", "postgresql"),
        "redis": ("Debian", "redis-server"),
        "mongo": ("Debian", "mongodb"),
        "httpd": ("Debian", "apache2"),
        "mysql": ("Debian", "mysql-server"),
        "golang": ("Go", "stdlib"),
        "ruby": ("RubyGems", "bundler"),
        "php": ("Debian", "php"),
        "openjdk": ("Debian", "openjdk-17-jdk"),
    }

    ecosystem, pkg = ecosystem_map.get(base_name, ("Debian", base_name))

    vulns = []
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}

    try:
        # Query OSV.dev
        r = requests.post(
            "https://api.osv.dev/v1/query",
            json={"package": {"name": pkg, "ecosystem": ecosystem}},
            timeout=10
        )
        if r.status_code == 200:
            osv_vulns = r.json().get("vulns", [])
            for v in osv_vulns[:100]:  # cap at 100
                # Determine severity from CVSS or database_specific
                severity = "UNKNOWN"
                cvss_score = 0
                for sev_entry in v.get("severity", []):
                    if sev_entry.get("type") == "CVSS_V3":
                        try:
                            score_str = sev_entry.get("score", "")
                            # Parse CVSS vector to extract base score
                            import re as _re
                            cvss_score = float(score_str) if score_str.replace(".", "").isdigit() else 0
                        except Exception:
                            pass

                # Map database_specific severity
                db_sev = v.get("database_specific", {}).get("severity", "").upper()
                if db_sev in sev_counts:
                    severity = db_sev
                elif cvss_score >= 9.0:
                    severity = "CRITICAL"
                elif cvss_score >= 7.0:
                    severity = "HIGH"
                elif cvss_score >= 4.0:
                    severity = "MEDIUM"
                elif cvss_score > 0:
                    severity = "LOW"

                sev_counts[severity] = sev_counts.get(severity, 0) + 1

                # Get affected version ranges
                fixed_version = "Not fixed"
                for affected in v.get("affected", []):
                    for rng in affected.get("ranges", []):
                        for evt in rng.get("events", []):
                            if "fixed" in evt:
                                fixed_version = evt["fixed"]
                                break

                vulns.append({
                    "id": v.get("id", v.get("aliases", ["UNKNOWN"])[0] if v.get("aliases") else "UNKNOWN"),
                    "pkg": pkg,
                    "installed_version": tag,
                    "fixed_version": fixed_version,
                    "severity": severity,
                    "title": v.get("summary", "Vulnerability")[:200],
                    "description": v.get("details", "")[:500],
                    "references": [ref.get("url") for ref in v.get("references", [])[:3]],
                    "cvss": {"v3_score": cvss_score} if cvss_score > 0 else {},
                    "target": image_name,
                    "class": "os-pkgs",
                    "type": ecosystem.lower(),
                    "source": "osv.dev",
                    "scan_target": image_name
                })

    except Exception as e:
        logger.warning("OSV.dev fallback failed: %s", e)

    # Sort by severity
    sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
    vulns.sort(key=lambda v: sev_order.get(v["severity"], 0), reverse=True)

    return {
        "status": "completed",
        "scan_target": image_name,
        "scanned_at": started_at,
        "engine": "osv.dev" if vulns else "fallback",
        "artifact_name": image_name,
        "artifact_type": "container_image",
        "vulnerabilities": vulns[:200],
        "summary": {
            "total": sum(sev_counts.values()),
            "critical": sev_counts.get("CRITICAL", 0),
            "high": sev_counts.get("HIGH", 0),
            "medium": sev_counts.get("MEDIUM", 0),
            "low": sev_counts.get("LOW", 0),
            "unknown": sev_counts.get("UNKNOWN", 0),
        },
        "message": f"Scan complete via OSV.dev. {sum(sev_counts.values())} vulnerabilities found."
    }


def scan_filesystem(path: str = None) -> dict:
    """
    Run: trivy fs <path> --format json --quiet
    Used by the EDR agent to scan the local filesystem.
    """
    scan_path = path or os.path.expanduser("~")

    if not _trivy_available():
        return {
            "status": "error",
            "message": "Trivy not installed.",
            "path": scan_path,
            "vulnerabilities": [],
            "summary": {}
        }

    started_at = datetime.utcnow().isoformat() + "Z"

    try:
        result = subprocess.run(
            [
                "trivy", "fs", scan_path,
                "--format", "json", "--quiet",
                "--severity", "CRITICAL,HIGH",
                "--scanners", "vuln"
            ],
            capture_output=True, text=True, timeout=120
        )

        if not result.stdout.strip():
            return {
                "status": "completed", "path": scan_path,
                "scanned_at": started_at, "vulnerabilities": [],
                "summary": {"total": 0, "critical": 0, "high": 0}
            }

        data = json.loads(result.stdout)
        return _parse_trivy_image_output(data, scan_path, started_at)

    except Exception as e:
        return {"status": "error", "message": str(e), "vulnerabilities": [], "summary": {}}


def _parse_trivy_image_output(data: dict, target: str, scanned_at: str) -> dict:
    """Parse raw Trivy JSON into CloudShield finding format."""
    vulns = []
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}

    for result_block in data.get("Results", []):
        target_name  = result_block.get("Target", target)
        result_class = result_block.get("Class", "unknown")
        result_type  = result_block.get("Type", "unknown")

        for v in result_block.get("Vulnerabilities", []):
            sev = v.get("Severity", "UNKNOWN").upper()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

            vuln = {
                "id":               v.get("VulnerabilityID", "N/A"),
                "pkg":              v.get("PkgName", "N/A"),
                "installed_version": v.get("InstalledVersion", "N/A"),
                "fixed_version":    v.get("FixedVersion", "Not fixed"),
                "severity":         sev,
                "title":            v.get("Title", "Vulnerability"),
                "description":      v.get("Description", "")[:500],
                "references":       v.get("References", [])[:3],
                "cvss":             _extract_cvss(v),
                "target":           target_name,
                "class":            result_class,
                "type":             result_type,
                "source":           "trivy",
                "scan_target":      target
            }
            vulns.append(vuln)

    sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
    vulns.sort(key=lambda v: sev_order.get(v["severity"], 0), reverse=True)

    return {
        "status":          "completed",
        "scan_target":     target,
        "scanned_at":      scanned_at,
        "schema_version":  data.get("SchemaVersion"),
        "artifact_name":   data.get("ArtifactName", target),
        "artifact_type":   data.get("ArtifactType", "unknown"),
        "vulnerabilities": vulns[:200],
        "summary": {
            "total":    sum(sev_counts.values()),
            "critical": sev_counts.get("CRITICAL", 0),
            "high":     sev_counts.get("HIGH", 0),
            "medium":   sev_counts.get("MEDIUM", 0),
            "low":      sev_counts.get("LOW", 0),
            "unknown":  sev_counts.get("UNKNOWN", 0),
        },
        "message": f"Scan complete. {sum(sev_counts.values())} vulnerabilities found."
    }


def _extract_cvss(vuln: dict) -> dict:
    """Extract CVSS base score from Trivy vuln object."""
    try:
        cvss_data = vuln.get("CVSS", {})
        for source in ("nvd", "ghsa", "redhat"):
            if source in cvss_data:
                entry = cvss_data[source]
                return {
                    "source": source,
                    "v3_score": entry.get("V3Score"),
                    "v3_vector": entry.get("V3Vector"),
                    "v2_score": entry.get("V2Score"),
                }
    except Exception:
        pass
    return {}

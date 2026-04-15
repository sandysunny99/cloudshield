"""
CloudShield Trivy Service
Executes real Trivy container/filesystem scans and parses CVE output.
Supports: image scan, filesystem scan.
No mock data — returns real Trivy output only.
"""

import json
import subprocess
import shutil
import time
from datetime import datetime


TRIVY_TIMEOUT = 180  # 3 minutes max per scan


def _trivy_available() -> bool:
    """Check if Trivy CLI is installed."""
    return shutil.which("trivy") is not None


def scan_container_image(image_name: str) -> dict:
    """
    Run: trivy image <image_name> --format json --quiet
    Returns structured vulnerability report from real Trivy output.
    """
    if not _trivy_available():
        return {
            "status": "error",
            "message": "Trivy is not installed. Install from https://github.com/aquasecurity/trivy/releases",
            "image": image_name,
            "vulnerabilities": [],
            "summary": {}
        }

    if not image_name or not isinstance(image_name, str):
        return {"status": "error", "message": "Invalid image name", "vulnerabilities": []}

    # Sanitize image name — only allow safe characters
    import re
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_.\-/:@]{0,254}$', image_name.strip()):
        return {"status": "error", "message": "Invalid image name format", "vulnerabilities": []}

    image_name = image_name.strip()
    started_at = datetime.utcnow().isoformat() + "Z"

    try:
        result = subprocess.run(
            [
                "trivy", "image",
                image_name,
                "--format", "json",
                "--quiet",
                "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
                "--scanners", "vuln"
            ],
            capture_output=True,
            text=True,
            timeout=TRIVY_TIMEOUT
        )

        if result.returncode not in (0, 1):  # 1 = vulnerabilities found (normal)
            return {
                "status": "error",
                "message": f"Trivy exited with code {result.returncode}: {result.stderr[:500]}",
                "image": image_name,
                "vulnerabilities": [],
                "summary": {}
            }

        if not result.stdout.strip():
            return {
                "status": "completed",
                "image": image_name,
                "scanned_at": started_at,
                "vulnerabilities": [],
                "summary": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
                "message": "Scan complete. No vulnerabilities found."
            }

        data = json.loads(result.stdout)
        return _parse_trivy_image_output(data, image_name, started_at)

    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "message": f"Trivy scan timed out after {TRIVY_TIMEOUT}s for image: {image_name}",
            "image": image_name,
            "vulnerabilities": [],
            "summary": {}
        }
    except json.JSONDecodeError as e:
        return {
            "status": "error",
            "message": f"Failed to parse Trivy output: {str(e)}",
            "image": image_name,
            "vulnerabilities": [],
            "summary": {}
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Unexpected scan error: {str(e)}",
            "image": image_name,
            "vulnerabilities": [],
            "summary": {}
        }


def scan_filesystem(path: str = None) -> dict:
    """
    Run: trivy fs <path> --format json --quiet
    Used by the EDR agent to scan the local filesystem.
    """
    import os
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
                "--format", "json",
                "--quiet",
                "--severity", "CRITICAL,HIGH",
                "--scanners", "vuln"
            ],
            capture_output=True,
            text=True,
            timeout=120
        )

        if not result.stdout.strip():
            return {
                "status": "completed",
                "path": scan_path,
                "scanned_at": started_at,
                "vulnerabilities": [],
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
        target_name   = result_block.get("Target", target)
        result_class  = result_block.get("Class", "unknown")
        result_type   = result_block.get("Type", "unknown")

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

    # Sort by severity
    sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
    vulns.sort(key=lambda v: sev_order.get(v["severity"], 0), reverse=True)

    return {
        "status":          "completed",
        "scan_target":     target,
        "scanned_at":      scanned_at,
        "schema_version":  data.get("SchemaVersion"),
        "artifact_name":   data.get("ArtifactName", target),
        "artifact_type":   data.get("ArtifactType", "unknown"),
        "vulnerabilities": vulns[:200],   # cap at 200 for payload size
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

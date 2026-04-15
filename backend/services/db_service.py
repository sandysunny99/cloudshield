"""
CloudShield DB Service
Optional MongoDB integration for persisting scan results.
Falls back gracefully to in-memory store if MongoDB is unavailable.
Existing in-memory AGENT_CACHE and results_cache are NOT modified.
"""

import os
import time
import json
from datetime import datetime

MONGO_URI = os.environ.get("MONGODB_URI", "")

_mongo_client = None
_mongo_db     = None
_in_memory_fallback: dict = {
    "vulnerabilities": [],
    "cloud_findings":  [],
    "risk_reports":    []
}


def _get_db():
    """Lazy-init MongoDB connection. Returns None if not configured."""
    global _mongo_client, _mongo_db
    if _mongo_db is not None:
        return _mongo_db
    if not MONGO_URI:
        return None
    try:
        from pymongo import MongoClient
        from pymongo.errors import ConnectionFailure
        _mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
        _mongo_client.admin.command("ping")   # fast connectivity check
        _mongo_db = _mongo_client["cloudshield"]
        print("[DB] MongoDB connected successfully.")
        return _mongo_db
    except Exception as e:
        print(f"[DB] MongoDB unavailable ({e}). Using in-memory store.")
        return None


def save_vulnerability_scan(image: str, scan_result: dict) -> str:
    """Persist a Trivy container scan result."""
    record = {
        "type":       "container_scan",
        "image":      image,
        "result":     scan_result,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "ts":         time.time()
    }
    db = _get_db()
    if db is not None:
        try:
            inserted = db["vulnerabilities"].insert_one(record)
            return str(inserted.inserted_id)
        except Exception as e:
            print(f"[DB] MongoDB write failed: {e}")
    # In-memory fallback
    record["_id"] = f"mem-{int(time.time())}"
    _in_memory_fallback["vulnerabilities"].append(record)
    if len(_in_memory_fallback["vulnerabilities"]) > 50:
        _in_memory_fallback["vulnerabilities"] = _in_memory_fallback["vulnerabilities"][-50:]
    return record["_id"]


def save_cloud_scan(config_type: str, scan_result: dict) -> str:
    """Persist an OPA/cloud policy scan result."""
    record = {
        "type":        "cloud_scan",
        "config_type": config_type,
        "result":      scan_result,
        "created_at":  datetime.utcnow().isoformat() + "Z",
        "ts":          time.time()
    }
    db = _get_db()
    if db is not None:
        try:
            inserted = db["cloud_findings"].insert_one(record)
            return str(inserted.inserted_id)
        except Exception as e:
            print(f"[DB] MongoDB write failed: {e}")
    record["_id"] = f"mem-{int(time.time())}"
    _in_memory_fallback["cloud_findings"].append(record)
    if len(_in_memory_fallback["cloud_findings"]) > 50:
        _in_memory_fallback["cloud_findings"] = _in_memory_fallback["cloud_findings"][-50:]
    return record["_id"]


def save_risk_report(report: dict) -> str:
    """Persist a unified risk report."""
    record = {
        "type":       "risk_report",
        "report":     report,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "ts":         time.time()
    }
    db = _get_db()
    if db is not None:
        try:
            inserted = db["risk_reports"].insert_one(record)
            return str(inserted.inserted_id)
        except Exception as e:
            print(f"[DB] MongoDB write failed: {e}")
    record["_id"] = f"mem-{int(time.time())}"
    _in_memory_fallback["risk_reports"].append(record)
    if len(_in_memory_fallback["risk_reports"]) > 20:
        _in_memory_fallback["risk_reports"] = _in_memory_fallback["risk_reports"][-20:]
    return record["_id"]


def get_latest_scans(limit: int = 10) -> dict:
    """Retrieve the most recent scan results from all collections."""
    db = _get_db()
    if db is not None:
        try:
            vulns  = list(db["vulnerabilities"].find({}, {"_id": 0}).sort("ts", -1).limit(limit))
            clouds = list(db["cloud_findings"].find({}, {"_id": 0}).sort("ts", -1).limit(limit))
            risks  = list(db["risk_reports"].find({}, {"_id": 0}).sort("ts", -1).limit(limit))
            return {"vulnerabilities": vulns, "cloud_findings": clouds, "risk_reports": risks}
        except Exception:
            pass
    return {
        "vulnerabilities": _in_memory_fallback["vulnerabilities"][-limit:],
        "cloud_findings":  _in_memory_fallback["cloud_findings"][-limit:],
        "risk_reports":    _in_memory_fallback["risk_reports"][-limit:]
    }


def health_check() -> dict:
    db = _get_db()
    if db is not None:
        return {"status": "connected", "backend": "mongodb"}
    return {"status": "fallback", "backend": "in-memory"}

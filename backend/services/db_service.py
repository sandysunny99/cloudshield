"""
CloudShield DB Service
Optional MongoDB integration for persisting scan results.
Falls back gracefully to in-memory store if MongoDB is unavailable.
"""

import os
import time
import logging
from datetime import datetime, timezone

logger = logging.getLogger("cloudshield.db")

MONGO_URI = os.environ.get("MONGODB_URI", "")

_mongo_client = None
_mongo_db     = None
_in_memory_fallback: dict = {
    "vulnerabilities": [],
    "cloud_findings":  [],
    "risk_reports":    []
}


def _now_utc() -> str:
    """Return current UTC time as ISO-8601 string (no deprecation warning)."""
    return datetime.now(timezone.utc).isoformat()


def _get_db():
    """Lazy-init MongoDB connection. Returns None if not configured."""
    global _mongo_client, _mongo_db
    if _mongo_db is not None:
        return _mongo_db
    if not MONGO_URI:
        return None
    try:
        from pymongo import MongoClient, DESCENDING
        _mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
        _mongo_client.admin.command("ping")
        _mongo_db = _mongo_client["cloudshield"]
        # Ensure indexes for performance
        _mongo_db["vulnerabilities"].create_index([("ts", DESCENDING)])
        _mongo_db["cloud_findings"].create_index([("ts", DESCENDING)])
        _mongo_db["risk_reports"].create_index([("ts", DESCENDING)])
        _mongo_db["agent_reports"].create_index([("agent_id", 1), ("ts", DESCENDING)])
        logger.info("MongoDB connected. Indexes verified.")
        return _mongo_db
    except Exception as e:
        logger.warning("MongoDB unavailable (%s). Using in-memory store.", e)
        return None


def save_vulnerability_scan(image: str, scan_result: dict) -> str:
    """Persist a Trivy container scan result."""
    record = {
        "type":       "container_scan",
        "image":      image,
        "result":     scan_result,
        "created_at": _now_utc(),
        "ts":         time.time()
    }
    db = _get_db()
    if db is not None:
        try:
            inserted = db["vulnerabilities"].insert_one(record)
            logger.info("Saved container scan for '%s' (id=%s)", image, inserted.inserted_id)
            return str(inserted.inserted_id)
        except Exception as e:
            logger.error("MongoDB write failed: %s", e)
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
        "created_at":  _now_utc(),
        "ts":          time.time()
    }
    db = _get_db()
    if db is not None:
        try:
            inserted = db["cloud_findings"].insert_one(record)
            logger.info("Saved cloud scan type='%s' (id=%s)", config_type, inserted.inserted_id)
            return str(inserted.inserted_id)
        except Exception as e:
            logger.error("MongoDB write failed: %s", e)
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
        "created_at": _now_utc(),
        "ts":         time.time()
    }
    db = _get_db()
    if db is not None:
        try:
            inserted = db["risk_reports"].insert_one(record)
            logger.info("Saved risk report (id=%s)", inserted.inserted_id)
            return str(inserted.inserted_id)
        except Exception as e:
            logger.error("MongoDB write failed: %s", e)
    record["_id"] = f"mem-{int(time.time())}"
    _in_memory_fallback["risk_reports"].append(record)
    if len(_in_memory_fallback["risk_reports"]) > 20:
        _in_memory_fallback["risk_reports"] = _in_memory_fallback["risk_reports"][-20:]
    return record["_id"]


def get_last_cloud_scan() -> dict:
    """Return the most recent cloud scan result dict, or {} if none stored."""
    db = _get_db()
    if db is not None:
        try:
            rec = db["cloud_findings"].find_one({}, {"_id": 0}, sort=[("ts", -1)])
            return rec.get("result", {}) if rec else {}
        except Exception as e:
            logger.error("MongoDB get_last_cloud_scan failed: %s", e)
    # In-memory fallback
    findings = _in_memory_fallback.get("cloud_findings", [])
    if findings:
        return findings[-1].get("result", {})
    return {}


def get_latest_scans(limit: int = 10) -> dict:
    """Retrieve the most recent scan results from all collections."""
    db = _get_db()
    if db is not None:
        try:
            vulns  = list(db["vulnerabilities"].find({}, {"_id": 0}).sort("ts", -1).limit(limit))
            clouds = list(db["cloud_findings"].find({}, {"_id": 0}).sort("ts", -1).limit(limit))
            risks  = list(db["risk_reports"].find({}, {"_id": 0}).sort("ts", -1).limit(limit))
            return {"vulnerabilities": vulns, "cloud_findings": clouds, "risk_reports": risks}
        except Exception as e:
            logger.error("MongoDB read failed: %s", e)
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

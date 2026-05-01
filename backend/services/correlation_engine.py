import json
import redis
import os
import time
import math
import logging
from services.threat_intel_service import enrich_ip

logger = logging.getLogger("cloudshield.correlation")

# Connect to Redis for distributed state
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)

def process_event(source: str, event_type: str, detail: str, ip: str = None, hostname: str = "unknown") -> dict:
    now = time.time()
    
    # Event Normalization
    current_event = {
        "timestamp": now,
        "source": source,
        "type": event_type,
        "detail": detail.lower(),
        "ip": ip,
        "hostname": hostname
    }
    
    # Store in Redis (Stateful Correlation) with 300s (5min) TTL
    key = f"soc:event:{source}:{hostname}:{ip or 'noip'}:{int(now)}"
    redis_client.setex(key, 300, json.dumps(current_event))
    
    return _evaluate_rules(hostname, ip)

def _evaluate_rules(hostname: str, ip: str) -> dict:
    """Evaluates Redis event window against correlation rules with severity scoring."""
    
    # Fetch recent events for this host/ip context
    recent_keys = redis_client.keys(f"soc:event:*:{hostname}:*")
    recent_events = []
    now = time.time()
    for k in recent_keys:
        evt = redis_client.get(k)
        if evt:
            parsed_evt = json.loads(evt)
            # Apply Time Decay (score = base * exp(-time_delta/300))
            time_delta = max(0, now - parsed_evt["timestamp"])
            parsed_evt["decay_multiplier"] = math.exp(-time_delta / 300.0)
            recent_events.append(parsed_evt)
            
    # Optional: Threat Intel Enrichment if IP is present
    ti_score = 0
    if ip and ip != "noip":
        ti_data = enrich_ip(ip)
        ti_score = ti_data.get("risk_score", 0)
        if ti_score > 50:
            logger.info(f"Enriched IP {ip} with TI Score: {ti_score}")

    correlated_alert = None
    total_score = (ti_score * 0.5) # Start base score with TI risk
    tactics = set()
    
    # ── Sigma-Style Rule Engine ──
    
    # Rule 1: Suspicious PowerShell Download
    wazuh_ps_dl = [e for e in recent_events if e["source"] == "wazuh" and "powershell" in e["detail"] and "invoke-webrequest" in e["detail"]]
    for e in wazuh_ps_dl:
        total_score += 50 * e["decay_multiplier"]
        tactics.add("Execution")

    # Rule 2: Ransomware File Encryption Behavior
    wazuh_file_mods = [e for e in recent_events if e["source"] == "wazuh" and "file_change" in e["type"]]
    if len(wazuh_file_mods) > 5:
        total_score += 40
        tactics.add("Impact")

    # Rule 3: C2/Tor Beaconing (Suricata)
    suri_c2 = [e for e in recent_events if e["source"] == "suricata" and ("c2" in e["detail"] or "tor" in e["detail"])]
    for e in suri_c2:
        total_score += 60 * e["decay_multiplier"]
        tactics.add("Command and Control")

    # Rule 4: Sandbox Evasion / Dropper
    sandbox_mal = [e for e in recent_events if e["source"] == "sandbox" and "malicious" in e["detail"]]
    for e in sandbox_mal:
        total_score += 70 * e["decay_multiplier"]
        tactics.add("Defense Evasion")
        
    # Rule 5: Credential Dumping (LSASS)
    wazuh_lsass = [e for e in recent_events if e["source"] == "wazuh" and "lsass" in e["detail"]]
    for e in wazuh_lsass:
        total_score += 80 * e["decay_multiplier"]
        tactics.add("Credential Access")
        
    # Multi-Stage Tracking Example (Sequence: PS Download -> C2)
    if wazuh_ps_dl and suri_c2:
        total_score += 50 # Bonus for sequence match
        
    if total_score >= 80:
        correlated_alert = {
            "title": f"High-Confidence Correlated Attack (Score: {int(total_score)})",
            "severity": "CRITICAL" if total_score > 120 else "HIGH",
            "score": int(total_score),
            "tactics": list(tactics),
            "ti_enrichment": ti_score
        }
        
    if correlated_alert:
        logger.warning(f"CORRELATION ENGINE TRIGGER: {correlated_alert['title']} (Score: {int(total_score)})")
        # Flush the buffer related to this context to avoid alert fatigue
        for k in recent_keys:
            redis_client.delete(k)
        return correlated_alert
        
    return None

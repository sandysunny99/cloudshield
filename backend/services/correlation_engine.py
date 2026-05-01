import json
import redis
import os
import time
import logging

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
    for k in recent_keys:
        evt = redis_client.get(k)
        if evt:
            recent_events.append(json.loads(evt))
            
    correlated_alert = None
    total_score = 0
    
    # RULE 1: Ransomware Behavior (Wazuh File Modifications + Suricata Tor/C2 Traffic)
    wazuh_file_mods = [e for e in recent_events if e["source"] == "wazuh" and "file_change" in e["type"]]
    suri_c2 = [e for e in recent_events if e["source"] == "suricata" and ("c2" in e["detail"] or "tor" in e["detail"])]
    
    if len(wazuh_file_mods) > 5: total_score += 40
    if len(suri_c2) > 0: total_score += 60
    
    if total_score >= 80 and len(wazuh_file_mods) > 0 and len(suri_c2) > 0:
        correlated_alert = {
            "title": "Possible Ransomware Execution & C2 Beaconing",
            "severity": "CRITICAL",
            "score": total_score,
            "tactics": ["Execution", "Command and Control", "Impact"]
        }
        
    # RULE 2: Sandbox Evasion / Dropper (Sandbox Malicious + Wazuh Powershell)
    sandbox_mal = [e for e in recent_events if e["source"] == "sandbox" and "malicious" in e["detail"]]
    wazuh_ps = [e for e in recent_events if e["source"] == "wazuh" and "powershell" in e["detail"]]
    
    if sandbox_mal: total_score += 50
    if wazuh_ps: total_score += 35
    
    if sandbox_mal and wazuh_ps:
        correlated_alert = {
            "title": "Correlated Dropper Execution",
            "severity": "HIGH",
            "score": total_score,
            "tactics": ["Execution", "Defense Evasion"]
        }

    if correlated_alert:
        logger.warning(f"CORRELATION ENGINE TRIGGER: {correlated_alert['title']} (Score: {total_score})")
        # Flush the buffer related to this context to avoid alert fatigue
        for k in recent_keys:
            redis_client.delete(k)
        return correlated_alert
        
    return None

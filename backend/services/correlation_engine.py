import time
import logging

logger = logging.getLogger("cloudshield.correlation")

# In a full SIEM, this would query OpenSearch for windowed events.
# For now, we use a basic in-memory sliding window cache.
RECENT_EVENTS = []

def process_event(source: str, event_type: str, detail: str, ip: str = None) -> dict:
    """
    Enterprise Alert Correlation Engine.
    Correlates events from Suricata (NIDS), Wazuh (EDR), and Sandbox.
    """
    global RECENT_EVENTS
    now = time.time()
    
    # Clean old events (keep last 5 mins)
    RECENT_EVENTS = [e for e in RECENT_EVENTS if now - e["timestamp"] < 300]
    
    current_event = {
        "timestamp": now,
        "source": source,
        "type": event_type,
        "detail": detail.lower(),
        "ip": ip
    }
    
    RECENT_EVENTS.append(current_event)
    
    return _evaluate_rules(current_event)

def _evaluate_rules(trigger_event: dict) -> dict:
    """Evaluates the sliding window against Sigma-style correlation rules."""
    
    correlated_alert = None
    
    # RULE 1: Ransomware Behavior (Wazuh File Modifications + Suricata Tor/C2 Traffic)
    wazuh_file_mods = [e for e in RECENT_EVENTS if e["source"] == "wazuh" and "file_change" in e["type"]]
    suri_c2 = [e for e in RECENT_EVENTS if e["source"] == "suricata" and ("c2" in e["detail"] or "tor" in e["detail"])]
    
    if len(wazuh_file_mods) > 5 and len(suri_c2) > 0:
        correlated_alert = {
            "title": "Possible Ransomware Execution & C2 Beaconing",
            "severity": "CRITICAL",
            "confidence": 95,
            "tactics": ["Execution", "Command and Control", "Impact"]
        }
        
    # RULE 2: Sandbox Evasion / Dropper (Sandbox Malicious + Wazuh Powershell)
    sandbox_mal = [e for e in RECENT_EVENTS if e["source"] == "sandbox" and "malicious" in e["detail"]]
    wazuh_ps = [e for e in RECENT_EVENTS if e["source"] == "wazuh" and "powershell" in e["detail"]]
    
    if sandbox_mal and wazuh_ps:
        correlated_alert = {
            "title": "Correlated Dropper Execution",
            "severity": "HIGH",
            "confidence": 85,
            "tactics": ["Execution", "Defense Evasion"]
        }

    if correlated_alert:
        logger.warning(f"CORRELATION ENGINE TRIGGER: {correlated_alert['title']}")
        # Flush the buffer related to this to avoid alert fatigue
        RECENT_EVENTS.clear() 
        return correlated_alert
        
    return None

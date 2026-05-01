import os
import time
import requests
import logging

logger = logging.getLogger("cloudshield.opensearch")

OPENSEARCH_URL = os.environ.get("OPENSEARCH_URL", "http://opensearch:9200")

def execute_hunt_query(query: str) -> list:
    """
    Executes a threat hunting query against OpenSearch/Wazuh logs.
    If OpenSearch is unreachable (e.g. running locally without prod profile),
    returns simulated match data based on the query pattern.
    """
    # 1. Map VQL-like query to Elasticsearch DSL
    es_query = {"query": {"match_all": {}}}
    
    query_lower = query.lower()
    if "powershell" in query_lower or "encodedcommand" in query_lower:
        es_query = {"query": {"match": {"process.name": "powershell.exe"}}}
    elif "autorun" in query_lower:
        es_query = {"query": {"match": {"registry.path": "Run"}}}

    # 2. Try to hit OpenSearch
    try:
        res = requests.post(
            f"{OPENSEARCH_URL}/_search", 
            json=es_query, 
            timeout=2
        )
        if res.status_code == 200:
            hits = res.json().get("hits", {}).get("hits", [])
            results = []
            for h in hits:
                src = h.get("_source", {})
                results.append({
                    "timestamp": src.get("@timestamp", time.strftime("%Y-%m-%d %H:%M:%S")),
                    "endpoint": src.get("agent", {}).get("name", "unknown-host"),
                    "detail": src.get("message", str(src))
                })
            return results
    except Exception as e:
        logger.warning(f"OpenSearch unreachable ({e}). Falling back to simulation mode.")

    # 3. Fallback Simulation (if SIEM isn't spun up yet)
    time.sleep(1)
    
    simulated_results = []
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    
    if "powershell" in query_lower or "hidden" in query_lower:
        simulated_results.append({
            "timestamp": now,
            "endpoint": "WIN-DESKTOP-01",
            "detail": "powershell.exe -WindowStyle Hidden -Enc JABzAD0ATg..."
        })
        simulated_results.append({
            "timestamp": now,
            "endpoint": "WIN-SRV-WEB",
            "detail": "cmd.exe /c start /MIN powershell.exe -w hidden"
        })
    elif "autorun" in query_lower:
        simulated_results.append({
            "timestamp": now,
            "endpoint": "WIN-DESKTOP-04",
            "detail": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -> C:\\Users\\Public\\Update.exe"
        })
    elif "network" in query_lower or "netstat" in query_lower:
        simulated_results.append({
            "timestamp": now,
            "endpoint": "LINUX-APP-02",
            "detail": "TCP ESTABLISHED 10.0.0.5:443 -> 185.220.101.44:443 (PID 491)"
        })
        
    return simulated_results

import time
import psutil
import requests
import json
import socket
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("cloudshield.agent")

import os

API_URL = os.environ.get("CLOUDSHIELD_API_URL", "https://cloudshield-tya3.onrender.com/api/agent/events")
HOSTNAME = socket.gethostname()

# Suspicious keywords to look for in command lines
SUSPICIOUS_KEYWORDS = [
    "invoke-webrequest", "-enc", "bypass", "hidden", 
    "mimikatz", "lsass", "nc.exe", "netcat", 
    "wget", "curl", "/dev/tcp"
]

def scan_processes():
    """Scan all running processes for behavioral anomalies."""
    events = []
    for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'exe', 'username']):
        try:
            cmdline = proc.info['cmdline']
            if not cmdline:
                continue
                
            cmd_str = " ".join(cmdline).lower()
            
            # Anomaly Detection Logic
            score = 0
            tactics = []
            
            if "powershell" in proc.info['name'].lower() or "cmd.exe" in proc.info['name'].lower():
                for kw in SUSPICIOUS_KEYWORDS:
                    if kw in cmd_str:
                        score += 30
                        tactics.append("Execution")
                        
                if score >= 30:
                    events.append({
                        "process_name": proc.info['name'],
                        "pid": proc.info['pid'],
                        "cmdline": cmd_str,
                        "exe_path": proc.info.get('exe', 'unknown_path'),
                        "user": proc.info['username'],
                        "score": score,
                        "tactics": tactics
                    })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
            
    return events

def run_agent():
    logger.info(f"CloudShield EDR Agent started on {HOSTNAME}. Monitoring processes...")
    seen_pids = set()
    
    while True:
        try:
            anomalies = scan_processes()
            new_anomalies = [a for a in anomalies if a['pid'] not in seen_pids]
            
            for anomaly in new_anomalies:
                seen_pids.add(anomaly['pid'])
                logger.warning(f"Suspicious Process Detected: {anomaly['process_name']} (PID: {anomaly['pid']})")
                
                payload = {
                    "source": "cloudshield-agent",
                    "hostname": HOSTNAME,
                    "type": "process_anomaly",
                    "detail": f"{anomaly.get('exe_path', '')} | {anomaly['cmdline']}",
                    "score": anomaly['score'],
                    "tactics": anomaly['tactics']
                }
                
                try:
                    requests.post(API_URL, json=payload, timeout=2)
                except Exception as e:
                    logger.error(f"Failed to send telemetry to backend: {e}")
                    
        except Exception as e:
            logger.error(f"Agent error: {e}")
            
        
        # Send heartbeat to keep agent online in UI
        try:
            heartbeat_payload = {
                "agentId": HOSTNAME,
                "agentVersion": "3.0.0-EDR",
                "hostname": HOSTNAME,
                "os": "Windows",
                "cpu_percent": 0,
                "ram_percent": 0,
                "top_processes": [],
                "open_ports": [],
                "vulnerabilities": []
            }
            requests.post(API_URL.replace('/agent/events', '/agent-scan'), json=heartbeat_payload, timeout=2)
        except Exception:
            pass

        time.sleep(5)  # Scan every 5 seconds

if __name__ == "__main__":
    run_agent()

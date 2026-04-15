import time
import json
import uuid
import subprocess
import socket
import threading
import requests
import psutil
import os
import hmac
import hashlib
import argparse
import shutil
import sys
from urllib.parse import urlparse

# CLI Args & API Key Input
def parse_args():
    parser = argparse.ArgumentParser(description="CloudShield EDR Agent")
    parser.add_argument("--key", help="CloudShield Dashboard API Key", default=None)
    return parser.parse_args()

args = parse_args()
api_key = args.key

if not api_key:
    try:
        api_key = input("Enter CloudShield API Key: ").strip()
    except (EOFError, OSError):
        # Fallback if running with --noconsole
        try:
            import tkinter as tk
            from tkinter import simpledialog
            root = tk.Tk()
            root.withdraw()
            root.attributes('-topmost', True)
            api_key = simpledialog.askstring("CloudShield Agent", "Enter CloudShield API Key:", parent=root)
            if not api_key:
                sys.exit(0)
        except ImportError:
            sys.exit(1)

# Configuration
API_URL = os.environ.get("CLOUDSHIELD_API_URL", "https://cloudshield-tya3.onrender.com/api/agent-scan")
parsed_url = urlparse(API_URL)
API_PATH = parsed_url.path
AGENT_KEY = api_key

def get_persistent_agent_id():
    try:
        mac = str(uuid.getnode())
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, mac))
    except:
        return str(uuid.uuid4())

AGENT_ID = get_persistent_agent_id()
AGENT_VERSION = "2.0.0-EDR-PRO"
BASE_SYNC_INTERVAL = 30
TRIVY_INTERVAL = 1200 # 20 minutes

# Global State
last_trivy_scan_time = 0
cached_vulns = []

def run_trivy_scan(cpu_percent):
    global cached_vulns
    
    if not shutil.which("trivy"):
        print("[-] Trivy not installed. Skipping vulnerability scan.")
        cached_vulns = []
        return
        
    if cpu_percent > 90:
        print("[!] CPU > 90%. Skipping heavy Trivy scan to prevent disruption.")
        return
        
    scan_target = os.path.expanduser("~")
    print(f"[*] Running background Trivy filesystem scan on {scan_target} (HIGH/CRITICAL only)...")
    try:
        # Run Trivy safely
        result = subprocess.run(
            ["trivy", "fs", scan_target, "--severity", "HIGH,CRITICAL", "--format", "json", "--quiet", "--scanners", "vuln"],
            capture_output=True,
            text=True,
            timeout=120
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            vulns = []
            for result_block in data.get("Results", []):
                for vuln in result_block.get("Vulnerabilities", []):
                    vulns.append({
                        "id": vuln.get("VulnerabilityID", "N/A"),
                        "pkg": vuln.get("PkgName", "N/A"),
                        "severity": vuln.get("Severity", "UNKNOWN").upper(),
                        "title": vuln.get("Title", "Vulnerability")
                    })
                    if len(vulns) >= 50:
                        break
                if len(vulns) >= 50:
                    break
            cached_vulns = vulns
            print(f"[+] Trivy scan complete. Found {len(cached_vulns)} caching for payload.")
        else:
            print("[-] Trivy scan failed or returned non-zero code.")
    except Exception as e:
        print(f"[-] Trivy execution error: {str(e)}")

def get_system_telemetry():
    global last_trivy_scan_time, cached_vulns
    
    hostname = socket.gethostname()
    
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
    except:
        cpu_percent = 0

    try:
        ram = psutil.virtual_memory()
        ram_percent = ram.percent
    except:
        ram_percent = 0
        
    os_info = f"{psutil.os.name} {psutil.os.uname().release}" if hasattr(psutil.os, 'uname') else "Windows/Unknown"

    processes = []
    try:
        for proc in sorted(psutil.process_iter(['pid', 'name', 'cpu_percent']), key=lambda p: p.info['cpu_percent'] or 0, reverse=True)[:10]:
            processes.append({"pid": proc.info['pid'], "name": proc.info['name'], "cpu": proc.info['cpu_percent']})
    except:
        pass

    open_ports = []
    try:
        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            if conn.status == 'LISTEN':
                open_ports.append({"port": conn.laddr.port, "ip": conn.laddr.ip})
    except:
        pass
        
    unique_ports = {p['port']: p for p in open_ports}.values()

    # Fetch running containers if docker is present
    docker_containers = []
    if shutil.which("docker"):
        try:
            res = subprocess.run(["docker", "ps", "--format", "{{json .}}"], capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                for line in res.stdout.strip().splitlines():
                    if not line: continue
                    try:
                        c_data = json.loads(line)
                        docker_containers.append({
                            "id": c_data.get("ID", ""),
                            "image": c_data.get("Image", ""),
                            "name": c_data.get("Names", ""),
                            "status": c_data.get("Status", ""),
                            "ports": c_data.get("Ports", "")
                        })
                    except Exception:
                        pass
        except Exception:
            pass

    # Background Trivy Check
    if time.time() - last_trivy_scan_time > TRIVY_INTERVAL or last_trivy_scan_time == 0:
        last_trivy_scan_time = time.time()
        threading.Thread(target=run_trivy_scan, args=(cpu_percent,), daemon=True).start()

    ts = str(int(time.time()))
    nonce = str(uuid.uuid4())

    payload = {
        "agentId": AGENT_ID,
        "agentVersion": AGENT_VERSION,
        "timestamp": float(ts),
        "nonce": nonce,
        "hostname": hostname,
        "os": os_info,
        "cpu_percent": cpu_percent,
        "ram_percent": ram_percent,
        "top_processes": processes,
        "open_ports": list(unique_ports)[:20],
        "vulnerabilities": cached_vulns,
        "docker_containers": docker_containers
    }
    
    return payload, ts, nonce, cpu_percent

def sign_payload(method, path, ts, nonce, body_str, secret):
    target = f"{method}\n{path}\n{ts}\n{nonce}\n{body_str}"
    return hmac.new(secret.encode('utf-8'), target.encode('utf-8'), hashlib.sha256).hexdigest()

def ship_telemetry():
    print(f"Starting Elite EDR Agent (ID: {AGENT_ID} | Version: {AGENT_VERSION})")
    while True:
        try:
            payload_dict, ts, nonce, cpu = get_system_telemetry()
            
            # Form raw JSON mapping
            payload_json = json.dumps(payload_dict, sort_keys=True, separators=(',', ':'))
            signature = sign_payload("POST", API_PATH, ts, nonce, payload_json, AGENT_KEY)
            
            headers = {
                "Content-Type": "application/json",
                "x-agent-signature": signature,
                "x-agent-timestamp": ts,
                "x-agent-nonce": nonce,
                "x-agent-key": AGENT_KEY # Sent purely for SaaS multitenant identification mapping (even though it's signed)
            }
            
            for attempt in range(3):
                try:
                    res = requests.post(API_URL, data=payload_json, headers=headers, timeout=10)
                    
                    # Also send to the new advanced report endpoint
                    report_url = API_URL.replace("/api/agent-scan", "/api/agent/report")
                    if report_url != API_URL:
                        requests.post(report_url, data=payload_json, headers=headers, timeout=10)
                        
                    if res.status_code == 200:
                        break
                    elif res.status_code == 403:
                        print("[-] 403 Forbidden: Invalid API Key. Agent terminated.")
                        sys.exit(1)
                except Exception as e:
                    print(f"[-] Network error: {str(e)}")
                time.sleep(2)
                
            # Adaptive Polling Calculation
            current_interval = BASE_SYNC_INTERVAL
            if cpu > 80:
                current_interval += 30 # Back off to 60s
                print(f"[*] High CPU ({cpu}%) -> Adaptive Sync Rate applied: {current_interval}s")
                
            time.sleep(current_interval)
            continue
                
        except Exception as system_e:
            print(f"[!] Critical crash loop protected: {str(system_e)}")
            time.sleep(BASE_SYNC_INTERVAL)

if __name__ == "__main__":
    ship_telemetry()

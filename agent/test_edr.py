import requests
import json
import uuid
import time
import hmac
import hashlib

API_URL = "https://cloudshield-tya3.onrender.com/api/agent-scan"
AGENT_KEY = "default-agent-key-123"

def sign_payload(method, path, ts, nonce, body_str, secret):
    target = f"{method}\n{path}\n{ts}\n{nonce}\n{body_str}"
    return hmac.new(secret.encode('utf-8'), target.encode('utf-8'), hashlib.sha256).hexdigest()

def make_payload(agent_id, hostname):
    return {
        "agentId": agent_id,
        "agentVersion": "2.0.0-EDR-PRO",
        "timestamp": float(int(time.time())),
        "nonce": str(uuid.uuid4()),
        "hostname": hostname,
        "os": "Test OS",
        "cpu_percent": 45.0,
        "ram_percent": 60.0,
        "top_processes": [],
        "open_ports": [],
        "cves": {"critical": 0, "high": 0}
    }

def print_result(name, res):
    print(f"--- {name} ---")
    print(f"Status: {res.status_code}")
    print(f"Response: {res.text.strip()}\n")

# 1. Valid Request
print("[*] Testing Valid EDR Agent Push...")
p = make_payload("testing-valid-agent-123", "ValidHost")
p_str = json.dumps(p, sort_keys=True, separators=(',', ':'))
ts = str(int(time.time()))
nonce = p["nonce"]
sig = sign_payload("POST", "/api/agent-scan", ts, nonce, p_str, AGENT_KEY)

headers = {"Content-Type": "application/json", "x-agent-signature": sig, "x-agent-timestamp": ts, "x-agent-nonce": nonce}
r1 = requests.post(API_URL, data=p_str, headers=headers)
print_result("1. Valid Request", r1)

# 2. Invalid Signature (Spoofing)
print("[*] Testing Spoof Authentication (Bad Key)...")
bad_sig = "a" * 64
headers["x-agent-signature"] = bad_sig
r2 = requests.post(API_URL, data=p_str, headers=headers)
print_result("2. Spoofed Signature", r2)

# 3. Replay Attack
print("[*] Testing Replay Attack (Duplicate Nonce)...")
# Send exact same headers and body as #1
r3 = requests.post(API_URL, data=p_str, headers={"Content-Type": "application/json", "x-agent-signature": sig, "x-agent-timestamp": ts, "x-agent-nonce": nonce})
print_result("3. Replay Attack", r3)

# 4. Timestamp Drift
print("[*] Testing Payload Expired (Timestamp Drift)...")
p_drift = make_payload("testing-drift-agent", "DriftHost")
ts_drift = str(int(time.time()) - 100) # 100 seconds in past
nonce_drift = p_drift["nonce"]
p_str_drift = json.dumps(p_drift, sort_keys=True, separators=(',', ':'))
sig_drift = sign_payload("POST", "/api/agent-scan", ts_drift, nonce_drift, p_str_drift, AGENT_KEY)

r4 = requests.post(API_URL, data=p_str_drift, headers={"Content-Type": "application/json", "x-agent-signature": sig_drift, "x-agent-timestamp": ts_drift, "x-agent-nonce": nonce_drift})
print_result("4. Timestamp Drift", r4)

print("[*] EDR Structural Validation Complete.")

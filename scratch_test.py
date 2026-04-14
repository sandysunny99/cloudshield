import requests
import json
import time

API_URL = "https://cloudshield-tya3.onrender.com/api/agent-scan"
print("Firing 6 Invalid (Spoofed) Requests to trigger auto-block...")

for i in range(1, 7):
    headers = {
        "x-agent-signature": "bogus-signature",
        "x-agent-timestamp": str(time.time()),
        "x-agent-nonce": f"random-nonce-{i}",
        "Content-Type": "application/json",
        "CF-Connecting-IP": "198.51.100.42"  # Simulating Cloudflare edge IP
    }
    
    resp = requests.post(API_URL, headers=headers, json={"agentId": "test-agent"})
    print(f"Request {i}: HTTP {resp.status_code}")
    time.sleep(0.5)

print("Done. Check the backend server logs for the [SECURITY] and [CF-API] alerts!")

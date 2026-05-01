import codecs

with codecs.open('agent/cloudshield_agent.py', 'r', 'utf-8') as f:
    text = f.read()

heartbeat_logic = """
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
"""

if "Send heartbeat" not in text:
    text = text.replace('time.sleep(5)  # Scan every 5 seconds', heartbeat_logic + '\n        time.sleep(5)  # Scan every 5 seconds')
    with codecs.open('agent/cloudshield_agent.py', 'w', 'utf-8') as f:
        f.write(text)
    print("Agent heartbeat added.")
else:
    print("Already added.")

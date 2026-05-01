import codecs
import re

with codecs.open('old_app.py', 'r', 'utf-8', errors='ignore') as f:
    old_app = f.read()

endpoints = [
    r'@app\.route\("/api/cloud-scan", methods=\["POST"\]\)\s*def cloud_scan\(\):.*?(?=@app\.route|$)',
    r'@app\.route\("/api/container-scan", methods=\["POST"\]\)\s*def container_scan\(\):.*?(?=@app\.route|$)',
    r'@app\.route\("/api/ai-risk", methods=\["POST"\]\)\s*def ai_risk_analysis\(\):.*?(?=@app\.route|$)',
    r'@app\.route\("/api/check-s3", methods=\["POST"\]\)\s*def check_s3_bucket\(\):.*?(?=@app\.route|$)'
]

extracted = "\n\n# --- RESTORED CLOUD & CONTAINER ENDPOINTS ---\n"
for ep in endpoints:
    m = re.search(ep, old_app, re.DOTALL)
    if m:
        extracted += m.group(0).strip() + "\n\n"

with codecs.open('backend/app.py', 'r', 'utf-8') as f:
    current_app = f.read()

if "RESTORED CLOUD & CONTAINER ENDPOINTS" not in current_app:
    # Insert before if __name__ == "__main__":
    current_app = current_app.replace('if __name__ == "__main__":', extracted + 'if __name__ == "__main__":')
    with codecs.open('backend/app.py', 'w', 'utf-8') as f:
        f.write(current_app)
    print("Endpoints restored to app.py")
else:
    print("Already restored.")

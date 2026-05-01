import codecs
import re

with codecs.open('old_app.py', 'r', 'utf-16le') as f:
    old_app = f.read()

endpoints = [
    r'@app\.route\("/api/scan/cloud".*?(?=@app\.route|$)',
    r'@app\.route\("/api/scan/container".*?(?=@app\.route|$)',
    r'@app\.route\("/api/analyze/risk".*?(?=@app\.route|$)',
    r'@app\.route\("/api/check-storage".*?(?=@app\.route|$)',
    r'@app\.route\("/api/scan/aws".*?(?=@app\.route|$)'
]

extracted = "\n\n"
for ep in endpoints:
    m = re.search(ep, old_app, re.DOTALL)
    if m:
        extracted += m.group(0).strip() + "\n\n"

# Add google generative ai import since we use it in analyze/risk
extracted = "try:\n    import google.generativeai as genai\nexcept ImportError:\n    pass\n\n" + extracted

with codecs.open('backend/app.py', 'r', 'utf-8') as f:
    current_app = f.read()

current_app = current_app.replace("# --- RESTORED CLOUD & CONTAINER ENDPOINTS ---\n", "")

current_app = current_app.replace('if __name__ == "__main__":', "# --- RESTORED CLOUD & CONTAINER ENDPOINTS ---\n" + extracted + '\nif __name__ == "__main__":')

with codecs.open('backend/app.py', 'w', 'utf-8') as f:
    f.write(current_app)

print("Endpoints successfully extracted.")

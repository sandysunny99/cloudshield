import re
with open('backend/app.py', 'r', encoding='utf-8') as f:
    js = f.read()
m = re.search(r'@app\.route\("/api/agent/events".*?(?=@app\.route|$)', js, re.DOTALL)
if m: print(m.group(0))

import re
with open('backend/app.py', 'r', encoding='utf-8') as f:
    app_str = f.read()
m = re.search(r'@app\.route\("/api/hunt".*?(?=@app\.route|$)', app_str, re.DOTALL)
if m: print(m.group(0))

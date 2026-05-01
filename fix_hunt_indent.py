import codecs

with codecs.open('backend/app.py', 'r', 'utf-8') as f:
    lines = f.readlines()

in_hunt = False
for i, line in enumerate(lines):
    if line.startswith('@limiter.limit("10 per minute")') and lines[i-1].strip() == '@app.route("/api/hunt", methods=["POST", "OPTIONS"])':
        in_hunt = True
    
    if in_hunt:
        if line.startswith('def api_threat_hunt') or not line.startswith('    ') and line.strip():
            lines[i] = '    ' + line
            
    if in_hunt and line.strip() == 'return jsonify({"status": "success", "results": results[:100]})':
        in_hunt = False

with codecs.open('backend/app.py', 'w', 'utf-8') as f:
    f.writelines(lines)

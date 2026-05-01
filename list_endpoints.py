import codecs
import re

with codecs.open('old_app.py', 'r', 'utf-16le') as f:
    text = f.read()

for m in re.finditer(r'@app\.route\(\"[^\"]+\"', text):
    print(m.group(0))

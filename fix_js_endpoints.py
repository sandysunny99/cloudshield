import codecs

with codecs.open('frontend/src/dashboard.js', 'r', 'utf-8', errors='ignore') as f:
    js = f.read()

js = js.replace('fetch("/api/sandbox/analyze"', 'fetch(`${API_BASE}/api/sandbox/analyze`')
js = js.replace('fetch("/api/hunt"', 'fetch(`${API_BASE}/api/hunt`')

with codecs.open('frontend/src/dashboard.js', 'w', 'utf-8') as f:
    f.write(js)

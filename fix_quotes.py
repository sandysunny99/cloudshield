import codecs

with codecs.open('frontend/src/dashboard.js', 'r', 'utf-8', errors='replace') as f:
    js = f.read()

# Replace \\" with \"
js = js.replace('\\\\"', '\\"')

with codecs.open('frontend/src/dashboard.js', 'w', 'utf-8') as f:
    f.write(js)

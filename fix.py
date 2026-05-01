import codecs

with codecs.open('frontend/src/dashboard.js', 'r', 'utf-8', errors='replace') as f:
    js = f.read()

bad = 'CommandLine =~ \\"Hidden|EncodedCommand\\"'
good = 'CommandLine =~ \\\\\\"Hidden|EncodedCommand\\\\\\"'

if bad in js:
    js = js.replace(bad, good)
    with codecs.open('frontend/src/dashboard.js', 'w', 'utf-8') as f:
        f.write(js)
    print("Fixed syntax error.")
else:
    print("Syntax string not found.")

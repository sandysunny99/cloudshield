import codecs
import re

with codecs.open('frontend/src/cspm_full.js', 'r', 'utf-8') as f:
    old_js = f.read()

m = re.search(r'async\s+function\s+fetchAgentTelemetry\s*\([^)]*\)\s*\{.*?\n\}', old_js, re.DOTALL)
if not m:
    print("Could not find fetchAgentTelemetry in old JS")
else:
    telemetry_fn = "window.fetchAgentTelemetry = " + m.group(0).replace("async function fetchAgentTelemetry", "async function") + ";\n"

    with codecs.open('frontend/src/dashboard.js', 'r', 'utf-8') as f:
        new_js = f.read()

    if 'window.fetchAgentTelemetry' not in new_js:
        new_js += "\n\n// Agent Telemetry\n" + telemetry_fn
        # Start polling
        new_js += "\nsetInterval(window.fetchAgentTelemetry, 5000);\n"
        new_js += "window.fetchAgentTelemetry();\n"
        
        with codecs.open('frontend/src/dashboard.js', 'w', 'utf-8') as f:
            f.write(new_js)
        print("Agent telemetry polling restored.")
    else:
        print("Already restored.")

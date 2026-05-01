import codecs
import re

# 1. Read old dashboard.js
with codecs.open('frontend/src/cspm_full.js', 'r', 'utf-8') as f:
    old_js = f.read()

# 2. Extract specific functions from old_js
funcs_to_extract = [
    "runScan", "runContainerScan", "runDemo", "checkS3Bucket", "renderAlerts", 
    "renderRemediations", "renderResults", "renderSeverityChart", 
    "renderSourceChart", "renderStreamChart", "renderComparison", 
    "renderTopIssues", "renderFindingsTable", "renderContainerScanResult", 
    "renderAiAnalysis", "renderCompliancePanel", "generateAiAnalysis", "pollAiAnalysis"
]

extracted_js = "// --- RESTORED CSPM & CONTAINER FUNCTIONS ---\n"

# We must also extract the global variables like chart instances
extracted_js += "let severityChart, sourceChart, streamChart;\n"

# Extract function definitions
for func in funcs_to_extract:
    # Match async function fn() { ... }
    m = re.search(r'async\s+function\s+' + func + r'\s*\([^)]*\)\s*\{.*?\n\}', old_js, re.DOTALL)
    if m:
        extracted_js += "window." + func + " = " + m.group(0).replace(f"async function {func}", "async function") + ";\n\n"
        continue
    
    # Match function fn() { ... }
    m2 = re.search(r'function\s+' + func + r'\s*\([^)]*\)\s*\{.*?\n\}', old_js, re.DOTALL)
    if m2:
        extracted_js += "window." + func + " = " + m2.group(0).replace(f"function {func}", "function") + ";\n\n"
        continue
        
    # Match const fn = async () => { ... }
    m3 = re.search(r'const\s+' + func + r'\s*=\s*async\s*\([^)]*\)\s*=>\s*\{.*?\n\};?', old_js, re.DOTALL)
    if m3:
        extracted_js += "window." + func + " = " + m3.group(0).replace(f"const {func} =", "") + "\n\n"
        continue

# 3. Read current dashboard.js
with codecs.open('frontend/src/dashboard.js', 'r', 'utf-8') as f:
    current_js = f.read()

# 4. Append if not already there
if "RESTORED CSPM & CONTAINER FUNCTIONS" not in current_js:
    current_js += "\n\n" + extracted_js
    with codecs.open('frontend/src/dashboard.js', 'w', 'utf-8') as f:
        f.write(current_js)

print("CSPM JS injected.")

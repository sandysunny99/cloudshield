import codecs
import re

with codecs.open('old_dashboard_utf8.js', 'r', 'utf-8-sig') as f:
    js = f.read()

# We need the CSPM specific functions:
# runScan, renderRemediationCards, generateAiAnalysis, pollAiAnalysis
# runContainerScan, renderCompliance
# Also we need to attach them to window so index.html onClick can call them.

def extract_fn(name):
    pattern = r'async function ' + name + r'\s*\([^)]*\)\s*\{.*?\n\}'
    m = re.search(pattern, js, re.DOTALL)
    if m:
        return f"window.{name} = " + m.group(0).replace(f"async function {name}", "async function") + ";"
    
    # Try const name = async () => {}
    pattern2 = r'const\s+' + name + r'\s*=\s*async\s*\([^)]*\)\s*=>\s*\{.*?\n\};?'
    m2 = re.search(pattern2, js, re.DOTALL)
    if m2:
        return f"window.{name} = " + m2.group(0).replace(f"const {name} = ", "")
        
    return f"// Function {name} not found"

cspm_js = """// Cloud Posture & Container Security Module

const API_BASE = window.location.origin.includes('localhost') ? 'http://localhost:5000' : 'https://cloudshield-tya3.onrender.com';

function showToast(msg, type='info') {
    if(window.showToast) { window.showToast(msg, type); }
    else { console.log(msg); }
}

function escapeHtml(str) {
    if (!str) return "";
    return str.toString()
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

"""

funcs = ["runScan", "renderRemediationCards", "generateAiAnalysis", "pollAiAnalysis", "runContainerScan", "renderCompliance"]

for fn in funcs:
    cspm_js += extract_fn(fn) + "\n\n"

with codecs.open('frontend/src/cspm.js', 'w', 'utf-8') as f:
    f.write(cspm_js)

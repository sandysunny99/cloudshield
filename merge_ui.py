import re
import codecs

# 1. Update index.html
with codecs.open('frontend/index.html', 'r', 'utf-8', errors='ignore') as f:
    index_html = f.read()

# Add navigation buttons
nav_target = '<button class="btn btn-outline" id="btn-hunt-panel"'
nav_addition = '''                <button class="btn btn-outline" id="btn-cspm-panel" aria-label="Cloud Security">
                    <span class="btn-icon">☁️</span> CSPM
                </button>
                <button class="btn btn-outline" id="btn-container-panel" aria-label="Container Security">
                    <span class="btn-icon">🐳</span> Containers
                </button>
'''
if 'id="btn-cspm-panel"' not in index_html:
    index_html = index_html.replace(nav_target, nav_addition + '                ' + nav_target)

# Add the old panels, adapted to the new telemetry-panel class
panels = '''
    <!-- CSPM Panel -->
    <div id="cspm-panel" class="telemetry-panel">
        <div class="tp-header">
            <h2><span class="tp-icon">☁️</span> Cloud Misconfiguration Scanner</h2>
            <button class="btn-close-tp" id="btn-close-cspm-panel">✖</button>
        </div>
        <div class="tp-content" style="padding: 1.5rem; overflow-y: auto;">
            <div class="scan-controls" style="margin-bottom: 1rem; display: flex; gap: 0.5rem;">
                <input id="aws-bucket-input" class="input-modern" type="text" placeholder="e.g. s3://my-prod-data" style="flex:1;">
                <button id="btn-scan" class="btn btn-primary" onclick="runScan()">
                    <span class="btn-icon">⚡</span> Run Scan
                </button>
            </div>
            <div id="scan-result" class="scan-result-card" style="margin-bottom: 1rem;">
                <p style="color:var(--text-muted)">Awaiting scan target...</p>
            </div>
            <div id="ai-analysis-container" class="ai-analysis-container" style="margin-top: 1rem;"></div>
        </div>
    </div>

    <!-- Container Panel -->
    <div id="container-panel" class="telemetry-panel">
        <div class="tp-header">
            <h2><span class="tp-icon">🐳</span> Container Vulnerability Scanner</h2>
            <button class="btn-close-tp" id="btn-close-container-panel">✖</button>
        </div>
        <div class="tp-content" style="padding: 1.5rem; overflow-y: auto;">
            <div class="container-scan-row" style="margin-bottom: 1rem; display: flex; gap: 0.5rem;">
                <input id="container-image-input" class="input-modern" type="text" placeholder="e.g. nginx:latest" style="flex:1;">
                <button id="btn-container-scan" class="btn btn-primary" onclick="runContainerScan()">
                    <span class="btn-icon">🔍</span> Scan Image
                </button>
            </div>
            <div id="container-scan-result" style="margin-bottom: 1rem;">
                <p style="color:var(--text-muted)">Enter an image name to discover CVEs...</p>
            </div>
            <div id="compliance-container" style="margin-top: 1rem;"></div>
        </div>
    </div>
'''

if 'id="cspm-panel"' not in index_html:
    index_html = index_html.replace('</body>', panels + '\n</body>')

with codecs.open('frontend/index.html', 'w', 'utf-8') as f:
    f.write(index_html)


# 2. Update dashboard.js
with codecs.open('frontend/src/dashboard.js', 'r', 'utf-8', errors='ignore') as f:
    js = f.read()

# Add logic for buttons
js_panels = '''
// CSPM and Container Panel Logic
const btnCspmPanel = document.getElementById('btn-cspm-panel');
const cspmPanel = document.getElementById('cspm-panel');
const btnCloseCspm = document.getElementById('btn-close-cspm-panel');

if(btnCspmPanel && cspmPanel && btnCloseCspm) {
    btnCspmPanel.addEventListener('click', () => {
        closeAllPanels();
        cspmPanel.classList.add('active');
    });
    btnCloseCspm.addEventListener('click', () => cspmPanel.classList.remove('active'));
}

const btnContainerPanel = document.getElementById('btn-container-panel');
const containerPanel = document.getElementById('container-panel');
const btnCloseContainer = document.getElementById('btn-close-container-panel');

if(btnContainerPanel && containerPanel && btnCloseContainer) {
    btnContainerPanel.addEventListener('click', () => {
        closeAllPanels();
        containerPanel.classList.add('active');
    });
    btnCloseContainer.addEventListener('click', () => containerPanel.classList.remove('active'));
}
'''

if 'btnCspmPanel' not in js:
    js = js.replace('// ── Case Management UI Logic ──', js_panels + '\n\n// ── Case Management UI Logic ──')


# We must also extract `runScan` and `runContainerScan` from old_dashboard.js
with codecs.open('old_dashboard.js', 'r', 'utf-8', errors='ignore') as f:
    old_js = f.read()

def extract_function(name, text):
    match = re.search(r'window\.' + name + r'\s*=\s*async\s*function\s*\(\)\s*\{.*?\n\};', text, re.DOTALL)
    if not match:
        match = re.search(r'async\s+function\s+' + name + r'\s*\(\)\s*\{.*?\n\}', text, re.DOTALL)
    return match.group(0) if match else ''

def extract_all():
    funcs = [
        "runScan", "runContainerScan", "renderCompliance", "renderRemediationCards",
        "generateAiAnalysis", "pollAiAnalysis"
    ]
    res = []
    for fn in funcs:
        m = extract_function(fn, old_js)
        if not m:
            # try normal function
            m2 = re.search(r'function\s+' + fn + r'\s*\([^)]*\)\s*\{.*?\n\}', old_js, re.DOTALL)
            if m2:
                res.append(m2.group(0))
        else:
            res.append(m)
    return "\\n\\n".join(res)

extracted_funcs = extract_all()

# To be safe, make them window attached if they aren't so HTML onclick works
extracted_funcs = extracted_funcs.replace("async function runScan()", "window.runScan = async function()")
extracted_funcs = extracted_funcs.replace("async function runContainerScan()", "window.runContainerScan = async function()")

if 'window.runScan' not in js:
    js += '\n\n// Restored CSPM and Container Functions\n' + extracted_funcs

with codecs.open('frontend/src/dashboard.js', 'w', 'utf-8') as f:
    f.write(js)

print("Unified UI files updated successfully.")

import codecs

def update_index():
    with codecs.open('frontend/index.html', 'r', 'utf-8') as f:
        content = f.read()

    btn_cases = '''                <button class="btn btn-outline" id="btn-cases-panel" aria-label="Open Case Management">
                    <span class="btn-icon">📂</span> Cases
                </button>'''

    if 'btn-cases-panel' not in content:
        content = content.replace(
            '<button class="btn btn-outline" id="btn-hunt-panel"',
            btn_cases + '\n                <button class="btn btn-outline" id="btn-hunt-panel"'
        )

    modal_cases = '''    <!-- Case Management Modal -->
    <div id="cases-panel" class="telemetry-panel">
        <div class="tp-header">
            <h2><span class="tp-icon">📂</span> Case Management</h2>
            <div class="tp-controls">
                <input type="text" id="case-search" placeholder="Search Title, Desc..." class="input-modern" style="margin-right: 1rem; width: 200px;">
                <select id="case-status-filter" class="input-modern" style="margin-right: 1rem;">
                    <option value="all">All Cases</option>
                    <option value="open">Open</option>
                    <option value="investigating">Investigating</option>
                    <option value="closed">Closed</option>
                </select>
                <button class="btn btn-primary" onclick="promptCreateCase()">+ New Case</button>
                <button class="btn-close-tp" id="btn-close-cases-panel" aria-label="Close Case Panel">✖</button>
            </div>
        </div>
        <div class="tp-content" style="padding: 1.5rem; overflow-y: auto;">
            <div class="table-container">
                <table id="cases-table">
                    <thead>
                        <tr>
                            <th>Case ID</th>
                            <th>Status</th>
                            <th>Title</th>
                            <th>Assigned To</th>
                            <th>Created</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr><td colspan="6" style="text-align:center;color:var(--text-muted)">Loading cases...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
'''

    if 'id="cases-panel"' not in content:
        content = content.replace('</body>', modal_cases + '</body>')

    with codecs.open('frontend/index.html', 'w', 'utf-8') as f:
        f.write(content)

def update_dashboard():
    with codecs.open('frontend/src/dashboard.js', 'r', 'utf-8', errors='ignore') as f:
        js = f.read()

    # Apply timeline modification
    target = '<div>\\n            <strong>Raw JSON:</strong>'
    replacement = '''        <div style="margin-bottom:1rem;">
            <strong>Investigation Timeline:</strong>
            <div style="margin-top:0.5rem; color:var(--text-bright); font-size:0.8rem; background:rgba(0,0,0,0.3); padding:0.5rem; border-left: 2px solid var(--color-med);">
                ${(alertData.network || []).map(n => `<div style="margin-bottom:4px"><span style="color:var(--text-muted)">[NETWORK]</span> ${escapeHtml(n)}</div>`).join("") || ""}
                ${(alertData.tactics || []).map(t => `<div style="margin-bottom:4px"><span style="color:var(--color-high)">[TACTIC]</span> ${escapeHtml(t)} Match</div>`).join("") || ""}
                ${alertData.analysis_id ? `<div style="margin-bottom:4px"><span style="color:var(--color-critical)">[ANALYSIS]</span> Job ID: ${escapeHtml(alertData.analysis_id)}</div>` : ""}
            </div>
        </div>
        <div>
            <strong>Raw JSON:</strong>'''
    if 'Investigation Timeline' not in js:
        js = js.replace(target, replacement)
        
    # Append case management JS
    with codecs.open('tmp_case.js', 'r', 'utf-8') as f:
        case_js = f.read()
        
    if 'function fetchCases' not in js:
        js += "\\n" + case_js
        
    with codecs.open('frontend/src/dashboard.js', 'w', 'utf-8') as f:
        f.write(js)

try:
    update_index()
    update_dashboard()
    print("Files successfully updated!")
except Exception as e:
    print(f"Error: {e}")

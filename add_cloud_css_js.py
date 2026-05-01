import codecs

# ─── 1. Add CSS for dropdown + cloud tabs ───
css_addition = '''

/* ═══ Cloud Security Dropdown ═══ */
.nav-dropdown { position: relative; display: inline-block; }
.dropdown-menu {
    display: none; position: absolute; top: 100%; left: 0; z-index: 100;
    min-width: 220px; margin-top: 4px;
    background: rgba(15, 23, 42, 0.97); border: 1px solid var(--border-glass);
    border-radius: 8px; box-shadow: 0 12px 40px rgba(0,0,0,0.5);
    backdrop-filter: blur(16px); overflow: hidden;
    animation: dropFade 0.2s ease;
}
@keyframes dropFade { from { opacity:0; transform:translateY(-6px); } to { opacity:1; transform:translateY(0); } }
.nav-dropdown:hover .dropdown-menu,
.nav-dropdown.open .dropdown-menu { display: block; }
.dropdown-item {
    display: flex; align-items: center; gap: 8px; width: 100%;
    padding: 0.65rem 1rem; border: none; background: none;
    color: var(--text-secondary); font-size: 0.82rem; cursor: pointer;
    transition: all 0.15s;
}
.dropdown-item:hover { background: rgba(59,130,246,0.12); color: #fff; }
.dropdown-item span { font-size: 1rem; }

/* ═══ Cloud Panel Sub-Tabs ═══ */
.cloud-tabs {
    display: flex; gap: 0; border-bottom: 1px solid var(--border-glass);
    background: rgba(0,0,0,0.15);
}
.cloud-tab {
    flex: 1; padding: 0.7rem 1rem; border: none; background: none;
    color: var(--text-secondary); font-size: 0.82rem; cursor: pointer;
    border-bottom: 2px solid transparent; transition: all 0.2s;
}
.cloud-tab:hover { color: #fff; background: rgba(255,255,255,0.03); }
.cloud-tab.active {
    color: var(--accent-blue); border-bottom-color: var(--accent-blue);
    background: rgba(59,130,246,0.06);
}
.cloud-tab-content { display: none; }
.cloud-tab-content.active { display: block; }
'''

with codecs.open('frontend/src/style.css', 'r', 'utf-8', errors='ignore') as f:
    css = f.read()

if '.cloud-tabs' not in css:
    css += css_addition
    with codecs.open('frontend/src/style.css', 'w', 'utf-8') as f:
        f.write(css)
    print("CSS updated.")
else:
    print("CSS already has cloud tabs.")

# ─── 2. Update JS: replace old panel buttons with new unified logic ───
with codecs.open('frontend/src/dashboard.js', 'r', 'utf-8') as f:
    js = f.read()

# Remove old individual panel button handlers if they exist
for old_code in [
    "const btnBucketPanel = document.getElementById('btn-bucket-panel');",
    "const bucketPanel = document.getElementById('bucket-scan-panel');",
    "const btnCloseBucket = document.getElementById('btn-close-bucket-panel');",
]:
    js = js.replace(old_code, '')

# Add the new unified Cloud Security panel logic
cloud_js = '''

// ═══ Cloud Security Panel (Unified) ═══
(function initCloudSecurityPanel() {
    const cloudPanel = document.getElementById('cloud-security-panel');
    const btnClose = document.getElementById('btn-close-cloud-panel');
    const tabs = document.querySelectorAll('.cloud-tab');
    const tabContents = document.querySelectorAll('.cloud-tab-content');

    // Dropdown toggle
    const dropdown = document.getElementById('cloud-security-dropdown');
    const btnCloudSec = document.getElementById('btn-cloud-security');
    if (btnCloudSec) {
        btnCloudSec.addEventListener('click', (e) => {
            e.stopPropagation();
            dropdown.classList.toggle('open');
        });
    }
    document.addEventListener('click', () => { if(dropdown) dropdown.classList.remove('open'); });

    // Sub-item clicks open panel with correct tab
    const tabMap = { 'btn-cspm-panel':'cspm-tab', 'btn-container-panel':'container-tab', 'btn-bucket-panel':'bucket-tab' };
    Object.entries(tabMap).forEach(([btnId, tabId]) => {
        const btn = document.getElementById(btnId);
        if (btn) btn.addEventListener('click', () => {
            closeAllPanels();
            if (cloudPanel) cloudPanel.classList.add('active');
            activateCloudTab(tabId);
            if (dropdown) dropdown.classList.remove('open');
        });
    });

    // Tab switching
    tabs.forEach(tab => {
        tab.addEventListener('click', () => activateCloudTab(tab.dataset.tab));
    });

    function activateCloudTab(tabId) {
        tabs.forEach(t => t.classList.toggle('active', t.dataset.tab === tabId));
        tabContents.forEach(tc => tc.classList.toggle('active', tc.id === tabId));
    }

    // Close
    if (btnClose) btnClose.addEventListener('click', () => { if(cloudPanel) cloudPanel.classList.remove('active'); });
})();
'''

if 'initCloudSecurityPanel' not in js:
    js += cloud_js
    with codecs.open('frontend/src/dashboard.js', 'w', 'utf-8') as f:
        f.write(js)
    print("JS updated.")
else:
    print("JS already has cloud panel logic.")

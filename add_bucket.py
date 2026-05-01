import codecs

with codecs.open('frontend/index.html', 'r', 'utf-8', errors='ignore') as f:
    index_html = f.read()

bucket_panel = '''
    <!-- Bucket Scan Panel -->
    <div id="bucket-scan-panel" class="telemetry-panel">
        <div class="tp-header">
            <h2><span class="tp-icon">🪣</span> S3 Bucket Security Scanner</h2>
            <button class="btn-close-tp" id="btn-close-bucket-panel">✖</button>
        </div>
        <div class="tp-content" style="padding: 1.5rem; overflow-y: auto;">
            <div class="scan-controls" style="margin-bottom: 1rem; display: flex; gap: 0.5rem;">
                <input id="s3-bucket-input" class="input-modern" type="text" placeholder="e.g. s3://public-finance-data" style="flex:1;">
                <button id="btn-s3-scan" class="btn btn-primary" onclick="checkS3Bucket()">
                    <span class="btn-icon">🔍</span> Scan Bucket
                </button>
            </div>
            <div id="bucket-scan-result" style="margin-bottom: 1rem;">
                <p style="color:var(--text-muted)">Enter a bucket name to assess ACLs and encryption...</p>
            </div>
        </div>
    </div>
'''

if 'id="bucket-scan-panel"' not in index_html:
    index_html = index_html.replace('</body>', bucket_panel + '\n</body>')

# Add the bucket button to nav
nav_target = '<button class="btn btn-outline" id="btn-container-panel"'
nav_addition = '''                <button class="btn btn-outline" id="btn-bucket-panel" aria-label="Bucket Scan">
                    <span class="btn-icon">🪣</span> Storage
                </button>
'''
if 'id="btn-bucket-panel"' not in index_html:
    index_html = index_html.replace(nav_target, nav_addition + '                ' + nav_target)

with codecs.open('frontend/index.html', 'w', 'utf-8') as f:
    f.write(index_html)

# Add logic for bucket button
with codecs.open('frontend/src/dashboard.js', 'r', 'utf-8', errors='ignore') as f:
    js = f.read()

js_panels = '''
const btnBucketPanel = document.getElementById('btn-bucket-panel');
const bucketPanel = document.getElementById('bucket-scan-panel');
const btnCloseBucket = document.getElementById('btn-close-bucket-panel');

if(btnBucketPanel && bucketPanel && btnCloseBucket) {
    btnBucketPanel.addEventListener('click', () => {
        closeAllPanels();
        bucketPanel.classList.add('active');
    });
    btnCloseBucket.addEventListener('click', () => bucketPanel.classList.remove('active'));
}
'''

if 'btnBucketPanel' not in js:
    js = js.replace('// ── Case Management UI Logic ──', js_panels + '\n\n// ── Case Management UI Logic ──')
    with codecs.open('frontend/src/dashboard.js', 'w', 'utf-8') as f:
        f.write(js)

print("Bucket panel added.")

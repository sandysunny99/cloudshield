"""
Rebuild the dashboard UI:
1. Group CSPM + Storage + Container under a single "Cloud Security" dropdown
2. Remove duplicate panels
3. Move misplaced panels inside <main>
4. Clean up nav bar clutter
"""
import codecs

with codecs.open('frontend/index.html', 'r', 'utf-8') as f:
    html = f.read()

# ─── Step 1: Replace the cluttered header-actions buttons ───
old_nav = '''                <button class="btn btn-outline" id="btn-cspm-panel" aria-label="Cloud Security">
                    <span class="btn-icon">☁️</span> CSPM
                </button>
                                <button class="btn btn-outline" id="btn-bucket-panel" aria-label="Bucket Scan">
                    <span class="btn-icon">🪣</span> Storage
                </button>
                <button class="btn btn-outline" id="btn-container-panel" aria-label="Container Security">
                    <span class="btn-icon">🐳</span> Containers
                </button>'''

new_nav = '''                <div class="nav-dropdown" id="cloud-security-dropdown">
                    <button class="btn btn-outline" id="btn-cloud-security" aria-label="Cloud Security">
                        <span class="btn-icon">☁️</span> Cloud Security <span style="font-size:0.6rem;margin-left:2px">▼</span>
                    </button>
                    <div class="dropdown-menu" id="cloud-dropdown-menu">
                        <button class="dropdown-item" id="btn-cspm-panel"><span>⚙️</span> Misconfiguration Scanner</button>
                        <button class="dropdown-item" id="btn-container-panel"><span>🐳</span> Container Vulnerability</button>
                        <button class="dropdown-item" id="btn-bucket-panel"><span>🪣</span> Storage / S3 Audit</button>
                    </div>
                </div>'''

html = html.replace(old_nav, new_nav)

# ─── Step 2: Remove duplicate inline container-panel + compliance-panel from <main> ───
# These are lines 470-496 approximately - the old inline sections
old_container_section = '''        <!-- ── Container Vulnerability Scanner Panel ────────────────── -->
        <section id="container-panel" class="section">
            <h2 class="section-title">🐳 Container Vulnerability Scanner</h2>
            <div class="container-scan-row">
                <input id="container-image-input" class="container-image-input"
                       type="text" placeholder="e.g. nginx:latest, ubuntu:22.04, python:3.12-slim"
                       aria-label="Container image name" />
                <button id="btn-container-scan" class="btn btn-primary" onclick="runContainerScan()">
                    <span class="btn-icon">🔍</span> Scan Image
                </button>
            </div>
            <div id="container-scan-result" class="container-scan-result">
                <p class="ai-sub" style="padding:1rem 0;">Enter a container image name above and click Scan Image to discover real CVEs using Trivy.</p>
            </div>
        </section>

        <!-- ── Compliance Status Panel ───────────────────────────────── -->
        <section id="compliance-panel" class="section">
            <h2 class="section-title">📋 Compliance Mapping</h2>
            <div id="compliance-container" class="compliance-container">
                <div class="compliance-placeholder">
                    <span style="font-size:2rem;">📋</span>
                    <p>Compliance status appears after a scan is completed.</p>
                    <p class="ai-sub">Findings are auto-mapped to CIS v8, NIST 800-53, ISO 27001, and HIPAA.</p>
                </div>
            </div>
        </section>'''

html = html.replace(old_container_section, '')

# ─── Step 3: Replace the overlay panels after </main> with a clean Cloud Security mega-panel ───
old_overlays = '''    <!-- CSPM Panel -->
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
    </div>'''

# The new unified Cloud Security panel - a single overlay with 3 tabs inside
new_cloud_panel = '''    <!-- ═══ Unified Cloud Security Panel ═══ -->
    <div id="cloud-security-panel" class="telemetry-panel">
        <div class="tp-header" style="border-bottom:1px solid var(--border-glass);">
            <h2><span class="tp-icon">☁️</span> Cloud Security</h2>
            <button class="btn-close-tp" id="btn-close-cloud-panel">✖</button>
        </div>
        <!-- Sub-tab navigation -->
        <div class="cloud-tabs">
            <button class="cloud-tab active" data-tab="cspm-tab">⚙️ Misconfig Scanner</button>
            <button class="cloud-tab" data-tab="container-tab">🐳 Container CVE</button>
            <button class="cloud-tab" data-tab="bucket-tab">🪣 Storage Audit</button>
        </div>
        <div class="tp-content" style="padding:1.5rem;overflow-y:auto;">
            <!-- CSPM Tab -->
            <div id="cspm-tab" class="cloud-tab-content active">
                <p style="color:var(--text-secondary);margin-bottom:1rem;font-size:0.85rem;">Analyze AWS/GCP/Azure configurations for policy violations mapped to CIS, NIST 800-53, and ISO 27001.</p>
                <div style="display:flex;gap:0.5rem;margin-bottom:1rem;">
                    <input id="aws-bucket-input" class="input-modern" type="text" placeholder="Paste cloud config JSON or leave blank for auto-detect" style="flex:1;">
                    <button class="btn btn-primary" onclick="runScan()"><span class="btn-icon">⚡</span> Scan</button>
                </div>
                <div id="scan-result" class="scan-result-card"><p style="color:var(--text-muted)">Awaiting scan target...</p></div>
                <div id="ai-analysis-container" class="ai-analysis-container" style="margin-top:1rem;"></div>
            </div>
            <!-- Container Tab -->
            <div id="container-tab" class="cloud-tab-content">
                <p style="color:var(--text-secondary);margin-bottom:1rem;font-size:0.85rem;">Scan Docker/OCI container images for known CVEs using the Trivy vulnerability database.</p>
                <div style="display:flex;gap:0.5rem;margin-bottom:1rem;">
                    <input id="container-image-input" class="input-modern" type="text" placeholder="e.g. nginx:latest, python:3.12-slim" style="flex:1;">
                    <button class="btn btn-primary" onclick="runContainerScan()"><span class="btn-icon">🔍</span> Scan Image</button>
                </div>
                <div id="container-scan-result"><p style="color:var(--text-muted)">Enter an image name to discover CVEs...</p></div>
                <div id="compliance-container" style="margin-top:1rem;"></div>
            </div>
            <!-- Bucket Tab -->
            <div id="bucket-tab" class="cloud-tab-content">
                <p style="color:var(--text-secondary);margin-bottom:1rem;font-size:0.85rem;">Audit S3 / GCS bucket permissions, ACLs, encryption status, and public access exposure.</p>
                <div style="display:flex;gap:0.5rem;margin-bottom:1rem;">
                    <input id="s3-bucket-input" class="input-modern" type="text" placeholder="e.g. s3://public-finance-data" style="flex:1;">
                    <button class="btn btn-primary" onclick="checkS3Bucket()"><span class="btn-icon">🔍</span> Scan Bucket</button>
                </div>
                <div id="bucket-scan-result"><p style="color:var(--text-muted)">Enter a bucket name to assess ACLs and encryption...</p></div>
            </div>
        </div>
    </div>'''

html = html.replace(old_overlays, new_cloud_panel)

with codecs.open('frontend/index.html', 'w', 'utf-8') as f:
    f.write(html)

print("HTML rebuilt.")

/* CloudShield Dashboard v3 — SaaS Production */

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:5000';

// ── Severity / Source colours ──
const SEVERITY_COLORS = { CRITICAL:'#ef4444', HIGH:'#f97316', MEDIUM:'#eab308', LOW:'#22c55e' };
const SOURCE_COLORS   = { trivy:'#3b82f6', opa:'#8b5cf6', correlation:'#06b6d4' };

// ── Chart instances ──
let severityBarChart = null, sourceDoughnutChart = null,
    streamBarChart  = null, trendChart          = null,
    attackRateChart = null, riskTrendChart      = null;

// ── Live data buffers (for mini-charts, status bar) ──
const ATTACK_RATE_HISTORY = [];   // {time, rate}
const RISK_TREND_HISTORY  = [];   // {time, score}
let lastAgentsData  = null;
let lastMetricsData = null;
let currentFleetSort = 'risk';

// ── SOC Event Timeline ──
const SOC_EVENTS = [];
function addSocEvent(level, message) {
    const now = new Date();
    SOC_EVENTS.unshift({ level, message, time: now.toISOString(), display: now.toLocaleTimeString() });
    if (SOC_EVENTS.length > 50) SOC_EVENTS.pop();
    renderSocTimeline();
}
function renderSocTimeline() {
    const el = document.getElementById('soc-timeline-list');
    if (!el) return;
    if (!SOC_EVENTS.length) {
        el.innerHTML = '<div class="soc-empty">No events recorded. System nominal.</div>';
        return;
    }
    const colors = { CRITICAL:'var(--color-critical)', WARNING:'var(--color-medium)', INFO:'var(--color-low)' };
    el.innerHTML = SOC_EVENTS.slice(0, 30).map(ev =>
        `<div class="soc-event">
            <span class="soc-time">${ev.display}</span>
            <span class="soc-level" style="color:${colors[ev.level]||'var(--text-secondary)'}">[${ev.level}]</span>
            <span class="soc-msg">${escapeHtml(ev.message)}</span>
         </div>`
    ).join('');
}

// ── Toast Notifications ──
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;
    const icons = { info:'ℹ️', success:'✅', error:'🚨', warning:'⚠️' };
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `<span class="toast-icon">${icons[type]||'ℹ️'}</span>
                       <span class="toast-msg">${escapeHtml(message)}</span>
                       <button class="toast-close" onclick="this.parentElement.remove()">×</button>`;
    container.appendChild(toast);
    requestAnimationFrame(() => toast.classList.add('toast-visible'));
    setTimeout(() => { toast.classList.remove('toast-visible'); setTimeout(() => toast.remove(), 400); }, 4500);
}

// ── Status Bar ──
function updateStatusBar() {
    const agents  = lastAgentsData  || [];
    const metrics = lastMetricsData || {};
    const online  = agents.filter(a => a.connection_status === 'online').length;
    const threats = (metrics.total_blocked || 0) + (metrics.total_attack_ips || 0);

    const sbStatus = document.getElementById('sb-system-status');
    const sbAgents = document.getElementById('sb-agent-count');
    const sbThreats = document.getElementById('sb-threat-count');
    const sbUpdated = document.getElementById('sb-last-updated');
    const bar = document.getElementById('global-status-bar');

    if (sbAgents)  sbAgents.textContent  = agents.length ? `${online}/${agents.length}` : '0/0';
    if (sbThreats) sbThreats.textContent = threats || 0;
    if (sbUpdated) sbUpdated.textContent = new Date().toLocaleTimeString();

    if (sbStatus) {
        if (threats > 0) {
            sbStatus.textContent = '🔴 Threats Detected';
            sbStatus.style.color = 'var(--color-critical)';
            if (bar) bar.style.borderBottomColor = 'rgba(239,68,68,0.5)';
        } else if (!agents.length) {
            sbStatus.textContent = '🟡 No Agents Connected';
            sbStatus.style.color = 'var(--color-medium)';
            if (bar) bar.style.borderBottomColor = 'rgba(234,179,8,0.3)';
        } else {
            sbStatus.textContent = '🟢 System Healthy';
            sbStatus.style.color = 'var(--color-low)';
            if (bar) bar.style.borderBottomColor = 'rgba(34,197,94,0.3)';
        }
    }
}

// ── Mini Chart: Attack Rate (lazy init + update-not-destroy) ──
function updateAttackRateChart(rate) {
    const now = new Date().toLocaleTimeString('en-US', { hour12:false, hour:'2-digit', minute:'2-digit', second:'2-digit' });
    ATTACK_RATE_HISTORY.push({ time: now, rate });
    if (ATTACK_RATE_HISTORY.length > 20) ATTACK_RATE_HISTORY.shift();

    const canvas = document.getElementById('attack-rate-chart');
    if (!canvas) return;

    if (!attackRateChart) {
        attackRateChart = new Chart(canvas.getContext('2d'), {
            type: 'line',
            data: {
                labels: ATTACK_RATE_HISTORY.map(d => d.time),
                datasets: [{ label: 'req/min', data: ATTACK_RATE_HISTORY.map(d => d.rate),
                    borderColor: '#ef4444', backgroundColor: 'rgba(239,68,68,0.08)',
                    borderWidth: 2, pointRadius: 2, tension: 0.4, fill: true }]
            },
            options: {
                responsive: true, animation: { duration: 300 },
                plugins: { legend: { display: false } },
                scales: {
                    x: { ticks: { color:'#64748b', maxTicksLimit:5, font:{size:9} }, grid:{ display:false } },
                    y: { beginAtZero:true, ticks:{ color:'#64748b', stepSize:1, font:{size:9} }, grid:{ color:'rgba(255,255,255,0.04)' } }
                }
            }
        });
    } else {
        attackRateChart.data.labels = ATTACK_RATE_HISTORY.map(d => d.time);
        attackRateChart.data.datasets[0].data = ATTACK_RATE_HISTORY.map(d => d.rate);
        attackRateChart.update('none');
    }
}

// ── Mini Chart: Risk Score Trend ──
function updateRiskTrendChart(score) {
    const now = new Date().toLocaleTimeString('en-US', { hour12:false, hour:'2-digit', minute:'2-digit' });
    RISK_TREND_HISTORY.push({ time: now, score });
    if (RISK_TREND_HISTORY.length > 20) RISK_TREND_HISTORY.shift();

    const canvas = document.getElementById('risk-trend-chart');
    if (!canvas) return;

    if (!riskTrendChart) {
        riskTrendChart = new Chart(canvas.getContext('2d'), {
            type: 'line',
            data: {
                labels: RISK_TREND_HISTORY.map(d => d.time),
                datasets: [{ label: 'Risk', data: RISK_TREND_HISTORY.map(d => d.score),
                    borderColor: '#8b5cf6', backgroundColor: 'rgba(139,92,246,0.08)',
                    borderWidth: 2, pointRadius: 2, tension: 0.4, fill: true }]
            },
            options: {
                responsive: true, animation: { duration: 300 },
                plugins: { legend: { display: false } },
                scales: {
                    x: { ticks: { color:'#64748b', maxTicksLimit:5, font:{size:9} }, grid:{ display:false } },
                    y: { beginAtZero:true, max:100, ticks:{ color:'#64748b', font:{size:9} }, grid:{ color:'rgba(255,255,255,0.04)' } }
                }
            }
        });
    } else {
        riskTrendChart.data.labels = RISK_TREND_HISTORY.map(d => d.time);
        riskTrendChart.data.datasets[0].data = RISK_TREND_HISTORY.map(d => d.score);
        riskTrendChart.update('none');
    }
}

// ── Scan History (localStorage) ──
function getScanHistory() {
    try { 
        const h = JSON.parse(localStorage.getItem('cloudshield_scan_history') || '[]');
        return Array.isArray(h) ? h : [];
    }
    catch { 
        localStorage.removeItem('cloudshield_scan_history');
        return []; 
    }
}
function saveScanToHistory(data) {
    if (!data) return;
    let history = getScanHistory();
    history.unshift({
        timestamp:     new Date().toISOString(),
        risk:          data.risk || {},
        findingsCount: (data.findings || []).length,
        data
    });
    if (history.length > 10) history = history.slice(0, 10);
    localStorage.setItem('cloudshield_scan_history', JSON.stringify(history));
    renderScanHistory();
    const el = document.getElementById('sb-last-scan');
    if (el) el.textContent = new Date().toLocaleTimeString();
}
function renderScanHistory() {
    const container = document.getElementById('scan-history-list');
    if (!container) return;
    const history = getScanHistory();
    if (!history.length) {
        container.innerHTML = '<div class="scan-history-empty">No scan history yet. Run a scan or demo to begin.</div>';
        return;
    }
    container.innerHTML = history.map((item, idx) => {
        const cat   = item.risk?.category || 'LOW';
        const score = item.risk?.final_score ?? '—';
        const ts    = new Date(item.timestamp).toLocaleString();
        const cls   = { CRITICAL:'badge-critical', HIGH:'badge-high', MEDIUM:'badge-medium' }[cat] || 'badge-low';
        return `<div class="scan-history-item" role="button" tabindex="0"
                     onclick="reloadScan(${idx})" onkeydown="if(event.key==='Enter')reloadScan(${idx})">
            <div class="shi-left">
                <span class="badge ${cls}">${cat}</span>
                <div>
                    <div style="font-weight:600;font-size:0.9rem;">${item.findingsCount} findings</div>
                    <div style="font-size:0.72rem;color:var(--text-secondary);">${ts}</div>
                </div>
            </div>
            <div class="shi-right">
                <div style="text-align:right;">
                    <div style="font-size:1.3rem;font-weight:800;color:var(--text-primary);">${score}</div>
                    <div style="font-size:0.7rem;color:var(--text-secondary);">Risk Score</div>
                </div>
                <button class="btn btn-xs" aria-label="Reload scan ${idx+1}">↩ Load</button>
            </div>
        </div>`;
    }).join('');
}
function reloadScan(idx) {
    const history = getScanHistory();
    if (!history[idx]) return;
    renderResults(history[idx].data);
    showToast(`Loaded scan from ${new Date(history[idx].timestamp).toLocaleString()}`, 'info');
    addSocEvent('INFO', `Loaded historical scan #${idx+1} (${history[idx].findingsCount} findings).`);
}
window.clearScanHistory = function() {
    localStorage.removeItem('cloudshield_scan_history');
    renderScanHistory();
    showToast('Scan history cleared.', 'info');
};

// ── Export Report ──
window.exportReport = async function() {
    const btn = document.getElementById('btn-export-report');
    if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> Generating...'; }
    try {
        const [ar, mr, rr, sr] = await Promise.allSettled([
            fetch(`${API_BASE}/api/agent-status`).then(r => r.json()),
            fetch(`${API_BASE}/api/security-metrics`).then(r => r.json()),
            fetch(`${API_BASE}/api/results`).then(r => r.json()),
            fetch(`${API_BASE}/api/soc-timeline?limit=50`).then(r => r.json()),
        ]);
        const report = {
            exported_at: new Date().toISOString(),
            platform: 'CloudShield EDR/CSPM', version: '3.0',
            agents:           ar.status === 'fulfilled' ? ar.value.agents          : [],
            security_metrics: mr.status === 'fulfilled' ? mr.value.metrics         : {},
            latest_scan:      rr.status === 'fulfilled' ? rr.value.data            : null,
            soc_events:       sr.status === 'fulfilled' ? sr.value.events          : [],
            scan_history:  getScanHistory().map(h => ({ timestamp:h.timestamp, risk:h.risk, findings_count:h.findingsCount })),
            storage_scans: JSON.parse(localStorage.getItem('cloudshield_s3_history') || '[]'),
        };
        const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement('a');
        a.href     = url;
        a.download = `cloudshield-report-${new Date().toISOString().slice(0,19).replace(/:/g,'-')}.json`;
        a.click();
        URL.revokeObjectURL(url);
        showToast('Security report downloaded ✅', 'success');
        addSocEvent('INFO', 'Full security report exported to JSON.');
    } catch (e) {
        showToast('Export failed: ' + e.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.innerHTML = '<span class="btn-icon">📥</span> Export Report'; }
    }
};

// ── Initialize ──
document.addEventListener('DOMContentLoaded', () => {
    loadCachedResults();
    renderScanHistory();
    renderSocTimeline();
    addSocEvent('INFO', 'CloudShield Dashboard v3 initialized.');

    // Panel navigation
    const pastePanel    = document.getElementById('config-panel');
    const telemetryPanel = document.getElementById('telemetry-panel');
    const s3Panel       = document.getElementById('s3-check-panel');
    const attackPanel   = document.getElementById('attack-dashboard');

    document.getElementById('btn-paste-panel')?.addEventListener('click', () => {
        pastePanel.classList.remove('hidden');
        [telemetryPanel, s3Panel, attackPanel].forEach(p => p?.classList.add('hidden'));
    });
    document.getElementById('btn-telemetry-panel')?.addEventListener('click', () => {
        telemetryPanel.classList.remove('hidden');
        attackPanel?.classList.remove('hidden');
        [pastePanel, s3Panel].forEach(p => p?.classList.add('hidden'));
    });
    document.getElementById('btn-storage-panel')?.addEventListener('click', () => {
        s3Panel.classList.remove('hidden');
        [pastePanel, telemetryPanel, attackPanel].forEach(p => p?.classList.add('hidden'));
    });
    document.getElementById('agent-sort-select')?.addEventListener('change', e => {
        currentFleetSort = e.target.value;
        fetchAgentTelemetry();
    });

    // Keyboard shortcuts
    document.addEventListener('keydown', e => {
        const tag = document.activeElement?.tagName;
        if (e.key === 'Enter' && tag !== 'TEXTAREA' && tag !== 'INPUT' && tag !== 'BUTTON') {
            if (!document.getElementById('btn-scan')?.disabled) runScan();
        }
        if (e.key === 'Escape') {
            [pastePanel, s3Panel].forEach(p => p?.classList.add('hidden'));
        }
    });

    // Polling — guarded by document.hidden
    fetchAgentTelemetry();
    setInterval(() => { if (!document.hidden) fetchAgentTelemetry(); }, 10000);
    fetchSecurityMetrics();
    setInterval(() => { if (!document.hidden) fetchSecurityMetrics(); }, 10000);
});

// ── Run Scan ──
async function runScan() {
    setButtonsDisabled(true);
    showPipelineRunning();
    clearLog();
    addLog('Starting scan...', 'info');
    try {
        const res = await fetch(`${API_BASE}/api/scan`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({})
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const json = await res.json();
        if (json.status === 'error') throw new Error(json.message || 'Scan failed');
        if (json.data) {
            renderResults(json.data);
            showPipelineDone();
            showToast('Scan completed successfully', 'success');
            addSocEvent('INFO', 'Full pipeline scan completed.');
        } else {
            showToast('Scan returned no data — backend may be warming up', 'warning');
        }
    } catch (e) {
        addLog('Scan failed: ' + e.message, 'error');
        showPipelineError();
        showToast('Scan failed: ' + e.message, 'error');
        addSocEvent('WARNING', `Pipeline scan error: ${e.message}`);
    } finally {
        setButtonsDisabled(false);
    }
}

// ── Run Demo ──
async function runDemo() {
    setButtonsDisabled(true);
    showPipelineRunning();
    clearLog();
    addLog('Running demo — BEFORE + AFTER scans...', 'info');
    try {
        const res = await fetch(`${API_BASE}/api/demo`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' }
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const json = await res.json();
        if (json.status === 'error') throw new Error(json.message || 'Demo failed');
        if (json.data) {
            renderResults(json.data.before);
            renderComparison(json.data.before, json.data.after);
            showPipelineDone();
            showToast('Demo complete — Before/After loaded', 'success');
            addSocEvent('INFO', 'Demo pipeline complete. Before/After comparison rendered.');
        }
    } catch (e) {
        addLog('Demo failed: ' + e.message, 'error');
        showPipelineError();
        showToast('Demo failed: ' + e.message, 'error');
        addSocEvent('WARNING', `Demo error: ${e.message}`);
    } finally {
        setButtonsDisabled(false);
    }
}

async function loadCachedResults() {
    try {
        const res = await fetch(`${API_BASE}/api/results`);
        if (!res.ok) return;
        const json = await res.json();
        if (json.status === 'cached' && json.data) {
            renderResults(json.data);
            addLog('Loaded cached results', 'info');
        }
    } catch { /* no cache yet */ }
}

// ── Paste & Scan ──
function toggleConfigPanel() {
    document.getElementById('config-panel')?.classList.toggle('hidden');
}
function clearConfigEditor() {
    document.getElementById('config-editor').value = '';
    document.getElementById('config-status').textContent = '';
}
function loadSampleBadConfig() {
    const sample = JSON.stringify({
        s3_buckets:[{name:'public-data-bucket',acl:'public-read',public_access_block:{block_public_acls:false,block_public_policy:false},encryption:{enabled:false},logging:{enabled:false}},{name:'logs-bucket',acl:'private',public_access_block:{block_public_acls:true,block_public_policy:true},encryption:{enabled:true,algorithm:'AES256'},logging:{enabled:false}}],
        iam_roles:[{name:'admin-role',mfa_required:false,policies:[{name:'full-access',action:'*',resource:'*'},{name:'s3-all',action:'s3:*',resource:'*'}]}],
        cloudtrail:{enabled:false,multi_region:false,log_file_validation:false},
        container_config:{privileged:true,run_as_root:true,read_only_rootfs:false}
    }, null, 2);
    document.getElementById('config-editor').value = sample;
    document.querySelector('input[name="config-type"][value="json"]').checked = true;
    document.getElementById('config-status').textContent = '✅ Sample bad config loaded';
}
async function scanRawConfig() {
    const configText = document.getElementById('config-editor').value.trim();
    const configType = document.querySelector('input[name="config-type"]:checked').value;
    const statusEl   = document.getElementById('config-status');
    if (!configText) {
        statusEl.textContent = '❌ Please paste a configuration first';
        statusEl.className = 'config-status error';
        showToast('Paste a configuration before analyzing', 'warning');
        return;
    }
    statusEl.textContent = '⏳ Analyzing...';
    statusEl.className = 'config-status loading';
    setButtonsDisabled(true);
    showPipelineRunning();
    clearLog();
    addLog(`Scanning ${configType.toUpperCase()} configuration...`, 'info');
    try {
        const res = await fetch(`${API_BASE}/api/scan-config`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ config_text: configText, config_type: configType })
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const json = await res.json();
        if (json.status === 'error') {
            statusEl.textContent = `❌ ${json.message}`;
            statusEl.className = 'config-status error';
            addLog(`Error: ${json.message}`, 'error');
            showToast(json.message, 'error');
            if (json.alerts) renderAlerts(json.alerts, { total:json.alerts.length, critical:0, high:1, medium:0, low:0 });
            showPipelineError();
        } else if (json.data) {
            const n = json.data.alert_summary?.total || 0;
            statusEl.textContent = `✅ Analysis complete — ${n} issues found`;
            statusEl.className = 'config-status success';
            renderResults(json.data);
            if (json.data.alerts)       renderAlerts(json.data.alerts, json.data.alert_summary);
            if (json.data.remediations) renderRemediations(json.data.remediations);
            showPipelineDone();
            showToast(`Config analyzed: ${n} issues`, n > 0 ? 'warning' : 'success');
            addSocEvent(n > 0 ? 'WARNING' : 'INFO', `Config scan: ${n} issues found.`);
        }
    } catch (e) {
        statusEl.textContent = `❌ Connection failed: ${e.message}`;
        statusEl.className = 'config-status error';
        addLog('Config scan failed: ' + e.message, 'error');
        showPipelineError();
        showToast('Backend unavailable: ' + e.message, 'error');
        addSocEvent('CRITICAL', `Backend unreachable during config scan: ${e.message}`);
    } finally {
        setButtonsDisabled(false);
    }
}

// ── Storage Scan History ──
function getScanHistoryS3() {
    try { return JSON.parse(localStorage.getItem('cloudshield_s3_history') || '[]'); }
    catch { return []; }
}
function saveToHistory(scanData) {
    let h = getScanHistoryS3();
    h.unshift(scanData);
    if (h.length > 10) h = h.slice(0, 10);
    localStorage.setItem('cloudshield_s3_history', JSON.stringify(h));
    renderHistory();
}
function renderHistory() {
    const list = document.getElementById('storage-history-list');
    if (!list) return;
    const history = getScanHistoryS3();
    const exportBtn = document.getElementById('btn-export-storage');
    if (!history.length) {
        list.innerHTML = '<div style="color:var(--text-secondary)">No scan history.</div>';
        if (exportBtn) exportBtn.style.display = 'none';
        return;
    }
    if (exportBtn) exportBtn.style.display = 'inline-flex';
    list.innerHTML = history.map(item => {
        const safe = item.status === 'PASS';
        return `<div style="display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid rgba(255,255,255,0.05);padding-bottom:0.5rem;">
            <div><span style="margin-right:0.5rem">${safe?'✅':'🚨'}</span>
            <strong style="color:${safe?'var(--color-low)':'var(--color-critical)'}">${escapeHtml(item.resource)}</strong>
            <span style="color:var(--text-secondary);margin-left:0.5rem;font-size:0.75rem;">(${item.provider.toUpperCase()})</span></div>
            <div style="color:var(--text-secondary);font-size:0.75rem;">${new Date(item.scannedAt).toLocaleString()} | ${item.scanDurationMs}ms</div>
        </div>`;
    }).join('');
}
function toggleHistory() {
    const d = document.getElementById('storage-history-drawer');
    if (!d) return;
    if (d.style.display === 'none') { renderHistory(); d.style.display = 'block'; }
    else d.style.display = 'none';
}
function exportStorageReport() {
    const h = getScanHistoryS3();
    if (!h.length) return;
    const blob = new Blob([JSON.stringify(h, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `storage-scans-${new Date().toISOString().slice(0,10)}.json`; a.click();
    URL.revokeObjectURL(url);
}

// ── Security Metrics + Attack Rate ──
window.fetchSecurityMetrics = async function() {
    try {
        const res = await fetch(`${API_BASE}/api/security-metrics`);
        if (!res.ok) return;
        const json = await res.json();
        if (json.status !== 'success') return;
        const m = json.metrics || {};
        lastMetricsData = m;

        // Cards
        const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v ?? 0; };
        set('metric-blocked-ips',  m.total_blocked);
        set('metric-attack-ips',   m.total_attack_ips);
        set('metric-attack-rate',  m.attack_rate);
        set('metric-peak-rate',    m.peak_attack_rate);

        // Live mini-chart
        updateAttackRateChart(m.attack_rate || 0);

        // Blocked IPs list
        const listDiv = document.getElementById('blocked-ips-list');
        if (listDiv) {
            if (!m.blocked_ips?.length) {
                listDiv.innerHTML = '<div style="color:var(--text-secondary);font-size:0.85rem;">No active blocks.</div>';
            } else {
                listDiv.innerHTML = m.blocked_ips.map(b =>
                    `<div style="display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid rgba(255,255,255,0.05);padding-bottom:0.5rem;font-size:0.85rem;">
                        <div><strong style="color:var(--color-critical)">${escapeHtml(b.ip)}</strong> <span style="color:var(--text-secondary);font-size:0.75rem;">(${escapeHtml(b.rule_id||'Pending')})</span></div>
                        <div style="color:var(--text-secondary)">Expires: <strong style="color:var(--color-info);">${b.time_remaining_seconds}s</strong></div>
                    </div>`
                ).join('');
                m.blocked_ips.forEach(b => {
                    const k = `blocked-${b.ip}`;
                    if (!sessionStorage.getItem(k)) {
                        addSocEvent('CRITICAL', `IP ${b.ip} blocked at Cloudflare Edge. Rule: ${b.rule_id||'Pending'}`);
                        sessionStorage.setItem(k, '1');
                    }
                });
            }
        }

        // SOC events for attack IPs
        (m.recent_attacks||[]).forEach(a => {
            const k = `attack-${a.ip}-${a.attempts}`;
            if (!sessionStorage.getItem(k) && a.attempts >= 3) {
                addSocEvent('WARNING', `Spoofing from ${a.ip} — ${a.attempts} bad auth attempts.`);
                sessionStorage.setItem(k, '1');
            }
        });

        updateStatusBar();
    } catch { /* silent poll error */ }
};

// ── Agent Telemetry ──
async function fetchAgentTelemetry() {
    try {
        const res = await fetch(`${API_BASE}/api/agent-status`);
        if (!res.ok) return;
        const json = await res.json();

        const badge     = document.getElementById('agent-status-badge');
        const container = document.getElementById('telemetry-container');
        const loading   = document.getElementById('telemetry-loading');
        const controls  = document.getElementById('fleet-controls');
        if (!badge || !container) return;

        if (!json.agents?.length) {
            badge.textContent = '🔴 Offline';
            badge.style.cssText = 'background:rgba(239,68,68,0.1);color:var(--color-critical);';
            container.innerHTML = '<div style="color:var(--text-secondary);text-align:center;padding:2rem;">No agents currently connected.</div>';
            if (loading) loading.style.display = 'none';
            if (controls) controls.style.display = 'none';
            document.getElementById('fleet-critical-banner')?.remove();
            lastAgentsData = [];
            updateStatusBar();
            return;
        }

        lastAgentsData = json.agents;
        loading.style.display = 'none';
        if (controls) controls.style.display = 'flex';

        // Sort
        const agents = [...json.agents].sort((a, b) => {
            if (currentFleetSort === 'risk')   return (b.risk_score||0) - (a.risk_score||0);
            if (currentFleetSort === 'health') return (b.healthScore||0) - (a.healthScore||0);
            return (a.hostname||'z').localeCompare(b.hostname||'z');
        });

        const onlineCount  = agents.filter(a => a.connection_status === 'online').length;
        const criticalCount = agents.filter(a => a.risk_level === 'Critical').length;
        const avgHealth    = Math.round(agents.reduce((s,a) => s+(a.healthScore||100),0)/agents.length);

        // Fleet badge
        badge.textContent = onlineCount > 0 ? `🟢 ${onlineCount}/${agents.length} Online` : '🔴 Offline';
        badge.style.cssText = onlineCount > 0
            ? 'background:rgba(34,197,94,0.15);color:var(--color-low);'
            : 'background:rgba(239,68,68,0.1);color:var(--color-critical);';

        const set = (id,v,s='') => { const el=document.getElementById(id); if(el){el.textContent=v; if(s) el.style.cssText=s;} };
        set('fleet-total-count', agents.length);
        set('fleet-critical-count', criticalCount);
        set('fleet-health-score', avgHealth+'%', `color:${avgHealth<50?'var(--color-critical)':avgHealth<80?'var(--color-medium)':'var(--color-low)'}`);

        // Agent cards
        container.innerHTML = agents.map(agent => {
            const riskColor = {Critical:'var(--color-critical)',High:'var(--color-high)',Medium:'var(--color-medium)'}[agent.risk_level]||'var(--color-low)';
            const lastSeen  = agent.last_seen_seconds_ago || 0;
            let connBadge, connBg, connColor;
            if (agent.connection_status === 'online' && lastSeen <= 60) {
                connBadge='🟢 Online';  connBg='rgba(34,197,94,0.15)';  connColor='var(--color-low)';
            } else if (agent.connection_status === 'stale') {
                connBadge='🟡 Stale';  connBg='rgba(234,179,8,0.15)';  connColor='var(--color-medium)';
            } else {
                connBadge='🔴 Offline'; connBg='rgba(239,68,68,0.1)';   connColor='var(--color-critical)';
            }
            const cpu  = agent.cpu_percent  || 0;
            const ram  = agent.ram_percent  || 0;
            const cves = agent.cves || { critical:0, high:0 };
            const bd   = agent.risk_breakdown || { system:0, network:0, cve:0 };
            const ports = agent.open_ports?.length
                ? agent.open_ports.map(p => `<li style="margin-bottom:0.2rem;"><code style="background:var(--bg-primary);padding:0.1rem 0.3rem;">${p.port}</code> <span style="color:var(--text-secondary)">${p.ip}</span></li>`).join('')
                : '<li style="color:var(--color-low)">✅ No unauthorized ports.</li>';

            return `<div style="border:1px solid var(--border-glass);border-radius:6px;overflow:hidden;background:rgba(255,255,255,0.02);margin-bottom:1rem;">
                <div style="display:flex;justify-content:space-between;align-items:center;padding:0.75rem 1rem;border-bottom:1px solid var(--border-glass);background:rgba(0,0,0,0.2);">
                    <div style="display:flex;align-items:center;gap:0.5rem;">
                        <span style="font-size:1.2rem;">🖥️</span>
                        <div>
                            <div style="font-weight:bold;">${escapeHtml(agent.hostname||'Unknown')}</div>
                            <div style="font-size:0.73rem;color:var(--text-secondary);">${escapeHtml(agent.agentId)} | v${escapeHtml(agent.agentVersion||'1.0')}</div>
                        </div>
                    </div>
                    <div style="display:flex;gap:1rem;align-items:center;">
                        <span style="display:inline-flex;align-items:center;padding:0.2rem 0.6rem;border-radius:999px;font-size:0.78rem;font-weight:600;background:${connBg};color:${connColor};border:1px solid ${connColor};">${connBadge}</span>
                        <div style="text-align:right;"><div style="font-size:1.05rem;font-weight:bold;color:${riskColor};">${agent.risk_level} RISK</div><div style="font-size:0.72rem;color:var(--text-secondary);">Score:${agent.risk_score} | Health:${agent.healthScore}%</div></div>
                    </div>
                </div>
                ${agent.priorityFix&&agent.priorityFix!=='No immediate action required.'?`<div style="padding:0.45rem 1rem;background:rgba(239,68,68,0.08);border-bottom:1px solid var(--border-glass);font-size:0.83rem;"><strong style="color:var(--color-critical);">⚡ Priority Fix:</strong> ${escapeHtml(agent.priorityFix)}</div>`:''}
                <div style="padding:1rem;">
                    <div style="display:flex;justify-content:space-around;margin-bottom:1rem;background:rgba(0,0,0,0.15);padding:0.45rem;border-radius:4px;font-size:0.78rem;">
                        <div>System:<strong style="color:${bd.system>0?'var(--color-high)':'var(--text-secondary)'}"> ${bd.system}</strong></div>
                        <div>Network:<strong style="color:${bd.network>0?'var(--color-high)':'var(--text-secondary)'}"> ${bd.network}</strong></div>
                        <div>CVE:<strong style="color:${bd.cve>0?'var(--color-critical)':'var(--text-secondary)'}"> ${bd.cve}</strong></div>
                    </div>
                    <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:1rem;">
                        <div>
                            <div style="display:flex;justify-content:space-between;font-size:0.83rem;margin-bottom:0.2rem;"><span>CPU</span><span>${cpu}%</span></div>
                            <div style="height:7px;background:rgba(255,255,255,0.08);border-radius:4px;overflow:hidden;"><div style="width:${cpu}%;height:100%;background:${cpu>90?'var(--color-critical)':cpu>70?'var(--color-medium)':'var(--color-info)'};transition:width .3s;"></div></div>
                        </div>
                        <div>
                            <div style="display:flex;justify-content:space-between;font-size:0.83rem;margin-bottom:0.2rem;"><span>RAM</span><span>${ram}%</span></div>
                            <div style="height:7px;background:rgba(255,255,255,0.08);border-radius:4px;overflow:hidden;"><div style="width:${ram}%;height:100%;background:${ram>90?'var(--color-critical)':'var(--color-medium)'};transition:width .3s;"></div></div>
                        </div>
                    </div>
                    <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;">
                        <div style="background:rgba(0,0,0,0.2);padding:0.75rem;border-radius:4px;max-height:130px;overflow-y:auto;">
                            <h3 style="margin:0 0 0.5rem;font-size:0.85rem;color:var(--text-secondary);">Open Ports</h3>
                            <ul style="list-style:none;padding:0;margin:0;font-size:0.82rem;">${ports}</ul>
                        </div>
                        <div style="background:rgba(0,0,0,0.2);padding:0.75rem;border-radius:4px;">
                            <h3 style="margin:0 0 0.5rem;font-size:0.85rem;color:var(--text-secondary);">CVE Density</h3>
                            <div style="display:flex;gap:1rem;justify-content:space-around;margin-top:0.25rem;">
                                <div style="text-align:center;"><div style="font-size:1.3rem;font-weight:800;color:var(--color-critical);">${cves.critical||0}</div><div style="font-size:0.68rem;">CRIT</div></div>
                                <div style="text-align:center;"><div style="font-size:1.3rem;font-weight:800;color:var(--color-high);">${cves.high||0}</div><div style="font-size:0.68rem;">HIGH</div></div>
                            </div>
                        </div>
                    </div>
                    <div style="margin-top:0.75rem;text-align:right;font-size:0.72rem;color:var(--text-secondary);">Updated ${lastSeen}s ago</div>
                </div>
            </div>`;
        }).join('');

        // Critical banner
        const section = document.getElementById('telemetry-panel');
        let banner = document.getElementById('fleet-critical-banner');
        if (criticalCount > 0) {
            if (!banner) {
                banner = document.createElement('div');
                banner.id = 'fleet-critical-banner';
                banner.style.cssText = 'padding:0.65rem 1rem;background:rgba(239,68,68,0.15);border:1px solid var(--color-critical);border-radius:6px;margin:0.75rem 0;color:var(--color-critical);display:flex;align-items:center;gap:0.5rem;font-size:0.9rem;';
                banner.innerHTML = `<strong>🚨 FLEET ALERT:</strong> ${criticalCount} agent(s) at critical risk. Immediate remediation required.`;
                section.insertBefore(banner, controls);
                addSocEvent('CRITICAL', `Fleet alert: ${criticalCount} critical-risk agent(s).`);
            }
        } else {
            banner?.remove();
        }

        updateStatusBar();
    } catch { /* silent */ }
}

// ── Storage Check ──
async function checkS3Bucket() {
    const input  = document.getElementById('s3-bucket-name');
    const name   = input.value.trim().toLowerCase();
    const provider = document.querySelector('input[name="cloud-provider"]:checked')?.value || 'aws';
    const resultDiv = document.getElementById('s3-check-result');
    const btn    = document.getElementById('btn-check-s3');

    if (!name) {
        resultDiv.style.display = 'block';
        resultDiv.innerHTML = '<span style="color:var(--color-critical)">❌ Enter a resource name</span>';
        showToast('Enter a resource name to check', 'warning');
        return;
    }
    if (!/^[a-z0-9.\-_]{3,63}$/.test(name)) {
        resultDiv.style.display = 'block';
        resultDiv.innerHTML = '<span style="color:var(--color-critical)">❌ Invalid name — only a-z, 0-9, hyphens, dots (3–63 chars)</span>';
        showToast('Invalid resource name format', 'error');
        input.style.borderColor = 'var(--color-critical)';
        setTimeout(() => { input.style.borderColor = ''; }, 3000);
        return;
    }

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Analyzing...';
    resultDiv.style.display = 'block';
    resultDiv.innerHTML = `<span style="color:var(--color-info)">⏳ Checking ${provider.toUpperCase()}…</span>`;

    try {
        const res = await fetch(`${API_BASE}/api/check-storage`, {
            method:'POST', headers:{'Content-Type':'application/json'},
            body: JSON.stringify({ provider, resource: name })
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const json = await res.json();
        if (json.status === 'error') {
            resultDiv.innerHTML = `<span style="color:var(--color-critical)">❌ ${escapeHtml(json.message)}</span>`;
            showToast(json.message, 'error');
        } else {
            const isPublic = json.isPublic;
            const statusColor = isPublic ? 'var(--color-critical)' : 'var(--color-low)';
            let extra = '';
            if (isPublic && json.remediation && json.remediation !== 'No action required.') {
                extra = `<div style="margin-top:0.75rem;padding-top:0.75rem;border-top:1px solid var(--border-glass);">
                    <div style="color:var(--text-secondary);font-size:0.83rem;margin-bottom:0.25rem;">Exposure</div>
                    <div style="margin-bottom:0.5rem;"><strong>${escapeHtml(json.exposureType)}</strong></div>
                    <div style="color:var(--text-secondary);font-size:0.83rem;margin-bottom:0.25rem;">Details</div>
                    <div style="margin-bottom:0.5rem;">${escapeHtml(json.details)}</div>
                    <div style="display:flex;justify-content:space-between;align-items:center;background:rgba(0,0,0,0.3);padding:0.45rem;border-radius:4px;font-family:monospace;font-size:0.82rem;">
                        <code>${escapeHtml(json.remediation)}</code>
                        <button class="btn btn-xs" onclick="copyCommand(this)">Copy</button>
                    </div>
                </div>`;
            }
            resultDiv.innerHTML = `
                <div style="display:flex;justify-content:space-between;align-items:center;">
                    <div><span class="badge badge-medium" style="margin-right:0.4rem;">${json.provider.toUpperCase()}</span><strong>Resource:</strong> <code>${escapeHtml(json.resource)}</code></div>
                    <span class="badge ${json.risk==='Critical'?'badge-critical':json.risk==='Medium'?'badge-medium':'badge-low'}">Risk: ${json.risk} (${json.confidence}%)</span>
                </div>
                <div style="margin-top:0.4rem;font-size:1rem;color:${statusColor};font-weight:bold;">${isPublic?'🚨 PUBLICLY ACCESSIBLE':'✅ SECURE (Private)'}</div>
                ${extra}`;
            saveToHistory(json);
            showToast(isPublic ? `⚠️ ${name} is PUBLICLY exposed` : `✅ ${name} is secure`, isPublic ? 'error' : 'success');
            addSocEvent(isPublic ? 'CRITICAL' : 'INFO', `Storage: ${name} (${provider.toUpperCase()}) — ${isPublic ? 'EXPOSED' : 'Secure'}`);
        }
    } catch (e) {
        resultDiv.innerHTML = `<span style="color:var(--color-critical)">❌ Connection failed: ${e.message}</span>`;
        showToast('Storage check failed: ' + e.message, 'error');
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<span class="btn-icon">☁️</span> Check Storage';
    }
}

// ── Alerts ──
function renderAlerts(alerts, summary) {
    const section = document.getElementById('alerts-section');
    section?.classList.remove('hidden');
    const summaryEl = document.getElementById('alert-summary');
    if (summaryEl) summaryEl.innerHTML = ['critical','high','medium','low','total'].map(k =>
        `<div class="alert-stat ${k}"><span class="alert-count">${summary?.[k]||0}</span> ${k.charAt(0).toUpperCase()+k.slice(1)}</div>`
    ).join('');
    const container = document.getElementById('alerts-container');
    if (!container) return;
    if (!alerts?.length) {
        container.innerHTML = '<div style="text-align:center;color:var(--text-secondary);padding:2rem;">✅ No alerts detected.</div>';
        return;
    }
    container.innerHTML = '';
    alerts.forEach(alert => {
        const card = document.createElement('div');
        card.className = `alert-card alert-${(alert.severity||'low').toLowerCase()}`;
        card.innerHTML = `<div class="alert-header"><span class="alert-level">${alert.alert_level||'ℹ️ INFO'}</span><span class="badge badge-${(alert.severity||'low').toLowerCase()}">${alert.severity}</span></div>
            <div class="alert-title">${escapeHtml(alert.title||'Unknown')}</div>
            <div class="alert-message">${escapeHtml(alert.message||'')}</div>
            <div class="alert-meta"><span>ID: <code>${alert.id||'N/A'}</code></span><span>Type: ${alert.type||'N/A'}</span></div>`;
        container.appendChild(card);
    });
}

// ── Remediations ──
function renderRemediations(remediations) {
    const section = document.getElementById('remediation-section');
    section?.classList.remove('hidden');
    const container = document.getElementById('remediation-container');
    if (!container) return;
    if (!remediations?.length) {
        container.innerHTML = '<div style="text-align:center;color:var(--text-secondary);padding:2rem;">✅ No remediation actions required.</div>';
        return;
    }
    container.innerHTML = '';
    remediations.forEach(rem => {
        const card = document.createElement('div');
        card.className = `remediation-card confidence-${rem.confidence||'low'}`;
        card.innerHTML = `<div class="rem-header"><span class="rem-title">🔧 ${escapeHtml(rem.title||'Unknown Fix')}</span><span class="badge badge-confidence-${rem.confidence||'low'}">${(rem.confidence||'low').toUpperCase()} confidence</span></div>
            <div class="rem-description">${escapeHtml(rem.description||'')}</div>
            <div class="rem-command"><div class="rem-command-header"><span>Fix Command:</span><button class="btn btn-xs" onclick="copyCommand(this)">📋 Copy</button></div><pre><code>${escapeHtml(rem.command||'# No command available')}</code></pre></div>
            <div class="rem-meta"><span>Finding: <code>${rem.finding_id||'N/A'}</code></span><span>Strategy: ${rem.strategy||'N/A'}</span></div>`;
        container.appendChild(card);
    });
}

function copyCommand(btn) {
    const code = btn.closest('.rem-command')?.querySelector('code') || btn.closest('div')?.querySelector('code');
    if (!code) return;
    navigator.clipboard.writeText(code.textContent).then(() => {
        const orig = btn.textContent; btn.textContent = '✅ Copied!';
        setTimeout(() => { btn.textContent = orig; }, 2000);
    });
}

// ── Render Results ──
function renderResults(data) {
    if (!data) return;
    const findings = data.findings || [];
    const risk = data.risk || {};
    animateCounter('total-vulns',     findings.filter(f => f.source==='trivy').length);
    animateCounter('total-misconfig', findings.filter(f => f.source==='opa').length);
    animateCounter('total-correlated',findings.filter(f => f.source==='correlation').length);
    const riskScore = risk.final_score || 0;
    document.getElementById('risk-score').textContent = riskScore;
    const cat = risk.category || 'LOW';
    const catBadge = document.getElementById('risk-category');
    if (catBadge) { catBadge.textContent = cat; catBadge.className = 'card-badge badge-'+cat.toLowerCase(); }

    const logs = data.execution_log || [];
    clearLog();
    (logs.length ? logs : ['No execution log returned.']).forEach(l => addLog(l, l.includes('✓')?'success':'info'));

    renderSeverityChart(findings);
    renderSourceChart(findings);
    renderStreamChart(risk);
    renderTopIssues(findings, data.remediations||[]);
    renderFindingsTable(findings, data.remediations||[]);

    // Update risk trend mini-chart
    updateRiskTrendChart(riskScore);

    // Save to history
    saveScanToHistory(data);
}

// ── Charts ──
function renderSeverityChart(findings) {
    const counts = { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0 };
    findings.forEach(f => { if (f.severity in counts) counts[f.severity]++; });
    const ctx = document.getElementById('severity-bar-chart').getContext('2d');
    if (severityBarChart) severityBarChart.destroy();
    severityBarChart = new Chart(ctx, {
        type:'bar', data:{ labels:Object.keys(counts), datasets:[{ label:'Findings', data:Object.values(counts), backgroundColor:Object.keys(counts).map(k=>SEVERITY_COLORS[k]), borderRadius:6, borderSkipped:false }] },
        options:{ responsive:true, plugins:{legend:{display:false}}, scales:{ y:{beginAtZero:true,ticks:{color:'#94a3b8',stepSize:1},grid:{color:'rgba(255,255,255,0.05)'}}, x:{ticks:{color:'#94a3b8'},grid:{display:false}} } }
    });
}
function renderSourceChart(findings) {
    const counts = { trivy:0, opa:0, correlation:0 };
    findings.forEach(f => { if (f.source in counts) counts[f.source]++; });
    const ctx = document.getElementById('source-doughnut-chart').getContext('2d');
    if (sourceDoughnutChart) sourceDoughnutChart.destroy();
    sourceDoughnutChart = new Chart(ctx, {
        type:'doughnut', data:{ labels:['CVE (Trivy)','Policy (OPA)','Correlated'], datasets:[{ data:Object.values(counts), backgroundColor:Object.values(SOURCE_COLORS), borderWidth:0, hoverOffset:8 }] },
        options:{ responsive:true, cutout:'65%', plugins:{ legend:{ position:'bottom', labels:{color:'#94a3b8',padding:12,usePointStyle:true,pointStyleWidth:10} } } }
    });
}
function renderStreamChart(risk) {
    const ctx = document.getElementById('stream-bar-chart').getContext('2d');
    if (streamBarChart) streamBarChart.destroy();
    streamBarChart = new Chart(ctx, {
        type:'bar', data:{ labels:['CVE Stream','Policy Stream','Corr. Stream'], datasets:[{ label:'Score', data:[risk.cve_score||0,risk.policy_score||0,risk.correlated_score||0], backgroundColor:[SOURCE_COLORS.trivy,SOURCE_COLORS.opa,SOURCE_COLORS.correlation], borderRadius:6, borderSkipped:false }] },
        options:{ indexAxis:'y', responsive:true, plugins:{legend:{display:false}}, scales:{ x:{beginAtZero:true,max:4.5,ticks:{color:'#94a3b8'},grid:{color:'rgba(255,255,255,0.05)'}}, y:{ticks:{color:'#94a3b8'},grid:{display:false}} } }
    });
}

// ── Comparison ──
function renderComparison(before, after) {
    document.getElementById('comparison-section')?.classList.remove('hidden');
    const bf=before.findings||[], af=after.findings||[], br=before.risk||{}, ar=after.risk||{};
    const set = (id,v) => { const el=document.getElementById(id); if(el) el.textContent=v; };
    set('comp-before-issues', bf.length); set('comp-after-issues', af.length);
    set('comp-before-crit', bf.filter(f=>f.severity==='CRITICAL').length);
    set('comp-after-crit',  af.filter(f=>f.severity==='CRITICAL').length);
    set('comp-before-score', br.final_score||0); set('comp-after-score', ar.final_score||0);
    set('comp-before-cat', br.category||'N/A');  set('comp-after-cat', ar.category||'N/A');
    const reduction = br.final_score>0 ? Math.round(((br.final_score-(ar.final_score||0))/br.final_score)*100) : 0;
    set('reduction-badge', `↓ ${reduction}% Risk Reduction`);
    const ctx = document.getElementById('trend-chart').getContext('2d');
    if (trendChart) trendChart.destroy();
    trendChart = new Chart(ctx, {
        type:'bar', data:{ labels:['CVE','Policy','Corr.','Final'],
            datasets:[{ label:'BEFORE', data:[br.cve_score||0,br.policy_score||0,br.correlated_score||0,br.final_score||0], backgroundColor:'rgba(239,68,68,0.7)', borderRadius:4 },
                       { label:'AFTER',  data:[ar.cve_score||0,ar.policy_score||0,ar.correlated_score||0,ar.final_score||0], backgroundColor:'rgba(34,197,94,0.7)',  borderRadius:4 }] },
        options:{ responsive:true, plugins:{legend:{labels:{color:'#94a3b8'}}}, scales:{ y:{beginAtZero:true,max:4.5,ticks:{color:'#94a3b8'},grid:{color:'rgba(255,255,255,0.05)'}}, x:{ticks:{color:'#94a3b8'},grid:{display:false}} } }
    });
}

// ── Top 5 Issues ──
function renderTopIssues(findings, remediations) {
    const remMap = {};
    remediations.forEach(r => { remMap[r.finding_id] = r; });
    const top5 = [...findings].sort((a,b) => ({CRITICAL:4,HIGH:3,MEDIUM:2,LOW:1}[b.severity]||0)-({CRITICAL:4,HIGH:3,MEDIUM:2,LOW:1}[a.severity]||0)).slice(0,5);
    const tbody = document.getElementById('top-issues-body');
    if (!tbody) return;
    if (!top5.length) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--color-low);padding:1.5rem;">✅ No critical issues detected.</td></tr>';
        return;
    }
    tbody.innerHTML = '';
    top5.forEach((f,i) => {
        const rem = remMap[f.id]||{};
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${i+1}</td><td><code>${f.id||'N/A'}</code></td><td>${f.source||'N/A'}</td>
            <td><span class="badge badge-${(f.severity||'low').toLowerCase()}">${f.severity||'N/A'}</span></td>
            <td>${{CRITICAL:4,HIGH:3,MEDIUM:2,LOW:1}[f.severity]||0}</td>
            <td title="${escapeHtml(rem.command||'')}">${escapeHtml((rem.title||'N/A').substring(0,50))}</td>`;
        tbody.appendChild(tr);
    });
}

// ── Full Findings Table ──
function renderFindingsTable(findings, remediations) {
    const remMap = {};
    remediations.forEach(r => { remMap[r.finding_id] = r; });
    const tbody = document.getElementById('findings-body');
    if (!tbody) return;
    if (!findings?.length) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--color-low);padding:1.5rem;">✅ No findings. System may be clean.</td></tr>';
        return;
    }
    tbody.innerHTML = '';
    findings.forEach(f => {
        const rem = remMap[f.id]||{};
        const comp = f.compliance||{};
        const fw = [comp.nist?.length&&'NIST', comp.iso27001?.length&&'ISO', comp.hipaa?.length&&'HIPAA'].filter(Boolean);
        const tr = document.createElement('tr');
        tr.innerHTML = `<td><code>${(f.id||'N/A').substring(0,20)}</code></td><td>${f.type||'N/A'}</td>
            <td><span class="badge badge-${(f.severity||'low').toLowerCase()}">${f.severity||'N/A'}</span></td>
            <td>${escapeHtml((f.title||f.message||'N/A').substring(0,60))}</td>
            <td>${escapeHtml((rem.title||'N/A').substring(0,40))}</td>
            <td>${fw.join(', ')||'—'}</td>`;
        tbody.appendChild(tr);
    });
}

// ── UI Helpers ──
function animateCounter(id, target) {
    const el = document.getElementById(id);
    if (!el) return;
    let cur = 0; const step = Math.max(1, Math.ceil(target/20));
    const iv = setInterval(() => { cur = Math.min(cur+step, target); el.textContent = cur; if (cur >= target) clearInterval(iv); }, 40);
}
function escapeHtml(str) { const d=document.createElement('div'); d.textContent=str||''; return d.innerHTML; }
function setButtonsDisabled(disabled) {
    ['btn-scan','btn-demo','btn-analyze'].forEach(id => { const el=document.getElementById(id); if(el) el.disabled=disabled; });
    const scan = document.getElementById('btn-scan');
    if (scan) scan.innerHTML = disabled ? '<span class="spinner"></span> Scanning...' : '<span class="btn-icon">⚡</span> Run Scan';
    const demo = document.getElementById('btn-demo');
    if (demo && !disabled) demo.innerHTML = '<span class="pulse-dot"></span> Live Scan';
}
function showPipelineRunning() {
    document.querySelectorAll('.pipeline-step').forEach(el => { el.classList.remove('done','error'); el.classList.add('active'); el.querySelector('.step-status').innerHTML='<span class="spinner"></span>'; });
}
function showPipelineDone() {
    document.querySelectorAll('.pipeline-step').forEach(el => { el.classList.remove('active','error'); el.classList.add('done'); el.querySelector('.step-status').textContent='✓ Done'; });
}
function showPipelineError() {
    document.querySelectorAll('.pipeline-step').forEach(el => { el.classList.remove('active','done'); el.classList.add('error'); el.querySelector('.step-status').textContent='✗ Error'; });
}
function clearLog() { document.getElementById('execution-log').innerHTML=''; }
function addLog(message, type) {
    const log = document.getElementById('execution-log');
    log.querySelector('.log-placeholder')?.remove();
    const div = document.createElement('div');
    div.className = 'log-entry '+(type||'info');
    div.textContent = message;
    log.appendChild(div); log.scrollTop = log.scrollHeight;
}

// ── Global Exports ──
window.runScan           = runScan;
window.runDemo           = runDemo;
window.toggleConfigPanel = toggleConfigPanel;
window.clearConfigEditor = clearConfigEditor;
window.loadSampleBadConfig = loadSampleBadConfig;
window.scanRawConfig     = scanRawConfig;
window.copyCommand       = copyCommand;
window.checkS3Bucket     = checkS3Bucket;
window.toggleHistory     = toggleHistory;
window.exportStorageReport = exportStorageReport;
window.fetchSecurityMetrics = window.fetchSecurityMetrics;
window.reloadScan        = reloadScan;

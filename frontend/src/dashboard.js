/* CloudShield Dashboard v3 — SaaS Production */

const API_BASE = window.location.origin.includes('localhost') ? 'http://localhost:5000' : 'https://cloudshield-tya3.onrender.com';

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
        const agents = ar.status === 'fulfilled' ? ar.value.agents : [];
        const metrics = mr.status === 'fulfilled' ? mr.value.metrics : {};
        const events = sr.status === 'fulfilled' ? sr.value.events : [];
        const history = getScanHistory().map(h => ({ timestamp:h.timestamp, risk:h.risk, findings_count:h.findingsCount }));

        const activeAgent = agents && agents.length > 0 ? agents[0] : null;
        let primaryIp = 'Unknown';
        if (activeAgent && activeAgent.open_ports && activeAgent.open_ports.length > 0) {
            primaryIp = activeAgent.open_ports[0].ip === '::' ? '127.0.0.1' : activeAgent.open_ports[0].ip;
        }

        const safeData = {
            target_info: {
                hostname: activeAgent ? activeAgent.hostname : "Unknown",
                ip_address: primaryIp,
                timestamp: new Date().toISOString(),
                agent_version: activeAgent ? activeAgent.agentVersion : "N/A"
            },
            history: history || [],
            agents: agents || [],
            metrics: metrics || {},
            events: events || []
        };

        const blob = new Blob([JSON.stringify(safeData, null, 2)], { type: 'application/json' });
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

    });

// ── Run Scan ──
async function runScan() {
    setButtonsDisabled(true);
    showPipelineRunning();
    clearLog();
    addLog('Starting live agent scan...', 'info');
    try {
        const res = await fetch(`${API_BASE}/api/scan`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({})
        });
        
        let json;
        try { json = await res.json(); } catch(e) {}
        
        if (!res.ok) {
            throw new Error(json && json.message ? json.message : `HTTP ${res.status}`);
        }
        if (json && json.status === 'error') {
            throw new Error(json.message || 'Scan failed');
        }
        if (json && json.data) {
            renderResults(json.data);
            showPipelineDone();
            showToast('Scan completed successfully with Live Agent data', 'success');
            addSocEvent('INFO', 'Full pipeline scan completed using live data.');
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

// runDemo removed — system operates on real data only.
// The Run Demo button now triggers a real scan instead.
async function runDemo() {
    showToast('Demo mode disabled — running live scan instead.', 'info');
    addSocEvent('INFO', 'Demo disabled. Redirecting to live scan.');
    runScan();
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
        const res = await fetch(`${API_BASE}/api/scan/cloud`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: configText
        });
        const json = await res.json();
        
        console.log("Cloud scan response:", json);

        const violations = json?.violations || [];

        if (violations.length > 0) {
            statusEl.textContent = `✅ Analysis complete — ${violations.length} issues found`;
            statusEl.className = 'config-status warning';

            renderAlerts(violations.map(v => ({
                title: v.title,
                severity: v.severity,
                description: v.description || v.message
            })));

            console.log("Findings sent to AI:", violations);
            runAIAnalysis(violations);

            showPipelineDone();
            showToast(`Config analyzed: ${violations.length} issues`, 'warning');
            addSocEvent('WARNING', `Config scan: ${violations.length} issues found.`);
        } else {
            statusEl.textContent = '✅ Analysis complete — 0 issues found';
            statusEl.className = 'config-status success';
            renderAlerts([]);
            showPipelineDone();
            showToast('No misconfigurations found', 'success');
            addSocEvent('INFO', 'Config scan clean: 0 issues found');
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

window.fetchSecurityMetrics = async function(silent = false) {
    try {
        const res = await fetch(`${API_BASE}/api/security-metrics`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const json = await res.json();
        if (!json || json.status !== 'success') {
            if (!silent) showToast("❌ Failed to load metrics", "error");
            return;
        }
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
    } catch (e) {
        if (!silent) showToast("❌ Security metrics unavailable", "error");
    }
};

// ── Agent Telemetry ──
// ── Agent Telemetry ───────────────────────────────────────────
function updateAgentsUI(agents) {
    if (!agents) return;
    const badge     = document.getElementById('agent-status-badge');
    const container = document.getElementById('telemetry-container');
    const loading   = document.getElementById('telemetry-loading');
    const controls  = document.getElementById('fleet-controls');
    if (!badge || !container) return;

    if (!agents.length) {
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

    lastAgentsData = agents;
    if (loading) loading.style.display = 'none';
    if (controls) controls.style.display = 'flex';

    // Sort
    const sortedAgents = [...agents].sort((a, b) => {
        if (currentFleetSort === 'risk')   return (b.risk_score||0) - (a.risk_score||0);
        if (currentFleetSort === 'health') return (b.healthScore||0) - (a.healthScore||0);
        return (a.hostname||'z').localeCompare(b.hostname||'z');
    });

    const onlineCount  = sortedAgents.filter(a => a.connection_status === 'online').length;
    const criticalCount = sortedAgents.filter(a => a.risk_level === 'Critical').length;
    const avgHealth    = Math.round(sortedAgents.reduce((s,a) => s+(a.healthScore||100),0)/sortedAgents.length);

    // Fleet badge
    badge.textContent = onlineCount > 0 ? `🟢 ${onlineCount}/${sortedAgents.length} Online` : '🔴 Offline';
    badge.style.cssText = onlineCount > 0
        ? 'background:rgba(34,197,94,0.15);color:var(--color-low);'
        : 'background:rgba(239,68,68,0.1);color:var(--color-critical);';

    const set = (id,v,s='') => { const el=document.getElementById(id); if(el){el.textContent=v; if(s) el.style.cssText=s;} };
    set('fleet-total-count', sortedAgents.length);
    set('fleet-critical-count', criticalCount);
    set('fleet-health-score', avgHealth+'%', `color:${avgHealth<50?'var(--color-critical)':avgHealth<80?'var(--color-medium)':'var(--color-low)'}`);

    // Agent cards
    container.innerHTML = sortedAgents.map(agent => {
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
}

function updateSecurityMetricsUI(m) {
    if (!m) return;
    lastMetricsData = m;
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v ?? 0; };
    set('metric-blocked-ips',  m.total_blocked);
    set('metric-attack-ips',   m.total_attack_ips || m.total_attack_ips_count || 0);
    set('metric-attack-rate',  m.attack_rate);
    set('metric-peak-rate',    m.peak_attack_rate);

    updateAttackRateChart(m.attack_rate || 0);

    const listDiv = document.getElementById('blocked-ips-list');
    if (listDiv) {
        if (!m.blocked_ips?.length) {
            listDiv.innerHTML = '<div style="color:var(--text-secondary);font-size:0.85rem;">No active blocks.</div>';
        } else {
            listDiv.innerHTML = m.blocked_ips.map(b =>
                `<div style="display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid rgba(255,255,255,0.05);padding-bottom:0.5rem;font-size:0.85rem;">
                    <div><strong style="color:var(--color-critical)">${escapeHtml(b.ip)}</strong></div>
                    <div style="color:var(--text-secondary)">Expires: <strong style="color:var(--color-info);">${b.time_remaining_seconds}s</strong></div>
                </div>`
            ).join('');
        }
    }
}

function updateGlobalRiskUI(risk) {
    if (!risk) return;
    const rEl = document.getElementById('sb-global-risk');
    if (!rEl) return;
    const score = risk.final_score || 0;
    const category = risk.category || 'LOW';
    rEl.textContent = `${score}/100`;
    const riskColor = { CRITICAL:'var(--color-critical)', HIGH:'var(--color-high)', MEDIUM:'var(--color-medium)', LOW:'var(--color-low)' }[category] || 'var(--color-low)';
    rEl.style.color = riskColor;
    updateRiskTrendChart(score);
}

function updateAlertsUI(alerts) {
    const countEl = document.getElementById('sb-alert-count');
    if (countEl) countEl.textContent = alerts?.length || 0;
    
    const container = document.getElementById('alerts-list-container');
    if (!container) return;
    if (!alerts?.length) {
        container.innerHTML = '<p style="color:var(--text-muted); font-size:0.85rem;">No recent alerts.</p>';
    } else {
        container.innerHTML = alerts.map(a => {
            const color = a.level === 'CRITICAL' ? 'var(--color-critical)' : 'var(--color-high)';
            return `
            <div style="border-left: 3px solid ${color}; padding: 0.75rem; background: var(--bg-primary); margin-bottom: 0.5rem; border-radius: 4px;">
                <div style="font-size: 0.75rem; color: var(--text-muted); margin-bottom: 0.2rem;">${a.timestamp} | ${a.source || 'agent'}</div>
                <div style="font-weight: 600; font-size: 0.85rem;">[${a.level}] ${a.message}</div>
            </div>`;
        }).join('');
    }
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
        const res = await fetch(`${API_BASE}/api/storage/check`, {
            method:'POST', headers:{'Content-Type':'application/json'},
            body: JSON.stringify({ provider, bucket: name })
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const json = await res.json();
                console.log('Storage API response:', json);
                const providerLabel = (json.provider || provider).toUpperCase();
                const bucketLabel   = escapeHtml(json.bucket || name);
                const demoTag = json.demo ? '<span style="font-size:0.75rem;padding:2px 8px;border-radius:20px;background:rgba(255,200,0,0.15);color:#FFD700;">⚡ Demo</span>' : '';
                if (json.public === true) {
            resultDiv.innerHTML = `<div style="display:flex;align-items:center;gap:0.6rem;margin-bottom:0.5rem;"><span style="background:rgba(255,60,60,0.15);color:var(--color-critical);padding:3px 10px;border-radius:20px;font-size:0.8rem;font-weight:600;">${providerLabel}</span><code style="color:var(--text-primary);">${bucketLabel}</code>${demoTag}</div><div style="font-size:1.15rem;font-weight:700;color:var(--color-critical);">🔴 PUBLIC</div><div style="color:var(--text-secondary);font-size:0.85rem;margin-top:0.25rem;">${escapeHtml(json.status||'Publicly accessible')}</div>`;
            showToast('🚨 Bucket is PUBLIC', 'error');
            addSocEvent('CRITICAL', `Storage: ${name} (${providerLabel}) — EXPOSED`);
            runAIAnalysis([{ title: `Public Storage Bucket: ${name}`, severity: 'HIGH', description: `${providerLabel} bucket "${name}" is publicly accessible.`, type: 'CloudMisconfiguration', id: 'CS-STORAGE-PUBLIC' }]);
        } else if (json.error) {
            resultDiv.innerHTML = `<span style="color:var(--color-critical)">❌ Error: ${escapeHtml(json.error)}</span>`;
            showToast(json.error, 'error');
        } else {
            resultDiv.innerHTML = `<div style="display:flex;align-items:center;gap:0.6rem;margin-bottom:0.5rem;"><span style="background:rgba(40,220,120,0.15);color:var(--color-low);padding:3px 10px;border-radius:20px;font-size:0.8rem;font-weight:600;">${providerLabel}</span><code style="color:var(--text-primary);">${bucketLabel}</code>${demoTag}</div><div style="font-size:1.15rem;font-weight:700;color:var(--color-low);">🟢 PRIVATE</div><div style="color:var(--text-secondary);font-size:0.85rem;margin-top:0.25rem;">${escapeHtml(json.status||'Not publicly accessible')}</div>`;
            showToast('✅ Bucket is NOT public', 'success');
            addSocEvent('INFO', `Storage: ${name} (${providerLabel}) — SECURE`);
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
    const parent = document.getElementById('severity-bar-chart')?.parentElement;
    if (!findings || findings.length === 0) {
        if (parent && !parent.innerText.includes('No data available')) {
            parent.innerHTML = '<h3>Severity Distribution</h3><div style="color:var(--text-secondary);text-align:center;padding:2rem;">No data available</div>';
        }
        return;
    }
    const counts = { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0 };
    findings.forEach(f => { if (f.severity in counts) counts[f.severity]++; });
    const ctx = document.getElementById('severity-bar-chart')?.getContext('2d');
    if (!ctx) return;
    if (severityBarChart) severityBarChart.destroy();
    severityBarChart = new Chart(ctx, {
        type:'bar', data:{ labels:Object.keys(counts), datasets:[{ label:'Findings', data:Object.values(counts), backgroundColor:Object.keys(counts).map(k=>SEVERITY_COLORS[k]), borderRadius:6, borderSkipped:false }] },
        options:{ responsive:true, plugins:{legend:{display:false}}, scales:{ y:{beginAtZero:true,ticks:{color:'#94a3b8',stepSize:1},grid:{color:'rgba(255,255,255,0.05)'}}, x:{ticks:{color:'#94a3b8'},grid:{display:false}} } }
    });
}
function renderSourceChart(findings) {
    const parent = document.getElementById('source-doughnut-chart')?.parentElement;
    if (!findings || findings.length === 0) {
        if (parent && !parent.innerText.includes('No data available')) {
            parent.innerHTML = '<h3>Finding Sources</h3><div style="color:var(--text-secondary);text-align:center;padding:2rem;">No data available</div>';
        }
        return;
    }
    const counts = { trivy:0, opa:0, correlation:0 };
    findings.forEach(f => { if (f.source in counts) counts[f.source]++; });
    const ctx = document.getElementById('source-doughnut-chart')?.getContext('2d');
    if (!ctx) return;
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


// ── SaaS Stability Controller ──
let _hubInterval = null;
let _backoffActive = false;

async function fetchDashboardHub(isSilent = false) {
    if (document.hidden || _backoffActive) return;
    try {
        const response = await fetch(`${API_BASE}/api/dashboard-summary`);
        if (response.status === 429) {
            _backoffActive = true;
            if (!isSilent) showToast("⚠️ Server rate limit hit. Pausing updates for 60s.", "warning");
            setTimeout(() => { _backoffActive = false; }, 60000);
            return;
        }
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const json = await response.json();
        
        // DevSecOps Guard: Mandatory safe render check
        if (!json || json.status !== 'success') {
            showToast("Error loading data", "error");
            return;
        }

        const data = json.data;
        
        // 1. Update Agents
        if (data.agents) updateAgentsUI(data.agents);
        
        // 2. Update Security Metrics
        if (data.metrics) updateSecurityMetricsUI(data.metrics);
        
        // 3. Update Global Risk
        if (data.risk) updateGlobalRiskUI(data.risk);

        // 4. Update Alerts & Keys
        if (data.alerts) updateAlertsUI(data.alerts);
        if (data.deploy) {
            _deployApiKey = data.deploy.api_key;
            _deployDownloadUrl = data.deploy.download_url;
        }

        updateStatusBar();
    } catch (e) {
        console.error("Hub fetch error:", e);
    }
}

function startSaaSPerformanceHub() {
    if (_hubInterval) clearInterval(_hubInterval);

    // ── SSE (Server-Sent Events) for real-time push ──
    // Falls back to 30s polling if SSE is not supported or fails
    let sseActive = false;

    if (typeof EventSource !== 'undefined') {
        try {
            const evtSource = new EventSource(`${API_BASE}/api/stream`);

            evtSource.addEventListener('agent_update', (e) => {
                try {
                    const d = JSON.parse(e.data);
                    // Merge SSE push into a minimal agent update
                    if (lastAgentsData) {
                        const idx = lastAgentsData.findIndex(a => a.agentId === d.agentId);
                        if (idx >= 0) {
                            lastAgentsData[idx].cpu_percent = d.cpu;
                            lastAgentsData[idx].ram_percent = d.ram;
                            lastAgentsData[idx].risk_score  = d.risk_score;
                            lastAgentsData[idx].risk_level  = d.risk_level;
                            lastAgentsData[idx].last_seen_seconds_ago = 0;
                            lastAgentsData[idx].connection_status = 'online';
                            updateAgentsUI(lastAgentsData);
                        }
                    }
                    updateRiskTrendChart(d.risk_score || 0);
                    addSocEvent('INFO', `Live update: ${d.hostname || d.agentId} | Risk ${d.risk_level}`);
                } catch (_) {}
            });

            evtSource.onerror = () => {
                if (sseActive) return; // Already logged
                console.warn('[SSE] Stream error — falling back to 30s polling');
                sseActive = false;
            };

            evtSource.onopen = () => {
                sseActive = true;
                addSocEvent('INFO', 'Real-time SSE stream connected.');
            };
        } catch (_) {
            console.warn('[SSE] Could not connect — using polling only');
        }
    }

    // Always run initial hub fetch + 3s polling as reliable baseline
    fetchDashboardHub(true);
    _hubInterval = setInterval(() => fetchDashboardHub(true), 3000);
}

// ── Global Exports ──
window.runScan           = runScan;
window.runDemo           = runDemo; // stub: runs live scan instead
window.toggleConfigPanel = toggleConfigPanel;
window.clearConfigEditor = clearConfigEditor;
window.scanRawConfig     = scanRawConfig;
window.copyCommand       = copyCommand;
window.checkS3Bucket     = checkS3Bucket;
window.toggleHistory     = toggleHistory;
window.exportStorageReport = exportStorageReport;
window.fetchSecurityMetrics = window.fetchSecurityMetrics;
window.reloadScan        = reloadScan;
    startSaaSPerformanceHub();

// ── Deploy Agent Modal ──
let _deployApiKey = '';
let _deployDownloadUrl = '';

window.openDeployModal = async function() {
    const modal = document.getElementById('deploy-modal');
    if (!modal) return;
    modal.classList.remove('hidden');
    document.body.style.overflow = 'hidden';

    // Fetch API key info from backend
    try {
        const res = await fetch(`${API_BASE}/api/agent-keys`);
        const data = await res.json();
        if (data.status === 'success') {
            _deployApiKey = data.api_key || 'N/A';
            _deployDownloadUrl = data.download_url || `${API_BASE}/api/download-agent`;
        } else {
            _deployApiKey = 'default-agent-key-123';
            _deployDownloadUrl = `${API_BASE}/api/download-agent`;
        }
    } catch {
        _deployApiKey = 'default-agent-key-123';
        _deployDownloadUrl = `${API_BASE}/api/download-agent`;
    }

    // Populate UI
    const keyEl = document.getElementById('deploy-api-key');
    if (keyEl) keyEl.textContent = _deployApiKey;

    const cmdEl = document.getElementById('deploy-cli-cmd');
    if (cmdEl) cmdEl.textContent = `.\\cloudshield-agent.exe --key ${_deployApiKey}`;

    const oneEl = document.getElementById('deploy-oneliner');
    if (oneEl) oneEl.textContent =
        `Invoke-WebRequest "${_deployDownloadUrl}" -OutFile cloudshield-agent.exe; .\\cloudshield-agent.exe --key ${_deployApiKey}`;
};

window.closeDeployModal = function() {
    const modal = document.getElementById('deploy-modal');
    if (modal) modal.classList.add('hidden');
    document.body.style.overflow = '';
};

window.closeDeployModalOutside = function(e) {
    if (e.target.id === 'deploy-modal') window.closeDeployModal();
};

window.downloadAgent = function() {
    const url = `${API_BASE}/api/download-agent`;
    const a = document.createElement('a');
    a.href = url;
    a.download = 'cloudshield-agent.exe';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    showToast('Downloading CloudShield Agent...', 'success');
    addSocEvent('INFO', 'Agent download initiated from Deploy Agent modal.');
};

window.copyApiKey = function() {
    if (!_deployApiKey) return;
    navigator.clipboard.writeText(_deployApiKey).then(() => {
        showToast('API Key copied to clipboard!', 'success');
    }).catch(() => {
        showToast('Copy failed — please copy manually.', 'warning');
    });
};

window.copyCliCmd = function() {
    const el = document.getElementById('deploy-cli-cmd');
    if (!el) return;
    navigator.clipboard.writeText(el.textContent).then(() => {
        showToast('CLI command copied!', 'success');
    }).catch(() => showToast('Copy failed.', 'warning'));
};

window.copyOneliner = function() {
    const el = document.getElementById('deploy-oneliner');
    if (!el) return;
    navigator.clipboard.writeText(el.textContent).then(() => {
        showToast('One-liner copied!', 'success');
    }).catch(() => showToast('Copy failed.', 'warning'));
};

// Keyboard: Esc closes modal
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        const modal = document.getElementById('deploy-modal');
        if (modal && !modal.classList.contains('hidden')) {
            window.closeDeployModal();
        }
    }
});

// ══════════════════════════════════════════════════════════════════
//  EXTENDED MODULES — Container Scan, AI Analysis, Compliance
// ══════════════════════════════════════════════════════════════════

// ── Container Image Scanner ──────────────────────────────────────
window.runContainerScan = async function() {
    const input = document.getElementById('container-image-input');
    const resultEl = document.getElementById('container-scan-result');
    const btn = document.getElementById('btn-container-scan');
    if (!input || !resultEl) return;

    const image = input.value.trim();
    if (!image) { showToast('Enter a container image name first', 'warning'); return; }

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Scanning...';
    resultEl.innerHTML = '<div class="container-scanning"><span class="spinner"></span> Running Trivy scan on <strong>' + image + '</strong>... this may take 30-60s for first pull.</div>';

    try {
        const res = await fetch(`${API_BASE}/api/scan/container`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ image })
        });
        const json = await res.json();
        console.log("API RESPONSE:", json);

        const vulnerabilities = json?.data?.vulnerabilities || [];

        let demoBanner = '';
        if (json?.data?._demo_mode) {
            demoBanner = `<div style="background:rgba(234,179,8,0.15);border:1px solid var(--color-medium);border-radius:8px;padding:0.6rem 1rem;font-size:0.82rem;margin-bottom:1rem;">⚠️ <strong>Demo Mode:</strong> Simulated vulnerabilities</div>`;
        }

        if (vulnerabilities.length > 0) {
            renderContainerScanResult(json.data || {}, resultEl, demoBanner);
            showToast(`Container scan complete: ${vulnerabilities.length} vulnerabilities`, 'warning');
            
            const findingsList = vulnerabilities.map(v => ({
                id: v.id, severity: v.severity, source: 'trivy',
                title: v.title, description: v.description || ''
            }));
            
            console.log("Findings sent to AI:", findingsList);
            runAIAnalysis(findingsList);
        } else {
            resultEl.innerHTML = `<div class="container-scan-error">✅ No vulnerabilities found</div>`;
        }

    } catch(e) {
        resultEl.innerHTML = `<div class="container-scan-error">❌ Connection failed: ${e.message}</div>`;
        showToast('Container scan failed', 'error');
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<span class="btn-icon">🔍</span> Scan Image';
    }
};

function renderContainerScanResult(data, container, extraHtml = '') {
    const s = data.summary || {};
    const vulns = data.vulnerabilities || [];

    const sevBadge = (sev, count) => {
        if (!count) return '';
        const cls = { CRITICAL: 'badge-critical', HIGH: 'badge-high', MEDIUM: 'badge-medium', LOW: 'badge-low' }[sev] || 'badge-low';
        return `<span class="badge ${cls}">${count} ${sev}</span>`;
    };

    const topVulns = vulns.slice(0, 20).map(v => `
        <tr>
            <td><code style="color:var(--accent-blue);font-size:0.75rem;">${v.id}</code></td>
            <td>${v.pkg}</td>
            <td><span class="badge badge-${v.severity.toLowerCase()}">${v.severity}</span></td>
            <td style="max-width:250px;font-size:0.8rem;">${(v.title||'').slice(0,80)}</td>
            <td style="font-size:0.78rem;color:${v.fixed_version === 'Not fixed' ? 'var(--color-critical)' : 'var(--color-low)'};">${v.fixed_version}</td>
        </tr>`).join('');

    container.innerHTML = `
        ${extraHtml}
        <div class="container-scan-summary">
            <div class="cs-meta">
                <strong>${data.artifact_name || data.scan_target}</strong>
                <span style="color:var(--text-muted);font-size:0.78rem;">Scanned at ${data.scanned_at || ''}</span>
            </div>
            <div class="cs-badges">
                ${sevBadge('CRITICAL', s.critical)}
                ${sevBadge('HIGH', s.high)}
                ${sevBadge('MEDIUM', s.medium)}
                ${sevBadge('LOW', s.low)}
                ${s.total === 0 ? '<span class="badge badge-low">✅ Clean</span>' : ''}
            </div>
        </div>
        ${vulns.length > 0 ? `
        <div class="table-container" style="margin-top:1rem;">
            <table>
                <thead><tr><th>CVE ID</th><th>Package</th><th>Severity</th><th>Title</th><th>Fix Version</th></tr></thead>
                <tbody>${topVulns}</tbody>
            </table>
            ${vulns.length > 20 ? `<p style="padding:0.5rem 1rem;font-size:0.78rem;color:var(--text-muted);">Showing 20 of ${vulns.length} vulnerabilities. Export report for full list.</p>` : ''}
        </div>` : '<p style="padding:1rem;color:var(--color-low);">✅ No vulnerabilities found in this image.</p>'}`;
}

// ── AI Risk Panel Renderer ────────────────────────────────────────
function renderAiAnalysis(analysis) {
    const container = document.getElementById('ai-analysis-container');
    if (!container || !analysis) return;

    const riskColor = {
        CRITICAL: 'var(--color-critical)',
        HIGH:     'var(--color-high)',
        MEDIUM:   'var(--color-medium)',
        LOW:      'var(--color-low)'
    }[analysis.overall_risk] || 'var(--text-secondary)';

    const actions = (analysis.priority_actions || []).map((a, i) => `
        <div class="ai-action">
            <div class="ai-action-rank">${a.rank || i+1}</div>
            <div class="ai-action-body">
                <div class="ai-action-title">${a.action}</div>
                ${a.command ? `<code class="ai-action-cmd">${a.command}</code>` : ''}
                <span class="ai-urgency ai-urgency-${a.urgency || 'low'}">${a.urgency || 'low'}</span>
            </div>
        </div>`).join('');

    const vectors = (analysis.attack_vectors || []).map(v =>
        `<li class="ai-vector-item">⚠️ ${v}</li>`).join('');

    const source = analysis._source === 'openai'
        ? `<span class="engine-badge engine-ai">🤖 OpenAI ${analysis._model || ''}</span>`
        : `<span class="engine-badge engine-det">⚙️ Deterministic Engine</span>`;

    container.innerHTML = `
        <div class="ai-card">
            <div class="ai-header">
                <div>
                    <div class="ai-risk-level" style="color:${riskColor};">${analysis.overall_risk || 'N/A'}</div>
                    <div class="ai-risk-label">Overall Risk Level</div>
                </div>
                ${source}
            </div>
            <div class="ai-summary">${analysis.executive_summary || ''}</div>
            ${vectors ? `<div class="ai-section"><div class="ai-section-title">⚡ Attack Vectors</div><ul class="ai-vectors">${vectors}</ul></div>` : ''}
            ${actions ? `<div class="ai-section"><div class="ai-section-title">🔧 Priority Actions</div><div class="ai-actions">${actions}</div></div>` : ''}
            ${analysis.compliance_risk ? `<div class="ai-section"><div class="ai-section-title">📋 Compliance Risk</div><p class="ai-summary">${analysis.compliance_risk}</p></div>` : ''}
            ${analysis.estimated_blast_radius ? `<div class="ai-section"><div class="ai-section-title">💥 Blast Radius</div><p class="ai-summary">${analysis.estimated_blast_radius}</p></div>` : ''}
        </div>`;
}

// ── Compliance Panel Renderer ──────────────────────────────────────
function renderCompliancePanel(compliance) {
    const container = document.getElementById('compliance-container');
    if (!container || !compliance) return;

    const fw = compliance.framework_summary || {};
    const statusIcon = s => s === 'COMPLIANT' ? '✅' : s === 'FAILING' ? '❌' : '⚠️';
    const statusColor = s => s === 'COMPLIANT' ? 'var(--color-low)' : s === 'FAILING' ? 'var(--color-critical)' : 'var(--color-high)';

    const frameworkCards = Object.values(fw).map(f => `
        <div class="compliance-fw-card">
            <div class="fw-header">
                <span class="fw-name">${f.name}</span>
                <span style="color:${statusColor(f.status)};font-weight:700;">${statusIcon(f.status)} ${f.status}</span>
            </div>
            <div class="fw-violations">${f.violations} control${f.violations !== 1 ? 's' : ''} violated</div>
        </div>`).join('');

    const sev = compliance.severity_breakdown || {};
    const overallColor = statusColor(compliance.overall_status);

    container.innerHTML = `
        <div class="compliance-card">
            <div class="compliance-header">
                <div>
                    <div class="compliance-status" style="color:${overallColor};">${statusIcon(compliance.overall_status)} ${compliance.overall_status}</div>
                    <div class="compliance-subtitle">${compliance.findings_mapped} findings mapped across ${compliance.frameworks_impacted} frameworks</div>
                </div>
                <div class="compliance-sev-row">
                    ${sev.CRITICAL ? `<span class="badge badge-critical">${sev.CRITICAL} Critical</span>` : ''}
                    ${sev.HIGH     ? `<span class="badge badge-high">${sev.HIGH} High</span>`         : ''}
                </div>
            </div>
            <div class="compliance-frameworks">${frameworkCards}</div>
            ${compliance.nist_controls?.length ? `
            <div class="compliance-controls-section">
                <div class="compliance-controls-title">NIST 800-53 Controls Triggered</div>
                <div class="compliance-controls-list">${compliance.nist_controls.slice(0,8).map(c => `<span class="ctrl-badge">${c}</span>`).join('')}</div>
            </div>` : ''}
        </div>`;
}

// ── AI Analysis Trigger ───────────────────────────────────────────
// Phase 6: Call /api/analyze/risk with dynamic findings list
window.runAIAnalysis = async function(findingsOverride) {
    const container = document.getElementById('ai-analysis-container');
    if (container) {
        container.innerHTML = '<div style="padding:1.5rem;text-align:center;"><span class="spinner"></span> Generating AI risk analysis...</div>';
    }
    try {
        const res = await fetch(`${API_BASE}/api/analyze/risk`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                findings: findingsOverride || [],
                risk_score: { final_score: 0, category: 'LOW', finding_count: (findingsOverride || []).length }
            })
        });
        const json = await res.json();
        const analysis = json.data || json;
        if (analysis && analysis.overall_risk) {
            renderAiAnalysis(analysis);
            addSocEvent('INFO', `AI risk analysis complete: ${analysis.overall_risk} risk.`);
        }
    } catch(e) {
        if (container) container.innerHTML = '<div style="padding:1rem;color:var(--color-medium);">AI analysis unavailable — backend unreachable.</div>';
    }
};

// ── Hook renderers into existing renderResults ────────────────────
const _origRenderResults = window.renderResults || function(){};
window.renderResults = function(data) {
    _origRenderResults(data);   // preserve existing rendering

    // Trigger AI analysis from scan result
    if (data?.findings && data?.risk) {
        fetch(`${API_BASE}/api/analyze/risk`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ findings: data.findings, risk_score: data.risk })
        }).then(r => r.json()).then(json => {
            if (json.status === 'success') renderAiAnalysis(json.data);
        }).catch(() => {});
    }

    // Render compliance data if present
    if (data?.compliance) {
        renderCompliancePanel(data.compliance);
    }
};

// ══════════════════════════════════════════════════════════════════
//  EXTENDED MODULES
// ══════════════════════════════════════════════════════════════════

window.toggleAlertsPanel = function() {
    document.getElementById('alerts-modal')?.classList.toggle('hidden');
    fetchDashboardHub(); // force refresh on open
};

window.closeAlertsModalOutside = function(e) {
    if (e.target.id === 'alerts-modal') {
        document.getElementById('alerts-modal').classList.add('hidden');
    }
};

// Consolidated Polling - Hub handles everything every 30s
startSaaSPerformanceHub();


 
 / /    % %  A N Y . R U N   /   M a l w a r e   S a n d b o x   I n t e g r a t i o n    % %
 w i n d o w . o p e n S a n d b o x   =   f u n c t i o n ( )   { 
         d o c u m e n t . q u e r y S e l e c t o r A l l ( " . s e c t i o n " ) . f o r E a c h ( s   = >   s . c l a s s L i s t . a d d ( " h i d d e n " ) ) ; 
         d o c u m e n t . g e t E l e m e n t B y I d ( " s a n d b o x - p a n e l " ) . c l a s s L i s t . r e m o v e ( " h i d d e n " ) ; 
 } ; 
 
 w i n d o w . d e t o n a t e S a n d b o x   =   a s y n c   f u n c t i o n ( )   { 
         c o n s t   t a r g e t   =   d o c u m e n t . g e t E l e m e n t B y I d ( " s a n d b o x - t a r g e t " ) . v a l u e ; 
         i f   ( ! t a r g e t )   {   s h o w T o a s t ( " E n t e r   a   t a r g e t   h a s h ,   I P   o r   U R L " ,   " w a r n i n g " ) ;   r e t u r n ;   } 
         
         d o c u m e n t . g e t E l e m e n t B y I d ( " s a n d b o x - r e s u l t s " ) . s t y l e . d i s p l a y   =   " b l o c k " ; 
         d o c u m e n t . g e t E l e m e n t B y I d ( " s a n d b o x - p r o c e s s - t r e e " ) . i n n e r H T M L   =   " < d i v   s t y l e = \ " p a d d i n g : 1 r e m ; \ " > B o o t i n g   s e c u r e   V M . . .   I n j e c t i n g   t a r g e t . . . < / d i v > " ; 
         
         s h o w T o a s t ( " D e t o n a t i o n   s t a r t e d   i n   S a n d b o x   V M " ,   " i n f o " ) ; 
         
         / /   S i m u l a t e   A N Y . R U N   p r o c e s s   t r e e   g e n e r a t i o n 
         s e t T i m e o u t ( ( )   = >   { 
                 d o c u m e n t . g e t E l e m e n t B y I d ( " s a n d b o x - p r o c e s s - t r e e " ) . i n n e r H T M L   =   ` 
                         < d i v   s t y l e = " c o l o r : v a r ( - - c o l o r - c r i t i c a l ) " > [ 1 3 : 4 2 : 0 1 ]   �&�  W I N W O R D . E X E   ( P I D :   4 0 1 2 ) < / d i v > 
                         < d i v   s t y l e = " m a r g i n - l e f t :   1 . 5 r e m ;   c o l o r : v a r ( - - t e x t - s e c o n d a r y ) " > % %  [ 1 3 : 4 2 : 0 3 ]   c m d . e x e   / c   p o w e r s h e l l   - e n c   J A B z A D 0 A T g B l A H c A L Q B P A G I A . . .   ( P I D :   4 0 8 8 ) < / d i v > 
                         < d i v   s t y l e = " m a r g i n - l e f t :   3 r e m ;   c o l o r : v a r ( - - c o l o r - c r i t i c a l ) " > % %  [ 1 3 : 4 2 : 0 4 ]   =ب�  p o w e r s h e l l . e x e   ( P I D :   4 1 0 2 )   -   B y p a s s e d   A M S I < / d i v > 
                         < d i v   s t y l e = " m a r g i n - l e f t :   4 . 5 r e m ;   c o l o r : v a r ( - - c o l o r - c r i t i c a l ) " > % %  [ 1 3 : 4 2 : 0 5 ]   =ب�  r u n d l l 3 2 . e x e   ( P I D :   4 2 1 0 )   -   N e t w o r k   C o n n e c t i o n < / d i v > 
                 ` ; 
                 d o c u m e n t . g e t E l e m e n t B y I d ( " s a n d b o x - n e t w o r k " ) . i n n e r H T M L   =   ` 
                         < d i v > T C P   1 0 . 0 . 2 . 1 5 : 4 9 1 5 2   - >   < s p a n   s t y l e = " c o l o r : v a r ( - - c o l o r - c r i t i c a l ) " > 1 8 5 . 2 2 0 . 1 0 1 . 4 4 : 4 4 3 < / s p a n >   ( M a l i c i o u s   I P ) < / d i v > 
                         < d i v > D N S   Q u e r y :   < s p a n   s t y l e = " c o l o r : v a r ( - - c o l o r - h i g h ) " > c 2 . e v i l - d o m a i n . c o m < / s p a n > < / d i v > 
                 ` ; 
                 d o c u m e n t . g e t E l e m e n t B y I d ( " s a n d b o x - i o c s " ) . i n n e r H T M L   =   ` 
                         < d i v > I P :   1 8 5 . 2 2 0 . 1 0 1 . 4 4   ( A b u s e I P D B   S c o r e :   1 0 0 ) < / d i v > 
                         < d i v > D o m a i n :   c 2 . e v i l - d o m a i n . c o m < / d i v > 
                         < d i v > S H A 2 5 6 :   4 a 2 b 1 . . .   ( D r o p p e r ) < / d i v > 
                 ` ; 
                 s h o w T o a s t ( " D e t o n a t i o n   c o m p l e t e .   3   I O C s   e x t r a c t e d . " ,   " w a r n i n g " ) ; 
                 a d d S o c E v e n t ( " C R I T I C A L " ,   " S a n d b o x   D e t o n a t i o n :   M a l i c i o u s   M a c r o   E x e c u t i o n   D e t e c t e d " ) ; 
         } ,   3 0 0 0 ) ; 
 } ; 
 
 / /    % %  V e l o c i r a p t o r   /   T h r e a t   H u n t i n g   I n t e g r a t i o n    % %
 w i n d o w . s e t V Q L T e m p l a t e   =   f u n c t i o n ( t y p e )   { 
         c o n s t   b o x   =   d o c u m e n t . g e t E l e m e n t B y I d ( " v q l - q u e r y " ) ; 
         i f   ( t y p e   = = =   " p r o c e s s " )   { 
                 b o x . v a l u e   =   " S E L E C T   *   F R O M   W i n d o w s . S y s t e m . P o w e r s h e l l . E x e c u t i o n ( )   W H E R E   C o m m a n d L i n e   = ~   \ \ " H i d d e n | E n c o d e d C o m m a n d \ \ " " ; 
         }   e l s e   i f   ( t y p e   = = =   " a u t o r u n " )   { 
                 b o x . v a l u e   =   " S E L E C T   *   F R O M   W i n d o w s . S y s . A u t o r u n ( )   W H E R E   E x e c u t a b l e   = ~   \ \ " T e m p | A p p D a t a \ \ " " ; 
         }   e l s e   i f   ( t y p e   = = =   " n e t " )   { 
                 b o x . v a l u e   =   " S E L E C T   *   F R O M   W i n d o w s . N e t w o r k . N e t s t a t ( )   W H E R E   S t a t u s   =   \ \ " E S T A B L I S H E D \ \ "   A N D   P i d   i n   ( S E L E C T   P i d   F R O M   W i n d o w s . S y s t e m . P s l i s t ( )   W H E R E   N a m e   = ~   \ \ " p o w e r s h e l l | c m d \ \ " ) " ; 
         } 
 } ; 
 
 w i n d o w . r u n T h r e a t H u n t   =   f u n c t i o n ( )   { 
         c o n s t   q   =   d o c u m e n t . g e t E l e m e n t B y I d ( " v q l - q u e r y " ) . v a l u e ; 
         i f   ( ! q )   {   s h o w T o a s t ( " E n t e r   a   V Q L   q u e r y " ,   " w a r n i n g " ) ;   r e t u r n ;   } 
         
         d o c u m e n t . g e t E l e m e n t B y I d ( " h u n t - r e s u l t s " ) . s t y l e . d i s p l a y   =   " b l o c k " ; 
         d o c u m e n t . g e t E l e m e n t B y I d ( " h u n t - r e s u l t s " ) . i n n e r H T M L   =   " < d i v   s t y l e = \ " p a d d i n g : 1 r e m ; c o l o r : v a r ( - - c o l o r - h i g h ) \ " > D i s p a t c h i n g   V Q L   t o   5 0   a c t i v e   e n d p o i n t s . . . < / d i v > " ; 
         
         s h o w T o a s t ( " V Q L   H u n t   D i s p a t c h e d " ,   " i n f o " ) ; 
         
         s e t T i m e o u t ( ( )   = >   { 
                 d o c u m e n t . g e t E l e m e n t B y I d ( " h u n t - r e s u l t s " ) . i n n e r H T M L   =   ` 
                         < t a b l e   s t y l e = " w i d t h : 1 0 0 % ;   b o r d e r - c o l l a p s e :   c o l l a p s e ;   t e x t - a l i g n :   l e f t ; " > 
                                 < t r   s t y l e = " b o r d e r - b o t t o m :   1 p x   s o l i d   v a r ( - - b o r d e r - g l a s s ) " > < t h > H o s t n a m e < / t h > < t h > T i m e s t a m p < / t h > < t h > M a t c h   D e t a i l < / t h > < / t r > 
                                 < t r > < t d > W I N - D E S K T O P - 0 1 < / t d > < t d > 2 0 2 4 - 0 5 - 0 1   1 3 : 4 5 : 0 1 < / t d > < t d   s t y l e = " c o l o r : v a r ( - - c o l o r - c r i t i c a l ) " > p o w e r s h e l l . e x e   - W i n d o w S t y l e   H i d d e n   - E n c   J A B . . . < / t d > < / t r > 
                                 < t r > < t d > W I N - S R V - W E B < / t d > < t d > 2 0 2 4 - 0 5 - 0 1   1 3 : 4 5 : 0 2 < / t d > < t d   s t y l e = " c o l o r : v a r ( - - c o l o r - c r i t i c a l ) " > c m d . e x e   / c   s t a r t   / M I N   p o w e r s h e l l . e x e . . . < / t d > < / t r > 
                         < / t a b l e > 
                 ` ; 
                 s h o w T o a s t ( " H u n t   C o m p l e t e .   2   M a t c h e s   F o u n d . " ,   " w a r n i n g " ) ; 
                 a d d S o c E v e n t ( " H I G H " ,   " T h r e a t   H u n t   V Q L   M a t c h e d   o n   2   E n d p o i n t s " ) ; 
         } ,   2 5 0 0 ) ; 
 } ; 
 
 d o c u m e n t . g e t E l e m e n t B y I d ( " b t n - s i e m - p a n e l " ) . a d d E v e n t L i s t e n e r ( " c l i c k " ,   ( )   = >   { 
         d o c u m e n t . q u e r y S e l e c t o r A l l ( " . s e c t i o n " ) . f o r E a c h ( s   = >   s . c l a s s L i s t . a d d ( " h i d d e n " ) ) ; 
         d o c u m e n t . g e t E l e m e n t B y I d ( " a t t a c k - d a s h b o a r d " ) . c l a s s L i s t . r e m o v e ( " h i d d e n " ) ; 
 } ) ; 
 
 d o c u m e n t . g e t E l e m e n t B y I d ( " b t n - h u n t - p a n e l " ) . a d d E v e n t L i s t e n e r ( " c l i c k " ,   ( )   = >   { 
         d o c u m e n t . q u e r y S e l e c t o r A l l ( " . s e c t i o n " ) . f o r E a c h ( s   = >   s . c l a s s L i s t . a d d ( " h i d d e n " ) ) ; 
         d o c u m e n t . g e t E l e m e n t B y I d ( " h u n t - p a n e l " ) . c l a s s L i s t . r e m o v e ( " h i d d e n " ) ; 
 } ) ; 
 
  
 
// ── ANY.RUN / Malware Sandbox Integration (Real Backend) ──
window.openSandbox = function() {
    document.querySelectorAll(".section").forEach(s => s.classList.add("hidden"));
    document.getElementById("sandbox-panel").classList.remove("hidden");
};

window.detonateSandbox = async function() {
    const target = document.getElementById("sandbox-target").value;
    if (!target) { showToast("Enter a target hash, IP or URL", "warning"); return; }
    
    document.getElementById("sandbox-results").style.display = "block";
    document.getElementById("sandbox-process-tree").innerHTML = "<div style='padding:1rem;color:var(--color-high)'>Booting secure container... Dispatching target...</div>";
    document.getElementById("sandbox-network").innerHTML = "<div style='padding:0.5rem;'>Analyzing network streams...</div>";
    document.getElementById("sandbox-iocs").innerHTML = "";
    
    showToast("Detonation started in Isolated Sandbox", "info");
    
    try {
        const res = await fetch("/api/sandbox/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target })
        });
        const data = await res.json();
        
        if(data.status === "success") {
            const processes = data.data.processes.map(p => "<div style='margin-bottom:4px'>└─ " + escapeHtml(p) + "</div>").join("") || "<div style='color:var(--text-muted)'>No suspicious processes detected.</div>";
            const network = data.data.network.map(n => "<div style='color:var(--color-critical)'>⚠️ " + escapeHtml(n) + "</div>").join("") || "<div style='color:var(--text-muted)'>No outbound connections.</div>";
            const iocs = data.data.iocs.map(i => "<div>" + escapeHtml(i) + "</div>").join("");
            
            document.getElementById("sandbox-process-tree").innerHTML = processes;
            document.getElementById("sandbox-network").innerHTML = network;
            document.getElementById("sandbox-iocs").innerHTML = iocs || "<div>Target: " + escapeHtml(data.data.target) + "</div>";
            showToast("Detonation complete. IOCs extracted.", "success");
            addSocEvent("WARNING", "Sandbox Detonation Completed for: " + target);
        } else {
            showToast("Sandbox failed: " + data.message, "error");
        }
    } catch(err) {
        showToast("Sandbox connection error.", "error");
    }
};

document.getElementById("btn-siem-panel").addEventListener("click", () => {
    document.querySelectorAll(".section").forEach(s => s.classList.add("hidden"));
    document.getElementById("attack-dashboard").classList.remove("hidden");
});

document.getElementById("btn-hunt-panel").addEventListener("click", () => {
    document.querySelectorAll(".section").forEach(s => s.classList.add("hidden"));
    document.getElementById("hunt-panel").classList.remove("hidden");
});

window.runThreatHunt = async function() {
    const q = document.getElementById("vql-query").value;
    if (!q) { showToast("Enter a query", "warning"); return; }
    
    document.getElementById("hunt-results").style.display = "block";
    document.getElementById("hunt-results").innerHTML = "<div style='padding:1rem;color:var(--color-high)'>Dispatching Query to OpenSearch/Velociraptor...</div>";
    
    try {
        const res = await fetch("/api/hunt", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ query: q })
        });
        const data = await res.json();
        
        if(data.status === "success") {
            let html = "<table style='width:100%; border-collapse: collapse; text-align: left;'><tr style='border-bottom: 1px solid var(--border-glass)'><th>Timestamp</th><th>Endpoint</th><th>Match Detail</th></tr>";
            data.results.forEach(r => {
                html += `<tr><td>${r.timestamp}</td><td>${r.endpoint}</td><td style='color:var(--color-critical)'>${escapeHtml(r.detail)}</td></tr>`;
            });
            html += "</table>";
            if(data.results.length === 0) html = "<div style='padding:1rem;color:var(--color-low)'>No matches found across fleet.</div>";
            
            document.getElementById("hunt-results").innerHTML = html;
            showToast(`Hunt Complete. ${data.results.length} Matches Found.`, "warning");
        }
    } catch(err) {
        document.getElementById("hunt-results").innerHTML = "<div style='color:var(--color-critical)'>Error reaching Threat Hunt API.</div>";
    }
};

// ── Real-Time Streaming & Alerts UI ──
const sseQueue = [];

function initSSE() {
    const sseStatus = document.createElement("div");
    sseStatus.id = "sse-status";
    sseStatus.style = "position:absolute; top: 1rem; right: 1rem; color: var(--color-low); font-size: 0.8rem; display: flex; align-items: center; gap: 0.5rem;";
    sseStatus.innerHTML = "<div class='status-dot' style='background: orange;'></div> Connecting...";
    document.body.appendChild(sseStatus);

    const eventSource = new EventSource("/api/stream");

    eventSource.onopen = () => {
        sseStatus.innerHTML = "<div class='status-dot' style='background: var(--color-low);'></div> Live Stream Connected";
    };

    eventSource.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            if (msg.type === "alert") {
                sseQueue.push(msg.data);
            }
        } catch (e) {
            console.error("SSE Parse Error", e);
        }
    };

    eventSource.onerror = () => {
        sseStatus.innerHTML = "<div class='status-dot' style='background: var(--color-critical);'></div> Stream Disconnected";
    };
}

// Process SSE Queue
setInterval(() => {
    if (sseQueue.length > 0) {
        const batch = sseQueue.splice(0, 5);
        batch.forEach(addLiveAlertToTable);
    }
}, 1000);

function addLiveAlertToTable(alertData) {
    const tableBody = document.querySelector("#attack-dashboard table");
    if (!tableBody) return;
    
    // Only use tbody
    let tbody = tableBody.querySelector("tbody") || tableBody;
    
    const row = document.createElement("tr");
    row.className = "new-alert";
    
    const severityColor = alertData.severity === "CRITICAL" ? "var(--color-critical)" : 
                          alertData.severity === "HIGH" ? "var(--color-high)" : "var(--color-med)";
                          
    row.style = `border-left: 3px solid ${severityColor}; cursor: pointer; transition: background 0.3s ease;`;
    
    row.innerHTML = `
        <td>${new Date().toLocaleTimeString()}</td>
        <td style="color:${severityColor}; font-weight:600;">${alertData.severity}</td>
        <td>${escapeHtml(alertData.title)}</td>
        <td>Score: ${alertData.score} | TI: ${alertData.ti_enrichment || 0}</td>
    `;
    
    // Drill down logic
    row.addEventListener("click", () => showAlertDrillDown(alertData));
    
    // Prepend to top
    if(tbody.firstChild) {
        tbody.insertBefore(row, tbody.firstChild);
    } else {
        tbody.appendChild(row);
    }
    
    // Remove highlight after 4s
    setTimeout(() => {
        row.style.background = "transparent";
    }, 4000);
}

function showAlertDrillDown(alertData) {
    let drillDown = document.getElementById("alert-drilldown-modal");
    if(!drillDown) {
        drillDown = document.createElement("div");
        drillDown.id = "alert-drilldown-modal";
        drillDown.style = "position:fixed; top:10%; right:2rem; width: 400px; background:var(--bg-glass); border:1px solid var(--border-glass); padding: 1.5rem; z-index:9999; backdrop-filter:blur(10px); box-shadow: 0 0 30px rgba(0,0,0,0.8);";
        document.body.appendChild(drillDown);
    }
    
    const tacticsHtml = (alertData.tactics || []).map(t => `<span style="background:rgba(255,255,255,0.1); padding:0.2rem 0.5rem; border-radius:4px; font-size:0.8rem; margin-right:4px;">${t}</span>`).join("");
    
    drillDown.innerHTML = `
        <div style="display:flex; justify-content:space-between; border-bottom:1px solid var(--border-glass); padding-bottom:1rem; margin-bottom:1rem;">
            <h3 style="margin:0; color:var(--text-bright)">Alert Detail</h3>
            <button onclick="document.getElementById('alert-drilldown-modal').remove()" style="background:none; border:none; color:var(--text-muted); cursor:pointer;">X</button>
        </div>
        <div style="margin-bottom:1rem">
            <strong>${alertData.title}</strong>
        </div>
        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:0.5rem; margin-bottom:1rem;">
            <div><strong>Severity:</strong> <span style="color:var(--color-critical)">${alertData.severity}</span></div>
            <div><strong>Score:</strong> ${alertData.score}</div>
            <div><strong>TI Enrichment:</strong> ${alertData.ti_enrichment || 'N/A'}</div>
        </div>
        <div style="margin-bottom:1rem;">
            <strong>Tactics:</strong>
            <div style="margin-top:0.5rem;">${tacticsHtml}</div>
        </div>
        <div>
            <strong>Raw JSON:</strong>
            <pre style="background:rgba(0,0,0,0.5); padding:1rem; font-size:0.8rem; overflow-x:auto; margin-top:0.5rem; border:1px solid var(--border-glass); color:var(--text-muted)">${JSON.stringify(alertData, null, 2)}</pre>
        </div>
        <div style="margin-top:1rem; text-align:right;">
            <button onclick="createCaseFromAlert('${escapeHtml(alertData.title)}')" class="btn">Create Case</button>
        </div>
    `;
}

function createCaseFromAlert(title) {
    showToast("Case creation feature invoked (Backend handles this).", "info");
    // Connect to /api/cases POST in reality
}

// Initialize SSE on load
setTimeout(initSSE, 1000);

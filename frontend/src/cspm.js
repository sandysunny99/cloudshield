// Cloud Posture & Container Security Module

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

window.runScan = async function() {
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
            showToast('Scan returned no data ΓÇö backend may be warming up', 'warning');
        }
    } catch (e) {
        addLog('Scan failed: ' + e.message, 'error');
        showPipelineError();
        showToast('Scan failed: ' + e.message, 'error');
        addSocEvent('WARNING', `Pipeline scan error: ${e.message}`);
    } finally {
        setButtonsDisabled(false);
    }
};

// Function renderRemediationCards not found

// Function generateAiAnalysis not found

// Function pollAiAnalysis not found

// Function runContainerScan not found

// Function renderCompliance not found


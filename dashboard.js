// dashboard.js
const totalScannedEl = document.getElementById('totalScanned');
const totalBlockedEl = document.getElementById('totalBlocked');
const avgRiskEl = document.getElementById('avgRisk');
const logTable = document.getElementById('logTable');

function init() {
    chrome.storage.local.get(['stats', 'scanLogs'], (res) => {
        const stats = res.stats || { scanned: 0, blocked: 0 };
        const rawLogs = res.scanLogs || [];

        // Filter out internal extension pages or extension IDs from display
        const logs = rawLogs.filter(log => {
            if (!log || !log.domain) return false;
            const d = log.domain.toLowerCase();
            if (d.includes('dashboard') || d.includes('chrome-extension') || d.includes('blocked.html') || d.includes('popup.html')) return false;
            if (/^[a-z]{32}$/.test(d)) return false; // Chrome extension ID
            return true;
        });

        // Clean up stale internal entries from storage if any were saved previously
        if (logs.length !== rawLogs.length) {
            chrome.storage.local.set({ scanLogs: logs });
        }

        totalScannedEl.textContent = stats.scanned.toLocaleString();
        totalBlockedEl.textContent = stats.blocked.toLocaleString();
        
        // Calculate suspicious sites (risk > 30%) and fake logins (risk > 80%) from logs
        let suspiciousCount = 0;
        let fakeLoginsCount = 0;
        
        logs.forEach(log => {
            if (log.risk >= 0.3 && log.risk < 0.8) suspiciousCount++;
            if (log.risk >= 0.8) fakeLoginsCount++;
        });

        document.getElementById('suspiciousSites').textContent = suspiciousCount.toLocaleString();
        document.getElementById('fakeLogins').textContent = fakeLoginsCount.toLocaleString();

        // Populate Table
        logTable.innerHTML = '';
        logs.slice().reverse().slice(0, 50).forEach(log => {
            const tr = document.createElement('tr');
            const date = new Date(log.ts).toLocaleString();
            let riskLevel = "Safe";
            let riskClass = "risk-low";
            
            if (log.risk >= 0.9) { riskLevel = "Malicious"; riskClass = "risk-high"; }
            else if (log.risk >= 0.7) { riskLevel = "High Risk"; riskClass = "risk-high"; }
            else if (log.risk >= 0.3) { riskLevel = "Suspicious"; riskClass = ""; }

            const flagHtml = log.flags ? log.flags.split(',').map(f => {
                const trimmed = f.trim();
                const isHighRisk = trimmed === 'Brand-Impersonation' || trimmed === 'Exfiltration-Endpoint' || trimmed === 'Tunnel';
                const bg = isHighRisk ? 'rgba(239, 68, 68, 0.2)' : 'rgba(99, 102, 241, 0.2)';
                const color = isHighRisk ? '#fca5a5' : '#c7d2fe';
                return `<span style="display: inline-block; padding: 2px 6px; margin: 1px; border-radius: 4px; background: ${bg}; color: ${color}; font-size: 0.72rem;">${trimmed}</span>`;
            }).join(' ') : '<span style="color: var(--text-dim); font-size: 0.75rem;">None</span>';

            tr.innerHTML = `
                <td>${date}</td>
                <td style="font-family: monospace">${log.domain}</td>
                <td class="${riskClass}">${riskLevel}</td>
                <td>${flagHtml}</td>
            `;
            logTable.appendChild(tr);
        });
    });

    fetchModelStatus();
}

function fetchModelStatus() {
    chrome.runtime.sendMessage({ action: 'getModelStatus' }, (res) => {
        if (!res || chrome.runtime.lastError) return;

        if (res.engine) {
            document.getElementById('engineBadge').textContent = res.engine;
        }
        if (res.version) {
            document.getElementById('modelVersionDisplay').textContent = `v${res.version}`;
        }
        if (res.treeCount) {
            document.getElementById('modelTreesDisplay').textContent = `${res.treeCount} Trees`;
        }
        if (res.totalNodes) {
            document.getElementById('modelNodesDisplay').textContent = `${res.totalNodes.toLocaleString()} Flat Nodes`;
        }
        if (res.allowlistSize) {
            const src = res.allowlistSource === 'ota' ? ' (OTA Synced)' : ' (Packaged Top 100k)';
            document.getElementById('allowlistSizeDisplay').textContent = `${res.allowlistSize.toLocaleString()} Domains${src}`;
        }
        if (res.lastOtaCheck) {
            const timeAgo = Math.round((Date.now() - res.lastOtaCheck) / 60000);
            const timeStr = timeAgo < 1 ? 'Just now' : `${timeAgo} min ago`;
            document.getElementById('lastCheckDisplay').textContent = `${new Date(res.lastOtaCheck).toLocaleDateString()} (${timeStr})`;
        }
    });
}

// Check for updates button
const checkUpdateBtn = document.getElementById('checkUpdateBtn');
const updateStatusText = document.getElementById('updateStatusText');

if (checkUpdateBtn) {
    checkUpdateBtn.addEventListener('click', () => {
        checkUpdateBtn.disabled = true;
        checkUpdateBtn.textContent = 'Checking...';
        updateStatusText.textContent = 'Contacting remote repository...';
        updateStatusText.style.color = 'var(--text-dim)';

        chrome.runtime.sendMessage({ action: 'checkForUpdates' }, (response) => {
            checkUpdateBtn.disabled = false;
            checkUpdateBtn.textContent = 'Check for Updates';

            if (chrome.runtime.lastError || !response) {
                updateStatusText.textContent = 'Failed to connect to update server.';
                updateStatusText.style.color = 'var(--danger)';
                return;
            }

            if (response.success) {
                updateStatusText.textContent = response.message;
                updateStatusText.style.color = response.updated ? 'var(--success)' : 'var(--primary)';
                fetchModelStatus();
            } else {
                updateStatusText.textContent = response.message || 'Offline fallback active.';
                updateStatusText.style.color = 'var(--warning)';
            }
        });
    });
}

init();

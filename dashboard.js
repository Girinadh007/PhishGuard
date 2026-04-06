// dashboard.js
const totalScannedEl = document.getElementById('totalScanned');
const totalBlockedEl = document.getElementById('totalBlocked');
const avgRiskEl = document.getElementById('avgRisk');
const logTable = document.getElementById('logTable');

function init() {
    chrome.storage.local.get(['stats', 'scanLogs'], (res) => {
        const stats = res.stats || { scanned: 0, blocked: 0, falsePositives: 0, falseNegatives: 0, totalRisk: 0 };
        const logs = res.scanLogs || [];

        const fp = stats.falsePositives || 0;
        const fn = stats.falseNegatives || 0;
        const tp = stats.blocked - fp;
        const tn = stats.scanned - stats.blocked - fn;

        totalScannedEl.textContent = stats.scanned.toLocaleString();
        totalBlockedEl.textContent = stats.blocked.toLocaleString();
        
        document.getElementById('truePositives').textContent = tp.toLocaleString();
        document.getElementById('falsePositives').textContent = fp.toLocaleString();
        document.getElementById('trueNegatives').textContent = tn > 0 ? tn.toLocaleString() : "0";
        document.getElementById('falseNegatives').textContent = fn.toLocaleString();

        // Populate Table
        logTable.innerHTML = '';
        logs.reverse().slice(0, 50).forEach(log => {
            const tr = document.createElement('tr');
            const date = new Date(log.ts).toLocaleString();
            const riskClass = log.risk > 0.8 ? 'risk-high' : (log.risk < 0.3 ? 'risk-low' : '');

            tr.innerHTML = `
                <td>${date}</td>
                <td style="font-family: monospace">${log.domain}</td>
                <td class="${riskClass}">${Math.round(log.risk * 100)}%</td>
                <td style="color: var(--text-dim); font-size: 0.75rem">${log.flags || '-'}</td>
            `;
            logTable.appendChild(tr);
        });
    });
}

init();

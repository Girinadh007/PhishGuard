// dashboard.js
const totalScannedEl = document.getElementById('totalScanned');
const totalBlockedEl = document.getElementById('totalBlocked');
const avgRiskEl = document.getElementById('avgRisk');
const logTable = document.getElementById('logTable');

function init() {
    chrome.storage.local.get(['stats', 'scanLogs'], (res) => {
        const stats = res.stats || { scanned: 0, blocked: 0 };
        const logs = res.scanLogs || [];

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
        logs.reverse().slice(0, 50).forEach(log => {
            const tr = document.createElement('tr');
            const date = new Date(log.ts).toLocaleString();
            let riskLevel = "Safe";
            let riskClass = "risk-low";
            
            if (log.risk >= 0.9) { riskLevel = "Malicious"; riskClass = "risk-high"; }
            else if (log.risk >= 0.7) { riskLevel = "High Risk"; riskClass = "risk-high"; }
            else if (log.risk >= 0.3) { riskLevel = "Suspicious"; riskClass = ""; }

            tr.innerHTML = `
                <td>${date}</td>
                <td style="font-family: monospace">${log.domain}</td>
                <td class="${riskClass}">${riskLevel}</td>
                <td style="color: var(--text-dim); font-size: 0.75rem">${log.flags || 'None'}</td>
            `;
            logTable.appendChild(tr);
        });
    });
}

init();

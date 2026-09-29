// scripts/blocked.js — External script for blocked.html (required by Chrome extension CSP)

const params = new URLSearchParams(window.location.search);
const url = params.get('url');
const reason = params.get('reason');

const risk = params.get('risk');
let riskPercent = risk ? Math.round(parseFloat(risk) * 100) + '%' : 'Unknown';

if (url) document.getElementById('urlDisplay').textContent = url;

const flags = params.get('flags') ? params.get('flags').split(',') : [];
const details = params.get('details');

// Populate reason block based on detection type
const reasonElement = document.querySelector('.reason');
if (reasonElement) {
    if (reason === 'cloudflare_tunnel') {
        reasonElement.innerHTML = `
            <strong>Why was this blocked? (Risk: ${riskPercent})</strong><br><br>
            This site is using a <code>.trycloudflare.net</code> tunnel. Attackers frequently use these free tunnels to host phishing pages that bypass traditional IP firewalls.
            <br><br><em>Security Tip:</em> Legitimate businesses almost never use temporary tunnel domains for login pages.
        `;
    } else if (reason === 'dom_heuristics') {
        let detailsHtml = '';
        if (details) {
            const detailItems = details.split(' | ');
            detailsHtml = '<ul style="text-align: left; margin: 12px auto; max-width: 500px; padding-left: 20px; font-size: 0.95rem; color: #fca5a5;">' +
                detailItems.map(d => `<li style="margin-bottom: 6px;">⚠️ ${d}</li>`).join('') +
                '</ul>';
        }

        reasonElement.innerHTML = `
            <strong>Why was this blocked? (Risk: ${riskPercent})</strong><br><br>
            ${flags.includes('Brand-Impersonation') ? '<span style="color: #f87171; font-weight: 700;">🚨 Brand Impersonation Detected</span><br>' : ''}
            PhishGuard inspected the underlying HTML and detected high-risk manipulation tactics.
            ${detailsHtml}
            <em>Security Tip:</em> Even if a page limits visual clues, PhishGuard inspects the HTML code for concealed credential collectors and identity spoofing.
        `;
    } else if (reason === 'tunnel_header_detected') {
        reasonElement.innerHTML = `
            <strong>Why was this blocked? (Risk: ${riskPercent})</strong><br><br>
            A reverse tunnel service header was detected in the HTTP response. Reverse tunnels (such as ngrok or serveo) are commonly utilized to rapidly deploy transient phishing portals.
        `;
    } else {
        reasonElement.innerHTML = `
            <strong>Why was this blocked? (Risk: ${riskPercent})</strong><br><br>
            The PhishGuard AI model detected structural anomalies common in phishing links and deceptive login pages.
            Are you sure you recognize this exact domain spelling? Look for extra hyphens, numbers replacing letters (like '0' instead of 'o'), or unusual domain endings.
        `;
    }
}

// Populate detailed evidence list if available
const evidenceList = document.querySelector('#evidenceSection ul');
if (evidenceList && (details || flags.length > 0)) {
    let items = [];
    if (details) {
        items = details.split(' | ').map(d => `<li style="margin-bottom: 8px;">⚠️ ${d}</li>`);
    } else if (flags.length > 0) {
        items = flags.map(f => `<li style="margin-bottom: 8px;">⚠️ Detected anomaly: <strong>${f}</strong></li>`);
    }
    if (items.length > 0) {
        evidenceList.innerHTML = items.join('');
    }
}

// Go Back button
document.getElementById('goBackBtn').addEventListener('click', () => {
    history.back();
});

// Allow Site button — ONE-TIME ONLY
document.getElementById('allowSiteBtn').addEventListener('click', () => {
    if (!url) {
        alert('No URL to allow. Please go back and try again.');
        return;
    }

    if (confirm(
        '⚠️ One-Time Access Warning\n\n' +
        'You are about to visit a site PhishGuard flagged as dangerous.\n\n' +
        'This will grant ONE-TIME access only.\n' +
        'The site will be blocked again on your next visit.\n\n' +
        'Are you absolutely sure you want to proceed?'
    )) {
        const btn = document.getElementById('allowSiteBtn');
        btn.textContent = 'Allowing (once)...';
        btn.disabled = true;

        chrome.runtime.sendMessage({ action: 'allowSiteOnce', url: url }, (response) => {
            if (chrome.runtime.lastError || !response || !response.success) {
                btn.textContent = 'Allow this site (I know it\'s safe)';
                btn.disabled = false;
                alert('Could not allow site. Please try again.');
            }
            // Navigation is handled by background.js
        });
    }
});

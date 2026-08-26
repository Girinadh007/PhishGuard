// scripts/blocked.js — External script for blocked.html (required by Chrome extension CSP)

const params = new URLSearchParams(window.location.search);
const url = params.get('url');
const reason = params.get('reason');

const risk = params.get('risk');
let riskPercent = risk ? Math.round(parseFloat(risk) * 100) + '%' : 'Unknown';

if (url) document.getElementById('urlDisplay').textContent = url;

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
        reasonElement.innerHTML = `
            <strong>Why was this blocked? (Risk: ${riskPercent})</strong><br><br>
            We detected highly suspicious HTML structures on this page. Examples include hidden elements, external form submission targets, or password fields over an unencrypted connection.
            <br><br><em>Security Tip:</em> Even if a page limits what you can see visually, PhishGuard inspects the actual HTML code for hidden manipulation tactics.
        `;
    } else {
        reasonElement.innerHTML = `
            <strong>Why was this blocked? (Risk: ${riskPercent})</strong><br><br>
            The PhishGuard ML model detected anomalies common in phishing.
            Are you sure you recognize this exact domain spelling? Look for extra hyphens, numbers replacing letters (like '0' instead of 'o'), or unusual domain endings.
        `;
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

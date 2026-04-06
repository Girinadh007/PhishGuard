chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === 'showWarningBanner') {
    const risk = msg.risk || 0;
    const threshold = 0.8;

    if (risk > threshold) {
      if (!document.getElementById('phishguard-banner')) {
        const banner = document.createElement('div');
        banner.id = 'phishguard-banner';
        banner.style.position = 'fixed';
        banner.style.top = '0';
        banner.style.left = '0';
        banner.style.right = '0';
        banner.style.backgroundColor = 'red';
        banner.style.color = '#fff';
        banner.style.padding = '10px';
        banner.style.fontWeight = 'bold';
        banner.style.textAlign = 'center';
        banner.style.zIndex = '999999';
        banner.textContent = `Warning: This site looks suspicious (risk ${(risk * 100).toFixed(1)}%)!`;

        document.documentElement.appendChild(banner);
      }
    }
  }
});

function performDOMAnalysis() {
    let domRiskScore = 0;
    const reasons = [];

    if (window.location.protocol !== 'https:') {
        const passwordInputs = document.querySelectorAll('input[type="password"]');
        if (passwordInputs.length > 0) {
            domRiskScore += 0.6;
            reasons.push("Password field detected on unsecured HTTP connection.");
        }
    }

    const forms = document.querySelectorAll('form');
    let externalForms = 0;
    forms.forEach(form => {
        const action = form.getAttribute('action');
        if (action && action.startsWith('http')) {
            try {
                const actionUrl = new URL(action);
                if (actionUrl.hostname !== window.location.hostname) {
                    externalForms++;
                }
            } catch (e) {}
        }
    });

    if (externalForms > 0) {
        domRiskScore += 0.4;
        reasons.push("Data submission points to an external, unseen domain.");
    }

    if (domRiskScore > 0) {
       chrome.runtime.sendMessage({ 
           action: 'domAnalysisReport', 
           riskScore: domRiskScore, 
           reasons: reasons,
           url: window.location.href 
       });
    }
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', performDOMAnalysis);
} else {
    performDOMAnalysis();
}

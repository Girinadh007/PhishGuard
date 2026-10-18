chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === 'showWarningBanner') {
    if (window.location.protocol !== 'http:' && window.location.protocol !== 'https:') return;
    if (window.location.href.includes('dashboard.html') || window.location.href.includes('blocked.html') || window.location.href.includes('popup.html')) return;

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
        banner.style.backgroundColor = 'rgba(153, 27, 27, 0.95)'; // Deep red, much easier on the eyes
        banner.style.color = '#fdf2f8'; // Off-white
        banner.style.padding = '14px';
        banner.style.fontWeight = '600';
        banner.style.textAlign = 'center';
        banner.style.zIndex = '999999';
        banner.style.backdropFilter = 'blur(8px)';
        banner.style.boxShadow = '0 4px 6px rgba(0,0,0,0.2)';
        banner.style.fontFamily = 'sans-serif';
        banner.textContent = `Warning: This site looks suspicious (risk ${(risk * 100).toFixed(1)}%)!`;

        document.documentElement.appendChild(banner);
      }
    }
  }
});

// Target brand signatures for lightweight visual & semantic impersonation detection
const BRAND_TARGETS = [
  { name: 'Microsoft', keywords: ['microsoft', 'office 365', 'office365', 'outlook', 'onedrive', 'sharepoint', 'azure'], domains: ['microsoft.com', 'live.com', 'office.com', 'office365.com', 'sharepoint.com', 'azure.com', 'msn.com', 'bing.com', 'outlook.com', 'windows.com', 'microsoftonline.com', 'microsoftonline-p.com'] },
  { name: 'Google', keywords: ['google', 'gmail', 'google drive', 'google workspace', 'google docs'], domains: ['google.com', 'youtube.com', 'gmail.com', 'googleblog.com', 'googleusercontent.com', '1e100.net'] },
  { name: 'Apple', keywords: ['apple id', 'icloud', 'itunes', 'apple support'], domains: ['apple.com', 'icloud.com', 'me.com'] },
  { name: 'PayPal', keywords: ['paypal', 'paypal credit', 'send money'], domains: ['paypal.com', 'paypal-communication.com', 'paypalobjects.com'] },
  { name: 'Amazon', keywords: ['amazon', 'prime video', 'aws'], domains: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.in', 'amazon.fr', 'amazon.es', 'amazon.it', 'amazon.ca', 'amazon.co.jp'] },
  { name: 'Netflix', keywords: ['netflix', 'watch netflix'], domains: ['netflix.com'] },
  { name: 'Meta', keywords: ['facebook', 'instagram', 'meta', 'whatsapp', 'messenger'], domains: ['facebook.com', 'meta.com', 'instagram.com', 'whatsapp.com', 'messenger.com'] },
  { name: 'Chase', keywords: ['chase bank', 'chase online', 'jpmorgan'], domains: ['chase.com'] },
  { name: 'Bank of America', keywords: ['bank of america', 'bofa', 'merrill lynch'], domains: ['bankofamerica.com'] },
  { name: 'Wells Fargo', keywords: ['wells fargo', 'wellsfargo'], domains: ['wellsfargo.com'] },
  { name: 'Coinbase', keywords: ['coinbase', 'coinbase pro', 'coinbase wallet'], domains: ['coinbase.com'] },
  { name: 'Binance', keywords: ['binance'], domains: ['binance.com'] },
  { name: 'MetaMask', keywords: ['metamask', 'connect wallet', 'ethereum wallet', 'secret recovery phrase'], domains: ['metamask.io'] },
  { name: 'Steam', keywords: ['steam community', 'steam powered', 'steam guard'], domains: ['steampowered.com', 'steamcommunity.com'] },
  { name: 'Adobe', keywords: ['adobe id', 'adobe creative cloud', 'creative cloud'], domains: ['adobe.com'] },
  { name: 'DocuSign', keywords: ['docusign', 'electronic signature'], domains: ['docusign.com', 'docusign.net'] },
  { name: 'Dropbox', keywords: ['dropbox', 'dropbox business'], domains: ['dropbox.com'] }
];

// Suspicious third-party data collection endpoints used in phishing kits
const SUSPICIOUS_FORM_ENDPOINTS = [
  'formspree.io',
  'api.telegram.org',
  'discord.com/api/webhooks',
  'discordapp.com/api/webhooks',
  'docs.google.com/forms',
  'getform.io',
  'airtable.com',
  'webtoffee.com',
  'sheetdb.io',
  'formcarry.com'
];

let analysisDone = false;

function performDOMAnalysis() {
  if (analysisDone) return;

  // Only run on standard web pages
  if (window.location.protocol !== 'http:' && window.location.protocol !== 'https:') return;
  if (window.location.href.includes('dashboard.html') || window.location.href.includes('blocked.html') || window.location.href.includes('popup.html')) return;

  const currentHost = window.location.hostname.toLowerCase();
  
  // Skip local extension pages or about/blank
  if (!currentHost || currentHost === 'localhost' || currentHost === '127.0.0.1') return;

  let domRiskScore = 0;
  const reasons = [];
  const flags = [];

  const passwordInputs = document.querySelectorAll('input[type="password"]');
  const hasPasswordInput = passwordInputs.length > 0;
  const isHttp = window.location.protocol !== 'https:';

  // 1. Password input over unencrypted HTTP
  if (isHttp && hasPasswordInput) {
    domRiskScore += 0.65;
    flags.push('Insecure-Password-HTTP');
    flags.push('Fake-Login');
    reasons.push('Password entry requested over an unencrypted HTTP connection.');
  }

  // 2. Brand Impersonation Check (Title, Headings, Meta, Favicon)
  const pageTitle = (document.title || '').toLowerCase();
  const metaDesc = (document.querySelector('meta[name="description"]')?.getAttribute('content') || '').toLowerCase();
  const ogTitle = (document.querySelector('meta[property="og:title"]')?.getAttribute('content') || '').toLowerCase();
  const ogSite = (document.querySelector('meta[property="og:site_name"]')?.getAttribute('content') || '').toLowerCase();
  
  // Aggregate prominent textual context, stripping out common SSO button phrases
  const h1Texts = Array.from(document.querySelectorAll('h1, h2')).map(h => (h.textContent || '').toLowerCase()).join(' ');
  let combinedContext = `${pageTitle} ${ogTitle} ${ogSite} ${metaDesc} ${h1Texts}`;
  combinedContext = combinedContext.replace(/(sign in with|continue with|log in with|login with) [a-z0-9 ]+/g, '');

  for (const brand of BRAND_TARGETS) {
    const isDomainLegit = brand.domains.some(dom => currentHost === dom || currentHost.endsWith('.' + dom));
    if (isDomainLegit) continue;

    // Strict matching: Check if the primary page metadata claims to be the brand
    const titleClaimsBrand = brand.keywords.some(kw => pageTitle.includes(kw) || ogTitle.includes(kw) || ogSite.includes(kw));

    if (titleClaimsBrand) {
      if (hasPasswordInput) {
        domRiskScore += 0.75;
        flags.push('Brand-Impersonation');
        flags.push('Fake-Login');
        reasons.push(`Brand mismatch: Page presents credentials interface for "${brand.name}", but host "${currentHost}" is not an official domain.`);
        break;
      } else if (/login|sign in|verify|account|password|auth|billing/i.test(combinedContext)) {
        domRiskScore += 0.55;
        flags.push('Brand-Impersonation');
        flags.push('Fake-Login');
        reasons.push(`Suspected brand impersonation: Uses "${brand.name}" identity on non-affiliated domain "${currentHost}".`);
        break;
      }
    }
  }

  // 3. Form exfiltration & Cross-Origin Password Targets
  const TRUSTED_SSO_PROVIDERS = [
    'auth0.com', 'okta.com', 'cognito.amazonaws.com', 'firebaseapp.com',
    'clerk.dev', 'clerk.com', 'supabase.co', 'supabase.com',
    'microsoftonline.com', 'onelogin.com', 'pingidentity.com', 'amazoncognito.com'
  ];

  const forms = document.querySelectorAll('form');
  forms.forEach(form => {
    const action = (form.getAttribute('action') || '').trim().toLowerCase();
    const hasPassword = form.querySelector('input[type="password"]') !== null;

    if (hasPassword) {
      // Direct exfiltration to webhook / public form service
      const matchesExfiltration = SUSPICIOUS_FORM_ENDPOINTS.some(endpoint => action.includes(endpoint));
      if (matchesExfiltration) {
        domRiskScore += 0.85;
        flags.push('Exfiltration-Endpoint');
        flags.push('Fake-Login');
        reasons.push('Form submits sensitive credentials to a known third-party collector/webhook endpoint.');
      } else if (action.startsWith('http')) {
        try {
          const actionUrl = new URL(action, window.location.href);
          const isTrustedSSO = TRUSTED_SSO_PROVIDERS.some(sso => actionUrl.hostname === sso || actionUrl.hostname.endsWith('.' + sso));
          
          if (actionUrl.hostname && actionUrl.hostname !== currentHost && !actionUrl.hostname.endsWith('.' + currentHost) && !isTrustedSSO) {
            domRiskScore += 0.6;
            flags.push('Cross-Domain-Form');
            flags.push('Fake-Login');
            reasons.push(`Password form submits credentials to an external, untrusted host: ${actionUrl.hostname}`);
          }
        } catch (e) {}
      } else if (action.startsWith('javascript:')) {
        // Only penalize javascript: actions, allow blank/'#' for modern React/Vue/Angular SPAs
        domRiskScore += 0.15;
        flags.push('JS-Form-Action');
        reasons.push('Password form uses a JavaScript pseudo-protocol action attribute.');
      }
    }
  });

  // Password inputs outside any form tag
  if (hasPasswordInput && forms.length === 0) {
    domRiskScore += 0.3;
    flags.push('Orphan-Password-Field');
    reasons.push('Password fields detected outside standard HTML forms (often captured via loose event listeners).');
  }

  // 4. Hidden & Zero-Dimension iFrames (Cloaking / Payload Injection)
  const iframes = document.querySelectorAll('iframe');
  let suspiciousIframeFound = false;
  iframes.forEach(iframe => {
    const style = window.getComputedStyle(iframe);
    const width = parseInt(style.width, 10);
    const height = parseInt(style.height, 10);
    const isZeroSized = (width === 0 || height === 0 || width === 1 || height === 1 || iframe.getAttribute('width') === '0' || iframe.getAttribute('height') === '0');
    const isHidden = style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0';
    const isOffscreen = parseInt(style.top, 10) < -200 || parseInt(style.left, 10) < -200;

    if (isZeroSized || isHidden || isOffscreen) {
      suspiciousIframeFound = true;
    }
  });

  if (suspiciousIframeFound) {
    domRiskScore += 0.45;
    flags.push('Hidden-Iframe');
    reasons.push('Zero-dimensional or hidden iframe detected (common cloaking / exploit mechanism).');
  }

  // 5. Anti-Inspection / Researcher Evasion Checks
  let antiAnalysisDetected = false;
  const bodyStyle = window.getComputedStyle(document.body || document.documentElement);
  const userSelectDisabled = bodyStyle.userSelect === 'none' || bodyStyle.webkitUserSelect === 'none';
  const hasContextMenuBlock = document.body && (
    document.body.getAttribute('oncontextmenu')?.includes('return false') ||
    document.documentElement.getAttribute('oncontextmenu')?.includes('return false')
  );

  if ((userSelectDisabled || hasContextMenuBlock) && hasPasswordInput) {
    antiAnalysisDetected = true;
  }

  if (antiAnalysisDetected) {
    domRiskScore += 0.35;
    flags.push('Anti-Inspection-Evasion');
    reasons.push('Page deliberately blocks user selection or right-click inspection near sensitive inputs.');
  }

  // 6. Report findings if risk detected
  if (domRiskScore > 0) {
    analysisDone = true;
    chrome.runtime.sendMessage({
      action: 'domAnalysisReport',
      riskScore: Math.min(1.0, domRiskScore),
      flags: flags,
      reasons: reasons,
      url: window.location.href
    });
  }
}

// Initial execution
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    performDOMAnalysis();
  });
} else {
  performDOMAnalysis();
}

// Second-pass check after 1.2s to catch dynamic SPAs/phishing kits rendered via JavaScript
setTimeout(() => {
  if (!analysisDone) {
    performDOMAnalysis();
  }
}, 1200);

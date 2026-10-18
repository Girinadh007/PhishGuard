// scripts/blocked.js — External script for blocked.html (required by Chrome extension CSP)

const params = new URLSearchParams(window.location.search);
const url = params.get('url');
const reason = params.get('reason');
const risk = params.get('risk');
const flags = params.get('flags') ? params.get('flags').split(',').map(f => f.trim()).filter(Boolean) : [];
const details = params.get('details');

let riskPercent = risk ? Math.round(parseFloat(risk) * 100) + '%' : 'High';

if (url) {
    const urlDisplay = document.getElementById('urlDisplay');
    if (urlDisplay) urlDisplay.textContent = url;
}

// Analyze threat context and keywords for educational explanation & search
function analyzeThreatContext(targetUrl, blockReason, detectedFlags, blockDetails) {
    const flagsLower = detectedFlags.map(f => (f || '').toLowerCase());
    const detailsStr = (blockDetails || '').toLowerCase();
    let hostname = '';
    try {
        if (targetUrl) hostname = new URL(targetUrl).hostname.toLowerCase();
    } catch (e) {}

    // 1. Reverse Tunnel / Ephemeral Hosting
    const isTunnel = blockReason === 'cloudflare_tunnel' ||
                     blockReason === 'tunnel_header_detected' ||
                     flagsLower.some(f => f.includes('tunnel')) ||
                     /(ngrok(-free)?\.app|ngrok\.io|trycloudflare\.com|trycloudflare\.net|localtunnel\.me|serveo\.net|telebit\.io)/.test(hostname);

    if (isTunnel) {
        return {
            category: 'Reverse Tunnel Phishing',
            badgeIcon: '🛡️',
            keywords: 'reverse tunnel phishing ngrok cloudflare tunnels threat',
            topicLabel: 'Reverse Tunnel Phishing',
            explanation: 'This site is operating through an ephemeral reverse tunnel service (such as Cloudflare Tunnel, ngrok, or Serveo). Cybercriminals frequently abuse these disposable tunnels to rapidly deploy phishing pages that bypass traditional IP firewalls.',
            suggestion: 'Legitimate businesses and financial services almost never host authentication portals on temporary tunnel domains. Avoid entering any credentials or downloading files.',
            learning: 'Reverse tunnels allow anyone to expose a local web service to the public internet instantly. Because these URLs are temporary, threat actors abuse them to avoid domain reputation blocklists.',
            defaultEvidence: [
                'Website operates via a transient reverse proxy / tunnel domain',
                'Authentication forms detected on temporary hosting infrastructure',
                'Unverified host infrastructure lacking enterprise domain ownership'
            ]
        };
    }

    // 2. Newly Registered Domain
    const isDomainAge = blockReason === 'new_domain_age' ||
                        flagsLower.some(f => f.includes('domain-age') || f.includes('age')) ||
                        detailsStr.includes('< 30 days');

    if (isDomainAge) {
        return {
            category: 'Newly Registered Domain Risk',
            badgeIcon: '⏳',
            keywords: 'newly registered domains cybersecurity phishing threat',
            topicLabel: 'Newly Registered Domains',
            explanation: 'This website was registered less than 30 days ago. Brand-new domains carry an exceptionally high risk factor because cybercriminals frequently purchase fresh domains for short-lived phishing campaigns.',
            suggestion: 'Exercise extreme caution. Verified organizations and established online services do not route account sign-ins to newly registered domains.',
            learning: 'Threat actors buy domains in bulk, run phishing campaigns for 24-48 hours, and discard them before security blacklists update. Checking domain registration age is a vital defense.',
            defaultEvidence: [
                'Domain was registered less than 30 days ago',
                'Lack of established web reputation and historical trust',
                'High statistical correlation with disposable phishing kits'
            ]
        };
    }

    // 3. IDN Homograph / Look-Alike Spoofing
    const isHomograph = flagsLower.some(f => f.includes('homograph')) ||
                        hostname.includes('xn--') ||
                        detailsStr.includes('homograph') || detailsStr.includes('look-alike');

    if (isHomograph) {
        return {
            category: 'IDN Homograph Look-Alike Attack',
            badgeIcon: '🔍',
            keywords: 'IDN homograph attack look-alike domain spoofing phishing',
            topicLabel: 'IDN Homograph Attacks',
            explanation: 'The website address uses look-alike characters (such as Cyrillic or Greek characters that resemble Latin letters, or subtle character substitutions) engineered to visually deceive you into believing it is a genuine site.',
            suggestion: 'Inspect the address bar carefully or manually type the official website address into your browser. Bookmark authentic login pages for your banks and services.',
            learning: 'Internationalized Domain Name (IDN) homograph attacks substitute twin glyphs into domain names. While the URL may look identical to human eyes, the computer connects to an attacker-controlled server.',
            defaultEvidence: [
                'Detected visual homoglyphs or Punycode character substitutions',
                'Domain visually resembles a trusted brand with subtle character differences',
                'Deceptive character set designed to circumvent visual human inspection'
            ]
        };
    }

    // 4. Brand Impersonation / Fake Login
    const isBrandImpersonation = flagsLower.some(f => f.includes('brand-impersonation') || f.includes('fake-login')) ||
                                 detailsStr.includes('brand mismatch') || detailsStr.includes('impersonat');

    if (isBrandImpersonation) {
        return {
            category: 'Brand Impersonation & Fake Login',
            badgeIcon: '🚨',
            keywords: 'brand impersonation phishing attack credential harvesting',
            topicLabel: 'Brand Impersonation Phishing',
            explanation: 'PhishGuard detected high-confidence brand impersonation tactics. This page visually copies a trusted service to trick you into submitting your username and password.',
            suggestion: 'Never submit credentials on a website whose domain name does not match the official provider. Check the top-level domain and official account links.',
            learning: 'Attackers create identical replicas of authentic login screens by copying brand logos and stylesheets. Always verify the domain name in the address bar before typing passwords.',
            defaultEvidence: [
                'Page presents branding and login fields belonging to a trusted service',
                'Hosting domain is not affiliated with the genuine brand owner',
                'Unverified form submission target aiming to capture credentials'
            ]
        };
    }

    // 5. Form Exfiltration / Cross-Domain / Insecure Password
    const isFormExfiltration = flagsLower.some(f => f.includes('exfiltration') || f.includes('cross-domain') || f.includes('insecure-password'));

    if (isFormExfiltration) {
        return {
            category: 'Credential Harvesting & Exfiltration',
            badgeIcon: '⚠️',
            keywords: 'phishing credential harvesting form webhook exfiltration',
            topicLabel: 'Credential Harvesting Forms',
            explanation: 'The webpage contains a credential form configured to silently transmit entered passwords to an unauthorized third-party destination or over an unencrypted channel.',
            suggestion: 'Do not enter passwords or personal data. Verified sites submit passwords directly to their own secure authentication domains over encrypted HTTPS.',
            learning: 'Phishing kits often use third-party webhooks (like Discord or Telegram bots) or cross-origin form endpoints to exfiltrate stolen credentials instantly to attackers.',
            defaultEvidence: [
                'Form action directs passwords to an external collector or webhook endpoint',
                'Insecure or cross-domain credential handling detected',
                'Unauthorized third-party data recipient identified in page HTML'
            ]
        };
    }

    // 6. Cloaking / Anti-Inspection / Hidden iFrames
    const isEvasion = flagsLower.some(f => f.includes('hidden-iframe') || f.includes('anti-inspection') || f.includes('evasion'));

    if (isEvasion) {
        return {
            category: 'Anti-Analysis & Cloaking Evasion',
            badgeIcon: '🕵️',
            keywords: 'phishing website evasion cloaking hidden iframe techniques',
            topicLabel: 'Phishing Evasion & Cloaking',
            explanation: 'This site employs stealth cloaking mechanisms (such as invisible frames or disabling browser inspection controls) to evade automated security inspection.',
            suggestion: 'Be cautious of any web page that prevents normal browser interactions like selecting text or right-clicking near input boxes.',
            learning: 'Malicious pages use cloaking to serve benign content to automated security scanners while displaying credential theft traps only to real human users.',
            defaultEvidence: [
                'Hidden or zero-pixel iframe detected in document hierarchy',
                'Anti-inspection event listeners blocking standard browser controls',
                'Anomalous DOM cloaking tactics characteristic of modern phishing kits'
            ]
        };
    }

    // 7. General Structural Anomalies / Machine Learning Detection
    return {
        category: 'Phishing Link & Structural Anomalies',
        badgeIcon: '🤖',
        keywords: 'phishing URL deceptive structure domain anomalies',
        topicLabel: 'Deceptive URL Structures',
        explanation: 'The PhishGuard machine learning engine detected multiple structural anomalies and deceptive link signatures typical of modern phishing schemes.',
        suggestion: 'Verify the domain name carefully. Check for misleading subdomains, excess hyphens, or unusual top-level domain extensions.',
        learning: 'Deceptive URLs frequently prepend reputable brand names into complex subdomains to mislead users who only read the beginning of a URL.',
        defaultEvidence: [
            'Deceptive URL lexical structure and high entropy pattern',
            'Multiple anomalous subdomains or high-risk domain characteristics',
            'Strong structural correlation with known malicious link distributions'
        ]
    };
}

// Function to search web for educational resources about a threat keyword topic
function openThreatSearch(keywords) {
    if (!keywords) return;
    const searchUrl = `https://www.google.com/search?q=${encodeURIComponent(keywords)}`;
    if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.create) {
        chrome.tabs.create({ url: searchUrl });
    } else {
        window.open(searchUrl, '_blank', 'noopener,noreferrer');
    }
}

// Map flags to secondary keyword search topics
const FLAG_KEYWORD_MAP = {
    'brand-impersonation': { label: 'Brand Impersonation', keywords: 'brand impersonation phishing attacks' },
    'fake-login': { label: 'Fake Login Page', keywords: 'fake login phishing detection' },
    'tunnel': { label: 'Reverse Tunnel', keywords: 'reverse tunnel phishing ngrok threats' },
    'tunnel-header': { label: 'Reverse Tunnel Header', keywords: 'reverse tunnel phishing ngrok threats' },
    'homograph': { label: 'Homograph Attack', keywords: 'IDN homograph attack URL spoofing' },
    'exfiltration-endpoint': { label: 'Form Exfiltration', keywords: 'phishing credential harvesting form webhook' },
    'cross-domain-form': { label: 'Cross-Domain Form', keywords: 'cross domain form phishing credentials' },
    'insecure-password-http': { label: 'Unencrypted Password', keywords: 'insecure http password login phishing' },
    'hidden-iframe': { label: 'Hidden iFrame Cloaking', keywords: 'phishing cloaking hidden iframe evasion' },
    'anti-inspection-evasion': { label: 'Anti-Inspection Evasion', keywords: 'phishing anti analysis evasion techniques' },
    'suspicious-domain-age': { label: 'Domain Age Risk', keywords: 'newly registered domain phishing threat' },
    'risk-tld': { label: 'Suspicious TLD', keywords: 'suspicious TLD phishing top level domain' },
    'subdomains': { label: 'Subdomain Deception', keywords: 'subdomain deception phishing URL' }
};

const threat = analyzeThreatContext(url, reason, flags, details);

// Populate reason block with side-by-side explanation, suggestion, and "Know more about this" button
const reasonElement = document.getElementById('reasonDisplay');
if (reasonElement) {
    reasonElement.innerHTML = `
        <div class="explanation-card">
            <div class="explanation-header-row">
                <div class="threat-meta">
                    <span class="threat-badge"><span>${threat.badgeIcon}</span> <span>${threat.category}</span></span>
                    <span class="threat-risk-pill">Risk: ${riskPercent}</span>
                </div>
                <div class="threat-topic-tag">
                    Threat Topic: <strong>${threat.topicLabel}</strong>
                </div>
            </div>
            
            <div class="explanation-body-grid">
                <div class="explanation-text-column">
                    <div class="explanation-detail">${threat.explanation}</div>
                    <div class="suggestion-box">
                        <strong>💡 Suggestion:</strong> ${threat.suggestion}
                    </div>
                    <div class="threat-chips-row" id="threatChipsRow"></div>
                </div>
                
                <div class="explanation-action-column">
                    <button id="knowMoreBtn" class="know-more-btn" type="button" aria-label="Know more about this threat">
                        <span>🔍</span> Know more about this
                    </button>
                    <span class="know-more-hint">Search topic: <em>"${threat.topicLabel}"</em></span>
                </div>
            </div>
        </div>
    `;

    // Attach click listener to primary "Know more about this" button
    const knowMoreBtn = document.getElementById('knowMoreBtn');
    if (knowMoreBtn) {
        knowMoreBtn.addEventListener('click', () => {
            openThreatSearch(threat.keywords);
        });
    }

    // Populate secondary threat chips if flags exist
    const chipsRow = document.getElementById('threatChipsRow');
    if (chipsRow && flags.length > 0) {
        const uniqueChips = [];
        flags.forEach(flag => {
            const key = flag.toLowerCase();
            if (FLAG_KEYWORD_MAP[key]) {
                const info = FLAG_KEYWORD_MAP[key];
                if (!uniqueChips.some(c => c.label === info.label)) {
                    uniqueChips.push(info);
                }
            }
        });

        if (uniqueChips.length > 0) {
            const labelSpan = document.createElement('span');
            labelSpan.className = 'threat-chips-label';
            labelSpan.textContent = 'Explore topics:';
            chipsRow.appendChild(labelSpan);

            uniqueChips.forEach(chipInfo => {
                const chipBtn = document.createElement('button');
                chipBtn.className = 'threat-chip';
                chipBtn.type = 'button';
                chipBtn.innerHTML = `<span>🔎</span> ${chipInfo.label}`;
                chipBtn.addEventListener('click', () => {
                    openThreatSearch(chipInfo.keywords);
                });
                chipsRow.appendChild(chipBtn);
            });
        }
    }
}

// Populate detailed evidence list
const evidenceList = document.getElementById('evidenceList');
if (evidenceList) {
    let items = [];
    if (details) {
        items = details.split(' | ').map(d => `<li style="margin-bottom: 8px;">⚠️ ${d}</li>`);
    } else if (flags.length > 0) {
        items = flags.map(f => `<li style="margin-bottom: 8px;">⚠️ Detected anomaly: <strong>${f}</strong></li>`);
    } else if (threat.defaultEvidence && threat.defaultEvidence.length > 0) {
        items = threat.defaultEvidence.map(e => `<li style="margin-bottom: 8px;">⚠️ ${e}</li>`);
    }
    if (items.length > 0) {
        evidenceList.innerHTML = items.join('');
    }
}

// Update educational learning text in evidence section
const learningContent = document.getElementById('learningContent');
if (learningContent && threat.learning) {
    learningContent.textContent = threat.learning;
}

// Attach listener to evidence section "Know more about this" button
const evidenceKnowMoreBtn = document.getElementById('evidenceKnowMoreBtn');
if (evidenceKnowMoreBtn) {
    evidenceKnowMoreBtn.addEventListener('click', () => {
        openThreatSearch(threat.keywords);
    });
}

// Go Back button
const goBackBtn = document.getElementById('goBackBtn');
if (goBackBtn) {
    goBackBtn.addEventListener('click', () => {
        history.back();
    });
}

// Learn Why toggle button
const learnWhyBtn = document.getElementById('learnWhyBtn');
if (learnWhyBtn) {
    learnWhyBtn.addEventListener('click', () => {
        const section = document.getElementById('evidenceSection');
        if (section) {
            if (section.style.display === 'none' || !section.style.display) {
                section.style.display = 'block';
                learnWhyBtn.textContent = 'Hide Details';
            } else {
                section.style.display = 'none';
                learnWhyBtn.textContent = 'Learn Why';
            }
        }
    });
}

// Allow Site button — ONE-TIME ONLY
const allowSiteBtn = document.getElementById('allowSiteBtn');
if (allowSiteBtn) {
    allowSiteBtn.addEventListener('click', () => {
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
            allowSiteBtn.textContent = 'Allowing (once)...';
            allowSiteBtn.disabled = true;

            chrome.runtime.sendMessage({ action: 'allowSiteOnce', url: url }, (response) => {
                if (chrome.runtime.lastError || !response || !response.success) {
                    allowSiteBtn.textContent = 'Continue Anyway (Not Recommended)';
                    allowSiteBtn.disabled = false;
                    alert('Could not allow site. Please try again.');
                }
                // Navigation is handled by background.js
            });
        }
    });
}

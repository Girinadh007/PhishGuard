// background.js
import {
  loadModel,
  extractFeaturesFromUrl,
  predictProbability
} from './scripts/model_predict.js';

const MODEL_PATH = chrome.runtime.getURL('model/model.json');
const BLOCK_THRESHOLD = 0.96; // Immediate block
const WARN_THRESHOLD = 0.85;  // Warning banner + Safe Mode

let modelLoaded = false;
let allowlist = new Set();

// One-time allow set — backed by chrome.storage.session so it survives service worker restarts
// (chrome.storage.session is cleared when the browser is closed, but persists across SW suspensions)
async function isOneTimeAllowed(domain) {
  const data = await chrome.storage.session.get('oneTimeAllowSet');
  const set = data.oneTimeAllowSet || [];
  return set.includes(domain);
}

async function addOneTimeAllow(domain) {
  const data = await chrome.storage.session.get('oneTimeAllowSet');
  const set = data.oneTimeAllowSet || [];
  if (!set.includes(domain)) set.push(domain);
  await chrome.storage.session.set({ oneTimeAllowSet: set });
}

async function consumeOneTimeAllow(domain) {
  const data = await chrome.storage.session.get('oneTimeAllowSet');
  const set = (data.oneTimeAllowSet || []).filter(d => d !== domain);
  await chrome.storage.session.set({ oneTimeAllowSet: set });
}

// Initialize Stats
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({
    stats: { scanned: 0, blocked: 0, totalRisk: 0, falsePositives: 0, falseNegatives: 0 },
    scanLogs: [],
    pending_training_data: [],
    allowlist: []
  });
});

(async () => {
  try {
    const allowlistUrl = chrome.runtime.getURL('model/allowlist.json');
    const response = await fetch(allowlistUrl);
    const allowlistArray = await response.json();
    allowlist = new Set(allowlistArray);
    console.log(`Loaded ${allowlist.size} domains into allowlist`);

    await loadModel(MODEL_PATH);
    modelLoaded = true;
    console.log('PhishGuard AI model loaded');
  } catch (err) {
    console.error('Model load failed:', err);
  }
})();

function isRestrictedUrl(url) {
  return url.startsWith('chrome://') || url.startsWith('about:') || url.startsWith('edge://') || url.startsWith('file://') || url.includes('blocked.html');
}

// Security Logger & Stats Tracker
async function logSecurityEvent(url, risk, features) {
  const domain = new URL(url).hostname;
  const flags = [];
  if (features.is_tunnel) flags.push("Tunnel");
  if (features.is_homograph) flags.push("Homograph");
  if (features.suspicious_tld) flags.push("Risk-TLD");
  if (features.subdomain_count > 2) flags.push("Subdomains");

  chrome.storage.local.get(['stats', 'scanLogs', 'pending_training_data', 'safeMode'], (res) => {
    let stats = res.stats || { scanned: 0, blocked: 0, totalRisk: 0, falsePositives: 0, falseNegatives: 0 };
    let logs = res.scanLogs || [];
    let trainingData = res.pending_training_data || [];

    stats.scanned++;
    stats.totalRisk += risk;
    if (risk >= BLOCK_THRESHOLD) stats.blocked++;

    logs.push({
      ts: Date.now(),
      domain: domain,
      risk: risk,
      flags: flags.join(', ')
    });

    // Save for dataset improvement (Anonymous)
    trainingData.push({ url, risk, ts: Date.now() });

    // Keep logs manageable
    if (logs.length > 500) logs.shift();
    if (trainingData.length > 1000) trainingData.shift();

    chrome.storage.local.set({ stats, scanLogs: logs, pending_training_data: trainingData });

    // Activate Safe Mode if Risk is High or User Enabled it
    const shouldEnforceSafeMode = (risk >= WARN_THRESHOLD) || !!res.safeMode;
    if (shouldEnforceSafeMode) {
      applySafeModeProtections(url, risk);
    }
  });
}

function applySafeModeProtections(url, risk) {
  chrome.tabs.query({ url: url }, (tabs) => {
    tabs.forEach(tab => {
      chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: (r) => {
          window.phishGuardRisk = r;
          console.log(`[PhishGuard] Safe Mode Active (Risk: ${Math.round(r * 100)}%)`);
          // Disable auto-fill and password fields protection
          document.querySelectorAll('input[type="password"]').forEach(i => {
            i.setAttribute('autocomplete', 'off');
            i.style.border = '2px solid #ef4444';
          });
          // Optional: Inject warning banner
        },
        args: [risk]
      }).catch(() => { });
    });
  });
}

// Local cache for RDAP lookups
const domainAgeCache = new Map();

async function checkDomainAge(hostname, tabId, url, currentRisk) {
    if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) return;
    const parts = hostname.split('.');
    if (parts.length < 2) return;
    
    // For TLDs like .co.uk, this is rough, but mostly works for top-level detection
    let rootDomain = parts.slice(-2).join('.');
    if (parts.length > 2 && (parts[parts.length - 2].length <= 3)) {
        rootDomain = parts.slice(-3).join('.');
    }
    
    if (currentRisk === 0) return; // Assume SAFE_DOMAIN
    
    if (domainAgeCache.has(rootDomain)) {
        applyAgePenalty(domainAgeCache.get(rootDomain), tabId, url, currentRisk);
        return;
    }

    try {
        const resp = await fetch(`https://rdap.org/domain/${rootDomain}`);
        if (resp.ok) {
            const data = await resp.json();
            const regEvent = data.events?.find(e => e.eventAction === 'registration');
            if (regEvent && regEvent.eventDate) {
                const regDate = new Date(regEvent.eventDate);
                const ageDays = (Date.now() - regDate.getTime()) / (1000 * 60 * 60 * 24);
                const isSuspiciousAge = ageDays < 30; // 30 day threshold
                domainAgeCache.set(rootDomain, isSuspiciousAge);
                applyAgePenalty(isSuspiciousAge, tabId, url, currentRisk);
                return;
            }
        }
        domainAgeCache.set(rootDomain, false); // don't penalize on error/missing data
    } catch(e) {
        domainAgeCache.set(rootDomain, false);
    }
}

function applyAgePenalty(isSuspiciousAge, tabId, url, currentRisk) {
    if (!isSuspiciousAge) return;
    const newRisk = Math.min(1.0, currentRisk + 0.4); 
    if (newRisk >= BLOCK_THRESHOLD) {
        chrome.tabs.update(tabId, {
            url: chrome.runtime.getURL('blocked.html') + `?url=${encodeURIComponent(url)}&risk=${newRisk}&reason=new_domain_age`
        });
    } else if (newRisk >= WARN_THRESHOLD) {
        applySafeModeProtections(url, newRisk);
    }
}

chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const url = details.url;
  if (isRestrictedUrl(url) || !modelLoaded) return;

  // Check one-time allow token FIRST — now backed by session storage to survive SW restarts
  try {
    const parsedUrl = new URL(url);
    if (await isOneTimeAllowed(parsedUrl.hostname)) {
      await consumeOneTimeAllow(parsedUrl.hostname); // Consume — blocked again on next visit
      return;
    }
  } catch (e) {
    return;
  }

  try {
    const parsedUrl = new URL(url);
    
    // Check if domain is in the global allowlist (Top 100k)
    let domainToCheck = parsedUrl.hostname;
    if (domainToCheck.startsWith('www.')) {
        domainToCheck = domainToCheck.substring(4);
    }
    if (allowlist.has(domainToCheck)) {
        return; // Immediately approve (0ms interception time)
    }

    const features = extractFeaturesFromUrl(url);
    const risk = await predictProbability(features, url);

    logSecurityEvent(url, risk, features);

    if (risk >= BLOCK_THRESHOLD) {
      chrome.tabs.update(details.tabId, {
        url: chrome.runtime.getURL('blocked.html') + `?url=${encodeURIComponent(url)}&risk=${risk}`
      });
    } else {
      checkDomainAge(parsedUrl.hostname, details.tabId, url, risk);
    }
  } catch (e) {
    console.error('Scan error:', e);
  }
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === 'getRiskForUrl') {
    (async () => {
      try {
        const features = extractFeaturesFromUrl(msg.url);
        const p = await predictProbability(features, msg.url);
        sendResponse({ fused: p, features: features });
      } catch (err) {
        sendResponse({ error: String(err) });
      }
    })();
    return true;
  }
  
  if (msg.action === 'allowSiteOnce') {
      (async () => {
          try {
              const domain = new URL(msg.url).hostname;
              const tabId = sender.tab ? sender.tab.id : null;

              // Grant one-time pass in session storage — survives SW suspension
              await addOneTimeAllow(domain);

              // Track as false positive in stats only (no persistent allowlist)
              chrome.storage.local.get(['stats'], (res) => {
                  const stats = res.stats || { scanned: 0, blocked: 0, totalRisk: 0, falsePositives: 0, falseNegatives: 0 };
                  stats.falsePositives = (stats.falsePositives || 0) + 1;
                  chrome.storage.local.set({ stats }, () => {
                      if (tabId) {
                          chrome.tabs.update(tabId, { url: msg.url }, () => {
                              sendResponse({ success: true });
                          });
                      } else {
                          sendResponse({ success: true });
                      }
                  });
              });
          } catch(e) {
              sendResponse({ success: false });
          }
      })();
      return true;
  }
  
  if (msg.action === 'reportSite') {
      try {
          chrome.storage.local.get(['stats'], (res) => {
              const stats = res.stats || { scanned: 0, blocked: 0, totalRisk: 0, falsePositives: 0, falseNegatives: 0 };
              stats.falseNegatives = (stats.falseNegatives || 0) + 1;
              chrome.storage.local.set({ stats: stats });
              sendResponse({ success: true });
          });
      } catch(e) {
         sendResponse({ success: false });
      }
      return true;
  }
  if (msg.action === 'domAnalysisReport') {
    const { riskScore, reasons, url } = msg;
    if (riskScore >= 0.8) {
      // Do NOT re-block if the user already explicitly allowed this domain once
      (async () => {
        try {
          const domain = new URL(url).hostname;
          if (await isOneTimeAllowed(domain)) return; // User just allowed it — skip DOM re-block
        } catch (e) {}
        chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
            if (tabs[0] && tabs[0].url === url) {
                chrome.tabs.update(tabs[0].id, {
                  url: chrome.runtime.getURL('blocked.html') + `?url=${encodeURIComponent(url)}&risk=${riskScore}&reason=dom_heuristics`
                });
            }
        });
      })();
    } else if (riskScore > 0) {
      logSecurityEvent(url, riskScore, { is_tunnel: 0, is_homograph: 0, suspicious_tld: 0, subdomain_count: 0 });
    }
  }
});

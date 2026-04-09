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

chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const url = details.url;
  if (isRestrictedUrl(url) || !modelLoaded) return;

  chrome.storage.local.get(['allowlist'], async (res) => {
    const list = res.allowlist || [];
    try {
      const parsedUrl = new URL(url);
      if (list.includes(parsedUrl.hostname)) {
          return; // User explicitly trusted this site
      }
    if (parsedUrl.hostname.endsWith('.trycloudflare.com') || parsedUrl.hostname === 'trycloudflare.com' || parsedUrl.hostname.endsWith('.trycloudflare.net') || parsedUrl.hostname === 'trycloudflare.net') {
      logSecurityEvent(url, 1.0, { is_tunnel: 1, is_homograph: 0, suspicious_tld: 0, subdomain_count: 0 });
      chrome.tabs.update(details.tabId, {
        url: chrome.runtime.getURL('blocked.html') + `?url=${encodeURIComponent(url)}&risk=1.00&reason=cloudflare_tunnel`
      });
      return;
    }

    const features = extractFeaturesFromUrl(url);
    const risk = await predictProbability(features, url);

    logSecurityEvent(url, risk, features);

    if (risk >= BLOCK_THRESHOLD) {
      chrome.tabs.update(details.tabId, {
        url: chrome.runtime.getURL('blocked.html') + `?url=${encodeURIComponent(url)}&risk=${risk}`
      });
    }
  } catch (e) {
    console.error('Scan error:', e);
  }
  }); // End storage get
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
  
  if (msg.action === 'allowSite') {
      try {
          const domain = new URL(msg.url).hostname;
          chrome.storage.local.get(['allowlist', 'stats'], (res) => {
              const list = res.allowlist || [];
              const stats = res.stats || { scanned: 0, blocked: 0, totalRisk: 0, falsePositives: 0, falseNegatives: 0 };
              
              if (!list.includes(domain)) {
                  list.push(domain);
                  stats.falsePositives = (stats.falsePositives || 0) + 1; // Mark as false positive
                  // Wait for storage write to complete BEFORE sending response
                  chrome.storage.local.set({ allowlist: list, stats: stats }, () => {
                      sendResponse({ success: true });
                  });
              } else {
                  // Already in allowlist, respond immediately
                  sendResponse({ success: true });
              }
          });
      } catch(e) {
          sendResponse({ success: false });
      }
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
      chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
          if (tabs[0] && tabs[0].url === url) {
              chrome.tabs.update(tabs[0].id, {
                url: chrome.runtime.getURL('blocked.html') + `?url=${encodeURIComponent(url)}&risk=${riskScore}&reason=dom_heuristics`
              });
          }
      });
    } else if (riskScore > 0) {
      logSecurityEvent(url, riskScore, { is_tunnel: 0, is_homograph: 0, suspicious_tld: 0, subdomain_count: 0 });
    }
  }
});

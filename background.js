// background.js
import {
  loadModel,
  extractFeaturesFromUrl,
  predictProbability,
  getModelInfo
} from './scripts/model_predict.js';

const MODEL_PATH = chrome.runtime.getURL('model/model.json');
const BLOCK_THRESHOLD = 0.80; // Immediate block
const WARN_THRESHOLD = 0.70;  // Warning banner + Safe Mode

let modelLoaded = false;
let allowlist = new Set();
let currentModelVersion = '1.0.0';
let allowlistSource = 'packaged';

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

// Initialize Stats & Scheduled OTA Alarms
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(['stats'], (res) => {
    if (!res.stats) {
      chrome.storage.local.set({
        stats: { scanned: 0, blocked: 0, totalRisk: 0, falsePositives: 0, falseNegatives: 0 },
        scanLogs: [],
        pending_training_data: [],
        allowlist: []
      });
    }
  });

  // Schedule daily background OTA check (every 24 hours)
  chrome.alarms.create('otaUpdateCheck', { periodInMinutes: 1440 });
});

// Periodic Alarm Listener for OTA Updates
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'otaUpdateCheck') {
    checkForOTAUpdates(false);
  }
});

// Over-The-Air (OTA) Model & Allowlist Updater
async function checkForOTAUpdates(manual = false) {
  try {
    const config = await chrome.storage.local.get(['ota_endpoint', 'model_version']);
    const endpoint = config.ota_endpoint || 'https://raw.githubusercontent.com/Girinadh007/PhishGuard/main/model';
    
    const versionResp = await fetch(`${endpoint}/version.json?_=${Date.now()}`, { cache: 'no-cache' });
    if (!versionResp.ok) throw new Error(`Remote repository returned HTTP ${versionResp.status}`);
    const remoteMeta = await versionResp.json();
    
    const localVersion = config.model_version || currentModelVersion || '1.0.0';
    if (remoteMeta.version && remoteMeta.version > localVersion) {
      // Download updated model
      const modelResp = await fetch(`${endpoint}/model.json?_=${Date.now()}`, { cache: 'no-cache' });
      if (!modelResp.ok) throw new Error(`Failed to download model.json (HTTP ${modelResp.status})`);
      const newModel = await modelResp.json();

      if (!newModel.trees || !newModel.features) {
        throw new Error('Downloaded model is missing required schema');
      }

      let newAllowlist = null;
      if (remoteMeta.allowlist_updated) {
        const allowResp = await fetch(`${endpoint}/allowlist.json?_=${Date.now()}`, { cache: 'no-cache' });
        if (allowResp.ok) newAllowlist = await allowResp.json();
      }

      // Hot reload model in memory
      await loadModel(newModel);
      currentModelVersion = remoteMeta.version;

      const toSave = {
        ota_model: newModel,
        model_version: remoteMeta.version,
        last_ota_check: Date.now()
      };
      if (newAllowlist && Array.isArray(newAllowlist)) {
        toSave.ota_allowlist = newAllowlist;
        allowlist = new Set(newAllowlist);
        allowlistSource = 'ota';
      }
      await chrome.storage.local.set(toSave);

      return {
        success: true,
        updated: true,
        version: remoteMeta.version,
        message: `Successfully updated to Model v${remoteMeta.version}!`
      };
    } else {
      await chrome.storage.local.set({ last_ota_check: Date.now() });
      return {
        success: true,
        updated: false,
        version: localVersion,
        message: `You are on the latest model rules (v${localVersion}).`
      };
    }
  } catch (err) {
    await chrome.storage.local.set({ last_ota_check: Date.now() });
    return {
      success: false,
      error: err.message,
      message: `Update check failed: ${err.message}`
    };
  }
}

// Load Active Model & Allowlist (OTA Cache with Packaged Fallback)
(async () => {
  try {
    const storage = await chrome.storage.local.get(['ota_allowlist', 'ota_model', 'model_version']);
    
    // 1. Allowlist loading
    if (storage.ota_allowlist && Array.isArray(storage.ota_allowlist)) {
      allowlist = new Set(storage.ota_allowlist);
      allowlistSource = 'ota';
      console.log(`[PhishGuard OTA] Loaded ${allowlist.size} domains from cached OTA allowlist`);
    } else {
      const allowlistUrl = chrome.runtime.getURL('model/allowlist.json');
      const response = await fetch(allowlistUrl);
      const allowlistArray = await response.json();
      allowlist = new Set(allowlistArray);
      allowlistSource = 'packaged';
      console.log(`[PhishGuard] Loaded ${allowlist.size} domains from packaged allowlist`);
    }

    // 2. ML Model loading (Flattened Typed-Array JIT Engine)
    if (storage.ota_model && typeof storage.ota_model === 'object') {
      await loadModel(storage.ota_model);
      currentModelVersion = storage.model_version || storage.ota_model.version || '1.1.0-ota';
      modelLoaded = true;
      console.log(`[PhishGuard OTA] Loaded AI model v${currentModelVersion} from OTA cache`);
    } else {
      await loadModel(MODEL_PATH);
      currentModelVersion = '1.0.0';
      modelLoaded = true;
      console.log('[PhishGuard] Packaged AI model loaded into Flattened Engine');
    }
  } catch (err) {
    console.error('Model load failed, attempting packaged fallback:', err);
    try {
      await loadModel(MODEL_PATH);
      modelLoaded = true;
    } catch (e) {}
  }
})();

function isRestrictedUrl(url) {
  return url.startsWith('chrome://') || url.startsWith('about:') || url.startsWith('edge://') || url.startsWith('file://') || url.includes('blocked.html');
}

// Security Logger & Stats Tracker
async function logSecurityEvent(url, risk, features, extraFlags = []) {
  const domain = new URL(url).hostname;
  const flags = [...extraFlags];
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
  
  if (msg.action === 'checkForUpdates') {
    (async () => {
      const result = await checkForOTAUpdates(true);
      sendResponse(result);
    })();
    return true;
  }

  if (msg.action === 'getModelStatus') {
    (async () => {
      const storage = await chrome.storage.local.get(['last_ota_check', 'model_version']);
      const info = getModelInfo();
      sendResponse({
        ...info,
        version: currentModelVersion,
        allowlistSize: allowlist.size,
        allowlistSource: allowlistSource,
        lastOtaCheck: storage.last_ota_check || null
      });
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
    const { riskScore, reasons, flags, url } = msg;
    const extraFlags = flags || [];
    const details = reasons && reasons.length ? reasons.join(' | ') : '';

    if (riskScore >= BLOCK_THRESHOLD) {
      // Do NOT re-block if the user already explicitly allowed this domain once
      (async () => {
        try {
          const domain = new URL(url).hostname;
          if (await isOneTimeAllowed(domain)) return; // User just allowed it — skip DOM re-block
        } catch (e) {}

        logSecurityEvent(url, riskScore, { is_tunnel: 0, is_homograph: 0, suspicious_tld: 0, subdomain_count: 0 }, extraFlags);

        const tabId = sender.tab ? sender.tab.id : null;
        const blockUrl = chrome.runtime.getURL('blocked.html') + 
          `?url=${encodeURIComponent(url)}&risk=${riskScore}&reason=dom_heuristics&flags=${encodeURIComponent(extraFlags.join(','))}&details=${encodeURIComponent(details)}`;

        if (tabId) {
          chrome.tabs.update(tabId, { url: blockUrl });
        } else {
          chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
            if (tabs[0] && tabs[0].url === url) {
              chrome.tabs.update(tabs[0].id, { url: blockUrl });
            }
          });
        }
      })();
    } else if (riskScore >= WARN_THRESHOLD) {
      logSecurityEvent(url, riskScore, { is_tunnel: 0, is_homograph: 0, suspicious_tld: 0, subdomain_count: 0 }, extraFlags);
      applySafeModeProtections(url, riskScore);
    } else if (riskScore > 0) {
      logSecurityEvent(url, riskScore, { is_tunnel: 0, is_homograph: 0, suspicious_tld: 0, subdomain_count: 0 }, extraFlags);
    }
  }
});

const TUNNEL_HEADERS = [
  'ngrok-skip-browser-warning',
  'x-ngrok-skip-browser-warning',
  'x-serveo-',
  'x-localtunnel-'
];

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.type !== 'main_frame') return;
    
    let isTunnel = false;
    if (details.responseHeaders) {
      for (let header of details.responseHeaders) {
        const headerName = header.name.toLowerCase();
        if (TUNNEL_HEADERS.some(t => headerName.includes(t))) {
          isTunnel = true;
          break;
        }
      }
    }
    
    if (isTunnel) {
      logSecurityEvent(details.url, 1.0, { is_tunnel: 1, is_homograph: 0, suspicious_tld: 0, subdomain_count: 0 });
      chrome.tabs.update(details.tabId, {
        url: chrome.runtime.getURL('blocked.html') + `?url=${encodeURIComponent(details.url)}&risk=1.00&reason=tunnel_header_detected`
      });
    }
  },
  { urls: ['<all_urls>'] },
  ['responseHeaders']
);

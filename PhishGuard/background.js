import {
  loadModel,
  extractFeaturesFromUrl,
  predictProbability
} from './scripts/model_predict.js';

const MODEL_PATH = chrome.runtime.getURL('model/model.json');
const BLOCK_THRESHOLD = 0.95;
const WARN_THRESHOLD = 0.9;

let modelLoaded = false;

// Load ML model on startup
(async () => {
  try {
    await loadModel(MODEL_PATH);
    modelLoaded = true;
    console.log('PhishGuard model loaded');
  } catch (err) {
    console.error('Model load failed:', err);
  }
})();

// Heuristic scoring function
function heuristicScore(url) {
  let score = 0;
  if (url.includes('@')) score += 0.6;
  if (url.match(/\d+\.\d+\.\d+\.\d+/)) score += 0.8;
  if (url.length > 200) score += 0.4;
  if (url.includes('xn--')) score += 0.4;
  return Math.min(1, score);
}

// Restricted URL check
function isRestrictedUrl(url) {
  return (
    url.startsWith('chrome://') ||
    url.startsWith('about:') ||
    url.startsWith('edge://') ||
    url.startsWith('file://')
  );
}

// Safe hostname extraction
function getHostname(url) {
  try {
    return new URL(url).hostname;
  } catch (e) {
    console.warn('Invalid URL for hostname extraction:', url);
    return 'unknown';
  }
}

// Navigation handler
chrome.webNavigation.onCommitted.addListener(async (details) => {
  const url = details.url;
  if (isRestrictedUrl(url)) {
    console.warn(`Restricted URL skipped: ${url}`);
    return;
  }

  try {
    const h = heuristicScore(url);

    if (h >= BLOCK_THRESHOLD) {
      const hostname = getHostname(url);
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icon.png',
        title: 'PhishGuard blocked a site',
        message: `Navigation to ${hostname} was blocked by heuristic checks.`,
        requireInteraction: true
      });
      chrome.tabs.update(details.tabId, {
        url: chrome.runtime.getURL('blocked.html') + `?url=${encodeURIComponent(url)}`
      });
      return;
    }

    if (!modelLoaded) return;

    const features = extractFeaturesFromUrl(url);
    if (!features) return;

    const p = await predictProbability(features);
    const fused = 0.4 * h + 0.6 * p;

    console.log(`PhishGuard check: URL=${url}, Heuristic=${h}, ML=${p}, Fused=${fused}`);

    if (fused >= BLOCK_THRESHOLD) {
      chrome.tabs.update(details.tabId, {
        url: chrome.runtime.getURL('blocked.html') + `?url=${encodeURIComponent(url)}`
      });
    } else if (fused >= 0.9) {  // WARN_THRESHOLD=0.9
    
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icon.png',
    title: 'PhishGuard warning',
    message: `This site looks suspicious (risk ${(fused * 100).toFixed(0)}%). Click extension to learn more.`,
    requireInteraction: true
  });
  // Inject content script and pass fused score
  chrome.scripting.executeScript({
    target: { tabId: details.tabId },
    files: ['content_script.js']
  }).then(() => {
    chrome.tabs.sendMessage(details.tabId, { action: 'showWarningBanner', risk: fused });
  }).catch(err => {
    console.error('Script injection failed:', err);
  });
}
  } catch (e) {
    console.error('Navigation check failed:', e);
  }
});

// Message listener
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === 'getRiskForUrl') {
    try {
      const url = msg.url;
      const hscore = heuristicScore(url);
      let p = 0;
      try {
        const features = extractFeaturesFromUrl(url);
        if (features) p = predictProbability(features);
      } catch (e) {
        console.warn('Model inference failed', e);
      }
      const fused = 0.4 * hscore + 0.6 * p;
      sendResponse({ probability: p, heuristic: hscore, fused });
    } catch (err) {
      sendResponse({ error: String(err) });
    }
    return true;
  }

  if (msg.action === 'uploadReport') {
    chrome.storage.local.get(['phg_pending_uploads'], (items) => {
      const q = items.phg_pending_uploads || [];
      q.push(msg.report);
      chrome.storage.local.set({ phg_pending_uploads: q }, () => sendResponse({ ok: true }));
    });
    return true;
  }
});
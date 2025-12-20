// popup.js
// Popup interacts with the background service worker to request a risk score for the active tab.
// It also allows opt-in reporting (stores a hashed URL) and triggers a model update message.

const currentUrlEl = document.getElementById('currentUrl');
const riskFillEl = document.getElementById('riskFill');
const riskTextEl = document.getElementById('riskText');
const explainEl = document.getElementById('explain');
const reportBtn = document.getElementById('reportBtn');
const updateModelBtn = document.getElementById('updateModel');
const optInCheckbox = document.getElementById('optInReporting');
const modelDateEl = document.getElementById('modelDate');
const openDashboardBtn = document.getElementById('openDashboard');

let currentTabUrl = null;
let lastScore = null;

async function sha256hex(msg) {
  const enc = new TextEncoder();
  const data = enc.encode(msg);
  const hash = await crypto.subtle.digest('SHA-256', data);
  const bytes = Array.from(new Uint8Array(hash));
  return bytes.map(b => b.toString(16).padStart(2, '0')).join('');
}

function setRiskUI(score) {
  // score: 0..1
  const pct = Math.round(score * 100);
  riskFillEl.style.width = pct + '%';
  riskTextEl.textContent = `Risk: ${pct}%`;
  if (pct < 40) explainEl.textContent = 'Low risk — proceed normally.';
  else if (pct < 90) explainEl.textContent = 'Suspicious — be careful (check domain & TLS).';
  else explainEl.textContent = 'High risk — recommended block or avoid entering credentials.';
  lastScore = score;
}

function showError(msg) {
  riskTextEl.textContent = 'Error';
  explainEl.textContent = msg;
  riskFillEl.style.width = '0%';
}

async function requestRiskForTab(url) {
  // send message to background service worker and wait for response
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ action: 'getRiskForUrl', url }, (resp) => {
      if (chrome.runtime.lastError) {
        return reject(chrome.runtime.lastError.message);
      }
      resolve(resp);
    });
  });
}

async function init() {
  // load stored opt-in
  chrome.storage.local.get(['phg_opt_in', 'model_meta'], (items) => {
    optInCheckbox.checked = !!items.phg_opt_in;
    if (items.model_meta && items.model_meta.updated_at) {
      modelDateEl.textContent = items.model_meta.updated_at;
    } else {
      modelDateEl.textContent = 'local';
    }
  });

  // get current active tab url
  try {
    const [tab] = await new Promise((res) => chrome.tabs.query({ active: true, currentWindow: true }, res));
    if (tab && tab.url) {
      currentTabUrl = tab.url;
      currentUrlEl.textContent = currentTabUrl;
      // ask background for risk
      const resp = await requestRiskForTab(currentTabUrl);
      if (!resp) throw new Error('No response from background');
      if (resp.error) throw new Error(resp.error);
      // resp should have {probability:0..1, heuristic:0..1, fused:0..1}
      const fused = resp.fused ?? resp.probability ?? 0;
      setRiskUI(fused);
    } else {
      currentUrlEl.textContent = 'Unable to get current tab URL';
      showError('No URL');
    }
  } catch (e) {
    currentUrlEl.textContent = 'Error getting tab';
    showError(String(e));
  }
}

// Report button: store hashed url (anonymous) and optionally send to background for upload




init();

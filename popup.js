// popup.js
const currentUrlEl = document.getElementById('currentUrl');
const riskNeedle = document.getElementById('riskNeedle');
const riskValueEl = document.getElementById('riskValue');
const statusBadge = document.getElementById('statusBadge');
const featureFlagsEl = document.getElementById('featureFlags');
const dashboardBtn = document.getElementById('openDashboard');
const safeModeBtn = document.getElementById('toggleSafeMode');

let safeModeActive = false;

function updateUI(data) {
  const fused = data.fused || 0;
  const pct = Math.round(fused * 100);

  // Update Needle (rotate from -135deg to +45deg)
  const rotation = -135 + (fused * 180);
  riskNeedle.style.transform = `rotate(${rotation}deg)`;
  riskValueEl.textContent = `${pct}%`;

  // Update Status Badge
  if (pct < 30) {
    statusBadge.textContent = "Safe";
    statusBadge.className = "status-badge status-safe";
    riskNeedle.style.borderColor = "#10b981";
  } else if (pct < 75) {
    statusBadge.textContent = "Suspicious";
    statusBadge.className = "status-badge status-warn";
    riskNeedle.style.borderColor = "#f59e0b";
  } else {
    statusBadge.textContent = "DANGER";
    statusBadge.className = "status-badge status-danger";
    riskNeedle.style.borderColor = "#ef4444";
  }

  // Update Feature Flags
  featureFlagsEl.innerHTML = '';

  const addFlag = (text, isDanger) => {
    const div = document.createElement('div');
    div.className = 'feature-item';
    div.innerHTML = `<span class="f-icon" style="background:${isDanger ? '#ef4444' : '#10b981'}"></span> ${text}`;
    featureFlagsEl.appendChild(div);
  };

  if (data.features) {
    if (data.features.is_tunnel) addFlag("Encrypted Tunnel Detected (Ngrok/CF)", true);
    if (data.features.is_homograph) addFlag("Visual Homograph (IDN) Detected", true);
    if (data.features.suspicious_tld) addFlag("High-Risk TLD (Reputation Low)", true);
    if (data.features.subdomain_count > 2) addFlag("Deep Subdomain Nesting", true);
    if (data.features.entropy > 4.5) addFlag("High Character Entropy", true);
  }
}

async function init() {
  // Load Safe Mode State
  chrome.storage.local.get(['safeMode'], (res) => {
    safeModeActive = !!res.safeMode;
    updateSafeModeUI();
  });

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url) {
      currentUrlEl.textContent = new URL(tab.url).hostname;

      chrome.runtime.sendMessage({ action: 'getRiskForUrl', url: tab.url }, (resp) => {
        if (resp && !resp.error) {
          updateUI(resp);
        }
      });
    }
  } catch (e) {
    currentUrlEl.textContent = "Error loading tab data";
  }
}

function updateSafeModeUI() {
  safeModeBtn.textContent = `Safe Mode: ${safeModeActive ? 'ON' : 'OFF'}`;
  safeModeBtn.style.background = safeModeActive ? 'rgba(99, 102, 241, 0.3)' : 'rgba(255,255,255,0.1)';
}

safeModeBtn.addEventListener('click', () => {
  safeModeActive = !safeModeActive;
  chrome.storage.local.set({ safeMode: safeModeActive });
  updateSafeModeUI();
  // Notify background to re-check current tab
  chrome.runtime.sendMessage({ action: 'toggleSafeMode', active: safeModeActive });
});

dashboardBtn.addEventListener('click', () => {
  chrome.tabs.create({ url: 'dashboard.html' });
});

init();

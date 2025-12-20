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

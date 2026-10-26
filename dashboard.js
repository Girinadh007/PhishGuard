// dashboard.js - PhishGuard Activity Logs & Category Telemetry
const totalScannedEl = document.getElementById('totalScanned');
const totalBlockedEl = document.getElementById('totalBlocked');
const suspiciousSitesEl = document.getElementById('suspiciousSites');
const fakeLoginsEl = document.getElementById('fakeLogins');
const logTable = document.getElementById('logTable');
const emptyState = document.getElementById('emptyState');
const emptyStateTitle = document.getElementById('emptyStateTitle');
const emptyStateDesc = document.getElementById('emptyStateDesc');
const emptyStateIcon = document.getElementById('emptyStateIcon');
const tableCategoryTitle = document.getElementById('tableCategoryTitle');
const tableCategorySubtitle = document.getElementById('tableCategorySubtitle');
const logSearchInput = document.getElementById('logSearchInput');
const logFilterStatus = document.getElementById('logFilterStatus');

let currentLogs = [];
let activeCategory = 'all';
let searchQuery = '';

const CATEGORY_META = {
    all: {
        title: 'All Sites Scanned',
        subtitle: 'Complete real-time inspection log of all websites visited',
        emptyIcon: '🌐',
        emptyTitle: 'No sites scanned yet',
        emptyDesc: 'Browse the web and PhishGuard will evaluate pages in real time using on-device ML and allowlist rules.'
    },
    threats: {
        title: 'Threats Prevented',
        subtitle: 'High-risk phishing attacks, tunnels, and malicious portals blocked by PhishGuard',
        emptyIcon: '🛡️',
        emptyTitle: 'No threats prevented yet',
        emptyDesc: 'Great news! No malicious phishing sites or blocked threats have been encountered in your browsing session.'
    },
    suspicious: {
        title: 'Suspicious Sites Checked',
        subtitle: 'Websites with elevated risk or anomalous structures placed under Safe Mode surveillance',
        emptyIcon: '⚠️',
        emptyTitle: 'No suspicious sites checked',
        emptyDesc: 'No websites with anomalous structures or elevated risk scores were detected.'
    },
    fake_logins: {
        title: 'Fake Login Pages Stopped',
        subtitle: 'Credential-harvesting interfaces, brand impersonation portals, and insecure login forms stopped',
        emptyIcon: '🚫',
        emptyTitle: 'No fake login pages detected',
        emptyDesc: 'No brand spoofing or credential exfiltration attempts found. PhishGuard continuously inspects form targets and brand signatures.'
    }
};

function getLogCategories(log) {
    const cats = ['all'];
    const risk = typeof log.risk === 'number' ? log.risk : 0;
    const flagsStr = (log.flags || '').toLowerCase();
    const urlStr = (log.url || log.domain || '').toLowerCase();
    const action = (log.action || '').toLowerCase();

    // 1. Fake Login Pages Stopped
    const hasFakeLoginFlag = flagsStr.includes('fake-login') ||
        flagsStr.includes('brand-impersonation') ||
        flagsStr.includes('exfiltration-endpoint') ||
        flagsStr.includes('insecure-password') ||
        flagsStr.includes('cross-domain-form') ||
        flagsStr.includes('orphan-password');

    const hasLoginKeyword = /(login|signin|sign-in|log-in|account|password|auth|verify|secure|credential|banking|wallet)/i.test(urlStr);
    const isFakeLogin = log.category === 'fake_login' ||
        hasFakeLoginFlag ||
        (hasLoginKeyword && risk >= 0.65) ||
        (flagsStr.includes('login-target') && risk >= 0.50);

    if (isFakeLogin) {
        cats.push('fake_logins');
    }

    // 2. Threats Prevented
    const isThreat = log.category === 'threat' ||
        risk >= 0.80 ||
        action === 'blocked' ||
        flagsStr.includes('tunnel') ||
        flagsStr.includes('suspicious-domain-age') ||
        isFakeLogin && (risk >= 0.80 || action === 'blocked');

    if (isThreat) {
        cats.push('threats');
    }

    // 3. Suspicious Sites Checked
    const isSuspicious = log.category === 'suspicious' ||
        action === 'safe_mode' ||
        (risk >= 0.30 && risk < 0.80);

    if (isSuspicious && !isThreat) {
        cats.push('suspicious');
    }

    // Safe (scanned legitimate)
    if (!isThreat && !isSuspicious && !isFakeLogin) {
        cats.push('safe');
    }

    return cats;
}

function getPrimaryCategoryBadge(log, cats) {
    if (cats.includes('fake_logins')) {
        return { label: '🚫 Fake Login', cls: 'badge-cat-fake-login' };
    }
    if (cats.includes('threats')) {
        return { label: '🛡️ Threat Blocked', cls: 'badge-cat-threat' };
    }
    if (cats.includes('suspicious')) {
        return { label: '⚠️ Suspicious', cls: 'badge-cat-suspicious' };
    }
    return { label: '🟢 Safe Scanned', cls: 'badge-cat-safe' };
}

function init() {
    chrome.storage.local.get(['stats', 'scanLogs'], (res) => {
        const stats = res.stats || { scanned: 0, blocked: 0 };
        const rawLogs = res.scanLogs || [];

        // Filter out internal extension pages or chrome IDs
        currentLogs = rawLogs.filter(log => {
            if (!log || !log.domain) return false;
            const d = log.domain.toLowerCase();
            if (d.includes('dashboard') || d.includes('chrome-extension') || d.includes('blocked.html') || d.includes('popup.html')) return false;
            if (/^[a-z]{32}$/.test(d)) return false;
            return true;
        });

        // Clean up stale entries from storage if filtered
        if (currentLogs.length !== rawLogs.length) {
            chrome.storage.local.set({ scanLogs: currentLogs });
        }

        // Compute counts per category
        let threatCount = 0;
        let suspiciousCount = 0;
        let fakeLoginCount = 0;

        currentLogs.forEach(log => {
            const cats = getLogCategories(log);
            if (cats.includes('threats')) threatCount++;
            if (cats.includes('suspicious')) suspiciousCount++;
            if (cats.includes('fake_logins')) fakeLoginCount++;
        });

        // Update Stat Cards (use highest of storage counter or actual logs)
        const scannedDisplay = Math.max(stats.scanned || 0, currentLogs.length);
        const blockedDisplay = Math.max(stats.blocked || 0, threatCount);

        totalScannedEl.textContent = scannedDisplay.toLocaleString();
        totalBlockedEl.textContent = blockedDisplay.toLocaleString();
        suspiciousSitesEl.textContent = suspiciousCount.toLocaleString();
        fakeLoginsEl.textContent = fakeLoginCount.toLocaleString();

        // Update Tab Pill Counts
        document.getElementById('pillAll').textContent = currentLogs.length.toLocaleString();
        document.getElementById('pillThreats').textContent = threatCount.toLocaleString();
        document.getElementById('pillSuspicious').textContent = suspiciousCount.toLocaleString();
        document.getElementById('pillFakeLogins').textContent = fakeLoginCount.toLocaleString();

        renderLogs();
    });

    fetchModelStatus();
    setupEventListeners();
}

function renderLogs() {
    logTable.innerHTML = '';

    const meta = CATEGORY_META[activeCategory] || CATEGORY_META.all;
    tableCategoryTitle.textContent = meta.title;

    // Filter by active category
    let filtered = currentLogs.filter(log => {
        const cats = getLogCategories(log);
        return cats.includes(activeCategory);
    });

    const categoryTotalCount = filtered.length;

    // Filter by search query if any
    if (searchQuery) {
        const q = searchQuery.toLowerCase();
        filtered = filtered.filter(log => {
            const d = (log.domain || '').toLowerCase();
            const u = (log.url || '').toLowerCase();
            const f = (log.flags || '').toLowerCase();
            const a = (log.action || '').toLowerCase();
            const r = (log.reason || '').toLowerCase();
            return d.includes(q) || u.includes(q) || f.includes(q) || a.includes(q) || r.includes(q);
        });
    }

    // Update Subtitle & Filter Status
    if (searchQuery) {
        tableCategorySubtitle.textContent = `Showing ${filtered.length} of ${categoryTotalCount} logs matching "${searchQuery}" in ${meta.title}`;
        logFilterStatus.textContent = `${filtered.length} results`;
    } else {
        tableCategorySubtitle.textContent = `${meta.subtitle} (${categoryTotalCount} total)`;
        logFilterStatus.textContent = `${filtered.length} entries`;
    }

    if (filtered.length === 0) {
        emptyState.style.display = 'block';
        emptyStateIcon.textContent = searchQuery ? '🔍' : meta.emptyIcon;
        emptyStateTitle.textContent = searchQuery ? 'No matching logs' : meta.emptyTitle;
        emptyStateDesc.textContent = searchQuery
            ? `No records found matching "${searchQuery}". Try a different domain or clear the search.`
            : meta.emptyDesc;
        return;
    }

    emptyState.style.display = 'none';

    // Populate rows (newest first)
    filtered.slice().reverse().forEach(log => {
        const tr = document.createElement('tr');
        const cats = getLogCategories(log);
        const badge = getPrimaryCategoryBadge(log, cats);

        const dateObj = new Date(log.ts || Date.now());
        const timeStr = dateObj.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        const dateStr = dateObj.toLocaleDateString([], { month: 'short', day: 'numeric' });
        const timeAgo = formatTimeAgo(log.ts);

        const risk = typeof log.risk === 'number' ? log.risk : 0;
        const pct = Math.round(risk * 100);

        let riskClass = "risk-low";
        let riskText = `${pct}% Safe`;
        let riskColor = "var(--success)";

        if (risk >= 0.85) {
            riskClass = "risk-high";
            riskText = `${pct}% Malicious`;
            riskColor = "var(--danger)";
        } else if (risk >= 0.70) {
            riskClass = "risk-high";
            riskText = `${pct}% High Risk`;
            riskColor = "#f87171";
        } else if (risk >= 0.30) {
            riskClass = "";
            riskText = `${pct}% Suspicious`;
            riskColor = "var(--warning)";
        }

        // Flags HTML formatting
        let flagHtml = '';
        if (log.flags && log.flags.trim()) {
            flagHtml = log.flags.split(',').map(f => {
                const trimmed = f.trim();
                if (!trimmed) return '';
                const isHighRisk = trimmed === 'Brand-Impersonation' || trimmed === 'Exfiltration-Endpoint' || trimmed === 'Tunnel' || trimmed === 'Fake-Login';
                const isAllowlist = trimmed === 'Allowlist-Verified';
                const bg = isHighRisk ? 'rgba(239, 68, 68, 0.2)' : (isAllowlist ? 'rgba(16, 185, 129, 0.2)' : 'rgba(99, 102, 241, 0.2)');
                const color = isHighRisk ? '#fca5a5' : (isAllowlist ? '#6ee7b7' : '#c7d2fe');
                return `<span style="display: inline-block; padding: 2px 7px; margin: 1px; border-radius: 4px; background: ${bg}; color: ${color}; font-size: 0.72rem; font-weight: 500;">${trimmed}</span>`;
            }).filter(Boolean).join(' ');
        } else if (log.reason && log.reason.toLowerCase().includes('allowlist')) {
            flagHtml = '<span style="display: inline-block; padding: 2px 7px; margin: 1px; border-radius: 4px; background: rgba(16, 185, 129, 0.2); color: #6ee7b7; font-size: 0.72rem; font-weight: 500;">Allowlist-Verified</span>';
        } else {
            flagHtml = '<span style="color: var(--text-dim); font-size: 0.75rem;">Clean Heuristics</span>';
        }

        // Action styling
        let actionHtml = '<span style="color: var(--success); font-weight: 600;">🟢 Allowed</span>';
        if (log.action === 'blocked' || risk >= 0.80) {
            actionHtml = '<span style="color: var(--danger); font-weight: 700;">🔴 Blocked</span>';
        } else if (log.action === 'safe_mode' || (risk >= 0.70)) {
            actionHtml = '<span style="color: var(--warning); font-weight: 600;">⚠️ Safe Mode</span>';
        }

        const urlDisplay = log.url && log.url !== log.domain
            ? `<div style="font-size: 0.75rem; color: var(--text-dim); max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(log.url)}">${escapeHtml(log.url)}</div>`
            : '';

        tr.innerHTML = `
            <td>
                <div style="font-weight: 600; font-size: 0.85rem;">${dateStr}, ${timeStr}</div>
                <div style="font-size: 0.72rem; color: var(--text-dim);">${timeAgo}</div>
            </td>
            <td>
                <div style="font-family: monospace; font-weight: 600; color: var(--text-main); font-size: 0.88rem;">${escapeHtml(log.domain)}</div>
                ${urlDisplay}
            </td>
            <td>
                <span class="badge-cat ${badge.cls}">${badge.label}</span>
            </td>
            <td>
                <div style="font-weight: 700; color: ${riskColor}; font-size: 0.88rem;">${riskText}</div>
                <div style="width: 100%; height: 4px; background: rgba(255,255,255,0.08); border-radius: 2px; margin-top: 4px; overflow: hidden;">
                    <div style="width: ${pct}%; height: 100%; background: ${riskColor};"></div>
                </div>
            </td>
            <td>
                <div>${flagHtml}</div>
                ${log.reason ? `<div style="font-size: 0.7rem; color: var(--text-dim); margin-top: 3px;" title="${escapeHtml(log.reason)}">${escapeHtml(log.reason)}</div>` : ''}
            </td>
            <td>${actionHtml}</td>
        `;
        logTable.appendChild(tr);
    });
}

function formatTimeAgo(ts) {
    if (!ts) return 'recently';
    const diff = Math.max(0, Date.now() - ts);
    const sec = Math.floor(diff / 1000);
    if (sec < 60) return 'Just now';
    const min = Math.floor(sec / 60);
    if (min < 60) return `${min}m ago`;
    const hrs = Math.floor(min / 60);
    if (hrs < 24) return `${hrs}h ago`;
    const days = Math.floor(hrs / 24);
    return `${days}d ago`;
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function setActiveCategory(cat) {
    activeCategory = cat;

    // Update Tab Buttons
    document.querySelectorAll('.cat-tab-btn').forEach(btn => {
        if (btn.getAttribute('data-category') === cat) {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
    });

    // Update Stat Cards active state
    document.querySelectorAll('.stat-card-clickable').forEach(card => {
        if (card.getAttribute('data-category') === cat) {
            card.classList.add('active');
        } else {
            card.classList.remove('active');
        }
    });

    renderLogs();
}

function setupEventListeners() {
    // Tab Button clicks
    document.querySelectorAll('.cat-tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const cat = btn.getAttribute('data-category');
            if (cat) setActiveCategory(cat);
        });
    });

    // Stat Card clicks
    document.querySelectorAll('.stat-card-clickable').forEach(card => {
        card.addEventListener('click', () => {
            const cat = card.getAttribute('data-category');
            if (cat) {
                setActiveCategory(cat);
                const logsSection = document.getElementById('logsSection');
                if (logsSection) {
                    logsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }
            }
        });
    });

    // Search input
    if (logSearchInput) {
        logSearchInput.addEventListener('input', (e) => {
            searchQuery = (e.target.value || '').trim();
            renderLogs();
        });
    }

    // Export CSV
    const exportCsvBtn = document.getElementById('exportCsvBtn');
    if (exportCsvBtn) {
        exportCsvBtn.addEventListener('click', exportLogsAsCsv);
    }

    // Export JSON
    const exportJsonBtn = document.getElementById('exportJsonBtn');
    if (exportJsonBtn) {
        exportJsonBtn.addEventListener('click', exportLogsAsJson);
    }

    // Clear Logs
    const clearLogsBtn = document.getElementById('clearLogsBtn');
    if (clearLogsBtn) {
        clearLogsBtn.addEventListener('click', () => {
            if (confirm('Are you sure you want to clear your local scan activity logs? Counters will reset to 0.')) {
                chrome.storage.local.set({
                    scanLogs: [],
                    stats: { scanned: 0, blocked: 0, totalRisk: 0, falsePositives: 0, falseNegatives: 0 }
                }, () => {
                    init();
                });
            }
        });
    }
}

function getExportableData() {
    return currentLogs.filter(log => {
        const cats = getLogCategories(log);
        return cats.includes(activeCategory);
    });
}

function exportLogsAsCsv() {
    const list = getExportableData();
    if (list.length === 0) {
        alert('No logs available to export in this category.');
        return;
    }

    const headers = ['Timestamp', 'ISO Date', 'Domain', 'URL', 'Risk Score', 'Category', 'Action', 'Flags', 'Reason'];
    const rows = list.map(l => {
        const cats = getLogCategories(l);
        const badge = getPrimaryCategoryBadge(l, cats);
        const iso = new Date(l.ts || Date.now()).toISOString();
        return [
            l.ts || '',
            iso,
            `"${(l.domain || '').replace(/"/g, '""')}"`,
            `"${(l.url || '').replace(/"/g, '""')}"`,
            l.risk !== undefined ? l.risk : '',
            `"${badge.label.replace(/"/g, '""')}"`,
            `"${(l.action || '').replace(/"/g, '""')}"`,
            `"${(l.flags || '').replace(/"/g, '""')}"`,
            `"${(l.reason || '').replace(/"/g, '""')}"`
        ].join(',');
    });

    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `phishguard_${activeCategory}_logs_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

function exportLogsAsJson() {
    const list = getExportableData();
    if (list.length === 0) {
        alert('No logs available to export in this category.');
        return;
    }

    const enriched = list.map(l => {
        const cats = getLogCategories(l);
        const badge = getPrimaryCategoryBadge(l, cats);
        return {
            ...l,
            categoryLabel: badge.label,
            categories: cats,
            dateTime: new Date(l.ts || Date.now()).toISOString()
        };
    });

    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(enriched, null, 2));
    const link = document.createElement('a');
    link.setAttribute('href', dataStr);
    link.setAttribute('download', `phishguard_${activeCategory}_logs_${Date.now()}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

function fetchModelStatus() {
    chrome.runtime.sendMessage({ action: 'getModelStatus' }, (res) => {
        if (!res || chrome.runtime.lastError) return;

        if (res.engine) {
            document.getElementById('engineBadge').textContent = res.engine;
        }
        if (res.version) {
            document.getElementById('modelVersionDisplay').textContent = `v${res.version}`;
        }
        if (res.treeCount) {
            document.getElementById('modelTreesDisplay').textContent = `${res.treeCount} Trees`;
        }
        if (res.totalNodes) {
            document.getElementById('modelNodesDisplay').textContent = `${res.totalNodes.toLocaleString()} Flat Nodes`;
        }
        if (res.allowlistSize) {
            const src = res.allowlistSource === 'ota' ? ' (OTA Synced)' : ' (Packaged Top 100k)';
            document.getElementById('allowlistSizeDisplay').textContent = `${res.allowlistSize.toLocaleString()} Domains${src}`;
        }
        if (res.lastOtaCheck) {
            const timeAgo = Math.round((Date.now() - res.lastOtaCheck) / 60000);
            const timeStr = timeAgo < 1 ? 'Just now' : `${timeAgo} min ago`;
            document.getElementById('lastCheckDisplay').textContent = `${new Date(res.lastOtaCheck).toLocaleDateString()} (${timeStr})`;
        }
    });
}

// Check for updates button
const checkUpdateBtn = document.getElementById('checkUpdateBtn');
const updateStatusText = document.getElementById('updateStatusText');

if (checkUpdateBtn) {
    checkUpdateBtn.addEventListener('click', () => {
        checkUpdateBtn.disabled = true;
        checkUpdateBtn.textContent = 'Checking...';
        updateStatusText.textContent = 'Contacting remote repository...';
        updateStatusText.style.color = 'var(--text-dim)';

        chrome.runtime.sendMessage({ action: 'checkForUpdates' }, (response) => {
            checkUpdateBtn.disabled = false;
            checkUpdateBtn.textContent = 'Check for Updates';

            if (chrome.runtime.lastError || !response) {
                updateStatusText.textContent = 'Failed to connect to update server.';
                updateStatusText.style.color = 'var(--danger)';
                return;
            }

            if (response.success) {
                updateStatusText.textContent = response.message;
                updateStatusText.style.color = response.updated ? 'var(--success)' : 'var(--primary)';
                fetchModelStatus();
            } else {
                updateStatusText.textContent = response.message || 'Offline fallback active.';
                updateStatusText.style.color = 'var(--warning)';
            }
        });
    });
}

init();

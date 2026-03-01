/* ============================================================
   NIDS Commander Dashboard — Application Logic
   ============================================================ */

// ── Configuration ──
const CONFIG = {
    API_BASE: window.location.origin,       // Same origin as Flask
    API_KEY: 'secure-research-demo-key-123', // X-NIDS-Auth header value
    POLL_INTERVAL: 10000,                    // 10 seconds
    ALERT_LIMIT: 50,
    LOG_LIMIT: 40,
};

// ── DOM References ──
const DOM = {
    // KPI
    kpiSensors: document.getElementById('kpi-sensors'),
    kpiAlerts: document.getElementById('kpi-alerts'),
    kpiBlocks: document.getElementById('kpi-blocks'),
    kpiTrust: document.getElementById('kpi-trust'),
    kpiTrustBar: document.getElementById('kpi-trust-bar'),

    // Connection badge
    connBadge: document.getElementById('conn-badge'),
    connIcon: document.getElementById('conn-icon'),
    connText: document.getElementById('conn-text'),

    // Tables
    alertTbody: document.getElementById('alert-tbody'),
    alertCountBadge: document.getElementById('alert-count-badge'),
    blocksTbody: document.getElementById('blocks-tbody'),
    blockCountBadge: document.getElementById('block-count-badge'),

    // Sensor grid
    sensorGrid: document.getElementById('sensor-grid'),
    sensorCountBadge: document.getElementById('sensor-count-badge'),

    // Controls
    ipInput: document.getElementById('ip-input'),
    btnUnban: document.getElementById('btn-unban'),
    btnBlock: document.getElementById('btn-block'),
    btnWhitelist: document.getElementById('btn-whitelist'),

    // Log terminal
    logTerminal: document.getElementById('log-terminal'),

    // Toast
    toastContainer: document.getElementById('toast-container'),
};

// ── State ──
let lastAlertId = 0;
let isConnected = false;

// ============================================================
//  API HELPERS
// ============================================================

async function apiFetch(endpoint, options = {}) {
    const url = `${CONFIG.API_BASE}${endpoint}`;
    try {
        const res = await fetch(url, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...options.headers,
            },
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        setConnected(true);
        return await res.json();
    } catch (err) {
        console.error(`API Error [${endpoint}]:`, err);
        setConnected(false);
        throw err;
    }
}

function apiAuthFetch(endpoint, body) {
    return apiFetch(endpoint, {
        method: 'POST',
        headers: { 'X-NIDS-Auth': CONFIG.API_KEY },
        body: JSON.stringify(body),
    });
}

// ============================================================
//  CONNECTION STATUS
// ============================================================

function setConnected(status) {
    isConnected = status;
    if (status) {
        DOM.connBadge.className = DOM.connBadge.className.replace('disconnected', '').trim() + ' connected';
        DOM.connIcon.textContent = 'wifi';
        DOM.connIcon.className = 'material-symbols-outlined text-xs text-emerald-400';
        DOM.connText.textContent = 'CONNECTED';
        DOM.connText.className = 'text-xs font-mono text-emerald-400';
    } else {
        DOM.connBadge.className = DOM.connBadge.className.replace('connected', '').trim() + ' disconnected';
        DOM.connIcon.textContent = 'wifi_off';
        DOM.connIcon.className = 'material-symbols-outlined text-xs text-red-400';
        DOM.connText.textContent = 'DISCONNECTED';
        DOM.connText.className = 'text-xs font-mono text-red-400';
    }
}

// ============================================================
//  DATA FETCHERS
// ============================================================

async function fetchStatus() {
    try {
        const data = await apiFetch('/api/status');
        animateNumber(DOM.kpiSensors, data.active_sensors || 0);
        animateNumber(DOM.kpiAlerts, data.total_alerts || 0);
        animateNumber(DOM.kpiBlocks, data.active_blocks || 0);
    } catch { /* silently retry next poll */ }
}

async function fetchAlerts() {
    try {
        const alerts = await apiFetch(`/api/alerts?limit=${CONFIG.ALERT_LIMIT}`);
        DOM.alertCountBadge.textContent = `${alerts.length} alerts`;
        renderAlerts(alerts);
    } catch { /* silently retry */ }
}

async function fetchNodes() {
    try {
        const nodes = await apiFetch('/api/nodes');
        DOM.sensorCountBadge.textContent = `${nodes.length} nodes`;
        renderSensors(nodes);
    } catch { /* silently retry */ }
}

async function fetchTrust() {
    try {
        const data = await apiFetch('/trust');
        const scores = Object.values(data);
        if (scores.length > 0) {
            const avg = scores.reduce((a, b) => a + b, 0) / scores.length;
            DOM.kpiTrust.textContent = avg.toFixed(1);
            DOM.kpiTrustBar.style.width = `${avg}%`;
        } else {
            DOM.kpiTrust.textContent = 'N/A';
            DOM.kpiTrustBar.style.width = '0%';
        }
    } catch { /* silently retry */ }
}

async function fetchBlocks() {
    try {
        const blocks = await apiFetch('/api/blocks');
        DOM.blockCountBadge.textContent = `${blocks.length} IPs`;
        renderBlocks(blocks);
    } catch { /* silently retry */ }
}

async function fetchLogs() {
    try {
        const logs = await apiFetch(`/api/logs?limit=${CONFIG.LOG_LIMIT}`);
        renderLogs(logs);
    } catch { /* silently retry */ }
}

// ============================================================
//  RENDERERS
// ============================================================

function renderAlerts(alerts) {
    if (alerts.length === 0) {
        DOM.alertTbody.innerHTML = `
            <tr>
                <td colspan="5" class="px-6 py-12 text-center text-slate-500">
                    <span class="material-symbols-outlined text-3xl mb-2 block">verified_user</span>
                    No alerts — All clear
                </td>
            </tr>`;
        return;
    }

    DOM.alertTbody.innerHTML = alerts.map(a => {
        const severity = getSeverity(a.score);
        const timeStr = formatTime(a.time);
        const isNew = a.id > lastAlertId;
        return `
            <tr class="hover:bg-white/5 ${isNew ? 'alert-row-new' : ''}">
                <td class="px-6 py-4 font-mono text-xs">${timeStr}</td>
                <td class="px-6 py-4 font-mono text-blue-300">${escapeHtml(a.ip)}</td>
                <td class="px-6 py-4 text-slate-300">${escapeHtml(a.sensor || '—')}</td>
                <td class="px-6 py-4 text-right font-mono">${a.score.toFixed(1)}</td>
                <td class="px-6 py-4 text-right">
                    <span class="px-2 py-0.5 rounded text-xs font-bold ${severity.class} ${severity.bg}">
                        ${severity.label}
                    </span>
                </td>
            </tr>`;
    }).join('');

    if (alerts.length > 0) {
        lastAlertId = Math.max(...alerts.map(a => a.id));
    }
}

function renderSensors(nodes) {
    if (nodes.length === 0) {
        DOM.sensorGrid.innerHTML = `
            <div class="glass rounded-xl p-4 text-center text-slate-500 col-span-2">
                <span class="material-symbols-outlined text-3xl mb-2 block">sensors_off</span>
                No sensors registered
            </div>`;
        return;
    }

    DOM.sensorGrid.innerHTML = nodes.map(n => {
        const statusColor = getStatusColor(n.status);
        const lastSeenStr = n.last_seen ? relativeTime(n.last_seen) : 'Never';
        const trustColor = n.trust >= 70 ? 'text-emerald-400' : n.trust >= 40 ? 'text-amber-400' : 'text-red-400';
        return `
            <div class="glass sensor-card rounded-xl p-4">
                <div class="flex justify-between items-start">
                    <span class="material-symbols-outlined text-slate-400">router</span>
                    <span class="w-2.5 h-2.5 rounded-full ${statusColor.bg} ${statusColor.glow}"></span>
                </div>
                <p class="font-bold mt-2 text-sm truncate" title="${escapeHtml(n.id)}">${escapeHtml(n.id)}</p>
                <p class="text-xs font-mono text-slate-400 mt-1">HB: ${lastSeenStr}</p>
                <div class="flex justify-between items-center mt-2">
                    <span class="text-xs text-slate-500">${escapeHtml(n.ip || '—')}</span>
                    <span class="text-xs font-bold ${trustColor}">${n.trust.toFixed(0)}%</span>
                </div>
                <div class="mt-2 h-1 bg-slate-700 rounded-full overflow-hidden">
                    <div class="h-full rounded-full transition-all duration-500 ${trustColor.includes('emerald') ? 'bg-emerald-500' : trustColor.includes('amber') ? 'bg-amber-500' : 'bg-red-500'}"
                         style="width: ${n.trust}%"></div>
                </div>
            </div>`;
    }).join('');
}

function renderBlocks(blocks) {
    if (blocks.length === 0) {
        DOM.blocksTbody.innerHTML = `
            <tr>
                <td colspan="5" class="px-6 py-8 text-center text-slate-500">
                    <span class="material-symbols-outlined text-3xl mb-2 block">shield</span>
                    No active blocks
                </td>
            </tr>`;
        return;
    }

    DOM.blocksTbody.innerHTML = blocks.map(b => {
        const blockedAt = formatTime(b.blocked_at);
        const expiresAt = b.expires_at ? formatTime(b.expires_at) : 'Permanent';
        return `
            <tr class="hover:bg-white/5">
                <td class="px-6 py-4 font-mono text-blue-300">${escapeHtml(b.ip)}</td>
                <td class="px-6 py-4 text-slate-300 text-xs">${escapeHtml(b.reason || '—')}</td>
                <td class="px-6 py-4 font-mono text-xs">${blockedAt}</td>
                <td class="px-6 py-4 font-mono text-xs">${expiresAt}</td>
                <td class="px-6 py-4 text-right">
                    <button onclick="doUnban('${escapeHtml(b.ip)}')"
                        class="text-xs px-3 py-1 rounded bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 hover:bg-indigo-600/30 transition-colors">
                        Unban
                    </button>
                </td>
            </tr>`;
    }).join('');
}

function renderLogs(logs) {
    if (!logs || logs.length === 0) {
        DOM.logTerminal.innerHTML = `<div><span class="text-slate-500">&gt;_</span> <span class="text-indigo-400">No log entries yet…</span></div>`;
        return;
    }

    DOM.logTerminal.innerHTML = logs.map(line => {
        const colorized = colorizeLog(line);
        return `<div class="leading-relaxed">${colorized}</div>`;
    }).join('');

    // Auto-scroll to bottom
    DOM.logTerminal.scrollTop = DOM.logTerminal.scrollHeight;
}

// ============================================================
//  ACTIONS
// ============================================================

function getIPInput() {
    const ip = DOM.ipInput.value.trim();
    if (!ip) {
        showToast('Please enter an IP address', 'error');
        DOM.ipInput.focus();
        return null;
    }
    return ip;
}

async function doUnban(ip) {
    if (!ip) ip = getIPInput();
    if (!ip) return;

    try {
        const res = await apiAuthFetch('/api/action/unban', { ip });
        showToast(`Unbanned ${res.ip}`, 'success');
        DOM.ipInput.value = '';
        refreshAll();
    } catch (err) {
        showToast(`Failed to unban: ${err.message}`, 'error');
    }
}

async function doBlock() {
    const ip = getIPInput();
    if (!ip) return;

    try {
        const res = await apiAuthFetch('/api/action/block', { ip });
        showToast(`Blocked ${res.ip}`, 'success');
        DOM.ipInput.value = '';
        refreshAll();
    } catch (err) {
        showToast(`Failed to block: ${err.message}`, 'error');
    }
}

async function doWhitelist() {
    const ip = getIPInput();
    if (!ip) return;

    try {
        const res = await apiAuthFetch('/api/action/whitelist', { ip });
        showToast(`Whitelisted ${res.ip}`, 'success');
        DOM.ipInput.value = '';
        refreshAll();
    } catch (err) {
        showToast(`Failed to whitelist: ${err.message}`, 'error');
    }
}

// ============================================================
//  UTILITY FUNCTIONS
// ============================================================

function getSeverity(score) {
    if (score >= 70) return { label: 'HIGH', class: 'text-red-400', bg: 'bg-red-500/10 border border-red-500/20' };
    if (score >= 35) return { label: 'MEDIUM', class: 'text-amber-400', bg: 'bg-amber-500/10 border border-amber-500/20' };
    return { label: 'LOW', class: 'text-emerald-400', bg: 'bg-emerald-500/10 border border-emerald-500/20' };
}

function getStatusColor(status) {
    if (status === 'online') return { bg: 'bg-emerald-500', glow: 'neon-dot' };
    if (status === 'degraded') return { bg: 'bg-amber-500', glow: 'neon-dot-amber' };
    return { bg: 'bg-slate-500', glow: '' };
}

function formatTime(isoStr) {
    if (!isoStr) return '—';
    const d = new Date(isoStr);
    if (isNaN(d.getTime())) return isoStr;
    return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function relativeTime(isoStr) {
    if (!isoStr) return 'Never';
    const d = new Date(isoStr);
    const diff = Math.floor((Date.now() - d.getTime()) / 1000);
    if (diff < 0) return 'Just now';
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
}

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function animateNumber(el, target) {
    const current = parseInt(el.textContent) || 0;
    if (current === target) return;

    const duration = 600;
    const start = performance.now();

    function step(timestamp) {
        const progress = Math.min((timestamp - start) / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
        el.textContent = Math.round(current + (target - current) * eased);
        if (progress < 1) requestAnimationFrame(step);
    }

    requestAnimationFrame(step);
}

function colorizeLog(line) {
    let color = 'text-slate-300';
    let tag = '';

    if (line.includes('[CRIT]') || line.includes('[BLOCK]') || line.includes('BLOCKING')) {
        color = 'text-red-400';
        tag = '<span class="text-red-400">[CRIT]</span>';
    } else if (line.includes('[WARN]') || line.includes('[VERIFY]')) {
        color = 'text-amber-400';
        tag = '<span class="text-amber-400">[WARN]</span>';
    } else if (line.includes('[INFO]')) {
        color = 'text-green-400';
        tag = '<span class="text-green-400">[INFO]</span>';
    } else if (line.includes('[ADMIN]')) {
        color = 'text-indigo-400';
        tag = '<span class="text-indigo-400">[ADMIN]</span>';
    } else if (line.includes('[TRUST]')) {
        color = 'text-cyan-400';
        tag = '<span class="text-cyan-400">[TRUST]</span>';
    }

    // Extract timestamp if present (format: 2026-03-01 10:42:05,123)
    const tsMatch = line.match(/^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})/);
    if (tsMatch) {
        const ts = tsMatch[1].split(' ')[1]; // just HH:MM:SS
        const rest = line.substring(tsMatch[0].length);
        return `<span class="text-slate-500">${ts}</span> <span class="${color}">${escapeHtml(rest)}</span>`;
    }

    return `<span class="${color}">${escapeHtml(line)}</span>`;
}

// ============================================================
//  TOAST NOTIFICATIONS
// ============================================================

function showToast(message, type = 'info') {
    const icons = {
        success: 'check_circle',
        error: 'error',
        info: 'info',
    };

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
        <span class="material-symbols-outlined text-lg">${icons[type] || icons.info}</span>
        <span>${escapeHtml(message)}</span>
    `;

    DOM.toastContainer.appendChild(toast);

    // Remove after animation completes
    setTimeout(() => {
        if (toast.parentNode) toast.parentNode.removeChild(toast);
    }, 3500);
}

// ============================================================
//  POLLING & INIT
// ============================================================

async function refreshAll() {
    await Promise.allSettled([
        fetchStatus(),
        fetchAlerts(),
        fetchNodes(),
        fetchTrust(),
        fetchBlocks(),
        fetchLogs(),
    ]);
}

function startPolling() {
    refreshAll();
    setInterval(refreshAll, CONFIG.POLL_INTERVAL);
}

// ── Event Listeners ──
DOM.btnUnban.addEventListener('click', () => doUnban());
DOM.btnBlock.addEventListener('click', doBlock);
DOM.btnWhitelist.addEventListener('click', doWhitelist);

// Allow Enter key in IP input
DOM.ipInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') doUnban();
});

// ── Boot ──
document.addEventListener('DOMContentLoaded', startPolling);

// If DOM already loaded (script at bottom of body)
if (document.readyState !== 'loading') {
    startPolling();
}

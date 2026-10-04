/**
 * GuardNet — Network Security Suite
 * Main Application Controller v2.6
 */

import ApiClient from './api.js';

// ─── State ───────────────────────────────────────────────────────────────────
let currentTab       = 'dashboard';
let activeScanId     = null;
let activeScanTimer  = null;
let charts           = {};
let detectedSubnet   = null;  
let dashboardDevices = []; // Track devices locally for topology mapping
let activeCategories = null;
const CATEGORY_COLORS = {
    'Router':               '#06b6d4',
    'Router / Gateway':     '#818cf8',
    'Desktop':              '#6366f1',
    'Laptop':               '#34d399',
    'Server':               '#fbbf24',
    'Storage Server':       '#f87171',
    'NAS':                  '#ec4899',
    'Smartphone':           '#a78bfa',
    'Tablet':               '#38bdf8',
    'Printer':              '#22d3ee',
    'Smart TV':             '#fb923c',
    'Streaming Device':     '#f59e0b',
    'Gaming Console':       '#4ade80',
    'IP Camera':            '#0e7490',
    'CCTV Camera':          '#e879f9',
    'IoT Device':           '#ec4899',
    'Network Infrastructure': '#94a3b8',
    'Unknown Device':       '#64748b'
};

const DEVICE_MAP_ICONS = {
    'Router':         '\uf6ff',
    'Desktop':        '\uf108',
    'Laptop':         '\uf109',
    'Server':         '\uf233',
    'Storage Server': '\uf0a0',
    'Smartphone':     '\uf3cd',
    'Printer':        '\uf02f',
    'Smart TV':       '\uf26c',
    'Gaming Console': '\uf11b',
    'CCTV Camera':    '\uf03d',
    'IoT Device':     '\uf2db',
    'Unknown Device': '\uf059'
};

// ─── DOM Refs ────────────────────────────────────────────────────────────────
const $ = (id) => document.getElementById(id);

// Sidebar / Nav
const sidebar        = $('sidebar');
const sidebarOverlay = $('sidebar-overlay');
const menuToggle     = $('menu-toggle');

// Topbar
const tabTitle       = $('tab-title');
const tabSubtitle    = $('tab-subtitle');
const headerIp       = $('header-ip');
const headerSubnet   = $('header-subnet');
const adminText      = $('admin-text');
const adminIcon      = $('admin-icon');
const themeBtn       = $('theme-btn');
const statusDot      = $('hb-dot');
const backendStatus  = $('backend-status');

// Dashboard
const gaugeCircle    = $('gauge-circle');
const gaugeScore     = $('gauge-score');
const gaugeLabel     = $('gauge-label');
const dashboardEmpty = $('dashboard-empty');

// Scanner
const scanForm       = $('scan-form');
const scanTarget     = $('scan-target');
const scanSimulation = $('scan-simulation');
const startScanBtn   = $('start-scan-btn');
const progressCard   = $('scan-progress-card');
const resultsCard    = $('scan-results-card');
const scanPlaceholder= $('scanner-placeholder');
const scanStateText  = $('scan-state-text');
const scanPct        = $('scan-pct');
const scanFill       = $('scan-progress-fill');
const consoleLogs    = $('console-logs');
const resultsList    = $('scan-results-list');
const resultsCount   = $('results-count');
const subnetPrompt   = $('subnet-prompt');
const suggestedText  = $('suggested-subnet-text');
const btnScanSingle  = $('btn-scan-single');
const btnExpandSubnet= $('btn-expand-subnet');
const nmapNote       = $('nmap-status-note');
const nmapNoteText   = $('nmap-status-text');
const abortScanBtn   = $('abort-scan-btn');

// Router discovery panel
const routerModel    = $('router-model');
const routerOs       = $('router-os');
const routerLan      = $('router-lan');
const routerWan      = $('router-wan');
const routerInterface= $('router-interface');
const routerDns      = $('router-dns');
const routerFirmware = $('router-firmware');
const routerUptime   = $('router-uptime');
const routerAnalyticsSec = $('router-analytics-section');
const routerDown     = $('router-down-speed');
const routerUp       = $('router-up-speed');
const routerClients  = $('router-clients');
const routerLoad     = $('router-load');

// Devices
const devicesGrid    = $('devices-grid');
const devicesEmpty   = $('devices-empty');
const devicesSearch  = $('devices-search');
const devicesType    = $('devices-type');
const devicesRisk    = $('devices-risk');
const devicesSort    = $('devices-sort');

// Alerts
const alertsList     = $('alerts-list');
const alertsFilter   = $('alerts-filter');
const alertsBadge    = $('alerts-badge');
const resolveAllBtn  = $('resolve-all-btn');

// History
const historyBody    = $('history-body');
const refreshHistBtn = $('refresh-history-btn');
const selectAllHistory = $('select-all-history');
const deleteSelectedBtn = $('delete-selected-btn');
const clearAllHistoryBtn = $('clear-all-history-btn');

// Settings
const settingsForm    = $('settings-form');
const settingsSubnet  = $('settings-subnet');
const settingsSchedule= $('settings-schedule');
const settingsEmail   = $('settings-email');
const settingsAlertNew   = $('settings-alert-new');
const settingsAlertChange= $('settings-alert-change');
const settingsSimMode    = $('settings-sim-mode');

// Settings SMTP fields
const smtpEnabled     = $('settings-smtp-enabled');
const smtpHost        = $('settings-smtp-host');
const smtpPort        = $('settings-smtp-port');
const smtpUser        = $('settings-smtp-user');
const smtpPass        = $('settings-smtp-pass');
const smtpFrom        = $('settings-smtp-from');
const smtpSecurity    = $('settings-smtp-security');
const smtpMinSeverity = $('settings-smtp-min-severity');
const btnTestSmtp     = $('btn-test-smtp');

// Modal
const deviceModal    = $('device-modal');
const modalClose     = $('modal-close');

// ─── Toasts ──────────────────────────────────────────────────────────────────
function toast(msg, type = 'info') {
    const container = $('toast-container');
    const icons     = { success: 'fa-circle-check', error: 'fa-circle-xmark', warning: 'fa-circle-exclamation', info: 'fa-circle-info' };
    const el        = document.createElement('div');
    el.className    = `toast ${type}`;
    el.innerHTML    = `<i class="fa-solid ${icons[type] || icons.info}"></i><span>${msg}</span>`;
    container.appendChild(el);
    requestAnimationFrame(() => el.classList.add('show'));
    setTimeout(() => {
        el.classList.remove('show');
        setTimeout(() => el.remove(), 350);
    }, 4500);
}

// ─── Theme ───────────────────────────────────────────────────────────────────
function initTheme() {
    const saved = localStorage.getItem('gn-theme') || 'dark';
    applyTheme(saved);
}

function applyTheme(theme) {
    document.documentElement.className = theme;
    localStorage.setItem('gn-theme', theme);
    // Use circle-half-stroke for both states — rotated 180° for light mode
    themeBtn.innerHTML = theme === 'dark'
        ? '<i class="fa-solid fa-circle-half-stroke"></i>'
        : '<i class="fa-solid fa-circle-half-stroke" style="transform:rotate(180deg);display:inline-block;"></i>';
    if (Object.keys(charts).length > 0) {
        setTimeout(rebuildCharts, 50);
    }
}

themeBtn.addEventListener('click', () => {
    const isDark = document.documentElement.classList.contains('dark');
    applyTheme(isDark ? 'light' : 'dark');
});

// ─── Mobile Sidebar ──────────────────────────────────────────────────────────
function initMobileSidebar() {
    if (window.innerWidth < 768) {
        menuToggle.style.display = 'flex';
    }
    menuToggle.addEventListener('click', () => {
        sidebar.classList.toggle('open');
        sidebarOverlay.classList.toggle('open');
    });
    sidebarOverlay.addEventListener('click', closeSidebar);
}

function closeSidebar() {
    sidebar.classList.remove('open');
    sidebarOverlay.classList.remove('open');
}

// ─── Themed Reusable Confirm Modal ───────────────────────────────────────────
function showConfirm(title, message, callback) {
    $('confirm-title').textContent = title;
    $('confirm-message').textContent = message;
    $('confirm-modal').classList.add('open');
    
    // Rebind proceed/ok action
    const okBtn = $('confirm-ok-btn');
    const newOkBtn = okBtn.cloneNode(true);
    okBtn.parentNode.replaceChild(newOkBtn, okBtn);
    newOkBtn.addEventListener('click', () => {
        $('confirm-modal').classList.remove('open');
        callback();
    });
    
    // Bind dismiss triggers
    const cancelAction = () => $('confirm-modal').classList.remove('open');
    $('confirm-cancel-btn').onclick = cancelAction;
    $('confirm-close').onclick = cancelAction;
}

// ─── Navigation ──────────────────────────────────────────────────────────────
const TAB_META = {
    dashboard: { title: 'Security Dashboard',     subtitle: 'Real-time statistics & network health overview' },
    devices:   { title: 'Devices Inventory',       subtitle: 'Full catalog of detected network hardware and devices' },
    scanner:   { title: 'Network Scanner',         subtitle: 'Scan targets, audit services, and analyze vulnerabilities' },
    alerts:    { title: 'Threat Intelligence Feed',subtitle: 'Anomalies, unauthorized devices, and insecure services' },
    history:   { title: 'Scan History',            subtitle: 'Historical log of all scan cycles in database' },
    settings:  { title: 'Platform Settings',       subtitle: 'Configure targets, schedules, and alert preferences' },
};

window.switchTab = function switchTab(tabId) {
    currentTab = tabId;

    document.querySelectorAll('.nav-btn').forEach(btn => {
        const active = btn.dataset.tab === tabId;
        btn.classList.toggle('active', active);
    });

    document.querySelectorAll('.tab-pane').forEach(pane => {
        pane.classList.toggle('active', pane.id === `tab-${tabId}`);
    });

    const meta     = TAB_META[tabId] || {};
    tabTitle.textContent    = meta.title    || tabId;
    tabSubtitle.textContent = meta.subtitle || '';

    closeSidebar();

    const loaders = {
        dashboard: loadDashboard,
        devices:   loadDevices,
        scanner:   () => { loadRouterDiscovery(); refreshDiagnosticsIfOpen(); },
        alerts:    loadAlerts,
        history:   loadHistory,
        settings:  loadSettings,
    };
    loaders[tabId]?.();
}

document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
});

// ─── Backend Health Check ─────────────────────────────────────────────────────
function setOnline(online) {
    if (statusDot) statusDot.className = online ? 'hb-dot' : 'hb-dot dead';
    if (backendStatus) backendStatus.textContent = online ? 'Connected' : 'API Offline';
}

// ─── Init App Data ───────────────────────────────────────────────────────────
async function initAppData() {
    try {
        const net = await ApiClient.getNetworkInfo();
        headerIp.textContent     = net.local_ip     || '—';
        headerSubnet.textContent = net.suggested_subnet || '—';
        detectedSubnet           = net.suggested_subnet;

        if (scanTarget.value === '' || scanTarget.value === '192.168.0.0/24') {
            scanTarget.value = net.suggested_subnet || '192.168.0.0/24';
        }

        if (net.is_admin) {
            adminIcon.style.color = '#34d399';
            adminText.innerHTML   = '<strong>Admin Mode</strong>';
        } else {
            adminIcon.style.color = '#94a3b8';
            adminText.textContent = 'Standard Mode';
        }

        if (net.nmap_available) {
            nmapNote.style.display   = 'block';
            nmapNoteText.textContent = ' Nmap detected — real scanning active';
        }

        setOnline(true);
        updateAlertsBadge();
        await loadDashboard();
    } catch (e) {
        console.error('Init error:', e);
        setOnline(false);
        toast('Cannot connect to GuardNet backend API.', 'error');
    }
}

// ─── Simulation Mode Sync ────────────────────────────────────────────────────
// Reads the saved setting from DB and syncs the scanner-tab toggle so that the
// hardcoded `checked` HTML attribute never overrides the user's saved preference.
async function syncSimulationToggle() {
    try {
        const s = await ApiClient.getSettings();
        // simulation_mode is stored as the string "true" or "false" in DB
        const savedSim = s.simulation_mode === 'true';
        if (scanSimulation.checked !== savedSim) {
            scanSimulation.checked = savedSim;
        }
    } catch (e) {
        // Non-critical: leave toggle in its current state if settings can't load
        console.warn('[SimSync] Could not sync simulation toggle:', e);
    }
}

// ─── Router Discovery Details ────────────────────────────────────────────────

async function loadRouterDiscovery() {
    try {
        const isSim = scanSimulation.checked;
        const info = await ApiClient.getRouterInfo(isSim);
        const r = info.router || {};

        // Router name: use DNS hostname only — never guess vendor model
        const hostname  = (r.hostname && r.hostname !== 'Unavailable' && r.hostname !== 'gateway.local') ? r.hostname : null;
        const vendorName = (r.vendor && r.vendor !== 'Unavailable') ? r.vendor : null;
        routerModel.textContent = hostname || vendorName || 'Unavailable';

        // Connection type (Wireless / Wired)
        const connType = (r.connection_type && r.connection_type !== 'Unavailable') ? r.connection_type : null;
        routerOs.textContent = connType || 'Unavailable';

        routerLan.textContent = r.lan_ip || '—';
        routerWan.textContent = (r.wan_ip && r.wan_ip !== 'Detecting...' && r.wan_ip !== 'No Internet Access') ? r.wan_ip : (r.wan_ip === 'No Internet Access' ? 'No Internet' : 'Detecting…');

        routerInterface.textContent = (info.interface && info.interface !== 'Unknown Interface') ? info.interface : 'Unavailable';
        routerDns.textContent       = info.dns_server || 'Unavailable';
        routerFirmware.textContent  = (r.firmware && r.firmware !== 'Unavailable' && r.firmware !== 'Simulated') ? r.firmware : 'Unavailable';
        routerUptime.textContent    = (r.uptime   && r.uptime   !== 'Unavailable' && r.uptime   !== 'Simulated Session') ? r.uptime : 'Unavailable';

        // Always show analytics section — bandwidth is polled separately by startBandwidthPolling()
        routerAnalyticsSec.style.display = 'block';
        if (r.analytics) {
            if (routerClients) routerClients.textContent = (r.analytics.active_clients ?? 0) + ' nodes';
            if (routerLoad) {
                let load = r.analytics.network_utilization ?? 0;
                routerLoad.textContent = String(load).replace(/%/g, '') + '%';
            }
        } else {
            if (routerClients) routerClients.textContent = '—';
            if (routerLoad)    routerLoad.textContent    = '—';
        }
    } catch (e) {
        console.error('Router discovery fetch error:', e);
        if (routerModel) routerModel.textContent = 'Unavailable';
    }
}

scanSimulation.addEventListener('change', loadRouterDiscovery);

// Refresh router on explicit button click
$('btn-refresh-router')?.addEventListener('click', () => {
    loadRouterDiscovery();
    toast('Refreshing network info…', 'info');
});

// Poll router analytics when dashboard tab is active (router card lives on dashboard)
setInterval(() => {
    if (currentTab === 'dashboard') {
        loadRouterDiscovery();
    }
}, 30000);

// ─── Dashboard ───────────────────────────────────────────────────────────────
async function loadDashboard() {
    try {
        const s = await ApiClient.getStatistics();
        const devices = await ApiClient.getDevices();
        dashboardDevices = devices;

        $('stat-scans').textContent          = s.total_scans        ?? 0;
        $('stat-total-devices').textContent  = s.total_devices       ?? 0;
        $('stat-online').textContent         = s.online_devices      ?? 0;
        $('stat-offline').textContent        = s.offline_devices     ?? 0;
        $('stat-ports').textContent          = s.total_open_ports    ?? 0;
        $('stat-vendors').textContent        = s.unique_vendors      ?? 0;
        $('stat-new').textContent            = s.new_devices_last_scan ?? 0;
        $('stat-alerts').textContent         = s.unresolved_alerts   ?? 0;

        const score = s.global_security_score ?? 0;
        updateGauge(gaugeCircle, gaugeScore, gaugeLabel, score, 238.76);

        const hasData = (s.total_scans ?? 0) > 0;
        dashboardEmpty.style.display = hasData ? 'none' : 'block';

        if (hasData) {
            renderDeviceTypesChart(s.device_types    || []);
            renderPortDistChart(s.port_distribution  || []);
            renderRiskChart(s.risk_distribution      || []);
            renderTimelineChart(s.scan_timeline      || []);
            // Auto-load diagnostics on dashboard so the panel is always visible
            loadDiagnostics();
        }
    } catch (e) {
        console.error('Dashboard load error:', e);
    }
}

function updateGauge(circleEl, textEl, labelEl, score, circumference) {
    const pct    = Math.max(0, Math.min(100, score));
    const offset = circumference - (pct / 100) * circumference;
    circleEl.style.strokeDashoffset = offset;

    let color = '#06b6d4'; 
    let label = 'No Data';
    if (score >= 90)      { color = '#10b981'; label = 'Excellent'; }
    else if (score >= 75) { color = '#06b6d4'; label = 'Good'; }
    else if (score >= 60) { color = '#f59e0b'; label = 'Moderate Risk'; }
    else if (score >= 40) { color = '#f97316'; label = 'High Risk'; }
    else if (score >  0)  { color = '#ef4444'; label = 'Critical'; }

    circleEl.style.stroke = color;
    textEl.textContent    = score > 0 ? score : '—';
    if (labelEl) {
        labelEl.textContent   = label;
        labelEl.style.color   = color;
        labelEl.style.borderColor = color + '30';
        labelEl.style.background  = color + '12';
    }
}




// ─── Charts Rendering ────────────────────────────────────────────────────────
function getChartDefaults() {
    const dark = document.documentElement.classList.contains('dark');
    return {
        textColor: dark ? '#cbd5e1' : '#475569',
        gridColor: dark ? 'rgba(255,255,255,0.06)' : 'rgba(15,23,42,0.08)',
    };
}

const CHART_PALETTE = [
    '#06b6d4','#818cf8','#34d399','#fbbf24','#f87171',
    '#a78bfa','#38bdf8','#fb923c','#4ade80','#e879f9'
];

function destroyChart(key) {
    if (charts[key]) { charts[key].destroy(); charts[key] = null; }
}

function rebuildCharts() { loadDashboard(); }

function renderDeviceTypesChart(data) {
    const canvas   = $('chart-device-types');
    const noData   = $('no-data-types');
    const legendEl = $('device-categories-legend');
    const hasItems = data.length > 0 && data.some(d => d.count > 0);

    canvas.style.display  = hasItems ? 'block' : 'none';
    noData.style.display  = hasItems ? 'none'  : 'flex';
    if (legendEl) legendEl.style.display = hasItems ? 'flex' : 'none';
    if (!hasItems) return;

    // Initialize activeCategories if not set or empty
    if (!activeCategories) {
        activeCategories = new Set(data.map(d => d.type));
    } else {
        // Ensure any new categories are automatically registered
        data.forEach(d => {
            if (!activeCategories.has(d.type) && !activeCategories.deleted_once) {
                activeCategories.add(d.type);
            }
        });
    }

    // Render interactive legend badges
    if (legendEl) {
        legendEl.innerHTML = '';
        data.forEach(item => {
            const type = item.type;
            const color = CATEGORY_COLORS[type] || '#64748b';
            const isActive = activeCategories.has(type);
            
            const pill = document.createElement('div');
            pill.className = `category-legend-item ${isActive ? 'active' : ''}`;
            
            const dot = document.createElement('span');
            dot.className = 'category-legend-dot';
            dot.style.background = color;
            
            const text = document.createElement('span');
            text.textContent = `${type} (${item.count})`;
            
            pill.appendChild(dot);
            pill.appendChild(text);
            
            pill.addEventListener('click', () => {
                if (activeCategories.has(type)) {
                    if (activeCategories.size > 1) {
                        activeCategories.delete(type);
                        activeCategories.deleted_once = true;
                    }
                } else {
                    activeCategories.add(type);
                }
                renderDeviceTypesChart(data);
            });
            
            legendEl.appendChild(pill);
        });
    }

    // Filter visible slices for Chart.js
    const visibleData = data.filter(d => activeCategories.has(d.type));

    destroyChart('types');
    const { textColor } = getChartDefaults();
    charts.types = new Chart(canvas, {
        type: 'doughnut',
        data: {
            labels:   visibleData.map(d => d.type),
            datasets: [{
                data:            visibleData.map(d => d.count),
                backgroundColor: visibleData.map(d => CATEGORY_COLORS[d.type] || '#64748b'),
                borderWidth:     2,
                borderColor:     'transparent',
                hoverBorderColor: 'transparent',
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: { callbacks: { label: (c) => ` ${c.label}: ${c.parsed} device(s)` } }
            },
            cutout: '60%',
        }
    });
}

function renderPortDistChart(data) {
    const canvas  = $('chart-ports');
    const noData  = $('no-data-ports');
    const hasItems = data.length > 0;

    canvas.style.display = hasItems ? 'block' : 'none';
    noData.style.display = hasItems ? 'none'  : 'flex';
    if (!hasItems) return;

    destroyChart('ports');
    const { textColor, gridColor } = getChartDefaults();
    charts.ports = new Chart(canvas, {
        type: 'bar',
        data: {
            labels:   data.map(d => d.port),
            datasets: [{
                label:           'Devices',
                data:            data.map(d => d.count),
                backgroundColor: 'rgba(6,182,212,0.65)',
                borderColor:     'rgba(6,182,212,0.9)',
                borderWidth:     1,
                borderRadius:    4,
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            indexAxis: 'y',
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { color: gridColor }, ticks: { color: textColor, font: { size: 10 } } },
                y: { grid: { color: gridColor }, ticks: { color: textColor, font: { size: 10.5, family: 'SFMono-Regular, monospace' } } },
            }
        }
    });
}

function renderRiskChart(data) {
    const canvas  = $('chart-risk');
    const noData  = $('no-data-risk');
    const hasItems = data.some(d => d.count > 0);

    canvas.style.display = hasItems ? 'block' : 'none';
    noData.style.display = hasItems ? 'none'  : 'flex';
    if (!hasItems) return;

    destroyChart('risk');
    const { textColor, gridColor } = getChartDefaults();
    const riskColors = { Low: '#34d399', Medium: '#fbbf24', High: '#f87171' };
    charts.risk = new Chart(canvas, {
        type: 'bar',
        data: {
            labels:   data.map(d => d.risk),
            datasets: [{
                label: 'Devices',
                data:  data.map(d => d.count),
                backgroundColor: data.map(d => (riskColors[d.risk] || '#94a3b8') + 'BB'),
                borderColor:     data.map(d => riskColors[d.risk] || '#94a3b8'),
                borderWidth:     1,
                borderRadius:    6,
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { color: gridColor }, ticks: { color: textColor } },
                y: { grid: { color: gridColor }, ticks: { color: textColor, precision: 0 } },
            }
        }
    });
}

function renderTimelineChart(data) {
    const canvas  = $('chart-timeline');
    const noData  = $('no-data-timeline');
    const hasItems = data.length >= 2;

    canvas.style.display = hasItems ? 'block' : 'none';
    noData.style.display = hasItems ? 'none'  : 'flex';
    if (!hasItems) return;

    destroyChart('timeline');
    const { textColor, gridColor } = getChartDefaults();
    charts.timeline = new Chart(canvas, {
        type: 'line',
        data: {
            labels: data.map(d => d.label),
            datasets: [{
                label:           'Devices Found',
                data:            data.map(d => d.device_count),
                borderColor:     '#06b6d4',
                backgroundColor: 'rgba(6,182,212,0.08)',
                fill:            true,
                tension:         0.4,
                pointBackgroundColor: '#06b6d4',
                pointRadius:     4,
                borderWidth:     2,
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { color: gridColor }, ticks: { color: textColor, font: { size: 10 } } },
                y: { grid: { color: gridColor }, ticks: { color: textColor, precision: 0 } },
            }
        }
    });
}

// ─── Device Icons & Styles ───────────────────────────────────────────────────
const DEVICE_ICONS = {
    'Router':         { icon: 'fa-router',            bg: 'rgba(99,102,241,0.12)',  border: 'rgba(99,102,241,0.25)',  color: '#818cf8' },
    'Desktop':        { icon: 'fa-desktop',           bg: 'rgba(6,182,212,0.12)',   border: 'rgba(6,182,212,0.25)',   color: '#06b6d4' },
    'Laptop':         { icon: 'fa-laptop',            bg: 'rgba(14,165,233,0.12)',  border: 'rgba(14,165,233,0.25)',  color: '#38bdf8' },
    'Server':         { icon: 'fa-server',            bg: 'rgba(139,92,246,0.12)', border: 'rgba(139,92,246,0.25)', color: '#a78bfa' },
    'Storage Server': { icon: 'fa-box-archive',       bg: 'rgba(236,72,153,0.12)',  border: 'rgba(236,72,153,0.25)',  color: '#ec4899' },
    'Smartphone':     { icon: 'fa-mobile-screen',     bg: 'rgba(16,185,129,0.12)', border: 'rgba(16,185,129,0.25)', color: '#34d399' },
    'Printer':        { icon: 'fa-print',             bg: 'rgba(245,158,11,0.12)', border: 'rgba(245,158,11,0.25)', color: '#fbbf24' },
    'Smart TV':       { icon: 'fa-tv',                bg: 'rgba(249,115,22,0.12)', border: 'rgba(249,115,22,0.25)', color: '#fb923c' },
    'Gaming Console': { icon: 'fa-gamepad',           bg: 'rgba(239,68,68,0.12)',  border: 'rgba(239,68,68,0.25)',  color: '#f87171' },
    'CCTV Camera':    { icon: 'fa-video',             bg: 'rgba(14,116,144,0.12)',  border: 'rgba(14,116,144,0.25)',  color: '#0e7490' },
    'IoT Device':     { icon: 'fa-microchip',         bg: 'rgba(34,211,238,0.12)', border: 'rgba(34,211,238,0.25)', color: '#22d3ee' },
    'Unknown Device': { icon: 'fa-circle-question',   bg: 'rgba(100,116,139,0.12)',border: 'rgba(100,116,139,0.25)',color: '#94a3b8' },
};

function getDeviceStyle(type) {
    return DEVICE_ICONS[type] || DEVICE_ICONS['Unknown Device'];
}

// ─── Plain English Service Explanations ──────────────────────────────────────
const FRIENDLY_PORT_EXPLANATIONS = {
    21:   "FTP Server. Exposes cleartext file downloads. Highly vulnerable protocol.",
    22:   "Secure Shell (SSH). Safe, encrypted interface for command-line access.",
    23:   "Telnet. Obsolete cleartext admin access. Security warning: replace with SSH.",
    25:   "SMTP Mail Server. Outbound mail queue routing.",
    53:   "DNS Server. Provides local network name-to-IP resolution.",
    80:   "HTTP Web Server. Unencrypted web services or admin console.",
    443:  "HTTPS Secure Web Server. Safe, encrypted connection for admin panels.",
    445:  "Windows File Sharing (SMB) active. Standard Windows networking port.",
    139:  "NetBIOS Windows Networking. Legacy file sharing interface.",
    135:  "RPC mapper service. Coordinates Windows server connectivity.",
    515:  "LPD print server daemon. Accepts incoming printer jobs.",
    631:  "CUPS internet printing protocol daemon.",
    1900: "UPnP Discovery beacon. Helps clients locate local multimedia hardware.",
    3306: "MySQL Database Server. Warning: database port exposed to network.",
    3389: "Windows Remote Desktop (RDP). Allows graphical logins.",
    5000: "Synology DiskStation admin manager web UI.",
    5432: "PostgreSQL Database. Warning: database exposed to network.",
    6379: "Redis Memory Cache Server. Risk: often runs without passwords.",
    8080: "Alternate Web Admin console interface.",
    9100: "RAW JetDirect print spooler. Spits printer files to printer.",
    27017:"MongoDB Database. Warning: DB exposed without password authentication."
};

function getFriendlyPortExplanation(port, rawService) {
    if (FRIENDLY_PORT_EXPLANATIONS[port]) {
        return FRIENDLY_PORT_EXPLANATIONS[port];
    }
    return `Active ${rawService || 'network service'} listening on port ${port}.`;
}

// ─── Devices Inventory ───────────────────────────────────────────────────────
let selectedDeviceIds = new Set();

async function loadDevices() {
    devicesGrid.innerHTML = renderSkeletons(6);
    devicesEmpty.style.display = 'none';

    const params = {};
    const s = devicesSearch.value.trim();
    const c = devicesType.value;
    const r = devicesRisk.value;
    const sortVal = devicesSort ? devicesSort.value : 'score_desc';
    if (s) params.search   = s;
    if (c && c !== 'all') params.category = c;
    if (r && r !== 'all') params.risk     = r;
    params.sort_by = sortVal;

    try {
        const devices = await ApiClient.getDevices(params);
        devicesGrid.innerHTML = '';

        if (!devices.length) {
            devicesEmpty.style.display = 'block';
            $('devices-actions-bar').style.display = 'none';
            return;
        }

        $('devices-actions-bar').style.display = 'flex';

        devices.forEach(d => {
            const style = getDeviceStyle(d.device_type);
            const score = d.security_score ?? 100;
            const circumference = 113.1;
            const offset = circumference - (score / 100) * circumference;
            const scoreColor = score >= 80 ? '#34d399' : score >= 60 ? '#fbbf24' : '#f87171';
            const isChecked = selectedDeviceIds.has(d.id);

            const card = document.createElement('div');
            card.className = 'device-card';
            card.setAttribute('data-device-id', d.id);
            card.onclick = (e) => {
                if (e.target.closest('.device-select-checkbox') || e.target.closest('.device-select-container')) {
                    return;
                }
                openDeviceModal(d.id);
            };

            card.innerHTML = `
              <div class="device-card-header">
                <div style="display:flex;align-items:center;gap:12px;">
                  <div class="device-select-container" onclick="event.stopPropagation()" style="display:flex; align-items:center;">
                    <input type="checkbox" class="device-select-checkbox" data-id="${d.id}" ${isChecked ? 'checked' : ''} style="cursor:pointer; width:16px; height:16px;">
                  </div>
                  <div class="device-icon-wrap" style="background:${style.bg};border:1px solid ${style.border};color:${style.color}">
                    <i class="fa-solid ${style.icon}"></i>
                  </div>
                  <div>
                    <div class="device-ip">${d.ip_address}</div>
                    <div class="device-hostname">${d.hostname || 'No hostname'}</div>
                  </div>
                </div>
                <div class="score-ring-sm">
                  <svg viewBox="0 0 44 44">
                    <circle cx="22" cy="22" r="18" stroke-width="4" stroke="var(--border)" fill="none"/>
                    <circle cx="22" cy="22" r="18" stroke-width="4" stroke="${scoreColor}" fill="none"
                            stroke-dasharray="${circumference}" stroke-dashoffset="${offset}"
                            transform="rotate(-90 22 22)"/>
                  </svg>
                  <div class="score-num" style="color:${scoreColor}">${score}</div>
                </div>
              </div>

              <div class="device-meta">
                <div class="device-meta-item">
                  <span>Type</span>
                  <span>${d.device_type}</span>
                </div>
                <div class="device-meta-item">
                  <span>Vendor</span>
                  <span>${d.vendor || '—'}</span>
                </div>
                <div class="device-meta-item">
                  <span>OS</span>
                  <span>${(d.os_name || '—').substring(0, 22)}</span>
                </div>
                <div class="device-meta-item">
                  <span>Open Ports</span>
                  <span>${d.ports?.length || 0}</span>
                </div>
              </div>

              <div class="device-footer">
                <span class="badge ${d.status === 'up' ? 'badge-online' : 'badge-offline'}">
                  <i class="fa-solid fa-circle" style="font-size:6px"></i>
                  ${d.status === 'up' ? 'Online' : 'Offline'}
                </span>
                ${d.randomized_mac ? '<span class="badge badge-private" title="Privacy-preserving randomized MAC"><i class="fa-solid fa-shield-halved"></i> Private MAC</span>' : ''}
                <span class="badge ${d.max_risk === 'High' ? 'badge-high' : d.max_risk === 'Medium' ? 'badge-medium' : 'badge-low'}">
                  ${d.max_risk} Risk
                </span>
                <span style="font-size:10.5px;color:var(--text-muted)">
                  <i class="fa-regular fa-clock"></i> ${d.last_seen?.split(' ')[0] || '—'}
                </span>
              </div>
            `;

            const cb = card.querySelector('.device-select-checkbox');
            cb.addEventListener('change', (e) => {
                if (e.target.checked) {
                    selectedDeviceIds.add(d.id);
                } else {
                    selectedDeviceIds.delete(d.id);
                }
                updateDeviceSelectionState();
            });

            devicesGrid.appendChild(card);
        });

        updateDeviceSelectionState();
    } catch (e) {
        devicesGrid.innerHTML = '';
        devicesEmpty.style.display = 'block';
        $('devices-actions-bar').style.display = 'none';
        toast('Failed to load devices list.', 'error');
    }
}

function updateDeviceSelectionState() {
    const selectAll = $('select-all-devices');
    const deleteBtn = $('delete-selected-devices-btn');
    const countLabel = $('selected-devices-count');
    
    const checkboxes = Array.from(document.querySelectorAll('.device-select-checkbox'));
    const checkedCount = selectedDeviceIds.size;
    
    if (countLabel) countLabel.textContent = checkedCount;
    if (deleteBtn) {
        deleteBtn.style.display = checkedCount > 0 ? 'inline-flex' : 'none';
    }
    
    if (selectAll) {
        if (checkboxes.length > 0 && checkboxes.every(cb => cb.checked)) {
            selectAll.checked = true;
        } else {
            selectAll.checked = false;
        }
    }
}

function renderSkeletons(n) {
    return Array(n).fill(0).map(() => `
      <div class="card" style="display:flex;flex-direction:column;gap:12px;padding:20px;">
        <div class="skeleton" style="height:20px;width:60%"></div>
        <div class="skeleton" style="height:14px;width:80%"></div>
        <div class="skeleton" style="height:14px;width:50%"></div>
      </div>
    `).join('');
}

let devSearchTimeout;
if (devicesSearch) devicesSearch.addEventListener('input', () => {
    clearTimeout(devSearchTimeout);
    devSearchTimeout = setTimeout(loadDevices, 350);
});
// devicesType/Risk/Sort changes are handled by setupCustomSelect() at bottom of file

$('select-all-devices').addEventListener('change', (e) => {
    const checked = e.target.checked;
    const checkboxes = document.querySelectorAll('.device-select-checkbox');
    checkboxes.forEach(cb => {
        cb.checked = checked;
        const id = parseInt(cb.getAttribute('data-id'));
        if (checked) {
            selectedDeviceIds.add(id);
        } else {
            selectedDeviceIds.delete(id);
        }
    });
    updateDeviceSelectionState();
});

$('delete-selected-devices-btn').addEventListener('click', () => {
    const ids = Array.from(selectedDeviceIds);
    if (ids.length === 0) return;
    
    showConfirm(
        'Delete Selected Devices',
        `Are you sure you want to permanently delete the ${ids.length} selected device(s) and all their associated alerts, history, and records?`,
        async () => {
            try {
                await ApiClient.deleteDevices(ids);
                toast(`Successfully deleted ${ids.length} device(s).`, 'success');
                selectedDeviceIds.clear();
                loadDevices();
                loadDashboard();
            } catch (e) {
                toast('Failed to delete selected devices.', 'error');
            }
        }
    );
});

$('clear-inventory-btn').addEventListener('click', () => {
    showConfirm(
        'Clear Device Inventory',
        'CRITICAL WARNING: This will permanently wipe all discovered devices, alerts, scan logs, and active client entries in the database. Proceed?',
        async () => {
            try {
                await ApiClient.clearAllDevices();
                toast('Device inventory cleared.', 'success');
                selectedDeviceIds.clear();
                loadDevices();
                loadDashboard();
            } catch (e) {
                toast('Failed to clear device inventory.', 'error');
            }
        }
    );
});

// ─── Device Modal ─────────────────────────────────────────────────────────────
async function openDeviceModal(deviceId) {
    deviceModal.classList.add('open');
    document.body.style.overflow = 'hidden';

    $('modal-ip').textContent       = 'Loading…';
    $('modal-hostname').textContent = '';
    $('modal-ports').innerHTML      = '<tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:16px">Loading…</td></tr>';
    $('modal-alerts').innerHTML     = '<div style="color:var(--text-muted);font-size:12px;text-align:center;padding:12px">Loading…</div>';
    $('modal-os-confidence-container').style.display = 'none';

    try {
        const d = await ApiClient.getDevice(deviceId);
        const style = getDeviceStyle(d.device_type);

        $('modal-icon').style.cssText = `background:${style.bg};border:1px solid ${style.border};color:${style.color};font-size:20px`;
        $('modal-icon').innerHTML = `<i class="fa-solid ${style.icon}"></i>`;

        $('modal-ip').textContent       = d.ip_address;
        $('modal-hostname').textContent = d.hostname || 'No hostname recorded';
        $('modal-vendor').textContent   = d.vendor   || '—';
        $('modal-type').textContent     = d.device_type;
        if (d.randomized_mac) {
            $('modal-mac').innerHTML    = `${d.mac_address || '—'} <span class="badge badge-private" style="margin-left:6px" title="Device uses randomized MAC for privacy"><i class="fa-solid fa-shield-halved"></i> Private MAC</span>`;
        } else {
            $('modal-mac').textContent  = d.mac_address || '—';
        }
        $('modal-os').textContent       = d.os_name  || '—';
        $('modal-first-seen').textContent = d.first_seen || '—';
        $('modal-last-seen').textContent  = d.last_seen  || '—';
        $('modal-appearances').textContent = `${d.appearance_count}x`;

        if (d.os_confidence) {
            $('modal-os-confidence-container').style.display = 'block';
            $('modal-os-confidence').textContent = d.os_confidence + '%';
        } else {
            $('modal-os-confidence-container').style.display = 'none';
        }
        
        if (d.classification_confidence) {
            $('modal-type-confidence').style.display = 'block';
            $('modal-type-confidence').textContent = d.classification_confidence + ' Match';
        } else {
            $('modal-type-confidence').style.display = 'none';
        }
        
        if (d.device_type.includes('Router') || d.device_type.includes('Gateway')) {
            $('modal-router-section').style.display = 'block';
        } else {
            $('modal-router-section').style.display = 'none';
        }

        $('modal-status').innerHTML = `<span class="badge ${d.status === 'up' ? 'badge-online' : 'badge-offline'}">
          <i class="fa-solid fa-circle" style="font-size:6px"></i> ${d.status === 'up' ? 'Online' : 'Offline'}
        </span>`;

        const score = d.security_score ?? 100;
        updateGauge($('modal-gauge'), $('modal-score'), null, score, 113.1);

        // Open Ports table with friendly explanations
        if (d.ports?.length) {
            $('modal-ports').innerHTML = d.ports.map(p => {
                const friendlyDesc = getFriendlyPortExplanation(p.port, p.service);
                return `
                  <tr>
                    <td><span class="port-num">${p.port}</span></td>
                    <td style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted)">${p.protocol?.toUpperCase()}</td>
                    <td style="color:var(--text-secondary);font-size:12px">${p.service || '—'}</td>
                    <td><span class="badge ${p.risk_level === 'High' ? 'badge-high' : p.risk_level === 'Medium' ? 'badge-medium' : 'badge-low'}">${p.risk_level}</span></td>
                    <td style="font-size:11px;color:var(--text-muted);max-width:260px; line-height: 1.45;">
                      <strong>${friendlyDesc}</strong>
                      ${p.description && p.description !== friendlyDesc ? `<br><span style="color:#ef4444; font-size:10px; margin-top:2px; display:inline-block">${p.description}</span>` : ''}
                    </td>
                  </tr>
                `;
            }).join('');
        } else {
            $('modal-ports').innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:16px">No open ports detected</td></tr>';
        }

        // Alerts
        if (d.alerts?.length) {
            $('modal-alerts').innerHTML = d.alerts.map(a => `
              <div style="padding:10px 14px;background:var(--bg-input);border-radius:var(--radius-md);border:1px solid var(--border);font-size:12px;">
                <div style="display:flex;align-items:center;gap:8px;margin-bottom:3px;">
                  <span class="badge ${a.severity === 'high' ? 'badge-high' : a.severity === 'medium' ? 'badge-medium' : 'badge-low'}">${a.severity}</span>
                  <span style="color:var(--text-muted);font-size:10.5px">${a.timestamp}</span>
                  ${a.resolved ? '<span style="font-size:10px;color:#34d399">✓ Resolved</span>' : ''}
                </div>
                <div style="color:var(--text-secondary)">${a.message}</div>
              </div>
            `).join('');
        } else {
            $('modal-alerts').innerHTML = '<div style="font-size:12px;color:var(--text-muted);text-align:center;padding:12px">No alerts for this device.</div>';
        }
    } catch (e) {
        toast('Failed to load device details.', 'error');
    }
}

function closeDeviceModal() {
    deviceModal.classList.remove('open');
    document.body.style.overflow = '';
}

modalClose.addEventListener('click', closeDeviceModal);
deviceModal.addEventListener('click', (e) => { if (e.target === deviceModal) closeDeviceModal(); });
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeDeviceModal(); });

window.viewScanDetails = function viewScanDetails(scanId) {
    ApiClient.getScanDetails(scanId).then(details => {
        const devices = details.devices || [];
        let hostsHtml = devices.length > 0
            ? devices.map(d => `<tr>
                <td style="font-family:var(--font-mono);font-size:12px">${d.ip_address}</td>
                <td style="font-size:11px;color:var(--text-muted)">${d.mac_address || '—'}</td>
                <td>${d.device_type}</td>
                <td><span class="badge ${d.status === 'up' ? 'badge-online' : 'badge-offline'}">${d.status === 'up' ? 'Online' : 'Offline'}</span></td>
              </tr>`).join('')
            : '<tr><td colspan="4" style="text-align:center;color:var(--text-muted);padding:16px">No devices found in this scan.</td></tr>';

        const modalHtml = `
          <div id="scan-modal" style="position:fixed;inset:0;background:rgba(0,0,0,0.6);backdrop-filter:blur(4px);z-index:9999;display:flex;align-items:center;justify-content:center;padding:20px;">
            <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius-lg);width:100%;max-width:700px;max-height:90vh;display:flex;flex-direction:column;box-shadow:0 25px 50px -12px rgba(0,0,0,0.5);">
              <div style="padding:20px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;">
                <div>
                  <h2 style="font-size:18px;margin:0;color:var(--text-primary);">Scan #${scanId} — ${devices.length} device(s)</h2>
                </div>
                <button class="icon-btn" onclick="document.getElementById('scan-modal').remove()"><i class="fa-solid fa-xmark"></i></button>
              </div>
              <div style="padding:20px;overflow-y:auto;flex:1;">
                <div style="overflow-x:auto;">
                  <table style="width:100%;text-align:left;border-collapse:collapse;font-size:13px;">
                    <thead>
                      <tr style="border-bottom:1px solid var(--border);color:var(--text-muted)">
                        <th style="padding:10px;">IP Address</th>
                        <th style="padding:10px;">MAC Address</th>
                        <th style="padding:10px;">Type</th>
                        <th style="padding:10px;">Status</th>
                      </tr>
                    </thead>
                    <tbody>${hostsHtml}</tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>`;
        document.body.insertAdjacentHTML('beforeend', modalHtml);
    }).catch(() => toast('Failed to load scan details.', 'error'));
};

// ─── Alerts ──────────────────────────────────────────────────────────────────
async function loadAlerts() {
    const unresolved = alertsFilter.value === 'unresolved';
    try {
        const alerts = await ApiClient.getAlerts(unresolved);
        renderAlerts(alerts);
    } catch (e) {
        toast('Failed to load alerts feed.', 'error');
    }
}

function renderAlerts(alerts) {
    if (!alerts.length) {
        alertsList.innerHTML = `
          <div class="empty-state">
            <i class="fa-solid fa-shield-check" style="color:#34d399"></i>
            <h3>No Active Threats</h3>
            <p>Network security audit feed is clear.</p>
          </div>`;
        return;
    }

    const SEVERITY_ICONS = {
        high:   'fa-triangle-exclamation',
        medium: 'fa-circle-exclamation',
        low:    'fa-circle-info',
    };
    const TYPE_LABELS = {
        new_device:      'New Device Discovered',
        unknown_vendor:  'Unknown MAC Prefix',
        hostname_changed:'Hostname Changed',
        ip_changed:      'IP Lease Changed',
        insecure_service:'Critical Port Exposed',
        rogue_device:    'Rogue Node Warning',
        port_changed:    'Open Ports Modified',
        device_offline:  'Device Disappeared'
    };

    alertsList.innerHTML = alerts.map(a => `
      <div class="alert-item ${a.resolved ? 'resolved' : ''}">
        <div class="alert-severity-dot ${a.severity}"></div>
        <div class="alert-meta">
          <h5><i class="fa-solid ${SEVERITY_ICONS[a.severity] || 'fa-circle-info'}" style="margin-right:6px"></i>${TYPE_LABELS[a.type] || a.type}</h5>
          <p>${a.message}</p>
          <div class="alert-ts"><i class="fa-regular fa-clock"></i> ${a.timestamp}</div>
        </div>
        ${!a.resolved ? `
          <button class="btn btn-ghost btn-sm" onclick="resolveAlert(${a.id})">
            <i class="fa-solid fa-check"></i> Resolve
          </button>` : `<span style="font-size:11px;color:#34d399;white-space:nowrap">✓ Resolved</span>`}
      </div>
    `).join('');
}

window.resolveAlert = async (id) => {
    try {
        await ApiClient.resolveAlert(id);
        toast('Alert resolved.', 'success');
        loadAlerts();
        updateAlertsBadge();
    } catch (e) {
        toast('Failed to resolve alert.', 'error');
    }
};

resolveAllBtn.addEventListener('click', async () => {
    try {
        const unresolved = await ApiClient.getAlerts(true);
        await Promise.all(unresolved.map(a => ApiClient.resolveAlert(a.id)));
        toast(`${unresolved.length} alert(s) resolved.`, 'success');
        loadAlerts();
        updateAlertsBadge();
    } catch (e) {
        toast('Failed to resolve alerts.', 'error');
    }
});

alertsFilter.addEventListener('change', loadAlerts);

async function updateAlertsBadge() {
    try {
        const unresolved = await ApiClient.getAlerts(true);
        const count = unresolved.length;
        if (count > 0) {
            alertsBadge.textContent  = count;
            alertsBadge.style.display = 'block';
        } else {
            alertsBadge.style.display = 'none';
        }
    } catch (e) { }
}

// ─── Scan History & Checkboxes ───────────────────────────────────────────────
async function loadHistory() {
    try {
        const scans = await ApiClient.getHistory();
        selectAllHistory.checked = false;
        deleteSelectedBtn.style.display = 'none';
        
        if (!scans.length) {
            historyBody.innerHTML = '<tr><td colspan="8" style="text-align:center;padding:40px;color:var(--text-muted)">No scan records found. Run a network scan.</td></tr>';
            return;
        }
        const PROFILE_LABELS = { quick: '⚡ Quick', standard: '🔍 Standard', deep: '🔬 Deep', inventory: '📋 Inventory', audit: '🛡️ Audit' };
        historyBody.innerHTML = scans.map(s => `
          <tr>
            <td style="text-align:center;"><input type="checkbox" class="history-select" value="${s.id}"></td>
            <td style="font-family:var(--font-mono);color:var(--brand-primary)">#${s.id}</td>
            <td>${s.timestamp}</td>
            <td style="font-family:var(--font-mono);font-size:12px;color:var(--text-secondary)">${s.target}</td>
            <td>${PROFILE_LABELS[s.scan_type] || s.scan_type}</td>
            <td><strong style="color:var(--text-primary)">${s.device_count}</strong></td>
            <td>
              <span class="badge ${s.status === 'completed' ? 'badge-online' : s.status === 'running' ? 'badge-medium' : 'badge-offline'}">
                ${s.status}
              </span>
            </td>
            <td>
              <div style="display:flex;gap:6px;">
                <button class="btn btn-ghost btn-icon-sm" onclick="viewScanDetails(${s.id})" title="Details">
                  <i class="fa-solid fa-eye"></i>
                </button>
                <button class="btn btn-danger btn-icon-sm" onclick="deleteScanRecord(${s.id})" title="Delete">
                  <i class="fa-solid fa-trash"></i>
                </button>
              </div>
            </td>
          </tr>
        `).join('');
        
        // Listen to checkbox toggles
        document.querySelectorAll('.history-select').forEach(box => {
            box.addEventListener('change', toggleSelectedBtnVisibility);
        });
    } catch (e) {
        toast('Failed to load scan history.', 'error');
    }
}

function toggleSelectedBtnVisibility() {
    const checked = document.querySelectorAll('.history-select:checked');
    deleteSelectedBtn.style.display = checked.length > 0 ? 'inline-flex' : 'none';
}

selectAllHistory.addEventListener('change', () => {
    const isChecked = selectAllHistory.checked;
    document.querySelectorAll('.history-select').forEach(box => {
        box.checked = isChecked;
    });
    toggleSelectedBtnVisibility();
});

// Delete specific single record (Using Themed showConfirm)
window.deleteScanRecord = (id) => {
    showConfirm(
        'Delete Scan Record',
        'Are you sure you want to delete this scan record? This will permanently delete associated device historical points.',
        async () => {
            try {
                await ApiClient.deleteScan(id);
                toast('Scan record deleted.', 'success');
                loadHistory();
                loadDashboard();
            } catch (e) {
                toast('Failed to delete scan.', 'error');
            }
        }
    );
};

// Batch delete selected records (Using Themed showConfirm)
deleteSelectedBtn.addEventListener('click', () => {
    const selectedBoxes = document.querySelectorAll('.history-select:checked');
    const ids = Array.from(selectedBoxes).map(box => parseInt(box.value));
    
    if (ids.length === 0) return;
    
    showConfirm(
        'Delete Selected Scans',
        `Are you sure you want to permanently delete ${ids.length} selected scan record(s)?`,
        async () => {
            try {
                await ApiClient.deleteSelected(ids);
                toast(`Successfully deleted ${ids.length} scans.`, 'success');
                loadHistory();
                loadDashboard();
            } catch (e) {
                toast('Failed to delete selected scans.', 'error');
            }
        }
    );
});

// Wipe all scan history (Using Themed showConfirm)
clearAllHistoryBtn.addEventListener('click', () => {
    showConfirm(
        'Clear Scan Database',
        'CRITICAL WARNING: This will permanently wipe ALL scan histories, discovered devices, alert logs, and telemetry. Proceed?',
        async () => {
            try {
                await ApiClient.clearAllHistory();
                toast('All database records cleared.', 'success');
                loadHistory();
                loadDashboard();
            } catch (e) {
                toast('Failed to clear database.', 'error');
            }
        }
    );
});

refreshHistBtn.addEventListener('click', loadHistory);

// ─── Settings ─────────────────────────────────────────────────────────────────
async function loadSettings() {
    try {
        const s = await ApiClient.getSettings();
        settingsSubnet.value          = s.default_subnet  || '192.168.1.0/24';
        setCustomSelectValue('settings-schedule-dropdown', 'settings-schedule', s.scan_schedule || 'manual');
        settingsEmail.value           = s.alert_email     || '';
        settingsAlertNew.checked      = s.alert_on_new    === 'true';
        settingsAlertChange.checked   = s.alert_on_change === 'true';
        settingsSimMode.checked       = s.simulation_mode === 'true';

        // SMTP settings fields mapping
        smtpEnabled.checked           = s.smtp_enabled === 'true';
        smtpHost.value                = s.smtp_host || '';
        smtpPort.value                = s.smtp_port || '587';
        smtpUser.value                = s.smtp_user || '';
        smtpPass.value                = s.smtp_pass || '';
        smtpFrom.value                = s.smtp_from || '';
        smtpSecurity.value            = s.smtp_security || 'tls';
        setCustomSelectValue('settings-severity-dropdown', 'smtp-min-severity', s.smtp_min_severity || 'medium');
        
    } catch (e) {
        toast('Failed to load settings from DB.', 'error');
    }
}

settingsForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
        await ApiClient.saveSettings({
            default_subnet:  settingsSubnet.value.trim(),
            scan_schedule:   settingsSchedule.value,
            alert_email:     settingsEmail.value.trim(),
            alert_on_new:    settingsAlertNew.checked    ? 'true' : 'false',
            alert_on_change: settingsAlertChange.checked ? 'true' : 'false',
            simulation_mode: settingsSimMode.checked     ? 'true' : 'false',
            
            // SMTP Save values
            smtp_enabled:    smtpEnabled.checked ? 'true' : 'false',
            smtp_host:       smtpHost.value.trim(),
            smtp_port:       smtpPort.value.trim(),
            smtp_user:       smtpUser.value.trim(),
            smtp_pass:       smtpPass.value.trim(),
            smtp_from:       smtpFrom.value.trim(),
            smtp_security:   smtpSecurity.value,
            smtp_min_severity: smtpMinSeverity.value,
        });
        toast('Settings updated successfully.', 'success');
        // Immediately sync the scanner-tab simulation toggle so it stays in
        // agreement with the newly saved preference without needing a tab switch.
        if (scanSimulation) {
            scanSimulation.checked = settingsSimMode.checked;
        }
    } catch (e) {
        toast('Failed to update settings.', 'error');
    }
});

btnTestSmtp.addEventListener('click', async () => {
    const payload = {
        smtp_enabled:    'true', // enforce true for testing
        smtp_host:       smtpHost.value.trim(),
        smtp_port:       smtpPort.value.trim(),
        smtp_user:       smtpUser.value.trim(),
        smtp_pass:       smtpPass.value.trim(),
        smtp_from:       smtpFrom.value.trim(),
        smtp_security:   smtpSecurity.value,
        alert_email:     settingsEmail.value.trim(),
    };
    
    if (!payload.smtp_host || !payload.smtp_from || !payload.alert_email) {
        toast('Please enter SMTP Host, From Email, and Alert Email to run test.', 'warning');
        return;
    }
    
    btnTestSmtp.disabled = true;
    btnTestSmtp.innerHTML = '<i class="fa-solid fa-circle-notch spin"></i> Testing Connection…';
    
    try {
        const res = await ApiClient.testEmail(payload);
        if (res.success) {
            toast('Test alert email successfully dispatched to ' + payload.alert_email, 'success');
        } else {
            toast(res.detail || 'Test delivery failed.', 'error');
        }
    } catch (err) {
        toast(err.message || 'SMTP Connection failed.', 'error');
    } finally {
        btnTestSmtp.disabled = false;
        btnTestSmtp.innerHTML = '<i class="fa-solid fa-paper-plane"></i> Test SMTP Connection';
    }
});

$('reset-settings-btn').addEventListener('click', () => {
    showConfirm(
        'Reset Settings',
        'Are you sure you want to reset all preferences to default values?',
        () => {
            settingsSubnet.value          = '192.168.1.0/24';
            settingsSchedule.value        = 'manual';
            settingsEmail.value           = '';
            settingsAlertNew.checked      = true;
            settingsAlertChange.checked   = true;
            settingsSimMode.checked       = true;
            
            smtpEnabled.checked           = false;
            smtpHost.value                = '';
            smtpPort.value                = '587';
            smtpUser.value                = '';
            smtpPass.value                = '';
            smtpFrom.value                = '';
            smtpSecurity.value            = 'tls';
            smtpMinSeverity.value         = 'medium';
            
            toast('Defaults loaded. Click Save to apply.', 'info');
        }
    );
});

// ─── Scanner Custom Dropdown & Profile Hints ─────────────────────────────────

const PROFILE_HINTS = {
    quick:     'Rapidly discovers active hosts using ARP, ICMP, and TCP probes. No port scanning.',
    standard:  'Scans common TCP ports on all discovered hosts. Best for routine inventory.',
    deep:      'Full service version detection and OS fingerprinting. Slower but thorough.',
    inventory: 'Rechecks previously discovered devices for online/offline status changes.',
    audit:     'Service and version analysis correlated with known vulnerability data.',
};

// Scan profile is handled entirely via setupCustomSelect() at the bottom

// Target IP subnet scanner helpers
const SINGLE_IP_RE = /^(\d{1,3}\.){3}\d{1,3}$/;

scanTarget.addEventListener('input', () => {
    const val = scanTarget.value.trim();
    if (SINGLE_IP_RE.test(val)) {
        const octets   = val.split('.');
        const subnet   = `${octets[0]}.${octets[1]}.${octets[2]}.0/24`;
        suggestedText.textContent = subnet;
        subnetPrompt.classList.add('visible');
    } else {
        subnetPrompt.classList.remove('visible');
    }
});

btnScanSingle.addEventListener('click', () => {
    subnetPrompt.classList.remove('visible');
});

btnExpandSubnet.addEventListener('click', () => {
    const val    = scanTarget.value.trim();
    const octets = val.split('.');
    scanTarget.value = `${octets[0]}.${octets[1]}.${octets[2]}.0/24`;
    subnetPrompt.classList.remove('visible');
    toast(`Subnet scope set to: ${scanTarget.value}`, 'info');
});

if (abortScanBtn) {
    abortScanBtn.addEventListener('click', () => {
        if (!activeScanId) return;
        const scanId = activeScanId;
        showConfirm('Abort Scan', 'Are you sure you want to abort the active scan? Partial results will not be saved.', async () => {
            try {
                await ApiClient.abortScan(scanId);
                clearInterval(activeScanTimer);
                activeScanId = null;
                activeScanTimer = null;
                toast('Scan aborted.', 'warning');
                resetScanUI();
            } catch (e) {
                toast('Failed to abort scan.', 'error');
            }
        });
    });
}

scanForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (activeScanId) {
        toast('A scan cycle is already in progress.', 'warning');
        return;
    }

    const target   = scanTarget.value.trim();
    const profileEl = document.getElementById('scan-profile');
    const profile  = profileEl ? profileEl.value : 'standard'; // Read from hidden input set by custom dropdown
    const simMode  = scanSimulation.checked;

    if (!target) {
        toast('Please enter a target subnet range.', 'warning');
        return;
    }

    subnetPrompt.classList.remove('visible');
    startScanBtn.disabled  = true;
    startScanBtn.innerHTML = '<i class="fa-solid fa-circle-notch spin"></i> <span>Scanning…</span>';
    if (abortScanBtn) abortScanBtn.style.display = 'flex';

    scanPlaceholder.style.display  = 'none';
    progressCard.style.display     = 'block';
    resultsCard.style.display      = 'none';
    consoleLogs.innerHTML          = '<div class="log-line">[System] Queued scan job…</div>';
    scanFill.style.width           = '0%';
    scanPct.textContent            = '0%';
    scanStateText.textContent      = 'Queued…';
    
    // Estimate
    const etaText = document.getElementById('scan-eta-text');
    if (etaText) etaText.style.display = 'block';

    try {
        const res = await ApiClient.startScan(target, profile);
        activeScanId     = res.scan_id;
        activeScanTimer  = setInterval(() => pollScanStatus(activeScanId), 1500);
        
    } catch (e) {
        if (etaText) etaText.style.display = 'none';
        if (e.message === 'ADMIN_REQUIRED') {
            const note = document.getElementById('nmap-status-note');
            if (note) {
                note.style.display = 'flex';
                note.style.background = 'rgba(239,68,68,0.1)';
                note.style.borderColor = 'rgba(239,68,68,0.2)';
                note.innerHTML = '<div style="display:flex;align-items:center;gap:8px;"><i class="fa-solid fa-triangle-exclamation" style="color:#f87171"></i><span style="color:#f87171;font-weight:700">Administrator privileges required to perform RAW packet scans. Please restart GuardNet as Admin.</span></div>';
            }
        } else {
            toast(`Scan startup failed: ${e.message}`, 'error');
        }
        resetScanUI();
    }
});

async function pollScanStatus(scanId) {
    try {
        const s = await ApiClient.getScanStatus(scanId);

        const pct = s.progress ?? 0;
        scanFill.style.width   = `${pct}%`;
        scanPct.textContent    = `${pct}%`;
        scanStateText.textContent = s.status === 'completed' ? 'Complete!' : s.status === 'failed' ? 'Failed' : s.status === 'aborted' ? 'Aborted' : 'Scanning…';

        const logs = s.logs || [];
        const alreadyRendered = consoleLogs.querySelectorAll('.log-line:not(.scan-running-indicator)').length;
        if (logs.length > alreadyRendered) {
            const newLogs = logs.slice(alreadyRendered);
            newLogs.forEach(log => {
                const div = document.createElement('div');
                div.className = 'log-line';
                const lower = log.toLowerCase();
                if (lower.includes('error') || lower.includes('fail')) div.className += ' error';
                else if (lower.includes('abort')) div.className += ' warning';
                else if (lower.includes('warn') || lower.includes('fallback') || lower.includes('offline') || lower.includes('disappeared')) div.className += ' warning';
                else if (lower.includes('complete') || lower.includes('found') || lower.includes('online') || lower.includes('up')) div.className += ' success';
                else div.className += ' info';
                div.textContent = log;
                consoleLogs.appendChild(div);
            });
            consoleLogs.scrollTop = consoleLogs.scrollHeight;
        }

        // Professional running indicator — steady dots, no jarring blink
        let indicator = consoleLogs.querySelector('.scan-running-indicator');
        if (s.status === 'running') {
            if (!indicator) {
                indicator = document.createElement('div');
                indicator.className = 'log-line info scan-running-indicator';
                indicator.style.cssText = 'display:flex;align-items:center;gap:8px;opacity:0.75;';
                indicator.innerHTML = '<i class="fa-solid fa-circle-notch" style="animation:spin 1.2s linear infinite;font-size:11px"></i><span>Scan engine running…</span>';
            }
            consoleLogs.appendChild(indicator);
            consoleLogs.scrollTop = consoleLogs.scrollHeight;
        } else if (indicator) {
            indicator.remove();
        }

        if (s.status === 'completed' || s.status === 'failed' || s.status === 'aborted') {
            clearInterval(activeScanTimer);
            activeScanId   = null;
            activeScanTimer = null;

            if (s.status === 'completed') {
                toast(`Network scan completed. Discovered ${s.device_count} hosts.`, 'success');
                await showScanResults(scanId);
                updateAlertsBadge();
                if (currentTab === 'dashboard') loadDashboard();
            } else if (s.status === 'aborted') {
                toast('Scan aborted.', 'warning');
            } else {
                toast('Network scan failed. Inspect console logs.', 'error');
            }
            resetScanUI();
        }
    } catch (e) {
        console.error('Poll error:', e);
    }
}

async function showScanResults(scanId) {
    try {
        const details  = await ApiClient.getScanDetails(scanId);
        const devices  = details.devices || [];

        resultsCard.style.display = 'block';
        resultsCount.textContent  = `${devices.length} found`;

        resultsList.innerHTML = devices.map(d => {
            const style = getDeviceStyle(d.device_type);
            const ports = d.ports || [];
            // Build a compact ports summary table (max 6 rows for readability)
            const visiblePorts = ports.slice(0, 6);
            const portsTable = visiblePorts.length ? `
              <table style="width:100%;margin-top:8px;border-collapse:collapse;font-size:10.5px;">
                <thead>
                  <tr style="color:var(--text-muted);border-bottom:1px solid var(--border);">
                    <th style="padding:3px 6px;text-align:left;font-weight:600">PORT</th>
                    <th style="padding:3px 6px;text-align:left;font-weight:600">PROTO</th>
                    <th style="padding:3px 6px;text-align:left;font-weight:600">SERVICE / BANNER</th>
                    <th style="padding:3px 6px;text-align:left;font-weight:600">RISK</th>
                  </tr>
                </thead>
                <tbody>
                  ${visiblePorts.map(p => `
                  <tr style="border-bottom:1px solid rgba(255,255,255,0.04);">
                    <td style="padding:3px 6px;font-family:var(--font-mono);color:var(--brand-primary);font-weight:700">${p.port}</td>
                    <td style="padding:3px 6px;font-family:var(--font-mono);color:var(--text-muted);font-size:10px">${(p.protocol || 'tcp').toUpperCase()}</td>
                    <td style="padding:3px 6px;color:var(--text-secondary);max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${p.service || ''}">${p.service || '—'}</td>
                    <td style="padding:3px 6px;"><span class="badge ${p.risk_level === 'High' ? 'badge-high' : p.risk_level === 'Medium' ? 'badge-medium' : 'badge-low'}" style="font-size:9px">${p.risk_level}</span></td>
                  </tr>`).join('')}
                  ${ports.length > 6 ? `<tr><td colspan="4" style="padding:4px 6px;color:var(--text-muted);font-size:10px">+${ports.length - 6} more ports — see full inventory</td></tr>` : ''}
                </tbody>
              </table>` : `<div style="font-size:10.5px;color:var(--text-muted);margin-top:6px;padding:4px 0">No open ports detected</div>`;

            return `
              <div class="scan-result-item" style="flex-direction:column;align-items:flex-start;gap:6px;">
                <div style="display:flex;align-items:center;gap:10px;width:100%;">
                  <div style="width:28px;height:28px;border-radius:6px;background:${style.bg};border:1px solid ${style.border};color:${style.color};display:flex;align-items:center;justify-content:center;font-size:12px;flex-shrink:0;">
                    <i class="fa-solid ${style.icon}"></i>
                  </div>
                  <div style="flex:1;min-width:0">
                    <div style="font-family:var(--font-mono);font-size:12.5px;font-weight:700;color:var(--text-primary)">${d.ip_address}</div>
                    <div style="font-size:11px;color:var(--text-secondary)">${d.hostname || d.device_type} ${d.vendor ? '• ' + d.vendor : ''}</div>
                  </div>
                  <div style="display:flex;align-items:center;gap:6px;flex-shrink:0;">
                    ${d.uptime && d.uptime !== 'Unknown / Security Firewalled' ? `<span style="font-size:10px;color:var(--text-muted);font-family:var(--font-mono)"><i class="fa-solid fa-clock" style="margin-right:3px"></i>${d.uptime}</span>` : ''}
                    <span class="badge ${d.status === 'up' ? 'badge-online' : 'badge-offline'}">${d.status === 'up' ? 'Up' : 'Down'}</span>
                  </div>
                </div>
                ${portsTable}
              </div>
            `;
        }).join('');
    } catch (e) { }
}

function resetScanUI() {
    startScanBtn.disabled  = false;
    startScanBtn.innerHTML = '<i class="fa-solid fa-satellite-dish"></i><span>Launch Scan</span>';
    if (abortScanBtn) abortScanBtn.style.display = 'none';
}

// ─── Exports ──────────────────────────────────────────────────────────────────
async function triggerExport(format) {
    try {
        toast(`Exporting security database logs to ${format.toUpperCase()}…`, 'info');
        const res = await ApiClient.exportData(format);
        if (!res.ok) { toast(`Export failed: ${res.statusText}`, 'error'); return; }
        const blob = await res.blob();
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement('a');
        a.href     = url;
        a.download = `guardnet_export_${new Date().toISOString().slice(0,10)}.${format}`;
        a.click();
        URL.revokeObjectURL(url);
        toast(`${format.toUpperCase()} audit log exported successfully.`, 'success');
    } catch (e) {
        toast(`Export failed: ${e.message}`, 'error');
    }
}

$('export-json').addEventListener('click', () => triggerExport('json'));
$('export-csv').addEventListener('click',  () => triggerExport('csv'));
$('export-pdf').addEventListener('click',  () => triggerExport('pdf'));

// ─── Real-time Bandwidth Polling ─────────────────────────────────────────────
let _bandwidthInterval = null;

function startBandwidthPolling() {
    if (_bandwidthInterval) clearInterval(_bandwidthInterval);

    async function refreshBandwidth() {
        try {
            const bw = await ApiClient.getBandwidth();
            const rx = parseFloat(bw.download_mbps || 0).toFixed(2);
            const tx = parseFloat(bw.upload_mbps   || 0).toFixed(2);

            // Header bandwidth indicators (inside router info card)
            const dashDown = $('dash-down-speed');
            const dashUp   = $('dash-up-speed');
            if (dashDown) dashDown.textContent = rx;
            if (dashUp)   dashUp.textContent   = tx;

            // Router analytics section speeds
            if (routerDown) routerDown.textContent = rx;
            if (routerUp)   routerUp.textContent   = tx;

            // Ensure analytics section is visible
            if (routerAnalyticsSec) routerAnalyticsSec.style.display = 'block';
        } catch (_) {
            // Bandwidth polling is optional — fail silently
        }
    }

    refreshBandwidth(); // Immediate first call
    _bandwidthInterval = setInterval(refreshBandwidth, 2000);
}

// ─── Network Change Detection ─────────────────────────────────────────────────
let _netHealthInterval = null;
let _isReinitializing  = false;

function startNetworkHealthMonitor() {
    if (_netHealthInterval) clearInterval(_netHealthInterval);

    _netHealthInterval = setInterval(async () => {
        if (_isReinitializing) return;
        try {
            const health = await ApiClient.getNetworkHealth();

            if (health.network_changed) {
                _isReinitializing = true;
                toast('Network change detected — refreshing connection…', 'info');

                // Update header immediately with new IP/subnet
                if (health.local_ip) headerIp.textContent     = health.local_ip;
                if (health.subnet)   headerSubnet.textContent = health.subnet;
                if (health.subnet)   detectedSubnet           = health.subnet;

                try {
                    await initAppData();
                    await loadRouterDiscovery();
                    // Restart bandwidth baseline after network switch
                    if (_bandwidthInterval) clearInterval(_bandwidthInterval);
                    startBandwidthPolling();
                    toast('Network reconnected. Dashboard refreshed.', 'success');
                } catch (e) {
                    setOnline(false);
                } finally {
                    _isReinitializing = false;
                }
            } else {
                setOnline(health.connected !== false);
            }
        } catch (e) {
            // Only mark offline on persistent failure — one miss is acceptable
        }
    }, 12000); // Check every 12 seconds
}

// ─── Discovery Diagnostics Panel ─────────────────────────────────────────────

let _diagnosticsLoaded = false;

function initDiagnosticsToggle() {
    const toggle = $('diagnostics-toggle');
    const body   = $('diagnostics-body');
    const chev   = $('diagnostics-chevron');
    if (!toggle) return;

    toggle.addEventListener('click', () => {
        const open = body.style.display !== 'none';
        body.style.display = open ? 'none' : 'block';
        chev.style.transform = open ? 'rotate(0deg)' : 'rotate(180deg)';
        if (!open && !_diagnosticsLoaded) {
            _diagnosticsLoaded = true;
            loadDiagnostics();
        }
    });
}

async function loadDiagnostics() {
    const grid = $('diagnostics-grid');
    if (!grid) return;
    grid.innerHTML = '<div style="text-align:center;padding:24px;color:var(--text-muted)"><i class="fa-solid fa-circle-notch spin"></i> Loading diagnostics…</div>';

    try {
        const d = await ApiClient.getDiagnostics();

        const boolBadge = (val, trueLabel, falseLabel, trueClass = 'badge-online', falseClass = 'badge-offline') =>
            val ? `<span class="badge ${trueClass}">${trueLabel}</span>`
                : `<span class="badge ${falseClass}">${falseLabel}</span>`;

        const row = (label, value) => `
          <div style="display:flex;justify-content:space-between;align-items:center;padding:7px 0;border-bottom:1px solid var(--border);">
            <span style="font-size:12px;color:var(--text-secondary)">${label}</span>
            <span style="font-size:12px;font-weight:600;color:var(--text-primary);text-align:right;max-width:55%;word-break:break-all">${value}</span>
          </div>`;

        grid.innerHTML = `
          <!-- Adapter Info -->
          <div class="card" style="padding:14px;border:1px solid var(--border);">
            <div style="font-size:12px;font-weight:700;color:var(--brand-primary);margin-bottom:10px;letter-spacing:0.05em">
              <i class="fa-solid fa-network-wired" style="margin-right:6px"></i>ACTIVE ADAPTER
            </div>
            ${row('Adapter Name', d.adapter_name || '—')}
            ${row('Local IP', d.local_ip || '—')}
            ${row('Gateway', d.gateway || '—')}
            ${row('Subnet', d.detected_subnet || '—')}
            ${row('Netmask', d.netmask || '—')}
            ${row('DNS Server', d.dns_server || '—')}
            ${row('Detection Method', d.detection_method || '—')}
          </div>

          <!-- Capabilities -->
          <div class="card" style="padding:14px;border:1px solid var(--border);">
            <div style="font-size:12px;font-weight:700;color:var(--brand-primary);margin-bottom:10px;letter-spacing:0.05em">
              <i class="fa-solid fa-microchip" style="margin-right:6px"></i>SCAN CAPABILITIES
            </div>
            ${row('Admin/Root Privileges', boolBadge(d.is_admin, 'Admin Mode', 'Standard Mode', 'badge-online', 'badge-medium'))}
            ${row('Nmap Engine', boolBadge(d.nmap_available, 'Available', 'Not Found', 'badge-online', 'badge-offline'))}
            ${d.nmap_available ? row('Nmap Path', `<code style="font-size:10px">${d.nmap_path}</code>`) : ''}
            ${row('Npcap Driver', boolBadge(d.npcap_available, 'Installed', 'Not Installed', 'badge-online', 'badge-medium'))}
            ${row('ARP Host Discovery', boolBadge(true, 'Active', 'Unavailable'))}
            ${row('ARP Table Hosts', `<strong style="color:var(--brand-primary)">${d.arp_hosts || 0}</strong>`)}
            ${row('ICMP Ping', boolBadge(d.is_admin, 'Available', 'Requires Admin', 'badge-online', 'badge-medium'))}
          </div>

          <!-- ARP Discovered Hosts -->
          ${d.arp_host_list?.length ? `
          <div class="card" style="padding:14px;border:1px solid var(--border);grid-column:span 2">
            <div style="font-size:12px;font-weight:700;color:var(--brand-primary);margin-bottom:10px;letter-spacing:0.05em">
              <i class="fa-solid fa-sitemap" style="margin-right:6px"></i>ARP-VISIBLE HOSTS (${d.arp_host_list.length} total — immediately reachable without scanning)
            </div>
            <div style="display:flex;flex-wrap:wrap;gap:6px;">
              ${d.arp_host_list.map(ip => `<code style="font-size:11.5px;background:var(--bg-input);padding:4px 8px;border-radius:6px;border:1px solid var(--border);font-family:var(--font-mono)">${ip}</code>`).join('')}
            </div>
          </div>` : ''}

          <!-- Limitations -->
          <div class="card" style="padding:14px;border:1px solid rgba(251,191,36,0.25);background:rgba(251,191,36,0.05);grid-column:span 2">
            <div style="font-size:12px;font-weight:700;color:#fbbf24;margin-bottom:10px;letter-spacing:0.05em">
              <i class="fa-solid fa-triangle-exclamation" style="margin-right:6px"></i>KNOWN DISCOVERY LIMITATIONS
            </div>
            <ul style="display:flex;flex-direction:column;gap:6px;padding-left:18px;margin:0">
              ${(d.limitations || []).map(l => `<li style="font-size:12px;color:var(--text-secondary);line-height:1.5">${l}</li>`).join('')}
            </ul>
          </div>
        `;
    } catch (e) {
        grid.innerHTML = '<div style="grid-column: 1 / -1; text-align:center; padding:24px; color:var(--text-muted)">Failed to load diagnostics.</div>';
    }
}

// Reload diagnostics when scanner tab is opened (if already expanded)
function refreshDiagnosticsIfOpen() {
    const body = $('diagnostics-body');
    if (body && body.style.display !== 'none') {
        loadDiagnostics();
    }
}

// ─── Session Exit Modal ───────────────────────────────────────────────────────
function initSessionExit() {
    let _exitHandled = false;

    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'hidden' && !_exitHandled) {
            const modal = document.getElementById('session-exit-modal');
            if (modal) modal.style.display = 'flex';
        }
    });

    window.addEventListener('beforeunload', (e) => {
        if (_exitHandled) return;
        const modal = document.getElementById('session-exit-modal');
        if (!modal) return;
        modal.style.display = 'flex';
        e.preventDefault();
        e.returnValue = '';
        return '';
    });

    window._markExitHandled = () => { _exitHandled = true; };
}

// Update DEVICE_ICONS to include NAS and IP Camera (from new classifier)
DEVICE_ICONS['NAS']             = { icon: 'fa-box-archive',      bg: 'rgba(236,72,153,0.12)',  border: 'rgba(236,72,153,0.25)',  color: '#ec4899' };
DEVICE_ICONS['IP Camera']       = { icon: 'fa-video',            bg: 'rgba(14,116,144,0.12)',  border: 'rgba(14,116,144,0.25)',  color: '#0e7490' };
DEVICE_ICONS['Router / Gateway']= { icon: 'fa-router',           bg: 'rgba(99,102,241,0.12)',  border: 'rgba(99,102,241,0.25)',  color: '#818cf8' };
DEVICE_ICONS['Tablet']          = { icon: 'fa-tablet-screen-button', bg: 'rgba(6,182,212,0.12)', border: 'rgba(6,182,212,0.25)', color: '#06b6d4' };
DEVICE_ICONS['Streaming Device']= { icon: 'fa-tv',               bg: 'rgba(249,115,22,0.12)',  border: 'rgba(249,115,22,0.25)',  color: '#fb923c' };
DEVICE_ICONS['Network Infrastructure'] = { icon: 'fa-sitemap',   bg: 'rgba(129,140,248,0.12)', border: 'rgba(129,140,248,0.25)', color: '#818cf8' };

// ─── Init ─────────────────────────────────────────────────────────────────────
async function init() {
    initTheme();
    initMobileSidebar();
    initDiagnosticsToggle();
    await initAppData();
    await loadRouterDiscovery();
    startBandwidthPolling();
    startNetworkHealthMonitor();
    startHeartbeat();
    initSessionExit();
    loadWanIp();
}

// ─── WAN IP Display ───────────────────────────────────────────────────────────
async function loadWanIp() {
    try {
        const data = await ApiClient.getNetworkInfo();
        const wanIp = data?.wan_ip || null;
        const el = document.getElementById('wan-ip-pill');
        if (el && wanIp && wanIp !== 'No Internet Access') {
            el.style.display = 'flex';
            const strong = document.getElementById('wan-ip-value');
            if (strong) strong.textContent = wanIp;
        }
    } catch (_) {}
}

// ─── Heartbeat (keep-alive ping every 5 seconds) ─────────────────────────────
let _hbMissed = 0;
function startHeartbeat() {
    const dot = document.getElementById('hb-dot');
    setInterval(async () => {
        try {
            await fetch('/api/heartbeat', { method: 'POST' });
            _hbMissed = 0;
            if (dot) { dot.className = 'hb-dot'; }
        } catch (_) {
            _hbMissed++;
            if (dot && _hbMissed >= 2) dot.className = 'hb-dot dead';
        }
    }, 5000);
}


window.sessionExit = async function(action) {
    const modal = document.getElementById('session-exit-modal');
    if (window._markExitHandled) window._markExitHandled();
    window.onbeforeunload = null;
    try {
        await fetch('/api/session', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action })
        });
    } catch (_) {}
    if (action === 'background') {
        if (modal) modal.style.display = 'none';
        toast('GuardNet running in background.', 'info');
    } else {
        window.onbeforeunload = null;
        window.close();
    }
};

// ─── Custom Select Logic ─────────────────────────────────────────────────────
function setupCustomSelect(dropdownId, inputId, onChange) {
    const dropdown = document.getElementById(dropdownId);
    if (!dropdown) return;
    const trigger = dropdown.querySelector('.custom-select-trigger');
    const options = dropdown.querySelectorAll('.custom-option');
    const input = document.getElementById(inputId);
    const textSpan = trigger.querySelector('span');

    trigger.addEventListener('click', (e) => {
        e.stopPropagation();
        document.querySelectorAll('.custom-select').forEach(el => {
            if (el !== dropdown) el.classList.remove('open');
        });
        dropdown.classList.toggle('open');
    });

    options.forEach(opt => {
        opt.addEventListener('click', () => {
            options.forEach(o => o.classList.remove('selected'));
            opt.classList.add('selected');
            textSpan.innerHTML = opt.innerHTML; // preserve icons
            input.value = opt.dataset.value;
            dropdown.classList.remove('open');
            if (onChange) onChange(input.value);
        });
    });
}

document.addEventListener('click', () => {
    document.querySelectorAll('.custom-select').forEach(el => el.classList.remove('open'));
});

// Initialize custom dropdowns
function setCustomSelectValue(dropdownId, inputId, value) {
    const dropdown = document.getElementById(dropdownId);
    const input = document.getElementById(inputId);
    if (!dropdown || !input) return;
    const triggerSpan = dropdown.querySelector('.custom-select-trigger span');
    const options = dropdown.querySelectorAll('.custom-option');
    options.forEach(opt => {
        if (opt.dataset.value === value) {
            opt.classList.add('selected');
            if (triggerSpan) triggerSpan.innerHTML = opt.innerHTML;
            input.value = value;
        } else {
            opt.classList.remove('selected');
        }
    });
}

setupCustomSelect('scan-profile-dropdown', 'scan-profile', (val) => {
    const hint = PROFILE_HINTS[val] || '';
    const hintEl = $('profile-hint');
    if (hintEl) hintEl.textContent = hint;
});
setupCustomSelect('alerts-filter-dropdown', 'alerts-filter', (val) => {
    loadAlerts();
});
setupCustomSelect('settings-schedule-dropdown', 'settings-schedule');
setupCustomSelect('settings-severity-dropdown', 'smtp-min-severity');
setupCustomSelect('devices-type-dropdown', 'devices-type', loadDevices);
setupCustomSelect('devices-risk-dropdown', 'devices-risk', loadDevices);
setupCustomSelect('devices-sort-dropdown', 'devices-sort', loadDevices);

init();

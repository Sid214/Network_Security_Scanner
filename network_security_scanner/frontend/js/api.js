// GuardNet API Client — v2.6
const BASE = '';

const ApiClient = {
    async _fetch(url, opts = {}) {
        const res = await fetch(BASE + url, opts);
        if (!res.ok) {
            const err = await res.json().catch(() => ({ detail: res.statusText }));
            throw new Error(err.detail || `HTTP ${res.status}`);
        }
        return res.json();
    },

    getNetworkInfo:   ()            => ApiClient._fetch('/api/network-info'),
    getNetworkHealth: ()            => ApiClient._fetch('/api/network-health'),
    getBandwidth:     ()            => ApiClient._fetch('/api/bandwidth'),
    getDiagnostics:   ()            => ApiClient._fetch('/api/diagnostics'),
    getRouterInfo:    (sim)         => ApiClient._fetch(`/api/router-info?simulation_mode=${sim ? 'true' : 'false'}`),
    getStatistics:    ()            => ApiClient._fetch('/api/statistics'),
    getDevices:       (p = {})      => ApiClient._fetch(`/api/devices?${new URLSearchParams(p)}`),
    getDevice:        (id)          => ApiClient._fetch(`/api/device/${id}`),
    getAlerts:        (unresolved)  => ApiClient._fetch(`/api/alerts${unresolved ? '?unresolved=true' : ''}`),
    resolveAlert:     (id)          => ApiClient._fetch(`/api/alerts/${id}/resolve`, { method: 'POST' }),
    getHistory:       ()            => ApiClient._fetch('/api/history'),
    getScanDetails:   (id)          => ApiClient._fetch(`/api/scan/${id}/details`),
    deleteScan:       (id)          => ApiClient._fetch(`/api/scan/${id}`, { method: 'DELETE' }),
    deleteSelected:   (ids)         => ApiClient._fetch('/api/history/delete-selected', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scan_ids: ids })
    }),
    clearAllHistory:  ()            => ApiClient._fetch('/api/history/clear-all', { method: 'POST' }),
    getSettings:      ()            => ApiClient._fetch('/api/settings'),
    saveSettings:     (settings)    => ApiClient._fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ settings })
    }),
    testEmail:        (settings)    => ApiClient._fetch('/api/settings/test-email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ settings })
    }),
    // simulation_mode parameter removed — all scans are live Nmap
    startScan: (target, scan_type) => ApiClient._fetch('/api/scan/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, scan_type, simulation_mode: false })
    }),
    deleteDevices:    (ids)         => ApiClient._fetch('/api/devices/delete-selected', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ device_ids: ids })
    }),
    clearAllDevices:  ()            => ApiClient._fetch('/api/devices/clear-all', { method: 'POST' }),
    abortScan:        (scan_id)     => ApiClient._fetch(`/api/scan/abort?scan_id=${scan_id}`, { method: 'POST' }),
    getScanStatus:    (scan_id)     => ApiClient._fetch(`/api/scan/status?scan_id=${scan_id}`),
    exportData:       (format)      => fetch(`${BASE}/api/export/${format}`),
};

export default ApiClient;

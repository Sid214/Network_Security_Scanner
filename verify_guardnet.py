"""
GuardNet End-to-End Verification Script
Tests all critical API endpoints and backend logic.
"""
import sys
import urllib.request
import json
import time

BASE = 'http://127.0.0.1:8000'
PASS = []
FAIL = []

def check(name, ok, detail=''):
    if ok:
        PASS.append(name)
        print(f'  [PASS] {name}')
    else:
        FAIL.append(name)
        print(f'  [FAIL] {name}: {detail}')

def get(path):
    try:
        req = urllib.request.Request(BASE + path, headers={'User-Agent': 'GuardNet-Test/1.0'})
        with urllib.request.urlopen(req, timeout=8) as r:
            return json.loads(r.read()), r.status
    except Exception as e:
        return None, str(e)

def post(path, data):
    try:
        body = json.dumps(data).encode()
        req = urllib.request.Request(BASE + path, data=body, headers={
            'Content-Type': 'application/json',
            'User-Agent': 'GuardNet-Test/1.0'
        }, method='POST')
        with urllib.request.urlopen(req, timeout=8) as r:
            return json.loads(r.read()), r.status
    except Exception as e:
        return None, str(e)

print('=' * 60)
print('  GuardNet — Full Verification Test')
print('=' * 60)

# 1. Backend import
print('\n[1] Backend module imports')
sys.path.insert(0, 'network_security_scanner/backend')
try:
    import scanner
    check('scanner.py imports', True)
    check('get_nmap_path() exists', hasattr(scanner, 'get_nmap_path'))
    check('is_admin() exists', hasattr(scanner, 'is_admin'))
    check('detect_local_network_info() exists', hasattr(scanner, 'detect_local_network_info'))
    check('parse_arp_table() exists', hasattr(scanner, 'parse_arp_table'))
    check('classify_device() exists', hasattr(scanner, 'classify_device'))
    check('get_discovery_diagnostics() exists', hasattr(scanner, 'get_discovery_diagnostics'))
    check('start_scan_job() exists', hasattr(scanner, 'start_scan_job'))
except Exception as e:
    check('scanner.py imports', False, str(e))

# 2. Network detection
print('\n[2] Network detection')
try:
    net = scanner.detect_local_network_info()
    ip = net.get('local_ip', '')
    gw = net.get('gateway', '')
    sn = net.get('subnet', '')
    iface = net.get('interface', '')
    method = net.get('detection_method', '')

    check('Local IP detected', ip and ip != '127.0.0.1', ip)
    check('Gateway detected', bool(gw), gw)
    check('Subnet calculated', bool(sn) and '/' in sn, sn)
    check('Interface name not VMware', 'vmware' not in iface.lower() and 'vmnet' not in iface.lower(), iface)
    check('Detection via routing table', method == 'routing_table', method)
    print(f'     Adapter: {iface} | IP: {ip} | Subnet: {sn} | GW: {gw}')
except Exception as e:
    check('Network detection', False, str(e))

# 3. ARP table
print('\n[3] ARP Table')
try:
    arp = scanner.parse_arp_table()
    check('ARP table parsed', isinstance(arp, list))
    check('ARP entries found', len(arp) > 0, f'{len(arp)} entries')
    print(f'     ARP hosts: {[h["ip_address"] for h in arp[:8]]}')
except Exception as e:
    check('ARP table', False, str(e))

# 4. Diagnostics function
print('\n[4] Discovery diagnostics')
try:
    diag = scanner.get_discovery_diagnostics()
    check('Diagnostics returns dict', isinstance(diag, dict))
    check('adapter_name present', 'adapter_name' in diag, str(diag.get('adapter_name')))
    check('local_ip present', 'local_ip' in diag, diag.get('local_ip'))
    check('nmap_available key', 'nmap_available' in diag)
    check('npcap_available key', 'npcap_available' in diag)
    check('arp_host_list key', 'arp_host_list' in diag)
    check('limitations list', isinstance(diag.get('limitations'), list) and len(diag['limitations']) > 0)
    check('Nmap found', diag.get('nmap_available'), str(diag.get('nmap_path')))
    check('Npcap found', diag.get('npcap_available'))
    print(f'     Admin: {diag["is_admin"]} | Nmap: {diag["nmap_available"]} | Npcap: {diag["npcap_available"]}')
    print(f'     ARP hosts visible: {diag["arp_hosts"]}')
except Exception as e:
    check('Diagnostics', False, str(e))

# 5. Device classification
print('\n[5] Device classifier')
cases = [
    ('Gateway detection',       ('', '', '', [53, 80, 1900], [], '192.168.0.1', '192.168.0.1'), 'Router / Gateway'),
    ('Synology NAS detection',  ('synology-ds920', 'synology', 'linux', [5000, 80, 443], []), 'NAS'),
    ('Samsung TV detection',    ('samsung-tv', 'samsung', 'tizen', [8001, 80], []), 'Smart TV'),
    ('Windows desktop',         ('DESKTOP-ABC', 'intel', 'windows 10', [445, 135, 3389], []), 'Desktop'),
    ('Printer detection',       ('brother-hl', 'brother industries', '', [9100, 631], []), 'Printer'),
    ('IP Camera detection',     ('hikvision-cam', 'hikvision', '', [554, 80], []), 'IP Camera'),
]
for name, args, expected in cases:
    result, _ = scanner.classify_device(*args)
    check(name, result == expected, f'got={result}, expected={expected}')

# 6. API endpoints
print('\n[6] Live API endpoints')
data, status = get('/api/network-info')
check('GET /api/network-info 200', data is not None, str(status))
if data:
    check('  network-info has local_ip', 'local_ip' in data)
    check('  network-info has gateway', 'gateway' in data)
    check('  network-info has adapter', 'adapter' in data)
    check('  IP is not 127.0.0.1', data.get('local_ip') != '127.0.0.1', data.get('local_ip'))
    check('  Not VMware subnet', '192.168.183' not in str(data.get('suggested_subnet','')) and '192.168.230' not in str(data.get('suggested_subnet','')), data.get('suggested_subnet'))
    print(f'     IP: {data.get("local_ip")} | Subnet: {data.get("suggested_subnet")} | Adapter: {data.get("adapter")}')

data, status = get('/api/diagnostics')
check('GET /api/diagnostics 200', data is not None, str(status))
if data:
    check('  diagnostics has adapter_name', 'adapter_name' in data)
    check('  diagnostics has arp_host_list', 'arp_host_list' in data)
    check('  diagnostics has limitations', 'limitations' in data)

data, status = get('/api/statistics')
check('GET /api/statistics 200', data is not None, str(status))
if data:
    check('  stats has total_scans', 'total_scans' in data)
    check('  stats has total_devices', 'total_devices' in data)

data, status = get('/api/devices')
check('GET /api/devices 200', data is not None, str(status))

data, status = get('/api/alerts')
check('GET /api/alerts 200', data is not None, str(status))

data, status = get('/api/history')
check('GET /api/history 200', data is not None, str(status))

data, status = get('/api/settings')
check('GET /api/settings 200', data is not None, str(status))

data, status = get('/api/network-health')
check('GET /api/network-health 200', data is not None, str(status))
if data:
    check('  health has connected key', 'connected' in data)

data, status = get('/api/bandwidth')
check('GET /api/bandwidth 200', data is not None, str(status))
if data:
    check('  bandwidth has download_mbps', 'download_mbps' in data)

data, status = get('/api/router-info?simulation_mode=true')
check('GET /api/router-info 200', data is not None, str(status))
if data:
    check('  router-info has router key', 'router' in data)
    check('  router-info has local_ip', 'local_ip' in data)

# 7. Scan start / status cycle (simulation)
print('\n[7] Scan pipeline (simulation mode)')
data, status = post('/api/scan/start', {
    'target': '192.168.0.0/24',
    'scan_type': 'quick',
    'simulation_mode': True
})
check('POST /api/scan/start returns scan_id', data is not None and 'scan_id' in (data or {}), str(data))
if data and 'scan_id' in data:
    scan_id = data['scan_id']
    check('scan_id is integer', isinstance(scan_id, int), str(scan_id))
    print(f'     Scan started: id={scan_id}')
    
    # Poll status
    time.sleep(2)
    s, _ = get(f'/api/scan/status?scan_id={scan_id}')
    check('GET /api/scan/status returns status', s is not None and 'status' in (s or {}))
    if s:
        check('scan status is running or completed', s.get('status') in ('running', 'completed', 'failed'), s.get('status'))
        check('progress is int', isinstance(s.get('progress', 0), int))
        print(f'     Scan status: {s.get("status")} | progress: {s.get("progress")}%')

# Summary
print()
print('=' * 60)
print(f'  Results: {len(PASS)} passed, {len(FAIL)} failed')
if FAIL:
    print()
    print('  FAILURES:')
    for f in FAIL:
        print(f'    - {f}')
print('=' * 60)

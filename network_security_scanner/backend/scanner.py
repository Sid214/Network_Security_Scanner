"""
GuardNet Scanner Engine v4.0 - Complete Rewrite
Uses thread-based subprocess scanning, Scapy ARP sweep, MAC randomization detection.
"""
import subprocess, shutil, os, re, xml.etree.ElementTree as ET
import threading, time, socket, platform, json, datetime, ipaddress
import ctypes, struct
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Any, Optional, Tuple, Union

_EVENT_LOOP = None
def set_event_loop(loop):
    global _EVENT_LOOP
    _EVENT_LOOP = loop

try:
    from . import database
except ImportError:
    import database

PROGRESS_LOCK = threading.Lock()
SCAN_PROGRESS: Dict[int, Dict[str, Any]] = {}
_ACTIVE_PROCESSES: Dict[int, subprocess.Popen] = {}
_ABORT_EVENTS: Dict[int, threading.Event] = {}

def get_progress(scan_id: int) -> Dict[str, Any]:
    with PROGRESS_LOCK:
        return dict(SCAN_PROGRESS.get(scan_id, {"progress": 0, "logs": ["Scan not found"], "status": "failed"}))

def _update(scan_id: int, progress: int = None, log: str = None, status: str = None):
    with PROGRESS_LOCK:
        if scan_id not in SCAN_PROGRESS:
            SCAN_PROGRESS[scan_id] = {"progress": 0, "logs": [], "status": "running"}
        if progress is not None:
            SCAN_PROGRESS[scan_id]["progress"] = progress
        if log is not None:
            ts = time.strftime("%H:%M:%S")
            SCAN_PROGRESS[scan_id]["logs"].append(f"[{ts}] {log}")
        if status is not None:
            SCAN_PROGRESS[scan_id]["status"] = status

def abort_scan(scan_id: int) -> bool:
    event = _ABORT_EVENTS.get(scan_id)
    if event:
        event.set()
    proc = _ACTIVE_PROCESSES.get(scan_id)
    if proc:
        try:
            proc.kill()
        except Exception:
            pass
        return True
    return bool(event)

def is_scan_aborted(scan_id: int) -> bool:
    event = _ABORT_EVENTS.get(scan_id)
    return event.is_set() if event else False

def get_nmap_path() -> Optional[str]:
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    candidate = os.path.join(root, "tools", "nmap", "nmap.exe" if platform.system() == "Windows" else "nmap")
    if os.path.isfile(candidate):
        return candidate
    in_path = shutil.which("nmap")
    if in_path:
        return in_path
    if platform.system() == "Windows":
        for p in [r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe",
                  r"D:\Program Files\Nmap\nmap.exe", r"D:\Program Files (x86)\Nmap\nmap.exe"]:
            if os.path.isfile(p):
                return p
    return None

def is_admin() -> bool:
    return True

# --- MAC Randomization Detection ---
def is_randomized_mac(mac: str) -> bool:
    """Detect locally-administered (randomized) MACs via the LA bit (bit 1 of first byte)."""
    if not mac:
        return False
    try:
        first_byte = int(mac.replace(":", "").replace("-", "")[:2], 16)
        return bool(first_byte & 0x02)
    except Exception:
        return False

def get_mac_vendor(mac: str) -> Optional[str]:
    if not mac or is_randomized_mac(mac):
        return None
    normalized = mac.upper().replace("-", ":").replace(".", ":")
    parts = re.split(r"[:\-\.]", normalized)
    if len(parts) < 3:
        return None
    oui = ":".join(parts[:3]).upper()
    OUI_DB = {
        "00:00:0C": "Cisco Systems", "00:1A:2B": "Cisco Systems", "5C:50:15": "Cisco Systems",
        "78:BC:1A": "Cisco Systems", "88:F0:31": "Cisco Systems", "00:0E:38": "Cisco Systems",
        "00:50:56": "VMware", "00:0C:29": "VMware", "00:15:5D": "Microsoft Hyper-V",
        "00:03:FF": "Microsoft", "28:18:78": "Microsoft",
        "B8:27:EB": "Raspberry Pi Foundation", "DC:A6:32": "Raspberry Pi Foundation",
        "E4:5F:01": "Raspberry Pi Foundation", "2C:CF:67": "Raspberry Pi Foundation",
        "00:50:B6": "Intel Corporation", "E0:D9:E3": "Intel Corporation",
        "00:1B:21": "Intel Corporation", "48:45:20": "Intel Corporation",
        "8C:EC:4B": "Intel Corporation",
        "A4:C3:F0": "Apple", "AC:BC:32": "Apple", "00:03:93": "Apple",
        "3C:D9:2B": "Hewlett-Packard", "00:01:30": "Hewlett-Packard",
        "00:17:A4": "Hewlett-Packard Enterprise", "FC:15:B4": "Hewlett-Packard Enterprise",
        "3C:4A:92": "Hewlett-Packard", "5C:B9:01": "Hewlett-Packard",
        "00:01:E6": "Hewlett-Packard", "00:22:64": "Hewlett-Packard",
        "70:8B:CD": "Sony Interactive Entertainment",
        "B8:81:98": "Samsung Electronics", "F4:7B:5E": "Samsung Electronics",
        "00:22:68": "Dell Inc.", "18:03:73": "Dell Inc.",
        "1C:C1:DE": "Dell Inc.", "14:18:77": "Dell Inc.", "00:11:43": "Dell Inc.",
        "E4:8D:8C": "Netgear", "20:E5:2A": "Netgear", "00:26:44": "Netgear",
        "10:0C:6B": "Netgear", "20:4E:7F": "Netgear", "30:46:9A": "Netgear",
        "4C:60:DE": "Netgear", "6C:B0:CE": "Netgear", "84:1B:5E": "Netgear",
        "9C:D3:6D": "Netgear", "A0:21:B7": "Netgear", "C0:3F:0E": "Netgear",
        "50:91:E3": "TP-Link Technologies", "C4:6E:1F": "TP-Link Technologies",
        "A0:F3:C1": "TP-Link Technologies", "60:E3:27": "TP-Link Technologies",
        "D4:D2:52": "TP-Link Technologies", "B0:FA:EB": "TP-Link",
        "7C:8B:CA": "TP-Link", "F8:1A:67": "TP-Link", "A4:2B:B0": "TP-Link",
        "14:CC:20": "TP-Link", "74:EA:3A": "TP-Link", "B0:BE:76": "TP-Link",
        "9C:21:6A": "TP-Link", "18:D6:C7": "TP-Link", "98:DE:D0": "TP-Link",
        "FC:EC:DA": "Ubiquiti Networks", "80:2A:A8": "Ubiquiti Networks",
        "00:15:6D": "Ubiquiti Networks", "24:A4:3C": "Ubiquiti Networks",
        "78:8A:20": "Ubiquiti Networks",
        "00:90:A9": "Western Digital", "00:14:EE": "Western Digital",
        "94:62:6D": "Xiaomi Communications", "98:F6:21": "Xiaomi Communications",
        "64:13:6C": "Xiaomi Communications", "AC:C1:EE": "Xiaomi", "7C:7A:91": "Xiaomi",
        "00:E0:4C": "Realtek Semiconductor", "52:54:00": "QEMU/KVM Virtual",
        "B4:75:0E": "ASUS", "04:D4:C4": "ASUS", "1C:87:2C": "ASUS",
        "F8:32:E4": "ASUS", "90:9F:33": "ASUS",
        "D8:50:E6": "D-Link", "28:10:7B": "D-Link", "74:DA:38": "D-Link",
        "1C:BD:B9": "D-Link", "00:19:5B": "D-Link",
        "44:94:FC": "Aruba Networks", "00:0B:86": "Aruba Networks", "24:DE:C6": "Aruba Networks",
        "A8:9C:ED": "Huawei Technologies", "0C:5B:8F": "Huawei Technologies",
        "8C:25:05": "Huawei Technologies", "AC:E8:7B": "Huawei Technologies",
        "CC:96:A0": "Huawei Technologies", "00:E0:FC": "Huawei Technologies",
        "D4:6E:5C": "Huawei", "B4:86:55": "Huawei", "70:72:CF": "Huawei",
        "68:7F:74": "Huawei",
        "90:17:3F": "Synology", "00:11:32": "Synology", "BC:87:FA": "Synology",
        "00:08:9B": "QNAP Systems", "24:5E:BE": "QNAP Systems",
        "74:9E:AF": "ARRIS Group",
        "00:30:6E": "Acer", "E8:40:F2": "Acer", "74:DE:2B": "Acer",
        "00:13:E8": "Cisco-Linksys", "00:14:BF": "Linksys", "00:25:9C": "Cisco-Linksys",
        "00:13:10": "Linksys", "00:18:F8": "Linksys", "00:21:29": "Linksys",
        "00:1C:10": "Linksys", "00:23:69": "Linksys", "00:25:2E": "Linksys",
        "20:CF:30": "Linksys",
    }
    if oui in OUI_DB:
        return OUI_DB[oui]
    try:
        with database.get_db() as db:
            v = db.query(database.Vendor).filter(database.Vendor.mac_prefix == oui).first()
            if v:
                return v.name
    except Exception:
        pass
    return None

# --- Network Detection ---
_VIRTUAL_ADAPTER_PATTERNS = [
    "vmware", "vmnet", "virtualbox", "vbox", "hyper-v", "hyperv",
    "virtual ethernet", "teredo", "isatap", "6to4", "loopback",
    "vpn", "nordvpn", "expressvpn", "openvpn", "wireguard",
    "tap-", "tun0", "tun1", "docker", "wsl", "zerotier", "hamachi",
    "microsoft wi-fi direct", "wi-fi direct", "bluetooth",
    "ndis", "miniport", "wan miniport",
]

def _is_virtual_adapter(name: str) -> bool:
    return any(p in name.lower() for p in _VIRTUAL_ADAPTER_PATTERNS)

def _get_default_route_interface() -> Optional[Dict[str, str]]:
    try:
        out = subprocess.check_output(["route", "print", "-4"], stderr=subprocess.DEVNULL, timeout=5).decode("utf-8", errors="ignore")
        best, best_metric = None, None
        for line in out.splitlines():
            m = re.match(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)", line.strip())
            if m:
                gw, ip, metric = m.group(1), m.group(2), int(m.group(3))
                if best_metric is None or metric < best_metric:
                    best_metric = metric
                    best = {"interface_ip": ip, "gateway": gw, "metric": metric}
        return best
    except Exception:
        return None

def _get_interface_info_from_psutil(target_ip: str) -> Optional[Dict[str, Any]]:
    try:
        import psutil
        for iface_name, iface_addrs in psutil.net_if_addrs().items():
            for addr in iface_addrs:
                if addr.family == socket.AF_INET and addr.address == target_ip:
                    stats = psutil.net_if_stats().get(iface_name)
                    return {"name": iface_name, "ip": target_ip,
                            "netmask": addr.netmask or "255.255.255.0",
                            "is_up": stats.isup if stats else True}
    except Exception:
        pass
    return None

def _calculate_subnet_cidr(ip: str, netmask: str) -> str:
    try:
        return str(ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False))
    except Exception:
        parts = ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24" if len(parts) == 4 else "192.168.0.0/24"

def detect_local_network_info() -> Dict[str, Any]:
    result = {"local_ip": "127.0.0.1", "gateway": None, "subnet": "192.168.0.0/24",
              "dns_server": None, "interface": "Unknown", "adapter": "Unknown",
              "netmask": "255.255.255.0", "all_subnets": [], "detection_method": "fallback"}
    route = _get_default_route_interface()
    if route:
        iface_ip, gw = route["interface_ip"], route["gateway"]
        info = _get_interface_info_from_psutil(iface_ip)
        if info:
            mask = info["netmask"]
            subnet = _calculate_subnet_cidr(iface_ip, mask)
            result.update({"local_ip": iface_ip, "gateway": gw, "interface": info["name"],
                           "adapter": info["name"], "netmask": mask, "subnet": subnet,
                           "detection_method": "routing_table"})
            if subnet not in result["all_subnets"]:
                result["all_subnets"].append(subnet)
        else:
            parts = iface_ip.split(".")
            subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24" if len(parts) == 4 else "192.168.0.0/24"
            result.update({"local_ip": iface_ip, "gateway": gw, "subnet": subnet,
                           "detection_method": "routing_table_partial"})
            if subnet not in result["all_subnets"]:
                result["all_subnets"].append(subnet)
    if result["local_ip"] == "127.0.0.1":
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(1.0)
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
                if ip and not ip.startswith("127."):
                    parts = ip.split(".")
                    subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                    result.update({"local_ip": ip, "subnet": subnet, "detection_method": "udp_socket"})
                    if subnet not in result["all_subnets"]:
                        result["all_subnets"].append(subnet)
        except Exception:
            pass
    try:
        if platform.system() == "Windows":
            out = subprocess.check_output(["ipconfig", "/all"], stderr=subprocess.DEVNULL, timeout=5).decode("utf-8", errors="ignore")
            for line in out.splitlines():
                stripped = line.strip()
                if "dns servers" in stripped.lower():
                    m = re.search(r"(\d+\.\d+\.\d+\.\d+)", stripped)
                    if m and not m.group(1).startswith("127."):
                        result["dns_server"] = m.group(1)
                        break
                if not result["gateway"] and "default gateway" in stripped.lower():
                    m = re.search(r"(\d+\.\d+\.\d+\.\d+)", stripped)
                    if m and not m.group(1).startswith("0."):
                        result["gateway"] = m.group(1)
    except Exception:
        pass
    if not result["dns_server"]:
        result["dns_server"] = result.get("gateway") or "8.8.8.8"
    if result["local_ip"] not in ("127.0.0.1", None) and result.get("netmask"):
        try:
            cs = _calculate_subnet_cidr(result["local_ip"], result["netmask"])
            result["subnet"] = cs
            if cs not in result["all_subnets"]:
                result["all_subnets"].insert(0, cs)
        except Exception:
            pass
    return result

def get_wan_ip() -> Optional[str]:
    import urllib.request
    for url in ["https://api.ipify.org?format=json", "https://icanhazip.com"]:
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "GuardNet/4.0"}), timeout=2) as r:
                text = r.read().decode().strip()
                return json.loads(text).get("ip") if url.endswith("json") else text
        except Exception:
            continue
    return None

import psutil
import urllib.request

_LAST_NET_IO = {"rx": 0, "tx": 0, "time": 0.0}
_BANDWIDTH_LOCK = threading.Lock()

def init_bandwidth_baseline():
    global _LAST_NET_IO
    with _BANDWIDTH_LOCK:
        try:
            io = psutil.net_io_counters()
            _LAST_NET_IO = {"rx": io.bytes_recv, "tx": io.bytes_sent, "time": time.time()}
        except Exception:
            pass

def get_realtime_bandwidth() -> Tuple[float, float]:
    global _LAST_NET_IO
    now = time.time()
    with _BANDWIDTH_LOCK:
        try:
            io = psutil.net_io_counters()
            rx, tx = io.bytes_recv, io.bytes_sent
            dt = now - _LAST_NET_IO["time"]
            if dt >= 0.5 and _LAST_NET_IO["time"] > 0:
                rx_s = max(0.0, round(((rx - _LAST_NET_IO["rx"]) * 8) / (dt * 1_000_000), 2))
                tx_s = max(0.0, round(((tx - _LAST_NET_IO["tx"]) * 8) / (dt * 1_000_000), 2))
            else:
                rx_s = tx_s = 0.0
            _LAST_NET_IO = {"rx": rx, "tx": tx, "time": now}
            return rx_s, tx_s
        except Exception:
            return 0.0, 0.0

# --- Scapy ARP Sweep ---
def perform_scapy_arp_sweep(subnet: str) -> List[Dict[str, str]]:
    """Active ARP broadcast sweep. Bypasses ICMP blocking, gets real MACs."""
    results = []
    try:
        from scapy.all import ARP, Ether, srp
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
                     timeout=3, retry=2, verbose=False)
        for _, rcv in ans:
            ip = rcv.psrc
            mac = rcv.hwsrc.upper()
            randomized = is_randomized_mac(mac)
            results.append({"ip_address": ip, "mac_address": mac,
                             "vendor": None if randomized else get_mac_vendor(mac),
                             "randomized_mac": randomized})
    except ImportError:
        pass
    except Exception as e:
        print(f"[Scanner] Scapy ARP sweep error: {e}")
    return results

def parse_arp_table(target_subnet: str = None) -> List[Dict[str, str]]:
    devices: Dict[str, Dict] = {}
    target_net = None
    if target_subnet:
        try:
            target_net = ipaddress.ip_network(target_subnet, strict=False)
        except Exception:
            pass

    # Step 1: Active subnet priming via ultra-fast concurrent ping sweep
    # Forces Windows / OS kernel to emit ARP requests on the wire for every IP.
    # Every connected device (including sleeping phones with randomized MACs) replies at Layer 2
    # and populates the OS kernel ARP cache!
    if target_net and target_net.num_addresses <= 1024:
        hosts_to_sweep = [str(ip) for ip in target_net.hosts()]
        if platform.system() == "Windows":
            def _ping_host(ip_str):
                try:
                    subprocess.run(["ping", "-n", "1", "-w", "120", ip_str],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except Exception:
                    pass
            with ThreadPoolExecutor(max_workers=64) as ex:
                list(ex.map(_ping_host, hosts_to_sweep))
        else:
            def _ping_host_unix(ip_str):
                try:
                    subprocess.run(["ping", "-c", "1", "-W", "1", ip_str],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except Exception:
                    pass
            with ThreadPoolExecutor(max_workers=64) as ex:
                list(ex.map(_ping_host_unix, hosts_to_sweep))

    # Step 2: Read operating system ARP cache
    try:
        if platform.system() == "Windows":
            out = subprocess.check_output(["arp", "-a"], stderr=subprocess.DEVNULL, timeout=10).decode("utf-8", errors="ignore")
            for line in out.splitlines():
                m = re.match(r'\s*([\d\.]+)\s+([\w\-:]+)\s+(dynamic|static)', line, re.IGNORECASE)
                if m:
                    ip, mac = m.group(1), m.group(2).replace("-", ":").upper()
                    if ip.startswith("224.") or ip.startswith("239.") or ip.endswith(".255") or ip == "255.255.255.255":
                        continue
                    if target_net:
                        try:
                            if ipaddress.ip_address(ip) not in target_net:
                                continue
                        except Exception:
                            continue
                    randomized = is_randomized_mac(mac)
                    devices[ip] = {
                        "ip_address": ip,
                        "mac_address": mac,
                        "vendor": None if randomized else get_mac_vendor(mac),
                        "randomized_mac": randomized
                    }
        else:
            out = subprocess.check_output(["arp", "-n"], stderr=subprocess.DEVNULL, timeout=10).decode("utf-8", errors="ignore")
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 3 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]):
                    ip = parts[0]
                    if ip.startswith("224.") or ip.startswith("239.") or ip.endswith(".255") or ip == "255.255.255.255":
                        continue
                    if target_net:
                        try:
                            if ipaddress.ip_address(ip) not in target_net:
                                continue
                        except Exception:
                            continue
                    mac = parts[2].upper() if ":" in parts[2] else None
                    if mac and mac != "(INCOMPLETE)" and ip not in devices:
                        randomized = is_randomized_mac(mac)
                        devices[ip] = {
                            "ip_address": ip,
                            "mac_address": mac,
                            "vendor": None if randomized else get_mac_vendor(mac),
                            "randomized_mac": randomized
                        }
    except Exception as e:
        print(f"[Scanner] ARP cache error: {e}")

    # Step 3: Ensure local host itself is included
    try:
        net_info = detect_local_network_info()
        local_ip = net_info.get("local_ip")
        if local_ip and local_ip not in devices:
            if not target_net or ipaddress.ip_address(local_ip) in target_net:
                import uuid
                raw_mac = ':'.join(re.findall('..', '%012X' % uuid.getnode())).upper()
                rand = is_randomized_mac(raw_mac)
                devices[local_ip] = {
                    "ip_address": local_ip,
                    "mac_address": raw_mac,
                    "vendor": None if rand else get_mac_vendor(raw_mac),
                    "randomized_mac": rand
                }
    except Exception as e:
        print(f"[Scanner] Local host detection notice: {e}")

    return list(devices.values())

# --- OS Name Cleaner ---
def clean_os_name(os_name: str) -> str:
    if not os_name:
        return "Unknown OS"
    n = os_name.lower()
    if "windows 11" in n: return "Windows 11"
    if "windows 10" in n: return "Windows 10"
    if "windows server 2022" in n: return "Windows Server 2022"
    if "windows server 2019" in n: return "Windows Server 2019"
    if "windows server 2016" in n: return "Windows Server 2016"
    if "windows server" in n: return "Windows Server"
    if "windows" in n: return "Windows"
    if "ios" in n and "cisco" not in n: return "iOS"
    if "macos" in n or "mac os" in n or "os x" in n: return "macOS"
    if "android" in n: return "Android OS"
    if "ubuntu" in n: return "Ubuntu Linux"
    if "debian" in n: return "Debian Linux"
    if "centos" in n: return "CentOS Linux"
    if "fedora" in n: return "Fedora Linux"
    if "raspbian" in n: return "Raspbian Linux"
    if "linux" in n: return "Linux"
    if "freebsd" in n: return "FreeBSD"
    if "openbsd" in n: return "OpenBSD"
    if "tizen" in n: return "Tizen OS"
    if "webos" in n: return "webOS"
    if "embedded" in n or ("router" in n and "cisco ios" not in n): return "Embedded OS"
    if "cisco ios" in n: return "Cisco IOS"
    return os_name[:60]

def infer_vendor_from_details(hostname: str = None, os_name: str = None, services: List[str] = None) -> Optional[str]:
    """Infer hardware vendor from hostname, OS fingerprint, or running services when MAC is randomized."""
    parts = []
    if hostname: parts.append(hostname)
    if os_name: parts.append(os_name)
    if services: parts.extend(services)
    combined = " ".join(parts).lower()
    if any(k in combined for k in ["iphone", "ipad", "ipod", "apple", "ios", "macos", "macbook", "darwin"]):
        return "Apple Inc."
    if any(k in combined for k in ["samsung", "galaxy", "tizen"]):
        return "Samsung Electronics"
    if any(k in combined for k in ["pixel", "google", "chromecast"]):
        return "Google"
    if any(k in combined for k in ["xiaomi", "redmi", "poco", "mi phone"]):
        return "Xiaomi"
    if any(k in combined for k in ["oneplus"]):
        return "OnePlus"
    if any(k in combined for k in ["windows", "microsoft"]):
        return "Microsoft Corporation"
    if any(k in combined for k in ["linux", "ubuntu", "debian", "raspbian", "raspberry"]):
        return "Linux / Raspberry Pi"
    if any(k in combined for k in ["sony", "playstation", "bravia"]):
        return "Sony"
    if any(k in combined for k in ["lg", "webos"]):
        return "LG Electronics"
    if any(k in combined for k in ["amazon", "echo", "firetv", "kindle"]):
        return "Amazon"
    if any(k in combined for k in ["android"]):
        return "Android Device"
    return None

# --- Device Classification ---
def classify_device(hostname, vendor, os_name, open_ports, services=None, gateway_ip=None, device_ip=None, randomized_mac=False) -> Tuple[str, str]:
    hostname = (hostname or "").lower().strip()
    vendor   = (vendor or "").lower().strip()
    os_clean = (os_name or "").lower().strip()
    scores: Dict[str, int] = {}
    def add(t, n): scores[t] = scores.get(t, 0) + n

    if gateway_ip and device_ip and device_ip == gateway_ip:
        return "Router", "High"
    if any(x in hostname for x in ["gateway", "router", "gw.", "gw-", "rt-", "modem", "pfsense", "openwrt", "dd-wrt"]): add("Router", 40)
    if any(x in vendor for x in ["netgear", "tp-link", "tplink", "cisco", "d-link", "linksys", "huawei", "ubiquiti", "zyxel", "mikrotik", "asus", "belkin", "arris", "aruba"]): add("Router", 25)
    if 53 in open_ports and 1900 in open_ports: add("Router", 30)
    if 67 in open_ports: add("Router", 35)
    if "embedded" in os_clean and (80 in open_ports or 443 in open_ports): add("Router", 20)

    if any(x in hostname for x in ["appletv", "samsung-tv", "lg-tv", "sony-tv", "firetv", "roku", "chromecast", "fire-tv", "shield", "webos", "smarttv"]): add("Smart TV", 55)
    if "tizen" in os_clean or "webos" in os_clean: add("Smart TV", 60)
    if 8001 in open_ports or 8060 in open_ports: add("Smart TV", 40)

    if any(x in hostname for x in ["appletv", "roku", "chromecast", "firestick", "fire-tv", "nvidia-shield"]): add("Streaming Device", 50)
    if "roku" in vendor: add("Streaming Device", 60)

    if any(x in hostname for x in ["xbox", "playstation", "ps4", "ps5", "nintendo", "switch", "wii"]): add("Gaming Console", 70)
    if any(x in vendor for x in ["sony interactive", "microsoft xbox", "nintendo"]): add("Gaming Console", 65)

    if any(x in hostname for x in ["camera", "cam-", "ipcam", "cctv", "dvr", "nvr", "hikvision", "dahua", "axis", "foscam"]): add("IP Camera", 60)
    if any(x in vendor for x in ["hikvision", "dahua", "axis", "foscam", "amcrest"]): add("IP Camera", 60)
    if 554 in open_ports or 8554 in open_ports: add("IP Camera", 50)

    if any(x in hostname for x in ["printer", "laserjet", "epson", "canon", "brother", "lexmark", "kyocera", "mfp"]): add("Printer", 60)
    if any(x in vendor for x in ["brother", "canon", "epson", "lexmark", "kyocera", "hewlett packard", "hp inc", "xerox", "ricoh"]): add("Printer", 55)
    if 9100 in open_ports or 515 in open_ports or 631 in open_ports: add("Printer", 50)

    if any(x in hostname for x in ["nas", "synology", "qnap", "terastation", "freenas", "truenas", "readynas"]): add("NAS", 65)
    if "synology" in vendor or "qnap" in vendor: add("NAS", 65)
    if 5000 in open_ports or 5001 in open_ports: add("NAS", 40)

    if any(x in hostname for x in ["server", "srv-", "backup", "db-", "sql", "proxmox", "esxi", "vmware-host"]): add("Server", 50)
    if "windows server" in os_clean: add("Server", 55)
    if any(p in open_ports for p in [3306, 5432, 1433, 6379, 27017, 5672, 9200]): add("Server", 40)

    if any(x in hostname for x in ["iphone", "ipad", "ipod", "android", "galaxy", "pixel", "oneplus"]): add("Smartphone", 60)
    if "ios" in os_clean: add("Smartphone", 60)
    if "android" in os_clean and "tv" not in hostname: add("Smartphone", 55)

    if any(x in hostname for x in ["ipad", "tablet", "kindle"]): add("Tablet", 60)

    if any(x in hostname for x in ["laptop", "macbook", "thinkpad", "latitude", "elitebook", "xps", "surface", "notebook"]): add("Laptop", 60)
    if "macbook" in hostname: add("Laptop", 70)
    if "macos" in os_clean: add("Laptop", 35)

    if any(x in hostname for x in ["desktop", "workstation", "pc-", "imac"]): add("Desktop", 55)
    if "windows" in os_clean: add("Desktop", 20)
    if any(p in open_ports for p in [3389, 135, 445]): add("Desktop", 20)

    if any(x in hostname for x in ["esp", "esp8266", "esp32", "smart-bulb", "alexa", "echo", "hub", "nest", "hue", "ring", "wemo", "sonoff", "shelly"]): add("IoT Device", 55)
    if any(x in vendor for x in ["espressif", "tuya", "shenzhen", "amazon", "philips lighting"]): add("IoT Device", 45)

    if any(x in hostname for x in ["switch", "ap-", "access-point", "wap-"]): add("Network Infrastructure", 55)
    if any(x in vendor for x in ["ubiquiti", "ruckus", "aruba", "juniper"]): add("Network Infrastructure", 40)

    if not scores:
        if randomized_mac:
            return "Smartphone", "Medium"
        return "Unknown Device", "Low"
    best_type = max(scores, key=scores.get)
    best_score = scores[best_type]
    if best_score < 20:
        if randomized_mac:
            return "Smartphone", "Medium"
        return "Unknown Device", "Low"
    return best_type, "High" if best_score >= 60 else "Medium" if best_score >= 35 else "Low"

def guess_device_type(hostname, vendor, os_name, open_ports, services=None, gateway_ip=None, device_ip=None, randomized_mac=False) -> str:
    t, _ = classify_device(hostname, vendor, os_name, open_ports, services, gateway_ip, device_ip, randomized_mac)
    return t

def get_port_risk_and_desc(port: int, service: str) -> Tuple[str, str]:
    PORT_INFO = {
        21: ("High", "FTP: cleartext credentials. Replace with SFTP/SCP."),
        22: ("Low", "SSH: encrypted remote access. Secure if key-auth enabled."),
        23: ("High", "Telnet: cleartext sessions. CRITICAL: disable and use SSH."),
        25: ("Medium", "SMTP: mail relay. Risk of open relay abuse."),
        53: ("Low", "DNS: name resolution. Risk of amplification if open recursion."),
        67: ("Low", "DHCP server. Normal for gateway/router devices."),
        80: ("Medium", "HTTP: cleartext web traffic. Upgrade to HTTPS."),
        110: ("Medium", "POP3: cleartext unless TLS configured."),
        135: ("Medium", "Windows RPC. Restrict to trusted hosts."),
        139: ("High", "NetBIOS: legacy Windows file sharing. Lateral movement risk."),
        143: ("Medium", "IMAP: ensure TLS is enforced."),
        443: ("Low", "HTTPS: encrypted web traffic. Ensure valid TLS cert."),
        445: ("High", "SMB: EternalBlue/WannaCry vector. Restrict to LAN only."),
        554: ("Low", "RTSP streaming. Restrict to authorized viewers."),
        993: ("Low", "IMAPS: encrypted IMAP. Secure mail protocol."),
        995: ("Low", "POP3S: encrypted POP3. Secure mail protocol."),
        1433: ("High", "MSSQL: database exposed to network. Restrict immediately."),
        1900: ("Low", "UPnP discovery. May expose device to LAN UPnP attacks."),
        3306: ("High", "MySQL: database exposed. Critical risk."),
        3389: ("Medium", "RDP: brute-force target. Use VPN or MFA."),
        5000: ("Low", "NAS management web UI. Restrict to trusted clients."),
        5432: ("High", "PostgreSQL: database exposed. Critical risk."),
        5900: ("High", "VNC: brute-force vulnerable. Disable if not needed."),
        5901: ("High", "VNC session 2: same risk as port 5900."),
        6379: ("High", "Redis: often unauthenticated. Extremely high risk if exposed."),
        8001: ("Low", "Samsung SmartTV API. Normal on Smart TV devices."),
        8060: ("Low", "Roku device control. Normal on Roku streaming devices."),
        8080: ("Medium", "Alt HTTP: cleartext. Often hosts admin panels."),
        8443: ("Low", "Alt HTTPS: encrypted non-standard port."),
        9100: ("Low", "Printer JetDirect. Restrict to print clients."),
        515: ("Low", "LPD print service. Restrict to print clients."),
        631: ("Low", "IPP print service."),
        27017: ("High", "MongoDB: often unauthenticated. Critical if exposed."),
    }
    return PORT_INFO.get(port, ("Low", f"Network service on port {port}."))

def calculate_security_score(ports: List[Dict[str, Any]]) -> int:
    PENALTIES = {21: 25, 23: 35, 445: 25, 139: 15, 3306: 25, 5432: 25,
                 6379: 30, 27017: 30, 1433: 25, 5900: 20, 5901: 20,
                 80: 5, 8080: 8, 3389: 12, 135: 8, 110: 5, 143: 5}
    score = 100
    for p in ports:
        if p.get("state") != "open":
            continue
        score -= PENALTIES.get(p.get("port"), 3)
    open_count = sum(1 for p in ports if p.get("state") == "open")
    if open_count > 6:
        score -= (open_count - 6) * 3
    return max(10, score)

def parse_nmap_xml(xml_content: str, gateway_ip: str = None, arp_map: Dict[str, Dict] = None) -> List[Dict[str, Any]]:
    devices = []
    arp_map = arp_map or {}
    try:
        root = ET.fromstring(xml_content)
        for host in root.findall("host"):
            status = host.find("status")
            if status is not None and status.get("state", "up") != "up":
                continue
            ip_address = mac_address = vendor = None
            randomized_mac = False
            for addr in host.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    ip_address = addr.get("addr")
                elif addr.get("addrtype") == "mac":
                    mac_address = addr.get("addr", "").upper()
                    vendor = addr.get("vendor") or None
            if not ip_address:
                continue
            if ip_address in arp_map:
                arp_data = arp_map[ip_address]
                if not mac_address and arp_data.get("mac_address"):
                    mac_address = arp_data["mac_address"]
                if not vendor and arp_data.get("vendor"):
                    vendor = arp_data["vendor"]
                randomized_mac = arp_data.get("randomized_mac", False)
            elif mac_address:
                randomized_mac = is_randomized_mac(mac_address)
                if randomized_mac:
                    vendor = None
                elif not vendor:
                    vendor = get_mac_vendor(mac_address)
            hostname = None
            hostnames_el = host.find("hostnames")
            if hostnames_el is not None:
                hn = hostnames_el.find("hostname")
                if hn is not None:
                    hostname = hn.get("name")
            os_name, firmware = "Unknown OS", None
            os_el = host.find("os")
            if os_el is not None:
                best_match, best_acc = None, 0
                for osmatch in os_el.findall("osmatch"):
                    acc = int(osmatch.get("accuracy", 0))
                    if acc > best_acc:
                        best_acc, best_match = acc, osmatch
                if best_match is not None:
                    name = best_match.get("name", "Unknown OS")
                    cleaned = clean_os_name(name)
                    accuracy = best_match.get("accuracy", "0")
                    os_name = f"{cleaned} ({accuracy}% confidence)" if int(accuracy) >= 70 else cleaned
                for osclass in os_el.findall("osclass"):
                    if osclass.get("type") in ("broadband router", "router", "switch", "firewall", "WAP"):
                        fw = osclass.get("osgen")
                        if fw:
                            firmware = fw
            ports, open_port_nums, services_found = [], [], []
            ports_el = host.find("ports")
            if ports_el is not None:
                for pe in ports_el.findall("port"):
                    pid = int(pe.get("portid", 0))
                    proto = pe.get("protocol", "tcp")
                    state_el = pe.find("state")
                    state = state_el.get("state", "closed") if state_el is not None else "closed"
                    if state != "open":
                        continue
                    open_port_nums.append(pid)
                    svc_el = pe.find("service")
                    svc_name = svc_el.get("name", "unknown") if svc_el is not None else "unknown"
                    services_found.append(svc_name)
                    product = (svc_el.get("product", "") if svc_el is not None else "").strip()
                    version = (svc_el.get("version", "") if svc_el is not None else "").strip()
                    svc_desc = f"{svc_name} ({' '.join(filter(None, [product, version]))})" if (product or version) else svc_name
                    risk, rdesc = get_port_risk_and_desc(pid, svc_desc)
                    ports.append({"port": pid, "protocol": proto, "service": svc_desc,
                                  "state": "open", "risk_level": risk, "description": rdesc})
            if not vendor or randomized_mac:
                inferred = infer_vendor_from_details(hostname, os_name, services_found)
                if inferred:
                    vendor = f"{inferred} (Private MAC)" if randomized_mac else inferred
                elif randomized_mac:
                    vendor = "Private MAC (Privacy Feature)"

            device_type, confidence = classify_device(hostname, vendor, os_name, open_port_nums, services_found,
                                                       gateway_ip=gateway_ip, device_ip=ip_address, randomized_mac=randomized_mac)
            security_score = calculate_security_score(ports)
            uptime_val = "Unknown / Security Firewalled"
            hs_el = host.find("hostscript")
            if hs_el is not None:
                for sc in hs_el.findall("script"):
                    if sc.get("id") == "uptime":
                        raw = sc.get("output", "").strip()
                        uptime_val = raw.split(" (since")[0].strip() or uptime_val
                        break
            devices.append({
                "ip_address": ip_address, "mac_address": mac_address, "hostname": hostname,
                "vendor": vendor, "os_name": os_name, "firmware": firmware, "uptime": uptime_val,
                "device_type": device_type, "classification_confidence": confidence,
                "status": "up", "ports": ports, "security_score": security_score,
                "randomized_mac": randomized_mac,
            })
    except Exception as e:
        print(f"[Scanner] XML parse error: {e}")
    return devices

def get_gateway_router_details_sync(gateway_ip: str, simulation_mode: bool) -> dict:
    details = {
        "vendor": "Unavailable", "model": "Unavailable", "firmware": "Unavailable",
        "os": "Unavailable", "uptime": "Unavailable", "lan_ip": gateway_ip or "Unavailable",
        "wan_ip": "Detecting...", "hostname": "Unavailable", "interface_type": "Unavailable",
        "dns_servers": "Unavailable", "dhcp_range": "Unavailable", "connection_type": "Unavailable",
        "snmp_active": False, "upnp_active": False, "analytics": None
    }
    net_info = detect_local_network_info()
    if net_info.get("dns_server"):
        details["dns_servers"] = net_info["dns_server"]
    iface = net_info.get("interface", "").lower()
    adapter = net_info.get("adapter", "").lower()
    if any(x in iface + adapter for x in ["wi-fi", "wireless", "802.11", "wlan", "wifi"]):
        details["interface_type"] = "Wireless (Wi-Fi)"
        details["connection_type"] = "Wireless"
    elif any(x in iface + adapter for x in ["ethernet", "local area", "gigabit"]):
        details["interface_type"] = "Wired (Ethernet)"
        details["connection_type"] = "Wired"
    if not gateway_ip:
        return details
    try:
        host, _, _ = socket.gethostbyaddr(gateway_ip)
        if host and host != gateway_ip:
            details["hostname"] = host
    except Exception:
        pass
    if gateway_ip:
        octets = gateway_ip.split(".")
        if len(octets) == 4:
            details["dhcp_range"] = f"{octets[0]}.{octets[1]}.{octets[2]}.100 - {octets[0]}.{octets[1]}.{octets[2]}.254"
    try:
        for port in [53, 80, 443, 161, 1900]:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.4)
            if s.connect_ex((gateway_ip, port)) == 0:
                if port == 161: details["snmp_active"] = True
                if port == 1900: details["upnp_active"] = True
            s.close()
    except Exception:
        pass
    try:
        with database.get_db() as db:
            dev = db.query(database.Device).filter(database.Device.ip_address == gateway_ip).first()
            if dev:
                if dev.vendor and dev.vendor not in ("Unknown Manufacturer", "Unknown", None, ""):
                    details["vendor"] = dev.vendor
                if dev.os_name and dev.os_name not in ("Unknown OS", "Unknown", None, ""):
                    details["os"] = dev.os_name
    except Exception:
        pass
    try:
        boot = datetime.datetime.fromtimestamp(psutil.boot_time())
        delta = datetime.datetime.now() - boot
        d, rem = delta.days, delta.seconds
        h, rem = divmod(rem, 3600)
        m, _ = divmod(rem, 60)
        details["uptime"] = f"{d}d {h}h {m}m (Local PC uptime)"
    except Exception:
        pass
    wan = get_wan_ip()
    details["wan_ip"] = wan or "No Internet Access"
    try:
        rx, tx = get_realtime_bandwidth()
        with database.get_db() as db:
            connected = db.query(database.Device).filter(database.Device.status == "up").count()
        details["analytics"] = {"upload_speed": tx, "download_speed": rx,
                                 "active_clients": connected, "connected_devices": connected,
                                 "network_utilization": round(min(99.0, (rx + tx) * 5.0), 1)}
    except Exception:
        details["analytics"] = {"upload_speed": 0.0, "download_speed": 0.0,
                                  "active_clients": 0, "connected_devices": 0, "network_utilization": 0.0}
    return details

# --- Core Scan Engine (Thread-based, no asyncio subprocess) ---
def _build_nmap_args(nmap_path: str, targets: Union[str, List[str]], profile: str) -> List[str]:
    target_list = [targets] if isinstance(targets, str) else list(targets)
    admin = is_admin()
    sf = "-sS" if admin else "-sT"
    os_flags = ["-O", "--osscan-guess"] if admin else []
    base = [nmap_path]
    pn_flag = ["-Pn"] if isinstance(targets, list) else []

    if profile == "quick":
        if isinstance(targets, list):
            return base + ["-sn"] + pn_flag + ["-T4", "--host-timeout", "10s",
                           "--stats-every", "2s", "-oX", "-"] + target_list
        else:
            return base + ["-sn", "-T4", "-PE", "-PS22,80,443,3389,8080,8443", "-PA80,443",
                           "--min-parallelism", "32", "--max-parallelism", "64",
                           "--max-rtt-timeout", "500ms", "--host-timeout", "15s",
                           "--stats-every", "2s", "-oX", "-"] + target_list
    elif profile == "inventory":
        return base + ["-sn", "-Pn", "-T4", "--host-timeout", "15s",
                       "--stats-every", "3s", "-oX", "-"] + target_list
    elif profile == "standard":
        return base + [sf, "-sV"] + os_flags + ["-Pn", "-T4", "--top-ports", "100",
                       "--script=banner", "--version-intensity", "5",
                       "--min-parallelism", "20", "--max-parallelism", "50",
                       "--max-rtt-timeout", "500ms", "--host-timeout", "60s",
                       "--stats-every", "3s", "-oX", "-"] + target_list
    elif profile == "deep":
        return base + [sf, "-sV"] + os_flags + ["-Pn", "-T4", "--top-ports", "500",
                       "--script=banner,uptime", "--version-intensity", "7",
                       "--min-parallelism", "15", "--max-parallelism", "40",
                       "--host-timeout", "120s", "--stats-every", "3s",
                       "-oX", "-"] + target_list
    elif profile == "audit":
        return base + [sf, "-sV"] + os_flags + ["-Pn", "-T4", "--top-ports", "100",
                       "--script=banner,vuln", "--version-intensity", "6",
                       "--host-timeout", "180s", "--stats-every", "3s",
                       "-oX", "-"] + target_list
    else:
        return _build_nmap_args(nmap_path, targets, "standard")


def run_scan_thread(scan_id: int, target: str, profile: str):
    """Main scan worker — runs in a dedicated daemon thread."""
    abort_event = threading.Event()
    _ABORT_EVENTS[scan_id] = abort_event
    try:
        nmap_path = get_nmap_path()
        if not nmap_path:
            _update(scan_id, 0, "[ERROR] Nmap not found. Install Nmap 7.x from https://nmap.org", "failed")
            database.update_scan_status(scan_id, "failed", 0)
            return

        _update(scan_id, 5, f"[INFO] Nmap detected at: {nmap_path}", "running")
        net_info = detect_local_network_info()
        gateway_ip = net_info.get("gateway")
        local_subnet = net_info.get("subnet", "")

        # Phase 1: ARP sweep for accurate MAC resolution
        _update(scan_id, 8, "[INFO] Performing ARP sweep for accurate MAC resolution...", "running")
        arp_results, arp_map = [], {}
        try:
            is_local = False
            try:
                net_obj = ipaddress.IPv4Network(target, strict=False)
                local_net = ipaddress.IPv4Network(local_subnet, strict=False)
                is_local = net_obj.overlaps(local_net) or str(net_obj) == str(local_net)
            except Exception:
                pass
            if is_local:
                arp_results = parse_arp_table(target)
                arp_map = {d["ip_address"]: d for d in arp_results}
                rc = sum(1 for d in arp_results if d.get("randomized_mac"))
                _update(scan_id, 12, f"[INFO] ARP sweep: {len(arp_results)} hosts ({rc} with randomized MACs)", "running")
                if rc > 0:
                    _update(scan_id, None, f"[INFO] {rc} device(s) use randomized MACs — private address resolution enabled.", "running")
            else:
                _update(scan_id, 12, "[INFO] Remote target — skipping local ARP sweep.", "running")
        except Exception as arp_err:
            print(f"[Scanner] ARP error: {arp_err}")

        if abort_event.is_set():
            _update(scan_id, 100, "[INFO] Scan aborted.", "aborted")
            database.update_scan_status(scan_id, "failed", 0)
            return

        # Phase 2: Select targets & build command
        if profile == "inventory":
            _update(scan_id, 15, "[INFO] Inventory Refresh — rechecking known hosts.", "running")
            try:
                with database.get_db() as db:
                    db_ips = [d.ip_address for d in db.query(database.Device).all()]
            except Exception:
                db_ips = []
            if not db_ips:
                db_ips = [d["ip_address"] for d in arp_results if d.get("ip_address")]
            if not db_ips:
                _update(scan_id, 100, "[INFO] No devices in inventory to refresh.", "completed")
                database.update_scan_status(scan_id, "completed", 0)
                return
            args = _build_nmap_args(nmap_path, db_ips, "inventory")
        else:
            # If we already found alive hosts via ARP on local subnet,
            # target those active IPs directly across all profiles.
            # This makes the scan blazing fast and eliminates dead IP timeouts!
            if arp_results and is_local:
                alive_ips = [d["ip_address"] for d in arp_results if d.get("ip_address")]
                if alive_ips:
                    _update(scan_id, 14, f"[INFO] Targeting {len(alive_ips)} active hosts detected on subnet.", "running")
                    args = _build_nmap_args(nmap_path, alive_ips, profile)
                else:
                    args = _build_nmap_args(nmap_path, target, profile)
            else:
                args = _build_nmap_args(nmap_path, target, profile)

        # Phase 3: Launch nmap process
        _update(scan_id, 15, f"[INFO] Launching nmap scan (profile: {profile})...", "running")
        try:
            proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except FileNotFoundError:
            _update(scan_id, 0, f"[ERROR] Cannot execute nmap at: {nmap_path}", "failed")
            database.update_scan_status(scan_id, "failed", 0)
            return

        _ACTIVE_PROCESSES[scan_id] = proc
        stderr_lines, stdout_chunks = [], []
        last_pct = [0]

        def read_stderr():
            for raw in proc.stderr:
                if abort_event.is_set():
                    break
                line = raw.decode("utf-8", errors="ignore").strip()
                if not line:
                    continue
                stderr_lines.append(line)
                m = re.search(r"About\s+(\d+(?:\.\d+)?)%\s+done", line, re.IGNORECASE)
                if m:
                    pct = float(m.group(1))
                    mapped = int(15 + (pct / 100.0) * 72)
                    milestone = int(pct // 20)
                    if milestone > last_pct[0]:
                        last_pct[0] = milestone
                        phase_msgs = {
                            "quick": f"Host discovery sweep ({pct:.0f}%)...",
                            "standard": f"Scanning ports and services ({pct:.0f}%)...",
                            "deep": f"Deep scan + OS fingerprinting ({pct:.0f}%)...",
                            "audit": f"Running vulnerability checks ({pct:.0f}%)...",
                            "inventory": f"Checking inventory devices ({pct:.0f}%)...",
                        }
                        _update(scan_id, mapped, f"[INFO] {phase_msgs.get(profile, f'Scanning ({pct:.0f}%)...')}", "running")

        def read_stdout():
            for chunk in iter(lambda: proc.stdout.read(65536), b""):
                if abort_event.is_set():
                    break
                stdout_chunks.append(chunk)

        t_err = threading.Thread(target=read_stderr, daemon=True)
        t_out = threading.Thread(target=read_stdout, daemon=True)
        t_err.start()
        t_out.start()

        while proc.poll() is None:
            if abort_event.is_set():
                proc.kill()
                break
            time.sleep(0.5)

        t_out.join(timeout=10)
        t_err.join(timeout=5)
        _ACTIVE_PROCESSES.pop(scan_id, None)

        if abort_event.is_set():
            _update(scan_id, 100, "[INFO] Scan aborted by user.", "aborted")
            database.update_scan_status(scan_id, "failed", 0)
            return

        returncode = proc.returncode
        raw_xml = b"".join(stdout_chunks).decode("utf-8", errors="ignore")

        # Phase 4: Handle non-zero return or missing XML
        if returncode != 0 and "<nmaprun" not in raw_xml:
            stderr_text = "\n".join(stderr_lines)
            if any(x in stderr_text.lower() for x in ["root", "permission", "administrator", "requires", "winpcap", "npcap"]):
                _update(scan_id, 40, "[WARN] Privilege/Npcap issue — retrying with TCP connect scan...", "running")
                retry_args = [nmap_path, "-sT", "-T4", "-PE", "-PS22,80,443",
                               "--host-timeout", "30s", "-oX", "-", target]
                try:
                    p2 = subprocess.run(retry_args, capture_output=True, timeout=180)
                    raw_xml = p2.stdout.decode("utf-8", errors="ignore")
                    if p2.returncode != 0 and "<nmaprun" not in raw_xml:
                        _update(scan_id, 100, f"[ERROR] Scan failed after retry. stderr: {stderr_text[:200]}", "failed")
                        database.update_scan_status(scan_id, "failed", 0)
                        return
                except Exception as e2:
                    _update(scan_id, 100, f"[ERROR] Retry failed: {e2}", "failed")
                    database.update_scan_status(scan_id, "failed", 0)
                    return
            else:
                _update(scan_id, 100, f"[ERROR] Nmap exited with code {returncode}. Verify target.", "failed")
                database.update_scan_status(scan_id, "failed", 0)
                return

        # Phase 5: Parse results
        _update(scan_id, 88, "[INFO] Parsing scan results...", "running")
        devices, discovered_ips = [], []

        if "<nmaprun" in raw_xml:
            devices = parse_nmap_xml(raw_xml, gateway_ip=gateway_ip, arp_map=arp_map)
            discovered_ips = [d["ip_address"] for d in devices]

        # Augment with any ARP hosts not seen by nmap (ACROSS ALL PROFILES!)
        nmap_ips = set(discovered_ips)
        for h in arp_results:
            if h["ip_address"] not in nmap_ips:
                is_rand = h.get("randomized_mac", False)
                h_vendor = h.get("vendor") or ("Private MAC (Privacy Feature)" if is_rand else None)
                dtype, conf = classify_device(None, h_vendor, None, [],
                                               gateway_ip=gateway_ip, device_ip=h["ip_address"], randomized_mac=is_rand)
                devices.append({
                    "ip_address": h["ip_address"], "mac_address": h.get("mac_address"),
                    "hostname": None, "vendor": h_vendor, "os_name": "Unknown OS",
                    "firmware": None, "uptime": "Unknown", "device_type": dtype,
                    "classification_confidence": conf, "status": "up", "ports": [],
                    "security_score": 100, "randomized_mac": is_rand,
                })
                discovered_ips.append(h["ip_address"])

        if not devices:
            if arp_results:
                for h in arp_results:
                    is_rand = h.get("randomized_mac", False)
                    h_vendor = h.get("vendor") or ("Private MAC (Privacy Feature)" if is_rand else None)
                    dtype, conf = classify_device(None, h_vendor, None, [],
                                                   gateway_ip=gateway_ip, device_ip=h["ip_address"], randomized_mac=is_rand)
                    devices.append({
                        "ip_address": h["ip_address"], "mac_address": h.get("mac_address"),
                        "hostname": None, "vendor": h_vendor, "os_name": "Unknown OS",
                        "firmware": None, "uptime": "Unknown", "device_type": dtype,
                        "classification_confidence": conf, "status": "up", "ports": [],
                        "security_score": 100, "randomized_mac": is_rand,
                    })
                    discovered_ips.append(h["ip_address"])
            else:
                _update(scan_id, 100, "[ERROR] Scan returned no results. Verify target subnet.", "failed")
                database.update_scan_status(scan_id, "failed", 0)
                return

        _update(scan_id, 93, f"[INFO] {len(devices)} host(s) found. Running security analysis...", "running")

        # Phase 6: Store in DB
        for dev in devices:
            try:
                device_id = database.upsert_device(
                    scan_id=scan_id, ip_address=dev["ip_address"],
                    mac_address=dev.get("mac_address"), hostname=dev.get("hostname"),
                    vendor=dev.get("vendor"), device_type=dev.get("device_type", "Unknown Device"),
                    os_name=dev.get("os_name"), status=dev.get("status", "up"),
                    classification_confidence=dev.get("classification_confidence"), is_simulation=False
                )
                database.update_device_ports_with_diff(device_id, dev.get("ports", []), scan_id)
                score = calculate_security_score([{"port": p["port"], "state": p["state"]} for p in dev.get("ports", [])])
                database.update_device_security_score(device_id, score)
            except Exception as dev_err:
                print(f"[Scanner] DB error for {dev.get('ip_address')}: {dev_err}")

        if profile not in ("quick",):
            try:
                database.mark_offline_missing_devices(scan_id, target, discovered_ips)
            except Exception:
                pass

        rc_count = sum(1 for d in devices if d.get("randomized_mac"))
        extra = f" ({rc_count} device(s) have randomized MACs)" if rc_count else ""
        database.update_scan_status(scan_id, "completed", len(devices))
        _update(scan_id, 100, f"[INFO] Scan complete. {len(devices)} host(s) discovered.{extra}", "completed")

    except Exception as e:
        import traceback
        traceback.print_exc()
        try:
            database.update_scan_status(scan_id, "failed", 0)
        except Exception:
            pass
        _update(scan_id, 100, f"[ERROR] Scanner crashed: {e}", "failed")
    finally:
        _ABORT_EVENTS.pop(scan_id, None)
        _ACTIVE_PROCESSES.pop(scan_id, None)


def start_scan_job(scan_id: int, target: str, scan_profile: str, simulation_mode: bool = False):
    """Start scan in a background daemon thread."""
    _update(scan_id, 0, "[INFO] Scan queued — initializing...", "running")
    t = threading.Thread(target=run_scan_thread, args=(scan_id, target, scan_profile),
                         daemon=True, name=f"scan-{scan_id}")
    t.start()


def get_discovery_diagnostics() -> Dict[str, Any]:
    net = detect_local_network_info()
    nmap_path = get_nmap_path()
    npcap_available = False
    try:
        if platform.system() == "Windows":
            npcap_available = os.path.isdir(r"C:\Windows\System32\Npcap")
        else:
            npcap_available = shutil.which("libpcap") is not None or os.path.exists("/usr/lib/libpcap.so")
    except Exception:
        pass
    scapy_available = False
    try:
        import importlib.util
        scapy_available = importlib.util.find_spec("scapy") is not None
    except Exception:
        pass
    try:
        arp_hosts = parse_arp_table()
    except Exception:
        arp_hosts = []
    arp_ips = sorted(set(
        h["ip_address"] for h in arp_hosts
        if not h["ip_address"].startswith("224.") and not h["ip_address"].endswith(".255")
    ))
    limitations = [
        "Mobile devices with randomized MACs cannot be tracked between scans — each scan may show them as a new device.",
        "Devices blocking all ICMP and TCP probes may not appear — this is a network-level limitation.",
    ]
    if not npcap_available:
        limitations.append("Npcap not detected — install from https://npcap.com for fastest SYN scans.")
    if not nmap_path:
        limitations.append("Nmap not found — install from https://nmap.org for active scanning.")
    if not scapy_available:
        limitations.append("Scapy not installed — run: pip install scapy")
    return {
        "active_adapter": net.get("adapter") or net.get("interface") or "Unknown",
        "adapter_name": net.get("adapter") or net.get("interface") or "Unknown",
        "detected_subnet": net.get("subnet", "Unknown"),
        "local_ip": net.get("local_ip", "Unknown"),
        "gateway": net.get("gateway", "Unknown"),
        "netmask": net.get("netmask", "Unknown"),
        "dns_server": net.get("dns_server", "Unknown"),
        "detection_method": net.get("detection_method", "unknown"),
        "is_admin": True,
        "nmap_available": nmap_path is not None,
        "nmap_path": nmap_path,
        "npcap_available": npcap_available,
        "scapy_available": scapy_available,
        "arp_hosts": len(arp_ips),
        "arp_host_list": arp_ips,
        "limitations": limitations,
        "discovery_methods": list(filter(None, [
            "Scapy ARP Sweep" if scapy_available else None,
            "OS ARP Table (passive)",
            "Nmap Active Network Scan" if nmap_path else None,
            "ICMP Ping Sweep",
            "SYN Stealth Scan" if (npcap_available and nmap_path) else None,
        ])),
    }

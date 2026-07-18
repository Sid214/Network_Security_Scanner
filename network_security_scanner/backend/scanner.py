"""
GuardNet Scanner Engine — Network Security Suite
=================================================
Implements all 5 scan profiles with real Nmap execution, automatic
network/adapter discovery from the routing table, and multi-signal
confidence-based device classification.
Supports bandwidth analytics, WAN IP detection, and CVE lookup.
"""

import subprocess
import shutil
import os
import sys
import re
import xml.etree.ElementTree as ET
import threading
import asyncio
import time
import random
import socket
import platform
import json
import datetime
import ipaddress
from typing import Dict, List, Any, Optional, Tuple

# FastAPI event loop reference — set at startup
_EVENT_LOOP: asyncio.AbstractEventLoop = None

def set_event_loop(loop: asyncio.AbstractEventLoop):
    global _EVENT_LOOP
    _EVENT_LOOP = loop

try:
    from . import database
except ImportError:
    import database

# Thread-safe in-memory scan progress tracker
PROGRESS_LOCK = threading.Lock()
SCAN_PROGRESS: Dict[int, Dict[str, Any]] = {}

# ─── Progress Tracking ───────────────────────────────────────────────────────

def get_progress(scan_id: int) -> Dict[str, Any]:
    with PROGRESS_LOCK:
        return SCAN_PROGRESS.get(scan_id, {"progress": 0, "logs": ["Scan not found"], "status": "failed"})

def update_progress(scan_id: int, progress: int = None, log_msg: str = None, status: str = None):
    with PROGRESS_LOCK:
        if scan_id not in SCAN_PROGRESS:
            SCAN_PROGRESS[scan_id] = {"progress": 0, "logs": [], "status": "running"}
        if progress is not None:
            SCAN_PROGRESS[scan_id]["progress"] = progress
        if log_msg is not None:
            timestamp = time.strftime("%H:%M:%S")
            SCAN_PROGRESS[scan_id]["logs"].append(f"[{timestamp}] {log_msg}")
        if status is not None:
            SCAN_PROGRESS[scan_id]["status"] = status

# ─── Nmap Detection ──────────────────────────────────────────────────────────

def get_nmap_path() -> Optional[str]:
    """Find nmap binary — check PATH and common install locations."""
    root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    # 1. Check bundled tools directory
    if platform.system() == "Windows":
        bundled = os.path.join(root_dir, "tools", "nmap", "nmap.exe")
    else:
        bundled = os.path.join(root_dir, "tools", "nmap", "nmap")

    if os.path.isfile(bundled):
        return bundled

    # 2. Check PATH
    in_path = shutil.which("nmap")
    if in_path:
        return in_path

    # 3. Common Windows paths
    if platform.system() == "Windows":
        for p in [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
            r"D:\Program Files\Nmap\nmap.exe",
            r"D:\Program Files (x86)\Nmap\nmap.exe",
        ]:
            if os.path.isfile(p):
                return p

    return None

def is_admin() -> bool:
    return True

# ─── Physical Adapter Detection (routing table based) ────────────────────────

# Blacklist patterns for virtual / non-physical adapters
_VIRTUAL_ADAPTER_PATTERNS = [
    "vmware", "vmnet", "virtualbox", "vbox", "hyper-v", "hyperv",
    "virtual ethernet", "teredo", "isatap", "6to4", "loopback",
    "vpn", "nordvpn", "expressvpn", "openvpn", "wireguard", "tunnelblick",
    "tap-", "tun0", "tun1", "docker", "wsl", "zerotier", "hamachi",
    "microsoft wi-fi direct", "wi-fi direct", "bluetooth",
    "ndis", "miniport", "wan miniport",
]

def _is_virtual_adapter(name: str) -> bool:
    lower = name.lower()
    return any(p in lower for p in _VIRTUAL_ADAPTER_PATTERNS)

def _get_default_route_interface() -> Optional[Dict[str, str]]:
    """
    Parse the Windows IPv4 routing table to find the interface associated
    with the default gateway (0.0.0.0 network destination).
    Returns: {interface_ip, gateway, metric}
    """
    try:
        out = subprocess.check_output(
            ["route", "print", "-4"],
            stderr=subprocess.DEVNULL,
            timeout=5
        ).decode("utf-8", errors="ignore")

        best_metric = None
        best_entry = None

        for line in out.splitlines():
            line = line.strip()
            # Match default route: 0.0.0.0  0.0.0.0  <gateway>  <interface_ip>  <metric>
            m = re.match(
                r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)",
                line
            )
            if m:
                gateway = m.group(1)
                iface_ip = m.group(2)
                metric = int(m.group(3))
                # Prefer lower metric (= more preferred route)
                if best_metric is None or metric < best_metric:
                    best_metric = metric
                    best_entry = {"interface_ip": iface_ip, "gateway": gateway, "metric": metric}

        return best_entry
    except Exception:
        return None

def _get_interface_info_from_psutil(target_ip: str) -> Optional[Dict[str, Any]]:
    """Given an IP address, find the matching psutil interface and its netmask."""
    try:
        import psutil
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()

        for iface_name, iface_addrs in addrs.items():
            for addr in iface_addrs:
                if addr.family == socket.AF_INET and addr.address == target_ip:
                    # Found matching interface
                    netmask = addr.netmask or "255.255.255.0"
                    is_up = stats.get(iface_name, None)
                    is_up = is_up.isup if is_up else True
                    return {
                        "name": iface_name,
                        "ip": target_ip,
                        "netmask": netmask,
                        "is_up": is_up
                    }
    except Exception:
        pass
    return None

def _calculate_subnet_cidr(ip: str, netmask: str) -> str:
    """Calculate CIDR notation from IP and netmask."""
    try:
        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        return str(network)
    except Exception:
        # Fallback: use /24
        octets = ip.split(".")
        if len(octets) == 4:
            return f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
        return "192.168.0.0/24"

def detect_local_network_info() -> Dict[str, Any]:
    """
    Detect local IP, gateway, subnet, active network interface, and DNS servers.
    
    Uses the routing table default route to identify the correct physical adapter.
    Will NOT select VMware, VirtualBox, Hyper-V, VPN, or loopback adapters
    when a real physical Wi-Fi or Ethernet adapter is available.
    """
    result = {
        "local_ip": "127.0.0.1",
        "gateway": None,
        "subnet": "192.168.0.0/24",
        "dns_server": None,
        "interface": "Unknown Interface",
        "adapter": "Unavailable",
        "netmask": "255.255.255.0",
        "all_subnets": [],
        "interfaces": [],
        "detection_method": "fallback"
    }

    # ── Step 1: Use routing table to find the default-route interface ──────────
    route_info = _get_default_route_interface()
    if route_info:
        iface_ip = route_info["interface_ip"]
        gateway  = route_info["gateway"]
        iface_info = _get_interface_info_from_psutil(iface_ip)

        if iface_info:
            iface_name = iface_info["name"]
            netmask    = iface_info["netmask"]
            subnet     = _calculate_subnet_cidr(iface_ip, netmask)

            result["local_ip"]         = iface_ip
            result["gateway"]          = gateway
            result["interface"]        = iface_name
            result["adapter"]          = iface_name
            result["netmask"]          = netmask
            result["subnet"]           = subnet
            result["detection_method"] = "routing_table"

            if subnet not in result["all_subnets"]:
                result["all_subnets"].append(subnet)
        else:
            # psutil didn't find it — construct subnet from routing table IP
            result["local_ip"] = iface_ip
            result["gateway"]  = gateway
            octets = iface_ip.split(".")
            if len(octets) == 4:
                subnet = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
                result["subnet"] = subnet
                if subnet not in result["all_subnets"]:
                    result["all_subnets"].append(subnet)
            result["detection_method"] = "routing_table_partial"

    # ── Step 2: If routing table gave us nothing, fall back to UDP socket ──────
    if result["local_ip"] == "127.0.0.1":
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(1.0)
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                if local_ip and not local_ip.startswith("127."):
                    result["local_ip"] = local_ip
                    octets = local_ip.split(".")
                    if len(octets) == 4:
                        subnet = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
                        result["subnet"] = subnet
                        if subnet not in result["all_subnets"]:
                            result["all_subnets"].append(subnet)
                    result["detection_method"] = "udp_socket"
        except Exception:
            pass

    # ── Step 3: Get DNS servers from ipconfig /all ─────────────────────────────
    try:
        if platform.system() == "Windows":
            # Find the DNS for our specific adapter
            out = subprocess.check_output(
                ["ipconfig", "/all"],
                stderr=subprocess.DEVNULL,
                timeout=5
            ).decode("utf-8", errors="ignore")

            current_adapter = ""
            in_target_section = False
            found_dns = False

            for line in out.splitlines():
                stripped = line.strip()

                # Detect adapter sections (lines ending with ":")
                if re.match(r'^[A-Za-z].*:$', stripped):
                    current_adapter = stripped
                    # Check if this section belongs to our detected interface
                    iface_name = result["interface"].lower()
                    in_target_section = (
                        iface_name in current_adapter.lower() or
                        iface_name in stripped.lower()
                    )
                    continue

                if "dns servers" in stripped.lower():
                    m = re.search(r"(\d+\.\d+\.\d+\.\d+)", stripped)
                    if m:
                        dns = m.group(1)
                        if not dns.startswith("127."):
                            if in_target_section or not found_dns:
                                result["dns_server"] = dns
                                found_dns = True

                # Also capture gateway from ipconfig if we didn't get it from route
                if not result["gateway"] and "default gateway" in stripped.lower():
                    m = re.search(r"(\d+\.\d+\.\d+\.\d+)", stripped)
                    if m:
                        gw = m.group(1)
                        if not gw.startswith("0."):
                            result["gateway"] = gw
        else:
            # Linux/macOS
            try:
                out = subprocess.check_output(
                    ["ip", "route"],
                    stderr=subprocess.DEVNULL,
                    timeout=4
                ).decode("utf-8")
                for line in out.splitlines():
                    if "default via" in line:
                        parts = line.split()
                        result["gateway"]   = parts[parts.index("via") + 1]
                        result["interface"] = parts[parts.index("dev") + 1]
            except Exception:
                pass

            if os.path.exists("/etc/resolv.conf"):
                with open("/etc/resolv.conf", "r") as f:
                    for line in f:
                        if line.startswith("nameserver"):
                            result["dns_server"] = line.split()[1]
                            break
    except Exception:
        pass

    if not result["dns_server"]:
        result["dns_server"] = result.get("gateway") or "8.8.8.8"

    # ── Step 4: Ensure subnet is correctly calculated from local IP + netmask ──
    if result["local_ip"] not in ("127.0.0.1", None) and result.get("netmask"):
        try:
            correct_subnet = _calculate_subnet_cidr(result["local_ip"], result["netmask"])
            if correct_subnet != result["subnet"]:
                result["subnet"] = correct_subnet
                if correct_subnet not in result["all_subnets"]:
                    result["all_subnets"].insert(0, correct_subnet)
        except Exception:
            pass

    return result

# ─── WAN IP Detection ──────────────────────────────────────────────────────────

def get_wan_ip() -> Optional[str]:
    """Fetch external public IP address using public API with timeout."""
    import urllib.request
    try:
        req = urllib.request.Request(
            "https://api.ipify.org?format=json",
            headers={'User-Agent': 'GuardNet/3.0'}
        )
        with urllib.request.urlopen(req, timeout=1.5) as response:
            data = json.loads(response.read().decode())
            return data.get("ip")
    except Exception:
        try:
            with urllib.request.urlopen("https://icanhazip.com", timeout=1.5) as response:
                return response.read().decode().strip()
        except Exception:
            return None

import psutil
import urllib.request

# Global net traffic trackers
_LAST_NET_IO = {"rx": 0, "tx": 0, "time": 0.0}
_BANDWIDTH_LOCK = threading.Lock()

def init_bandwidth_baseline():
    global _LAST_NET_IO
    with _BANDWIDTH_LOCK:
        try:
            net_io = psutil.net_io_counters()
            _LAST_NET_IO = {"rx": net_io.bytes_recv, "tx": net_io.bytes_sent, "time": time.time()}
        except Exception:
            pass

def get_realtime_bandwidth() -> Tuple[float, float]:
    global _LAST_NET_IO
    now = time.time()
    with _BANDWIDTH_LOCK:
        try:
            net_io = psutil.net_io_counters()
            rx = net_io.bytes_recv
            tx = net_io.bytes_sent

            dt = now - _LAST_NET_IO["time"]
            if dt >= 0.5 and _LAST_NET_IO["time"] > 0:
                rx_speed = ((rx - _LAST_NET_IO["rx"]) * 8) / (dt * 1_000_000)
                tx_speed = ((tx - _LAST_NET_IO["tx"]) * 8) / (dt * 1_000_000)
                rx_speed = max(0.0, round(rx_speed, 2))
                tx_speed = max(0.0, round(tx_speed, 2))
            else:
                rx_speed = 0.0
                tx_speed = 0.0

            _LAST_NET_IO = {"rx": rx, "tx": tx, "time": now}
            return rx_speed, tx_speed
        except Exception:
            return 0.0, 0.0

# ─── Gateway Router Details ────────────────────────────────────────────────────

def get_gateway_router_details_sync(gateway_ip: str, simulation_mode: bool) -> dict:
    """
    Inspects gateway IP to discover router info with reliability.
    Only shows confirmed info — never guesses vendor or model.
    """
    details = {
        "vendor": "Unavailable",
        "model": "Unavailable",
        "firmware": "Unavailable",
        "os": "Unavailable",
        "uptime": "Unavailable",
        "lan_ip": gateway_ip or "Unavailable",
        "wan_ip": "Detecting...",
        "hostname": "Unavailable",
        "interface_type": "Unavailable",
        "dns_servers": "Unavailable",
        "dhcp_range": "Unavailable",
        "connection_type": "Unavailable",
        "snmp_active": False,
        "upnp_active": False,
        "analytics": None
    }

    net_info = detect_local_network_info()
    if net_info.get("dns_server"):
        details["dns_servers"] = net_info["dns_server"]

    # Connection/Interface type heuristics from adapter name
    iface = net_info.get("interface", "").lower()
    adapter = net_info.get("adapter", "").lower()
    if any(x in iface or x in adapter for x in ["wi-fi", "wireless", "802.11", "wlan", "wifi", "intel wireless", "realtek wireless"]):
        details["interface_type"] = "Wireless (Wi-Fi)"
        details["connection_type"] = "Wireless"
    elif any(x in iface or x in adapter for x in ["ethernet", "local area", "gigabit", "realtek pcie", "intel ethernet"]):
        details["interface_type"] = "Wired (Ethernet)"
        details["connection_type"] = "Wired"

    if simulation_mode:
        details["vendor"] = "Demo Vendor"
        details["model"] = "Demo Gateway Router"
        details["firmware"] = "Simulated"
        details["os"] = "Embedded Linux (Simulated)"
        details["uptime"] = "Simulated Session"
        details["hostname"] = "gateway.local"
        details["dhcp_range"] = "192.168.0.100 – 192.168.0.254"
        details["snmp_active"] = False
        details["upnp_active"] = False
        details["analytics"] = {
            "upload_speed": 0.0,
            "download_speed": 0.0,
            "active_clients": 0,
            "network_utilization": 0.0,
            "connected_devices": 0
        }
        try:
            rx, tx = get_realtime_bandwidth()
            details["analytics"]["download_speed"] = rx
            details["analytics"]["upload_speed"] = tx
        except Exception:
            pass
        return details

    if not gateway_ip:
        return details

    # Resolve hostname via DNS (reliable)
    try:
        host, _, _ = socket.gethostbyaddr(gateway_ip)
        if host and host != gateway_ip:
            details["hostname"] = host
    except Exception:
        details["hostname"] = "Unavailable"

    # DHCP range heuristic
    if gateway_ip:
        octets = gateway_ip.split(".")
        if len(octets) == 4:
            details["dhcp_range"] = f"{octets[0]}.{octets[1]}.{octets[2]}.100 – {octets[0]}.{octets[1]}.{octets[2]}.254"

    # Check open ports on gateway
    try:
        open_ports = []
        for port in [53, 80, 443, 161, 1900]:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.4)
            res = s.connect_ex((gateway_ip, port))
            if res == 0:
                open_ports.append(port)
            s.close()

        details["snmp_active"] = (161 in open_ports)
        details["upnp_active"] = (1900 in open_ports)
    except Exception:
        pass

    # Pull confirmed data from DB if a previous scan logged this gateway
    try:
        with database.get_db() as db:
            dev = db.query(database.Device).filter(database.Device.ip_address == gateway_ip).first()
            if dev:
                if dev.vendor and dev.vendor not in ("Unknown Manufacturer", "Unknown", None, ""):
                    details["vendor"] = dev.vendor
                if details["hostname"] in ("Unavailable", None) and dev.hostname and dev.hostname != gateway_ip:
                    details["hostname"] = dev.hostname
                if dev.os_name and dev.os_name not in ("Unknown OS", "Unknown", None, ""):
                    details["os"] = dev.os_name
    except Exception:
        pass

    # Local PC uptime (clearly labeled)
    try:
        boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
        uptime_delta = datetime.datetime.now() - boot_time
        days = uptime_delta.days
        hours, remainder = divmod(uptime_delta.seconds, 3600)
        minutes, _ = divmod(remainder, 60)
        details["uptime"] = f"{days}d {hours}h {minutes}m (Local PC uptime)"
    except Exception:
        details["uptime"] = "Unavailable"

    # Fetch public WAN IP
    wan = get_wan_ip()
    details["wan_ip"] = wan if wan else "No Internet Access"

    # Real-time bandwidth
    try:
        rx_speed, tx_speed = get_realtime_bandwidth()
        with database.get_db() as db:
            connected = db.query(database.Device).filter(database.Device.status == "up").count()
        details["analytics"] = {
            "upload_speed": tx_speed,
            "download_speed": rx_speed,
            "active_clients": connected,
            "network_utilization": round(min(99.0, (rx_speed + tx_speed) * 5.0), 1),
            "connected_devices": connected
        }
    except Exception:
        details["analytics"] = {
            "upload_speed": 0.0,
            "download_speed": 0.0,
            "active_clients": 0,
            "network_utilization": 0.0,
            "connected_devices": 0
        }

    return details

# ─── ARP Table Parser ──────────────────────────────────────────────────────────

def perform_scapy_arp_discovery(target_subnet: str) -> List[Dict[str, str]]:
    """Actively sweep the local subnet using Scapy ARP requests to find live hosts immediately."""
    devices = []
    try:
        from scapy.all import ARP, Ether, srp
        # Send ARP who-has to target_subnet
        # timeout=2, retry=1 for quick results
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_subnet), timeout=2, retry=1, verbose=False)
        for sent, received in ans:
            ip = received.psrc
            mac = received.hwsrc.upper()
            devices.append({"ip_address": ip, "mac_address": mac})
    except Exception as e:
        print(f"[Scanner] Scapy ARP discovery failed: {e}")
    return devices

def parse_arp_table(target_subnet: str = None) -> List[Dict[str, str]]:
    """Parse the OS ARP table and perform active Scapy sweep (if local subnet is provided) to get visible hosts."""
    devices = {}
    
    # 1. Active Scapy ARP Sweep (if we know the target)
    if target_subnet:
        scapy_devices = perform_scapy_arp_discovery(target_subnet)
        for d in scapy_devices:
            devices[d["ip_address"]] = d["mac_address"]

    # 2. Passive OS ARP Cache Parsing
    try:
        if platform.system() == "Windows":
            out = subprocess.check_output(
                ["arp", "-a"],
                stderr=subprocess.DEVNULL,
                timeout=10
            ).decode("utf-8", errors="ignore")

            for line in out.splitlines():
                match = re.match(
                    r'\s*([\d\.]+)\s+([\w\-:]+)\s+(dynamic|static)',
                    line, re.IGNORECASE
                )
                if match:
                    ip = match.group(1)
                    mac = match.group(2).replace("-", ":").upper()
                    if not ip.startswith("224.") and not ip.endswith(".255") and ip != "255.255.255.255":
                        if ip not in devices:
                            devices[ip] = mac
        else:
            out = subprocess.check_output(
                ["arp", "-n"],
                stderr=subprocess.DEVNULL,
                timeout=10
            ).decode("utf-8", errors="ignore")
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 3 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]):
                    ip = parts[0]
                    mac = parts[2].upper() if ":" in parts[2] else None
                    if mac and mac != "(INCOMPLETE)":
                        if ip not in devices:
                            devices[ip] = mac
    except Exception as e:
        print(f"[Scanner] OS ARP parse failed: {e}")
        
    return [{"ip_address": ip, "mac_address": mac} for ip, mac in devices.items()]

# ─── OS Name Cleaner ──────────────────────────────────────────────────────────

def clean_os_name(os_name: str) -> str:
    if not os_name:
        return "Unknown OS"
    n = os_name.lower()
    if "windows 11" in n:            return "Windows 11"
    elif "windows 10" in n:          return "Windows 10"
    elif "windows server 2022" in n: return "Windows Server 2022"
    elif "windows server 2019" in n: return "Windows Server 2019"
    elif "windows server" in n:      return "Windows Server"
    elif "windows" in n:             return "Windows"
    elif "ios" in n and "cisco" not in n: return "iOS"
    elif "macos" in n or "mac os" in n or "os x" in n: return "macOS"
    elif "android" in n:             return "Android OS"
    elif "ubuntu" in n:              return "Ubuntu Linux"
    elif "debian" in n:              return "Debian Linux"
    elif "centos" in n:              return "CentOS Linux"
    elif "fedora" in n:              return "Fedora Linux"
    elif "raspbian" in n:            return "Raspbian Linux"
    elif "linux" in n:               return "Linux"
    elif "freebsd" in n:             return "FreeBSD"
    elif "openbsd" in n:             return "OpenBSD"
    elif "tizen" in n:               return "Tizen OS"
    elif "webos" in n:               return "webOS"
    elif "embedded" in n or "router" in n or "cisco ios" in n: return "Embedded OS"
    else:                            return os_name[:50]  # preserve original if unrecognized

# ─── Confidence-Based Device Classification ──────────────────────────────────

def classify_device(
    hostname: str,
    vendor: str,
    os_name: str,
    open_ports: List[int],
    services: List[str] = None,
    gateway_ip: str = None,
    device_ip: str = None
) -> Tuple[str, str]:
    """
    Multi-signal confidence-based device classification.
    Returns (device_type, confidence) where confidence is 'High', 'Medium', or 'Low'.
    """
    hostname  = (hostname or "").lower().strip()
    vendor    = (vendor or "").lower().strip()
    os_clean  = (os_name or "").lower().strip()
    services_lower = [s.lower() for s in (services or [])]

    scores: Dict[str, int] = {}

    def add(dtype, pts):
        scores[dtype] = scores.get(dtype, 0) + pts

    # ── Gateway detection: strongest signal ─────────────────────────────────
    if gateway_ip and device_ip and device_ip == gateway_ip:
        return "Router", "High"
    if any(x in hostname for x in ["gateway", "router", "gw.", "gw-", "rt-", "modem", "pfsense", "openwrt", "dd-wrt"]):
        add("Router / Gateway", 40)
    if any(x in vendor for x in ["netgear", "tp-link", "tplink", "cisco", "d-link", "linksys", "huawei", "ubiquiti", "zyxel", "mikrotik", "asus", "belkin", "arris"]):
        add("Router / Gateway", 25)
    if 53 in open_ports and 1900 in open_ports:
        add("Router / Gateway", 30)  # DNS + UPnP = gateway fingerprint
    if 67 in open_ports:  # DHCP server
        add("Router / Gateway", 35)
    if "embedded" in os_clean and (80 in open_ports or 443 in open_ports):
        add("Router / Gateway", 20)

    # ── Smart TV ────────────────────────────────────────────────────────────
    if any(x in hostname for x in ["appletv", "samsung-tv", "lg-tv", "sony-tv", "firetv", "roku", "chromecast", "fire-tv", "shield", "webos", "smarttv"]):
        add("Smart TV", 55)
    if "tizen" in os_clean or "webos" in os_clean:
        add("Smart TV", 60)
    if "samsung" in vendor and "tv" in hostname:
        add("Smart TV", 50)
    if 8001 in open_ports or 8060 in open_ports:  # Samsung SmartTV API / Roku
        add("Smart TV", 40)
    if any("smart-tv" in s for s in services_lower):
        add("Smart TV", 45)
    if "android" in os_clean and ("tv" in hostname or 8001 in open_ports or 8060 in open_ports):
        add("Smart TV", 40)

    # ── Streaming Device ────────────────────────────────────────────────────
    if any(x in hostname for x in ["appletv", "roku", "chromecast", "firestick", "fire-tv", "nvidia-shield"]):
        add("Streaming Device", 50)
    if "roku" in vendor:
        add("Streaming Device", 60)

    # ── Gaming Console ───────────────────────────────────────────────────────
    if any(x in hostname for x in ["xbox", "playstation", "ps4", "ps5", "nintendo", "switch", "wii"]):
        add("Gaming Console", 70)
    if any(x in vendor for x in ["sony interactive", "microsoft xbox", "nintendo"]):
        add("Gaming Console", 65)

    # ── IP Camera / CCTV ────────────────────────────────────────────────────
    if any(x in hostname for x in ["camera", "cam-", "ipcam", "cctv", "dvr", "nvr", "hikvision", "dahua", "axis", "onvif", "foscam"]):
        add("IP Camera", 60)
    if any(x in vendor for x in ["hikvision", "dahua", "axis", "foscam", "amcrest"]):
        add("IP Camera", 60)
    if 554 in open_ports or 8554 in open_ports:  # RTSP
        add("IP Camera", 50)
    if any("rtsp" in s or "onvif" in s for s in services_lower):
        add("IP Camera", 55)

    # ── Printer ─────────────────────────────────────────────────────────────
    if any(x in hostname for x in ["printer", "laserjet", "epson", "canon", "brother", "lexmark", "kyocera", "copier", "mfp"]):
        add("Printer", 60)
    if any(x in vendor for x in ["brother", "canon", "epson", "lexmark", "kyocera", "hewlett packard", "hp inc", "xerox", "ricoh"]):
        add("Printer", 55)
    if 9100 in open_ports or 515 in open_ports or 631 in open_ports:
        add("Printer", 50)

    # ── NAS Storage ─────────────────────────────────────────────────────────
    if any(x in hostname for x in ["nas", "synology", "qnap", "terastation", "freenas", "truenas", "readynas"]):
        add("NAS", 65)
    if "synology" in vendor or "qnap" in vendor:
        add("NAS", 65)
    if 5000 in open_ports or 5001 in open_ports:  # Synology DSM
        add("NAS", 40)
    if 5005 in open_ports:  # QNAP
        add("NAS", 40)

    # ── Server ───────────────────────────────────────────────────────────────
    if any(x in hostname for x in ["server", "srv-", "backup", "db-", "sql", "proxmox", "esxi", "vmware-host"]):
        add("Server", 50)
    if "windows server" in os_clean:
        add("Server", 55)
    if 22 in open_ports and "linux" in os_clean and "raspberry" not in vendor:
        add("Server", 20)
    if any(p in open_ports for p in [3306, 5432, 1433, 6379, 27017, 5672, 9200]):
        add("Server", 40)  # Databases

    # ── Smartphone / Mobile ──────────────────────────────────────────────────
    if any(x in hostname for x in ["iphone", "ipad", "ipod", "android", "galaxy", "pixel", "oneplus"]):
        add("Smartphone", 60)
    if "ios" in os_clean:
        add("Smartphone", 60)
    if "android" in os_clean and "tv" not in hostname:
        add("Smartphone", 55)
    if any(x in vendor for x in ["apple", "samsung electronics"]) and len(open_ports) == 0:
        add("Smartphone", 30)

    # ── Tablet ──────────────────────────────────────────────────────────────
    if any(x in hostname for x in ["ipad", "tablet", "kindle"]):
        add("Tablet", 60)

    # ── Laptop ───────────────────────────────────────────────────────────────
    if any(x in hostname for x in ["laptop", "macbook", "thinkpad", "latitude", "elitebook", "xps", "surface", "notebook"]):
        add("Laptop", 60)
    if "macbook" in hostname:
        add("Laptop", 70)
    if "macos" in os_clean:
        add("Laptop", 35)
    if "windows" in os_clean and any(x in hostname for x in ["laptop", "book", "portable"]):
        add("Laptop", 40)

    # ── Desktop ──────────────────────────────────────────────────────────────
    if any(x in hostname for x in ["desktop", "workstation", "pc-", "imac"]):
        add("Desktop", 55)
    if "windows" in os_clean:
        add("Desktop", 20)  # Windows is more likely a desktop than laptop without other signals
    if any(p in open_ports for p in [3389, 135, 445]):
        add("Desktop", 20)

    # ── IoT Device ───────────────────────────────────────────────────────────
    if any(x in hostname for x in ["esp", "esp8266", "esp32", "smart-bulb", "alexa", "echo", "hub", "nest", "hue", "ring", "wemo", "sonoff", "shelly"]):
        add("IoT Device", 55)
    if any(x in vendor for x in ["espressif", "tuya", "shenzhen", "amazon", "philips lighting"]):
        add("IoT Device", 45)
    if any(p in open_ports for p in [8008, 9000, 5000]):
        add("IoT Device", 40)
    if "raspberry" in vendor:
        add("IoT Device", 30)

    # ── Network Infrastructure ───────────────────────────────────────────────
    if any(x in hostname for x in ["switch", "ap-", "access-point", "wap-", "hub-"]):
        add("Network Infrastructure", 55)
    if any(x in vendor for x in ["cisco", "ubiquiti", "ruckus", "aruba", "juniper"]) and "router" not in hostname:
        add("Network Infrastructure", 40)

    # ── Determine winner ─────────────────────────────────────────────────────
    if not scores:
        return "Unknown Device", "Low"

    best_type  = max(scores, key=scores.get)
    best_score = scores[best_type]

    # Normalize confidence
    if best_score >= 60:
        confidence = "High"
    elif best_score >= 35:
        confidence = "Medium"
    else:
        confidence = "Low"

    # If no strong signal, return Unknown
    if best_score < 20:
        return "Unknown Device", "Low"

    return best_type, confidence

# Legacy compatibility function
def guess_device_type(
    hostname: str, vendor: str, os_name: str,
    open_ports: List[int], services: List[str] = None,
    gateway_ip: str = None, device_ip: str = None
) -> str:
    dtype, _ = classify_device(hostname, vendor, os_name, open_ports, services, gateway_ip, device_ip)
    return dtype

# ─── Port Risk Classification ──────────────────────────────────────────────────

def get_port_risk_and_desc(port: int, service: str) -> Tuple[str, str]:
    service = (service or "").lower()
    risk = "Low"
    desc = f"Standard network service on port {port}."

    PORT_INFO = {
        21:   ("High",   "FTP sends credentials in plaintext. Vulnerable to credential harvesting and sniffing attacks."),
        22:   ("Low",    "SSH provides encrypted remote access. Secure if strong key-based authentication is used."),
        23:   ("High",   "Telnet transmits all sessions in plaintext. CRITICAL: Disable immediately and use SSH (22) instead."),
        25:   ("Medium", "SMTP mail relay. Risk of spam relay abuse if misconfigured."),
        53:   ("Low",    "DNS service. Could be used for DNS amplification attacks if open recursion is enabled."),
        67:   ("Low",    "DHCP server port. Normal on gateway/router devices."),
        80:   ("Medium", "HTTP transmits web traffic without encryption. Upgrade to HTTPS to protect session data."),
        110:  ("Medium", "POP3 mail service. Transmits credentials in plaintext unless TLS is configured."),
        135:  ("Medium", "Windows RPC service. Exposed to DCE/RPC-based attacks. Restrict to trusted hosts."),
        139:  ("High",   "NetBIOS session service. Legacy Windows file sharing. High risk of lateral movement exploitation."),
        143:  ("Medium", "IMAP mail service. Ensure TLS is enforced to protect credentials."),
        443:  ("Low",    "HTTPS encrypted web traffic. Secure if TLS certificate is valid and up to date."),
        445:  ("High",   "SMB file sharing. CRITICAL: Known vector for EternalBlue/WannaCry ransomware. Restrict to LAN only."),
        554:  ("Low",    "RTSP streaming protocol. Used by IP cameras. Restrict access to authorized viewers only."),
        993:  ("Low",    "IMAPS — encrypted IMAP. Secure mail retrieval protocol."),
        995:  ("Low",    "POP3S — encrypted POP3. Secure mail retrieval protocol."),
        1433: ("High",   "Microsoft SQL Server. Database port exposed to network. Restrict access immediately."),
        1900: ("Low",    "UPnP discovery. May expose device to LAN-based UPnP attacks."),
        3306: ("High",   "MySQL database service. Database exposure is a critical security risk."),
        3389: ("Medium", "Remote Desktop Protocol (RDP). High risk of brute-force attacks. Use VPN or MFA."),
        5000: ("Low",    "NAS management service (e.g. Synology DSM). Restrict to trusted clients."),
        5432: ("High",   "PostgreSQL database. Database exposure is a critical security risk."),
        5900: ("High",   "VNC remote desktop. Vulnerable to brute force. Disable if not needed."),
        5901: ("High",   "VNC remote desktop session 2. Same risk profile as port 5900."),
        6379: ("High",   "Redis database. Often runs without authentication. Extremely high risk if exposed."),
        8001: ("Low",    "Samsung SmartTV API. Normal on Smart TV devices."),
        8060: ("Low",    "Roku device control. Normal on Roku streaming devices."),
        8080: ("Medium", "Alternative HTTP. Cleartext web traffic on non-standard port. Often hosts admin panels."),
        8443: ("Low",    "Alternative HTTPS. Encrypted web traffic on non-standard port."),
        9100: ("Low",    "Printer JetDirect service. Restrict to authorized print clients only."),
        515:  ("Low",    "LPD printer service. Restrict to authorized print clients only."),
        631:  ("Low",    "IPP printer service. Internet Printing Protocol."),
        27017:("High",   "MongoDB database. Often runs without authentication. Critical risk if network-exposed."),
    }

    if port in PORT_INFO:
        risk, desc = PORT_INFO[port]

    return risk, desc

# ─── Security Score ────────────────────────────────────────────────────────────

def calculate_security_score(ports: List[Dict[str, Any]]) -> int:
    score = 100
    PENALTIES = {
        21: 25, 23: 35, 445: 25, 139: 15, 3306: 25,
        5432: 25, 6379: 30, 27017: 30, 1433: 25,
        5900: 20, 5901: 20, 80: 5, 8080: 8, 3389: 12,
        135: 8, 110: 5, 143: 5
    }
    for p in ports:
        port_num = p.get("port")
        if p.get("state") != "open":
            continue
        penalty = PENALTIES.get(port_num, 3)
        score -= penalty

    open_count = sum(1 for p in ports if p.get("state") == "open")
    if open_count > 6:
        score -= (open_count - 6) * 3

    return max(10, score)

# ─── Nmap XML Parser ────────────────────────────────────────────────────────────

def parse_nmap_xml(xml_content: str, gateway_ip: str = None) -> List[Dict[str, Any]]:
    devices = []
    try:
        root = ET.fromstring(xml_content)
        for host in root.findall('host'):
            status_elem = host.find('status')
            if status_elem is not None and status_elem.get('state', 'up') != 'up':
                continue

            ip_address  = None
            mac_address = None
            vendor      = None

            for addr in host.findall('address'):
                addrtype = addr.get('addrtype')
                if addrtype == 'ipv4':
                    ip_address = addr.get('addr')
                elif addrtype == 'mac':
                    mac_address = addr.get('addr')
                    vendor = addr.get('vendor', None)

            if not ip_address:
                continue

            hostname = None
            hostnames_elem = host.find('hostnames')
            if hostnames_elem is not None:
                hostname_elem = hostnames_elem.find('hostname')
                if hostname_elem is not None:
                    hostname = hostname_elem.get('name')

            # Parse OS match
            os_name = "Unknown OS"
            firmware = None
            os_elem = host.find('os')
            if os_elem is not None:
                osmatch_elem = os_elem.find('osmatch')
                if osmatch_elem is not None:
                    name     = osmatch_elem.get('name', 'Unknown OS')
                    cleaned  = clean_os_name(name)
                    accuracy = osmatch_elem.get('accuracy')
                    if accuracy and int(accuracy) >= 70:
                        os_name = f"{cleaned} ({accuracy}% confidence)"
                    else:
                        os_name = cleaned
                
                # Fetch deeper OS info (Kernel/Firmware) exactly as Nmap provides
                for osclass in os_elem.findall('osclass'):
                    if osclass.get('type') in ('broadband router', 'router', 'switch', 'firewall', 'WAP'):
                        fw = osclass.get('osgen')
                        if fw: firmware = fw
                    elif osclass.get('type') == 'general purpose':
                        # Try to capture kernel versions
                        fam = osclass.get('osfamily')
                        gen = osclass.get('osgen')
                        if fam and gen and os_name == "Unknown OS":
                            os_name = f"{fam} {gen}"


            ports = []
            open_port_nums  = []
            services_found  = []
            ports_elem = host.find('ports')
            if ports_elem is not None:
                for port_elem in ports_elem.findall('port'):
                    port_id  = int(port_elem.get('portid'))
                    protocol = port_elem.get('protocol', 'tcp')
                    state_elem = port_elem.find('state')
                    state = state_elem.get('state', 'closed') if state_elem is not None else 'closed'

                    if state == 'open':
                        open_port_nums.append(port_id)
                        service_elem = port_elem.find('service')
                        service_name = service_elem.get('name', 'unknown') if service_elem is not None else 'unknown'
                        services_found.append(service_name)

                        product = service_elem.get('product', '') if service_elem is not None else ''
                        version = service_elem.get('version', '') if service_elem is not None else ''

                        service_desc = (f"{service_name} ({product} {version})".strip(" ()")) if (product or version) else service_name
                        risk, risk_desc = get_port_risk_and_desc(port_id, service_desc)

                        ports.append({
                            'port':       port_id,
                            'protocol':   protocol,
                            'service':    service_desc,
                            'state':      state,
                            'risk_level': risk,
                            'description': risk_desc
                        })

            device_type, confidence = classify_device(
                hostname, vendor, os_name, open_port_nums, services_found,
                gateway_ip=gateway_ip, device_ip=ip_address
            )
            security_score = calculate_security_score(ports)

            devices.append({
                'ip_address':    ip_address,
                'mac_address':   mac_address.upper() if mac_address else None,
                'hostname':      hostname,
                'vendor':        vendor,
                'os_name':       os_name,
                'firmware':      firmware,
                'device_type':   device_type,
                'classification_confidence': confidence,
                'status':        'up',
                'ports':         ports,
                'security_score': security_score
            })
    except Exception as e:
        print(f"[Scanner] Error parsing Nmap XML: {e}")
    return devices

# ─── Discovery Diagnostics ─────────────────────────────────────────────────────

def get_discovery_diagnostics() -> Dict[str, Any]:
    """Return capability status for the Discovery Diagnostics view."""
    net = detect_local_network_info()
    nmap_path = get_nmap_path()
    admin = is_admin()

    npcap_available = False
    scapy_available = False
    if platform.system() == "Windows":
        try:
            npcap_check = subprocess.run(
                ["sc", "query", "npcap"],
                capture_output=True, text=True, timeout=3
            )
            npcap_available = "RUNNING" in npcap_check.stdout
        except Exception:
            pass

    try:
        import scapy
        scapy_available = True
    except ImportError:
        pass

    # ARP table entries (currently reachable devices)
    arp_entries = parse_arp_table()
    return {
        "active_adapter":      net.get("adapter") or net.get("interface") or "Unavailable",
        "adapter_name":        net.get("interface", "Unavailable"),
        "detected_subnet":     net.get("subnet", "Unavailable"),
        "local_ip":            net.get("local_ip", "Unavailable"),
        "gateway":             net.get("gateway", "Unavailable"),
        "netmask":             net.get("netmask", "Unavailable"),
        "dns_server":          net.get("dns_server", "Unavailable"),
        "detection_method":    net.get("detection_method", "unknown"),
        "is_admin":            admin,
        "nmap_available":      nmap_path is not None,
        "nmap_path":           nmap_path or "Not found",
        "npcap_available":     npcap_available,
        "scapy_available":     scapy_available,
        "arp_hosts":           len(arp_entries),
        "arp_host_list":       [h["ip_address"] for h in arp_entries],
        "discovery_methods": {
            "nmap_host_discovery":  nmap_path is not None,
            "arp_table":            True,
            "npcap_passive":        npcap_available,
            "icmp_ping":            admin,
        },
        "limitations": [
            "Wi-Fi client isolation may prevent peer device visibility",
            "Guest network isolation separates guest devices",
            "Privacy-hardened devices may not respond to discovery",
            "Sleeping/idle devices may not respond to ping",
            "Firewall rules on devices can block scan responses",
        ]
    }

# ─── Simulation Mode ──────────────────────────────────────────────────────────

def _get_sim_base_ip() -> str:
    try:
        net = detect_local_network_info()
        subnet = net.get("subnet", "192.168.0.0/24")
        base = ".".join(subnet.split(".")[:3])
        return base
    except Exception:
        return "192.168.0"

def _build_mock_library(base_ip: str) -> List[Dict]:
    return [
        {
            "mac_address":  "E4:8D:8C:1A:2B:3C",
            "ip_address":   f"{base_ip}.1",
            "hostname":     "gateway.local",
            "vendor":       "Router Manufacturer",
            "device_type":  "Router / Gateway",
            "classification_confidence": "High",
            "os_name":      "Embedded Linux",
            "ports": [
                {"port": 80,  "protocol": "tcp", "service": "http",  "state": "open", "risk_level": "Medium", "description": "HTTP web admin panel"},
                {"port": 443, "protocol": "tcp", "service": "https", "state": "open", "risk_level": "Low",    "description": "HTTPS secure panel"},
                {"port": 53,  "protocol": "tcp", "service": "dns",   "state": "open", "risk_level": "Low",    "description": "DNS server"},
                {"port": 1900,"protocol": "udp", "service": "upnp",  "state": "open", "risk_level": "Low",    "description": "UPnP discovery"},
            ]
        },
        {
            "mac_address":  "00:22:68:55:A1:B2",
            "ip_address":   f"{base_ip}.100",
            "hostname":     "workstation-pc",
            "vendor":       "Dell Inc.",
            "device_type":  "Desktop",
            "classification_confidence": "High",
            "os_name":      "Windows 11",
            "ports": [
                {"port": 135,  "protocol": "tcp", "service": "msrpc",              "state": "open", "risk_level": "Medium", "description": "Windows RPC service"},
                {"port": 139,  "protocol": "tcp", "service": "netbios-ssn",        "state": "open", "risk_level": "High",   "description": "NetBIOS file sharing"},
                {"port": 445,  "protocol": "tcp", "service": "microsoft-ds (SMB)", "state": "open", "risk_level": "High",   "description": "SMB file sharing port"},
                {"port": 3389, "protocol": "tcp", "service": "ms-wbt-server (RDP)","state": "open", "risk_level": "Medium", "description": "Remote Desktop Protocol"},
            ]
        },
        {
            "mac_address":  "AC:BC:32:89:FE:D2",
            "ip_address":   f"{base_ip}.105",
            "hostname":     "macbook-pro",
            "vendor":       "Apple, Inc.",
            "device_type":  "Laptop",
            "classification_confidence": "High",
            "os_name":      "macOS",
            "ports": [
                {"port": 22,  "protocol": "tcp", "service": "ssh (OpenSSH 9.2)",   "state": "open", "risk_level": "Low", "description": "Secure Shell access"},
                {"port": 443, "protocol": "tcp", "service": "https",                "state": "open", "risk_level": "Low", "description": "HTTPS service"},
            ]
        },
        {
            "mac_address":  "3C:D9:2B:4E:5F:60",
            "ip_address":   f"{base_ip}.120",
            "hostname":     "hp-printer",
            "vendor":       "Hewlett-Packard",
            "device_type":  "Printer",
            "classification_confidence": "High",
            "os_name":      "HP JetDirect OS",
            "ports": [
                {"port": 80,   "protocol": "tcp", "service": "http (HP Management)", "state": "open", "risk_level": "Medium", "description": "Printer web console"},
                {"port": 515,  "protocol": "tcp", "service": "printer (LPD)",         "state": "open", "risk_level": "Low",    "description": "Line Printer Daemon"},
                {"port": 9100, "protocol": "tcp", "service": "jetdirect",             "state": "open", "risk_level": "Low",    "description": "JetDirect print port"},
            ]
        },
        {
            "mac_address":  "B8:81:98:3C:4D:5E",
            "ip_address":   f"{base_ip}.130",
            "hostname":     "samsung-tv",
            "vendor":       "Samsung Electronics",
            "device_type":  "Smart TV",
            "classification_confidence": "High",
            "os_name":      "Tizen OS",
            "ports": [
                {"port": 8001, "protocol": "tcp", "service": "smart-tv-remote", "state": "open", "risk_level": "Low",    "description": "Samsung SmartTV API"},
                {"port": 8080, "protocol": "tcp", "service": "http-proxy",      "state": "open", "risk_level": "Medium", "description": "HTTP proxy service"},
            ]
        },
        {
            "mac_address":  "B8:27:EB:5C:6D:7E",
            "ip_address":   f"{base_ip}.200",
            "hostname":     "raspi-device",
            "vendor":       "Raspberry Pi Foundation",
            "device_type":  "IoT Device",
            "classification_confidence": "Medium",
            "os_name":      "Raspbian Linux",
            "ports": [
                {"port": 22,   "protocol": "tcp", "service": "ssh (OpenSSH 8.4)", "state": "open", "risk_level": "Low",    "description": "SSH remote shell"},
                {"port": 80,   "protocol": "tcp", "service": "http (nginx)",       "state": "open", "risk_level": "Medium", "description": "Web server"},
            ]
        },
        {
            "mac_address":  "00:0C:29:A1:B2:C3",
            "ip_address":   f"{base_ip}.250",
            "hostname":     "legacy-server",
            "vendor":       "Dell Inc.",
            "device_type":  "Server",
            "classification_confidence": "High",
            "os_name":      "Ubuntu Linux",
            "ports": [
                {"port": 21,  "protocol": "tcp", "service": "ftp (vsftpd)",   "state": "open", "risk_level": "High",   "description": "FTP server — plaintext"},
                {"port": 23,  "protocol": "tcp", "service": "telnet",          "state": "open", "risk_level": "High",   "description": "Telnet — plaintext"},
                {"port": 80,  "protocol": "tcp", "service": "http (Apache)",   "state": "open", "risk_level": "Medium", "description": "HTTP web server"},
                {"port": 22,  "protocol": "tcp", "service": "ssh (OpenSSH 7)", "state": "open", "risk_level": "Low",   "description": "SSH remote access"},
            ]
        },
        {
            "mac_address":  "A4:C3:F0:11:22:33",
            "ip_address":   f"{base_ip}.145",
            "hostname":     "iphone-mobile",
            "vendor":       "Apple, Inc.",
            "device_type":  "Smartphone",
            "classification_confidence": "High",
            "os_name":      "iOS",
            "ports": []
        },
        {
            "mac_address":  "DC:A6:32:44:55:66",
            "ip_address":   f"{base_ip}.210",
            "hostname":     "nas-storage",
            "vendor":       "Synology Inc.",
            "device_type":  "NAS",
            "classification_confidence": "High",
            "os_name":      "DiskStation Manager",
            "ports": [
                {"port": 22,   "protocol": "tcp", "service": "ssh",            "state": "open", "risk_level": "Low",    "description": "Secure shell access"},
                {"port": 80,   "protocol": "tcp", "service": "http (DSM UI)",  "state": "open", "risk_level": "Medium", "description": "NAS web interface"},
                {"port": 443,  "protocol": "tcp", "service": "https (DSM UI)", "state": "open", "risk_level": "Low",    "description": "Secure NAS interface"},
                {"port": 5000, "protocol": "tcp", "service": "synology-dsm",   "state": "open", "risk_level": "Low",    "description": "Synology DSM service"},
            ]
        },
        {
            "mac_address":  "70:8B:CD:9E:F0:12",
            "ip_address":   f"{base_ip}.115",
            "hostname":     "gaming-console",
            "vendor":       "Sony Interactive Entertainment",
            "device_type":  "Gaming Console",
            "classification_confidence": "High",
            "os_name":      "FreeBSD",
            "ports": [
                {"port": 80,  "protocol": "tcp", "service": "http",  "state": "open", "risk_level": "Medium", "description": "Game service HTTP"},
                {"port": 443, "protocol": "tcp", "service": "https", "state": "open", "risk_level": "Low",    "description": "Secure game services"},
            ]
        },
    ]


def run_simulation(scan_id: int, target: str, scan_profile: str):
    """Full simulation engine — implements all 5 scan profiles with demo data."""
    try:
        update_progress(scan_id, 5, "Scanner engine initialized — Simulation Mode active", "running")
        time.sleep(0.3)
        update_progress(scan_id, 10, "Generating demo dataset — no real network scanning", "running")
        time.sleep(0.3)

        base_ip = _get_sim_base_ip()
        MOCK_DEVICES = _build_mock_library(base_ip)

        devices_to_insert = []
        discovered_ips    = []

        # ── Profile: inventory ──────────────────────────────────────────────
        if scan_profile == "inventory":
            update_progress(scan_id, 20, "Rechecking known devices in inventory", "running")
            time.sleep(0.4)

            try:
                with database.get_db() as db:
                    existing_devices = db.query(database.Device).all()
                    device_data = []
                    for d in existing_devices:
                        ports_raw = db.query(database.Port).filter(database.Port.device_id == d.id).all()
                        device_data.append({
                            "id": d.id,
                            "mac_address": d.mac_address,
                            "ip_address":  d.ip_address,
                            "hostname":    d.hostname,
                            "vendor":      d.vendor,
                            "device_type": d.device_type,
                            "os_name":     d.os_name,
                            "ports": [{"port": p.port, "protocol": p.protocol, "service": p.service,
                                       "state": p.state, "risk_level": p.risk_level, "description": p.description}
                                      for p in ports_raw]
                        })
            except Exception as e:
                update_progress(scan_id, 100, f"Inventory read error", "failed")
                database.update_scan_status(scan_id, "failed", 0)
                return

            if not device_data:
                update_progress(scan_id, 100, "No devices in inventory to verify", "completed")
                database.update_scan_status(scan_id, "completed", 0)
                return

            for i, d in enumerate(device_data):
                progress_val = 20 + int((i / max(len(device_data), 1)) * 65)
                status = "up" if random.random() > 0.10 else "down"
                update_progress(scan_id, progress_val,
                    f"Verified {d['ip_address']} — {'Online' if status == 'up' else 'Offline'}", "running")
                time.sleep(0.15)
                if status == "up":
                    discovered_ips.append(d["ip_address"])
                devices_to_insert.append({**d, "status": status})

        # ── Profile: quick ──────────────────────────────────────────────────
        elif scan_profile == "quick":
            update_progress(scan_id, 20, "Host discovery sweep — ping-free multi-probe method", "running")
            time.sleep(0.5)

            for i, mock in enumerate(MOCK_DEVICES):
                progress_val = 20 + int((i / len(MOCK_DEVICES)) * 65)
                update_progress(scan_id, progress_val, f"Discovered {mock['ip_address']} — {mock['device_type']}", "running")
                time.sleep(0.1)
                mock_copy = dict(mock)
                mock_copy["ports"]  = []  # Quick scan: no port data
                mock_copy["status"] = "up"
                devices_to_insert.append(mock_copy)
                discovered_ips.append(mock["ip_address"])

        # ── Profile: deep ───────────────────────────────────────────────────
        elif scan_profile == "deep":
            update_progress(scan_id, 15, "Initiating deep service inspection", "running")
            time.sleep(0.4)
            update_progress(scan_id, 25, "Enumerating open ports", "running")
            time.sleep(0.4)
            update_progress(scan_id, 35, "Service version fingerprinting active", "running")
            time.sleep(0.4)
            update_progress(scan_id, 45, "Operating system detection running", "running")
            time.sleep(0.4)

            for i, mock in enumerate(MOCK_DEVICES):
                progress_val = 45 + int((i / len(MOCK_DEVICES)) * 40)
                update_progress(scan_id, progress_val, f"Deep scan → {mock['ip_address']} ({mock['device_type']})", "running")
                time.sleep(0.1)
                mock_copy = dict(mock)
                mock_copy["status"] = "up"
                devices_to_insert.append(mock_copy)
                discovered_ips.append(mock["ip_address"])

        # ── Profile: audit ──────────────────────────────────────────────────
        elif scan_profile == "audit":
            update_progress(scan_id, 15, "Security audit starting — analyzing services", "running")
            time.sleep(0.4)
            update_progress(scan_id, 25, "Scanning for vulnerable services", "running")
            time.sleep(0.4)
            update_progress(scan_id, 38, "Running protocol security checks", "running")
            time.sleep(0.4)

            for i, mock in enumerate(MOCK_DEVICES):
                progress_val = 38 + int((i / len(MOCK_DEVICES)) * 47)
                high_risk = [p for p in mock.get("ports", []) if p.get("risk_level") == "High"]
                if high_risk:
                    update_progress(scan_id, progress_val,
                        f"Risk detected on {mock['ip_address']} — {len(high_risk)} vulnerable port(s)", "running")
                else:
                    update_progress(scan_id, progress_val, f"Audit {mock['ip_address']} — Clean", "running")
                time.sleep(0.1)
                mock_copy = dict(mock)
                mock_copy["status"] = "up"
                devices_to_insert.append(mock_copy)
                discovered_ips.append(mock["ip_address"])

        # ── Profile: standard (default) ─────────────────────────────────────
        else:
            update_progress(scan_id, 20, "Discovering active hosts on network", "running")
            time.sleep(0.4)
            update_progress(scan_id, 30, "Scanning top 1000 TCP ports on each host", "running")
            time.sleep(0.4)

            for i, mock in enumerate(MOCK_DEVICES):
                progress_val = 30 + int((i / len(MOCK_DEVICES)) * 55)
                port_count = len(mock.get("ports", []))
                update_progress(scan_id, progress_val,
                    f"Found {mock['ip_address']} — {mock['device_type']} ({port_count} port(s) open)", "running")
                time.sleep(0.1)
                mock_copy = dict(mock)
                mock_copy["status"] = "up"
                devices_to_insert.append(mock_copy)
                discovered_ips.append(mock_copy["ip_address"])

        # ── Finalize ────────────────────────────────────────────────────────
        update_progress(scan_id, 88, "Building network topology map", "running")
        time.sleep(0.3)
        update_progress(scan_id, 93, "Performing risk analysis", "running")
        time.sleep(0.3)

        for dev in devices_to_insert:
            try:
                status = dev.get("status", "up")
                device_id = database.upsert_device(
                    scan_id=scan_id,
                    ip_address=dev["ip_address"],
                    mac_address=dev.get("mac_address"),
                    hostname=dev.get("hostname"),
                    vendor=dev.get("vendor"),
                    device_type=dev.get("device_type", "Unknown Device"),
                    os_name=dev.get("os_name"),
                    status=status,
                    classification_confidence=dev.get("classification_confidence"),
                    is_simulation=True
                )
                database.update_device_ports_with_diff(device_id, dev.get("ports", []), scan_id)
                score = calculate_security_score(
                    [{"port": p["port"], "state": p.get("state", "open")} for p in dev.get("ports", [])]
                )
                database.update_device_security_score(device_id, score)
            except Exception as dev_err:
                print(f"[Simulation] Error inserting device {dev.get('ip_address')}: {dev_err}")
                continue

        if scan_profile not in ("quick",):
            try:
                database.mark_offline_missing_devices(scan_id, target, discovered_ips)
            except Exception:
                pass

        database.update_scan_status(scan_id, "completed", len(discovered_ips))
        update_progress(scan_id, 100, f"Scan complete — {len(discovered_ips)} demo hosts generated [SIMULATION]", "completed")

    except Exception as e:
        import traceback
        traceback.print_exc()
        try:
            database.update_scan_status(scan_id, "failed", 0)
        except Exception:
            pass
        update_progress(scan_id, 100, "Simulation error occurred", "failed")

# ─── Real Nmap Scan ────────────────────────────────────────────────────────────

async def run_nmap_async(scan_id: int, target: str, scan_profile: str):
    """Run a real Nmap scan as an asyncio coroutine with proper async subprocess."""
    try:
        nmap_path = get_nmap_path()
        if not nmap_path:
            update_progress(scan_id, 5, "Nmap not found — falling back to Simulation Mode", "running")
            await asyncio.sleep(0.5)
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, run_simulation, scan_id, target, scan_profile)
            return

        update_progress(scan_id, 5, "Scanner engine initialized", "running")
        admin = is_admin()

        # Detect gateway for classification
        net_info   = detect_local_network_info()
        gateway_ip = net_info.get("gateway")

        # ── Build nmap argument list per profile ────────────────────────────
        if scan_profile == "quick":
            # Quick Discovery: host detection only, no port scan
            # Use multiple host-discovery techniques for better coverage
            update_progress(scan_id, 10, "Quick Discovery — multi-probe host detection", "running")
            if admin:
                args = [nmap_path,
                    "-sn",                         # No port scan
                    "-PS22,80,443,3389",           # TCP SYN ping
                    "-PU53,67,123",                # UDP ping
                    "-PE",                         # ICMP echo
                    "--min-parallelism", "100",
                    "--max-rtt-timeout", "300ms",
                    "--stats-every", "3s",
                    "-oX", "-",
                    target
                ]
            else:
                args = [nmap_path,
                    "-sn",
                    "-Pn",
                    "-PS22,80,443,3389",
                    "--min-parallelism", "50",
                    "--stats-every", "3s",
                    "-oX", "-",
                    target
                ]

        elif scan_profile == "inventory":
            # Inventory Refresh: re-check previously discovered devices
            update_progress(scan_id, 10, "Inventory Refresh — rechecking known hosts", "running")
            try:
                with database.get_db() as db:
                    db_ips = [d.ip_address for d in db.query(database.Device).all()]
            except Exception:
                db_ips = []

            if not db_ips:
                update_progress(scan_id, 100, "No devices in inventory to refresh", "completed")
                database.update_scan_status(scan_id, "completed", 0)
                return

            args = [nmap_path,
                "-sn",
                "-Pn",
                "-PS22,80,443,3389",
                "--stats-every", "3s",
                "-oX", "-"
            ] + db_ips

        elif scan_profile == "deep":
            # Deep Inspection: service versions + OS detection
            update_progress(scan_id, 10, "Deep Inspection — service version and OS detection", "running")
            args = [nmap_path,
                "-sS",           # SYN scan (requires root)
                "-Pn",
                "-sV",           # Version detection
                "-O",            # OS detection
                "-F",            # Fast (top 100 ports)
                "--open",
                "--version-intensity", "5",
                "--stats-every", "3s",
                "-oX", "-",
                target
            ]

        elif scan_profile == "audit":
            # Security Audit: services + NSE scripts for vulnerability analysis
            update_progress(scan_id, 10, "Security Audit — service analysis and vulnerability checks", "running")
            args = [nmap_path,
                "-sS",
                "-Pn",
                "-sV",
                "-O",
                "-F",
                "--open",
                "--script=vuln",
                "--version-intensity", "5",
                "--stats-every", "3s",
                "-oX", "-",
                target
            ]

        else:  # standard
            # Standard Scan: common TCP ports, host + service discovery
            update_progress(scan_id, 10, "Standard Scan — top 1000 TCP ports", "running")
            args = [nmap_path,
                "-sS",
                "-Pn",
                "-sV",
                "-O",
                "-F",
                "--open",
                "--min-parallelism", "50",
                "--stats-every", "3s",
                "-oX", "-",
                target
            ]

        # ── Also grab ARP table before scan (augments discovery) ────────────
        try:
            # Check if target is a local subnet
            is_local = gateway_ip and any(target.startswith(gateway_ip.rsplit('.', 1)[0]) for _ in range(1))
            arp_subnet = target if is_local else None
            arp_hosts = parse_arp_table(arp_subnet)
        except Exception:
            arp_hosts = []

        # ── Launch Nmap process ──────────────────────────────────────────────
        process = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        update_progress(scan_id, 15, "Discovering active hosts", "running")

        # Parse Nmap stderr progress lines in real time
        async def read_stderr(stream):
            while True:
                line_bytes = await stream.readline()
                if not line_bytes:
                    break
                line = line_bytes.decode('utf-8', errors='ignore').strip()
                if not line:
                    continue
                match = re.search(r"About\s+(\d+(?:\.\d+)?)%\s+done", line, re.IGNORECASE)
                if match:
                    pct = float(match.group(1))
                    mapped_pct = int(15 + (pct / 100.0) * 70)

                    if scan_profile == "deep":
                        if pct > 60:   phase = "Identifying operating systems"
                        elif pct > 30: phase = "Service version fingerprinting"
                        else:          phase = "Enumerating open ports"
                    elif scan_profile == "audit":
                        if pct > 40:   phase = "Running vulnerability checks"
                        else:          phase = "Enumerating services"
                    elif scan_profile == "standard":
                        if pct > 40:   phase = "Enumerating TCP services"
                        else:          phase = "Discovering active hosts"
                    elif scan_profile == "quick":
                        phase = "Host discovery sweep"
                    elif scan_profile == "inventory":
                        phase = "Verifying device status"
                    else:
                        phase = "Scanning"

                    update_progress(scan_id, mapped_pct, phase, "running")

        # Buffer stdout chunks
        stdout_chunks = []
        async def read_stdout(stream):
            while True:
                chunk = await stream.read(65536)
                if not chunk:
                    break
                stdout_chunks.append(chunk)

        stderr_task = asyncio.create_task(read_stderr(process.stderr))
        stdout_task = asyncio.create_task(read_stdout(process.stdout))

        await asyncio.gather(stdout_task, stderr_task)
        await process.wait()

        stdout = b"".join(stdout_chunks)

        # ── Handle non-zero return code ──────────────────────────────────────
        if process.returncode != 0 and process.returncode is not None:
            err_msg = stdout.decode('utf-8', errors='ignore').strip()
            if any(x in err_msg.lower() for x in ["root", "permission", "administrator", "requires"]):
                update_progress(scan_id, 50, "Insufficient privileges — retrying with TCP connect scan", "running")
                args2 = [nmap_path, "-sT", "-Pn", "-F", "--open", "-oX", "-", target]
                process2 = await asyncio.create_subprocess_exec(
                    *args2,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await process2.communicate()
                if process2.returncode != 0:
                    update_progress(scan_id, 100, "Scan failed — check network and permissions", "failed")
                    database.update_scan_status(scan_id, "failed", 0)
                    return
            else:
                update_progress(scan_id, 100, "Scan encountered an error — check target subnet", "failed")
                database.update_scan_status(scan_id, "failed", 0)
                return

        update_progress(scan_id, 88, "Parsing scan results", "running")
        xml_content = stdout.decode('utf-8', errors='ignore')

        # ── Parse results ────────────────────────────────────────────────────
        if not xml_content.strip() or '<nmaprun' not in xml_content:
            # Fall back to ARP data for quick/standard scans
            if arp_hosts and scan_profile in ("quick", "standard"):
                devices = []
                for h in arp_hosts:
                    dtype, conf = classify_device(
                        None, None, None, [], gateway_ip=gateway_ip, device_ip=h['ip_address']
                    )
                    devices.append({
                        'ip_address':  h['ip_address'],
                        'mac_address': h.get('mac_address'),
                        'hostname':    None,
                        'vendor':      None,
                        'os_name':     'Unknown OS',
                        'device_type': dtype,
                        'classification_confidence': conf,
                        'status':      'up',
                        'ports':       [],
                        'security_score': 100
                    })
                discovered_ips = [d['ip_address'] for d in devices]
                update_progress(scan_id, 93, f"ARP table found {len(devices)} hosts", "running")
            else:
                update_progress(scan_id, 100, "Scan returned no hosts — verify target subnet", "failed")
                database.update_scan_status(scan_id, "failed", 0)
                return
        else:
            devices = parse_nmap_xml(xml_content, gateway_ip=gateway_ip)
            discovered_ips = [dev["ip_address"] for dev in devices]

            # Augment with ARP entries not found by nmap
            if scan_profile in ("quick", "standard"):
                nmap_ips = set(discovered_ips)
                for h in arp_hosts:
                    if h['ip_address'] not in nmap_ips:
                        dtype, conf = classify_device(
                            None, None, None, [], gateway_ip=gateway_ip, device_ip=h['ip_address']
                        )
                        devices.append({
                            'ip_address':  h['ip_address'],
                            'mac_address': h.get('mac_address'),
                            'hostname':    None,
                            'vendor':      None,
                            'os_name':     'Unknown OS',
                            'device_type': dtype,
                            'classification_confidence': conf,
                            'status':      'up',
                            'ports':       [],
                            'security_score': 100
                        })
                        discovered_ips.append(h['ip_address'])

        update_progress(scan_id, 93, "Performing risk analysis", "running")

        # ── Store results in database ─────────────────────────────────────────
        for dev in devices:
            try:
                device_id = database.upsert_device(
                    scan_id=scan_id,
                    ip_address=dev["ip_address"],
                    mac_address=dev.get("mac_address"),
                    hostname=dev.get("hostname"),
                    vendor=dev.get("vendor"),
                    device_type=dev.get("device_type", "Unknown Device"),
                    os_name=dev.get("os_name"),
                    status=dev.get("status", "up"),
                    classification_confidence=dev.get("classification_confidence"),
                    is_simulation=False
                )
                database.update_device_ports_with_diff(device_id, dev.get("ports", []), scan_id)
                score = calculate_security_score(
                    [{"port": p["port"], "state": p["state"]} for p in dev.get("ports", [])]
                )
                database.update_device_security_score(device_id, score)
            except Exception as dev_err:
                print(f"[Scanner] Error storing device {dev.get('ip_address')}: {dev_err}")
                continue

        if scan_profile not in ("quick",):
            try:
                database.mark_offline_missing_devices(scan_id, target, discovered_ips)
            except Exception:
                pass

        database.update_scan_status(scan_id, "completed", len(devices))
        update_progress(scan_id, 100, f"Scan complete — {len(devices)} hosts discovered", "completed")

    except Exception as e:
        import traceback
        traceback.print_exc()
        try:
            database.update_scan_status(scan_id, "failed", 0)
        except Exception:
            pass
        update_progress(scan_id, 100, "Scanner encountered an unexpected error", "failed")


def start_scan_job(scan_id: int, target: str, scan_profile: str, simulation_mode: bool):
    """Dispatch a scan job — simulation runs in a thread, real Nmap uses the event loop."""
    update_progress(scan_id, 0, "Scan job queued", "running")

    if simulation_mode:
        t = threading.Thread(
            target=run_simulation,
            args=(scan_id, target, scan_profile),
            daemon=True
        )
        t.start()
    else:
        if _EVENT_LOOP is not None and _EVENT_LOOP.is_running():
            asyncio.run_coroutine_threadsafe(
                run_nmap_async(scan_id, target, scan_profile),
                _EVENT_LOOP
            )
        else:
            def _run_in_thread():
                asyncio.run(run_nmap_async(scan_id, target, scan_profile))
            threading.Thread(target=_run_in_thread, daemon=True).start()

# Initialize bandwidth baseline when module loads
try:
    init_bandwidth_baseline()
except Exception:
    pass


# ─── Discovery Diagnostics ───────────────────────────────────────────────────

def get_discovery_diagnostics() -> Dict[str, Any]:
    """
    Returns a full diagnostic snapshot:
    - Active adapter name, IP, gateway, subnet, netmask, DNS
    - Nmap availability, path, version
    - Npcap driver status
    - Admin/root privilege status
    - ARP-visible hosts (immediately reachable without scanning)
    - Human-readable limitations list
    """
    net = detect_local_network_info()
    nmap_path = get_nmap_path()
    admin = is_admin()

    # Check npcap
    npcap_available = False
    try:
        if platform.system() == "Windows":
            npcap_dir = r"C:\Windows\System32\Npcap"
            npcap_available = os.path.isdir(npcap_dir)
        else:
            npcap_available = shutil.which("libpcap") is not None or os.path.exists("/usr/lib/libpcap.so")
    except Exception:
        pass

    # Check scapy
    scapy_available = False
    try:
        import importlib.util
        scapy_available = importlib.util.find_spec("scapy") is not None
    except Exception:
        pass

    # Get ARP host list (valid unicast IPs only)
    try:
        arp_hosts = parse_arp_table(target)
    except Exception:
        arp_hosts = []
    arp_ips = sorted(set(
        h["ip_address"] for h in arp_hosts
        if not h["ip_address"].startswith("224.")
        and not h["ip_address"].endswith(".255")
        and h["ip_address"] != "255.255.255.255"
    ))

    # Build limitations list
    limitations = []
    if not admin:
        limitations.append(
            "Not running as Administrator — SYN/ARP scanning is disabled. "
            "Use TCP-Connect scanning (slower, less stealthy). "
            "Run GuardNet as Administrator for full discovery capabilities."
        )
    if not npcap_available:
        limitations.append(
            "Npcap driver not detected — raw packet capture unavailable. "
            "Install Npcap from https://npcap.com for ARP-based active discovery."
        )
    if not nmap_path:
        limitations.append(
            "Nmap not found — only ARP-table passive discovery is available. "
            "Install Nmap from https://nmap.org/download to enable active scanning."
        )
    if not scapy_available:
        limitations.append(
            "Scapy not installed — Python-native ARP sweep unavailable. "
            "Optional: pip install scapy for supplemental discovery."
        )
    limitations.append(
        "Devices that block ICMP (ping) and are not in the ARP table cannot be "
        "observed by GuardNet. This is a fundamental network limitation, not a bug."
    )
    limitations.append(
        "Mobile devices with randomized MAC addresses may appear as new devices on "
        "each scan, even if they are known devices."
    )

    return {
        "active_adapter":   net.get("adapter") or net.get("interface") or "Unknown",
        "adapter_name":     net.get("adapter") or net.get("interface") or "Unknown",
        "detected_subnet":  net.get("subnet", "Unknown"),
        "local_ip":         net.get("local_ip", "Unknown"),
        "gateway":          net.get("gateway", "Unknown"),
        "netmask":          net.get("netmask", "Unknown"),
        "dns_server":       net.get("dns_server", "Unknown"),
        "detection_method": net.get("detection_method", "unknown"),
        "is_admin":         admin,
        "nmap_available":   nmap_path is not None,
        "nmap_path":        nmap_path or None,
        "npcap_available":  npcap_available,
        "scapy_available":  scapy_available,
        "arp_hosts":        len(arp_ips),
        "arp_host_list":    arp_ips,
        "limitations":      limitations,
        "discovery_methods": [
            "ARP Table Passive Scan",
            "Nmap Active Network Scan" if nmap_path else None,
            "ICMP Ping Sweep" if admin else None,
            "SYN Stealth Scan" if (admin and npcap_available and nmap_path) else None,
        ]
    }

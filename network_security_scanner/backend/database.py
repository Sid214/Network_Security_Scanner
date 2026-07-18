import os
import datetime
from contextlib import contextmanager
from sqlalchemy import create_engine, and_, or_, func
from sqlalchemy.orm import sessionmaker, scoped_session

try:
    from .models import Base, Scan, Device, Port, Alert, Vendor, Setting
except ImportError:
    from models import Base, Scan, Device, Port, Alert, Vendor, Setting

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scanner.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)
session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
SessionLocal = scoped_session(session_factory)

@contextmanager
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    Base.metadata.create_all(bind=engine)
    with get_db() as db:
        seed_settings(db)
        seed_vendors(db)

def seed_settings(db):
    default_settings = {
        "simulation_mode":    "true",
        "scan_schedule":      "manual",
        "alert_email":        "admin@guardnet.local",
        "alert_on_new":       "true",
        "alert_on_change":    "true",
        "default_subnet":     "192.168.1.0/24",
        "theme":              "dark",
        
        # SMTP email alert configuration defaults
        "smtp_enabled":       "false",
        "smtp_host":          "smtp.example.com",
        "smtp_port":          "587",
        "smtp_user":          "",
        "smtp_pass":          "",
        "smtp_security":      "tls",
        "smtp_from":          "guardnet@example.com",
        "alert_min_severity": "low",
    }
    for key, val in default_settings.items():
        if not db.query(Setting).filter(Setting.key == key).first():
            db.add(Setting(key=key, value=val))
    db.commit()

def seed_vendors(db):
    default_vendors = {
        "00:50:56": "VMware, Inc.",
        "00:0C:29": "VMware, Inc.",
        "00:15:5D": "Microsoft Corporation",
        "E4:8D:8C": "Netgear",
        "AC:BC:32": "Apple, Inc.",
        "00:03:93": "Apple, Inc.",
        "A4:C3:F0": "Apple, Inc.",
        "3C:D9:2B": "Hewlett-Packard",
        "00:25:90": "Super Micro Computer, Inc.",
        "B8:27:EB": "Raspberry Pi Foundation",
        "DC:A6:32": "Raspberry Pi Foundation",
        "00:1A:2B": "Cisco Systems",
        "FC:EC:DA": "Ubiquiti Networks",
        "E0:D9:E3": "Intel Corporation",
        "00:50:B6": "Intel Corporation",
        "B8:81:98": "Samsung Electronics",
        "00:22:68": "Dell Inc.",
        "70:8B:CD": "Sony Interactive Entertainment",
    }
    for prefix, name in default_vendors.items():
        if not db.query(Vendor).filter(Vendor.mac_prefix == prefix.upper()).first():
            db.add(Vendor(mac_prefix=prefix.upper(), name=name))
    db.commit()

def _register_pragmas():
    from sqlalchemy import event
    @event.listens_for(engine, "connect")
    def connect(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

_register_pragmas()


# ─── CVE VULNERABILITY DATABASE ──────────────────────────────────────────────

def match_cves_for_port(port: int, service: str) -> list:
    """Lookup known common CVE vulnerabilities for an open port and service banner."""
    service_lower = (service or "").lower()
    cves = []
    
    # 1. Backdoor Command Execution
    if "vsftpd 2.3.4" in service_lower:
        cves.append({
            "cve": "CVE-2011-2523",
            "title": "vsftpd 2.3.4 Backdoor Command Execution",
            "severity": "high",
            "cvss": 10.0,
            "desc": "The vsftpd 2.3.4 download archive contained a backdoor that opens a shell on port 6200 when a username ending in :) is used."
        })
    
    # 2. SMB v1 EternalBlue
    if port == 445:
        cves.append({
            "cve": "CVE-2017-0144",
            "title": "Microsoft SMBv1 Remote Code Execution (EternalBlue)",
            "severity": "high",
            "cvss": 9.3,
            "desc": "A critical remote code execution vulnerability exists in Microsoft SMBv1 servers (MS17-010), commonly exploited by WannaCry and Petya ransomware."
        })
        
    # 3. Apache Legacy XSS
    if "apache 2.2.3" in service_lower:
        cves.append({
            "cve": "CVE-2007-6200",
            "title": "Apache HTTP Server Cross-Site Scripting",
            "severity": "medium",
            "cvss": 4.3,
            "desc": "Cross-site scripting (XSS) vulnerability in Apache HTTP Server 2.2.x allows remote attackers to inject arbitrary web script via request headers."
        })
        
    # 4. OpenSSH Agent Forwarding
    if "openssh 7.2p2" in service_lower or "openssh 7.2" in service_lower:
        cves.append({
            "cve": "CVE-2016-10009",
            "title": "OpenSSH Agent Forwarding Remote Code Execution",
            "severity": "high",
            "cvss": 7.5,
            "desc": "A vulnerability in sshd allows remote code execution via agent forwarding hijacking of ssh-agent sockets."
        })
        
    # 5. Redis Unauthenticated Access
    if port == 6379:
        cves.append({
            "cve": "CWE-306",
            "title": "Redis Server Unauthenticated Access",
            "severity": "high",
            "cvss": 9.8,
            "desc": "Redis server exposed without password authentication, enabling remote attackers to execute commands, modify memory databases, and obtain RCE."
        })

    # 6. MongoDB Unauthenticated Access
    if port == 27017:
        cves.append({
            "cve": "CWE-306",
            "title": "MongoDB Instance Unauthenticated Exposure",
            "severity": "high",
            "cvss": 9.8,
            "desc": "MongoDB database is exposed to the public network without access control enabled, letting unauthorized users read or write all databases."
        })
        
    # 7. Telnet Cleartext Protocol
    if port == 23:
        cves.append({
            "cve": "CWE-319",
            "title": "Telnet Cleartext Sensitive Information Transmission",
            "severity": "high",
            "cvss": 8.5,
            "desc": "Telnet protocol transmits all session data, including management credentials, in cleartext. Upgrade immediately to SSH."
        })
        
    # 8. FTP Cleartext Protocol
    if port == 21:
        cves.append({
            "cve": "CWE-319",
            "title": "FTP Cleartext Credentials Transmission",
            "severity": "medium",
            "cvss": 6.5,
            "desc": "FTP protocol transmits passwords and payload data without encryption. Upgrade to SFTP or FTPS."
        })

    return cves


# ─── ALERTS CENTRAL HELPER ───────────────────────────────────────────────────

def create_alert(db, scan_id: int, device_id: int, type_: str, severity: str, message: str):
    """Inserts a new threat alert into SQLite and dispatches an SMTP email alert asynchronously."""
    alert = Alert(
        scan_id=scan_id,
        device_id=device_id,
        type=type_,
        severity=severity,
        message=message,
        timestamp=datetime.datetime.now(),
        resolved=False
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    
    # Dispatch SMTP alert in background
    try:
        from .alerts_sender import trigger_alert_email
    except ImportError:
        from alerts_sender import trigger_alert_email

    trigger_alert_email(
        severity=severity,
        subject=f"GuardNet Alert: {type_.replace('_', ' ').title()}",
        message_html=f"<p><strong>Threat Detected:</strong> {message}</p><p><strong>Device ID:</strong> {device_id}</p><p><strong>Alert Severity:</strong> {severity.upper()}</p>"
    )


# ─── SCAN HISTORY CRUD ────────────────────────────────────────────────────────

def create_scan(target: str, scan_type: str, status: str = "running") -> int:
    with get_db() as db:
        scan = Scan(
            target=target,
            scan_type=scan_type,
            status=status,
            timestamp=datetime.datetime.now()
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        return scan.id

def update_scan_status(scan_id: int, status: str, device_count: int = 0):
    with get_db() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = status
            scan.device_count = device_count
            db.commit()

def get_all_scans() -> list:
    with get_db() as db:
        scans = db.query(Scan).order_by(Scan.timestamp.desc()).all()
        return [
            {
                "id": s.id,
                "timestamp": s.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "target": s.target,
                "scan_type": s.scan_type,
                "status": s.status,
                "device_count": s.device_count
            }
            for s in scans
        ]

def get_scan(scan_id: int) -> dict:
    with get_db() as db:
        s = db.query(Scan).filter(Scan.id == scan_id).first()
        if not s:
            return None
        return {
            "id": s.id,
            "timestamp": s.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "target": s.target,
            "scan_type": s.scan_type,
            "status": s.status,
            "device_count": s.device_count
        }

def get_scan_details(scan_id: int) -> dict:
    with get_db() as db:
        s = db.query(Scan).filter(Scan.id == scan_id).first()
        if not s:
            return None

        devices = db.query(Device).filter(Device.scan_id == scan_id).all()
        device_list = []
        for d in devices:
            ports = db.query(Port).filter(Port.device_id == d.id).all()
            port_list = [
                {"id": p.id, "port": p.port, "protocol": p.protocol,
                 "service": p.service, "state": p.state,
                 "risk_level": p.risk_level, "description": p.description}
                for p in ports
            ]
            device_list.append({
                "id": d.id,
                "ip_address": d.ip_address,
                "mac_address": d.mac_address,
                "hostname": d.hostname,
                "vendor": d.vendor,
                "device_type": d.device_type,
                "os_name": d.os_name,
                "status": d.status,
                "first_seen": d.first_seen.strftime("%Y-%m-%d %H:%M:%S"),
                "last_seen": d.last_seen.strftime("%Y-%m-%d %H:%M:%S"),
                "appearance_count": d.appearance_count,
                "security_score": d.security_score,
                "classification_confidence": d.classification_confidence,
                "ports": port_list
            })

        return {
            "id": s.id,
            "timestamp": s.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "target": s.target,
            "scan_type": s.scan_type,
            "status": s.status,
            "device_count": s.device_count,
            "devices": device_list
        }

def delete_scan(scan_id: int) -> bool:
    with get_db() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return False
        db.delete(scan)
        db.commit()
        return True

def delete_selected_scans(scan_ids: list) -> bool:
    """Deletes multiple scans from history."""
    with get_db() as db:
        scans = db.query(Scan).filter(Scan.id.in_(scan_ids)).all()
        if not scans:
            return False
        for s in scans:
            db.delete(s)
        db.commit()
        return True

def clear_all_scans() -> bool:
    """Wipes all scan logs and related devices/ports/alerts from database."""
    with get_db() as db:
        db.query(Scan).delete(synchronize_session=False)
        db.query(Device).delete(synchronize_session=False)
        db.query(Port).delete(synchronize_session=False)
        db.query(Alert).delete(synchronize_session=False)
        db.commit()
        return True


# ─── DEVICE INVENTORY OPERATIONS ─────────────────────────────────────────────

def upsert_device(scan_id: int, ip_address: str, mac_address: str = None, hostname: str = None,
                  vendor: str = None, device_type: str = "Unknown Device", os_name: str = None,
                  status: str = "up", classification_confidence: str = None, is_simulation: bool = False) -> int:
    with get_db() as db:
        device = None
        if mac_address:
            device = db.query(Device).filter(Device.mac_address == mac_address.upper()).first()
        if not device:
            device = db.query(Device).filter(
                and_(Device.ip_address == ip_address, Device.mac_address == None)
            ).first()

        now = datetime.datetime.now()
        alert_on_new    = get_setting_value("alert_on_new")    == "true"
        alert_on_change = get_setting_value("alert_on_change") == "true"

        # Determine if MAC is randomized (locally administered MAC)
        is_randomized = False
        if mac_address and len(mac_address) >= 2:
            second_char = mac_address[1].upper()
            if second_char in ('2', '6', 'A', 'E'):
                is_randomized = True

        if not device:
            detected_vendor = vendor
            if mac_address:
                prefix = mac_address.upper()[:8]
                vendor_rec = db.query(Vendor).filter(Vendor.mac_prefix == prefix).first()
                if vendor_rec:
                    detected_vendor = vendor_rec.name
                elif not detected_vendor:
                    detected_vendor = "Unknown Manufacturer"

            # Insert new device
            device = Device(
                scan_id=scan_id,
                ip_address=ip_address,
                mac_address=mac_address.upper() if mac_address else None,
                hostname=hostname,
                vendor=detected_vendor,
                device_type=device_type,
                os_name=os_name,
                status=status,
                first_seen=now,
                last_seen=now,
                appearance_count=1,
                security_score=100,
                classification_confidence=classification_confidence
            )
            db.add(device)
            db.flush()
            device_id = device.id
            db.commit()

            if device_id is None:
                device = db.query(Device).filter(
                    Device.ip_address == ip_address,
                    Device.mac_address == (mac_address.upper() if mac_address else None)
                ).order_by(Device.id.desc()).first()
                device_id = device.id if device else None

            if alert_on_new and device_id is not None:
                # Severity depends on critical category
                severity = "high" if device_type in ["Router", "Server", "Desktop", "Storage Server"] else "medium"
                create_alert(db, scan_id, device_id, "new_device", severity,
                             f"New device joined network: {ip_address} ({hostname or 'No Hostname'}) — MAC: {mac_address or 'N/A'}")

            # Rogue device alert for randomized MACs
            if is_randomized and device_id is not None:
                create_alert(db, scan_id, device_id, "rogue_device", "high",
                             f"Warning: Potential rogue device detected at {ip_address}. Device is using a randomized MAC address ({mac_address}).")

            if detected_vendor == "Unknown Manufacturer" and mac_address and not is_randomized and alert_on_change and device_id is not None:
                create_alert(db, scan_id, device_id, "unknown_vendor", "low",
                             f"Unknown manufacturer prefix on {ip_address} — MAC: {mac_address[:8]}")
        else:
            # Device exists. Update state.
            if alert_on_change:
                if hostname and device.hostname and device.hostname != hostname:
                    create_alert(db, scan_id, device.id, "hostname_changed", "medium",
                                 f"Hostname changed on {device.ip_address}: '{device.hostname}' → '{hostname}'")
                if device.ip_address != ip_address:
                    create_alert(db, scan_id, device.id, "ip_changed", "low",
                                 f"Device MAC {device.mac_address} changed IP: {device.ip_address} → {ip_address}")

            device.scan_id = scan_id
            device.ip_address = ip_address
            if hostname:
                device.hostname = hostname
            if os_name and os_name != "Unknown OS":
                device.os_name = os_name
            if device_type and device_type not in ("Unknown", "Unknown Device"):
                device.device_type = device_type
            if vendor and (not device.vendor or device.vendor == "Unknown Manufacturer"):
                device.vendor = vendor
            if classification_confidence:
                device.classification_confidence = classification_confidence
            device.status = status
            device.last_seen = now
            device.appearance_count += 1
            db.commit()
            device_id = device.id
        return device_id

def delete_device_ports(device_id: int):
    with get_db() as db:
        db.query(Port).filter(Port.device_id == device_id).delete()
        db.commit()

def update_device_ports_with_diff(device_id: int, new_ports: list, scan_id: int = None):
    """
    Diffs the list of open ports before deleting/re-inserting to detect and alert on changes.
    Also handles local CVE matching and critical vulnerability triggers.
    """
    with get_db() as db:
        # Fetch current ports in database
        old_ports = db.query(Port).filter(Port.device_id == device_id).all()
        old_open_set = {p.port for p in old_ports if p.state == "open"}
        new_open_set = {p["port"] for p in new_ports if p.get("state") == "open"}

        device = db.query(Device).filter(Device.id == device_id).first()
        device_ip = device.ip_address if device else "Device"

        # If previous scans exist, alert on diffs
        if len(old_open_set) > 0 and old_open_set != new_open_set:
            added = new_open_set - old_open_set
            removed = old_open_set - new_open_set
            
            msg = f"Port configuration changed on {device_ip}:"
            if added:
                msg += f" Exposed new ports {list(added)};"
            if removed:
                msg += f" Closed old ports {list(removed)};"
            
            if get_setting_value("alert_on_change") == "true":
                create_alert(db, scan_id, device_id, "port_changed", "medium", msg)

        # Delete all old ports
        db.query(Port).filter(Port.device_id == device_id).delete()
        db.commit()

        # Insert new ports with CVE matching
        for p in new_ports:
            port_num = p["port"]
            proto = p.get("protocol", "tcp")
            service = p.get("service", "")
            state = p.get("state", "open")
            
            risk_level = "Low"
            description = f"Standard network service on port {port_num}."

            # Perform CVE matching
            cves = match_cves_for_port(port_num, service)
            if cves:
                cve_texts = []
                for cve in cves:
                    cve_texts.append(f"[{cve['cve']}] {cve['title']} (CVSS: {cve['cvss']}) - {cve['desc']}")
                    if cve['severity'] == 'high':
                        risk_level = "High"
                    elif cve['severity'] == 'medium' and risk_level != "High":
                        risk_level = "Medium"
                description = " | ".join(cve_texts)
            else:
                # Custom port alerts fallback
                if port_num in [21, 23, 445, 6379, 27017]:
                    risk_level = "High"
                    description = f"Critical exposed interface: Port {port_num} ({service}) is vulnerable."
                elif port_num in [80, 8080, 3389]:
                    risk_level = "Medium"

            port = Port(
                device_id=device_id,
                port=port_num,
                protocol=proto,
                service=service,
                state=state,
                risk_level=risk_level,
                description=description
            )
            db.add(port)

            # Trigger critical vulnerability alert
            if state == "open" and (risk_level == "High" or port_num in [21, 23, 445, 6379, 27017]):
                dup = db.query(Alert).filter(
                    and_(Alert.device_id == device_id,
                         Alert.type == "insecure_service",
                         Alert.resolved == False,
                         Alert.message.like(f"%port {port_num}%"))
                ).first()
                if not dup and get_setting_value("alert_on_change") == "true":
                    create_alert(db, scan_id, device_id, "insecure_service", "high",
                                 f"Critical vulnerability: Insecure protocol active on {device_ip} (port {port_num} - {service})")
        db.commit()


def mark_offline_missing_devices(scan_id: int, target: str, discovered_ips: list):
    """
    Identifies devices in target range that went missing/offline in the latest scan cycle.
    Updates their status in the DB and triggers disappeared device alerts.
    """
    with get_db() as db:
        # Determine prefix if it's a subnet (e.g. 192.168.1.0/24 -> prefix is 192.168.1.)
        subnet_prefix = None
        if "/" in target:
            base_ip = target.split("/")[0]
            octets = base_ip.split(".")
            if len(octets) >= 3:
                subnet_prefix = f"{octets[0]}.{octets[1]}.{octets[2]}."

        query = db.query(Device).filter(Device.status == "up")
        
        # If subnet prefix is detected, check only that range. Otherwise check specific IP.
        if subnet_prefix:
            query = query.filter(Device.ip_address.like(f"{subnet_prefix}%"))
        else:
            query = query.filter(Device.ip_address == target)

        active_devices = query.all()
        for d in active_devices:
            if d.ip_address not in discovered_ips:
                d.status = "down"
                d.last_seen = datetime.datetime.now()
                db.commit()
                
                # Disappeared alert trigger
                create_alert(db, scan_id, d.id, "device_offline", "medium",
                             f"Device disappeared: {d.ip_address} ({d.hostname or 'No Hostname'}) has gone offline or dropped off network.")


def insert_port(device_id: int, port_number: int, protocol: str = "tcp", service: str = None,
                state: str = "open", risk_level: str = "Low", description: str = None):
    """Fallback function for backward compatibility."""
    with get_db() as db:
        port = Port(
            device_id=device_id,
            port=port_number,
            protocol=protocol,
            service=service,
            state=state,
            risk_level=risk_level,
            description=description
        )
        db.add(port)
        db.commit()

def update_device_security_score(device_id: int, score: int):
    with get_db() as db:
        device = db.query(Device).filter(Device.id == device_id).first()
        if device:
            device.security_score = score
            db.commit()

def get_devices(search_query: str = None, category_filter: str = None, risk_filter: str = None, sort_by: str = "score_desc") -> list:
    with get_db() as db:
        query = db.query(Device)

        if search_query:
            q = f"%{search_query}%"
            query = query.filter(
                or_(Device.ip_address.like(q), Device.mac_address.like(q),
                    Device.hostname.like(q), Device.vendor.like(q), Device.os_name.like(q))
            )

        if category_filter and category_filter != "all":
            query = query.filter(Device.device_type == category_filter)

        # Apply database level sorting
        if sort_by == "ip_asc":
            query = query.order_by(Device.ip_address.asc())
        elif sort_by == "ip_desc":
            query = query.order_by(Device.ip_address.desc())
        elif sort_by == "score_asc":
            query = query.order_by(Device.security_score.asc())
        elif sort_by == "score_desc":
            query = query.order_by(Device.security_score.desc())
        elif sort_by == "seen_asc":
            query = query.order_by(Device.last_seen.asc())
        elif sort_by == "seen_desc":
            query = query.order_by(Device.last_seen.desc())
        else:
            query = query.order_by(Device.ip_address.asc())

        devices = query.all()
        device_list = []
        for d in devices:
            ports = db.query(Port).filter(Port.device_id == d.id).all()
            port_list = [
                {"id": p.id, "port": p.port, "protocol": p.protocol,
                 "service": p.service, "state": p.state,
                 "risk_level": p.risk_level, "description": p.description}
                for p in ports
            ]

            max_risk = "Low"
            for p in port_list:
                if p["risk_level"] == "High":
                    max_risk = "High"
                    break
                elif p["risk_level"] == "Medium":
                    max_risk = "Medium"

            if risk_filter and risk_filter != "all":
                if max_risk != risk_filter:
                    continue

            device_list.append({
                "id": d.id,
                "ip_address": d.ip_address,
                "mac_address": d.mac_address,
                "hostname": d.hostname,
                "vendor": d.vendor,
                "device_type": d.device_type,
                "os_name": d.os_name,
                "status": d.status,
                "first_seen": d.first_seen.strftime("%Y-%m-%d %H:%M:%S"),
                "last_seen": d.last_seen.strftime("%Y-%m-%d %H:%M:%S"),
                "appearance_count": d.appearance_count,
                "security_score": d.security_score,
                "classification_confidence": d.classification_confidence,
                "ports": port_list,
                "max_risk": max_risk
            })
        return device_list

def delete_devices(device_ids: list) -> bool:
    with get_db() as db:
        devices = db.query(Device).filter(Device.id.in_(device_ids)).all()
        if not devices:
            return False
        for d in devices:
            db.delete(d)
        db.commit()
        return True

def clear_all_devices() -> bool:
    with get_db() as db:
        db.query(Device).delete(synchronize_session=False)
        db.query(Port).delete(synchronize_session=False)
        db.query(Alert).delete(synchronize_session=False)
        db.commit()
        return True

def get_device_by_id(device_id: int) -> dict:
    with get_db() as db:
        d = db.query(Device).filter(Device.id == device_id).first()
        if not d:
            return None

        ports  = db.query(Port).filter(Port.device_id == d.id).all()
        alerts = db.query(Alert).filter(Alert.device_id == d.id).order_by(Alert.timestamp.desc()).all()

        return {
            "id": d.id,
            "ip_address": d.ip_address,
            "mac_address": d.mac_address,
            "hostname": d.hostname,
            "vendor": d.vendor,
            "device_type": d.device_type,
            "os_name": d.os_name,
            "status": d.status,
            "first_seen": d.first_seen.strftime("%Y-%m-%d %H:%M:%S"),
            "last_seen": d.last_seen.strftime("%Y-%m-%d %H:%M:%S"),
            "appearance_count": d.appearance_count,
            "security_score": d.security_score,
            "classification_confidence": d.classification_confidence,
            "ports": [
                {"port": p.port, "protocol": p.protocol, "service": p.service,
                 "state": p.state, "risk_level": p.risk_level, "description": p.description}
                for p in ports
            ],
            "alerts": [
                {"id": a.id, "timestamp": a.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                 "type": a.type, "severity": a.severity,
                 "message": a.message, "resolved": a.resolved}
                for a in alerts
            ]
        }


# ─── ALERTS OPERATIONS ────────────────────────────────────────────────────────

def get_alerts(resolved: bool = None) -> list:
    with get_db() as db:
        query = db.query(Alert)
        if resolved is not None:
            query = query.filter(Alert.resolved == resolved)
        alerts = query.order_by(Alert.timestamp.desc()).all()
        return [
            {"id": a.id, "timestamp": a.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
             "type": a.type, "severity": a.severity,
             "message": a.message, "resolved": a.resolved, "device_id": a.device_id}
            for a in alerts
        ]

def resolve_alert(alert_id: int) -> bool:
    with get_db() as db:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            return False
        alert.resolved = True
        db.commit()
        return True


# ─── SETTINGS OPERATIONS ──────────────────────────────────────────────────────

def get_settings() -> dict:
    with get_db() as db:
        settings = db.query(Setting).all()
        return {s.key: s.value for s in settings}

def get_setting_value(key: str) -> str:
    with get_db() as db:
        s = db.query(Setting).filter(Setting.key == key).first()
        return s.value if s else None

def save_settings(settings_dict: dict):
    with get_db() as db:
        for key, val in settings_dict.items():
            s = db.query(Setting).filter(Setting.key == key).first()
            if s:
                s.value = str(val)
            else:
                db.add(Setting(key=key, value=str(val)))
        db.commit()


# ─── STATISTICS ───────────────────────────────────────────────────────────────

def get_statistics() -> dict:
    with get_db() as db:
        # Core counts
        total_scans   = db.query(Scan).count()
        total_devices = db.query(Device).count()
        online_devices  = db.query(Device).filter(Device.status == "up").count()
        offline_devices = db.query(Device).filter(Device.status == "down").count()

        # Average security score
        avg_score_res = db.query(func.avg(Device.security_score)).first()
        avg_score = round(avg_score_res[0]) if avg_score_res and avg_score_res[0] is not None else 0

        # Total open ports
        total_open_ports = db.query(Port).filter(Port.state == "open").count()

        # Unique vendors
        unique_vendors = db.query(func.count(func.distinct(Device.vendor))).scalar() or 0

        # Unresolved alerts
        unresolved_alerts = db.query(Alert).filter(Alert.resolved == False).count()

        # New devices discovered in the most recent completed scan
        new_devices_last_scan = 0
        latest_scan = db.query(Scan).filter(Scan.status == "completed").order_by(Scan.timestamp.desc()).first()
        if latest_scan:
            new_devices_last_scan = db.query(Device).filter(Device.scan_id == latest_scan.id).count()

        # Most common open port
        common_port_query = db.query(
            Port.port, func.count(Port.port).label('count')
        ).filter(Port.state == 'open').group_by(Port.port).order_by(func.count(Port.port).desc()).first()
        most_common_port = f"Port {common_port_query[0]}" if common_port_query else "None"

        # Port distribution (top 10)
        port_dist = db.query(
            Port.port, func.count(Port.port).label('count')
        ).filter(Port.state == 'open').group_by(Port.port).order_by(func.count(Port.port).desc()).limit(10).all()
        port_distribution = [
            {"port": f":{r[0]}", "count": r[1], "port_number": r[0]}
            for r in port_dist
        ]

        # Device category distribution
        device_types = db.query(
            Device.device_type, func.count(Device.device_type).label('count')
        ).group_by(Device.device_type).all()
        category_distribution = [{"type": r[0] or "Unknown", "count": r[1]} for r in device_types]
        if not category_distribution:
            category_distribution = [{"type": "No Data", "count": 0}]

        # Risk distribution
        devices = db.query(Device).all()
        risk_counts = {"Low": 0, "Medium": 0, "High": 0}
        for d in devices:
            ports = db.query(Port).filter(Port.device_id == d.id, Port.state == 'open').all()
            max_risk = "Low"
            for p in ports:
                if p.risk_level == "High":
                    max_risk = "High"
                    break
                elif p.risk_level == "Medium":
                    max_risk = "Medium"
            risk_counts[max_risk] += 1

        risk_distribution = [
            {"risk": r, "count": count}
            for r, count in risk_counts.items()
        ]

        # Scan history timeline (last 12 scans)
        recent_scans = db.query(Scan).filter(
            Scan.status == "completed"
        ).order_by(Scan.timestamp.desc()).limit(12).all()
        scan_timeline = [
            {
                "label": s.timestamp.strftime("%m/%d %H:%M"),
                "device_count": s.device_count,
                "scan_type": s.scan_type
            }
            for s in reversed(recent_scans)
        ]

        # Vendor breakdown (top 8)
        vendor_dist = db.query(
            Device.vendor, func.count(Device.vendor).label('count')
        ).group_by(Device.vendor).order_by(func.count(Device.vendor).desc()).limit(8).all()
        vendor_distribution = [
            {"vendor": r[0] or "Unknown", "count": r[1]}
            for r in vendor_dist
        ]

        return {
            "total_scans":          total_scans,
            "total_devices":        total_devices,
            "online_devices":       online_devices,
            "offline_devices":      offline_devices,
            "new_devices_last_scan": new_devices_last_scan,
            "global_security_score": avg_score,
            "total_open_ports":     total_open_ports,
            "unique_vendors":       unique_vendors,
            "unresolved_alerts":    unresolved_alerts,
            "most_common_port":     most_common_port,
            "port_distribution":    port_distribution,
            "device_types":         category_distribution,
            "risk_distribution":    risk_distribution,
            "scan_timeline":        scan_timeline,
            "vendor_distribution":  vendor_distribution,
        }

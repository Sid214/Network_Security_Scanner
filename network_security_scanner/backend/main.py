import os
import socket
import uvicorn
import webbrowser
import threading
import asyncio
import datetime
import time
import csv
import io
import json
import re
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field
from contextlib import asynccontextmanager
from typing import Optional, Dict, Any, List

try:
    from . import database
    from . import scanner
    from . import alerts_sender
except ImportError:
    import database
    import scanner
    import alerts_sender



class ScanRequest(BaseModel):
    target: str = Field(..., json_schema_extra={"example": "192.168.0.0/24"})
    scan_type: str = Field(default="standard", description="quick|standard|deep|inventory|audit")
    simulation_mode: bool = Field(default=False)

class SettingsRequest(BaseModel):
    settings: Dict[str, Any]

class TestEmailRequest(BaseModel):
    settings: Dict[str, Any]

class DeleteSelectedRequest(BaseModel):
    scan_ids: List[int]

class DeleteDevicesRequest(BaseModel):
    device_ids: List[int]

def open_browser():
    time.sleep(1.5)
    webbrowser.open("http://127.0.0.1:8000/")

async def run_schedule_worker():
    print("[Scheduler] GuardNet schedule worker initialized.")
    while True:
        try:
            await asyncio.sleep(60)
            settings = database.get_settings()
            schedule = settings.get("scan_schedule", "manual")
            sim_mode = settings.get("simulation_mode", "true") == "true"
            target   = settings.get("default_subnet", "192.168.0.0/24")

            if schedule in ["daily", "weekly"]:
                scans      = database.get_all_scans()
                should_run = False
                if not scans:
                    should_run = True
                else:
                    try:
                        last_time = datetime.datetime.strptime(scans[0]["timestamp"], "%Y-%m-%d %H:%M:%S")
                        diff      = datetime.datetime.now() - last_time
                        if schedule == "daily"  and diff.total_seconds() >= 86400:  should_run = True
                        if schedule == "weekly" and diff.total_seconds() >= 604800: should_run = True
                    except Exception:
                        should_run = True

                if should_run:
                    print(f"[Scheduler] Starting scheduled {schedule} scan for {target}")
                    scan_id = database.create_scan(target=target, scan_type=schedule, status="running")
                    scanner.start_scan_job(scan_id=scan_id, target=target, scan_profile="standard")
        except Exception as e:
            print(f"[Scheduler] Error: {e}")

async def run_network_monitor():
    """Periodically detect network changes and update cached state."""
    global _last_known_ip, _cached_net_info
    print("[NetworkMonitor] Interface monitor started.")
    while True:
        try:
            await asyncio.sleep(15)
            net = scanner.detect_local_network_info()
            current_ip = net.get("local_ip")
            if current_ip and current_ip != "127.0.0.1":
                if current_ip != _last_known_ip:
                    print(f"[NetworkMonitor] Network change detected: {_last_known_ip} -> {current_ip}")
                    _last_known_ip  = current_ip
                    _cached_net_info = net
        except Exception as e:
            pass

_last_known_ip: str = None
_cached_net_info: dict = None

@asynccontextmanager
async def lifespan(app_instance):
    """Modern FastAPI lifespan handler — replaces deprecated @app.on_event."""
    global _last_known_ip, _cached_net_info
    # ── Startup ────────────────────────────────────────────────────────────────
    database.init_db()
    loop = asyncio.get_event_loop()
    scanner.set_event_loop(loop)
    threading.Thread(target=open_browser, daemon=True).start()
    loop.create_task(run_schedule_worker())
    loop.create_task(run_network_monitor())
    loop.create_task(run_heartbeat_watchdog())
    try:
        scanner.init_bandwidth_baseline()
    except Exception:
        pass
    try:
        net = scanner.detect_local_network_info()
        _last_known_ip   = net.get("local_ip")
        _cached_net_info = net
        # Fire off an initial WAN IP fetch in background so it's cached
        threading.Thread(target=scanner.get_wan_ip, daemon=True).start()
        print(f"[Startup] Active adapter: {net.get('adapter')} | IP: {net.get('local_ip')} | Subnet: {net.get('subnet')} | Gateway: {net.get('gateway')}")
    except Exception as e:
        print(f"[Startup] Network detection error: {e}")
    yield
    # ── Shutdown (nothing to clean up) ──────────────────────────────────────────

app = FastAPI(
    title="GuardNet Network Security Intelligence API",
    version="3.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)



# ─── Session Management & Heartbeat ──────────────────────────────────────────

_last_heartbeat_time = time.time()
_watchdog_active = True

@app.post("/api/heartbeat")
def heartbeat():
    global _last_heartbeat_time
    _last_heartbeat_time = time.time()
    return {"status": "alive"}

class SessionAction(BaseModel):
    action: str

@app.post("/api/session")
def manage_session(req: SessionAction):
    global _watchdog_active
    act = req.action.lower()
    
    if act == "background":
        _watchdog_active = False
        print("[Session] Browser detached. GuardNet continuing in background.")
        return {"status": "backgrounded"}
        
    elif act == "dismiss":
        print("[Session] Dismiss & Close requested. Wiping state and shutting down...")
        database.delete_all_scans()
        database.delete_all_devices()
        _shutdown_server()
        return {"status": "shutting_down"}
        
    elif act == "save":
        print("[Session] Save & Exit requested. Shutting down cleanly...")
        _shutdown_server()
        return {"status": "shutting_down"}
        
    return {"status": "ignored"}

def _shutdown_server():
    def _do_shutdown():
        time.sleep(0.5)
        os._exit(0)
    threading.Thread(target=_do_shutdown, daemon=True).start()

async def run_heartbeat_watchdog():
    """Shuts down server if UI tab is closed (no heartbeat for 15s), unless backgrounded."""
    print("[Watchdog] Session keep-alive monitor started.")
    while True:
        await asyncio.sleep(5)
        if not _watchdog_active:
            continue
        if time.time() - _last_heartbeat_time > 60.0:
            print("[Watchdog] No heartbeat from frontend for 60s. Auto-shutting down...")
            _shutdown_server()

# ─── Network Info & Router Discovery ──────────────────────────────────────────

@app.get("/api/network-info")
def get_network_info():
    """Detect local IP, gateway, and suggest scan subnet dynamically."""
    global _last_known_ip, _cached_net_info
    net_info = scanner.detect_local_network_info()
    current_ip = net_info.get("local_ip")
    changed = (current_ip != _last_known_ip) if _last_known_ip else False
    _last_known_ip  = current_ip
    _cached_net_info = net_info
    return {
        "local_ip":         current_ip,
        "gateway":          net_info.get("gateway"),
        "suggested_subnet": net_info.get("subnet"),
        "netmask":          net_info.get("netmask"),
        "adapter":          net_info.get("adapter") or net_info.get("interface"),
        "interface":        net_info.get("interface"),
        "all_subnets":      net_info.get("all_subnets", []),
        "is_admin":         scanner.is_admin(),
        "nmap_available":   scanner.get_nmap_path() is not None,
        "network_changed":  changed,
        "detection_method": net_info.get("detection_method", "unknown"),
        "wan_ip":           scanner.get_wan_ip() or "No Internet Access"
    }

@app.get("/api/network-health")
def get_network_health():
    """Lightweight endpoint to detect network changes without full router probe."""
    global _last_known_ip
    try:
        net_info = scanner.detect_local_network_info()
        current_ip = net_info.get("local_ip")
        changed = (current_ip != _last_known_ip) if _last_known_ip else False
        if changed:
            _last_known_ip = current_ip
        return {
            "local_ip":       current_ip,
            "subnet":         net_info.get("subnet"),
            "gateway":        net_info.get("gateway"),
            "adapter":        net_info.get("adapter") or net_info.get("interface"),
            "network_changed": changed,
            "connected":      current_ip not in ("127.0.0.1", None)
        }
    except Exception:
        return {"local_ip": "Unavailable", "subnet": "Unavailable", "network_changed": False, "connected": False}

@app.get("/api/bandwidth")
def get_bandwidth():
    """Fast real-time bandwidth polling endpoint — returns download/upload Mbps."""
    try:
        rx, tx = scanner.get_realtime_bandwidth()
        return {"download_mbps": rx, "upload_mbps": tx}
    except Exception:
        return {"download_mbps": 0.0, "upload_mbps": 0.0}

@app.get("/api/router-info")
def get_router_info(simulation_mode: bool = True):
    """Automatically scans or retrieves router hardware specifications and telemetry."""
    net_info = scanner.detect_local_network_info()
    gateway_ip = net_info.get("gateway")

    router_details = scanner.get_gateway_router_details_sync(gateway_ip, simulation_mode)

    return {
        "local_ip":   net_info.get("local_ip"),
        "gateway_ip": gateway_ip,
        "subnet":     net_info.get("subnet"),
        "netmask":    net_info.get("netmask"),
        "dns_server": net_info.get("dns_server"),
        "interface":  net_info.get("interface"),
        "adapter":    net_info.get("adapter"),
        "router":     router_details
    }

@app.get("/api/diagnostics")
def get_diagnostics():
    """Return capability and discovery diagnostics for the diagnostics view."""
    return scanner.get_discovery_diagnostics()


# ─── Scanning ─────────────────────────────────────────────────────────────────

@app.post("/api/scan/start")
def start_scan(request: ScanRequest):
    target = request.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target cannot be empty")

    scan_id = database.create_scan(target=target, scan_type=request.scan_type)
    scanner.start_scan_job(
        scan_id=scan_id,
        target=target,
        scan_profile=request.scan_type,
    )
    return {"scan_id": scan_id, "status": "running", "message": "Scan initiated."}

@app.post("/api/scan/abort")
def abort_scan(scan_id: int):
    killed = scanner.abort_scan(scan_id)
    if killed:
        return {"status": "aborted", "message": "Scan aborted."}
    return {"status": "not_found", "message": "No active scan found with that ID."}

@app.get("/api/scan/status")
def get_scan_status(scan_id: int):
    progress_info = scanner.get_progress(scan_id)
    scan_db       = database.get_scan(scan_id)

    if not scan_db:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan_db["status"] in ["completed", "failed"]:
        return {
            "id": scan_id,
            "status":       scan_db["status"],
            "progress":     100 if scan_db["status"] == "completed" else 0,
            "logs":         [f"Scan finished with status: {scan_db['status']}"],
            "device_count": scan_db["device_count"]
        }

    return {
        "id":           scan_id,
        "status":       progress_info.get("status", "running"),
        "progress":     progress_info.get("progress", 0),
        "logs":         progress_info.get("logs", []),
        "device_count": scan_db["device_count"]
    }


# ─── Devices ──────────────────────────────────────────────────────────────────

@app.get("/api/devices")
def get_devices(search: Optional[str] = None, category: Optional[str] = None,
                risk: Optional[str] = None, sort_by: Optional[str] = "score_desc"):
    devices = database.get_devices(search_query=search, category_filter=category,
                                   risk_filter=risk, sort_by=sort_by)

    # Parse OS confidence for display
    for d in devices:
        os_raw = d["os_name"] or "Unknown OS"
        match = re.search(r'\(([^)]+)(?:% confidence|% accuracy|%)\)', os_raw)
        if match:
            d["os_confidence"] = match.group(1).replace("%", "").strip()
            d["os_name"] = re.sub(r'\s*\([^)]+\)', '', os_raw).strip()
        else:
            d["os_confidence"] = None

    return devices

@app.get("/api/device/{device_id}")
def get_device_details(device_id: int):
    device = database.get_device_by_id(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    os_raw = device["os_name"] or "Unknown OS"
    match = re.search(r'\(([^)]+)(?:% confidence|% accuracy|%)\)', os_raw)
    if match:
        device["os_confidence"] = match.group(1).replace("%", "").strip()
        device["os_name"] = re.sub(r'\s*\([^)]+\)', '', os_raw).strip()
    else:
        device["os_confidence"] = None

    return device

@app.post("/api/devices/delete-selected")
def delete_selected_devices(request: DeleteDevicesRequest):
    success = database.delete_devices(request.device_ids)
    if not success:
        raise HTTPException(status_code=400, detail="Failed to delete selected devices")
    return {"message": f"Successfully deleted {len(request.device_ids)} devices"}

@app.post("/api/devices/clear-all")
def clear_all_devices():
    success = database.clear_all_devices()
    if not success:
        raise HTTPException(status_code=500, detail="Failed to clear device inventory")
    return {"message": "All devices cleared successfully"}


# ─── Alerts ───────────────────────────────────────────────────────────────────

@app.get("/api/alerts")
def get_alerts(unresolved: Optional[bool] = None):
    resolved = False if unresolved else None
    return database.get_alerts(resolved=resolved)

@app.post("/api/alerts/{alert_id}/resolve")
def resolve_alert(alert_id: int):
    if not database.resolve_alert(alert_id):
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"success": True}


# ─── Scan History & Deletions ─────────────────────────────────────────────────

@app.get("/api/history")
def get_history():
    return database.get_all_scans()

@app.delete("/api/scan/{scan_id}")
def remove_scan(scan_id: int):
    if not database.delete_scan(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"success": True}

@app.post("/api/history/delete-selected")
def delete_selected(request: DeleteSelectedRequest):
    if not database.delete_selected_scans(request.scan_ids):
        raise HTTPException(status_code=404, detail="No matching scans found to delete")
    return {"success": True, "message": f"Successfully deleted {len(request.scan_ids)} scan logs."}

@app.post("/api/history/clear-all")
def clear_all():
    database.clear_all_scans()
    return {"success": True, "message": "All scan histories successfully wiped."}

@app.get("/api/scan/{scan_id}/details")
def get_scan_details(scan_id: int):
    details = database.get_scan_details(scan_id)
    if not details:
        raise HTTPException(status_code=404, detail="Scan not found")
    return details


# ─── Settings & Test Email ────────────────────────────────────────────────────

@app.get("/api/settings")
def get_settings():
    return database.get_settings()

@app.post("/api/settings")
def save_settings(request: SettingsRequest):
    database.save_settings(request.settings)
    return {"success": True, "message": "Settings saved."}

@app.post("/api/settings/test-email")
def test_email(request: TestEmailRequest):
    res = alerts_sender.test_smtp_configuration(request.settings)
    if res == "success":
        return {"success": True, "message": "Test email successfully sent to your alert inbox."}
    else:
        raise HTTPException(status_code=400, detail=f"SMTP Mailer Connection Failure: {res}")


# ─── Statistics ───────────────────────────────────────────────────────────────

@app.get("/api/statistics")
def get_statistics():
    return database.get_statistics()


# ─── Exports ──────────────────────────────────────────────────────────────────

def _build_pdf(devices, stats) -> bytes:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

    buf    = io.BytesIO()
    doc    = SimpleDocTemplate(buf, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    story  = []
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle('T', parent=styles['Heading1'],
        fontName='Helvetica-Bold', fontSize=22, leading=26,
        textColor=colors.HexColor('#0891b2'), spaceAfter=6)
    sub_style   = ParagraphStyle('S', parent=styles['Normal'],
        fontName='Helvetica', fontSize=10,
        textColor=colors.HexColor('#475569'), spaceAfter=15)
    section_style = ParagraphStyle('H', parent=styles['Heading2'],
        fontName='Helvetica-Bold', fontSize=13, leading=16,
        textColor=colors.HexColor('#0f172a'), spaceBefore=14, spaceAfter=8)
    body_style = ParagraphStyle('B', parent=styles['Normal'],
        fontName='Helvetica', fontSize=8, leading=10,
        textColor=colors.HexColor('#334155'))

    story.append(Paragraph("GuardNet — Network Intelligence & Security Report", title_style))
    story.append(Paragraph(
        f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | GuardNet v3.0",
        sub_style
    ))

    story.append(Paragraph("Intelligence Overview", section_style))
    overview_data = [
        [Paragraph(f"<b>Security Score:</b> {stats['global_security_score']}/100", body_style),
         Paragraph(f"<b>Total Devices:</b> {stats['total_devices']}", body_style)],
        [Paragraph(f"<b>Online:</b> {stats['online_devices']} / Offline: {stats['offline_devices']}", body_style),
         Paragraph(f"<b>Unresolved Alerts:</b> {stats['unresolved_alerts']}", body_style)]
    ]
    tbl = Table(overview_data, colWidths=[270, 270])
    tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f1f5f9')),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#e2e8f0')),
        ('PADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 15))

    story.append(Paragraph("Device Inventory", section_style))
    table_data = [["IP Address", "Hostname", "Category", "Vendor / OS", "Score"]]
    for d in devices:
        table_data.append([
            d['ip_address'],
            d['hostname'] or '—',
            d['device_type'],
            f"{d['vendor'] or '—'}\n({d['os_name'] or 'Unknown OS'})",
            f"{d['security_score']}/100"
        ])
    dtbl = Table(table_data, colWidths=[80, 110, 80, 190, 80])
    dtbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 9),
        ('BOTTOMPADDING', (0,0), (-1,0), 6),
        ('TOPPADDING', (0,0), (-1,0), 6),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
        ('PADDING', (0,1), (-1,-1), 6),
    ]))
    story.append(dtbl)

    doc.build(story)
    buf.seek(0)
    return buf.getvalue()

@app.get("/api/export/{export_format}")
def export_data(export_format: str):
    devices = database.get_devices()
    stats   = database.get_statistics()

    if export_format == "json":
        data = {"statistics": stats, "devices_inventory": devices}
        return StreamingResponse(
            io.BytesIO(json.dumps(data, indent=4).encode()),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=guardnet_export.json"}
        )

    elif export_format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["IP", "MAC", "Hostname", "Vendor", "Category", "OS", "Security Score", "Status", "First Seen", "Last Seen"])
        for d in devices:
            writer.writerow([
                d["ip_address"], d["mac_address"] or "N/A",
                d["hostname"] or "N/A", d["vendor"] or "N/A",
                d["device_type"], d["os_name"] or "N/A",
                f"{d['security_score']}/100", d["status"],
                d["first_seen"], d["last_seen"]
            ])
        output.seek(0)
        return StreamingResponse(
            io.BytesIO(output.getvalue().encode()),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=guardnet_export.csv"}
        )

    elif export_format == "pdf":
        try:
            pdf_bytes = _build_pdf(devices, stats)
            return StreamingResponse(
                io.BytesIO(pdf_bytes),
                media_type="application/pdf",
                headers={"Content-Disposition": "attachment; filename=guardnet_report.pdf"}
            )
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}")

    raise HTTPException(status_code=400, detail="Invalid format. Use json, csv, or pdf.")


# ─── Frontend Static Serve ────────────────────────────────────────────────────

frontend_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend")
if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")
else:
    @app.get("/")
    def read_root():
        return {"message": "GuardNet API running. Frontend not found."}


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False)

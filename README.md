# GuardNet - Network Intelligence & Security Analysis Platform

GuardNet is a modern, enterprise-ready **Network Intelligence and Security Analysis Platform**. Beyond a simple network discovery or port scanning tool, GuardNet functions as a localized Intrusion Detection System (IDS) and asset inventory manager with real-time hardware tracking, vulnerability heuristics, and live terminal telemetry.

Built with a **FastAPI** asynchronous backend, **SQLAlchemy ORM** SQLite persistence, and a high-performance **Vanilla CSS / JavaScript** cyber-themed dashboard with micro-animations.

---

## 🚀 Key Features

1. **Persistent Terminal GUI & Live Telemetry**:
   - Always-visible cyber terminal panel with real-time log streaming and blinking command prompt.
   - Live **Nmap binary detection** with status indicator pill in the terminal header.
   - Height-balanced responsive layout that eliminates negative space and matches the Scan Configuration panel.

2. **Interactive Scan Controls & Micro-Animations**:
   - Fluid split button transition: Clicking **Launch Scan** smoothly compresses its width to the left while an **Abort Scan** button expands dynamically with a pulsing emergency glow.
   - One-click interactive target chips (`192.168.0.1`, `192.168.0.0/24`, `10.0.0.0/24`) that automatically fill the scan target.
   - Comprehensive UI micro-interactions: card hover lifts, cyber gradient shimmer on progress bars, input focus rings, and animated status pills.

3. **Multi-Method Discovery & Security Scanning**:
   - **Nmap Engine**: Native integration with Nmap for ARP sweeps, ICMP ping, TCP port scans, service version detection, and OS fingerprinting.
   - **Socket Fallback**: Automatic fallback to Python raw socket scanner when Nmap is not present on the host system.
   - **5 Tuned Profiles**: Quick Discovery, Standard Scan, Deep Inspection, Inventory Refresh, and Security Audit.

4. **Master Asset Inventory & Anomaly Detection (IDS)**:
   - Tracks devices across scan cycles by IP and MAC address with vendor identification.
   - Automatically detects and alerts on:
     - **New Device Alert**: Triggered when an unrecognized MAC address joins the network.
     - **Hardware Change Alert**: Triggered when an existing IP binds to a new MAC address.
     - **Hostname Anomaly Alert**: Flags unauthorized or unexpected hostname modifications.
     - **Vulnerable Service Exposure**: Flags active legacy/unencrypted services (FTP :21, Telnet :23, SMB :445, etc.).

5. **Security Health & Risk Scoring**:
   - Calculates a global network health score (0–100) using a dynamic gauge chart.
   - Categorizes individual device risk levels (Low, Medium, High) based on open ports and running services.

6. **Automated Alerts & Multi-Format Reports**:
   - SMTP email notifications for critical anomalies and high-severity threat detections.
   - Export full intelligence audit logs in **JSON**, **CSV**, or formatted **PDF** (rendered via `reportlab`).

---

## 📁 Repository Structure

```
Network_Security_Scanner/
├── main.py                       # FastAPI entrypoint, API routes & static file server
├── requirements.txt              # Core Python dependencies
├── README.md                     # Comprehensive platform documentation
├── network_security_scanner/
│   ├── backend/
│   │   ├── __init__.py           # Package initialization
│   │   ├── database.py           # SQLAlchemy ORM models, session & schema helpers
│   │   ├── models.py             # Database entity dataclasses
│   │   ├── scanner.py            # Nmap subprocess execution & socket scan engine
│   │   ├── alerts_sender.py      # SMTP email alert dispatcher
│   │   └── scanner.db            # Local SQLite database
│   └── frontend/
│       ├── index.html            # Responsive SPA dashboard & live terminal GUI
│       ├── css/
│       │   └── styles.css        # Cyber aesthetic design system & micro-animations
│       └── js/
│           └── app.js            # Frontend logic, API client & real-time polling
```

---

## ⚙️ Installation & Quickstart

### Prerequisites
- **Python 3.10+**
- **Nmap** (Optional, recommended: provides raw packet scanning and OS fingerprinting; socket mode used if unavailable)
- **Administrative Privileges** (Recommended for raw socket / ARP sweeps)

### 1. Setup Virtual Environment
```bash
# Create virtual environment
python -m venv .venv

# Activate on Windows (PowerShell)
.venv\Scripts\Activate.ps1

# Activate on Linux/macOS
source .venv/bin/activate
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Launch GuardNet
```bash
python main.py
```
*The platform will start at `http://127.0.0.1:8000/` and automatically launch your default browser.*

---

## 🔌 REST API Endpoints

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/network-info` | `GET` | Fetches local IP, subnet, admin status, and Nmap availability |
| `/api/scan/start` | `POST` | Launches a background scan cycle (profile, target, simulation) |
| `/api/scan/status` | `GET` | Polls progress percentage and live console logs |
| `/api/scan/abort` | `POST` | Aborts the active scan cycle |
| `/api/devices` | `GET` | Returns asset inventory with search, type, and risk filters |
| `/api/device/{id}` | `GET` | Returns detailed host profile, port table, and alerts |
| `/api/alerts` | `GET` | Retrieves threat intelligence feed |
| `/api/alerts/{id}/resolve`| `POST` | Marks an alert as resolved |
| `/api/history` | `GET` | Returns past scan cycles history |
| `/api/settings` | `GET` | Retrieves application preferences and SMTP configuration |
| `/api/settings` | `POST` | Saves configuration preferences |
| `/api/export/{format}` | `GET` | Downloads audit reports in `json`, `csv`, or `pdf` |

---

## 🛡️ License

This project is licensed under the MIT License.

# Network Security Scanner Implementation Plan

This document outlines the design and implementation plan for a modern local network security scanner application. The application comprises a FastAPI Python backend, a SQLite database for scan storage, and a premium dark-themed web dashboard for visualization.

---

## User Review Required

> [!IMPORTANT]
> **Nmap Executable & Administrative Rights**
> - **Nmap Binary**: Nmap must be installed and available in the system PATH. We have verified that Nmap 7.99 is installed on this machine.
> - **Privilege Requirements**: Certain advanced features of Nmap (like SYN Stealth scan `-sS` and OS fingerprinting `-O`) require administrative privileges on Windows.
> - **Our Approach**:
>   1. We will implement automatic privilege detection in Python.
>   2. If run *with* admin rights, the application will allow detailed scans (using `-sS -sV -O`).
>   3. If run *without* admin rights, it will automatically fall back to a TCP Connect scan (`-sT -sV` or `-sT -F`) which works under standard user accounts.
>   4. We will also implement a **Simulation/Demo Mode** toggle, enabling immediate testing of the frontend dashboard and database with mock data without executing actual network commands.

---

## Open Questions

> [!NOTE]
> *No critical open questions. We have successfully detected the local subnet (`192.168.0.0/24`) and confirmed the presence of Python 3.14 and Nmap 7.99. The plan below details a self-contained, robust setup.*

---

## Proposed Changes

We will create a new directory `network_security_scanner` inside the project folder.

```
network_security_scanner/
├── backend/
│   ├── __init__.py
│   ├── database.py       # SQLite database configuration and CRUD queries
│   ├── scanner.py        # Nmap wrapper and XML parser (runs subprocesses asynchronously)
│   ├── main.py           # FastAPI application, CORS configuration, background tasks, static file mounting
│   └── requirements.txt  # Python packages (fastapi, uvicorn)
├── frontend/
│   ├── index.html        # Main HTML file for the single-page dashboard
│   ├── css/
│   │   └── styles.css    # Premium CSS styles (dark mode, glassmorphism, responsive grid)
│   └── js/
│       ├── api.js        # API client for backend communication
│       └── app.js        # UI logic, Chart.js integration, scanning status polling
├── README.md             # Project documentation and execution instructions
└── .gitignore            # Git exclusion rules
```

---

### Backend Components

#### [NEW] [database.py](file:///C:/Users/Siddhesh/Patil/.gemini/antigravity/scratch/network_security_scanner/backend/database.py)
Manages SQLite operations. Creates the schema on startup and provides interfaces for:
- Saving scan sessions (timestamps, subnet targeted, configuration).
- Inserting discovered devices and their open ports.
- Retrieval of past scans, device details, and aggregated statistics (port frequencies, device types).

**Schema Draft**:
- `scans` table: `id`, `timestamp`, `target`, `scan_type`, `status` (running/completed/failed), `device_count`.
- `devices` table: `id`, `scan_id`, `ip_address`, `mac_address`, `hostname`, `vendor` (MAC-based), `os_name`, `device_type`, `status`.
- `ports` table: `id`, `device_id`, `port`, `protocol`, `service`, `state`.

#### [NEW] [scanner.py](file:///C:/Users/Siddhesh/Patil/.gemini/antigravity/scratch/network_security_scanner/backend/scanner.py)
Triggers Nmap as a background process and parses its outputs:
- Runs Nmap with XML output (`-oX -`) to parse structured stdout directly using `xml.etree.ElementTree`.
- Supports three scan profiles:
  - **Quick Discover** (Host discovery only): `nmap -sn <target>`
  - **TCP Port Scan** (User-level): `nmap -sT -F --open <target>` (Fast TCP connection scan, top 100 ports, doesn't need admin privileges)
  - **Detailed Scan** (Requires Admin privileges): `nmap -sS -sV -O -F --open <target>` (Stealth scan, service versions, OS details)
- Falls back gracefully to standard port scan if the detailed scan fails due to lacking admin privileges.
- Includes a **Simulation Mode** that generates dummy network topologies (e.g. 5-10 hosts with realistic IPs, hostnames, OS types, and typical open ports like 22, 80, 443, 8080) for testing.

#### [NEW] [main.py](file:///C:/Users/Siddhesh/Patil/.gemini/antigravity/scratch/network_security_scanner/backend/main.py)
The FastAPI server entry point:
- Declares endpoints:
  - `GET /api/network-info`: Retrieves the current host's IP and suggests a default subnet (e.g. `192.168.0.0/24`).
  - `POST /api/scan`: Starts a scan in a background thread. Returns a scan ID immediately.
  - `GET /api/scan/{scan_id}`: Returns status of a specific scan.
  - `GET /api/scans`: Lists all scan history.
  - `GET /api/scans/{scan_id}/details`: Returns complete devices and ports for a scan.
  - `DELETE /api/scans/{scan_id}`: Removes a scan from history.
  - `GET /api/statistics`: Returns statistics for frontend charts (e.g. device types, open port distribution).
- Mounts the `frontend/` directory to serve static assets.

#### [NEW] [requirements.txt](file:///C:/Users/Siddhesh/Patil/.gemini/antigravity/scratch/network_security_scanner/backend/requirements.txt)
Defines minimal requirements:
```
fastapi>=0.110.0
uvicorn>=0.28.0
```

---

### Frontend Components

#### [NEW] [index.html](file:///C:/Users/Siddhesh/Patil/.gemini/antigravity/scratch/network_security_scanner/frontend/index.html)
A modern, single-page application dashboard:
- **Sidebar**: Logo, Navigation links (Dashboard, Scanner, History, Settings).
- **Dashboard Tab**:
  - Stat cards (Total Scans, Last Scan Device Count, Most Common Open Port, Active Devices).
  - Visual charts: Doughnut chart for Device Types (Workstation, Router, Mobile, IoT, Printer, Unknown) and Bar chart for Open Port Frequencies.
- **Scanner Tab**:
  - Scanning configuration card (target range, profile selection, simulation mode toggle).
  - Real-time scan progress panel (loading animation, logs console, progress bar).
  - Active scan results table (expandable rows to view open ports and details).
- **History Tab**:
  - Interactive table of past scans.
  - Detail view panel showing list of devices from the selected historical scan.
- Includes CDN references for:
  - Chart.js (for high-performance charts).
  - FontAwesome (for icons).

#### [NEW] [styles.css](file:///C:/Users/Siddhesh/Patil/.gemini/antigravity/scratch/network_security_scanner/frontend/css/styles.css)
A clean, premium design style sheet:
- Dark slate/gray color palette (`#0f172a`, `#1e293b`, `#334155`).
- Font family: Inter/system UI.
- Glassmorphism effects (semi-transparent backgrounds, subtle borders, backdrop blur).
- Smooth hover animations and custom loading animations for active scanning.
- Responsive design adapting to mobile and desktop layouts.

#### [NEW] [api.js](file:///C:/Users/Siddhesh/Patil/.gemini/antigravity/scratch/network_security_scanner/frontend/js/api.js)
Handles API requests to the Python FastAPI backend.

#### [NEW] [app.js](file:///C:/Users/Siddhesh/Patil/.gemini/antigravity/scratch/network_security_scanner/frontend/js/app.js)
Coordinates UI updates:
- Event handlers for scanning, tab switching, and deleting scans.
- Polling mechanism to check active scan progress.
- Drawing and updating Chart.js instances with statistics payload.
- Filtering and search functionalities for scanning and history tables.

---

## Verification Plan

### Automated Tests
1. **API Sanity Checks**:
   - Run the FastAPI server locally: `python backend/main.py`
   - Access the automated docs at `http://127.0.0.1:8000/docs` to test schema validation.
2. **Scanner dry-runs**:
   - Run a standalone Python test script to invoke Nmap on localhost (`127.0.0.1`) and check if the XML is parsed correctly.
   - Verify that simulated scans succeed instantly without Nmap binary issues.

### Manual Verification
1. **Scanner Test**:
   - Run a Scan against the host's actual local subnet (`192.168.0.0/24` or a smaller range like `192.168.0.107/32` to speed up tests).
   - Verify that device hostname, IP, MAC address, open ports, and device type are properly rendered in the UI.
2. **Dashboard UI Checks**:
   - Check that searching and filtering devices works instantly (e.g., search "192", or filter by port "80").
   - Confirm that Chart.js statistics load correctly and reflect data in SQLite.
   - Verify scan history can be loaded and deleted.

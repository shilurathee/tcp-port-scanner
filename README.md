# SOC Port Reconnaissance Console

A multithreaded TCP port scanner and service fingerprinting dashboard engineered as a **Security Operations Center (SOC)** console. Inspired by serious operational tools like Burp Suite, Wireshark, and Metasploit, it combines high-speed scanning with an interactive GUI that teaches Nmap commands in real time.

Scan only systems you own or have explicit permission to test. [`scanme.nmap.org`](https://nmap.org/book/legal-issues.html) is Nmap’s officially authorized public test host.

```
portscanner/
├── scanner.py        # core scan() engine & standalone CLI
├── app.py            # Flask streaming server (SSE & REST API)
├── reports.py        # Pentest-grade PDF, CSV, and JSON generators
├── templates/        # index.html (SOC console), about.html (architecture briefing)
├── static/           # css (cyber theme), js (SSE telemetry & canvas), img
└── reports/          # generated security assessment reports
```

## Tech Stack

- **Python 3** — `socket`, `ThreadPoolExecutor`, `argparse`
- **Flask** — Server-Sent Events (SSE) live streaming and RESTful endpoints
- **HTML5 + CSS3 + Vanilla ES6+** — Cyber SOC aesthetic (no heavy frontend frameworks required)
- **Google Fonts** — JetBrains Mono (technical monospace), Rajdhani (tactical headers)
- **ReportLab** — Pentest audit reports (PDF with monospace tables & executive summary)
- **Nmap** — Command verification and educational live translation

## Web Dashboard (SOC Console)

### 1. Install & Run
```bash
pip install -r requirements.txt
python app.py
```
Open **[http://127.0.0.1:5000](http://127.0.0.1:5000)** in your browser.

### 2. Features & Controls
- **Target Specification:** Hostname or IPv4 input with validation and quick presets (`scanme.nmap.org`, `127.0.0.1`, `localhost`).
- **Scan Profiles:**
  - `Quick`: Top 100 ports
  - `Standard`: Ports 1–1024
  - `Full`: 1–65535 (Safe/Local targets)
  - `Custom`: Custom port ranges (e.g. `21-25, 80, 443, 8080`)
- **Pick by Service:** Interactive toggle chips that auto-append ports:
  - `WEB` &rarr; 80, 443, 8080
  - `SSH / RDP` &rarr; 22, 3389
  - `DATABASE` &rarr; 3306, 5432, 27017
  - `MAIL` &rarr; 25, 110, 143
  - `FTP / SMB` &rarr; 21, 445
- **Service Detection (`-sV`):** Dynamic banner grabbing via raw socket reads and lightweight HTTP probes.
- **Velocity Slider:** Map concurrency to speed profiles:
  - `Stealth` &rarr; 20 threads
  - `Normal` &rarr; 100 threads
  - `Aggressive` &rarr; 200 threads
- **Live Nmap Preview:** Standout terminal bar (`$ nmap -sV -p ... target`) that updates dynamically on every click to teach CLI flags while using the GUI. Includes 1-click clipboard copy.
- **Live SSE Streaming:** Results table animates as ports are discovered; terminal window streams stdout log lines with live elapsed timing and ports/sec speed.
- **Pentest Report Exports:** Download executive-ready PDF audit reports, CSV tables, or JSON artifacts.

### 3. Safety Guardrails
- Input validation on target hostnames and IPv4 formats.
- Concurrency cap at 200 threads to prevent self-denial-of-service.
- Mandatory testing consent verification checkbox.
- Public scope guardrail: 1–65535 full scans and queries exceeding 4,096 ports are restricted to loopback (`127.0.0.1`), RFC1918 private subnets, and `scanme.nmap.org`.

## Command Line Interface (CLI)

The same core `scan()` engine powers the CLI:

```bash
# Scan scanme.nmap.org standard ports with 100 threads
python scanner.py -t scanme.nmap.org -p 1-1000 --threads 100

# Fast scan of specific services with banner grabbing
python scanner.py -t 127.0.0.1 -p 22,80,443,3306,8080

# Disable banner grabbing for stealth/speed
python scanner.py -t scanme.nmap.org -p 1-1024 --no-banner
```

## How It Works

A networked host has **65,535 TCP doors**. Each worker thread attempts a non-blocking `connect_ex((ip, port))` socket handshake:
- **Return code 0:** The door is open; a daemon is actively listening.
- **Non-zero / Timeout:** The port is closed or filtered by a firewall.
- **Banner Grabbing:** For open doors, the engine immediately captures the server's initial greeting or dispatches a `HEAD / HTTP/1.0` probe to discover exact software versions (e.g., `OpenSSH_6.6.1p1`, `Apache/2.4.7`).

## Verification Against Nmap

```bash
nmap -sV -p 1-1000 scanme.nmap.org
```

Cross-checking against `scanme.nmap.org` consistently verifies **22/tcp OpenSSH** and **80/tcp Apache 2.4.7**, matching Nmap’s documented test services.

---
**Author:** Romansh Rathee 
**License:** MIT  
*For educational and authorized security auditing only.*

# Paradox Recon

<p align="center">
  <img src="assets/logo.svg" alt="Paradox Recon" width="280"/>
</p>

**NETWORK • WEB • SYSTEM • SECURITY**

A modular reconnaissance & diagnostic toolkit for **Termux** and **Linux**.

```
╔════════════════════════════════════════╗
║          ◆  PARADOX RECON  ◆           ║
║    NETWORK • WEB • SYSTEM • SECURITY   ║
╚════════════════════════════════════════╝
     ░ eyes open · signals clear · recon online ░
```

## Features

### Network
- Local IP / interfaces
- Public IP
- LAN host discovery (ARP + limited ping)
- DNS lookup / reverse DNS
- ASN / organization lookup
- WHOIS lookup
- Route tracing
- Gateway detection
- Wi-Fi / network information

### Web Diagnostics
- HTTP/HTTPS status & response headers
- Redirect chain analysis
- TLS / certificate information (expiry, SANs, issuer)
- Response-time measurement
- robots.txt / sitemap detection
- Server / technology hints

### Security Checks
- Security header audit (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, …)
- TLS certificate expiry
- Common path / sensitive file checks (authorized testing only)
- Common service port discovery
- Basic subdomain enumeration (authorized domains only)
- Local network exposure summary

### Diagnostics
- Internet / DNS / gateway / HTTPS connectivity
- Latency & basic packet-loss indication
- IPv4 / IPv6 connectivity
- Automatic full diagnostic report

### Termux / Device
- CPU architecture, RAM, storage
- Battery status (Termux API or sysfs)
- Android / Termux version
- Kernel, hostname, environment
- Running processes
- Network interfaces

### Reporting
- JSON + human-readable TXT reports
- Timestamped files in `./reports/`
- Scan history (`reports/scan_history.json`)
- Auto-save after most actions

## Requirements

- Python 3.8+
- Recommended packages (optional but improve results):
  - `curl`, `dig` / `host`, `whois`, `traceroute` / `tracepath`, `iproute2`, `ping`
- Python: `requests` (strongly recommended)

### Termux quick setup

```bash
pkg update && pkg install python curl dnsutils whois traceroute iproute2
pip install requests
```

### Linux (Debian/Ubuntu)

```bash
sudo apt update
sudo apt install python3 python3-requests curl dnsutils whois traceroute iproute2
```

## Usage

```bash
# Interactive menu (default)
python3 paradox_recon.py

# One-shot full diagnostic
python3 paradox_recon.py --full

# Quick helpers
python3 paradox_recon.py --public-ip
python3 paradox_recon.py --device
```

## Menu Map

```
 NETWORK
 ├─ 01  Network Overview
 ├─ 02  Discover Local Devices
 ├─ 03  DNS Intelligence
 ├─ 04  WHOIS / ASN Lookup
 └─ 05  Route Analysis

 WEB
 ├─ 06  Website Diagnostics
 ├─ 07  HTTP Header Inspector
 ├─ 08  TLS Certificate Check
 ├─ 09  Security Header Audit
 └─ 10  Redirect Analyzer

 SECURITY
 ├─ 11  Port Exposure Check
 ├─ 12  Domain Surface Check
 └─ 13  Local Network Audit

 SYSTEM
 ├─ 14  Device Information
 ├─ 15  Network Interfaces
 └─ 16  Resource Monitor

 TOOLS
 ├─ 17  Full Diagnostic
 ├─ 18  Generate Report
 └─ 19  Scan History

 20  Exit
```

## Important – Authorized Use Only

- Port scanning, subdomain enumeration, and path checks must only be performed on systems **you own** or have **explicit written permission** to test.
- The tool includes confirmation prompts for surface checks.
- Never use against third-party infrastructure without authorization.

## Reports

All scans that return data are automatically saved under:

```
./reports/
  <action>_<YYYYMMDD_HHMMSS>.json
  <action>_<YYYYMMDD_HHMMSS>.txt   (full diagnostic)
  scan_history.json
```

## License

MIT — Use responsibly. For educational and authorized security testing only.

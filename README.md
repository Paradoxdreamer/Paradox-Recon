# Paradox Recon

<p align="center">
  <img src="assets/IMG_7776.jpeg" alt="Paradox Recon" width="320"/>
</p>

**NETWORK • WEB • SYSTEM • SECURITY** — v1.2.0

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
- Local IP / interfaces, public IP + GeoIP
- LAN host discovery (ARP + ping)
- DNS lookup / reverse DNS (A, AAAA, MX, NS, TXT, CNAME, SOA)
- ASN / organization / WHOIS
- Route tracing, gateway detection, Wi-Fi info

### Web Diagnostics
- HTTP/HTTPS status, headers, redirect chains
- TLS certificate (expiry, SANs, issuer, cipher)
- Response-time measurement
- robots.txt / sitemap detection
- Technology fingerprinting (WordPress, React, nginx, Cloudflare, …)

### Security
- Security header audit (CSP, HSTS, XFO, XCTO, Referrer-Policy, …)
- Port scan + **banner grabbing**
- Common path / sensitive file checks (authorized only)
- Subdomain enumeration (authorized only)
- **Email auth**: SPF / DMARC / DKIM selectors
- **CORS** misconfiguration check
- **Cookie** flags (HttpOnly, Secure, SameSite)
- **WAF / CDN** detection
- Cloud metadata endpoint probe (IMDSv1 exposure)

### Tools
- Encoder/decoder (Base64, URL, Hex, MD5, SHA1/256/512)
- Hash type identifier
- Full auto diagnostic + JSON/TXT reports

### System (Termux / Linux)
- CPU, RAM, disk, battery, Android/Termux version
- Kernel, processes, interfaces

## Menu

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
 ├─ 11  Port + Banner Grab
 ├─ 12  Domain Surface Check
 ├─ 13  Local Network Audit
 ├─ 14  Email Auth (SPF/DMARC)
 ├─ 15  CORS / Cookie Audit
 └─ 16  WAF / Tech Fingerprint

 SYSTEM
 ├─ 17  Device Information
 ├─ 18  Network Interfaces
 └─ 19  Resource Monitor

 TOOLS
 ├─ 20  Full Diagnostic
 ├─ 21  Encoder / Decoder
 ├─ 22  Hash Identifier
 ├─ 23  Cloud Metadata Check
 ├─ 24  Generate Report
 └─ 25  Scan History

 26  Exit
```

## Install

### Termux

```bash
# 1. Update & install packages
pkg update -y
pkg install -y python git curl dnsutils whois traceroute nmap iproute2

# 2. Python dependency
pip install requests

# 3. Clone & run
git clone https://github.com/Paradoxdreamer/Paradox-Recon.git
cd Paradox-Recon
python paradox_recon.py
```

Optional (Wi-Fi / battery APIs):

```bash
pkg install -y termux-api
```

### Linux (Debian / Ubuntu / Kali)

```bash
# 1. Update & install packages
sudo apt update
sudo apt install -y python3 python3-pip python3-requests git curl dnsutils whois traceroute iproute2 iputils-ping

# 2. Clone & run
git clone https://github.com/Paradoxdreamer/Paradox-Recon.git
cd Paradox-Recon
python3 paradox_recon.py
```

### One-liner (any system with git + python3)

```bash
git clone https://github.com/Paradoxdreamer/Paradox-Recon.git && cd Paradox-Recon && python3 paradox_recon.py
```

> **Note:** `requests` is strongly recommended. Without it, the tool falls back to `curl` for HTTP checks.

## Usage

```bash
python3 paradox_recon.py              # interactive menu
python3 paradox_recon.py --full       # full diagnostic
python3 paradox_recon.py --public-ip
python3 paradox_recon.py --device
python3 paradox_recon.py --dns example.com
python3 paradox_recon.py --tls example.com
python3 paradox_recon.py --headers https://example.com
```

## Authorized use only

Port scans, subdomain enum, and path checks must only target systems **you own** or have **written permission** to test.

## License

MIT

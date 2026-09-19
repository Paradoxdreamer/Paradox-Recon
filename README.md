# Paradox Recon

<p align="center">
  <img src="assets/IMG_7776.jpeg" alt="Paradox Recon" width="320"/>
</p>

**Discovery → Diagnostics → Correlation → Risk → Report**

```
╔════════════════════════════════════════╗
║          ◆  PARADOX RECON  ◆           ║
║         v1.3.0  ·  pipeline engine     ║
╚════════════════════════════════════════╝
```

Not another “run 30 tools” script.  
A structured **scan pipeline** with plugins, correlation, and professional reports.

## Pipeline

```
Target  →  Discovery  →  Diagnostics  →  Correlation  →  Risk findings  →  Report
```

| Stage | What happens |
|-------|----------------|
| **Discovery** | Map the surface (DNS, network, system context) |
| **Diagnostics** | Probe (web, TLS, security headers, email auth) |
| **Correlation** | Cross-link evidence into higher-order risks |
| **Report** | JSON + TXT + HTML from one schema |

## Install

### Termux

```bash
pkg update -y
pkg install -y python git curl dnsutils whois traceroute iproute2
pip install requests
git clone https://github.com/Paradoxdreamer/Paradox-Recon.git
cd Paradox-Recon
pip install -e .
paradox-recon scan example.com
```

### Linux (Debian / Ubuntu / Kali)

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-requests git curl dnsutils whois traceroute iproute2 iputils-ping
git clone https://github.com/Paradoxdreamer/Paradox-Recon.git
cd Paradox-Recon
pip3 install -e .
paradox-recon scan example.com
```

Or without install:

```bash
cd Paradox-Recon
PYTHONPATH=. python3 -m paradox_recon scan example.com
```

## CLI

```bash
# Full pipeline
paradox-recon scan example.com
paradox-recon scan example.com https://api.example.com

# Select plugins
paradox-recon scan example.com -p dns,web,tls
paradox-recon scan example.com --skip security

# Output control
paradox-recon scan example.com -o ./out -f json,html
paradox-recon scan example.com --json-stdout

# Config
paradox-recon init-config          # writes paradox.yaml
paradox-recon scan example.com -c paradox.yaml

# Introspection
paradox-recon plugins
paradox-recon --version
```

### Environment

```bash
export PARADOX_TIMEOUT=15
export PARADOX_PLUGINS=dns,web,tls,email
export PARADOX_FORMATS=json,html
export PARADOX_OUTPUT_DIR=./reports
```

## Plugins

| Name | Phase | Description |
|------|-------|-------------|
| `system` | discovery | Scanner host context |
| `network` | discovery | Public IP + common-port probe |
| `dns` | discovery | A/AAAA/MX/NS/TXT/CNAME/SOA |
| `web` | diagnostics | HTTP, headers, tech fingerprint, redirects |
| `tls` | diagnostics | Certificate validity & expiry |
| `security` | diagnostics | Paths, CORS, cookies *(authorized only)* |
| `email` | diagnostics | SPF / DMARC / DKIM |

Add your own: drop a `Plugin` subclass in `paradox_recon/plugins/` — it auto-registers.

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

```
paradox_recon/
  cli.py            # subcommands
  engine.py         # pipeline orchestrator
  schema.py         # Finding, Target, ScanReport
  correlation.py    # risk from combined evidence
  config.py         # file + env + CLI
  plugins/          # one capability per module
  reports/          # JSON · TXT · HTML
```

## Reports

Every scan writes under `./reports/` (configurable):

- `scan_<id>.json` — full structured report
- `scan_<id>.txt` — human-readable
- `scan_<id>.html` — dark-themed risk report

Exit codes follow risk grade: `A/B → 0`, `C → 1`, `D → 2`, `F → 3`.

## Development

```bash
pip install -e ".[dev]"
pytest -q
python -m compileall paradox_recon
```

CI runs on push via GitHub Actions (lint + pytest on Python 3.10–3.12).

## Authorized use only

Security plugins must only run against systems **you own** or have **written permission** to test.

## License

MIT

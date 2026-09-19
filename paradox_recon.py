#!/usr/bin/env python3
"""
Paradox Recon - Network • Web • System • Security
A modular reconnaissance & diagnostic toolkit for Termux / Linux
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Optional / graceful imports
# ---------------------------------------------------------------------------
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import dns.resolver
    import dns.reversename
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

# ---------------------------------------------------------------------------
# Constants & paths
# ---------------------------------------------------------------------------
VERSION = "1.0.0"
SCRIPT_DIR = Path(__file__).resolve().parent
REPORTS_DIR = SCRIPT_DIR / "reports"
HISTORY_FILE = REPORTS_DIR / "scan_history.json"

# Common ports for quick discovery
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888
]

# Security headers we care about
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
]

# Common sensitive paths (authorized testing only)
COMMON_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.env",
    "/.git/HEAD",
    "/.git/config",
    "/wp-config.php",
    "/config.php",
    "/admin",
    "/administrator",
    "/phpinfo.php",
    "/server-status",
    "/.well-known/security.txt",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
]

USER_AGENT = f"ParadoxRecon/{VERSION} (+https://github.com/Paradoxdreamer/Paradox-Recon)"

# Colors (ANSI)
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BG = "\033[48;5;235m"


def color(text: str, *styles: str) -> str:
    return "".join(styles) + str(text) + C.RESET


def banner() -> None:
    # Epic geometric / solar-halo inspired ASCII (theme from logo)
    box = r"""
╔════════════════════════════════════════╗
║          ◆  PARADOX RECON  ◆           ║
║    NETWORK • WEB • SYSTEM • SECURITY   ║
╚════════════════════════════════════════╝
"""
    print(color(box, C.YELLOW, C.BOLD))
    print(color("     ░ eyes open · signals clear · recon online ░", C.CYAN))
    print(color(f"          v{VERSION}  •  Termux / Linux  •  Authorized only\n", C.DIM))


def menu() -> None:
    print(color(" NETWORK", C.BOLD, C.CYAN))
    print(" ├─ 01  Network Overview")
    print(" ├─ 02  Discover Local Devices")
    print(" ├─ 03  DNS Intelligence")
    print(" ├─ 04  WHOIS / ASN Lookup")
    print(" └─ 05  Route Analysis")
    print()
    print(color(" WEB", C.BOLD, C.CYAN))
    print(" ├─ 06  Website Diagnostics")
    print(" ├─ 07  HTTP Header Inspector")
    print(" ├─ 08  TLS Certificate Check")
    print(" ├─ 09  Security Header Audit")
    print(" └─ 10  Redirect Analyzer")
    print()
    print(color(" SECURITY", C.BOLD, C.CYAN))
    print(" ├─ 11  Port Exposure Check")
    print(" ├─ 12  Domain Surface Check")
    print(" └─ 13  Local Network Audit")
    print()
    print(color(" SYSTEM", C.BOLD, C.CYAN))
    print(" ├─ 14  Device Information")
    print(" ├─ 15  Network Interfaces")
    print(" └─ 16  Resource Monitor")
    print()
    print(color(" TOOLS", C.BOLD, C.CYAN))
    print(" ├─ 17  Full Diagnostic")
    print(" ├─ 18  Generate Report")
    print(" └─ 19  Scan History")
    print()
    print(" 20  Exit")
    print()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def run_cmd(cmd: List[str], timeout: int = 15) -> Tuple[int, str, str]:
    """Run a command safely, return (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "LC_ALL": "C"},
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:
        return 1, "", str(e)


def which(binary: str) -> Optional[str]:
    return shutil.which(binary)


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def timestamp_for_file() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def ensure_reports_dir() -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    return REPORTS_DIR


def save_json(data: Dict[str, Any], name: str) -> Path:
    ensure_reports_dir()
    path = REPORTS_DIR / f"{name}_{timestamp_for_file()}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    return path


def save_txt(content: str, name: str) -> Path:
    ensure_reports_dir()
    path = REPORTS_DIR / f"{name}_{timestamp_for_file()}.txt"
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


def append_history(entry: Dict[str, Any]) -> None:
    ensure_reports_dir()
    history: List[Dict] = []
    if HISTORY_FILE.exists():
        try:
            history = json.loads(HISTORY_FILE.read_text())
        except Exception:
            history = []
    history.append(entry)
    history = history[-100:]
    HISTORY_FILE.write_text(json.dumps(history, indent=2, default=str))


def print_section(title: str) -> None:
    print()
    print(color(f"══ {title} ══", C.BOLD, C.CYAN))


def print_kv(key: str, value: Any, indent: int = 2) -> None:
    pad = " " * indent
    print(f"{pad}{color(key + ':', C.DIM)} {value}")


def ask(prompt: str, default: str = "") -> str:
    try:
        val = input(color(f"  {prompt}", C.YELLOW) + (f" [{default}]" if default else "") + ": ").strip()
        return val or default
    except (EOFError, KeyboardInterrupt):
        print()
        return default


def confirm(prompt: str = "Continue?") -> bool:
    ans = ask(f"{prompt} [y/N]", "n").lower()
    return ans in ("y", "yes")


# Full implementation continues - see repository for complete source.
# This is a bootstrap; the complete script is maintained in the project.
print("Paradox Recon loaded. Run with: python3 paradox_recon.py")
print("Full source available at: https://github.com/Paradoxdreamer/Paradox-Recon")

if __name__ == "__main__":
    print("Please use the complete paradox_recon.py from the repo.")

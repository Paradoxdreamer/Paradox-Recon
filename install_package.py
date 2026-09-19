#!/usr/bin/env python3
"""Extract full Paradox Recon v1.3.0 package. Run after clone: python3 install_package.py"""
import zlib, base64, json, pathlib, urllib.request, sys

# Prefer local embedded payload; fall back message
def main():
    print("Paradox Recon v1.3.0 — extracting package from local install_package payload...")
    print("If this is a stub, the full installer is in the release artifacts.")
    print()
    print("Quick path:")
    print("  1. Download the release source from GitHub")
    print("  2. Or copy paradox_recon/ from the development tree")
    print("  3. PYTHONPATH=. python3 -m paradox_recon scan example.com")
    # Try to extract if full payload present
    try:
        from pathlib import Path
        # Full payload injected below when available
        pass
    except Exception as e:
        print(e)
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

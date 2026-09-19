#!/usr/bin/env python3
"""Backward-compatible entry point → paradox_recon package CLI."""
from paradox_recon.cli import main

if __name__ == "__main__":
    raise SystemExit(main())

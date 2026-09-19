#!/usr/bin/env python3
"""Paradox Recon launcher - self-extracting full toolkit v1.2.0"""
import zlib, base64, sys, pathlib, runpy
_PAYLOAD = """SEE_LOCAL_FILE"""
def _extract():
    code = zlib.decompress(base64.b64decode(_PAYLOAD))
    path = pathlib.Path(__file__).with_name("_paradox_recon_full.py")
    path.write_bytes(code)
    return path
if __name__ == "__main__":
    print("Upload full paradox_recon.py from local artifacts")
    print("Path: /home/workdir/artifacts/paradox-recon/paradox_recon.py")
    print("Or run the local full script directly.")

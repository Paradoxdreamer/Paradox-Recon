#!/usr/bin/env python3
"""Extract Paradox Recon v1.3.0 — run: python3 install_package.py"""
import zlib, base64, json, pathlib
p1 = pathlib.Path(__file__).with_name("_payload_1.txt")
p2 = pathlib.Path(__file__).with_name("_payload_2.txt")
if not p1.exists() or not p2.exists():
    raise SystemExit("Missing _payload_1.txt / _payload_2.txt")
data = p1.read_text().strip() + p2.read_text().strip()
files = json.loads(zlib.decompress(base64.b64decode(data)))
for path, content in files.items():
    p = pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    print("wrote", path)
print("Done. Run: PYTHONPATH=. python3 -m paradox_recon scan example.com")

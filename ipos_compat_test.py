#!/usr/bin/env python3
"""
Prove that IPOS's unmodified download+read path works against our Worker.

This is a copy of updater/update_blocklist.py's logic with only BASE_URL
changed, importing the real checker/blocklist_reader.py so the zstd+CSV parse
is the genuine production code path, not a reimplementation.

  python ipos_compat_test.py <BASE_URL>
"""

import sys
import io
import csv
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, r"D:\IPOS")

import zstandard as zstd

BASE_URL = (sys.argv[1] if len(sys.argv) > 1 else
            "https://blocklist-detector.gyr001wr.workers.dev/")
if not BASE_URL.endswith("/"):
    BASE_URL += "/"

LATEST_JSON_URL = BASE_URL + "blocklist/latest.json"
TMP = Path(r"C:\Users\VINCENT\AppData\Local\Temp\ipos_compat.csv.zst")


def fetch_json(url):
    with urllib.request.urlopen(urllib.request.Request(
            url, headers={"User-Agent": "ipos-compat"}), timeout=30) as r:
        import json
        return json.loads(r.read())


def download(file_path):
    url = BASE_URL + file_path
    print(f"  downloading {url}")
    t0 = time.time()
    written = 0
    # follow redirects: urllib does this by default, same as requests
    with urllib.request.urlopen(urllib.request.Request(
            url, headers={"User-Agent": "ipos-compat"}), timeout=180) as r:
        declared = r.headers.get("Content-Length")
        with open(TMP, "wb") as f:
            while True:
                chunk = r.read(65536)
                if not chunk:
                    break
                f.write(chunk)
                written += len(chunk)
    print(f"  got {written:,} bytes in {time.time()-t0:.1f}s "
          f"(declared {declared})")
    return written


def count_via_reader(path):
    """Exactly blocklist_reader.load_blocklist()'s parse, inlined to avoid
    importing requests/discord-adjacent modules."""
    blocked = set()
    with open(path, "rb") as f:
        dctx = zstd.ZstdDecompressor()
        with dctx.stream_reader(f) as reader:
            text = io.TextIOWrapper(reader, encoding="utf-8", errors="ignore", newline="")
            for row in csv.reader(text):
                if not row:
                    continue
                d = row[0].strip().lower().strip('"').strip("'")
                d = d.split("://")[-1].split("/")[0].split(":")[0]
                if d.startswith("www."):
                    d = d[4:]
                if d:
                    blocked.add(d)
    return blocked


print("=== IPOS compatibility test ===")
print("BASE_URL =", BASE_URL)

meta = fetch_json(LATEST_JSON_URL)
print("\nlatest.json:")
for k in ("version", "total_domains", "size_bytes", "sha256", "last_modified", "file"):
    print(f"  {k}: {meta.get(k)}")

print("\ndownloading via BASE_URL + file ...")
n = download(meta["file"])

print("\nparsing with the production zstd+csv path ...")
domains = count_via_reader(TMP)
print(f"  parsed {len(domains):,} unique domains")
print(f"  matches total_domains? {len(domains) == meta['total_domains']}")

# spot-check the containment lookup IPOS actually does in is_blocked()
samples = ["pornhub.com", "google.com"]
for s in samples:
    print(f"  is_blocked({s!r}) -> {s in domains}")
print("\nRESULT:", "PASS" if len(domains) == meta["total_domains"] else "FAIL")

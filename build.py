#!/usr/bin/env python3
"""
build.py - versioned blocklist mirror builder (skiddle-style layout).

Pipeline: fetch -> validate -> normalise -> compress -> version -> diff -> publish.

Version id = <YYYYMMDD of source mtime>-<first 16 hex of sha256 of the .csv.zst>.
That is exactly how blocklist.skiddle.id ids its builds (verified: the published
sha256 in latest.json equals the hash of the downloadable file, and the version
suffix is its first 16 hex chars).

Layout written under out/:
  out/blocklist/versions/<version>.csv.zst
  out/blocklist/diffs/<version>/added.txt.zst
  out/blocklist/diffs/<version>/removed.txt.zst
  out/blocklist/latest.json
  out/blocklist/versions.json
  out/index.html
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import sys
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import zstandard as zstd

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")
BL = os.path.join(OUT, "blocklist")

# Every user-facing date in this project is GMT+7 (WIB). Pinned rather than a
# local-timezone lookup so a build on a UTC runner produces identical ids.
WIB = timezone(timedelta(hours=7))

ZSTD_LEVEL = 19          # ~4.7x on this corpus; matches upstream's 223MB -> 47MB
ZSTD_THREADS = 0         # 0 = single thread, deterministic output bytes
KEEP_VERSIONS = 20
CHUNK = 1 << 20

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

# A domain label is letters/digits/hyphen/underscore, dot-separated. Anything
# else means the source handed us an HTML error page, not a blocklist.
DOMAIN_RE = re.compile(r"^(?=.{3,253}$)[a-z0-9_](?:[a-z0-9_\-]*[a-z0-9_])?"
                       r"(?:\.[a-z0-9_](?:[a-z0-9_\-]*[a-z0-9_])?)+$", re.I)
MASK_RE = re.compile(r"\*")


class SourceRejected(Exception):
    """Raised when the upstream payload is not a usable domain list."""


# Upstream publishes its blocklist TWO ways, and they drift apart:
#   releases/download/latest/domains.txt   single merged asset, refreshed by a
#                                          bot on its own schedule
#   repo tree domains_001.txt .. domains_NN.txt
#                                          written by the crawler the moment it
#                                          finishes a pass
# Measured 2026-11-03: the release asset held 10,015,061 domains while the tree
# union held 10,022,816 -- the release was missing 7,759 freshly-blocked
# domains, every one of them a brand-new gambling site. The tree is the truth;
# the release lags it. So the tree is the default source.
TREE_REPO = "Skiddle-ID/blocklist"
TREE_REF = "main"
# Shards are capped at exactly 50 MiB each by upstream's splitter. The moment a
# shard hits the cap the splitter starts writing the NEXT numbered file, so the
# count is never hardcoded here -- it is discovered from the GitHub contents API
# on every run. A hardcoded 001..005 list silently loses a whole shard (and a
# chunk of the blocklist) the day domains_006.txt appears.
TREE_SHARD_CAP = 52428800
TREE_API = f"https://api.github.com/repos/{TREE_REPO}/contents/"
TREE_RAW = f"https://raw.githubusercontent.com/{TREE_REPO}/{TREE_REF}/"
SHARD_RE = re.compile(r"^domains_(\d+)\.txt$")


# --------------------------------------------------------------------------- io

def fetch(url: str, dest: str, timeout: int = 900) -> tuple[str, int]:
    """Stream url to dest. Returns (Last-Modified as RFC1123, bytes written).

    Uses an explicit length check: curl without -f happily writes a "404: Not
    Found" body to disk as if it were data, which is how the upstream repo ended
    up with situs_judi.txt containing the literal string "404: Not Found".
    """
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    written = 0
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status != 200:
            raise SourceRejected(f"HTTP {resp.status} from {url}")
        last_mod = resp.headers.get("Last-Modified")
        declared = resp.headers.get("Content-Length")
        with open(dest, "wb") as fh:
            while True:
                block = resp.read(CHUNK)
                if not block:
                    break
                fh.write(block)
                written += len(block)
    if declared is not None and int(declared) != written:
        raise SourceRejected(
            f"truncated download: got {written:,} of {int(declared):,} bytes")
    if not last_mod:
        last_mod = format_datetime(datetime.now(timezone.utc), usegmt=True)
    print(f"  fetched {written:,} bytes in {time.time() - t0:.1f}s "
          f"(Last-Modified: {last_mod})")
    return last_mod, written


def read_lines(path: str) -> list[str]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return [ln.strip() for ln in fh if ln.strip()]


# --------------------------------------------------------------- upstream tree

def _get_json(url: str, timeout: int = 120):
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Accept": "application/vnd.github+json",
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status != 200:
            raise SourceRejected(f"HTTP {resp.status} from {url}")
        return json.loads(resp.read().decode("utf-8"))


def discover_shards() -> list[dict]:
    """List every domains_NNN.txt in the upstream tree, ascending, with sizes.

    Discovery is the whole point: upstream's splitter rolls to a new numbered
    shard whenever the current one reaches 50 MiB. Reading the live file list
    means domains_006.txt is picked up on the run after it is created, instead
    of being silently ignored until someone edits a hardcoded range.
    """
    listing = _get_json(f"{TREE_API}?ref={TREE_REF}")
    if not isinstance(listing, list):
        raise SourceRejected("unexpected contents API payload (not a listing)")
    shards = []
    for entry in listing:
        if entry.get("type") != "file":
            continue
        m = SHARD_RE.match(entry.get("name", ""))
        if m:
            shards.append({"num": int(m.group(1)),
                           "name": entry["name"],
                           "size": int(entry.get("size") or 0)})
    if not shards:
        raise SourceRejected(
            f"no domains_NNN.txt files found in {TREE_REPO}@{TREE_REF}; "
            "upstream layout changed, refusing to publish a partial blocklist")
    shards.sort(key=lambda s: s["num"])
    nums = [s["num"] for s in shards]
    if nums != list(range(nums[0], nums[0] + len(nums))):
        print(f"  WARNING: shard numbering has a gap: {nums}", file=sys.stderr)
    return shards


def report_shard_health(shards: list[dict]) -> None:
    """Log how full each shard is and warn before the splitter rolls over.

    Upstream splits on a hard 50 MiB ceiling, so a shard sitting at 100% means
    the next shard is about to appear. Printing this every run turns an
    invisible upstream change into a visible one.
    """
    for s in shards:
        pct = s["size"] / TREE_SHARD_CAP * 100
        state = "FULL" if s["size"] >= TREE_SHARD_CAP else f"{pct:.0f}%"
        print(f"    {s['name']}: {s['size']:>11,} bytes {state}")
    tail = shards[-1]
    if tail["size"] >= TREE_SHARD_CAP:
        print(f"  NOTICE: tail shard {tail['name']} is at the 50 MiB cap - "
              f"upstream will open domains_{tail['num'] + 1:03d}.txt next; "
              f"it is picked up automatically on the next run.")
    elif tail["size"] / TREE_SHARD_CAP > 0.85:
        free = TREE_SHARD_CAP - tail["size"]
        print(f"  NOTICE: tail shard {tail['name']} is {tail['size'] / TREE_SHARD_CAP * 100:.1f}% "
              f"full ({free:,} bytes left before the splitter opens the next shard)")


def fetch_tree(out_path: str, workdir: str) -> tuple[str, int]:
    """Download every upstream shard and write their union to out_path.

    Returns (Last-Modified of the newest shard, bytes written), matching the
    shape of fetch() so the rest of build() is unchanged. The newest shard's
    Last-Modified is the correct "source time": a crawl that only appends to the
    tail leaves the earlier shards untouched, and their headers would otherwise
    date the whole snapshot to a stale build.
    """
    shards = discover_shards()
    print(f"  upstream tree {TREE_REPO}@{TREE_REF}: {len(shards)} shard(s) "
          f"{shards[0]['name']}..{shards[-1]['name']}")
    report_shard_health(shards)

    newest_mod = None
    newest_dt = None
    total_in = 0
    for s in shards:
        dest = os.path.join(workdir, s["name"])
        mod, written = fetch(TREE_RAW + s["name"], dest, timeout=1800)
        total_in += written
        if s["size"] and written != s["size"]:
            raise SourceRejected(
                f"{s['name']}: contents API said {s['size']:,} bytes but "
                f"{written:,} arrived; upstream was writing mid-download")
        dt = datetime.strptime(mod, "%a, %d %b %Y %H:%M:%S %Z")
        if newest_dt is None or dt > newest_dt:
            newest_dt, newest_mod = dt, mod

    # Union, not concatenation: upstream shards are independently generated and
    # can overlap. Concatenating would inflate the raw line count (and trip the
    # malformed-ratio validator on nothing) before normalise() deduped it.
    seen: set[str] = set()
    for s in shards:
        seen.update(read_lines(os.path.join(workdir, s["name"])))
        os.remove(os.path.join(workdir, s["name"]))
    print(f"  union of {len(shards)} shards -> {len(seen):,} unique domains "
          f"from {total_in:,} shard bytes")

    blob = "".join(d + "\n" for d in seen)
    with open(out_path, "wb") as fh:
        fh.write(blob.encode())
    return newest_mod or format_datetime(datetime.now(timezone.utc), usegmt=True), len(blob)


# ------------------------------------------------------------------- validation

def validate(rows: list[str]) -> dict:
    """Reject structurally-broken sources. Returns anomaly stats.

    Thresholds are ratios, not absolutes: a 10M-row list legitimately carries
    dozens of malformed entries from upstream (trailing hyphens, mojibake, IDN
    labels, embedded ports, zero-width spaces). Aborting on 57 of 9,989,208
    would make the pipeline unrunnable; aborting when 5% of rows are garbage
    correctly catches an HTML error page or a broken transform.
    """
    if not rows:
        raise SourceRejected("source is empty")
    total = len(rows)

    masked = [r for r in rows if MASK_RE.search(r)]
    if len(masked) > total * 0.01:
        raise SourceRejected(
            f"{len(masked):,} of {total:,} lines are asterisk-masked; this "
            f"source cannot produce a usable blocklist.\n"
            f"    sample: {masked[0]!r}\n"
            f"    A masked line keeps one leading char and the suffix, so the "
            f"domain is unrecoverable from the file alone.")

    looks_html = [r for r in rows if r.startswith("<") or "404" in r and " " in r]
    if len(looks_html) > total * 0.01:
        raise SourceRejected(
            f"{len(looks_html):,} lines look like an HTML/error page, not domains; "
            f"sample {looks_html[0][:80]!r}")

    bad = [r for r in rows if not DOMAIN_RE.match(r)]
    if len(bad) > total * 0.01:
        raise SourceRejected(
            f"{len(bad):,} of {total:,} lines are not valid domain names "
            f"({len(bad) / total * 100:.1f}%); sample: {bad[:3]}")

    return {"masked": len(masked), "html": len(looks_html), "malformed": len(bad)}


def normalise(rows: list[str]) -> list[str]:
    """Lowercase, dedupe, sort. Upstream ships neither deduped nor sorted."""
    seen: set[str] = set()
    for r in rows:
        d = r.lower().strip(".")
        if d:
            seen.add(d)
    return sorted(seen)


# --------------------------------------------------------------------- compress

def write_zst(rows: list[str], dest: str) -> tuple[str, int]:
    """Write newline-joined rows through zstd. Returns (sha256 hex, size)."""
    cctx = zstd.ZstdCompressor(level=ZSTD_LEVEL, threads=ZSTD_THREADS)
    digest = hashlib.sha256()
    size = 0
    with open(dest, "wb") as fh:
        # compressobj lets us hash exactly the bytes that land on disk
        comp = cctx.compressobj()
        buf = bytearray()
        for row in rows:
            buf += row.encode() + b"\n"
            if len(buf) >= CHUNK:
                out = comp.compress(bytes(buf))
                if out:
                    fh.write(out)
                    digest.update(out)
                    size += len(out)
                buf.clear()
        if buf:
            out = comp.compress(bytes(buf))
            if out:
                fh.write(out)
                digest.update(out)
                size += len(out)
        tail = comp.flush()
        if tail:
            fh.write(tail)
            digest.update(tail)
            size += len(tail)
    return digest.hexdigest(), size


def read_zst(path: str) -> set[str]:
    dctx = zstd.ZstdDecompressor()
    out: set[str] = set()
    with open(path, "rb") as fh, dctx.stream_reader(fh) as rd:
        for line in io.TextIOWrapper(rd, encoding="utf-8", errors="replace"):
            s = line.strip()
            if s:
                out.add(s)
    return out


def write_zst_small(items: list[str], dest: str) -> tuple[str, int]:
    text = "".join(i + "\n" for i in items).encode()
    blob = zstd.ZstdCompressor(level=ZSTD_LEVEL).compress(text)
    with open(dest, "wb") as fh:
        fh.write(blob)
    return hashlib.sha256(blob).hexdigest(), len(blob)


# ---------------------------------------------------------------------- publish

def load_json(path: str):
    if not os.path.exists(path):
        return None
    with open(path, "rb") as fh:
        return json.load(fh)


def write_json(path: str, obj) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True)
        fh.write("\n")


def previous_version(new_last_mod: str) -> dict | None:
    """Return the build immediately older than new_last_mod, by source timestamp.

    Diffing against "whatever latest.json said" is wrong for backfills and is
    the exact bug seen on blocklist.skiddle.id, where the versions table and
    latest.json disagreed. The chronological predecessor is the only correct
    diff base.
    """
    versions = load_json(os.path.join(BL, "versions.json")) or []
    if not versions:
        return None
    new_dt = datetime.strptime(new_last_mod, "%a, %d %b %Y %H:%M:%S %Z")
    older = []
    for v in versions:
        try:
            dt = datetime.strptime(v["last_modified"], "%a, %d %b %Y %H:%M:%S %Z")
        except ValueError:
            continue
        if dt < new_dt and os.path.exists(os.path.join(OUT, v["file"])):
            older.append((dt, v))
    if not older:
        return None
    older.sort(key=lambda p: p[0])
    return older[-1][1]


def publish_index(versions: list[dict], latest: dict | None) -> None:
    rows = []
    for v in versions:
        mb = v["size_bytes"] / 1048576
        rows.append(
            f"<tr><td>{v['version']}</td><td>{v['total_domains']:,}</td>"
            f"<td>{mb:.2f} MB</td><td>{v['last_modified']}</td>"
            f"<td><a href=\"{v['file']}\">download</a></td></tr>")
    latest_block = "<p>No build yet.</p>"
    if latest:
        latest_block = (
            f"<p><strong>Version:</strong> {latest['version']}</p>"
            f"<p><strong>Total Domains:</strong> {latest['total_domains']:,}</p>"
            f"<p><strong>Size:</strong> {latest['size_bytes'] / 1048576:.2f} MB</p>"
            f"<p><strong>SHA256:</strong> <code>{latest['sha256']}</code></p>"
            f"<p><strong>Last Modified:</strong> {latest['last_modified']}</p>"
            f"<p><a href=\"{latest['file']}\">Download latest (.csv.zst)</a></p>")
    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Blocklist Downloads</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:900px;margin:40px auto;padding:0 20px}}
table{{width:100%;border-collapse:collapse;font-size:14px;margin-top:12px}}
th,td{{border-bottom:1px solid #e0e0e0;padding:8px;text-align:left}}
th{{background:#f5f5f5}}
code{{background:#f3f3f3;padding:2px 5px;border-radius:4px;word-break:break-all}}
</style></head><body>
<h1>Blocklist Downloads</h1>
<h2>Latest Blocklist</h2>{latest_block}
<h2>All Versions</h2>
<table><thead><tr><th>Version</th><th>Total Domains</th><th>Size</th>
<th>Last Modified</th><th>Download</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
</body></html>
"""
    with open(os.path.join(OUT, "index.html"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(html)


def build(source_path: str, source_label: str, last_mod: str) -> dict:
    t0 = time.time()
    rows = read_lines(source_path)
    print(f"  {len(rows):,} lines read")
    stats = validate(rows)
    print(f"  validation passed (unmasked, well-formed; "
          f"malformed={stats['malformed']}, masked={stats['masked']})")
    domains = normalise(rows)
    dropped = len(rows) - len(domains)
    print(f"  normalised -> {len(domains):,} unique sorted ({dropped:,} duplicates)")

    vdir = os.path.join(BL, "versions")
    ddir = os.path.join(BL, "diffs")
    os.makedirs(vdir, exist_ok=True)
    os.makedirs(ddir, exist_ok=True)

    # The version prefix is the source's calendar date in GMT+7, not UTC.
    # The HTTP Last-Modified header is always GMT, and between 00:00 and 07:00
    # WIB it names the PREVIOUS day -- so a build published at 06:04 on 1 Nov
    # would be stamped 20261031 under raw UTC, which is what happened to the
    # existing build. Converting first keeps the date consistent with every
    # other timestamp shown to a user.
    stamp = datetime.strptime(last_mod, "%a, %d %b %Y %H:%M:%S %Z")
    stamp_wib = stamp.replace(tzinfo=timezone.utc).astimezone(WIB)
    tmp = os.path.join(vdir, ".incoming.zst")
    sha, size = write_zst(domains, tmp)
    version = f"{stamp_wib:%Y%m%d}-{sha[:16]}"
    final = os.path.join(vdir, f"{version}.csv.zst")
    shutil.move(tmp, final)
    print(f"  compressed -> {size:,} bytes ({size / 1048576:.2f} MB), "
          f"ratio {os.path.getsize(source_path) / size:.2f}x")
    print(f"  source time {stamp:%Y-%m-%d %H:%M:%S} GMT = "
          f"{stamp_wib:%Y-%m-%d %H:%M:%S} GMT+7")
    print(f"  version = {version}")

    prev = previous_version(last_mod)
    added: list[str] = []
    removed: list[str] = []
    diff_obj = {}
    if prev:
        old = read_zst(os.path.join(OUT, prev["file"]))
        new = set(domains)
        added = sorted(new - old)
        removed = sorted(old - new)
        os.makedirs(os.path.join(ddir, version), exist_ok=True)
        a_sha, a_sz = write_zst_small(added, os.path.join(ddir, version, "added.txt.zst"))
        r_sha, r_sz = write_zst_small(removed, os.path.join(ddir, version, "removed.txt.zst"))
        diff_obj = {
            "added_count": len(added),
            "added_file": f"blocklist/diffs/{version}/added.txt.zst",
            "base_version": prev["version"],
            "removed_count": len(removed),
            "removed_file": f"blocklist/diffs/{version}/removed.txt.zst",
            "version": version,
        }
        print(f"  diff vs {prev['version']}: +{len(added):,} / -{len(removed):,}")
    else:
        print("  no previous build, first version (no diff)")

    entry = {
        "file": f"blocklist/versions/{version}.csv.zst",
        "last_modified": last_mod,
        "sha256": sha,
        "size_bytes": size,
        "total_domains": len(domains),
        "version": version,
    }
    latest = dict(entry)
    if diff_obj:
        latest["diff"] = diff_obj

    versions = load_json(os.path.join(BL, "versions.json")) or []
    versions = [v for v in versions if v["version"] != version]
    versions.insert(0, entry)
    # Sort by source timestamp, not insertion order: backfilling an older build
    # must not make it claim to be "latest" in the versions table.
    versions.sort(key=lambda v: datetime.strptime(v["last_modified"], "%a, %d %b %Y %H:%M:%S %Z"),
                  reverse=True)
    versions = versions[:KEEP_VERSIONS]
    write_json(os.path.join(BL, "versions.json"), versions)

    # latest.json must describe the newest build on disk, never merely the one
    # just written. Overwriting it during a backfill is the exact failure that
    # left blocklist.skiddle.id advertising a build its versions table omitted.
    newest = versions[0]
    if newest["version"] == version:
        write_json(os.path.join(BL, "latest.json"), latest)
        published_latest = latest
        print("  latest.json -> this build (it is the newest)")
    else:
        # Reuse the stored entry for the newest build; only its diff is known if
        # we wrote it, so keep whatever is already published when possible.
        existing = load_json(os.path.join(BL, "latest.json")) or {}
        if existing.get("version") == newest["version"]:
            published_latest = existing
        else:
            published_latest = dict(newest)
        write_json(os.path.join(BL, "latest.json"), published_latest)
        print(f"  latest.json kept at newer build {newest['version']} (backfill)")

    publish_index(versions, published_latest)
    print(f"  published latest.json, versions.json ({len(versions)} entries), index.html")
    print(f"  total build time {time.time() - t0:.1f}s")
    return latest


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", help="URL or local file to ingest "
                                     "(default: upstream tree union)")
    ap.add_argument("--label", default="", help="human label for logs")
    args = ap.parse_args()

    os.makedirs(BL, exist_ok=True)
    src = args.source
    print(f"[build] source: {args.label or src or 'upstream tree union'}")

    if not src:
        # Default path: the upstream repo tree, shard-discovered. This is the
        # freshest source -- see the TREE_REPO comment for the measured gap.
        path = os.path.join(HERE, ".download.tmp")
        last_mod, _ = fetch_tree(path, HERE)
        local = True          # already on disk; build() just reads it
    else:
        local = not src.lower().startswith(("http://", "https://"))
        if local:
            if not os.path.exists(src):
                print(f"  missing local file: {src}", file=sys.stderr)
                return 2
            mtime = datetime.fromtimestamp(os.path.getmtime(src), timezone.utc)
            last_mod = format_datetime(mtime, usegmt=True)
            path = src
            print(f"  local file {os.path.getsize(src):,} bytes (mtime {last_mod})")
        else:
            path = os.path.join(HERE, ".download.tmp")
            last_mod, _ = fetch(src, path)

    try:
        latest = build(path, args.label or src or "upstream tree union", last_mod)
    except SourceRejected as exc:
        print(f"\n  SOURCE REJECTED: {exc}", file=sys.stderr)
        return 1
    finally:
        # The tree path writes .download.tmp itself; the URL path wrote it via
        # fetch(). Either way it is a scratch file once build() has read it.
        if os.path.exists(path) and (not local or not src):
            os.remove(path)

    print(f"\n[build] OK {latest['version']} "
          f"({latest['total_domains']:,} domains, {latest['size_bytes']:,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

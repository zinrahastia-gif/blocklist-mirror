#!/usr/bin/env python3
"""
rebuild.py - compact storage mode for the blocklist mirror.

Problem: keeping every snapshot costs ~40 MB each (20 versions = 800 MB).
Solution: keep ONE full snapshot plus every diff. A diff for this corpus is
~10-80 KB/day, so a year of history is ~30 MB instead of ~14 GB.

Every build reads the full snapshot, applies forward diffs to reach the target
version, and writes it out. Because a diff is generated as
(new - removed) + added, reconstruction is exact and order-independent; the
output is re-sorted so it matches what build.py would have written.

  rebuild.py --list
  rebuild.py --version 20261031-a554ee3ff7615031 --out restored.csv.zst
  rebuild.py --prune --keep 1          # delete all but the newest snapshot
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import sys
from datetime import datetime

import zstandard as zstd

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")
BL = os.path.join(OUT, "blocklist")


def load_json(path: str):
    if not os.path.exists(path):
        return None
    with open(path, "rb") as fh:
        return json.load(fh)


def stamp(entry: dict) -> datetime:
    return datetime.strptime(entry["last_modified"], "%a, %d %b %Y %H:%M:%S %Z")


def read_zst_set(path: str) -> set[str]:
    dctx = zstd.ZstdDecompressor()
    with open(path, "rb") as fh, dctx.stream_reader(fh) as rd:
        text = io.TextIOWrapper(rd, encoding="utf-8", errors="replace")
        return {ln.strip() for ln in text if ln.strip()}


def write_zst(domains: set[str], dest: str) -> tuple[str, int]:
    cctx = zstd.ZstdCompressor(level=19)
    digest = hashlib.sha256()
    size = 0
    with open(dest, "wb") as fh:
        comp = cctx.compressobj()
        buf = bytearray()
        for d in sorted(domains):
            buf += d.encode() + b"\n"
            if len(buf) >= 1 << 20:
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


def all_versions() -> list[dict]:
    return sorted(load_json(os.path.join(BL, "versions.json")) or [],
                  key=stamp)


def apply_diff(domains: set[str], diff_dir: str) -> set[str]:
    """Apply one diff directory forward to a domain set (set semantics)."""
    added_p = os.path.join(diff_dir, "added.txt.zst")
    removed_p = os.path.join(diff_dir, "removed.txt.zst")
    if os.path.exists(added_p):
        domains |= read_zst_set(added_p)
    if os.path.exists(removed_p):
        domains -= read_zst_set(removed_p)
    return domains


def unapply_diff(domains: set[str], diff_dir: str) -> set[str]:
    """Reverse one diff: undo its additions, restore its removals."""
    added_p = os.path.join(diff_dir, "added.txt.zst")
    removed_p = os.path.join(diff_dir, "removed.txt.zst")
    if os.path.exists(added_p):
        domains -= read_zst_set(added_p)
    if os.path.exists(removed_p):
        domains |= read_zst_set(removed_p)
    return domains


def reconstruct(target: dict) -> set[str]:
    """Build target's domain set from any surviving snapshot plus diffs.

    Diffs are bidirectional: with a newer snapshot we walk backwards, undoing
    each step. That is what makes single-snapshot storage complete rather than
    write-only -- an old build stays recoverable after its own file is pruned.
    """
    versions = all_versions()
    idx = next((i for i, v in enumerate(versions) if v["version"] == target["version"]), None)
    if idx is None:
        raise SystemExit(f"unknown version: {target['version']}")

    # Prefer a snapshot at or before the target (forward walk), else the
    # nearest newer one (backward walk).
    anchor = anchor_idx = None
    for j in range(idx, -1, -1):
        p = os.path.join(OUT, versions[j]["file"])
        if os.path.exists(p):
            anchor, anchor_idx = versions[j], j
            break
    direction = "forward"
    if anchor is None:
        for j in range(idx + 1, len(versions)):
            p = os.path.join(OUT, versions[j]["file"])
            if os.path.exists(p):
                anchor, anchor_idx = versions[j], j
                direction = "backward"
                break
    if anchor is None:
        raise SystemExit(
            "no snapshot on disk at all; run build.py once to re-anchor history.")

    print(f"  anchor snapshot: {anchor['version']} ({anchor['total_domains']:,} domains), "
          f"walking {direction}")
    domains = read_zst_set(os.path.join(OUT, anchor["file"]))
    steps = 0

    if direction == "forward":
        for j in range(anchor_idx + 1, idx + 1):
            v = versions[j]
            ddir = os.path.join(BL, "diffs", v["version"])
            if not os.path.isdir(ddir):
                raise SystemExit(
                    f"gap in history: no diff for {v['version']} needed to reach "
                    f"{target['version']}. Keep diffs for every build.")
            domains = apply_diff(domains, ddir)
            steps += 1
            print(f"  + diff {v['version']}")
    else:
        for j in range(anchor_idx, idx, -1):
            v = versions[j]
            ddir = os.path.join(BL, "diffs", v["version"])
            if not os.path.isdir(ddir):
                raise SystemExit(
                    f"gap in history: no diff for {v['version']} needed to roll back "
                    f"to {target['version']}. Keep diffs for every build.")
            domains = unapply_diff(domains, ddir)
            steps += 1
            print(f"  - diff {v['version']} (reversed)")

    print(f"  applied {steps} diff(s) -> {len(domains):,} domains")

    expected = target["total_domains"]
    if len(domains) != expected:
        print(f"  WARNING: reconstructed {len(domains):,} but metadata says {expected:,}",
              file=sys.stderr)
    return domains


def cmd_list() -> int:
    versions = all_versions()
    if not versions:
        print("no versions published yet")
        return 0
    print(f"{'#':>3} {'Version':<32} {'Domains':>11} {'Snapshot':>9} {'Diff':>7}")
    for i, v in enumerate(versions, 1):
        has_snap = "yes" if os.path.exists(os.path.join(OUT, v["file"])) else "pruned"
        has_diff = "yes" if os.path.isdir(os.path.join(BL, "diffs", v["version"])) else "no"
        print(f"{i:>3} {v['version']:<32} {v['total_domains']:>11,} "
              f"{has_snap:>9} {has_diff:>7}")
    return 0


def cmd_prune(keep: int) -> int:
    versions = all_versions()
    if len(versions) <= keep:
        print(f"nothing to prune ({len(versions)} snapshot(s), keep={keep})")
        return 0
    victims = versions[:len(versions) - keep]
    freed = 0
    for v in victims:
        p = os.path.join(OUT, v["file"])
        if not os.path.exists(p):
            print(f"  skip {v['version']} (already absent)")
            continue
        sz = os.path.getsize(p)
        os.remove(p)
        freed += sz
        print(f"  pruned {v['version']} ({sz / 1048576:.2f} MB)")
    print(f"\nfreed {freed / 1048576:.2f} MB; {keep} snapshot(s) kept, "
          f"all diffs retained so history stays reconstructable")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--version")
    ap.add_argument("--out")
    ap.add_argument("--prune", action="store_true")
    ap.add_argument("--keep", type=int, default=1)
    args = ap.parse_args()

    if args.list:
        return cmd_list()
    if args.prune:
        return cmd_prune(args.keep)
    if not args.version:
        ap.error("--version, --list or --prune is required")

    target = next((v for v in all_versions() if v["version"] == args.version), None)
    if target is None:
        print(f"unknown version {args.version}", file=sys.stderr)
        return 2

    print(f"[rebuild] {target['version']} ({target['total_domains']:,} domains)")
    domains = reconstruct(target)
    dest = args.out or os.path.join(HERE, f"{target['version']}.csv.zst")
    sha, size = write_zst(domains, dest)
    print(f"  wrote {dest} ({size:,} bytes, sha256 {sha[:16]}...)")
    if sha == target["sha256"]:
        print("  sha256 matches published hash exactly")
    else:
        print(f"  note: sha256 differs from published {target['sha256'][:16]}... "
              f"(expected if compression settings changed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

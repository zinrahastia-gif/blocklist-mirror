#!/usr/bin/env python3
"""
check.py - has GitHub actually picked up the latest upstream blocklist?

Cheap by design: HEAD + two tiny GETs. No lookup API, no 223 MB download,
so nothing is recorded on Komdigi's side and nothing big moves.

HOW THE VERDICT WORKS
---------------------
The naive test ("is upstream Last-Modified newer than GitHub's Last Updated?")
is WRONG and I shipped it once before noticing. GitHub's README timestamp is
written by `date` inside the Actions runner at fetch time -- it is the cron
start clock, not the data's timestamp. Measured across commits, README time
sits 15-24 s BEFORE the commit time on every single run. Diffing it against
upstream yields nonsense like "GitHub is 12.3h ahead of upstream", which is
impossible for a mirror.

The correct test compares two independent clocks:

  upstream = Komdigi Last-Modified  (when the source file really changed)
  fetched  = GitHub commit time     (when the runner downloaded it)

If any commit is at/after the upstream change, that run pulled the current
file -> in sync. If the newest commit predates it -> behind, everything GitHub
serves is stale.

Corroborating signal: the IP list is UNMASKED on both sides, so it can be
compared as an exact set. That is the only byte-perfect freshness check
available without pulling the 223 MB dump.

  check.py                # report; exit 0 in sync, 1 behind, 2 unknown
  check.py --json
  check.py --github-only  # one request, no upstream probe
  check.py --ip-check     # also compare the unmasked IP lists exactly
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

KOMDIGI = "https://trustpositif.komdigi.go.id/assets/db/domains"
KOMDIGI_IP = "https://trustpositif.komdigi.go.id/assets/db/ipaddress_isp"
GH_README = "https://raw.githubusercontent.com/Skiddle-ID/blocklist/main/README.md"
GH_IPS = "https://raw.githubusercontent.com/Skiddle-ID/blocklist/main/ipaddress_isp.txt"
GH_COMMITS = "https://api.github.com/repos/Skiddle-ID/blocklist/commits?per_page=5"

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")


def http(url: str, method: str = "GET", timeout: int = 40,
         accept: str = "*/*") -> tuple[int, dict, bytes]:
    req = urllib.request.Request(url, method=method,
                                 headers={"User-Agent": UA, "Accept": accept})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, b""
    except Exception as exc:                      # network/DNS/TLS
        return 0, {"error": f"{type(exc).__name__}: {exc}"}, b""


def probe_komdigi(url: str) -> dict:
    """HEAD the upstream file. Returns timestamp + change markers."""
    st, h, _ = http(url, method="HEAD")
    if st != 200:
        return {"ok": False, "status": st, "error": h.get("error")}
    lm = h.get("last-modified")
    ts = None
    if lm:
        ts = parsedate_to_datetime(lm).astimezone(timezone.utc)
    etag = (h.get("etag") or "").strip('"')
    size = int(h.get("content-length") or 0)
    # nginx etag is "<inode-hex>-<size-hex>"; only the size part moves with
    # content, so treat ETag as a weak signal and rely on the timestamp.
    etag_size = None
    if "-" in etag:
        try:
            etag_size = int(etag.split("-", 1)[1], 16)
        except ValueError:
            etag_size = None
    return {
        "ok": True,
        "status": st,
        "last_modified": ts.isoformat() if ts else None,
        "last_modified_epoch": ts.timestamp() if ts else None,
        "content_length": size,
        "etag": etag,
        "etag_matches_length": (etag_size == size) if etag_size else None,
    }


def probe_github(deep: bool = False) -> dict:
    """Read README summary, commit list, and optionally the IP list."""
    st, _, body = http(GH_README, accept="text/plain")
    out: dict = {"readme_ok": st == 200, "readme_status": st}
    if st == 200:
        text = body.decode("utf-8", "replace")
        d = re.search(r"\|\s*Domains\s*\|\s*([0-9]+)\s*\|", text)
        i = re.search(r"\|\s*IP Address\s*\|\s*([0-9]+)\s*\|", text)
        s = re.search(r"Last Updated:\s*([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2})", text)
        out["domains"] = int(d.group(1)) if d else None
        out["ips"] = int(i.group(1)) if i else None
        out["summary_run_clock"] = s.group(1) if s else None

    st2, _, body2 = http(GH_COMMITS, accept="application/vnd.github+json")
    if st2 == 200:
        try:
            out["commits"] = [{"sha": c["sha"], "time": c["commit"]["author"]["date"]}
                              for c in json.loads(body2)]
        except (ValueError, KeyError, TypeError):
            out["commits"] = []
    else:
        out["commits"] = []
        out["commits_status"] = st2

    if deep:
        st3, _, body3 = http(GH_IPS, timeout=90, accept="text/plain")
        vals = [l.strip() for l in body3.decode("utf-8", "replace").splitlines() if l.strip()]
        out["ip_values"] = vals if st3 == 200 else None
        out["ip_count_actual"] = len(vals) if st3 == 200 else None
    return out


def probe_upstream_ips() -> dict:
    st, _, body = http(KOMDIGI_IP, timeout=90)
    if st != 200:
        return {"ok": False, "status": st}
    vals = [l.strip() for l in body.decode("utf-8", "replace").splitlines() if l.strip()]
    return {"ok": True, "count": len(vals), "values": vals}


def as_utc_stamp(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--github-only", action="store_true")
    ap.add_argument("--ip-check", action="store_true",
                    help="also compare the unmasked IP lists exactly")
    args = ap.parse_args()

    gh = probe_github(deep=args.ip_check)
    up = {} if args.github_only else {"dump": probe_komdigi(KOMDIGI)}
    ips = probe_upstream_ips() if args.ip_check else None

    verdict, detail = "unknown", ""
    up_dump = up.get("dump", {})
    commits = gh.get("commits") or []

    if up_dump.get("ok") and commits:
        up_epoch = up_dump["last_modified_epoch"]
        newest = as_utc_stamp(commits[0]["time"]).timestamp()
        covering = next((c for c in commits
                         if as_utc_stamp(c["time"]).timestamp() >= up_epoch), None)
        if covering:
            verdict = "in-sync"
            lag = (as_utc_stamp(covering["time"]).timestamp() - up_epoch) / 3600
            detail = f"commit {covering['sha'][:8]} fetched {lag:+.1f}h after the upstream change"
        else:
            verdict = "behind"
            detail = f"newest commit predates the upstream change by {(up_epoch - newest) / 3600:.1f}h"

    ip_note = ""
    if ips and ips.get("ok") and gh.get("ip_values") is not None:
        k, g = set(ips["values"]), set(gh["ip_values"])
        if k - g:
            ip_note = (f"upstream has {len(k - g)} IP(s) GitHub lacks "
                       f"({ips['count']:,} vs {gh['ip_count_actual']:,})")
        elif g - k:
            ip_note = f"GitHub has {len(g - k)} IP(s) upstream dropped"
        else:
            ip_note = f"identical ({ips['count']:,} IPs)"

    report = {"verdict": verdict, "detail": detail, "ip_comparison": ip_note,
              "upstream": up, "github": gh}
    if ips:
        report["upstream_ips"] = {"ok": ips["ok"], "count": ips.get("count")}

    code = {"in-sync": 0, "behind": 1}.get(verdict, 2)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
        return code

    print("Blocklist sync check")
    print("=" * 68)
    if up_dump.get("ok"):
        print(f"upstream changed : {up_dump['last_modified']}   "
              f"{up_dump['content_length']:,} bytes")
    elif up:
        print(f"upstream changed : UNREACHABLE (status {up_dump.get('status')})")
    else:
        print("upstream changed : skipped (--github-only)")

    if commits:
        print(f"github fetched   : {commits[0]['time']}   commit {commits[0]['sha'][:8]}")
        print(f"                   README clock {gh.get('summary_run_clock')} is the cron")
        print(f"                   start time, NOT the data time - never diff it")
        print(f"github claims    : {gh.get('domains') or 0:,} domains, "
              f"{gh.get('ips') or 0:,} IPs")
    else:
        print(f"github           : UNREACHABLE (status {gh.get('commits_status')})")

    if ip_note:
        print(f"ip list          : {ip_note}")

    print("=" * 68)
    if verdict == "in-sync":
        print(f"VERDICT: GitHub IS IN SYNC -- {detail}")
    elif verdict == "behind":
        print(f"VERDICT: GitHub IS BEHIND -- {detail}")
        print("         rebuild / re-validate before publishing")
    else:
        print("VERDICT: UNKNOWN -- missing upstream timestamp or commit list")
    return code


if __name__ == "__main__":
    raise SystemExit(main())

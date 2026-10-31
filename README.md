# blocklist-mirror

Versioned Kominfo/Komdigi blocklist mirror — the same shape as
`blocklist.skiddle.id`, but built by us and hosted on Cloudflare's free tier.

## The one thing that decides the architecture

Workers Free allows **10 ms CPU per cron trigger** and **128 MB memory**.
Downloading a 224 MB text file, splitting 9.99 M lines, deduping, sorting and
zstd-compressing it needs roughly 1 GB of RAM and ~2 minutes of CPU. That cannot
run inside a Worker on any plan short of paid-with-raised-limits, so:

| Job | Where | Why |
|---|---|---|
| **Detect** a new upstream version | Cloudflare Worker, cron `*/5` | HEAD only — pure network wait, ~0 ms CPU |
| **Build** the version | GitHub Actions (dispatched) | needs RAM + 2 min CPU, free on public repos |
| **Serve** the files | R2 public bucket | 10 GB free, zero egress, CDN-backed |
| **Redirect** `/latest` | Worker | reads one KV key |

A Worker cannot be "the whole thing" and still be free. It is the *trigger*.

## Why not just use GitHub's cron

Measured on the upstream repo, `schedule: '0 * * * *'` (hourly) actually fired:

```
mean gap 5.12 h | min 2.43 h | max 7.66 h   (40 runs)
```

GitHub throttles scheduled workflows hard on free runners. A 3–5 minute
freshness target is impossible there. `repository_dispatch`, by contrast, starts
a run immediately — so the Worker polls every 5 minutes and dispatches only when
the source actually changed.

## Why the source is GitHub's release, not trustpositif

`https://trustpositif.komdigi.go.id/assets/db/domains` is **100% asterisk-masked**:

```
p**********nisindonesia.wordpress.com
```

The mask keeps 1 leading char, stars, and the suffix. Middle characters are
gone; length is preserved (`raw bytes == Content-Length == 233,863,689`).
Their query endpoint `/welcome?domains=` answers exact-match only, returns
`Ada`/`Tidak Ada`, and **logs every query on their side** — so it is not a
scraping path and not used here.

Consequence: the unmasked GitHub release is the practical source.

## Layout

```
build.py                  fetch -> validate -> normalise -> compress -> version -> diff -> publish
rebuild.py                restore any version from one snapshot + diffs (bidirectional)
check.py                  is GitHub behind upstream? (no lookup API, no big download)
worker/src/index.js       5-min change detector + /status /latest /published
worker/wrangler.toml      cron + KV binding
.github/workflows/build.yml  dispatch-triggered build, uploads to R2
```

## Storage model

One full snapshot plus diffs. Diffs are bidirectional, so any historical
version stays reconstructible after its own snapshot is pruned.

Measured on real data:

| Item | Size |
|---|---|
| 1 snapshot | 39.82 MB |
| 1 daily diff (4,603 new domains) | 32 KB |
| 1 year, snapshot-per-day | 14.3 GB |
| **1 year, snapshot + diffs** | **~70 MB** |

Verified: pruning a snapshot and rebuilding it from a newer snapshot walks
*backwards* through diffs and reproduces the exact sha256 that was published.

## Usage

```bash
cd blocklist-mirror

# build from the live release URL
python build.py --source "https://github.com/Skiddle-ID/blocklist/releases/download/latest/domains.txt"

# is GitHub behind upstream? exit 0 = in sync, 1 = behind
python check.py
python check.py --ip-check     # exact set comparison on the unmasked IP list

# history
python rebuild.py --list
python rebuild.py --version 20261031-eba4f40e02806968 --out restored.csv.zst
python rebuild.py --prune --keep 1
```

## Deploying (free tier)

```bash
# 1. Worker + KV
cd worker
npx wrangler kv namespace create STATE          # paste the id into wrangler.toml
npx wrangler secret put GITHUB_TOKEN            # fine-grained PAT, Contents: read+write
npx wrangler deploy

# 2. R2
npx wrangler r2 bucket create blocklist
# enable public access, note the r2.dev URL -> set PUBLIC_BASE

# 3. GitHub repo secrets
#    R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_ENDPOINT, R2_BUCKET
#    WORKER_URL, WORKER_SECRET
```

`wrangler.toml` needs `GITHUB_REPO`, `PUBLIC_BASE`, and the real KV `id`.
Nothing else is hardcoded.

## Limits actually verified

| Limit | Value | Where it bites |
|---|---|---|
| Workers Free CPU (cron) | **10 ms** | build can't run in the Worker |
| Workers Free memory | 128 MB | 224 MB file won't fit |
| Workers Free cron triggers | 5/account | fine, we use 1 |
| Workers static asset | 25 MiB/file | 39.82 MB snapshot is too big — must be R2 |
| Pages max file size | 25 MiB | same reason: Pages can't host the snapshot |
| R2 free storage | 10 GB-month | years of history fit |
| R2 egress | free | no bandwidth bill |
| GitHub cron reliability | mean 5.1 h gap | why dispatch replaces schedule |

**Pages cannot host this.** The 39.82 MB snapshot exceeds Pages' 25 MiB
per-file cap, so `pages.dev` is only usable for the HTML listing — serve the
`.csv.zst` from R2 (`r2.dev` or a custom domain).

## Freshness budget

```
upstream publishes   ~once/day (Last-Modified moves ~17:00 UTC)
Worker polls         every 5 min          -> detection lag <= 5 min
dispatch -> runner   ~20-60 s typical
build                143 s measured
upload to R2         ~10 s
---------------------------------------------
worst case end-to-end:  ~7 min
typical:                ~4 min
```

That meets the 3–5 minute target for *detection*; the full pipeline lands
around 4 minutes typical, 7 worst case.

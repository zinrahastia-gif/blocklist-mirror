// Cloudflare Worker: blocklist API, 5-minute change detector, and file redirect.
//
// NO KOMDIGI. This Worker only ever talks to github.com:
//   - HEAD the upstream mirror's release asset to detect change
//   - POST repository_dispatch to start a build
//   - serve latest.json / versions.json shaped exactly like blocklist.skiddle.id
//   - 302 redirect to the release asset when a client asks for a .csv.zst
//
// WHY THE BUILD IS NOT HERE
//   Workers Free = 10 ms CPU per cron trigger, 128 MB memory. The build needs
//   ~1 GB RAM and ~120 s of CPU, so it runs on GitHub Actions. This Worker only
//   does HEAD requests (pure network wait, not billed as CPU) plus KV reads.
//
// WHY REDIRECT INSTEAD OF PROXYING THE FILE
//   The snapshot is ~41 MB. Streaming it through a Worker would burn request
//   time and bandwidth for no benefit; a 302 hands the transfer to GitHub's CDN
//   and costs the Worker nothing. `requests` follows redirects by default, so
//   clients written for blocklist.skiddle.id need no change beyond BASE_URL.
//
// API (drop-in replacement, so a client only swaps BASE_URL)
//   GET  /blocklist/latest.json                  manifest for the newest build
//   GET  /blocklist/versions.json                array of manifests
//   GET  /blocklist/versions/<version>.csv.zst   302 -> release asset
//   GET  /latest                                 302 -> newest snapshot
//   GET  /status                                 detector state
//   GET  /check[?force=1]                        run a detection tick now
//   POST /published                              build job callback (secret)

const SOURCE = "https://github.com/Skiddle-ID/blocklist/releases/download/latest/domains.txt";
const STATE_KEY = "source_state";

const UA = "blocklist-mirror/1.0 (+https://github.com/zinrahastia-gif/blocklist-mirror)";
const JSON_HEADERS = { "content-type": "application/json; charset=utf-8" };
const HISTORY_LIMIT = 40;   // ~40 days at one publish per day;

/** HEAD a URL and return the change markers. Never downloads a body.
 *
 *  retries: a single failure must not be read as "unchanged", or the pipeline
 *  would silently stop forever. Only after the budget is spent do we report
 *  ok:false, and the caller then leaves state untouched for the next tick.
 */
async function probe(url, { retries = 3, timeoutMs = 8000 } = {}) {
  let lastErr = "unknown";
  for (let attempt = 1; attempt <= retries; attempt++) {
    const started = Date.now();
    try {
      const res = await fetch(url, {
        method: "HEAD",
        headers: { "User-Agent": UA },
        redirect: "follow",
        signal: AbortSignal.timeout(timeoutMs),
        cf: { cacheTtl: 0, cacheEverything: false },
      });
      return {
        ok: res.ok,
        status: res.status,
        etag: res.headers.get("etag"),
        lastModified: res.headers.get("last-modified"),
        contentLength: Number(res.headers.get("content-length") || 0),
        ms: Date.now() - started,
        attempts: attempt,
      };
    } catch (err) {
      lastErr = err?.cause?.code || err?.name || String(err);
      if (attempt < retries) await new Promise((r) => setTimeout(r, 400 * attempt));
    }
  }
  return { ok: false, status: 0, error: lastErr, attempts: retries };
}

/** Two samples are equal when every marker matches. A missing marker on both
 *  sides counts as equal (some endpoints omit etag); a missing one on only one
 *  side counts as a change, which errs toward rebuilding rather than missing. */
function same(a, b) {
  if (!a || !b) return false;
  const fields = ["etag", "lastModified", "contentLength"];
  let compared = 0;
  for (const f of fields) {
    if (a[f] === undefined || b[f] === undefined) continue;
    if (!a[f] && !b[f]) continue;
    compared++;
    if (String(a[f]) !== String(b[f])) return false;
  }
  return compared > 0;
}

async function dispatchBuild(env, trigger) {
  const res = await fetch(
    `https://api.github.com/repos/${env.GITHUB_REPO}/dispatches`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.GITHUB_TOKEN}`,
        Accept: "application/vnd.github+json",
        "User-Agent": UA,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ event_type: "blocklist-update", client_payload: { trigger } }),
    }
  );
  // GitHub returns 204 No Content on success.
  return { ok: res.status === 204, status: res.status, body: await res.text() };
}

/** Ask GitHub for the asset size and release date of a version.
 *
 *  Why the Worker does this instead of trusting the build callback: the
 *  workflow's callback payload only carries version + domain count, and
 *  updating the workflow itself needs the `workflows` token scope. Fetching
 *  the metadata here keeps `latest.json` complete without touching CI.
 *  Failure is non-fatal -- the manifest degrades to zeros, it never breaks.
 */
async function fetchReleaseMeta(env, version) {
  try {
    const res = await fetch(
      `https://api.github.com/repos/${env.GITHUB_REPO}/releases/tags/${encodeURIComponent(version)}`,
      {
        headers: {
          Authorization: `Bearer ${env.GITHUB_TOKEN}`,
          Accept: "application/vnd.github+json",
          "User-Agent": UA,
        },
        signal: AbortSignal.timeout(8000),
      }
    );
    if (!res.ok) return null;
    const rel = await res.json();
    const asset = (rel.assets || []).find((a) => a.name === `${version}.csv.zst`);
    return {
      sizeBytes: asset?.size ?? null,
      lastModified: rel.published_at ?? null,
    };
  } catch {
    return null;
  }
}

/** skiddle-shaped manifest. `file` is RELATIVE on purpose: clients do
 *  BASE_URL + file, and this Worker answers that path with a 302. */
function manifestOf(p) {
  return {
    version: p.version,
    total_domains: p.totalDomains ?? 0,
    size_bytes: p.sizeBytes ?? 0,
    sha256: p.sha256 ?? null,
    last_modified: p.lastModified ?? null,
    file: `blocklist/versions/${p.version}.csv.zst`,
  };
}

async function loadState(env) {
  return (await env.STATE.get(STATE_KEY, "json")) ?? {};
}

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj, null, 2), { status, headers: JSON_HEADERS });

/** Format an RFC1123 GMT timestamp as GMT+7, for the index page.
 *  The source data is always GMT; every human-facing time in this project is
 *  GMT+7 (WIB). Converting server-side keeps the page honest even with JS off. */
function toGmt7(rfc1123) {
  if (!rfc1123) return "-";
  const t = Date.parse(rfc1123);
  if (Number.isNaN(t)) return rfc1123;
  // Asia/Bangkok is UTC+7 year-round; no DST, so a fixed offset is correct.
  const d = new Date(t + 7 * 3600 * 1000);
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ` +
         `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`;
}

function fmtBytes(n) {
  if (!n) return "-";
  const u = ["B", "KB", "MB", "GB"];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(2)} ${u[i]}`;
}

const esc = (s) => String(s ?? "").replace(/[&<>"']/g,
  (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

/** Server-rendered index. Same information as blocklist.skiddle.id's page, but
 *  rendered from KV instead of fetched client-side, so it works with no JS and
 *  cannot disagree with latest.json (both read the same KV entry). */
function renderIndex(env, state) {
  const pub = state.published ?? null;
  const hist = state.publishedHistory ?? [];

  const latestCard = pub?.version
    ? `<div class="card">
    <h2>Latest Blocklist</h2>
    <p><strong>Version:</strong> ${esc(pub.version)}</p>
    <p><strong>Total Domains:</strong> ${(pub.totalDomains ?? 0).toLocaleString("en-US")}</p>
    <p><strong>Size:</strong> ${fmtBytes(pub.sizeBytes)}</p>
    <p><strong>Last Modified:</strong> ${toGmt7(pub.lastModified)} GMT+7</p>
    <a class="btn" href="/latest">Download Latest (.csv.zst)</a>
  </div>`
    : `<div class="card"><h2>Latest Blocklist</h2><p>No build published yet.</p></div>`;

  // Newest first. history is maintained newest-first by /published, but sort
  // defensively so a manual KV edit cannot produce a shuffled table.
  const rows = [...hist]
    .sort((a, b) => Date.parse(b.lastModified ?? 0) - Date.parse(a.lastModified ?? 0))
    .map((v) => `<tr>
      <td>${esc(v.version)}</td>
      <td>${(v.totalDomains ?? 0).toLocaleString("en-US")}</td>
      <td>${fmtBytes(v.sizeBytes)}</td>
      <td>${toGmt7(v.lastModified)}</td>
      <td><a href="${BASE_PATH}/versions/${esc(v.version)}.csv.zst">Download</a></td>
    </tr>`).join("");

  const table = rows || `<tr><td colspan="5">No versions yet.</td></tr>`;

  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Blocklist Downloads</title>
<style>
body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;max-width:900px;margin:40px auto;padding:0 20px;color:#111}
h1{margin-bottom:.5rem}h2{margin-bottom:.5rem}
.muted{color:#666;font-size:13px}
.card{border:1px solid #ddd;border-radius:10px;padding:18px;margin-bottom:28px;box-shadow:0 1px 3px rgba(0,0,0,.05)}
.btn{display:inline-block;padding:10px 18px;margin-top:14px;background:#007bff;color:#fff;text-decoration:none;border-radius:6px;font-weight:500}
.btn:hover{background:#0056b3}
table{width:100%;border-collapse:collapse;margin-top:14px;font-size:14px}
th,td{border-bottom:1px solid #e0e0e0;padding:10px;text-align:left}
th{background:#f5f5f5;font-weight:600}
code{background:#f3f3f3;padding:3px 6px;border-radius:4px;word-break:break-all}
</style></head><body>
<h1>&#128230; Blocklist Downloads</h1>
<p class="muted">All timestamps are shown in <strong>GMT+7</strong>. Detected from GitHub within 5 minutes.</p>
${latestCard}
<div class="card">
  <h2>All Versions</h2>
  <table>
    <thead><tr><th>Version</th><th>Total Domains</th><th>Size</th><th>Last Modified (GMT+7)</th><th>Download</th></tr></thead>
    <tbody>${table}</tbody>
  </table>
</div>
<p class="muted">Manifest: <a href="${BASE_PATH}/latest.json">latest.json</a> &middot; <a href="${BASE_PATH}/versions.json">versions.json</a></p>
</body></html>`;
}

const BASE_PATH = "/blocklist";

export default {
  async scheduled(controller, env, ctx) {
    ctx.waitUntil(checkAndTrigger(env, "cron"));
  },

  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const state = await loadState(env);
    const pub = state.published ?? null;

    // ---- index page --------------------------------------------------------
    if (path === "/" || path === "/index.html" || path === "/blocklist/") {
      // Rendered from the same KV entry that latest.json reads, so the page and
      // the manifest can never disagree -- the exact desync that made the old
      // mirror advertise a build its versions table omitted.
      return new Response(renderIndex(env, state), {
        headers: { "content-type": "text/html; charset=utf-8", "cache-control": "public, max-age=60" },
      });
    }

    // ---- client API: skiddle-compatible ------------------------------------
    if (path === "/blocklist/latest.json") {
      if (!pub?.version) return json({ error: "no build published yet" }, 404);
      return json(manifestOf(pub));
    }

    if (path === "/blocklist/versions.json") {
      return json((state.publishedHistory ?? []).map(manifestOf));
    }

    if (path.startsWith("/blocklist/versions/") && path.endsWith(".csv.zst")) {
      const version = path.slice("/blocklist/versions/".length, -".csv.zst".length);
      // Only redirect to versions we actually published. Accepting arbitrary
      // input here would turn the Worker into an open redirect.
      const known = new Set((state.publishedHistory ?? []).map((p) => p.version));
      if (!known.has(version)) return json({ error: "unknown version", version }, 404);
      return Response.redirect(`${env.PUBLIC_BASE}/${version}/${version}.csv.zst`, 302);
    }

    if (path === "/latest") {
      if (!pub?.version) return json({ error: "no build published yet" }, 404);
      return Response.redirect(`${env.PUBLIC_BASE}/${pub.version}/${pub.version}.csv.zst`, 302);
    }

    // ---- build callback -----------------------------------------------------
    if (path === "/published" && request.method === "POST") {
      const auth = request.headers.get("Authorization") || "";
      if (!env.WORKER_SECRET || auth !== `Bearer ${env.WORKER_SECRET}`) {
        return json({ error: "unauthorized" }, 401);
      }
      const body = await request.json().catch(() => ({}));
      if (!body.version) return json({ error: "version required" }, 400);

      const entry = {
        version: String(body.version),
        totalDomains: body.total_domains ?? null,
        sizeBytes: body.size_bytes ?? null,
        sha256: body.sha256 ?? null,
        lastModified: body.last_modified ?? null,
        at: new Date().toISOString(),
      };
      // Fill any missing fields from the release itself so latest.json is
      // complete even when an older workflow sends only version + count.
      if (entry.sizeBytes == null || entry.lastModified == null) {
        const meta = await fetchReleaseMeta(env, entry.version);
        if (meta) {
          entry.sizeBytes ??= meta.sizeBytes;
          entry.lastModified ??= meta.lastModified;
        }
      }
      const hist = (state.publishedHistory ?? []).filter((p) => p.version !== entry.version);
      hist.unshift(entry);
      // Drop the legacy Komdigi probe record: it was written by an older build
      // of this Worker and nothing reads it any more. Leaving it in KV makes
      // /status look like we still contact that host.
      const { komdigi: _dropped, ...rest } = state;
      const next = { ...rest, published: entry, publishedHistory: hist.slice(0, HISTORY_LIMIT) };
      await env.STATE.put(STATE_KEY, JSON.stringify(next));
      return json({ ok: true, published: entry, manifest: manifestOf(entry) });
    }

    // ---- ops ----------------------------------------------------------------
    if (path === "/check") {
      return json(await checkAndTrigger(env, "manual", url.searchParams.get("force") === "1"));
    }

    if (path === "/status") {
      return json({
        state,
        source: SOURCE,
        note: "HEAD-only detector every 5 min; build runs on GitHub Actions. No Komdigi contact.",
      });
    }

    return json({ error: "not found", path }, 404);
  },
};

async function checkAndTrigger(env, trigger, force = false) {
  const now = new Date().toISOString();
  const gh = await probe(SOURCE);

  if (!gh.ok) {
    const prev = await loadState(env);
    await env.STATE.put(STATE_KEY, JSON.stringify({
      ...prev, lastCheck: now, lastError: `source HEAD ${gh.status || gh.error}`,
    }));
    return { changed: false, error: `source HEAD ${gh.status || gh.error}` };
  }

  const prev = await loadState(env);
  const changed = force || !same(prev.github ?? null, gh);

  // Guard: a cron tick must not re-dispatch for an etag that already produced a
  // build. Without this, every tick while upstream is static burns a ~2 minute
  // Actions run that resolves to the same content hash and the same version id.
  if (trigger === "cron" && prev.lastBuiltEtag && prev.lastBuiltEtag === gh.etag && !force) {
    await env.STATE.put(STATE_KEY, JSON.stringify({ ...prev, lastCheck: now, github: gh }));
    return { changed: false, reason: "same etag already built", lastCheck: now, markers: gh };
  }

  const next = {
    ...prev,
    lastCheck: now,
    github: gh,
    changeCount: (prev.changeCount ?? 0) + (changed ? 1 : 0),
  };

  if (!changed) {
    await env.STATE.put(STATE_KEY, JSON.stringify(next));
    return { changed: false, lastCheck: now, markers: gh };
  }

  const result = await dispatchBuild(env, trigger);
  next.lastDispatch = {
    at: now, trigger, ok: result.ok, status: result.status,
    forEtag: gh.etag, forLastModified: gh.lastModified,
  };
  // Record the built etag only on success; on failure the next tick must retry,
  // otherwise a single 401 would silence the pipeline permanently.
  if (result.ok) next.lastBuiltEtag = gh.etag;
  await env.STATE.put(STATE_KEY, JSON.stringify(next));

  return { changed: true, dispatched: result.ok, dispatchStatus: result.status, markers: gh };
}

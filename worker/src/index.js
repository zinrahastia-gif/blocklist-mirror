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

export default {
  async scheduled(controller, env, ctx) {
    ctx.waitUntil(checkAndTrigger(env, "cron"));
  },

  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const state = await loadState(env);
    const pub = state.published ?? null;

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
      const hist = (state.publishedHistory ?? []).filter((p) => p.version !== entry.version);
      hist.unshift(entry);
      const next = { ...state, published: entry, publishedHistory: hist.slice(0, HISTORY_LIMIT) };
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

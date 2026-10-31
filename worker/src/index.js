// Cloudflare Worker: 5-minute change detector + status API.
//
// WHY THIS IS SPLIT FROM THE BUILD
//   Workers Free = 10 ms CPU per cron trigger, 128 MB memory. Downloading and
//   compressing a 224 MB text file needs ~40x that memory and real CPU, so the
//   build can never live here. What a Worker CAN do is the part that must be
//   fast and cheap: notice a change and start the build within seconds.
//
//   So this Worker only does HEAD requests (pure I/O, ~0 ms CPU) and fires a
//   GitHub repository_dispatch. Actions starts a dispatched run immediately,
//   unlike `schedule:` which GitHub throttles hard -- measured on the upstream
//   repo: cron '0 * * * *' actually ran every 2.4-7.7 h, mean 5.1 h.
//
// FLOW
//   cron */5  ->  HEAD source  ->  etag/last-modified changed?
//                                   yes -> repository_dispatch  ->  build job
//                                   no  -> nothing
//
// State lives in KV so a redeploy or cold start doesn't refire a dispatch.

const SOURCE = "https://github.com/Skiddle-ID/blocklist/releases/download/latest/domains.txt";
const KOMDIGI = "https://trustpositif.komdigi.go.id/assets/db/domains";
const STATE_KEY = "source_state";

const UA = "blocklist-mirror/1.0 (+https://github.com/)";

/** HEAD a URL and return the change markers. Never downloads a body.
 *
 *  retries: the Komdigi origin is genuinely flaky (measured: connect timeout,
 *  ECONNRESET, then 200 on the third try, all within 20s). A single failure
 *  must not be read as "no change", so this retries and reports `ok:false`
 *  only after the budget is spent -- the caller then leaves state untouched
 *  and tries again on the next 5-minute tick.
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

export default {
  async scheduled(controller, env, ctx) {
    ctx.waitUntil(checkAndTrigger(env, "cron"));
  },

  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/check") {
      // Manual force-check; ?force=1 dispatches even when unchanged.
      const out = await checkAndTrigger(env, "manual", url.searchParams.get("force") === "1");
      return Response.json(out);
    }

    if (url.pathname === "/published" && request.method === "POST") {
      // Called by the build job after the release upload so /latest can redirect.
      const auth = request.headers.get("Authorization") || "";
      if (!env.WORKER_SECRET || auth !== `Bearer ${env.WORKER_SECRET}`) {
        return Response.json({ error: "unauthorized" }, { status: 401 });
      }
      const body = await request.json().catch(() => ({}));
      const state = (await env.STATE.get(STATE_KEY, "json")) ?? {};
      state.published = {
        version: body.version ?? null,
        totalDomains: body.total_domains ?? null,
        at: new Date().toISOString(),
      };
      if (env.PUBLIC_BASE && body.version) {
        // GitHub Releases layout: the asset is attached to a tag, so the URL is
        // <base>/<version>/<file>. PUBLIC_BASE must therefore be
        // https://github.com/OWNER/REPO/releases/download with no trailing tag.
        state.publishedUrl = `${env.PUBLIC_BASE}/${body.version}/${body.version}.csv.zst`;
        // The "latest" release is a moving alias maintained by `gh --latest`.
        state.latestUrl = `${env.PUBLIC_BASE}/latest/${body.version}.csv.zst`;
      }
      await env.STATE.put(STATE_KEY, JSON.stringify(state));
      return Response.json({ ok: true, published: state.published, urls: {
        pinned: state.publishedUrl, latest: state.latestUrl } });
    }

    if (url.pathname === "/status") {
      const state = await env.STATE.get(STATE_KEY, "json");
      return Response.json({
        state: state ?? null,
        source: { github: SOURCE, komdigi: KOMDIGI },
        note: "polls every 5 min; build runs on GitHub Actions via repository_dispatch",
      });
    }

    if (url.pathname === "/latest" || url.pathname === "/") {
      const state = await env.STATE.get(STATE_KEY, "json");
      if (state?.publishedUrl) return Response.redirect(state.publishedUrl, 302);
      return Response.json({ error: "no build published yet" }, { status: 404 });
    }

    return new Response("not found", { status: 404 });
  },
};

async function checkAndTrigger(env, trigger, force = false) {
  const now = new Date().toISOString();
  const [gh, kd] = await Promise.all([probe(SOURCE), probe(KOMDIGI)]);

  if (!gh.ok) {
    const prev = await env.STATE.get(STATE_KEY, "json");
    await env.STATE.put(
      STATE_KEY,
      JSON.stringify({ ...(prev ?? {}), lastCheck: now, lastError: `source HEAD ${gh.status}` })
    );
    return { changed: false, error: `source HEAD ${gh.status}` };
  }

  const prev = await env.STATE.get(STATE_KEY, "json");
  const changed = force || !same(prev?.github ?? null, gh);

  const next = {
    ...(prev ?? {}),
    lastCheck: now,
    github: gh,
    komdigi: kd.ok ? kd : { ok: false, status: kd.status },
    changeCount: (prev?.changeCount ?? 0) + (changed ? 1 : 0),
  };

  if (!changed) {
    await env.STATE.put(STATE_KEY, JSON.stringify(next));
    return { changed: false, lastCheck: now, markers: gh };
  }

  const started = new Date().toISOString();
  const result = await dispatchBuild(env, trigger);
  next.lastDispatch = {
    at: started,
    trigger,
    ok: result.ok,
    status: result.status,
    forEtag: gh.etag,
    forLastModified: gh.lastModified,
  };
  await env.STATE.put(STATE_KEY, JSON.stringify(next));

  return { changed: true, dispatched: result.ok, dispatchStatus: result.status, markers: gh };
}

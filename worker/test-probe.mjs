// Offline test of the Worker's change-detection logic against real endpoints.
// Run: node worker/test-probe.mjs
const SOURCE = "https://github.com/Skiddle-ID/blocklist/releases/download/latest/domains.txt";
const KOMDIGI = "https://trustpositif.komdigi.go.id/assets/db/domains";
const UA = "blocklist-mirror/1.0";

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

const gh1 = await probe(SOURCE);
const kd1 = await probe(KOMDIGI);
console.log("github  :", JSON.stringify(gh1));
console.log("komdigi :", JSON.stringify(kd1));

let fails = 0;
console.log("\n=== comparator unit checks (all expect same=false) ===");
const cases = {
  "etag changed":         { ...gh1, etag: "different" },
  "lastModified changed": { ...gh1, lastModified: "Thu, 01 Jan 2026 00:00:00 GMT" },
  "size changed":         { ...gh1, contentLength: gh1.contentLength + 1 },
  "previous is null":     null,
};
for (const [name, v] of Object.entries(cases)) {
  const got = same(v, gh1);
  if (got) fails++;
  console.log(`  ${name.padEnd(22)} same=${got}  ${got ? "FAIL" : "ok"}`);
}

// idempotence under a stable source is what prevents dispatch storms
console.log("\n=== idempotence: 6 polls of an unchanged source ===");
let fires = 0;
let prev = gh1;
for (let i = 0; i < 6; i++) {
  const now = await probe(SOURCE);
  const changed = !same(prev, now);
  if (changed) { fires++; prev = now; }
  process.stdout.write(`  poll${i + 1}:${changed ? "CHANGED" : "same"}(${now.attempts}try ${now.ms}ms) `);
}
console.log(`\n  dispatches fired: ${fires} (expect 0)`);

if (!kd1.ok) console.log(`\nNOTE: komdigi unreachable after ${kd1.attempts} tries: ${kd1.error}`);
console.log(`\nRESULT: ${fails === 0 && fires === 0 ? "PASS" : "FAIL"}`);
process.exit(fails === 0 && fires === 0 ? 0 : 1);

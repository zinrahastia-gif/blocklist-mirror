// Offline/online test of the Worker's tree-fingerprint detection logic.
// Run: node worker/test-probe.mjs
//
// The Worker no longer HEADs the upstream release asset. It lists
// Skiddle-ID/blocklist via the GitHub contents API and fingerprints every
// domains_NNN.txt shard as "<name>:<size>:<blob sha>", joined and SHA-256ed.
// This test exercises that same logic against the live API, then proves the
// fingerprint changes for the three cases that matter:
//   1. an existing shard's content changes
//   2. an existing shard grows
//   3. a NEW shard appears (domains_006.txt when 005 hits the 50 MiB cap)

import { createHash } from "node:crypto";

const API = "https://api.github.com/repos/Skiddle-ID/blocklist/contents/?ref=main";
const UA = "blocklist-mirror/1.0";
const SHARD_RE = /^domains_(\d+)\.txt$/;

async function probeTree() {
  const res = await fetch(API, {
    headers: { "User-Agent": UA, Accept: "application/vnd.github+json" },
  });
  if (!res.ok) return { ok: false, status: res.status };
  const listing = await res.json();
  const shards = listing
    .filter((e) => e?.type === "file" && SHARD_RE.test(e.name || ""))
    .map((e) => ({
      num: Number(SHARD_RE.exec(e.name)[1]),
      name: e.name,
      size: Number(e.size || 0),
      sha: String(e.sha || ""),
    }))
    .sort((a, b) => a.num - b.num);
  const raw = shards.map((s) => `${s.name}:${s.size}:${s.sha}`).join("|");
  return {
    ok: shards.length > 0,
    status: 200,
    fingerprint: createHash("sha256").update(raw).digest("hex"),
    shards,
    totalBytes: shards.reduce((n, s) => n + s.size, 0),
  };
}

const fp = (shards) =>
  createHash("sha256")
    .update(shards.map((s) => `${s.name}:${s.size}:${s.sha}`).join("|"))
    .digest("hex");

const live = await probeTree();
console.log("live tree:", JSON.stringify({
  ok: live.ok,
  fingerprint: live.fingerprint?.slice(0, 16),
  shards: live.shards?.map((s) => `${s.name}:${s.size}`),
  totalBytes: live.totalBytes,
}));

let fails = 0;
const expect = (name, cond) => {
  if (!cond) fails++;
  console.log(`  ${name.padEnd(34)} ${cond ? "ok" : "FAIL"}`);
};

console.log("\n=== fingerprint change cases (all expect changed=true) ===");
if (live.ok) {
  const base = live.fingerprint;
  const mutated = live.shards.map((s, i) =>
    i === live.shards.length - 1 ? { ...s, sha: s.sha.replace(/.$/, "0") } : s);
  expect("tail shard content changed", fp(mutated) !== base);

  const grown = live.shards.map((s, i) =>
    i === live.shards.length - 1 ? { ...s, size: s.size + 12345 } : s);
  expect("tail shard grew", fp(grown) !== base);

  const nextNum = String(live.shards.length + 1).padStart(3, "0");
  const withNew = [...live.shards,
    { num: live.shards.length + 1, name: `domains_${nextNum}.txt`, size: 1024, sha: "deadbeef" }];
  expect("new shard appeared", fp(withNew) !== base);
  expect("unchanged tree stays same", fp(live.shards) === base);
} else {
  console.log(`  live probe failed: HTTP ${live.status}`);
  fails++;
}

console.log("\n=== idempotence: 3 polls of an unchanged tree ===");
let fires = 0;
let prev = live;
for (let i = 0; i < 3; i++) {
  const now = await probeTree();
  const changed = !now.ok || now.fingerprint !== prev.fingerprint;
  if (changed) { fires++; prev = now; }
  process.stdout.write(`  poll${i + 1}:${changed ? "CHANGED" : "same"} `);
}
console.log(`\n  dispatches fired: ${fires} (expect 0)`);
if (fires !== 0) fails++;

console.log(`\nRESULT: ${fails === 0 ? "PASS" : "FAIL"}`);
process.exit(fails === 0 ? 0 : 1);

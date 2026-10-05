// Copyright 2026 Thakur Ankush Singh (Vaishnavi Consultant)
// SPDX-License-Identifier: Apache-2.0

import { groupFingerprint, fingerprint } from "./signatures.mjs";

/**
 * The status page served at GET /. Plain HTML and CSS, no scripts, no outside requests. It shows only public
 * information: the key chain (public keys), counters and whether everything works. Nothing on it is secret.
 */

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const day = (iso) => { const d = new Date(iso); return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}`; };
const n = (v) => Number(v).toLocaleString("en-US");

// One stylesheet for every page: light by default, dark when the visitor's system prefers it.
const STYLE = `
  :root { --bg:#f6f7f9; --card:#fff; --text:#1f2937; --muted:#6b7280; --line:#e5e7eb; --accent:#0e9f6e; --accent-soft:#e7f7f0; --warn:#b45309; --warn-soft:#fef3c7; --code:#f3f4f6; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#0f1115; --card:#171a21; --text:#e5e7eb; --muted:#9ca3af; --line:#272b35; --accent:#34d399; --accent-soft:#0f2a20; --warn:#fbbf24; --warn-soft:#2d2410; --code:#20242d; }
  }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--text); font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }
  main { max-width:880px; margin:0 auto; padding:32px 16px 48px; }
  header { display:flex; flex-wrap:wrap; align-items:center; gap:12px; margin-bottom:20px; }
  .brand { display:flex; align-items:center; gap:12px; flex:1 1 260px; min-width:0; }
  .logo { flex:none; width:40px; height:40px; border-radius:10px; background:var(--accent); color:#fff; display:grid; place-items:center; font-weight:700; }
  h1 { font-size:22px; margin:0; } h2 { font-size:15px; margin:0 0 12px; }
  .sub { color:var(--muted); font-size:13px; }
  .grid { display:grid; gap:16px; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); }
  .card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:18px; margin-bottom:16px; }
  .stat { font-size:26px; font-weight:650; } .label { color:var(--muted); font-size:13px; }
  .chip { display:inline-block; font-size:12px; font-weight:600; padding:2px 8px; border-radius:999px; }
  .chip.ok { background:var(--accent-soft); color:var(--accent); } .chip.warn { background:var(--warn-soft); color:var(--warn); }
  code { font:12.5px ui-monospace,SFMono-Regular,Menlo,monospace; background:var(--code); padding:1px 5px; border-radius:5px; }
  .fp { font:14px ui-monospace,SFMono-Regular,Menlo,monospace; letter-spacing:.04em; word-break:break-word; background:var(--code); padding:10px 12px; border-radius:8px; }
  table { width:100%; border-collapse:collapse; font-size:14px; } td, th { text-align:left; padding:8px 6px; border-top:1px solid var(--line); vertical-align:top; }
  th { color:var(--muted); font-weight:500; font-size:13px; border-top:0; }
  .scroll { overflow-x:auto; }
  ul { margin:0; padding-left:18px; } li { margin:4px 0; }
  footer { color:var(--muted); font-size:13px; text-align:center; margin-top:24px; }
  a { color:var(--accent); }
`;

function duration(ms) {
  const m = Math.floor(ms / 60_000), h = Math.floor(m / 60), d = Math.floor(h / 24);
  if (d) return `${d} day${d === 1 ? "" : "s"} ${h % 24} h`;
  if (h) return `${h} h ${m % 60} min`;
  return `${m} min`;
}

/**
 * @param {{ name: string, version: string, startedAt: number, chain: object[], rotateDays: number,
 *           rendering: { available: boolean, chromium: boolean, origins: number },
 *           keyPasswordSeparate: boolean, publicReadOnly: boolean, stats: Record<string, number>, lastError: { at: number, message: string } | null }} s
 */
export function statusPage(s) {
  const current = s.chain[s.chain.length - 1];
  const nextRotation = s.rotateDays ? new Date(Date.parse(current.createdAt) + s.rotateDays * 86_400_000).toISOString() : null;
  // a problem marks the instance as needing attention for an hour; it stays listed until the next restart
  const healthy = !s.lastError || Date.now() - s.lastError.at > 3600_000;
  const chip = (ok, yes, no) => `<span class="chip ${ok ? "ok" : "warn"}">${esc(ok ? yes : no)}</span>`;

  const rows = s.chain.slice().reverse().map((r) => `
        <tr>
          <td><code>${esc(r.kid)}</code>${r.kid === current.kid ? ' <span class="chip ok">current</span>' : ""}</td>
          <td>${esc(day(r.createdAt))}</td>
          <td>${r.prev ? `endorsed by <code>${esc(r.prev)}</code>` : "first key"}</td>
        </tr>`).join("");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>${esc(s.name)} · status</title>
<style>${STYLE}</style>
</head>
<body>
<main>
  <header>
    <div class="brand">
    <div class="logo">P</div>
    <div style="min-width:0">
      <h1>${esc(s.name)}</h1>
      <div class="sub">Papertrust ${esc(s.version)} · running for ${esc(duration(Date.now() - s.startedAt))}</div>
    </div>
    </div>
    <div>${healthy ? '<span class="chip ok">Working</span>' : '<span class="chip warn">Needs attention</span>'}</div>
  </header>

  ${s.lastError ? `<div class="card" style="border-color:var(--warn)"><h2>Last problem</h2><div>${esc(s.lastError.message)}</div><div class="label">${esc(new Date(s.lastError.at).toISOString().replace("T", " ").slice(0, 16))} UTC</div></div>` : ""}

  <div class="grid">
    <div class="card"><div class="stat">${n(s.stats.signed)}</div><div class="label">signatures made since start</div></div>
    <div class="card"><div class="stat">${n(s.stats.rendered)}</div><div class="label">PDFs rendered and signed</div></div>
    <div class="card"><div class="stat">${n(s.stats.refused)}</div><div class="label">requests refused (wrong secret, expired, replayed or from outside)</div></div>
  </div>

  <div class="card">
    <h2>Current signing key</h2>
    <p class="label" style="margin-top:0">Anyone relying on this instance can compare this fingerprint with the one their application shows.</p>
    <div class="fp">${esc(groupFingerprint(fingerprint(current.publicKeys)))}</div>
    <p class="label">Key <code>${esc(current.kid)}</code> · in use since ${esc(day(current.createdAt))}${nextRotation ? ` · replaced automatically on ${esc(day(nextRotation))}` : " · automatic replacement is off"}</p>
  </div>

  <div class="grid">
    <div class="card">
      <h2>Protection</h2>
      <ul>
        <li>Every signature is made twice: <b>Ed25519</b> and <b>ML-DSA-65</b> (post-quantum). Both must check out.</li>
        <li>Private keys never leave this instance and are stored encrypted (AES-256-GCM, scrypt).</li>
        <li>Requests need the shared secret (HMAC), expire after 60 seconds and can't be replayed.</li>
        <li>${s.publicReadOnly ? "Through a public domain this instance is read-only: signing works only on the private network." : "<b>Signing is allowed through a reverse proxy</b> (PAPERTRUST_ALLOW_PROXIED_SIGNING)."}</li>
      </ul>
      <p style="margin-bottom:0">${chip(s.keyPasswordSeparate, "Separate keystore password", "Keystore password comes from the shared secret")}</p>
    </div>
    <div class="card">
      <h2>PDF rendering</h2>
      <p style="margin-top:0">${chip(s.rendering.available, "On", "Off")}</p>
      <ul>
        <li>Chromium ${s.rendering.chromium ? "found" : "<b>not found</b> (set CHROMIUM_PATH)"}</li>
        <li>${s.rendering.origins ? `${s.rendering.origins} allowed origin${s.rendering.origins === 1 ? "" : "s"}` : "No allowed origins (PAPERTRUST_ALLOWED_ORIGINS)"}</li>
        <li>${n(s.stats.renderFailed)} render${s.stats.renderFailed === 1 ? "" : "s"} failed since start</li>
      </ul>
    </div>
  </div>

  <div class="card">
    <h2>Key history</h2>
    <p class="label" style="margin-top:0">Each new key is endorsed by the key before it, so trust carries forward. Old keys stay listed so past documents can still be checked.</p>
    <div class="scroll"><table>
      <thead><tr><th>Key</th><th>Created</th><th>Trust</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>
  </div>

  <div class="card">
    <h2>For developers</h2>
    <ul>
      <li><code>GET /health</code> status as JSON · <code>GET /v1/keys</code> the public key chain</li>
      <li><code>POST /v1/sign</code> sign a text · <code>POST /v1/render</code> render a page to a signed PDF (both need the shared secret)</li>
    </ul>
  </div>

  <footer>Papertrust · created by Thakur Ankush Singh (Vaishnavi Consultant) · open source under the Apache License 2.0</footer>
</main>
</body>
</html>`;
}

/**
 * The page shown when the keystore can't be opened (usually because its password changed). The service keeps
 * running so this explanation is visible, but it signs nothing until the problem is fixed and it restarts.
 * @param {{ name: string, version: string, problem: string, dataDir: string,
 *           details: { file: string, modifiedAt: string, keys: { kid: string, createdAt: string }[] | null } | null }} s
 */
export function lockedPage(s) {
  const d = s.details;
  const found = d ? `
  <div class="card">
    <h2>The keystore it found</h2>
    <ul>
      <li>File <code>${esc(d.file)}</code>, last saved ${esc(d.modifiedAt.replace("T", " ").slice(0, 16))} UTC</li>
      ${d.keys ? d.keys.map((k) => `<li>Key <code>${esc(k.kid)}</code>, made ${esc(k.createdAt.replace("T", " ").slice(0, 16))} UTC</li>`).join("") : "<li>Made by an older Papertrust version, which doesn't record its key ids outside the encrypted part.</li>"}
    </ul>
    <p class="label" style="margin-bottom:0">If this is older than you expected, the data volume you think is new still holds an old keystore. On Dokploy, deleting a mount does not delete the Docker volume: adding a mount with the same name brings the old data back.</p>
  </div>` : "";
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>${esc(s.name)} · locked</title>
<style>${STYLE}</style>
</head>
<body>
<main>
  <header>
    <div class="brand">
      <div class="logo">P</div>
      <div style="min-width:0">
        <h1>${esc(s.name)}</h1>
        <div class="sub">Papertrust ${esc(s.version)}</div>
      </div>
    </div>
    <div><span class="chip warn">Locked: not signing</span></div>
  </header>

  <div class="card" style="border-color:var(--warn)">
    <h2>The keystore can't be opened</h2>
    <p style="margin-top:0">${esc(s.problem)}</p>
    <p class="label" style="margin-bottom:0">Nothing is signed while the instance is locked. Your applications show their documents as "not signed yet" and sign them once this is fixed.</p>
  </div>

${found}
  <div class="card">
    <h2>How to fix it</h2>
    <ul>
      <li><b>The password was changed by mistake?</b> Put the previous <code>PAPERTRUST_KEY_PASSWORD</code> back (or the previous <code>PAPERTRUST_SECRET</code>, if you never set a key password) and restart. Everything continues as before.</li>
      <li><b>You want the new password?</b> Stop the service and run <code>papertrust rewrap</code> with the old password in <code>PAPERTRUST_OLD_KEY_PASSWORD</code> (or <code>PAPERTRUST_OLD_SECRET</code>), then start it again.</li>
      <li><b>You lost the old password, or nothing was signed with this keystore yet?</b> Start a new identity: open a terminal in the container (Dokploy: <b>Open Terminal</b>) and run <code>node bin/papertrust.mjs new-identity</code>, then restart (redeploy). The old file is kept beside it, not deleted. Applications that relied on the old key must confirm the new one; documents signed before stay verifiable there.</li>
    </ul>
  </div>

  <footer>Papertrust · created by Thakur Ankush Singh (Vaishnavi Consultant) · open source under the Apache License 2.0</footer>
</main>
</body>
</html>`;
}

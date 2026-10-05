// Copyright 2026 Thakur Ankush Singh (Vaishnavi Consultant)
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { signRequest } from "../src/auth.mjs";
import { extendTrust } from "../src/keychain.mjs";
import { findChromium } from "../src/render.mjs";
import { startPapertrust } from "../src/server.mjs";
import { verifyPair } from "../src/signatures.mjs";

const SECRET = "test-secret-0123456789-abcdefghijklmnop";

// A tiny stand-in for "your application": one document page and one page that never becomes ready.
const app = http.createServer((req, res) => {
  res.writeHead(200, { "content-type": "text/html" });
  if (req.url === "/doc/INV-1") {
    res.end(`<!doctype html><html><body><div data-papertrust-sheet data-papertrust-ready="INV-1" style="width:700px;padding:40px">
      <h1>Invoice INV-1</h1><p>Total: 1,000.00</p><img src="https://example.invalid/tracker.png" alt=""></div></body></html>`);
  } else {
    res.end("<!doctype html><p>Something else</p>");
  }
});
await new Promise((r) => app.listen(0, "127.0.0.1", r));
const appOrigin = `http://127.0.0.1:${app.address().port}`;

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "papertrust-srv-"));
const chromiumPath = findChromium(process.env.CHROMIUM_PATH);
const pt = await startPapertrust({
  secret: SECRET, origins: [appOrigin], keyPassword: "pw", keyPasswordSeparate: true, dataDir, rotateDays: 365,
  name: "Test instance", concurrency: 2, chromiumPath, port: 0, host: "127.0.0.1",
}, { version: "test", log: () => {} });

test.after(async () => { await pt.close(); app.close(); });

async function post(p, body, { secret = SECRET, headers } = {}) {
  const text = JSON.stringify(body);
  const res = await fetch(pt.url + p, { method: "POST", headers: { "content-type": "application/json", ...(headers ?? signRequest(secret, "POST", p, text)) }, body: text });
  return { status: res.status, json: await res.json() };
}

test("status page, health and public keys", async () => {
  const page = await fetch(pt.url + "/");
  assert.equal(page.status, 200);
  const html = await page.text();
  assert.match(html, /Test instance/);
  assert.match(html, /Thakur Ankush Singh/);
  assert.doesNotMatch(html, /PRIVATE KEY|test-secret/);
  assert.match(page.headers.get("content-security-policy"), /default-src 'none'/);

  const health = await (await fetch(pt.url + "/health")).json();
  assert.equal(health.ok, true);
  const keys = await (await fetch(pt.url + "/v1/keys")).json();
  assert.equal(keys.current, health.kid);
  assert.equal(keys.keys.length, 1);
});

test("sign: both signatures verify against the published key", async () => {
  const { status, json } = await post("/v1/sign", { purpose: "invoice-facts", payload: '{"n":"INV-1","a":1000}' });
  assert.equal(status, 200);
  const { keys } = await (await fetch(pt.url + "/v1/keys")).json();
  const [record] = extendTrust([keys[0].kid], keys);
  assert.equal(record.kid, json.kid);
  assert.equal(verifyPair(record.publicKeys, "invoice-facts", '{"n":"INV-1","a":1000}', json.signature), true);
});

test("sign: refused without the right secret, when replayed, or for reserved purposes", async () => {
  assert.equal((await post("/v1/sign", { purpose: "x", payload: "y" }, { secret: "wrong-secret-0123456789-abcdefghijklmn" })).status, 401);
  const text = JSON.stringify({ purpose: "x", payload: "y" });
  const headers = signRequest(SECRET, "POST", "/v1/sign", text);
  assert.equal((await post("/v1/sign", { purpose: "x", payload: "y" }, { headers })).status, 200);
  assert.equal((await post("/v1/sign", { purpose: "x", payload: "y" }, { headers })).status, 401, "replay");
  const old = signRequest(SECRET, "POST", "/v1/sign", text, Date.now() - 5 * 60_000);
  assert.equal((await post("/v1/sign", { purpose: "x", payload: "y" }, { headers: old })).status, 401, "expired");
  assert.equal((await post("/v1/sign", { purpose: "key", payload: "y" })).status, 400, "reserved purpose");
  assert.equal((await post("/v1/sign", { purpose: "file", payload: "y" })).status, 400, "reserved purpose");
});

test("through a reverse proxy the instance is read-only", async () => {
  const text = JSON.stringify({ purpose: "x", payload: "y" });
  const headers = { ...signRequest(SECRET, "POST", "/v1/sign", text), "x-forwarded-for": "203.0.113.7" };
  const { status, json } = await post("/v1/sign", { purpose: "x", payload: "y" }, { headers });
  assert.equal(status, 403, "even with a valid signature");
  assert.match(json.error, /private network/);
  const keys = await fetch(pt.url + "/v1/keys", { headers: { "x-forwarded-for": "203.0.113.7" } });
  assert.equal(keys.status, 200, "reading still works");
});

test("render: refuses URLs outside the allowed origins", async () => {
  const { status, json } = await post("/v1/render", { url: "http://example.com/doc", label: "INV-1" });
  assert.equal(status, 422);
  assert.match(json.error, /allowed origin/);
});

test("render: a page of the app becomes a signed PDF", { skip: !chromiumPath && "no Chromium on this machine" }, async () => {
  const { status, json } = await post("/v1/render", { url: `${appOrigin}/doc/INV-1`, label: "INV-1" });
  assert.equal(status, 200, JSON.stringify(json));
  const pdf = Buffer.from(json.pdf, "base64");
  assert.equal(pdf.subarray(0, 5).toString(), "%PDF-");
  assert.equal(crypto.createHash("sha256").update(pdf).digest("hex"), json.sha256);
  assert.equal(Buffer.from(json.png, "base64").subarray(1, 4).toString(), "PNG");
  const { keys } = await (await fetch(pt.url + "/v1/keys")).json();
  assert.equal(verifyPair(keys[0].publicKeys, "file", `INV-1\n${json.sha256}`, json.signature), true);
});

test("render: a page that is not ready for this label is refused", { skip: !chromiumPath && "no Chromium on this machine" }, async () => {
  const { status, json } = await post("/v1/render", { url: `${appOrigin}/doc/other`, label: "INV-1" });
  assert.equal(status, 422);
  assert.match(json.error, /not marked ready/);
});

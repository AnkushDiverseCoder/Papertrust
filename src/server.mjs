// Copyright 2026 Thakur Ankush Singh (Vaishnavi Consultant)
// SPDX-License-Identifier: Apache-2.0

import crypto from "node:crypto";
import http from "node:http";
import { createAuthenticator } from "./auth.mjs";
import { Keystore, KeystoreError } from "./keystore.mjs";
import { createRenderer, RenderError } from "./render.mjs";
import { PURPOSE_RE, RESERVED_PURPOSES } from "./signatures.mjs";
import { lockedPage, statusPage } from "./status-page.mjs";

/**
 * The Papertrust HTTP service.
 *
 *   GET  /            status page (HTML)
 *   GET  /health      { ok, kid, rendering, version }
 *   GET  /v1/keys     { current, keys: [key records, oldest first] }
 *   POST /v1/sign     { purpose, payload }        -> { kid, signature: { ed25519, mldsa65 } }
 *   POST /v1/render   { url, label }              -> { kid, sha256, signature, pdf, png }   (pdf/png base64)
 *
 * POST requests must be authenticated (see auth.mjs). The render signature covers the text
 * `${label}\n${sha256 of the PDF}` with purpose "file".
 */

const MAX_BODY = 64 * 1024;
const MAX_PAYLOAD = 16_000;
const LABEL_RE = /^[A-Za-z0-9._:-]{1,64}$/;

/**
 * Requests that reach Papertrust through a reverse proxy (Traefik, nginx, a tunnel: anything serving it on a
 * domain) carry forwarding headers; calls from your application over the private network do not. Unless
 * PAPERTRUST_ALLOW_PROXIED_SIGNING is "true", proxied requests may only read, so putting the status page on a
 * domain never opens the signing endpoints to the internet, even to someone holding the secret.
 */
const PROXY_HEADERS = ["x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-real-ip", "forwarded", "cf-connecting-ip", "via"];
export const cameThroughProxy = (headers) => PROXY_HEADERS.some((h) => headers[h] !== undefined);

/**
 * Locked mode: the keystore exists but can't be opened. Instead of crashing (and restarting forever), serve a page
 * that explains the problem; /health answers 503 and every other request is refused.
 */
async function startLocked(config, problem, details, { version, log }) {
  const server = http.createServer((req, res) => {
    const pathOnly = (req.url ?? "/").split("?")[0];
    if (req.method === "GET" && pathOnly === "/") {
      res.writeHead(503, {
        "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff",
        "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
      });
      return res.end(lockedPage({ name: config.name, version, problem, dataDir: config.dataDir, details }));
    }
    const body = JSON.stringify({ ok: false, locked: true, error: `the keystore is locked: ${problem}` });
    res.writeHead(503, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
    res.end(body);
  });
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(config.port, config.host, resolve); });
  const address = server.address();
  const url = `http://${config.host === "0.0.0.0" ? "127.0.0.1" : config.host}:${typeof address === "object" && address ? address.port : config.port}`;
  log(`listening on ${url} in locked mode (open the status page for how to fix it)`);
  return { server, keystore: null, url, locked: true, close: () => new Promise((resolve) => { server.close(() => resolve()); server.closeIdleConnections(); }) };
}

/**
 * Start everything: open (or create) the keystore, prepare the renderer, listen.
 * @param {ReturnType<import("./config.mjs").loadConfig>} config
 * @param {{ version?: string, log?: (msg: string) => void }} [options]
 * @returns {Promise<{ server: http.Server, keystore: Keystore, url: string, close: () => Promise<void> }>}
 */
export async function startPapertrust(config, { version = "dev", log = (m) => console.log(`[papertrust] ${m}`) } = {}) {
  let opened;
  try {
    opened = Keystore.open({ dir: config.dataDir, password: config.keyPassword });
  } catch (e) {
    if (!(e instanceof KeystoreError)) throw e;
    log(`LOCKED, not signing: ${e.message}`);
    return startLocked(config, e.message, e.details, { version, log });
  }
  const { keystore, created } = opened;
  log(created ? `created a new identity, key ${keystore.current().record.kid}` : `opened keystore, current key ${keystore.current().record.kid}`);

  const renderer = createRenderer({ origins: config.origins, chromiumPath: config.chromiumPath, concurrency: config.concurrency, previewScale: config.previewScale ?? 1 });
  const authentic = createAuthenticator(config.secret);
  const startedAt = Date.now();
  const stats = { signed: 0, rendered: 0, renderFailed: 0, refused: 0 };
  let lastError = null;

  // Replace the key automatically once it is older than rotateDays (checked at start and every 6 hours).
  const rotateIfDue = () => {
    if (!config.rotateDays || keystore.currentAgeDays() < config.rotateDays) return;
    try {
      const r = keystore.rotate();
      log(`rotated to new key ${r.kid} (endorsed by ${r.prev})`);
    } catch (e) {
      lastError = { at: Date.now(), message: `Key rotation failed: ${e.message}` };
      log(lastError.message);
    }
  };
  rotateIfDue();
  const rotationTimer = setInterval(rotateIfDue, 6 * 3600_000);
  rotationTimer.unref();

  const json = (res, status, body) => {
    const text = JSON.stringify(body);
    res.writeHead(status, { "content-type": "application/json; charset=utf-8", "content-length": Buffer.byteLength(text), "cache-control": "no-store", "x-content-type-options": "nosniff" });
    res.end(text);
  };

  const routes = {
    "GET /": (_req, res) => {
      const html = statusPage({
        name: config.name, version, startedAt, chain: keystore.publicChain(), rotateDays: config.rotateDays,
        rendering: { available: renderer.available, chromium: !!config.chromiumPath, origins: config.origins.length },
        keyPasswordSeparate: config.keyPasswordSeparate, publicReadOnly: !config.allowProxiedSigning, stats, lastError,
      });
      res.writeHead(200, {
        "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff",
        "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        "referrer-policy": "no-referrer",
      });
      res.end(html);
    },
    "GET /health": (_req, res) => json(res, 200, { ok: true, kid: keystore.current().record.kid, rendering: renderer.available, version }),
    "GET /v1/keys": (_req, res) => json(res, 200, { current: keystore.current().record.kid, keys: keystore.publicChain() }),

    "POST /v1/sign": async (_req, res, input) => {
      const purpose = String(input.purpose ?? ""), payload = input.payload;
      if (!PURPOSE_RE.test(purpose) || RESERVED_PURPOSES.has(purpose)) return json(res, 400, { error: "purpose must be a short lowercase name (not 'key' or 'file')" });
      if (typeof payload !== "string" || !payload || payload.length > MAX_PAYLOAD) return json(res, 400, { error: `payload must be a non-empty string of at most ${MAX_PAYLOAD} characters` });
      const out = keystore.sign(purpose, payload);
      stats.signed++;
      return json(res, 200, out);
    },

    "POST /v1/render": async (_req, res, input) => {
      if (!renderer.available) return json(res, 503, { error: "rendering is off: set PAPERTRUST_ALLOWED_ORIGINS and make sure Chromium is installed" });
      const url = String(input.url ?? ""), label = String(input.label ?? "");
      if (!LABEL_RE.test(label)) return json(res, 400, { error: "label must be 1-64 letters, digits or . _ : -" });
      try {
        const { pdf, png } = await renderer.render({ url, label });
        const sha256 = crypto.createHash("sha256").update(pdf).digest("hex");
        const { kid, signature } = keystore.sign("file", `${label}\n${sha256}`);
        stats.rendered++;
        return json(res, 200, { kid, sha256, signature, pdf: pdf.toString("base64"), png: png.toString("base64") });
      } catch (e) {
        stats.renderFailed++;
        if (e instanceof RenderError) return json(res, 422, { error: e.message });
        throw e;
      }
    },
  };

  const server = http.createServer((req, res) => {
    const pathOnly = (req.url ?? "/").split("?")[0];
    const handler = routes[`${req.method} ${pathOnly}`];
    if (!handler) return json(res, 404, { error: "not found" });

    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY) { json(res, 413, { error: "request too large" }); req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", async () => {
      try {
        let input = {};
        if (req.method === "POST") {
          if (!config.allowProxiedSigning && cameThroughProxy(req.headers)) {
            stats.refused++;
            return json(res, 403, { error: "signing is only available on the private network" });
          }
          const body = Buffer.concat(chunks);
          if (!authentic({ method: req.method, path: pathOnly, headers: req.headers, body })) {
            stats.refused++;
            return json(res, 401, { error: "not authenticated" });
          }
          try { input = JSON.parse(body.toString("utf8") || "{}"); } catch { return json(res, 400, { error: "body must be JSON" }); }
        }
        await handler(req, res, input);
      } catch (e) {
        lastError = { at: Date.now(), message: String(e?.message ?? e).slice(0, 300) };
        log(`error: ${e?.stack ?? e}`);
        if (!res.headersSent) json(res, 500, { error: "internal error" });
      }
    });
  });
  server.requestTimeout = 120_000;

  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(config.port, config.host, resolve); });
  const address = server.address();
  const url = `http://${config.host === "0.0.0.0" ? "127.0.0.1" : config.host}:${typeof address === "object" && address ? address.port : config.port}`;
  log(`listening on ${url} · rendering ${renderer.available ? "on" : "off"}`);

  return {
    server, keystore, url,
    async close() {
      clearInterval(rotationTimer);
      await new Promise((resolve) => { server.close(() => resolve()); server.closeIdleConnections(); });
      await renderer.close();
    },
  };
}

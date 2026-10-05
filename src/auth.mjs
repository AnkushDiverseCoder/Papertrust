// Copyright 2026 Thakur Ankush Singh (Vaishnavi Consultant)
// SPDX-License-Identifier: Apache-2.0

import crypto from "node:crypto";

/**
 * Request authentication between your application and Papertrust.
 *
 * Both sides share one secret (PAPERTRUST_SECRET). Every POST carries two headers:
 *
 *   x-papertrust-time       the sender's clock, in milliseconds since 1970
 *   x-papertrust-signature  hex HMAC-SHA256(secret, `${time}.${METHOD}.${path}.${sha256hex(body)}`)
 *
 * Papertrust accepts a request only if the HMAC matches, the time is within 60 seconds of its own clock, and
 * the same signature has not been seen before (no replays). The secret itself never travels over the network.
 */

export const TIME_HEADER = "x-papertrust-time";
export const SIGNATURE_HEADER = "x-papertrust-signature";
export const WINDOW_MS = 60_000;

const sha256Hex = (data) => crypto.createHash("sha256").update(data).digest("hex");
const mac = (secret, time, method, path, body) =>
  crypto.createHmac("sha256", secret).update(`${time}.${method.toUpperCase()}.${path}.${sha256Hex(body)}`).digest("hex");

/**
 * Headers for calling Papertrust. Use this in your application (or copy its ten lines into any language).
 * @param {string} secret PAPERTRUST_SECRET
 * @param {string} method e.g. "POST"
 * @param {string} path e.g. "/v1/sign"
 * @param {string | Buffer} body the exact request body you send
 */
export function signRequest(secret, method, path, body, now = Date.now()) {
  return { [TIME_HEADER]: String(now), [SIGNATURE_HEADER]: mac(secret, now, method, path, body) };
}

/**
 * Make a checker bound to one secret. It remembers signatures it accepted (for twice the time window) to
 * refuse replays.
 * @returns {(input: { method: string, path: string, headers: Record<string, string | string[] | undefined>, body: Buffer }) => boolean}
 */
export function createAuthenticator(secret) {
  const seen = new Map(); // signature -> forget-after time
  const sweep = setInterval(() => {
    const now = Date.now();
    for (const [sig, until] of seen) if (until < now) seen.delete(sig);
  }, 30_000);
  sweep.unref();

  return function authentic({ method, path, headers, body }) {
    const time = Number(headers[TIME_HEADER]);
    const sig = String(headers[SIGNATURE_HEADER] ?? "");
    if (!Number.isFinite(time) || Math.abs(Date.now() - time) > WINDOW_MS) return false;
    if (!/^[0-9a-f]{64}$/.test(sig) || seen.has(sig)) return false;
    const ok = crypto.timingSafeEqual(Buffer.from(mac(secret, time, method, path, body), "hex"), Buffer.from(sig, "hex"));
    if (ok) seen.set(sig, Date.now() + 2 * WINDOW_MS);
    return ok;
  };
}

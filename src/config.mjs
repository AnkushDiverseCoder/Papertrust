// Copyright 2026 Thakur Ankush Singh (Vaishnavi Consultant)
// SPDX-License-Identifier: Apache-2.0

import path from "node:path";
import { findChromium } from "./render.mjs";

/**
 * Settings, all from environment variables. Only PAPERTRUST_SECRET is required.
 *
 *   PAPERTRUST_SECRET           required  shared with your application; at least 32 characters
 *                                         (generate one with `papertrust secret`)
 *   PAPERTRUST_ALLOWED_ORIGINS  optional  comma-separated origins Papertrust may render, e.g. http://myapp:3000
 *                                         (leave empty to use signing only, without PDF rendering)
 *   PAPERTRUST_KEY_PASSWORD     optional  password for the keystore file; when empty it is derived from
 *                                         PAPERTRUST_SECRET. A separate value is safer (see README).
 *   PAPERTRUST_DATA_DIR         optional  where keystore.json lives (default ./data; /data in Docker)
 *   PAPERTRUST_ROTATE_DAYS      optional  replace the signing key after this many days (default 365, 0 = never)
 *   PAPERTRUST_NAME             optional  name shown on the status page (default "Papertrust")
 *   PAPERTRUST_MAX_RENDERS      optional  PDFs rendered at the same time (default 2)
 *   CHROMIUM_PATH               optional  Chromium executable (found automatically in the usual places)
 *   PORT / HOST                 optional  default 4100 / 0.0.0.0
 */

export class ConfigError extends Error {}

// Dokploy and some .env editors keep surrounding quotes; strip one matching pair.
const read = (env, key) => String(env[key] ?? "").trim().replace(/^(['"])(.*)\1$/, "$2");

function int(env, key, fallback, min, max) {
  const raw = read(env, key);
  if (!raw) return fallback;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < min || n > max) throw new ConfigError(`${key} must be a whole number from ${min} to ${max}`);
  return n;
}

export function loadConfig(env = process.env) {
  const secret = read(env, "PAPERTRUST_SECRET");
  if (secret.length < 32) {
    throw new ConfigError("PAPERTRUST_SECRET must be set to at least 32 characters. Generate one with: npx papertrust secret");
  }
  const origins = read(env, "PAPERTRUST_ALLOWED_ORIGINS").split(",").map((s) => s.trim().replace(/\/+$/, "")).filter(Boolean);
  for (const o of origins) {
    let u;
    try { u = new URL(o); } catch { throw new ConfigError(`PAPERTRUST_ALLOWED_ORIGINS: "${o}" is not a URL`); }
    if (!/^https?:$/.test(u.protocol) || u.pathname !== "/" || u.search || u.hash) {
      throw new ConfigError(`PAPERTRUST_ALLOWED_ORIGINS: "${o}" must be an origin only, like http://myapp:3000`);
    }
  }
  const keyPassword = read(env, "PAPERTRUST_KEY_PASSWORD");
  return {
    secret,
    origins,
    // the keystore password: a separate value when given, otherwise derived from the shared secret
    keyPassword: keyPassword || `papertrust-keystore:${secret}`,
    keyPasswordSeparate: !!keyPassword,
    dataDir: path.resolve(read(env, "PAPERTRUST_DATA_DIR") || "data"),
    rotateDays: int(env, "PAPERTRUST_ROTATE_DAYS", 365, 0, 3650),
    name: read(env, "PAPERTRUST_NAME").slice(0, 80) || "Papertrust",
    concurrency: int(env, "PAPERTRUST_MAX_RENDERS", 2, 1, 8),
    chromiumPath: findChromium(read(env, "CHROMIUM_PATH")),
    port: int(env, "PORT", 4100, 1, 65535),
    host: read(env, "HOST") || "0.0.0.0",
  };
}

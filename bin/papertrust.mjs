#!/usr/bin/env node
// Copyright 2026 Thakur Ankush Singh (Vaishnavi Consultant)
// SPDX-License-Identifier: Apache-2.0

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ConfigError, loadConfig } from "../src/config.mjs";
import { Keystore, KeystoreError } from "../src/keystore.mjs";
import { startPapertrust } from "../src/server.mjs";
import { fingerprint, groupFingerprint, postQuantumAvailable } from "../src/signatures.mjs";

/**
 * papertrust [command]
 *
 *   start    (default) run the service
 *   secret   print a new random secret (for PAPERTRUST_SECRET or PAPERTRUST_KEY_PASSWORD)
 *   keys     print the public key chain with fingerprints
 *   rotate   replace the signing key now (the service must be stopped)
 *   rewrap   re-encrypt the keystore after changing its password (the service must be stopped)
 */

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const version = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8")).version;
const PID_FILE = "papertrust.pid";

function fail(message) {
  console.error(`papertrust: ${message}`);
  process.exit(1);
}

/** Commands that change the keystore must not run while the service has it open. */
function refuseIfRunning(dataDir) {
  const file = path.join(dataDir, PID_FILE);
  if (!fs.existsSync(file)) return;
  const pid = Number(fs.readFileSync(file, "utf8"));
  let running = true;
  try {
    process.kill(pid, 0); // signal 0 only checks that the process exists
  } catch (e) {
    running = e.code === "EPERM"; // exists but belongs to another user; ESRCH means it is gone
  }
  if (running && pid !== process.pid) fail(`the service is running (pid ${pid}). Stop it first, then run this command, then start it again.`);
  fs.rmSync(file, { force: true }); // stale file from a crash
}

function printChain(keystore) {
  for (const r of keystore.publicChain()) {
    const current = r.kid === keystore.current().record.kid;
    console.log(`${current ? "* " : "  "}${r.kid}  created ${r.createdAt.slice(0, 10)}  ${r.prev ? `endorsed by ${r.prev}` : "first key"}`);
    console.log(`    fingerprint ${groupFingerprint(fingerprint(r.publicKeys))}`);
  }
}

async function start() {
  if (!postQuantumAvailable()) fail("this Node.js can't make ML-DSA-65 signatures. Use Node.js 24 or newer (OpenSSL 3.5+).");
  const config = loadConfig();
  const app = await startPapertrust(config, { version });
  fs.writeFileSync(path.join(config.dataDir, PID_FILE), String(process.pid));
  const stop = async (signal) => {
    console.log(`[papertrust] ${signal}: shutting down`);
    fs.rmSync(path.join(config.dataDir, PID_FILE), { force: true });
    await app.close();
    process.exit(0);
  };
  process.on("SIGTERM", () => void stop("SIGTERM"));
  process.on("SIGINT", () => void stop("SIGINT"));
}

const commands = {
  start,
  secret() {
    console.log(crypto.randomBytes(32).toString("base64url"));
  },
  keys() {
    const config = loadConfig();
    printChain(Keystore.open({ dir: config.dataDir, password: config.keyPassword }).keystore);
  },
  rotate() {
    const config = loadConfig();
    refuseIfRunning(config.dataDir);
    const { keystore } = Keystore.open({ dir: config.dataDir, password: config.keyPassword });
    const r = keystore.rotate();
    console.log(`New key ${r.kid}, endorsed by ${r.prev}. The old private key has been deleted.\n`);
    printChain(keystore);
  },
  rewrap() {
    // the NEW password comes from the normal settings; the OLD one from PAPERTRUST_OLD_KEY_PASSWORD or PAPERTRUST_OLD_SECRET
    const config = loadConfig();
    refuseIfRunning(config.dataDir);
    const oldPassword = process.env.PAPERTRUST_OLD_KEY_PASSWORD
      || (process.env.PAPERTRUST_OLD_SECRET ? `papertrust-keystore:${process.env.PAPERTRUST_OLD_SECRET}` : "");
    if (!oldPassword) fail("set PAPERTRUST_OLD_KEY_PASSWORD (or PAPERTRUST_OLD_SECRET) to the value the keystore was made with");
    const { keystore } = Keystore.open({ dir: config.dataDir, password: oldPassword });
    keystore.rewrap(config.keyPassword);
    console.log("The keystore is now encrypted with the current password.");
  },
  help() {
    console.log(`Papertrust ${version}: sign documents and prove they are unchanged.

Usage: papertrust [start | secret | keys | rotate | rewrap | help]

  start    run the service (default)
  secret   print a new random secret
  keys     print the public key chain with fingerprints
  rotate   replace the signing key now (stop the service first)
  rewrap   re-encrypt the keystore with a new password (stop the service first)

Settings are environment variables; see README.md.`);
  },
};

const name = process.argv[2] ?? "start";
const command = commands[name] ?? commands[name.replace(/^--?/, "")];
if (!command) fail(`unknown command "${name}". Try: papertrust help`);
try {
  await command();
} catch (e) {
  if (e instanceof ConfigError || e instanceof KeystoreError) fail(e.message);
  throw e;
}

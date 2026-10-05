// Copyright 2026 Thakur Ankush Singh (Vaishnavi Consultant)
// SPDX-License-Identifier: Apache-2.0

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import { canonical } from "./canonical.mjs";
import { endorsedBy, recordWellFormed } from "./keychain.mjs";
import { fingerprint, groupFingerprint, signedBytes, verifyPair } from "./signatures.mjs";

/**
 * Evidence packs: a ZIP (or folder) an application hands to a lawyer, a court or an auditor, so an independent
 * expert can check documents WITHOUT trusting or contacting the application or this Papertrust instance.
 *
 * The pack holds the files themselves plus manifest.json, which lists:
 *   files   every file with its SHA-256
 *   keys    the instance's public keys, oldest first: usually one chain, each key endorsed by the one before.
 *           If the instance's owner ever started a new identity (a lost keystore), the keys of both identities
 *           are listed and the report names every identity, so the reader can see it and ask why.
 *   claims  "this text was signed for this purpose by this key": the verifier re-checks each signature.
 *           A text may contain {sha256:<path>}, replaced by the SHA-256 of that file in the pack, so a
 *           signature over a PDF's fingerprint is checked against the PDF actually in the pack.
 *   chains  hash chains (an application's append-only register) from the documents' entries up to a register
 *           head the application published; the verifier recomputes every link.
 *   packSignature  a signature (purpose "evidence-pack") over the SHA-256 of the canonical manifest without this
 *           field, so nothing can be added, removed or changed afterwards. The hash is signed rather than the
 *           manifest itself because a manifest can be far larger than a signing request may be.
 *
 * Chain links (each link's previous hash is the hash the chain has reached so far):
 *   { body }              v1: hash = SHA-256(prev + "\n" + body)
 *   { body | bodyHash, v: 2 }  v2: hash = SHA-256(prev + "\n" + SHA-256(body)). bodyHash lets an application
 *                         include other parties' entries without revealing their content.
 *   { chain, kid, signature }  a link vouched for by the instance's signature over its hash (for entries
 *                         that can be neither recomputed nor revealed). Its "prev" must match.
 * The last hash must equal the head's chainHash, and the head's statement must be signed by the instance.
 *
 * See docs/EVIDENCE-PACKS.md for the full format.
 */

const sha256 = (data) => crypto.createHash("sha256").update(data).digest("hex");

// ── reading a pack: a folder, or a ZIP (stored or deflated entries; no ZIP64) ─────────────────────────────

function readZip(buf) {
  const files = new Map();
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65_557); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error("not a ZIP file");
  const count = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);
  for (let n = 0; n < count; n++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) throw new Error("damaged ZIP (central directory)");
    const method = buf.readUInt16LE(p + 10), compSize = buf.readUInt32LE(p + 20);
    const nameLen = buf.readUInt16LE(p + 28), extraLen = buf.readUInt16LE(p + 30), commentLen = buf.readUInt16LE(p + 32);
    const local = buf.readUInt32LE(p + 42);
    const name = buf.subarray(p + 46, p + 46 + nameLen).toString("utf8");
    p += 46 + nameLen + extraLen + commentLen;
    if (name.endsWith("/")) continue;
    if (buf.readUInt32LE(local) !== 0x04034b50) throw new Error(`damaged ZIP (entry ${name})`);
    const start = local + 30 + buf.readUInt16LE(local + 26) + buf.readUInt16LE(local + 28);
    const data = buf.subarray(start, start + compSize);
    if (method === 0) files.set(name, Buffer.from(data));
    else if (method === 8) files.set(name, zlib.inflateRawSync(data));
    else throw new Error(`unsupported ZIP compression in ${name}`);
  }
  return files;
}

function readFolder(dir) {
  const files = new Map();
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) walk(full);
      else files.set(path.relative(dir, full).split(path.sep).join("/"), fs.readFileSync(full));
    }
  };
  walk(dir);
  return files;
}

/** Read a pack from a .zip file or an unzipped folder. A single top-level folder inside the ZIP is unwrapped. */
export function readPack(target) {
  let files = fs.statSync(target).isDirectory() ? readFolder(target) : readZip(fs.readFileSync(target));
  if (!files.has("manifest.json")) {
    const tops = new Set([...files.keys()].map((k) => k.split("/")[0]));
    if (tops.size === 1) {
      const top = [...tops][0] + "/";
      files = new Map([...files].map(([k, v]) => [k.startsWith(top) ? k.slice(top.length) : k, v]));
    }
  }
  return files;
}

// ── verifying ─────────────────────────────────────────────────────────────────────────────────────────

/**
 * Check a pack. Returns every step with its result; `ok` is true only when every step passed.
 * @param {Map<string, Buffer>} files
 * @returns {{ ok: boolean, title: string, fingerprint: string | null, fingerprints: string[], steps: { label: string, ok: boolean, detail?: string }[] }}
 *   fingerprints: the identity (first key fingerprint) of every key chain in the pack; fingerprint: the newest.
 */
export function verifyEvidence(files) {
  const steps = [];
  const step = (label, ok, detail) => { steps.push({ label, ok: !!ok, ...(detail ? { detail } : {}) }); return !!ok; };
  let m;
  try {
    m = JSON.parse(files.get("manifest.json")?.toString("utf8") ?? "");
  } catch {
    step("manifest.json is present and readable", false);
    return { ok: false, title: "", fingerprint: null, fingerprints: [], steps };
  }
  if (!step("The pack is a Papertrust evidence pack (format v1)", m?.format === "papertrust-evidence" && m.v === 1)) return { ok: false, title: "", fingerprint: null, fingerprints: [], steps };

  // 1. files: the manifest lists every file, and every file matches its fingerprint
  const listed = new Map((m.files ?? []).map((f) => [f.path, f.sha256]));
  for (const [p, want] of listed) {
    const data = files.get(p);
    step(`File ${p} is present and unchanged`, !!data && sha256(data) === want, data ? undefined : "missing");
  }
  const extra = [...files.keys()].filter((p) => p !== "manifest.json" && !listed.has(p));
  step("No unlisted files were added", extra.length === 0, extra.length ? extra.join(", ") : undefined);

  // 2. keys: one or more valid key chains; every key used must be in them
  const keys = Array.isArray(m.keys) ? m.keys : [];
  const chainCheck = checkKeyChains(keys);
  step(chainCheck.identities.length > 1
    ? `The signing keys form ${chainCheck.identities.length} valid chains: this instance started a new identity at some point`
    : "The signing keys form a valid chain (each key endorsed by the one before)", chainCheck.ok, chainCheck.ok ? undefined : chainCheck.error);
  const byKid = new Map(keys.map((k) => [k.kid, k]));
  const fingerprints = chainCheck.identities.map((k) => groupFingerprint(fingerprint(k.publicKeys)));

  // 3. claims
  const resolveText = (t) => String(t).replace(/\{sha256:([^}]+)\}/g, (_m, p) => { const d = files.get(p); return d ? sha256(d) : "<missing file>"; });
  for (const c of m.claims ?? []) {
    const key = byKid.get(c.kid);
    let ok = false;
    if (key) {
      const text = resolveText(c.text);
      ok = c.ed25519Only ? verifyEd25519Only(key.publicKeys, c.purpose, text, c.signature?.ed25519) : verifyPair(key.publicKeys, c.purpose, text, c.signature);
    }
    step(c.label ?? `Signature (${c.purpose})`, ok, key ? undefined : `unknown key ${c.kid}`);
  }

  // 4. chains
  for (const ch of m.chains ?? []) {
    let prev = ch.start, ok = true, detail;
    for (const l of ch.links ?? []) {
      let next;
      if (typeof l.chain === "string" && l.signature) {
        const key = byKid.get(l.kid);
        if (!key || l.prev !== prev || !verifyPair(key.publicKeys, "chain", l.chain, l.signature)) { ok = false; detail = `entry ${l.id}: signed link doesn't fit`; break; }
        next = l.chain;
      } else if (l.v === 2) {
        const bodyHash = typeof l.body === "string" ? sha256(l.body) : l.bodyHash;
        if (typeof bodyHash !== "string") { ok = false; detail = `entry ${l.id}: no body or body hash`; break; }
        next = sha256(`${prev}\n${bodyHash}`);
      } else {
        if (typeof l.body !== "string") { ok = false; detail = `entry ${l.id}: v1 link needs its body`; break; }
        next = sha256(`${prev}\n${l.body}`);
      }
      if (l.expect && l.expect !== next) { ok = false; detail = `entry ${l.id}: hash doesn't match the entry`; break; }
      prev = next;
    }
    const head = ch.head ?? {};
    step(`${ch.label ?? "Register chain"}: every link recomputed up to the register head`, ok && prev === head.chainHash, detail ?? (ok && prev !== head.chainHash ? "the chain doesn't end at the head" : undefined));
    const hk = byKid.get(head.statement?.kid);
    step(`Register head ${String(head.chainHash ?? "").slice(0, 12)}… is signed by the instance`,
      !!hk && String(head.statement?.text ?? "").includes(head.chainHash) && verifyPair(hk.publicKeys, head.statement.purpose, head.statement.text, head.statement.signature));
  }

  // 5. the manifest itself
  const ps = m.packSignature, pk = byKid.get(ps?.kid);
  const { packSignature: _ignored, ...unsigned } = m;
  step("The pack as a whole is signed by the instance (nothing added or removed)", !!pk && verifyPair(pk.publicKeys, "evidence-pack", sha256(canonical(unsigned)), ps.signature));

  return { ok: steps.every((s) => s.ok), title: String(m.title ?? ""), fingerprint: fingerprints.at(-1) ?? null, fingerprints, steps };
}

/**
 * Keys oldest first. A key with no predecessor starts an identity (it must carry no endorsement); every other key
 * must come after its predecessor and be endorsed by it.
 */
function checkKeyChains(keys) {
  const seen = new Map(), identities = [];
  if (keys.length === 0) return { ok: false, error: "no keys", identities };
  for (const r of keys) {
    if (!recordWellFormed(r)) return { ok: false, error: `key ${r?.kid ?? "?"} is malformed`, identities };
    if (r.prev === null) {
      if (r.endorsement !== null) return { ok: false, error: `key ${r.kid} has no predecessor but carries an endorsement`, identities };
      identities.push(r);
    } else {
      const p = seen.get(r.prev);
      if (!p || !endorsedBy(r, p)) return { ok: false, error: `key ${r.kid} is not endorsed by the key before it`, identities };
    }
    seen.set(r.kid, r);
  }
  return { ok: true, identities };
}

function verifyEd25519Only(publicKeys, purpose, text, sig) {
  try {
    const key = crypto.createPublicKey({ key: Buffer.from(publicKeys.ed25519, "base64"), format: "der", type: "spki" });
    return !!sig && crypto.verify(null, signedBytes(purpose, text), key, Buffer.from(sig, "base64url"));
  } catch {
    return false;
  }
}

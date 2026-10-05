// Copyright 2026 Thakur Ankush Singh (Vaishnavi Consultant)
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { canonical } from "../src/canonical.mjs";
import { readPack, verifyEvidence } from "../src/evidence.mjs";
import { Keystore } from "../src/keystore.mjs";

const sha = (d) => crypto.createHash("sha256").update(d).digest("hex");
const dir = () => fs.mkdtempSync(path.join(os.tmpdir(), "papertrust-ev-"));

/** Build a small but complete pack: one PDF, its signature, a 3-entry chain to a signed head. */
function buildPack() {
  const { keystore } = Keystore.open({ dir: dir(), password: "pw" });
  const pdf = Buffer.from("%PDF-1.7 a signed invoice");
  const files = new Map([["documents/invoice.pdf", pdf]]);
  const sign = (purpose, text) => keystore.sign(purpose, text);
  const file = sign("file", `INV-1\n${sha(pdf)}`);

  // a register: entry 1 belongs to someone else (only its body hash is revealed), entry 2 is ours, entry 3 is old-style
  const bodies = ['{"other":"party"}', '{"code":"INV-1","sha256":"' + sha(pdf) + '"}', '{"later":"entry"}'];
  const genesis = "0".repeat(64);
  const h1 = sha(`${genesis}\n${sha(bodies[0])}`), h2 = sha(`${h1}\n${sha(bodies[1])}`), h3 = sha(`${h2}\n${bodies[2]}`);
  const head = canonical({ chainHash: h3, label: "2026-09", rows: 3 });
  const headSig = sign("register-head", head);

  const manifest = {
    format: "papertrust-evidence", v: 1, title: "Invoice INV-1", createdAt: new Date().toISOString(),
    files: [{ path: "documents/invoice.pdf", sha256: sha(pdf) }],
    keys: keystore.publicChain(),
    claims: [{ label: "PDF signature", purpose: "file", text: "INV-1\n{sha256:documents/invoice.pdf}", kid: file.kid, signature: file.signature }],
    chains: [{
      label: "Register chain", start: genesis,
      links: [{ id: 1, v: 2, bodyHash: sha(bodies[0]) }, { id: 2, v: 2, body: bodies[1], expect: h2 }, { id: 3, v: 1, body: bodies[2] }],
      head: { chainHash: h3, statement: { purpose: "register-head", text: head, kid: headSig.kid, signature: headSig.signature } },
    }],
  };
  const packSig = sign("evidence-pack", crypto.createHash("sha256").update(canonical(manifest)).digest("hex"));
  manifest.packSignature = { kid: packSig.kid, signature: packSig.signature };
  files.set("manifest.json", Buffer.from(JSON.stringify(manifest)));
  return files;
}

test("a complete pack passes every check", () => {
  const r = verifyEvidence(buildPack());
  assert.equal(r.ok, true, JSON.stringify(r.steps.filter((s) => !s.ok)));
  assert.ok(r.fingerprint);
});

test("a changed PDF fails (file check and its signature)", () => {
  const files = buildPack();
  files.set("documents/invoice.pdf", Buffer.from("%PDF-1.7 a changed invoice"));
  const r = verifyEvidence(files);
  assert.equal(r.ok, false);
  assert.ok(r.steps.some((s) => !s.ok && s.label.includes("documents/invoice.pdf")));
  assert.ok(r.steps.some((s) => !s.ok && s.label === "PDF signature"));
});

test("a changed register entry breaks the chain", () => {
  const files = buildPack();
  const m = JSON.parse(files.get("manifest.json").toString());
  m.chains[0].links[1].body = m.chains[0].links[1].body.replace("INV-1", "INV-2");
  files.set("manifest.json", Buffer.from(JSON.stringify(m)));
  const r = verifyEvidence(files);
  assert.equal(r.ok, false);
  assert.ok(r.steps.some((s) => !s.ok && s.label.includes("Register chain")));
});

test("an added file is noticed", () => {
  const files = buildPack();
  files.set("documents/extra.pdf", Buffer.from("smuggled"));
  assert.equal(verifyEvidence(files).ok, false);
});

test("packs can be read from a folder", () => {
  const files = buildPack();
  const d = dir();
  for (const [p, data] of files) { fs.mkdirSync(path.dirname(path.join(d, "Evidence", p)), { recursive: true }); fs.writeFileSync(path.join(d, "Evidence", p), data); }
  assert.equal(verifyEvidence(readPack(path.join(d, "Evidence"))).ok, true);
});

test("keys of a second identity are accepted and named; an unconnected key is not", () => {
  const files = buildPack();
  const m = JSON.parse(files.get("manifest.json").toString());
  const { keystore: other } = Keystore.open({ dir: dir(), password: "pw" });
  const claim = other.sign("facts", "signed by the second identity");
  m.keys = [...m.keys, ...other.publicChain()];
  m.claims.push({ label: "Second identity", purpose: "facts", text: "signed by the second identity", kid: claim.kid, signature: claim.signature });
  // (the pack signature no longer matches after these edits; only the key and claim steps are looked at here)
  const withKeys = (keys) => {
    const mm = { ...m, keys };
    files.set("manifest.json", Buffer.from(JSON.stringify(mm)));
    return verifyEvidence(files);
  };
  const r = withKeys(m.keys);
  assert.equal(r.fingerprints.length, 2);
  assert.ok(r.steps.some((s) => s.ok && s.label.includes("2 valid chains")));
  assert.ok(r.steps.some((s) => s.ok && s.label === "Second identity"));
  const broken = withKeys([...m.keys, { ...other.publicChain()[0], kid: "0000000000000000", prev: "ffffffffffffffff" }]);
  assert.ok(broken.steps.some((s) => !s.ok && s.label.includes("signing keys")));
});

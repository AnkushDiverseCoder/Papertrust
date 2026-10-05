// Copyright 2026 Thakur Ankush Singh (Vaishnavi Consultant)
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { verifyChain } from "../src/keychain.mjs";
import { Keystore, KeystoreError, moveKeystoreAside } from "../src/keystore.mjs";
import { startPapertrust } from "../src/server.mjs";
import { verifyPair } from "../src/signatures.mjs";

const tempDir = () => fs.mkdtempSync(path.join(os.tmpdir(), "papertrust-ks-"));

test("first open creates a genesis key; reopening loads the same key", () => {
  const dir = tempDir();
  const first = Keystore.open({ dir, password: "correct horse battery staple" });
  assert.equal(first.created, true);
  const kid = first.keystore.current().record.kid;
  const again = Keystore.open({ dir, password: "correct horse battery staple" });
  assert.equal(again.created, false);
  assert.equal(again.keystore.current().record.kid, kid);
});

test("the file on disk is encrypted: no key material in plain text", () => {
  const dir = tempDir();
  Keystore.open({ dir, password: "pw-1234567890" });
  const text = fs.readFileSync(path.join(dir, "keystore.json"), "utf8");
  assert.doesNotMatch(text, /PRIVATE KEY/);
  assert.match(text, /"cipher": "aes-256-gcm"/);
});

test("a wrong password is refused with a clear message", () => {
  const dir = tempDir();
  Keystore.open({ dir, password: "right password" });
  assert.throws(() => Keystore.open({ dir, password: "wrong password" }), (e) => e instanceof KeystoreError && /can't be opened/.test(e.message));
});

test("a tampered keystore file is refused", () => {
  const dir = tempDir();
  Keystore.open({ dir, password: "pw" });
  const file = path.join(dir, "keystore.json");
  const json = JSON.parse(fs.readFileSync(file, "utf8"));
  const data = Buffer.from(json.data, "base64");
  data[10] ^= 1;
  json.data = data.toString("base64");
  fs.writeFileSync(file, JSON.stringify(json));
  assert.throws(() => Keystore.open({ dir, password: "pw" }), KeystoreError);
});

test("rotation: new key endorsed by the old one, old private key deleted, old signatures still check", () => {
  const dir = tempDir();
  const { keystore } = Keystore.open({ dir, password: "pw" });
  const old = keystore.current().record;
  const signedBefore = keystore.sign("invoice", "INV-7");
  const next = keystore.rotate();
  assert.equal(next.prev, old.kid);
  assert.deepEqual(verifyChain(keystore.publicChain()), { ok: true });

  const reopened = Keystore.open({ dir, password: "pw" }).keystore;
  assert.equal(reopened.current().record.kid, next.kid);
  assert.equal(reopened.entries.filter((e) => e.privateKeys).length, 1, "only the current key keeps private keys");
  assert.doesNotMatch(fs.readFileSync(path.join(dir, "keystore.json"), "utf8"), new RegExp(old.kid + ".*privateKeys"));
  assert.equal(verifyPair(old.publicKeys, "invoice", "INV-7", signedBefore.signature), true);
  assert.equal(reopened.sign("invoice", "INV-8").kid, next.kid);
});

test("rewrap: re-encrypt with a new password", () => {
  const dir = tempDir();
  const { keystore } = Keystore.open({ dir, password: "old" });
  const kid = keystore.current().record.kid;
  keystore.rewrap("new");
  assert.throws(() => Keystore.open({ dir, password: "old" }), KeystoreError);
  assert.equal(Keystore.open({ dir, password: "new" }).keystore.current().record.kid, kid);
});

test("a keystore with a different password starts in locked mode, explaining how to fix it", async () => {
  const dir = tempDir();
  Keystore.open({ dir, password: "first password" });
  const config = { secret: "s".repeat(40), origins: [], keyPassword: "changed password", keyPasswordSeparate: true, dataDir: dir, rotateDays: 365,
    name: "Locked test", concurrency: 1, chromiumPath: null, port: 0, host: "127.0.0.1" };
  const pt = await startPapertrust(config, { version: "test", log: () => {} });
  try {
    assert.equal(pt.locked, true);
    const page = await fetch(pt.url + "/");
    assert.equal(page.status, 503);
    const html = await page.text();
    assert.match(html, /can't be opened/);
    assert.match(html, /papertrust rewrap/);
    assert.match(html, /new-identity/);
    assert.match(html, /The keystore it found/, "describes the keystore it found");
    const health = await fetch(pt.url + "/health");
    assert.equal(health.status, 503);
    assert.equal((await health.json()).locked, true);
    const sign = await fetch(pt.url + "/v1/sign", { method: "POST", body: "{}" });
    assert.equal(sign.status, 503);
  } finally {
    await pt.close();
  }
});

test("new-identity: the old keystore is moved aside (kept) and the next open makes a new identity", () => {
  const dir = tempDir();
  const old = Keystore.open({ dir, password: "first" }).keystore.current().record.kid;
  const aside = moveKeystoreAside(dir);
  assert.ok(aside && fs.existsSync(aside), "old file kept");
  const fresh = Keystore.open({ dir, password: "second" });
  assert.equal(fresh.created, true);
  assert.notEqual(fresh.keystore.current().record.kid, old);
});

test("the keystore file carries a public summary (key ids and dates) but no secrets", () => {
  const dir = tempDir();
  const { keystore } = Keystore.open({ dir, password: "pw" });
  const file = JSON.parse(fs.readFileSync(path.join(dir, "keystore.json"), "utf8"));
  assert.equal(file.public.keys[0].kid, keystore.current().record.kid);
  assert.doesNotMatch(JSON.stringify(file.public), /PRIVATE|publicKeys/);
});

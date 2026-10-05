// Copyright 2026 Thakur Ankush Singh (Vaishnavi Consultant)
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { canonical } from "../src/canonical.mjs";
import { extendTrust, makeRecord, verifyChain } from "../src/keychain.mjs";
import { generateKeys, keyId, postQuantumAvailable, signPair, verifyPair } from "../src/signatures.mjs";

const pair = () => { const k = generateKeys(); return { privateKeys: { ed25519: k.ed25519, mldsa65: k.mldsa65 }, publicKeys: k.publicKeys }; };

test("this Node.js supports ML-DSA-65", () => {
  assert.equal(postQuantumAvailable(), true);
});

test("canonical JSON sorts keys at every depth and drops undefined", () => {
  assert.equal(canonical({ b: 1, a: { d: [3, { z: 1, y: 2 }], c: undefined } }), '{"a":{"d":[3,{"y":2,"z":1}]},"b":1}');
  assert.equal(canonical(null), "null");
  assert.equal(canonical("x"), '"x"');
});

test("a signature pair verifies, and fails on any change", () => {
  const k = pair();
  const sig = signPair(k.privateKeys, "invoice", "INV-1 total 1000.00");
  assert.equal(verifyPair(k.publicKeys, "invoice", "INV-1 total 1000.00", sig), true);
  assert.equal(verifyPair(k.publicKeys, "invoice", "INV-1 total 1000.01", sig), false, "changed text");
  assert.equal(verifyPair(k.publicKeys, "letter", "INV-1 total 1000.00", sig), false, "other purpose");
  assert.equal(verifyPair(pair().publicKeys, "invoice", "INV-1 total 1000.00", sig), false, "other key");
});

test("both algorithms are required", () => {
  const k = pair();
  const sig = signPair(k.privateKeys, "invoice", "x");
  assert.equal(verifyPair(k.publicKeys, "invoice", "x", { ed25519: sig.ed25519 }), false, "missing ML-DSA");
  assert.equal(verifyPair(k.publicKeys, "invoice", "x", { mldsa65: sig.mldsa65 }), false, "missing Ed25519");
  const other = signPair(pair().privateKeys, "invoice", "x");
  assert.equal(verifyPair(k.publicKeys, "invoice", "x", { ed25519: sig.ed25519, mldsa65: other.mldsa65 }), false, "foreign ML-DSA half");
  assert.equal(verifyPair(k.publicKeys, "invoice", "x", { ed25519: other.ed25519, mldsa65: sig.mldsa65 }), false, "foreign Ed25519 half");
});

test("garbage never throws, it is just invalid", () => {
  const k = pair();
  assert.equal(verifyPair(k.publicKeys, "invoice", "x", null), false);
  assert.equal(verifyPair(k.publicKeys, "invoice", "x", { ed25519: "!!", mldsa65: "??" }), false);
  assert.equal(verifyPair({ ed25519: "bm9wZQ==", mldsa65: "bm9wZQ==" }, "invoice", "x", { ed25519: "a", mldsa65: "b" }), false);
  assert.equal(verifyPair(k.publicKeys, "Bad Purpose", "x", { ed25519: "a", mldsa65: "b" }), false);
});

test("key chain: endorsements carry trust forward, strangers are left out", () => {
  const a = pair(), b = pair(), c = pair(), mallory = pair();
  const ra = makeRecord(a.publicKeys);
  const rb = makeRecord(b.publicKeys, { record: ra, privateKeys: a.privateKeys });
  const rc = makeRecord(c.publicKeys, { record: rb, privateKeys: b.privateKeys });
  assert.equal(ra.kid, keyId(a.publicKeys));
  assert.deepEqual(verifyChain([ra, rb, rc]), { ok: true });

  // someone appends their own key claiming to follow c, endorsed by their own key
  const fake = makeRecord(mallory.publicKeys, { record: { ...rc }, privateKeys: mallory.privateKeys });
  assert.equal(verifyChain([ra, rb, rc, fake]).ok, false);
  assert.deepEqual(extendTrust([ra.kid], [ra, rb, rc, fake]).map((r) => r.kid), [ra.kid, rb.kid, rc.kid]);

  // trusting only a later key does not make earlier keys trusted
  assert.deepEqual(extendTrust([rb.kid], [ra, rb, rc]).map((r) => r.kid), [rb.kid, rc.kid]);

  // a record whose public key was swapped no longer matches its kid
  const swapped = { ...rb, publicKeys: mallory.publicKeys };
  assert.equal(verifyChain([ra, swapped]).ok, false);
});

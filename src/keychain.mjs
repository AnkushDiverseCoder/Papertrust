// Copyright 2026 Thakur Ankush Singh (Vaishnavi Consultant)
// SPDX-License-Identifier: Apache-2.0

import { canonical } from "./canonical.mjs";
import { keyId, SCHEME, signPair, verifyPair } from "./signatures.mjs";

/**
 * The key chain: the public history of every key a Papertrust instance has used.
 *
 * Papertrust has no central authority and no master key held by a person. Instead:
 *
 *   1. On first start, an instance makes its first key (the "genesis" key). Whoever relies on the instance
 *      trusts that key once, by its fingerprint, the same way you trust an SSH host key the first time.
 *   2. When the key is replaced (automatically, every year by default), the OLD key signs the NEW key's
 *      record. That signature is the "endorsement".
 *   3. Anyone who trusted any earlier key can follow the endorsements forward and trust the new key too,
 *      without asking anybody. A key that is not endorsed by a trusted key is not trusted.
 *
 * Old private keys are destroyed after a rotation; their public records stay in the chain forever, so every
 * document signed in the past can still be checked.
 *
 * A key record (public, safe to publish anywhere):
 *
 *   {
 *     v: 1,
 *     kid: "3f9a0c…",                 // keyId() of the public keys
 *     scheme: "ed25519+ml-dsa-65",
 *     publicKeys: { ed25519, mldsa65 },  // base64 SPKI
 *     createdAt: "2026-10-05T10:00:00.000Z",
 *     prev: null | "<kid of the key before>",
 *     endorsement: null | { ed25519, mldsa65 }   // signature pair by `prev` over the record without this field
 *   }
 */

/** The text a previous key signs to endorse `record` (the record without its endorsement). */
export function endorsementText(record) {
  const { endorsement: _ignored, ...body } = record;
  return canonical(body);
}

/**
 * Build the public record for a new key. When `previous` is given ({ record, privateKeys }), the new record is
 * endorsed by it; otherwise this is a genesis key.
 */
export function makeRecord(publicKeys, previous = null, createdAt = new Date().toISOString()) {
  const record = { v: 1, kid: keyId(publicKeys), scheme: SCHEME, publicKeys, createdAt, prev: previous?.record.kid ?? null, endorsement: null };
  if (previous) record.endorsement = signPair(previous.privateKeys, "key", endorsementText(record));
  return record;
}

/** Is this record internally consistent (right shape, kid matches its public keys)? Says nothing about trust. */
export function recordWellFormed(record) {
  return !!record && record.v === 1 && record.scheme === SCHEME
    && typeof record.publicKeys?.ed25519 === "string" && typeof record.publicKeys?.mldsa65 === "string"
    && typeof record.kid === "string" && record.kid === keyId(record.publicKeys)
    && typeof record.createdAt === "string" && !Number.isNaN(Date.parse(record.createdAt));
}

/** Was `record` endorsed by `endorser` (another record)? */
export function endorsedBy(record, endorser) {
  return record.prev === endorser.kid && verifyPair(endorser.publicKeys, "key", endorsementText(record), record.endorsement);
}

/**
 * Check a whole chain as published by an instance (oldest first): a genesis key, then each key endorsed by
 * the one before it.
 * @returns {{ ok: true } | { ok: false, error: string }}
 */
export function verifyChain(records) {
  if (!Array.isArray(records) || records.length === 0) return { ok: false, error: "the chain is empty" };
  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    if (!recordWellFormed(r)) return { ok: false, error: `key #${i + 1} is malformed` };
    if (i === 0) {
      if (r.prev !== null || r.endorsement !== null) return { ok: false, error: "the first key must be a genesis key" };
    } else if (!endorsedBy(r, records[i - 1])) {
      return { ok: false, error: `key ${r.kid} is not endorsed by the key before it` };
    }
  }
  return { ok: true };
}

/**
 * Extend trust along a published chain.
 *
 * Give the kids you already trust and the records an instance publishes; get back every record you can now
 * trust: the ones you already trusted, plus each later key endorsed by a trusted key. Keys that do not
 * connect to anything you trust are left out.
 *
 * @param {Iterable<string>} trustedKids
 * @param {object[]} records oldest first
 * @returns {object[]} trusted records, oldest first
 */
export function extendTrust(trustedKids, records) {
  const trusted = new Map();
  const known = new Set(trustedKids);
  for (const r of records) {
    if (!recordWellFormed(r)) continue;
    if (known.has(r.kid)) { trusted.set(r.kid, r); continue; }
    const endorser = r.prev ? trusted.get(r.prev) : null;
    if (endorser && endorsedBy(r, endorser)) { trusted.set(r.kid, r); known.add(r.kid); }
  }
  return [...trusted.values()];
}

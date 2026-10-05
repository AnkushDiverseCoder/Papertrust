// Copyright 2026 Thakur Ankush Singh (Vaishnavi Consultant)
// SPDX-License-Identifier: Apache-2.0

import crypto from "node:crypto";

/**
 * Signature pairs.
 *
 * Every message Papertrust signs is signed twice, by two independent algorithms:
 *
 *   ed25519    Fast, small (64-byte signatures), widely trusted. Secure against every computer that exists today.
 *   ml-dsa-65  Post-quantum (NIST FIPS 204, 2024). Stays secure even against a future large quantum computer,
 *              which could break Ed25519.
 *
 * A signature pair is valid only when BOTH signatures are valid, so forging one means breaking both
 * algorithms at once.
 *
 * Domain separation: the signed bytes are always
 *
 *     papertrust/v1/<purpose> + "\n" + <text>
 *
 * so a signature made for one purpose (say "invoice-facts") can never be replayed as a signature for
 * another (say "key"). Purposes are short lowercase names chosen by the calling application.
 */

export const SCHEME = "ed25519+ml-dsa-65";

/** Lowercase letters, digits and dashes; starts with a letter; at most 32 characters. */
export const PURPOSE_RE = /^[a-z][a-z0-9-]{0,31}$/;

/** Purposes Papertrust uses itself. Applications cannot request these through /v1/sign. */
export const RESERVED_PURPOSES = new Set(["key", "file"]);

/** The exact bytes that get signed for `purpose` and `text`. */
export function signedBytes(purpose, text) {
  if (!PURPOSE_RE.test(purpose)) throw new TypeError(`invalid purpose "${purpose}"`);
  return Buffer.from(`papertrust/v1/${purpose}\n${text}`, "utf8");
}

const b64url = (buf) => Buffer.from(buf).toString("base64url");

/**
 * Make a fresh key pair for both algorithms.
 * @returns {{ ed25519: crypto.KeyObject, mldsa65: crypto.KeyObject, publicKeys: { ed25519: string, mldsa65: string } }}
 *   private keys as KeyObjects, public keys as base64 SPKI (DER)
 */
export function generateKeys() {
  const ed = crypto.generateKeyPairSync("ed25519");
  const pq = crypto.generateKeyPairSync("ml-dsa-65");
  return {
    ed25519: ed.privateKey,
    mldsa65: pq.privateKey,
    publicKeys: {
      ed25519: ed.publicKey.export({ type: "spki", format: "der" }).toString("base64"),
      mldsa65: pq.publicKey.export({ type: "spki", format: "der" }).toString("base64"),
    },
  };
}

/**
 * Key id: the first 16 hex characters of SHA-256 over both public keys (Ed25519 SPKI bytes, then ML-DSA SPKI bytes).
 * Short enough to print on a document, long enough that two keys never collide in practice.
 */
export function keyId(publicKeys) {
  return fingerprint(publicKeys).slice(0, 16);
}

/** Full SHA-256 fingerprint of a key's two public keys, as 64 hex characters. Compare this to trust a key by hand. */
export function fingerprint(publicKeys) {
  return crypto.createHash("sha256")
    .update(Buffer.from(publicKeys.ed25519, "base64"))
    .update(Buffer.from(publicKeys.mldsa65, "base64"))
    .digest("hex");
}

/** A fingerprint in groups of four, easier to read aloud or compare on two screens. */
export const groupFingerprint = (hex) => hex.toUpperCase().match(/.{1,4}/g).join(" ");

/**
 * Sign `text` for `purpose` with both private keys.
 * @returns {{ ed25519: string, mldsa65: string }} base64url signatures
 */
export function signPair(privateKeys, purpose, text) {
  const bytes = signedBytes(purpose, text);
  return {
    ed25519: b64url(crypto.sign(null, bytes, privateKeys.ed25519)),
    mldsa65: b64url(crypto.sign(null, bytes, privateKeys.mldsa65)),
  };
}

// Parsing a public key is relatively slow (ML-DSA keys are about 2 KB); verification calls repeat a lot.
const publicKeyCache = new Map();
function publicKeyObject(b64) {
  let key = publicKeyCache.get(b64);
  if (!key) {
    key = crypto.createPublicKey({ key: Buffer.from(b64, "base64"), format: "der", type: "spki" });
    if (publicKeyCache.size > 256) publicKeyCache.clear();
    publicKeyCache.set(b64, key);
  }
  return key;
}

/**
 * Check a signature pair. True only when both signatures are valid for these public keys.
 * Never throws: malformed input is simply invalid.
 *
 * @param {{ ed25519: string, mldsa65: string }} publicKeys base64 SPKI
 * @param {string} purpose
 * @param {string} text
 * @param {{ ed25519?: string, mldsa65?: string } | null | undefined} signature base64url
 */
export function verifyPair(publicKeys, purpose, text, signature) {
  try {
    if (!signature?.ed25519 || !signature?.mldsa65) return false;
    const bytes = signedBytes(purpose, text);
    const edKey = publicKeyObject(publicKeys.ed25519), pqKey = publicKeyObject(publicKeys.mldsa65);
    if (edKey.asymmetricKeyType !== "ed25519" || pqKey.asymmetricKeyType !== "ml-dsa-65") return false;
    return crypto.verify(null, bytes, edKey, Buffer.from(signature.ed25519, "base64url"))
      && crypto.verify(null, bytes, pqKey, Buffer.from(signature.mldsa65, "base64url"));
  } catch {
    return false;
  }
}

/** True when this Node.js build can make and check ML-DSA-65 signatures (Node 24 with OpenSSL 3.5 or newer). */
export function postQuantumAvailable() {
  try {
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ml-dsa-65");
    const sig = crypto.sign(null, Buffer.from("self-test"), privateKey);
    return crypto.verify(null, Buffer.from("self-test"), publicKey, sig);
  } catch {
    return false;
  }
}

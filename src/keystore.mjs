// Copyright 2026 Thakur Ankush Singh (Vaishnavi Consultant)
// SPDX-License-Identifier: Apache-2.0

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { makeRecord, verifyChain } from "./keychain.mjs";
import { generateKeys, signPair } from "./signatures.mjs";

/**
 * The keystore: this instance's keys, kept in one encrypted file (`keystore.json` in the data directory).
 *
 * File format (JSON):
 *
 *   {
 *     "format": "papertrust-keystore", "v": 1,
 *     "kdf":    { "name": "scrypt", "salt": <base64>, "N": 32768, "r": 8, "p": 1 },
 *     "cipher": "aes-256-gcm", "iv": <base64>, "tag": <base64>,
 *     "data":   <base64 ciphertext>
 *   }
 *
 * Next to the encrypted part the file keeps a small PUBLIC summary ("public": the key ids, when each key was made,
 * when the file was last saved). It holds nothing secret and is only used to describe a keystore that can't be
 * opened, so the operator can tell which keystore it is.
 *
 * The decrypted data is { keys: [{ record, privateKeys?: { ed25519, mldsa65 } }] }, oldest first. Only the
 * CURRENT key keeps its private keys (PKCS#8 PEM). When a key is rotated out, its private keys are deleted
 * and only its public record stays, so a stolen old backup can't sign anything new once rotation happened.
 *
 * The encryption key is derived with scrypt from the keystore password. A copy of the file alone, without the
 * password, is useless. Writes go to a temporary file first and are then renamed into place, so a crash never
 * leaves a half-written keystore.
 */

const SCRYPT = { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

/** A keystore problem. `details` describes the keystore file that was found (when there is one). */
export class KeystoreError extends Error {
  constructor(message, details = null) {
    super(message);
    /** @type {{ file: string, modifiedAt: string, keys: { kid: string, createdAt: string }[] | null } | null} */
    this.details = details;
  }
}

export const KEYSTORE_FILE = "keystore.json";

/** What can be said about a keystore file without its password. */
export function describeKeystoreFile(dir) {
  const file = path.join(dir, KEYSTORE_FILE);
  try {
    const stat = fs.statSync(file);
    let keys = null;
    try { keys = JSON.parse(fs.readFileSync(file, "utf8")).public?.keys ?? null; } catch { /* unreadable: just the date */ }
    return { file, modifiedAt: stat.mtime.toISOString(), keys };
  } catch {
    return null;
  }
}

/**
 * Move the keystore aside (never deleted) so the next start creates a new identity. Returns the new file name.
 * The old file stays next to it: with its password it can still be restored later.
 */
export function moveKeystoreAside(dir) {
  const file = path.join(dir, KEYSTORE_FILE);
  if (!fs.existsSync(file)) return null;
  const aside = path.join(dir, `keystore.replaced-${new Date().toISOString().replace(/[:.]/g, "-")}.json`);
  fs.renameSync(file, aside);
  return aside;
}

function deriveKey(password, salt, kdf = SCRYPT) {
  return crypto.scryptSync(password, salt, 32, { N: kdf.N, r: kdf.r, p: kdf.p, maxmem: SCRYPT.maxmem });
}

function encrypt(password, plain) {
  const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", deriveKey(password, salt), iv);
  const data = Buffer.concat([cipher.update(JSON.stringify(plain), "utf8"), cipher.final()]);
  return {
    format: "papertrust-keystore", v: 1,
    kdf: { name: "scrypt", salt: salt.toString("base64"), N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p },
    cipher: "aes-256-gcm", iv: iv.toString("base64"), tag: cipher.getAuthTag().toString("base64"), data: data.toString("base64"),
  };
}

function decrypt(password, file, dir) {
  if (file?.format !== "papertrust-keystore" || file.v !== 1 || file.kdf?.name !== "scrypt" || file.cipher !== "aes-256-gcm") {
    throw new KeystoreError("keystore.json is not a Papertrust keystore (or is from a newer version)", describeKeystoreFile(dir));
  }
  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", deriveKey(password, Buffer.from(file.kdf.salt, "base64"), file.kdf), Buffer.from(file.iv, "base64"));
    decipher.setAuthTag(Buffer.from(file.tag, "base64"));
    return JSON.parse(Buffer.concat([decipher.update(Buffer.from(file.data, "base64")), decipher.final()]).toString("utf8"));
  } catch {
    throw new KeystoreError(
      "The keystore can't be opened with this password. If PAPERTRUST_KEY_PASSWORD or PAPERTRUST_SECRET was changed, "
      + "put the old value back, or re-encrypt the keystore with `papertrust rewrap` (see README).",
      describeKeystoreFile(dir),
    );
  }
}

function writeAtomic(file, content) {
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, content, { mode: 0o600 });
  fs.renameSync(tmp, file);
}

const loadPrivate = (pem) => crypto.createPrivateKey(pem);
const exportPrivate = (key) => key.export({ type: "pkcs8", format: "pem" });

export class Keystore {
  /** @private use Keystore.open() */
  constructor(dir, password, entries) {
    this.dir = dir;
    this.password = password;
    this.entries = entries; // [{ record, privateKeys?: { ed25519: KeyObject, mldsa65: KeyObject } }]
  }

  /**
   * Open the keystore in `dir`, creating it (with a new genesis key) on first start.
   * @param {{ dir: string, password: string }} options
   * @returns {{ keystore: Keystore, created: boolean }}
   */
  static open({ dir, password }) {
    if (!password) throw new KeystoreError("a keystore password is required");
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const file = path.join(dir, KEYSTORE_FILE);
    if (!fs.existsSync(file)) {
      const ks = new Keystore(dir, password, []);
      ks.#addKey();
      return { keystore: ks, created: true };
    }
    let parsed;
    try {
      parsed = JSON.parse(fs.readFileSync(file, "utf8"));
    } catch {
      throw new KeystoreError(`${file} can't be read as JSON. Restore it from a backup; do not delete it unless you mean to start a brand-new identity.`);
    }
    const plain = decrypt(password, parsed, dir);
    const entries = (plain.keys ?? []).map((k) => ({
      record: k.record,
      privateKeys: k.privateKeys ? { ed25519: loadPrivate(k.privateKeys.ed25519), mldsa65: loadPrivate(k.privateKeys.mldsa65) } : undefined,
    }));
    const ks = new Keystore(dir, password, entries);
    const check = verifyChain(ks.publicChain());
    if (!check.ok) throw new KeystoreError(`the keystore's key chain is broken: ${check.error}`);
    if (!ks.current().privateKeys) throw new KeystoreError("the keystore has no private key for its current key");
    return { keystore: ks, created: false };
  }

  /** The key used for signing now: { record, privateKeys }. */
  current() {
    return this.entries[this.entries.length - 1];
  }

  /** Every public key record, oldest first. Safe to publish. */
  publicChain() {
    return this.entries.map((e) => e.record);
  }

  /** Sign `text` for `purpose` with the current key. */
  sign(purpose, text) {
    const { record, privateKeys } = this.current();
    return { kid: record.kid, signature: signPair(privateKeys, purpose, text) };
  }

  /** How many days the current key has been in use. */
  currentAgeDays(now = Date.now()) {
    return (now - Date.parse(this.current().record.createdAt)) / 86_400_000;
  }

  /**
   * Replace the current key with a new one endorsed by it, then forget the old private keys.
   * @returns {object} the new key's public record
   */
  rotate() {
    return this.#addKey();
  }

  /** Re-encrypt the keystore with a different password (used by `papertrust rewrap`). */
  rewrap(newPassword) {
    if (!newPassword) throw new KeystoreError("a new password is required");
    this.password = newPassword;
    this.#save();
  }

  #addKey() {
    const fresh = generateKeys();
    const previous = this.entries.length ? this.current() : null;
    const record = makeRecord(fresh.publicKeys, previous ? { record: previous.record, privateKeys: previous.privateKeys } : null);
    const before = this.entries;
    // the old key's private half is no longer needed once it has endorsed its successor
    this.entries = [...before.map((e) => ({ record: e.record })), { record, privateKeys: { ed25519: fresh.ed25519, mldsa65: fresh.mldsa65 } }];
    try {
      this.#save();
    } catch (e) {
      this.entries = before;
      throw e;
    }
    return record;
  }

  #save() {
    const plain = {
      keys: this.entries.map((e) => ({
        record: e.record,
        ...(e.privateKeys ? { privateKeys: { ed25519: exportPrivate(e.privateKeys.ed25519), mldsa65: exportPrivate(e.privateKeys.mldsa65) } } : {}),
      })),
    };
    const summary = { keys: this.entries.map((e) => ({ kid: e.record.kid, createdAt: e.record.createdAt })), savedAt: new Date().toISOString() };
    writeAtomic(path.join(this.dir, KEYSTORE_FILE), JSON.stringify({ ...encrypt(this.password, plain), public: summary }, null, 2));
  }
}

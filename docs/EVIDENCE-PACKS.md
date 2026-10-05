# Evidence packs

An **evidence pack** is a ZIP file (or a folder) that an application gives to a lawyer, a court, an auditor or anyone in a dispute, so that an independent expert can check its documents **without trusting or even contacting** the application or its Papertrust instance.

Anyone can check a pack with one command, offline:

```bash
npx github:AnkushDiverseCoder/Papertrust verify-pack "Evidence INV-1.zip"
```

```
Papertrust evidence check 1.5.0

  Invoice INV-1: Example Traders

  PASS  The pack is a Papertrust evidence pack (format v1)
  PASS  File documents/invoice.pdf is present and unchanged
  PASS  No unlisted files were added
  PASS  The signing keys form a valid chain (each key endorsed by the one before)
  PASS  PDF signature
  PASS  Register chain: every link recomputed up to the register head
  PASS  Register head 3fa1c09e2b7d… is signed by the instance
  PASS  The pack as a whole is signed by the instance (nothing added or removed)

  Identity of the signer (first key fingerprint):
  95DB 3707 8AFE D0C4 66AB B8C9 F6D8 DBF5 3DE5 D1EE DDEC 9D1E F0B7 7E90 2264 C81C
  Compare it with an independent source: the issuer's status page, its published statements, or an earlier pack.

  RESULT: every check passed — the documents are exactly as the issuer registered them
```

The command exits with `0` when every check passes and `1` otherwise, so it can be scripted. The same check is available as a library function: `verifyEvidence(readPack(path))` from `papertrust`.

This page describes the format, so that any application can produce packs and anyone can write a verifier in another language.

---

## What a pack proves

| Question | How the pack answers it |
| --- | --- |
| Is this the exact file the issuer signed? | The file's SHA-256 is in a signed claim; any change, even one pixel, gives a different SHA-256. |
| Was it signed by *this* issuer? | Every signature is checked against the issuer's public keys; the keys form a chain back to one identity, whose fingerprint can be compared with an independent source. |
| Could the issuer have rewritten its records later? | The document's records are linked into the application's append-only, hash-chained register, up to a **register head** that the application published to others (for example in signed monthly statements to its customers). A rewritten register can't reach the same head again, and the copies held by others would show it. |
| Was anything added to or removed from the pack? | `manifest.json` lists every file with its SHA-256 and is itself signed. |

A pack does **not** prove that a document's *contents* are true, only that they are exactly what the issuer registered and when.

---

## Layout

```
Evidence INV-1/              a single top-level folder is optional; the verifier unwraps it
├── manifest.json            required: what to check (below)
├── documents/…              the files themselves (any names; all listed in the manifest)
└── …                        anything else the application adds: register extracts, guides, certificates
```

Every file except `manifest.json` must be listed in the manifest. An unlisted file fails the check.

---

## manifest.json

```json
{
  "format": "papertrust-evidence",
  "v": 1,
  "title": "Invoice INV-1: Example Traders",
  "createdAt": "2026-10-06T05:30:00.000Z",
  "files":  [ { "path": "documents/invoice.pdf", "sha256": "6016c78…" } ],
  "keys":   [ { "v": 1, "kid": "95db37078afed0c4", "prev": null, "publicKeys": { … }, "endorsement": null, … } ],
  "claims": [ … ],
  "chains": [ … ],
  "packSignature": { "kid": "a88f589f54a0963a", "signature": { "ed25519": "…", "mldsa65": "…" } }
}
```

Applications may add other fields (the verifier ignores them, but they are covered by the pack signature).

### files

Every file in the pack with its SHA-256 (lowercase hex). The verifier recomputes each one.

### keys

Public key records exactly as the instance publishes them at `GET /v1/keys`, **oldest first**. A key with `prev: null` starts an identity and carries no endorsement; every other key must come after its predecessor and be endorsed by it.

Usually there is one identity. If the instance's owner ever started a new identity (after losing a keystore), the keys of both appear and the verifier reports every identity's fingerprint, so the reader can see it and ask why.

The **fingerprint** of an identity is the SHA-256 of its first key's public keys (see [Trust model](../README.md#trust-model)). It is what a reader compares with an independent source.

### claims

"This text was signed for this purpose by this key." Each claim:

```json
{ "label": "PDF signature", "purpose": "file", "text": "INV-1\n{sha256:documents/invoice.pdf}", "kid": "a88f589f54a0963a",
  "signature": { "ed25519": "…", "mldsa65": "…" } }
```

- `text` may contain `{sha256:<path>}`, which the verifier replaces with the SHA-256 of that file **in the pack**. This ties a signature over a fingerprint to the actual file handed over.
- Both signatures must verify (Ed25519 and ML-DSA-65), using the domain-separated message `papertrust/v1/<purpose>\n<text>`.
- `ed25519Only: true` checks the Ed25519 signature alone (for short codes that only carry one, such as a QR code).
- `label` is shown in the report; make it meaningful to a non-expert.

### chains

Hash chains from an application's append-only register: from the pack's documents up to a register head.

```json
{
  "label": "Register chain",
  "start": "<the hash before the first link>",
  "links": [ … ],
  "head": { "chainHash": "…", "label": "Checkpoint 2026-09",
            "statement": { "purpose": "register-head", "text": "…", "kid": "…", "signature": { … } } }
}
```

Starting from `start`, each link gives the next hash:

| Link | Next hash | Use |
| --- | --- | --- |
| `{ "v": 2, "body": "…" }` | `SHA-256(prev + "\n" + SHA-256(body))` | the pack's own entries, shown in full |
| `{ "v": 2, "bodyHash": "…" }` | `SHA-256(prev + "\n" + bodyHash)` | other parties' entries, without revealing their content |
| `{ "body": "…" }` (no `v`, or `v: 1`) | `SHA-256(prev + "\n" + body)` | older entries made before v2 |
| `{ "prev": "…", "chain": "…", "kid": "…", "signature": { … } }` | `chain` | entries that can be neither recomputed nor revealed (an old-style entry of another party): the instance's `chain` signature over the hash vouches for it, and `prev` must equal the hash so far |

A link may carry `expect`, the hash the application stored for that entry; the verifier checks it matches.

The final hash must equal `head.chainHash`, and the head's `statement` must be signed by one of the pack's keys and contain `chainHash`. The statement's format is up to the application; Papertrust only checks the signature and that the hash appears in it.

**Why v2.** With v1 links, proving the chain from one entry to the head means revealing every later entry in full, other parties' included. With v2, an entry's body is hashed first, so a pack can show other entries by their body hash alone. Applications should write v2 for new entries.

**Where a head should come from.** A head is strongest when others hold it, independently of the issuer: a signed statement sent to every customer each month, a value printed in a newspaper notice, a copy filed with an auditor. Then even the issuer can't quietly rewrite its register: the head held by others would no longer be reachable. A head signed only at the moment the pack was made proves the chain is intact up to that moment, and is witnessed once the application next publishes a head that includes it.

### packSignature

A signature (purpose `evidence-pack`) by one of the pack's keys over the **SHA-256 (lowercase hex) of the canonical JSON** of the manifest without the `packSignature` field. The hash is signed rather than the manifest itself because a manifest can be far larger than a signing request may be (`POST /v1/sign` takes at most 16,000 characters).

Canonical JSON: object keys sorted, no whitespace, `undefined` dropped (see [`src/canonical.mjs`](../src/canonical.mjs)).

---

## Making packs from your application

1. Keep the evidence when you sign: the file's SHA-256 and its signature, the key id, and your register entry (body, previous hash, chain hash and its signature).
2. Publish register heads to people who keep them: for example, sign `{"label":"2026-09","chainHash":"…","rowId":…}` with purpose `register-head` at every month end and send each customer a statement that carries it.
3. To make a pack: collect the files, the claims, the register links from the document's first entry to a published head, the key records (`GET /v1/keys`) for every key used, then sign the SHA-256 of the canonical manifest with purpose `evidence-pack`.
4. Add guides for people: what the pack is, how to check it, and any certificate your courts expect. In India, for example, a certificate under Section 63 of the Bharatiya Sakshya Adhiniyam, 2023, with the files' SHA-256 values.
5. Check every pack you make with `papertrust verify-pack` in your tests.

`register-head` and `evidence-pack` are ordinary purposes: any application can use them with `POST /v1/sign`.

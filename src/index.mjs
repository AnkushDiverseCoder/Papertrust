// Copyright 2026 Thakur Ankush Singh (Vaishnavi Consultant)
// SPDX-License-Identifier: Apache-2.0

/**
 * Papertrust as a library: everything an application needs to TALK to a Papertrust instance and to CHECK its
 * signatures, without running the service itself.
 *
 *   import { signRequest, extendTrust, verifyPair } from "papertrust";
 *
 * Typical flow in your application:
 *   1. Call POST /v1/sign or /v1/render with headers from signRequest().
 *   2. Store what comes back (kid + signature) next to your document.
 *   3. Fetch GET /v1/keys once, pin the first key's fingerprint, and keep the trusted records (extendTrust).
 *   4. To verify later: find the record for the kid and call verifyPair(record.publicKeys, purpose, text, signature).
 */

export { canonical } from "./canonical.mjs";
export { signRequest, TIME_HEADER, SIGNATURE_HEADER } from "./auth.mjs";
export { verifyPair, fingerprint, groupFingerprint, keyId, signedBytes, SCHEME, PURPOSE_RE } from "./signatures.mjs";
export { verifyChain, extendTrust, endorsedBy, recordWellFormed, endorsementText } from "./keychain.mjs";

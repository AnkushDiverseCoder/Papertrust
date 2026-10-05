// Copyright 2026 Thakur Ankush Singh (Vaishnavi Consultant)
// SPDX-License-Identifier: Apache-2.0

/**
 * Canonical JSON: the same value always becomes the same text, byte for byte.
 *
 * Signatures are made over text, so two programs that want to agree on a signature must turn a JSON value
 * into exactly the same string. Plain JSON.stringify does not guarantee that (key order follows insertion
 * order), so this function:
 *   - sorts object keys alphabetically, at every depth;
 *   - drops keys whose value is `undefined` (as JSON.stringify does);
 *   - writes no whitespace.
 *
 * Arrays keep their order. Numbers, strings, booleans and null are written as JSON.stringify writes them.
 *
 * If you verify Papertrust signatures from another language, implement exactly these rules.
 *
 * @param {unknown} value
 * @returns {string}
 */
export function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value ?? null);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
}

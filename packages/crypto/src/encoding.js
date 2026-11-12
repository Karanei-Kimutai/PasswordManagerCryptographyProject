/**
 * @file encoding.js
 *
 * Conversions between strings, bytes and Base64, plus a canonical JSON
 * serializer.
 *
 * This is the successor of the coursework's `lib.js`. The original relied on
 * Node's `Buffer`, which does not exist in browsers. Everything here uses only
 * web-standard globals (`TextEncoder`, `TextDecoder`, `btoa`, `atob`,
 * `crypto.getRandomValues`), which Node.js 20+ also provides. The same file
 * therefore runs in the browser (the real app) and in Node (the tests and the
 * server).
 *
 * Why Base64? SubtleCrypto works on raw bytes, but JSON and object keys need
 * strings. Base64 is the bridge: every IV, ciphertext, salt and MAC tag is
 * stored as a Base64 string in the serialized vault.
 */

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

/**
 * Encodes a JavaScript string as UTF-8 bytes.
 *
 * Note that `string.length` counts UTF-16 code units, not bytes: "é" has
 * length 1 but encodes to 2 bytes, and an emoji has length 2 but encodes to 4.
 * All size limits in the crypto layer are therefore enforced on the output of
 * this function, never on `string.length`.
 *
 * @param {string} text
 * @returns {Uint8Array}
 */
export function stringToBytes(text) {
  return textEncoder.encode(text);
}

/**
 * Decodes UTF-8 bytes back into a string. Uses a *fatal* decoder, so malformed
 * UTF-8 throws instead of silently producing replacement characters.
 *
 * @param {BufferSource} bytes
 * @returns {string}
 */
export function bytesToString(bytes) {
  return textDecoder.decode(bytes);
}

/**
 * Encodes bytes as standard Base64 (with padding).
 *
 * `btoa` only accepts "binary strings" (one character per byte), so we build
 * one first. We build it in a loop rather than with
 * `String.fromCharCode(...bytes)` because spreading a large array can overflow
 * the call stack.
 *
 * @param {BufferSource} bytes
 * @returns {string}
 */
export function bytesToBase64(bytes) {
  const byteArray = toUint8Array(bytes);
  let binaryString = "";
  for (let index = 0; index < byteArray.length; index++) {
    binaryString += String.fromCharCode(byteArray[index]);
  }
  return btoa(binaryString);
}

/**
 * Decodes a standard Base64 string into bytes. Throws on invalid input.
 *
 * @param {string} base64Text
 * @returns {Uint8Array}
 */
export function base64ToBytes(base64Text) {
  if (typeof base64Text !== "string") {
    throw new TypeError("Expected a Base64 string");
  }
  const binaryString = atob(base64Text);
  const byteArray = new Uint8Array(binaryString.length);
  for (let index = 0; index < binaryString.length; index++) {
    byteArray[index] = binaryString.charCodeAt(index);
  }
  return byteArray;
}

/**
 * Returns `length` cryptographically secure random bytes.
 *
 * `crypto.getRandomValues` draws from the operating system's CSPRNG. It is the
 * only source of randomness used anywhere in Tessera: salts, IVs and generated
 * passwords all come from here. `Math.random()` is never used, because it is
 * predictable and unsuitable for cryptography.
 *
 * @param {number} length
 * @returns {Uint8Array}
 */
export function getRandomBytes(length) {
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

/**
 * Compares two strings in time that depends only on their length, not on
 * where they first differ.
 *
 * A normal `===` comparison can return as soon as it finds a mismatch, so its
 * running time leaks how many leading characters were correct. For values that
 * act as secrets (MAC tags, password checks) we avoid that timing side
 * channel. The inputs here are Base64 strings of public length, so leaking
 * the length is harmless.
 *
 * @param {string} left
 * @param {string} right
 * @returns {boolean}
 */
export function constantTimeEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string") {
    return false;
  }
  if (left.length !== right.length) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < left.length; index++) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}

/**
 * Serializes a JSON-compatible value deterministically: object keys are
 * sorted at every level and no whitespace is emitted.
 *
 * Why this matters: the vault's integrity tag is an HMAC over the vault's
 * contents. A MAC is computed over *bytes*, so the sender and verifier must
 * turn the same logical object into exactly the same bytes. Plain
 * `JSON.stringify` keeps insertion order, which can differ after a
 * round-trip through a server or database. Sorting the keys removes that
 * ambiguity.
 *
 * @param {unknown} value - Plain objects, arrays, strings, finite numbers,
 *   booleans and null only.
 * @returns {string}
 */
export function canonicalJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("canonicalJson: numbers must be finite");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  if (typeof value === "object") {
    const sortedKeys = Object.keys(value).sort();
    const members = sortedKeys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`);
    return `{${members.join(",")}}`;
  }
  throw new TypeError(`canonicalJson: unsupported type ${typeof value}`);
}

/**
 * Normalizes any BufferSource (ArrayBuffer, typed array, DataView) to a
 * Uint8Array view without copying.
 *
 * @param {BufferSource} bytes
 * @returns {Uint8Array}
 */
function toUint8Array(bytes) {
  if (bytes instanceof Uint8Array) {
    return bytes;
  }
  if (ArrayBuffer.isView(bytes)) {
    return new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }
  return new Uint8Array(bytes);
}

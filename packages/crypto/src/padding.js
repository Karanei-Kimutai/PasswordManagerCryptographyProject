/**
 * @file padding.js
 *
 * Fixed-size padding for record plaintexts, so ciphertext length reveals
 * nothing about the record.
 *
 * AES-GCM is a stream-cipher mode: the ciphertext is exactly as long as the
 * plaintext (plus a 16-byte tag). Without padding, anyone holding the vault
 * file could tell a 6-character password from a 40-character one, or an entry
 * with no notes from one with long notes.
 *
 * The coursework padded each password to 193 bytes. Tessera records hold a
 * whole entry (website, username, password, notes), so we pad to
 * RECORD_PLAINTEXT_BYTES (4096) instead, using the same layout:
 *
 *   ┌───────────────┬────────────────────────────┬───────────────────────┐
 *   │ length (2 B,  │ payload (UTF-8 JSON,       │ 0x00 … zero padding   │
 *   │ big-endian)   │ `length` bytes)            │                       │
 *   └───────────────┴────────────────────────────┴───────────────────────┘
 *    └──────────────────────────── 4096 bytes ──────────────────────────┘
 *
 * Lessons carried over from the coursework's bug fixes:
 * - Pad **bytes**, not characters. Limits are checked after UTF-8 encoding,
 *   so non-ASCII text cannot overflow the fixed size.
 * - Use an explicit **length prefix** rather than stripping zero bytes, so a
 *   payload that legitimately contains "\0" round-trips exactly.
 * - **Reject** oversized input instead of producing a longer ciphertext.
 */

import {
  MAX_RECORD_PAYLOAD_BYTES,
  RECORD_LENGTH_PREFIX_BYTES,
  RECORD_PLAINTEXT_BYTES,
} from "./constants.js";

/** Thrown when a record is too large to fit in one fixed-size plaintext. */
export class RecordTooLargeError extends Error {
  constructor(payloadBytes) {
    super(`Entry is too large (${payloadBytes} bytes; the limit is ${MAX_RECORD_PAYLOAD_BYTES}). Shorten the notes.`);
    this.name = "RecordTooLargeError";
    this.payloadBytes = payloadBytes;
  }
}

/**
 * Pads a payload to exactly RECORD_PLAINTEXT_BYTES.
 *
 * @param {Uint8Array} payloadBytes
 * @returns {Uint8Array} A new zero-filled buffer containing the length and payload.
 */
export function padRecord(payloadBytes) {
  if (payloadBytes.length > MAX_RECORD_PAYLOAD_BYTES) {
    throw new RecordTooLargeError(payloadBytes.length);
  }
  const padded = new Uint8Array(RECORD_PLAINTEXT_BYTES); // zero-filled by default
  // Write the length as a 16-bit big-endian integer (4094 fits easily).
  padded[0] = (payloadBytes.length >>> 8) & 0xff;
  padded[1] = payloadBytes.length & 0xff;
  padded.set(payloadBytes, RECORD_LENGTH_PREFIX_BYTES);
  return padded;
}

/**
 * Inverse of padRecord: reads the length prefix and returns exactly that many
 * payload bytes.
 *
 * This only runs on plaintext that already passed AES-GCM authentication, so
 * malformed padding indicates a bug rather than an attack. We still validate
 * it rather than trust it.
 *
 * @param {BufferSource} paddedBuffer
 * @returns {Uint8Array}
 */
export function unpadRecord(paddedBuffer) {
  const padded = new Uint8Array(paddedBuffer);
  if (padded.length !== RECORD_PLAINTEXT_BYTES) {
    throw new Error("Malformed record padding: unexpected size");
  }
  const payloadLength = (padded[0] << 8) | padded[1];
  if (payloadLength > MAX_RECORD_PAYLOAD_BYTES) {
    throw new Error("Malformed record padding: invalid length");
  }
  return padded.slice(RECORD_LENGTH_PREFIX_BYTES, RECORD_LENGTH_PREFIX_BYTES + payloadLength);
}

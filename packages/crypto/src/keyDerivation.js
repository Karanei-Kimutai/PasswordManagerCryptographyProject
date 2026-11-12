/**
 * @file keyDerivation.js
 *
 * Turns the master password into every key Tessera uses.
 *
 * The key hierarchy (unchanged in spirit from the coursework, extended with
 * two more sub-keys for the web setting):
 *
 *   master password ──┐
 *                     ├─ PBKDF2-HMAC-SHA256 (600,000 iterations) ─ 256 bits
 *   random 128-bit ───┘                                              │
 *   salt                                                  masterKey (HMAC-SHA256, a PRF)
 *                                                                    │
 *        ┌──────────────┬───────────────┬─────────────────┬──────────┴──────┐
 *   recordKey       indexKey       integrityKey         authKey      passwordCheck
 *   AES-256-GCM     HMAC-SHA256    HMAC-SHA256          sent to the  stored in the
 *   encrypts each   hides which    authenticates the    server to    vault; gives a
 *   record          sites/users    whole vault          log in       clear "wrong
 *                   are stored     (rollback defense)                password" error
 *
 * Two principles from the coursework carry over:
 *
 * 1. **PBKDF2 runs exactly once per unlock.** It is deliberately slow; that
 *    slowness is what makes guessing the master password expensive. Every
 *    other key is derived from its output with one fast HMAC call.
 * 2. **Key separation.** Each sub-key is HMAC(masterKey, distinctLabel).
 *    HMAC is a pseudorandom function (PRF), so outputs for different labels
 *    look independent. Knowing one sub-key reveals nothing about the others.
 *
 * Why the server can safely receive `authKey`: it is one PRF output among
 * several. From it, the server cannot compute `masterKey` (that would mean
 * inverting HMAC) and so cannot compute `recordKey`. The server stores only a
 * slow scrypt hash of `authKey`, so even a database leak does not let an
 * attacker log in as the user.
 */

import {
  DEFAULT_PBKDF2_ITERATIONS,
  KDF_ALGORITHM,
  KEY_LABELS,
  MAX_PBKDF2_ITERATIONS,
  MIN_PBKDF2_ITERATIONS,
  SALT_BYTES,
} from "./constants.js";
import { base64ToBytes, bytesToBase64, getRandomBytes, stringToBytes } from "./encoding.js";

const subtle = globalThis.crypto.subtle;

/**
 * @typedef {object} KdfParameters
 * @property {string} algorithm  - Always "PBKDF2-SHA256" for now.
 * @property {number} iterations - PBKDF2 iteration count.
 * @property {string} salt       - Base64 of 16 random bytes.
 */

/**
 * @typedef {object} VaultKeys
 * @property {CryptoKey} recordKey    - AES-GCM key that encrypts records.
 * @property {CryptoKey} indexKey     - HMAC key that computes record locators.
 * @property {CryptoKey} integrityKey - HMAC key that tags the whole vault.
 * @property {string} authKey         - Base64 credential sent to the server.
 * @property {string} passwordCheck   - Base64 verifier stored in the vault.
 * @property {KdfParameters} kdf      - The parameters these keys came from.
 */

/**
 * Creates fresh KDF parameters for a new vault (or a master-password change):
 * a new random salt and the current default iteration count.
 *
 * A fresh random salt per vault means two users with the same master password
 * still get unrelated keys, and an attacker cannot precompute a table of
 * password → key (a "rainbow table") ahead of time.
 *
 * @param {{ iterations?: number }} [options]
 * @returns {KdfParameters}
 */
export function createKdfParameters({ iterations = DEFAULT_PBKDF2_ITERATIONS } = {}) {
  return {
    algorithm: KDF_ALGORITHM,
    iterations,
    salt: bytesToBase64(getRandomBytes(SALT_BYTES)),
  };
}

/**
 * Checks KDF parameters that arrived from somewhere untrusted (the server, or
 * a serialized vault). Throws if they are malformed or too weak.
 *
 * @param {KdfParameters} kdf
 * @param {{ allowWeakKdf?: boolean }} [options] - Tests may opt in to low
 *   iteration counts so they run fast. The app never sets this.
 */
export function validateKdfParameters(kdf, { allowWeakKdf = false } = {}) {
  if (!kdf || kdf.algorithm !== KDF_ALGORITHM) {
    throw new Error("Unsupported key-derivation algorithm");
  }
  if (!Number.isInteger(kdf.iterations) || kdf.iterations > MAX_PBKDF2_ITERATIONS || kdf.iterations < 1) {
    throw new Error("Invalid PBKDF2 iteration count");
  }
  if (!allowWeakKdf && kdf.iterations < MIN_PBKDF2_ITERATIONS) {
    throw new Error("PBKDF2 iteration count is below the minimum allowed");
  }
  let saltBytes;
  try {
    saltBytes = base64ToBytes(kdf.salt);
  } catch {
    throw new Error("Invalid salt encoding");
  }
  if (saltBytes.length !== SALT_BYTES) {
    throw new Error("Invalid salt length");
  }
}

/**
 * Normalizes the master password before it is used.
 *
 * Some characters have more than one Unicode representation: "é" can be one
 * code point or "e" plus a combining accent, and different keyboards and
 * operating systems produce different forms. NFKC normalization maps them to
 * a single form, so the same password typed on a phone and on a laptop
 * produces the same bytes, and therefore the same keys.
 *
 * @param {string} masterPassword
 * @returns {Uint8Array}
 */
export function encodeMasterPassword(masterPassword) {
  if (typeof masterPassword !== "string" || masterPassword.length === 0) {
    throw new Error("A master password is required");
  }
  return stringToBytes(masterPassword.normalize("NFKC"));
}

/**
 * Derives every key Tessera needs from the master password.
 *
 * Cost: one PBKDF2 call (slow, by design) plus five HMAC calls (fast).
 *
 * @param {string} masterPassword
 * @param {KdfParameters} kdf
 * @param {{ allowWeakKdf?: boolean }} [options]
 * @returns {Promise<VaultKeys>}
 */
export async function deriveVaultKeys(masterPassword, kdf, options = {}) {
  validateKdfParameters(kdf, options);

  // Step 1: import the password as raw PBKDF2 key material.
  // `extractable: false` means the bytes can never be read back out of the
  // CryptoKey object, only used for the listed operation.
  const passwordBytes = encodeMasterPassword(masterPassword);
  const passwordKey = await subtle.importKey("raw", passwordBytes, { name: "PBKDF2" }, false, ["deriveBits"]);
  passwordBytes.fill(0); // Best-effort wipe of our copy of the password bytes.

  // Step 2: the single slow step. Stretch the password into 256 bits.
  const masterBits = new Uint8Array(
    await subtle.deriveBits(
      { name: "PBKDF2", salt: base64ToBytes(kdf.salt), iterations: kdf.iterations, hash: "SHA-256" },
      passwordKey,
      256,
    ),
  );

  // Step 3: use those bits as an HMAC key, i.e. as a PRF for deriving sub-keys.
  const masterKey = await subtle.importKey("raw", masterBits, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  masterBits.fill(0);

  /** Evaluates the PRF: HMAC(masterKey, label). Returns 32 bytes. */
  const derive = async (label) => new Uint8Array(await subtle.sign("HMAC", masterKey, stringToBytes(label)));

  // Step 4: derive each sub-key with its own label, importing each one with
  // only the usages it needs (principle of least privilege).
  const recordKeyBits = await derive(KEY_LABELS.recordKey);
  const recordKey = await subtle.importKey("raw", recordKeyBits, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  recordKeyBits.fill(0);

  const indexKeyBits = await derive(KEY_LABELS.indexKey);
  const indexKey = await subtle.importKey("raw", indexKeyBits, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  indexKeyBits.fill(0);

  const integrityKeyBits = await derive(KEY_LABELS.integrityKey);
  const integrityKey = await subtle.importKey(
    "raw",
    integrityKeyBits,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
  integrityKeyBits.fill(0);

  // These two are not CryptoKeys: they are values that leave this module
  // (authKey goes to the server, passwordCheck goes into the vault file).
  const authKey = bytesToBase64(await derive(KEY_LABELS.authKey));
  const passwordCheck = bytesToBase64(await derive(KEY_LABELS.passwordCheck));

  return {
    recordKey,
    indexKey,
    integrityKey,
    authKey,
    passwordCheck,
    kdf: { algorithm: kdf.algorithm, iterations: kdf.iterations, salt: kdf.salt },
  };
}

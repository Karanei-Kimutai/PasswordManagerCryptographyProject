/**
 * @file constants.js
 *
 * Every tunable cryptographic parameter in Tessera lives in this file, so the
 * security-relevant choices can be reviewed in one place.
 */

/** Identifies a serialized Tessera vault. Covered by the integrity tag. */
export const VAULT_FORMAT = "tessera-vault";

/**
 * Version of the serialized vault layout. Bump it whenever the format changes
 * in a way older clients cannot read. Covered by the integrity tag, so an
 * attacker cannot downgrade it.
 */
export const VAULT_FORMAT_VERSION = 1;

/** The only key-derivation function currently supported. */
export const KDF_ALGORITHM = "PBKDF2-SHA256";

/**
 * PBKDF2 iteration count for new vaults.
 *
 * The coursework used 100,000. OWASP's Password Storage Cheat Sheet
 * recommends 600,000 for PBKDF2-HMAC-SHA256, so new vaults use that. Each
 * guess an offline attacker makes then costs 600,000 HMAC computations.
 *
 * The count is stored alongside the salt, so it can be raised later without
 * breaking existing vaults (the coursework hard-coded it, which the README
 * listed as a limitation).
 */
export const DEFAULT_PBKDF2_ITERATIONS = 600_000;

/**
 * Lower and upper bounds accepted for a stored iteration count. The lower
 * bound stops a malicious server from weakening the KDF by advertising a tiny
 * count at sign-in. (Tests pass a smaller count explicitly, with
 * `allowWeakKdf`, so they run quickly.)
 */
export const MIN_PBKDF2_ITERATIONS = 100_000;
export const MAX_PBKDF2_ITERATIONS = 10_000_000;

/** Salt length in bytes: 128 bits, as the coursework handout required. */
export const SALT_BYTES = 16;

/**
 * AES-GCM IV (nonce) length in bytes. 96 bits is the size NIST SP 800-38D
 * recommends: GCM uses it directly, without an extra hashing step.
 */
export const AES_GCM_IV_BYTES = 12;

/**
 * Every record is padded to exactly this many bytes before encryption, so
 * every ciphertext in the vault has the same length. This generalizes the
 * coursework's 193-byte password padding to whole entries (website, username,
 * password and notes).
 *
 * Layout: [2-byte big-endian length][UTF-8 JSON payload][zero padding]
 */
export const RECORD_PLAINTEXT_BYTES = 4096;

/** Size of the length prefix at the start of every padded record. */
export const RECORD_LENGTH_PREFIX_BYTES = 2;

/** The largest JSON payload that fits in one padded record. */
export const MAX_RECORD_PAYLOAD_BYTES = RECORD_PLAINTEXT_BYTES - RECORD_LENGTH_PREFIX_BYTES;

/**
 * Per-field limits, in characters, enforced before encryption. They exist so
 * the UI can show a helpful message long before the hard byte limit above is
 * reached. The byte limit is still checked after encoding.
 */
export const FIELD_LIMITS = Object.freeze({
  site: 255,
  username: 255,
  password: 256,
  notes: 2000,
});

/**
 * Labels fed to HMAC(masterKey, label) to derive independent sub-keys.
 * Distinct labels give independent-looking keys (key separation): a weakness
 * in how one key is used cannot leak another.
 */
export const KEY_LABELS = Object.freeze({
  recordKey: "tessera/v1/record-encryption",
  indexKey: "tessera/v1/record-index",
  integrityKey: "tessera/v1/vault-integrity",
  authKey: "tessera/v1/server-authentication",
  passwordCheck: "tessera/v1/password-check",
});

/** Domain-separation prefix for the vault integrity tag input. */
export const INTEGRITY_TAG_CONTEXT = "tessera/v1/vault-integrity-tag\n";

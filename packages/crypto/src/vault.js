/**
 * @file vault.js
 *
 * The Vault: an encrypted key-value store of login entries. This is the
 * successor of the coursework's `Keychain` class, extended for a multi-device
 * web application.
 *
 * ─── How it maps to the coursework ────────────────────────────────────────
 *
 *  Coursework Keychain                 Tessera Vault
 *  ──────────────────────────────────  ──────────────────────────────────────
 *  kvs[HMAC(domainKey, domain)]        records[HMAC(indexKey, site + "\0" + username)]
 *  value = password (≤ 64 chars)       value = JSON entry {site, username, password, notes, …}
 *  padded to 193 bytes                 padded to 4096 bytes
 *  AES-GCM, AAD = domain               AES-GCM, AAD = record locator
 *  SHA-256 checksum in trusted storage integrity tag (HMAC) + monotonic version
 *                                      counter + checksum kept by each device
 *  init / load / dump / get / set /    create / load / dump / getEntry /
 *  remove                              setEntry / removeEntry / listEntries
 *
 * ─── The serialized form (what the server stores) ───────────────────────
 *
 *   {
 *     "format": "tessera-vault",
 *     "formatVersion": 1,
 *     "kdf": { "algorithm": "PBKDF2-SHA256", "iterations": 600000, "salt": "…" },
 *     "version": 12,
 *     "passwordCheck": "…",
 *     "records": { "<locator>": { "iv": "…", "ciphertext": "…" }, … },
 *     "integrityTag": "…"
 *   }
 *
 * Everything in it is safe for the server to see: random salts and IVs,
 * ciphertexts of identical length, pseudorandom locators and tags. The server
 * learns how many entries exist and when the vault changes, and nothing else.
 *
 * ─── Defenses, layer by layer ──────────────────────────────────────────────
 *
 * 1. Confidentiality: every record is AES-256-GCM encrypted under recordKey
 *    with a fresh random 96-bit IV, so equal entries never produce equal
 *    ciphertexts.
 * 2. Length hiding: every plaintext is padded to the same size (padding.js).
 * 3. Hidden sites: the record locator is HMAC(indexKey, site, username), a
 *    PRF output that reveals nothing about its input without the key.
 * 4. Swap defense: the locator is the GCM associated data (AAD). A ciphertext
 *    moved under a different locator fails authentication. This works on its
 *    own, even if the integrity tag below were never checked.
 * 5. Whole-vault integrity: integrityTag = HMAC(integrityKey, everything
 *    else). Deleting, re-adding, reordering a record or changing the version
 *    number breaks the tag.
 * 6. Rollback defense: each save increments `version`, and the tag stops the
 *    server from forging it. Each device remembers the highest version it has
 *    seen (the coursework's "trusted storage") and refuses anything older.
 */

import { AES_GCM_IV_BYTES, FIELD_LIMITS, INTEGRITY_TAG_CONTEXT, RECORD_PLAINTEXT_BYTES, VAULT_FORMAT, VAULT_FORMAT_VERSION } from "./constants.js";
import {
  base64ToBytes,
  bytesToBase64,
  bytesToString,
  canonicalJson,
  constantTimeEqual,
  getRandomBytes,
  stringToBytes,
} from "./encoding.js";
import {
  DuplicateEntryError,
  EntryValidationError,
  RollbackError,
  VaultFormatError,
  VaultIntegrityError,
  WrongPasswordError,
} from "./errors.js";
import { padRecord, unpadRecord } from "./padding.js";

const subtle = globalThis.crypto.subtle;

/** AES-GCM appends a 16-byte authentication tag to every ciphertext. */
const AES_GCM_TAG_BYTES = 16;
const EXPECTED_CIPHERTEXT_BYTES = RECORD_PLAINTEXT_BYTES + AES_GCM_TAG_BYTES;

/**
 * @typedef {object} Entry
 * @property {string} id        - The record locator. Stable while site and username are unchanged.
 * @property {string} site      - Website as the user typed it, e.g. "github.com".
 * @property {string} username
 * @property {string} password
 * @property {string} notes
 * @property {string} createdAt - ISO 8601 timestamp (encrypted, invisible to the server).
 * @property {string} updatedAt - ISO 8601 timestamp (encrypted, invisible to the server).
 */

/**
 * @typedef {object} EncryptedRecord
 * @property {string} iv         - Base64 of the 12-byte AES-GCM IV.
 * @property {string} ciphertext - Base64 of the padded, encrypted entry plus its GCM tag.
 */

/**
 * @typedef {object} TrustedState
 * What a device remembers about the newest vault it has seen. This is the web
 * app's version of the coursework's "trusted storage".
 * @property {number} version  - Highest vault version seen.
 * @property {string} checksum - SHA-256 (Base64) of that version's serialized form.
 */

/**
 * Normalizes a website so that "https://www.GitHub.com/login" and
 * "github.com" refer to the same record.
 *
 * Rules: trim and lowercase; drop a URL scheme ("https://"); drop any path,
 * query or fragment; drop a leading "www.". Text that is not a hostname
 * ("My Bank") is just trimmed and lowercased.
 *
 * @param {string} site
 * @returns {string}
 */
export function normalizeSite(site) {
  let text = String(site).trim().toLowerCase();
  const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//.test(text);
  if (hasScheme) {
    text = text.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
  }
  if (hasScheme || !/\s/.test(text)) {
    // Only treat "/" as a path separator when the text looks like a URL or a
    // hostname, so a label such as "work / personal" is left alone.
    text = text.split(/[/?#]/)[0];
  }
  if (text.startsWith("www.")) {
    text = text.slice(4);
  }
  return text;
}

/**
 * Computes the SHA-256 checksum (Base64) of a serialized vault. This is the
 * same checksum the coursework's `dump()` returned as its second value.
 *
 * @param {string} serializedVault
 * @returns {Promise<string>}
 */
export async function computeChecksum(serializedVault) {
  return bytesToBase64(await subtle.digest("SHA-256", stringToBytes(serializedVault)));
}

export class Vault {
  /** @type {import("./keyDerivation.js").VaultKeys} */
  #keys;
  /** @type {Map<string, EncryptedRecord>} locator → encrypted record */
  #records;
  /** @type {number} Monotonic counter; increases by 1 on every change. */
  #version;

  /**
   * Private-by-convention: use `Vault.create` or `Vault.load`.
   *
   * @param {import("./keyDerivation.js").VaultKeys} keys
   * @param {Map<string, EncryptedRecord>} records
   * @param {number} version
   */
  constructor(keys, records, version) {
    this.#keys = keys;
    this.#records = records;
    this.#version = version;
  }

  /**
   * Creates a new, empty vault (the coursework's `Keychain.init`). The keys
   * come from `deriveVaultKeys`, so PBKDF2 has already run exactly once.
   *
   * @param {import("./keyDerivation.js").VaultKeys} keys
   * @returns {Vault}
   */
  static create(keys) {
    return new Vault(keys, new Map(), 0);
  }

  /**
   * Restores a vault from its serialized form (the coursework's
   * `Keychain.load`), checking everything that can be checked:
   *
   * 1. The format is one we understand.
   * 2. The vault was made with the same KDF parameters as `keys`.
   * 3. The password check matches → otherwise WrongPasswordError.
   * 4. The integrity tag verifies → otherwise VaultIntegrityError.
   * 5. The version is not older than `trustedState.version`
   *    → otherwise RollbackError.
   * 6. Same version but a different checksum → VaultIntegrityError
   *    (two different histories, i.e. a forked vault).
   *
   * Records stay encrypted. Each one is decrypted only when it is read, as
   * the coursework required.
   *
   * @param {import("./keyDerivation.js").VaultKeys} keys
   * @param {string} serializedVault
   * @param {{ trustedState?: TrustedState | null }} [options]
   * @returns {Promise<Vault>}
   */
  static async load(keys, serializedVault, { trustedState = null } = {}) {
    let parsed;
    try {
      parsed = JSON.parse(serializedVault);
    } catch {
      throw new VaultFormatError("The stored vault is not valid JSON");
    }
    if (!parsed || parsed.format !== VAULT_FORMAT || parsed.formatVersion !== VAULT_FORMAT_VERSION) {
      throw new VaultFormatError();
    }
    if (!Number.isSafeInteger(parsed.version) || parsed.version < 0) {
      throw new VaultFormatError("Invalid vault version");
    }
    if (!parsed.records || typeof parsed.records !== "object" || Array.isArray(parsed.records)) {
      throw new VaultFormatError("Invalid record set");
    }

    // (2) The keys only fit if they came from the same salt and iteration count.
    if (
      !parsed.kdf ||
      parsed.kdf.salt !== keys.kdf.salt ||
      parsed.kdf.iterations !== keys.kdf.iterations ||
      parsed.kdf.algorithm !== keys.kdf.algorithm
    ) {
      throw new VaultIntegrityError("Vault key-derivation parameters do not match");
    }

    // (3) A cheap, clear "wrong password" signal, checked before anything else.
    if (!constantTimeEqual(parsed.passwordCheck, keys.passwordCheck)) {
      throw new WrongPasswordError();
    }

    // (4) Authenticate the whole vault: record set, version and metadata.
    const expectedTagInput = Vault.#integrityTagInput(parsed);
    let tagBytes;
    try {
      tagBytes = base64ToBytes(parsed.integrityTag);
    } catch {
      throw new VaultIntegrityError();
    }
    const tagIsValid = await subtle.verify("HMAC", keys.integrityKey, tagBytes, stringToBytes(expectedTagInput));
    if (!tagIsValid) {
      throw new VaultIntegrityError();
    }

    // (5) and (6): rollback and fork detection against this device's memory.
    if (trustedState) {
      if (parsed.version < trustedState.version) {
        throw new RollbackError(trustedState.version, parsed.version);
      }
      if (parsed.version === trustedState.version) {
        const checksum = await computeChecksum(serializedVault);
        if (!constantTimeEqual(checksum, trustedState.checksum)) {
          throw new VaultIntegrityError("Vault fork detected: same version, different contents");
        }
      }
    }

    // Structural sanity checks on each record (sizes are fixed by design).
    const records = new Map();
    for (const [locator, record] of Object.entries(parsed.records)) {
      if (!isWellFormedRecord(record)) {
        throw new VaultFormatError("Malformed record");
      }
      records.set(locator, { iv: record.iv, ciphertext: record.ciphertext });
    }

    return new Vault(keys, records, parsed.version);
  }

  /** Current version number. Increases by exactly 1 per change. */
  get version() {
    return this.#version;
  }

  /** Number of entries (the server can count these too; that leak is accepted). */
  get size() {
    return this.#records.size;
  }

  /** The KDF parameters this vault's keys were derived with. */
  get kdf() {
    return { ...this.#keys.kdf };
  }

  /** The credential this vault's owner uses to authenticate to the server. */
  get authKey() {
    return this.#keys.authKey;
  }

  /**
   * Serializes the vault for storage (the coursework's `dump`).
   *
   * Returns the serialized string together with its SHA-256 checksum and
   * version, which the caller records as this device's trusted state after the
   * server accepts the save.
   *
   * Keys are never part of the output: only the public fields below are
   * serialized, and every CryptoKey is non-extractable anyway.
   *
   * @returns {Promise<{ serializedVault: string, checksum: string, version: number }>}
   */
  async dump() {
    const body = {
      format: VAULT_FORMAT,
      formatVersion: VAULT_FORMAT_VERSION,
      kdf: { ...this.#keys.kdf },
      version: this.#version,
      passwordCheck: this.#keys.passwordCheck,
      records: Object.fromEntries(this.#records),
    };
    const tagBytes = await subtle.sign("HMAC", this.#keys.integrityKey, stringToBytes(Vault.#integrityTagInput(body)));
    const serializedVault = canonicalJson({ ...body, integrityTag: bytesToBase64(tagBytes) });
    return { serializedVault, checksum: await computeChecksum(serializedVault), version: this.#version };
  }

  /**
   * Looks up one entry by website and username in O(1) (the coursework's
   * `get`): compute the locator with one HMAC, then index the map. Returns
   * null if there is no such entry.
   *
   * @param {string} site
   * @param {string} username
   * @returns {Promise<Entry | null>}
   */
  async getEntry(site, username) {
    const locator = await this.#computeLocator(site, username);
    return this.getEntryById(locator);
  }

  /**
   * Decrypts one entry by its id (locator), or returns null if absent.
   *
   * @param {string} entryId
   * @returns {Promise<Entry | null>}
   */
  async getEntryById(entryId) {
    const record = this.#records.get(entryId);
    if (!record) {
      return null;
    }
    return this.#decryptRecord(entryId, record);
  }

  /**
   * Decrypts every entry. The vault screen needs the whole list to show and
   * search it; individual records are still encrypted separately.
   *
   * @returns {Promise<Entry[]>}
   */
  async listEntries() {
    const entries = [];
    for (const [locator, record] of this.#records) {
      entries.push(await this.#decryptRecord(locator, record));
    }
    return entries;
  }

  /**
   * Adds a new entry or updates an existing one (the coursework's `set`).
   *
   * When editing, pass the entry's current id as `previousId`. If the website
   * or username changed, the locator changes, so the old record is removed
   * and a new one written. `createdAt` is preserved across edits.
   *
   * Bumps the version by 1.
   *
   * @param {{ site: string, username?: string, password: string, notes?: string }} fields
   * @param {{ previousId?: string | null }} [options]
   * @returns {Promise<Entry>}
   * @throws {EntryValidationError | DuplicateEntryError | import("./padding.js").RecordTooLargeError}
   */
  async setEntry(fields, { previousId = null } = {}) {
    const cleanFields = validateEntryFields(fields);
    const locator = await this.#computeLocator(cleanFields.site, cleanFields.username);

    // Writing over a *different* existing entry would silently destroy it.
    if (this.#records.has(locator) && locator !== previousId) {
      throw new DuplicateEntryError();
    }

    const now = new Date().toISOString();
    let createdAt = now;
    if (previousId) {
      const previous = await this.getEntryById(previousId);
      if (previous) {
        createdAt = previous.createdAt;
      }
    }

    const entryPayload = { ...cleanFields, createdAt, updatedAt: now };
    const record = await this.#encryptRecord(locator, entryPayload);

    if (previousId && previousId !== locator) {
      this.#records.delete(previousId);
    }
    this.#records.set(locator, record);
    this.#version += 1;
    return { id: locator, ...entryPayload };
  }

  /**
   * Removes an entry (the coursework's `remove`). Returns true if it existed.
   * Bumps the version by 1 when something is removed.
   *
   * @param {string} entryId
   * @returns {boolean}
   */
  removeEntry(entryId) {
    const existed = this.#records.delete(entryId);
    if (existed) {
      this.#version += 1;
    }
    return existed;
  }

  /**
   * Produces a copy of this vault under new keys, used when the master
   * password changes. A new password means a new salt, so every key changes,
   * and every record must be decrypted with the old keys and re-encrypted
   * with the new ones (with new IVs and new locators).
   *
   * The original vault is left untouched, so if the server rejects the
   * change the app keeps working with the old one.
   *
   * @param {import("./keyDerivation.js").VaultKeys} newKeys
   * @returns {Promise<Vault>}
   */
  async rekey(newKeys) {
    const rekeyed = new Vault(newKeys, new Map(), this.#version + 1);
    for (const [locator, record] of this.#records) {
      // Drop the old id: the locator changes because indexKey changes.
      const { id: _oldLocator, ...payload } = await this.#decryptRecord(locator, record);
      const newLocator = await rekeyed.#computeLocator(payload.site, payload.username);
      rekeyed.#records.set(newLocator, await rekeyed.#encryptRecord(newLocator, payload));
    }
    return rekeyed;
  }

  // ─── Private helpers ──────────────────────────────────────────────────────

  /**
   * Record locator = Base64(HMAC(indexKey, normalizedSite + "\0" + username)).
   *
   * HMAC is deterministic, so the same site and username always map to the
   * same locator, which gives O(1) lookups (coursework Short Answer 4). It is
   * also a PRF, so without indexKey the locator reveals nothing about which
   * site it belongs to. The "\0" separator cannot appear in a normalized site,
   * so ("a", "b\0c") and ("a\0b", "c") cannot collide.
   */
  async #computeLocator(site, username) {
    const name = `${normalizeSite(site)}\u0000${username}`;
    return bytesToBase64(await subtle.sign("HMAC", this.#keys.indexKey, stringToBytes(name)));
  }

  /** Associated data that binds a ciphertext to its locator (swap defense). */
  static #associatedData(locator) {
    return stringToBytes(`tessera/v1/record\n${locator}`);
  }

  /**
   * Pads and encrypts an entry payload with a fresh random IV.
   *
   * IV uniqueness is critical for GCM: reusing an IV with the same key leaks
   * the XOR of two plaintexts and lets an attacker forge tags. A random
   * 96-bit IV per encryption makes a repeat negligibly likely for any
   * realistic number of records.
   */
  async #encryptRecord(locator, entryPayload) {
    const paddedPlaintext = padRecord(stringToBytes(JSON.stringify(entryPayload)));
    const iv = getRandomBytes(AES_GCM_IV_BYTES);
    const ciphertext = await subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: Vault.#associatedData(locator) },
      this.#keys.recordKey,
      paddedPlaintext,
    );
    paddedPlaintext.fill(0);
    return { iv: bytesToBase64(iv), ciphertext: bytesToBase64(ciphertext) };
  }

  /**
   * Decrypts and authenticates one record.
   *
   * If the ciphertext, IV, or the locator it is stored under were changed,
   * GCM authentication fails and SubtleCrypto throws. We turn that into a
   * VaultIntegrityError. As defense in depth, we also recompute the locator
   * from the decrypted site and username and check it matches.
   */
  async #decryptRecord(locator, record) {
    let plaintext;
    try {
      plaintext = await subtle.decrypt(
        { name: "AES-GCM", iv: base64ToBytes(record.iv), additionalData: Vault.#associatedData(locator) },
        this.#keys.recordKey,
        base64ToBytes(record.ciphertext),
      );
    } catch {
      throw new VaultIntegrityError("A record failed authentication: it was swapped or modified");
    }
    const payload = JSON.parse(bytesToString(unpadRecord(plaintext)));
    const expectedLocator = await this.#computeLocator(payload.site, payload.username);
    if (expectedLocator !== locator) {
      throw new VaultIntegrityError("A record is stored under the wrong locator");
    }
    return { id: locator, ...payload };
  }

  /**
   * The exact string the integrity tag is computed over: a fixed context
   * prefix (so this HMAC input can never be confused with any other use of
   * the key) plus the canonical JSON of every field except the tag itself.
   */
  static #integrityTagInput(vaultBody) {
    return (
      INTEGRITY_TAG_CONTEXT +
      canonicalJson({
        format: vaultBody.format,
        formatVersion: vaultBody.formatVersion,
        kdf: vaultBody.kdf,
        version: vaultBody.version,
        passwordCheck: vaultBody.passwordCheck,
        records: vaultBody.records,
      })
    );
  }
}

/**
 * Checks that a stored record has the fixed shape every record must have: a
 * 12-byte IV and a ciphertext of exactly padded-size + 16-byte tag. Any other
 * size could only come from corruption or tampering.
 *
 * @param {unknown} record
 * @returns {boolean}
 */
function isWellFormedRecord(record) {
  if (!record || typeof record.iv !== "string" || typeof record.ciphertext !== "string") {
    return false;
  }
  try {
    return (
      base64ToBytes(record.iv).length === AES_GCM_IV_BYTES &&
      base64ToBytes(record.ciphertext).length === EXPECTED_CIPHERTEXT_BYTES
    );
  } catch {
    return false;
  }
}

/**
 * Validates and normalizes user-supplied entry fields. Character limits come
 * from FIELD_LIMITS. The final byte limit is enforced by padRecord.
 *
 * @param {object} fields
 * @returns {{ site: string, username: string, password: string, notes: string }}
 */
export function validateEntryFields(fields) {
  if (!fields || typeof fields !== "object") {
    throw new EntryValidationError("Entry fields are required");
  }
  const clean = {
    site: typeof fields.site === "string" ? fields.site.trim() : "",
    username: typeof fields.username === "string" ? fields.username.trim() : "",
    password: typeof fields.password === "string" ? fields.password : "",
    notes: typeof fields.notes === "string" ? fields.notes : "",
  };
  if (!clean.site || !normalizeSite(clean.site)) {
    throw new EntryValidationError("Website is required");
  }
  if (!clean.password) {
    throw new EntryValidationError("Password is required");
  }
  for (const [field, limit] of Object.entries(FIELD_LIMITS)) {
    if (clean[field].length > limit) {
      throw new EntryValidationError(`${field[0].toUpperCase()}${field.slice(1)} must be at most ${limit} characters`);
    }
  }
  return clean;
}

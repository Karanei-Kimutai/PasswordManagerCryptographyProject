/**
 * @file errors.js
 *
 * Distinct error types, so the UI can tell the user *what* went wrong:
 * mistyping the master password is routine, while a failed integrity check
 * means someone may have tampered with the stored data.
 */

/** The master password does not match this vault. */
export class WrongPasswordError extends Error {
  constructor(message = "Incorrect master password") {
    super(message);
    this.name = "WrongPasswordError";
  }
}

/**
 * The vault's contents fail authentication: a record, the record set or the
 * version number was modified, swapped, added or removed by someone without
 * the keys.
 */
export class VaultIntegrityError extends Error {
  constructor(message = "Vault integrity check failed: the stored data was modified") {
    super(message);
    this.name = "VaultIntegrityError";
  }
}

/**
 * The vault is authentic but older than one this device has already seen.
 * That is the signature of a rollback attack: replaying a stale (but
 * genuine) copy of the vault.
 */
export class RollbackError extends Error {
  constructor(seenVersion, receivedVersion) {
    super(
      `Rollback detected: this device has already seen vault version ${seenVersion}, ` +
        `but the server returned version ${receivedVersion}`,
    );
    this.name = "RollbackError";
    this.seenVersion = seenVersion;
    this.receivedVersion = receivedVersion;
  }
}

/** The serialized vault is not something this version of Tessera can read. */
export class VaultFormatError extends Error {
  constructor(message = "Unrecognized vault format") {
    super(message);
    this.name = "VaultFormatError";
  }
}

/** An entry with the same website and username already exists. */
export class DuplicateEntryError extends Error {
  constructor() {
    super("An entry for this website and username already exists");
    this.name = "DuplicateEntryError";
  }
}

/** An entry failed validation (missing field, field too long, wrong type). */
export class EntryValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = "EntryValidationError";
  }
}

/**
 * @file vaultSession.js
 *
 * Orchestrates the browser side of Tessera: it connects the crypto core
 * (@tessera/crypto), the server API and the device's trusted state.
 *
 * A VaultSession exists only while the vault is unlocked. It holds the
 * derived keys (non-extractable CryptoKeys) and the Vault object. Locking
 * simply drops the session, and with it every reference to the keys.
 *
 *   signUp / signIn ──▶ VaultSession ──▶ listEntries / saveEntry / deleteEntry
 *                                    └──▶ changeMasterPassword
 */

import {
  Vault,
  WrongPasswordError,
  constantTimeEqual,
  createKdfParameters,
  deriveVaultKeys,
} from "@tessera/crypto";

import { ApiError, apiClient } from "./apiClient.js";
import { readTrustedState, writeTrustedState } from "./trustedStateStore.js";

/**
 * Progress steps reported during sign-in, so the UI can show what is
 * happening during the deliberately slow key derivation.
 */
export const UNLOCK_STEPS = Object.freeze({
  deriving: "Deriving keys (PBKDF2-SHA256)",
  authenticating: "Verifying with server",
  decrypting: "Checking vault integrity",
});

/** Thrown when a save conflicted with a change made on another device. */
export class SyncConflictError extends Error {
  constructor() {
    super("Your vault was changed on another device. The latest version has been loaded; please make your change again.");
    this.name = "SyncConflictError";
  }
}

export class VaultSession {
  /** @type {string} */
  #email;
  /** @type {import("@tessera/crypto").VaultKeys} */
  #keys;
  /** @type {Vault} */
  #vault;
  /** Serializes writes, so two quick edits cannot race each other. */
  #writeQueue = Promise.resolve();

  constructor(email, keys, vault) {
    this.#email = email;
    this.#keys = keys;
    this.#vault = vault;
  }

  /**
   * Creates an account. The salt, the keys and the empty vault are all made
   * here, in the browser. The server receives only the salt, the authKey
   * and the (encrypted, empty) vault.
   *
   * @param {string} email
   * @param {string} masterPassword
   * @param {(step: string) => void} [onProgress]
   * @returns {Promise<VaultSession>}
   */
  static async signUp(email, masterPassword, onProgress = () => {}) {
    onProgress(UNLOCK_STEPS.deriving);
    const keys = await deriveVaultKeys(masterPassword, createKdfParameters());
    const vault = Vault.create(keys);
    const { serializedVault, checksum, version } = await vault.dump();

    onProgress(UNLOCK_STEPS.authenticating);
    const { email: storedEmail } = await apiClient.register({
      email,
      kdf: keys.kdf,
      authKey: keys.authKey,
      vault: serializedVault,
    });
    await writeTrustedState(storedEmail, { version, checksum });
    return new VaultSession(storedEmail, keys, vault);
  }

  /**
   * Signs in (or unlocks after a lock) and opens the vault.
   *
   * 1. Ask the server for this account's salt and iteration count.
   * 2. Run PBKDF2 once, locally, and derive every key.
   * 3. Prove knowledge of the password by sending authKey (never the password).
   * 4. Fetch the encrypted vault and verify it: password check, integrity
   *    tag, and rollback check against this device's trusted state.
   *
   * @param {string} email
   * @param {string} masterPassword
   * @param {(step: string) => void} [onProgress]
   * @returns {Promise<VaultSession>}
   */
  static async signIn(email, masterPassword, onProgress = () => {}) {
    const { kdf } = await apiClient.prelogin(email);

    onProgress(UNLOCK_STEPS.deriving);
    // deriveVaultKeys refuses iteration counts below the minimum, so a
    // malicious server cannot weaken the KDF by advertising a low count.
    const keys = await deriveVaultKeys(masterPassword, kdf);

    onProgress(UNLOCK_STEPS.authenticating);
    let storedEmail;
    try {
      ({ email: storedEmail } = await apiClient.login(email, keys.authKey));
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        throw new WrongPasswordError(error.message);
      }
      throw error;
    }

    onProgress(UNLOCK_STEPS.decrypting);
    const vault = await VaultSession.#fetchAndVerify(storedEmail, keys);
    return new VaultSession(storedEmail, keys, vault);
  }

  /**
   * Downloads the vault and verifies it against this device's trusted state,
   * then records the (possibly newer) version as trusted.
   *
   * @returns {Promise<Vault>}
   */
  static async #fetchAndVerify(email, keys) {
    const { vault: serializedVault } = await apiClient.getVault();
    const trustedState = await readTrustedState(email);
    const vault = await Vault.load(keys, serializedVault, { trustedState });
    const { checksum } = await vault.dump();
    // dump() re-serializes canonically, which is byte-identical to what the
    // server holds, because every honest client stores canonical JSON.
    await writeTrustedState(email, { version: vault.version, checksum });
    return vault;
  }

  get email() {
    return this.#email;
  }

  get version() {
    return this.#vault.version;
  }

  get entryCount() {
    return this.#vault.size;
  }

  get kdf() {
    return this.#vault.kdf;
  }

  /** Decrypts and returns every entry. */
  listEntries() {
    return this.#vault.listEntries();
  }

  /**
   * Adds or edits an entry, then saves the vault to the server.
   *
   * @param {{ site: string, username: string, password: string, notes: string }} fields
   * @param {string | null} previousId - The entry being edited, or null for a new entry.
   * @returns {Promise<import("@tessera/crypto").Entry>}
   */
  saveEntry(fields, previousId = null) {
    return this.#enqueueWrite(() => this.#vault.setEntry(fields, { previousId }));
  }

  /**
   * Deletes an entry, then saves the vault to the server.
   *
   * @param {string} entryId
   */
  deleteEntry(entryId) {
    return this.#enqueueWrite(async () => this.#vault.removeEntry(entryId));
  }

  /**
   * Replaces the master password.
   *
   * A new password needs a new salt, which changes every key, so the whole
   * vault is decrypted and re-encrypted here in the browser. The server then
   * swaps in the new credentials and the re-encrypted vault in one
   * transaction.
   *
   * @param {string} currentPassword
   * @param {string} newPassword
   * @param {(step: string) => void} [onProgress]
   */
  changeMasterPassword(currentPassword, newPassword, onProgress = () => {}) {
    return this.#enqueue(async () => {
      onProgress("Checking current password");
      const currentKeys = await deriveVaultKeys(currentPassword, this.#keys.kdf);
      if (!constantTimeEqual(currentKeys.authKey, this.#keys.authKey)) {
        throw new WrongPasswordError("Current master password is incorrect");
      }

      onProgress("Deriving new keys");
      const newKeys = await deriveVaultKeys(newPassword, createKdfParameters());

      onProgress(`Re-encrypting ${this.#vault.size} item${this.#vault.size === 1 ? "" : "s"}`);
      const rekeyedVault = await this.#vault.rekey(newKeys);
      const { serializedVault, checksum, version } = await rekeyedVault.dump();

      onProgress("Saving");
      try {
        await apiClient.changeMasterPassword({
          currentAuthKey: currentKeys.authKey,
          newAuthKey: newKeys.authKey,
          newKdf: newKeys.kdf,
          vault: serializedVault,
          expectedVersion: this.#vault.version,
        });
      } catch (error) {
        if (error instanceof ApiError && error.status === 409) {
          this.#vault = await VaultSession.#fetchAndVerify(this.#email, this.#keys);
          throw new SyncConflictError();
        }
        throw error;
      }
      this.#keys = newKeys;
      this.#vault = rekeyedVault;
      await writeTrustedState(this.#email, { version, checksum });
    });
  }

  /**
   * Applies one change to the in-memory vault and saves it. If the save fails
   * for any reason, the in-memory vault is reloaded from the server, so what
   * the user sees always matches what is actually stored.
   */
  #enqueueWrite(mutate) {
    return this.#enqueue(async () => {
      const expectedVersion = this.#vault.version;
      const result = await mutate(); // validation errors throw here, before anything changed
      if (this.#vault.version === expectedVersion) {
        return result; // nothing changed (e.g. deleting something already gone)
      }
      try {
        const { serializedVault, checksum, version } = await this.#vault.dump();
        await apiClient.putVault(serializedVault, expectedVersion);
        await writeTrustedState(this.#email, { version, checksum });
        return result;
      } catch (error) {
        try {
          this.#vault = await VaultSession.#fetchAndVerify(this.#email, this.#keys);
        } catch {
          // Reload failed too. Surface the original error.
        }
        if (error instanceof ApiError && error.status === 409) {
          throw new SyncConflictError();
        }
        throw error;
      }
    });
  }

  /** Runs `task` after every previously queued task has finished. */
  #enqueue(task) {
    const run = this.#writeQueue.then(task, task);
    this.#writeQueue = run.catch(() => {});
    return run;
  }
}

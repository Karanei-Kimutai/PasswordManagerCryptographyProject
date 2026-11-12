/**
 * @file trustedStateStore.js
 *
 * The device's memory of the newest vault it has seen: the web app's
 * version of the coursework's "trusted storage" for the rollback checksum.
 *
 * ─── Why this lives on the device ───────────────────────────────────────
 *
 * Coursework Short Answer 3 established that rollback can only be detected
 * with some state the attacker cannot modify. In Tessera the attacker we
 * defend against is the server (or anyone who controls it), so that state
 * cannot be on the server. It lives here, in the browser's localStorage, which
 * the server cannot write to.
 *
 * We store, per account:
 *   { version, checksum }  the highest vault version seen, and the SHA-256
 *                          checksum of that exact serialized vault.
 *
 * Vault.load() then refuses any vault with a lower version (rollback) or with
 * the same version but a different checksum (fork).
 *
 * ─── Honest limitations ─────────────────────────────────────────────────
 *
 * - First sign-in on a new device has nothing to compare against
 *   ("trust on first use"). From then on, that device is protected.
 * - Clearing site data resets the memory to that first-use state.
 * - The version number is protected against forgery by the vault's integrity
 *   tag, so a malicious server cannot fake a *higher* version to get past
 *   this check.
 */

const storagePrefix = "tessera.trustedState.";

/**
 * Hashes the email for the storage key, so localStorage does not hold a
 * readable list of the accounts used on this device.
 *
 * @param {string} email
 * @returns {Promise<string>}
 */
async function storageKeyFor(email) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(email.trim().toLowerCase()));
  const hex = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
  return storagePrefix + hex.slice(0, 32);
}

/**
 * @param {string} email
 * @returns {Promise<{ version: number, checksum: string } | null>}
 */
export async function readTrustedState(email) {
  try {
    const raw = localStorage.getItem(await storageKeyFor(email));
    if (!raw) {
      return null;
    }
    const parsed = JSON.parse(raw);
    if (Number.isSafeInteger(parsed.version) && typeof parsed.checksum === "string") {
      return parsed;
    }
  } catch {
    // Storage unavailable (private mode, blocked) or corrupted: treat as first use.
  }
  return null;
}

/**
 * Records a newly seen vault version. Never moves backwards.
 *
 * @param {string} email
 * @param {{ version: number, checksum: string }} state
 */
export async function writeTrustedState(email, state) {
  try {
    const current = await readTrustedState(email);
    if (current && current.version > state.version) {
      return;
    }
    localStorage.setItem(await storageKeyFor(email), JSON.stringify({ version: state.version, checksum: state.checksum }));
  } catch {
    // Without storage we lose rollback detection on this device, but the vault still works.
  }
}

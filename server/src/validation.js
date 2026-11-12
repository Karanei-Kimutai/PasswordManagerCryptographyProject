/**
 * @file validation.js
 *
 * Validates request bodies. The server cannot check anything *inside* the
 * encrypted vault (it has no keys), but it can and should check that the
 * shapes it stores are what an honest client would send.
 */

import { VAULT_FORMAT, VAULT_FORMAT_VERSION, base64ToBytes, validateKdfParameters } from "@tessera/crypto";

/** Thrown for any malformed request; turned into a 400 response. */
export class RequestValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = "RequestValidationError";
  }
}

/** Maximum size of a serialized vault, in characters (≈ 1,400 entries). */
export const MAX_VAULT_CHARACTERS = 8 * 1024 * 1024;

/**
 * @param {unknown} email
 * @returns {string} The trimmed email.
 */
export function validateEmail(email) {
  if (typeof email !== "string") {
    throw new RequestValidationError("Email is required");
  }
  const trimmed = email.trim();
  // Deliberately simple: something@something.something, at most 254 characters.
  if (trimmed.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) {
    throw new RequestValidationError("Enter a valid email address");
  }
  return trimmed;
}

/**
 * An authKey is the Base64 encoding of exactly 32 bytes (one HMAC-SHA256 output).
 *
 * @param {unknown} authKey
 * @returns {string}
 */
export function validateAuthKey(authKey) {
  if (typeof authKey !== "string" || authKey.length > 64) {
    throw new RequestValidationError("Invalid authentication key");
  }
  let bytes;
  try {
    bytes = base64ToBytes(authKey);
  } catch {
    throw new RequestValidationError("Invalid authentication key");
  }
  if (bytes.length !== 32) {
    throw new RequestValidationError("Invalid authentication key");
  }
  return authKey;
}

/**
 * @param {unknown} kdf
 * @param {{ allowWeakKdf: boolean }} config
 */
export function validateKdf(kdf, config) {
  try {
    validateKdfParameters(kdf, { allowWeakKdf: config.allowWeakKdf });
  } catch (error) {
    throw new RequestValidationError(error.message);
  }
  return { algorithm: kdf.algorithm, iterations: kdf.iterations, salt: kdf.salt };
}

/**
 * Checks the *outer* shape of a serialized vault and returns its version.
 *
 * We also check that the vault's KDF salt matches the account's salt. An
 * honest client never sends a mismatched vault, and catching it here stops
 * an account from ending up with a vault nobody can open.
 *
 * @param {unknown} serializedVault
 * @param {{ kdfSalt: string, kdfIterations: number }} account
 * @returns {number} The vault's version number.
 */
export function validateSerializedVault(serializedVault, account) {
  if (typeof serializedVault !== "string" || serializedVault.length > MAX_VAULT_CHARACTERS) {
    throw new RequestValidationError("Invalid vault");
  }
  let parsed;
  try {
    parsed = JSON.parse(serializedVault);
  } catch {
    throw new RequestValidationError("Vault is not valid JSON");
  }
  if (
    !parsed ||
    parsed.format !== VAULT_FORMAT ||
    parsed.formatVersion !== VAULT_FORMAT_VERSION ||
    !Number.isSafeInteger(parsed.version) ||
    parsed.version < 0 ||
    typeof parsed.integrityTag !== "string" ||
    !parsed.records ||
    typeof parsed.records !== "object"
  ) {
    throw new RequestValidationError("Unrecognized vault format");
  }
  if (parsed.kdf?.salt !== account.kdfSalt || parsed.kdf?.iterations !== account.kdfIterations) {
    throw new RequestValidationError("Vault key-derivation parameters do not match the account");
  }
  return parsed.version;
}

/**
 * @param {unknown} value
 * @returns {number}
 */
export function validateExpectedVersion(value) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RequestValidationError("expectedVersion must be a non-negative integer");
  }
  return value;
}

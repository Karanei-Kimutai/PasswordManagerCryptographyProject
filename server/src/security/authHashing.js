/**
 * @file authHashing.js
 *
 * Server-side hashing of the client's `authKey`.
 *
 * Why hash something that is already a derived key? If the database leaked
 * and we had stored authKey as-is, the attacker could log in as every user
 * immediately (though still not decrypt their vaults). Storing
 * scrypt(authKey) means a leaked database holds nothing that can be replayed.
 *
 * Why scrypt? It is built into Node (no extra dependency) and is
 * *memory-hard*: each evaluation needs N × r × 128 bytes of RAM (32 MiB with
 * the parameters below), which makes large-scale GPU or ASIC attacks
 * expensive. The PBKDF2 already applied on the client makes guessing the
 * master password slow; this adds a second, independent layer on the server.
 */

import { randomBytes, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(scryptCallback);

const SCRYPT_PARAMETERS = Object.freeze({ N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
const HASH_BYTES = 32;
const HASH_SALT_BYTES = 16;

/**
 * Hashes an authKey with a fresh random salt.
 *
 * @param {string} authKey - Base64 string received from the client.
 * @returns {Promise<{ authHash: string, authHashSalt: string }>}
 */
export async function hashAuthKey(authKey) {
  const salt = randomBytes(HASH_SALT_BYTES);
  const hash = await scrypt(authKey, salt, HASH_BYTES, SCRYPT_PARAMETERS);
  return { authHash: hash.toString("base64"), authHashSalt: salt.toString("base64") };
}

/**
 * Checks an authKey against a stored hash, comparing in constant time.
 *
 * @param {string} authKey
 * @param {string} authHash
 * @param {string} authHashSalt
 * @returns {Promise<boolean>}
 */
export async function verifyAuthKey(authKey, authHash, authHashSalt) {
  const candidate = await scrypt(authKey, Buffer.from(authHashSalt, "base64"), HASH_BYTES, SCRYPT_PARAMETERS);
  const expected = Buffer.from(authHash, "base64");
  return candidate.length === expected.length && timingSafeEqual(candidate, expected);
}

/**
 * Burns the same amount of time as a real verification. Used when the email
 * does not exist, so response timing does not reveal which emails have
 * accounts.
 *
 * @returns {Promise<void>}
 */
export async function simulateAuthKeyVerification() {
  await scrypt("dummy-auth-key", randomBytes(HASH_SALT_BYTES), HASH_BYTES, SCRYPT_PARAMETERS);
}

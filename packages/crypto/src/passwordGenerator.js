/**
 * @file passwordGenerator.js
 *
 * Generates random passwords that are uniformly distributed over the chosen
 * character pool, and estimates their strength in bits of entropy.
 *
 * ─── Modulo bias, and why we avoid it ──────────────────────────────────
 *
 * The obvious approach, `pool[randomByte % pool.length]`, is subtly biased.
 * With a 62-character pool, a random byte (0–255) covers 256 values, and
 * 256 = 4 × 62 + 8. The first 8 characters of the pool can be produced 5 ways,
 * the other 54 only 4 ways, so the first 8 come up 25% more often. That
 * makes generated passwords slightly easier to guess.
 *
 * **Rejection sampling** fixes it. Draw a random 32-bit number. If it falls in
 * the incomplete final "block" (the leftover 2^32 mod n values), throw it
 * away and draw again. What remains divides evenly into n buckets, so every
 * index is exactly equally likely. The expected number of redraws is tiny
 * (under 2^-24 for any pool we use).
 *
 * ─── Required character classes ────────────────────────────────────────
 *
 * Many websites insist on "at least one digit" and similar rules. If a
 * generated password is missing an enabled class, we discard the whole
 * password and generate a new one. Rejecting whole passwords (instead of, say,
 * overwriting a random position with a digit) keeps the result uniform over
 * all passwords that satisfy the rules.
 */

import { getRandomBytes } from "./encoding.js";

export const CHARACTER_SETS = Object.freeze({
  lowercase: "abcdefghijklmnopqrstuvwxyz",
  uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  digits: "0123456789",
  symbols: "!@#$%^&*()-_=+[]{};:,.<>?/~",
});

/** Characters that are easy to confuse when read or retyped by hand. */
export const AMBIGUOUS_CHARACTERS = "Il1O0o";

export const MIN_GENERATED_LENGTH = 8;
export const MAX_GENERATED_LENGTH = 128;

/**
 * @typedef {object} GeneratorOptions
 * @property {number}  [length=20]
 * @property {boolean} [lowercase=true]
 * @property {boolean} [uppercase=true]
 * @property {boolean} [digits=true]
 * @property {boolean} [symbols=true]
 * @property {boolean} [excludeAmbiguous=false]
 */

/**
 * Returns a uniformly random integer in [0, upperBound) using rejection
 * sampling over 32-bit values from the CSPRNG.
 *
 * @param {number} upperBound - Between 1 and 2^32.
 * @returns {number}
 */
export function randomIndex(upperBound) {
  if (!Number.isInteger(upperBound) || upperBound < 1 || upperBound > 2 ** 32) {
    throw new RangeError("upperBound must be an integer between 1 and 2^32");
  }
  const range = 2 ** 32;
  // Largest multiple of upperBound that fits in 32 bits. Values at or above it
  // fall in the incomplete final block and are rejected.
  const acceptLimit = range - (range % upperBound);
  for (;;) {
    const bytes = getRandomBytes(4);
    const value = ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
    if (value < acceptLimit) {
      return value % upperBound;
    }
  }
}

/**
 * Builds the character classes enabled by `options`, with ambiguous
 * characters removed if requested.
 *
 * @param {GeneratorOptions} options
 * @returns {string[]} One string per enabled class.
 */
export function buildCharacterClasses(options) {
  const classes = [];
  for (const className of Object.keys(CHARACTER_SETS)) {
    if (options[className]) {
      let characters = CHARACTER_SETS[className];
      if (options.excludeAmbiguous) {
        characters = [...characters].filter((character) => !AMBIGUOUS_CHARACTERS.includes(character)).join("");
      }
      classes.push(characters);
    }
  }
  return classes;
}

/**
 * Generates a password.
 *
 * @param {GeneratorOptions} [options]
 * @returns {string}
 */
export function generatePassword(options = {}) {
  const settings = {
    length: 20,
    lowercase: true,
    uppercase: true,
    digits: true,
    symbols: true,
    excludeAmbiguous: false,
    ...options,
  };
  if (
    !Number.isInteger(settings.length) ||
    settings.length < MIN_GENERATED_LENGTH ||
    settings.length > MAX_GENERATED_LENGTH
  ) {
    throw new RangeError(`Length must be between ${MIN_GENERATED_LENGTH} and ${MAX_GENERATED_LENGTH}`);
  }
  const characterClasses = buildCharacterClasses(settings);
  if (characterClasses.length === 0) {
    throw new Error("Select at least one character type");
  }
  const pool = characterClasses.join("");

  // With length ≥ 8 and at most 4 classes, a password missing a class is
  // rare, so this loop almost always finishes on its first or second pass.
  for (let attempt = 0; attempt < 1000; attempt++) {
    let password = "";
    for (let position = 0; position < settings.length; position++) {
      password += pool[randomIndex(pool.length)];
    }
    const containsEveryClass = characterClasses.every((characters) =>
      [...password].some((character) => characters.includes(character)),
    );
    if (containsEveryClass) {
      return password;
    }
  }
  throw new Error("Could not generate a password meeting the requirements");
}

/**
 * Estimated entropy of a password generated with these options, in bits:
 * length × log2(pool size).
 *
 * This is the attacker's work factor *if they know exactly how the password
 * was generated*. That is the honest measure for random passwords. It
 * slightly overestimates, because the "every class present" rule removes a
 * small fraction of possible passwords.
 *
 * @param {GeneratorOptions} options
 * @returns {number}
 */
export function estimateEntropyBits(options) {
  const poolSize = buildCharacterClasses(options).join("").length;
  if (poolSize === 0) {
    return 0;
  }
  return options.length * Math.log2(poolSize);
}

/**
 * Turns an entropy estimate into a label plus a plain-language explanation,
 * so the UI explains *why* rather than showing a bare coloured bar.
 *
 * Thresholds: an offline attacker against a fast hash might manage around
 * 10^12 guesses per second (≈ 2^40), so 2^40 guesses take about a second;
 * 2^60 takes decades; 2^80 is out of reach.
 *
 * @param {number} entropyBits
 * @returns {{ level: "weak" | "fair" | "strong" | "excellent", label: string, explanation: string }}
 */
export function describeStrength(entropyBits) {
  if (entropyBits < 45) {
    return {
      level: "weak",
      label: "Weak",
      explanation: "Could be cracked quickly by an attacker with a leaked password hash. Increase the length.",
    };
  }
  if (entropyBits < 65) {
    return {
      level: "fair",
      label: "Fair",
      explanation: "Resists casual attacks but not a determined offline attacker. Add length if the site allows it.",
    };
  }
  if (entropyBits < 90) {
    return {
      level: "strong",
      label: "Strong",
      explanation: "Out of reach for offline guessing with current hardware.",
    };
  }
  return {
    level: "excellent",
    label: "Excellent",
    explanation: "Far beyond any feasible guessing attack.",
  };
}

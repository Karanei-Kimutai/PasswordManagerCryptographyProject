/**
 * @file primitives.test.js
 *
 * Tests for the building blocks: encoding, canonical JSON, padding, key
 * derivation and the password generator.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  AMBIGUOUS_CHARACTERS,
  CHARACTER_SETS,
  MAX_RECORD_PAYLOAD_BYTES,
  RECORD_PLAINTEXT_BYTES,
  RecordTooLargeError,
  base64ToBytes,
  bytesToBase64,
  canonicalJson,
  constantTimeEqual,
  createKdfParameters,
  deriveVaultKeys,
  describeStrength,
  estimateEntropyBits,
  generatePassword,
  padRecord,
  randomIndex,
  stringToBytes,
  unpadRecord,
  validateKdfParameters,
} from "../src/index.js";

describe("encoding", () => {
  it("round-trips bytes through Base64", () => {
    const bytes = Uint8Array.from({ length: 300 }, (_, index) => index % 256);
    assert.deepEqual(base64ToBytes(bytesToBase64(bytes)), bytes);
  });

  it("produces the same canonical JSON regardless of key order", () => {
    assert.equal(canonicalJson({ b: 1, a: { d: [1, 2], c: null } }), canonicalJson({ a: { c: null, d: [1, 2] }, b: 1 }));
    assert.equal(canonicalJson({ b: 1, a: 2 }), '{"a":2,"b":1}');
  });

  it("compares strings in constant time correctly", () => {
    assert.equal(constantTimeEqual("abc", "abc"), true);
    assert.equal(constantTimeEqual("abc", "abd"), false);
    assert.equal(constantTimeEqual("abc", "ab"), false);
  });
});

describe("padding", () => {
  it("pads every payload to the same size and round-trips exactly", () => {
    for (const text of ["", "x", "ab\u0000cd", "😀".repeat(100)]) {
      const padded = padRecord(stringToBytes(text));
      assert.equal(padded.length, RECORD_PLAINTEXT_BYTES);
      assert.deepEqual(unpadRecord(padded), stringToBytes(text));
    }
  });

  it("accepts the maximum payload and rejects one byte more", () => {
    padRecord(new Uint8Array(MAX_RECORD_PAYLOAD_BYTES));
    assert.throws(() => padRecord(new Uint8Array(MAX_RECORD_PAYLOAD_BYTES + 1)), RecordTooLargeError);
  });
});

describe("key derivation", () => {
  const fastKdf = () => createKdfParameters({ iterations: 1000 });

  it("is deterministic for the same password and salt", async () => {
    const kdf = fastKdf();
    const first = await deriveVaultKeys("password", kdf, { allowWeakKdf: true });
    const second = await deriveVaultKeys("password", kdf, { allowWeakKdf: true });
    assert.equal(first.authKey, second.authKey);
    assert.equal(first.passwordCheck, second.passwordCheck);
  });

  it("separates keys: authKey and passwordCheck differ from each other", async () => {
    const keys = await deriveVaultKeys("password", fastKdf(), { allowWeakKdf: true });
    assert.notEqual(keys.authKey, keys.passwordCheck);
  });

  it("gives unrelated keys for different salts", async () => {
    const first = await deriveVaultKeys("password", fastKdf(), { allowWeakKdf: true });
    const second = await deriveVaultKeys("password", fastKdf(), { allowWeakKdf: true });
    assert.notEqual(first.authKey, second.authKey);
  });

  it("normalizes Unicode in the master password", async () => {
    const kdf = fastKdf();
    const composed = await deriveVaultKeys("café", kdf, { allowWeakKdf: true });
    const decomposed = await deriveVaultKeys("café", kdf, { allowWeakKdf: true });
    assert.equal(composed.authKey, decomposed.authKey);
  });

  it("makes every CryptoKey non-extractable", async () => {
    const keys = await deriveVaultKeys("password", fastKdf(), { allowWeakKdf: true });
    for (const key of [keys.recordKey, keys.indexKey, keys.integrityKey]) {
      assert.equal(key.extractable, false);
    }
    assert.deepEqual([...keys.recordKey.usages].sort(), ["decrypt", "encrypt"]);
  });

  it("rejects weak or malformed KDF parameters", () => {
    assert.throws(() => validateKdfParameters(createKdfParameters({ iterations: 1000 })), /below the minimum/);
    assert.throws(() => validateKdfParameters({ algorithm: "MD5", iterations: 600000, salt: "AAAA" }), /Unsupported/);
    assert.throws(
      () => validateKdfParameters({ algorithm: "PBKDF2-SHA256", iterations: 600000, salt: bytesToBase64(new Uint8Array(4)) }),
      /salt length/,
    );
    validateKdfParameters(createKdfParameters());
  });
});

describe("password generator", () => {
  it("generates passwords of the requested length containing every enabled class", () => {
    for (let run = 0; run < 50; run++) {
      const password = generatePassword({ length: 12 });
      assert.equal(password.length, 12);
      for (const characters of Object.values(CHARACTER_SETS)) {
        assert.ok([...password].some((character) => characters.includes(character)));
      }
    }
  });

  it("respects disabled classes and the ambiguous-character option", () => {
    for (let run = 0; run < 50; run++) {
      const password = generatePassword({ length: 30, symbols: false, uppercase: false, excludeAmbiguous: true });
      assert.match(password, /^[a-z0-9]+$/);
      assert.ok(![...password].some((character) => AMBIGUOUS_CHARACTERS.includes(character)));
    }
  });

  it("rejects invalid options", () => {
    assert.throws(() => generatePassword({ length: 4 }), RangeError);
    assert.throws(() => generatePassword({ lowercase: false, uppercase: false, digits: false, symbols: false }));
  });

  it("draws indices uniformly (rough chi-squared check)", () => {
    const buckets = new Array(10).fill(0);
    const draws = 20000;
    for (let index = 0; index < draws; index++) {
      buckets[randomIndex(10)] += 1;
    }
    const expected = draws / 10;
    const chiSquared = buckets.reduce((sum, observed) => sum + (observed - expected) ** 2 / expected, 0);
    // 9 degrees of freedom: chi-squared exceeds 27.9 with probability 0.001.
    assert.ok(chiSquared < 27.9, `chi-squared ${chiSquared}`);
  });

  it("estimates entropy and explains strength", () => {
    const bits = estimateEntropyBits({ length: 20, lowercase: true, uppercase: true, digits: true, symbols: false });
    assert.ok(Math.abs(bits - 20 * Math.log2(62)) < 1e-9);
    assert.equal(describeStrength(bits).level, "excellent");
    assert.equal(describeStrength(30).level, "weak");
  });
});

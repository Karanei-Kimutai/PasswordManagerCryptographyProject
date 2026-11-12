/**
 * @file vault.test.js
 *
 * Tests for the Vault: the coursework's original functionality and security
 * tests, adapted to the new API, plus attacks that matter once the vault
 * lives on a server we do not trust (swap, tampering, deletion, version
 * forgery, rollback and fork).
 *
 * PBKDF2 runs with 1,000 iterations here (via `allowWeakKdf`) so the suite
 * stays fast. The app itself refuses anything below 100,000.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  INTEGRITY_TAG_CONTEXT,
  RECORD_PLAINTEXT_BYTES,
  DuplicateEntryError,
  EntryValidationError,
  RecordTooLargeError,
  RollbackError,
  Vault,
  VaultIntegrityError,
  WrongPasswordError,
  bytesToBase64,
  canonicalJson,
  createKdfParameters,
  deriveVaultKeys,
  normalizeSite,
  stringToBytes,
} from "../src/index.js";

const testIterations = { iterations: 1000 };
const weakKdfAllowed = { allowWeakKdf: true };
const masterPassword = "correct horse battery staple";

/** Creates fresh keys and an empty vault. */
async function createTestVault(password = masterPassword) {
  const keys = await deriveVaultKeys(password, createKdfParameters(testIterations), weakKdfAllowed);
  return { keys, vault: Vault.create(keys) };
}

/** Re-signs a tampered vault body with the real integrity key. Simulates an
 *  attacker who could somehow bypass the whole-vault tag, so we can test
 *  that the per-record defenses still hold on their own. */
async function resignVault(body, integrityKey) {
  const { integrityTag: _unused, ...rest } = body;
  const input = INTEGRITY_TAG_CONTEXT + canonicalJson(rest);
  const tag = await globalThis.crypto.subtle.sign("HMAC", integrityKey, stringToBytes(input));
  return canonicalJson({ ...rest, integrityTag: bytesToBase64(tag) });
}

describe("Vault: functionality (coursework tests, adapted)", () => {
  it("creates an empty vault without error", async () => {
    const { vault } = await createTestVault();
    assert.equal(vault.size, 0);
    assert.equal(vault.version, 0);
  });

  it("can set and retrieve an entry", async () => {
    const { vault } = await createTestVault();
    await vault.setEntry({ site: "www.google.com", username: "alice", password: "hunter2", notes: "" });
    const entry = await vault.getEntry("www.google.com", "alice");
    assert.equal(entry.password, "hunter2");
    assert.equal(entry.username, "alice");
  });

  it("can set and retrieve multiple entries", async () => {
    const { vault } = await createTestVault();
    const sites = ["service1.com", "service2.com", "service3.com"];
    for (const [index, site] of sites.entries()) {
      await vault.setEntry({ site, username: "bob", password: `pass${index}` });
    }
    for (const [index, site] of sites.entries()) {
      assert.equal((await vault.getEntry(site, "bob")).password, `pass${index}`);
    }
  });

  it("returns null for entries that do not exist", async () => {
    const { vault } = await createTestVault();
    await vault.setEntry({ site: "example.com", username: "a", password: "x" });
    assert.equal(await vault.getEntry("example.com", "b"), null);
    assert.equal(await vault.getEntry("other.com", "a"), null);
  });

  it("can remove an entry, and reports whether something was removed", async () => {
    const { vault } = await createTestVault();
    const entry = await vault.setEntry({ site: "example.com", username: "a", password: "x" });
    assert.equal(vault.removeEntry(entry.id), true);
    assert.equal(await vault.getEntry("example.com", "a"), null);
    assert.equal(vault.removeEntry(entry.id), false);
  });

  it("can dump and restore the vault", async () => {
    const { keys, vault } = await createTestVault();
    await vault.setEntry({ site: "github.com", username: "carol", password: "pw1", notes: "work account" });
    await vault.setEntry({ site: "github.com", username: "carol-personal", password: "pw2" });
    const { serializedVault, checksum, version } = await vault.dump();

    const restored = await Vault.load(keys, serializedVault, { trustedState: { version, checksum } });
    assert.equal(restored.size, 2);
    assert.equal((await restored.getEntry("github.com", "carol")).notes, "work account");
    assert.equal((await restored.getEntry("github.com", "carol-personal")).password, "pw2");
  });

  it("rejects the wrong master password", async () => {
    const { keys, vault } = await createTestVault();
    const { serializedVault } = await vault.dump();
    const wrongKeys = await deriveVaultKeys("not the password", keys.kdf, weakKdfAllowed);
    await assert.rejects(Vault.load(wrongKeys, serializedVault), WrongPasswordError);
  });

  it("supports several accounts on the same website", async () => {
    const { vault } = await createTestVault();
    await vault.setEntry({ site: "mail.com", username: "one", password: "a" });
    await vault.setEntry({ site: "mail.com", username: "two", password: "b" });
    assert.equal(vault.size, 2);
  });

  it("treats URL spellings of the same site as one site", async () => {
    const { vault } = await createTestVault();
    await vault.setEntry({ site: "https://www.GitHub.com/login", username: "dan", password: "x" });
    assert.equal((await vault.getEntry("github.com", "dan")).password, "x");
    await assert.rejects(vault.setEntry({ site: "github.com", username: "dan", password: "y" }), DuplicateEntryError);
  });

  it("edits an entry in place and keeps createdAt", async () => {
    const { vault } = await createTestVault();
    const original = await vault.setEntry({ site: "a.com", username: "u", password: "old" });
    const edited = await vault.setEntry({ site: "a.com", username: "u", password: "new" }, { previousId: original.id });
    assert.equal(edited.id, original.id);
    assert.equal(edited.createdAt, original.createdAt);
    assert.equal((await vault.getEntry("a.com", "u")).password, "new");
  });

  it("moves an entry when its username changes", async () => {
    const { vault } = await createTestVault();
    const original = await vault.setEntry({ site: "a.com", username: "old", password: "p" });
    const moved = await vault.setEntry({ site: "a.com", username: "new", password: "p" }, { previousId: original.id });
    assert.notEqual(moved.id, original.id);
    assert.equal(vault.size, 1);
    assert.equal(await vault.getEntry("a.com", "old"), null);
  });

  it("validates entries", async () => {
    const { vault } = await createTestVault();
    await assert.rejects(vault.setEntry({ site: "", password: "x" }), EntryValidationError);
    await assert.rejects(vault.setEntry({ site: "a.com", password: "" }), EntryValidationError);
    await assert.rejects(
      vault.setEntry({ site: "a.com", password: "x", notes: "n".repeat(2001) }),
      EntryValidationError,
    );
  });

  it("increments the version on every change", async () => {
    const { vault } = await createTestVault();
    const entry = await vault.setEntry({ site: "a.com", password: "x" });
    await vault.setEntry({ site: "b.com", password: "x" });
    vault.removeEntry(entry.id);
    assert.equal(vault.version, 3);
  });

  it("re-encrypts everything under new keys when the master password changes", async () => {
    const { vault } = await createTestVault();
    await vault.setEntry({ site: "a.com", username: "u", password: "secret" });
    const newKeys = await deriveVaultKeys("a new master password", createKdfParameters(testIterations), weakKdfAllowed);
    const rekeyed = await vault.rekey(newKeys);
    const { serializedVault } = await rekeyed.dump();

    const restored = await Vault.load(newKeys, serializedVault);
    assert.equal((await restored.getEntry("a.com", "u")).password, "secret");
    assert.equal(restored.version, vault.version + 1);
    // The old password no longer opens it.
    const oldKeys = await deriveVaultKeys(masterPassword, newKeys.kdf, weakKdfAllowed);
    await assert.rejects(Vault.load(oldKeys, serializedVault), WrongPasswordError);
  });
});

describe("Vault: security", () => {
  it("does not store sites, usernames, passwords or the master password in the clear", async () => {
    const { vault } = await createTestVault();
    await vault.setEntry({ site: "secret-site.com", username: "secret-user", password: "secret-pass", notes: "secret-note" });
    const { serializedVault } = await vault.dump();
    for (const forbidden of ["secret-site", "secret-user", "secret-pass", "secret-note", masterPassword]) {
      assert.ok(!serializedVault.includes(forbidden), `dump contains "${forbidden}"`);
    }
  });

  it("includes exactly one record per entry", async () => {
    const { vault } = await createTestVault();
    await vault.setEntry({ site: "a.com", password: "x" });
    await vault.setEntry({ site: "b.com", password: "y" });
    const parsed = JSON.parse((await vault.dump()).serializedVault);
    assert.equal(Object.keys(parsed.records).length, 2);
  });

  it("produces ciphertexts of identical length regardless of content", async () => {
    const { vault } = await createTestVault();
    await vault.setEntry({ site: "a.com", password: "x" });
    await vault.setEntry({ site: "b.com", username: "ü".repeat(255), password: "😀".repeat(128), notes: "日本".repeat(250) });
    await vault.setEntry({ site: "c.com", password: "ab\u0000cd" });
    const parsed = JSON.parse((await vault.dump()).serializedVault);
    const lengths = new Set(Object.values(parsed.records).map((record) => record.ciphertext.length));
    assert.equal(lengths.size, 1);
    assert.equal((await vault.getEntry("c.com", "")).password, "ab\u0000cd");
  });

  it("rejects an entry too large for one padded record", async () => {
    const { vault } = await createTestVault();
    // 1,000 emoji = 2,000 UTF-16 units (within the 2,000-character notes limit)
    // but 4,000 UTF-8 bytes, which together with the other fields exceeds the
    // 4,094-byte payload limit. Limits must be enforced in bytes.
    const notes = "😀".repeat(1000);
    await assert.rejects(vault.setEntry({ site: "a.com", password: "x", notes }), RecordTooLargeError);
    assert.equal(RECORD_PLAINTEXT_BYTES, 4096);
  });

  it("encrypts identical entries to different ciphertexts (random IVs)", async () => {
    const { vault } = await createTestVault();
    await vault.setEntry({ site: "a.com", username: "1", password: "same" });
    await vault.setEntry({ site: "a.com", username: "2", password: "same" });
    const parsed = JSON.parse((await vault.dump()).serializedVault);
    const [first, second] = Object.values(parsed.records);
    assert.notEqual(first.iv, second.iv);
    assert.notEqual(first.ciphertext, second.ciphertext);
  });

  it("detects a swap attack via the whole-vault integrity tag", async () => {
    const { keys, vault } = await createTestVault();
    await vault.setEntry({ site: "bank.com", password: "bank-pass" });
    await vault.setEntry({ site: "evil.com", password: "evil-pass" });
    const parsed = JSON.parse((await vault.dump()).serializedVault);
    const [locatorA, locatorB] = Object.keys(parsed.records);
    [parsed.records[locatorA], parsed.records[locatorB]] = [parsed.records[locatorB], parsed.records[locatorA]];
    await assert.rejects(Vault.load(keys, JSON.stringify(parsed)), VaultIntegrityError);
  });

  it("detects a swap attack via AES-GCM associated data alone (independent of the tag)", async () => {
    const { keys, vault } = await createTestVault();
    const bank = await vault.setEntry({ site: "bank.com", password: "bank-pass" });
    const evil = await vault.setEntry({ site: "evil.com", password: "evil-pass" });
    const parsed = JSON.parse((await vault.dump()).serializedVault);
    [parsed.records[bank.id], parsed.records[evil.id]] = [parsed.records[evil.id], parsed.records[bank.id]];

    // Pretend the attacker defeated the integrity tag: the vault now loads...
    const loaded = await Vault.load(keys, await resignVault(parsed, keys.integrityKey));
    // ...but reading the swapped records still fails, so no password is revealed.
    await assert.rejects(loaded.getEntry("evil.com", ""), VaultIntegrityError);
    await assert.rejects(loaded.getEntry("bank.com", ""), VaultIntegrityError);
  });

  it("detects a modified ciphertext", async () => {
    const { keys, vault } = await createTestVault();
    const entry = await vault.setEntry({ site: "a.com", password: "x" });
    const parsed = JSON.parse((await vault.dump()).serializedVault);
    const bytes = Uint8Array.from(atob(parsed.records[entry.id].ciphertext), (character) => character.charCodeAt(0));
    bytes[10] ^= 0x01;
    parsed.records[entry.id].ciphertext = bytesToBase64(bytes);
    await assert.rejects(Vault.load(keys, JSON.stringify(parsed)), VaultIntegrityError);
  });

  it("detects a deleted record", async () => {
    const { keys, vault } = await createTestVault();
    const entry = await vault.setEntry({ site: "a.com", password: "x" });
    await vault.setEntry({ site: "b.com", password: "y" });
    const parsed = JSON.parse((await vault.dump()).serializedVault);
    delete parsed.records[entry.id];
    await assert.rejects(Vault.load(keys, JSON.stringify(parsed)), VaultIntegrityError);
  });

  it("detects a forged version number", async () => {
    const { keys, vault } = await createTestVault();
    await vault.setEntry({ site: "a.com", password: "x" });
    const parsed = JSON.parse((await vault.dump()).serializedVault);
    parsed.version = 999;
    await assert.rejects(Vault.load(keys, JSON.stringify(parsed)), VaultIntegrityError);
  });

  it("detects a rollback to an older, genuine version", async () => {
    const { keys, vault } = await createTestVault();
    await vault.setEntry({ site: "a.com", password: "old-password" });
    const oldDump = await vault.dump();
    await vault.setEntry({ site: "a.com", password: "new-password" }, { previousId: (await vault.getEntry("a.com", "")).id });
    const newDump = await vault.dump();

    const trustedState = { version: newDump.version, checksum: newDump.checksum };
    await assert.rejects(Vault.load(keys, oldDump.serializedVault, { trustedState }), RollbackError);
    // Without trusted state, the stale copy is indistinguishable from a real one,
    // which is exactly coursework Short Answer 3.
    await Vault.load(keys, oldDump.serializedVault);
  });

  it("detects a fork: same version number, different contents", async () => {
    const { keys, vault } = await createTestVault();
    const base = await vault.dump();
    const forkA = Vault.create(keys);
    await forkA.setEntry({ site: "a.com", password: "x" });
    const forkB = await Vault.load(keys, base.serializedVault);
    await forkB.setEntry({ site: "b.com", password: "y" });
    const dumpA = await forkA.dump();
    const dumpB = await forkB.dump();
    assert.equal(dumpA.version, dumpB.version);
    await assert.rejects(
      Vault.load(keys, dumpB.serializedVault, { trustedState: { version: dumpA.version, checksum: dumpA.checksum } }),
      VaultIntegrityError,
    );
  });

  it("accepts a newer version made on another device", async () => {
    const { keys, vault } = await createTestVault();
    const seen = await vault.dump();
    await vault.setEntry({ site: "a.com", password: "x" });
    const newer = await vault.dump();
    const loaded = await Vault.load(keys, newer.serializedVault, { trustedState: { version: seen.version, checksum: seen.checksum } });
    assert.equal(loaded.version, 1);
  });

  it("produces pseudorandom locators that differ between vaults", async () => {
    const first = await createTestVault();
    const second = await createTestVault();
    const entryOne = await first.vault.setEntry({ site: "a.com", password: "x" });
    const entryTwo = await second.vault.setEntry({ site: "a.com", password: "x" });
    assert.notEqual(entryOne.id, entryTwo.id);
  });
});

describe("normalizeSite", () => {
  it("normalizes URLs and hostnames", () => {
    assert.equal(normalizeSite("https://www.GitHub.com/login?x=1"), "github.com");
    assert.equal(normalizeSite("  Example.org/path "), "example.org");
    assert.equal(normalizeSite("localhost:8080"), "localhost:8080");
  });

  it("leaves free-text labels intact apart from case", () => {
    assert.equal(normalizeSite("My Bank / Savings"), "my bank / savings");
  });
});

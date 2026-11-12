# Testing

```bash
npm test                      # everything
npm test -w packages/crypto   # crypto core only (fast, < 1 s)
npm test -w server            # API end-to-end (a few seconds; scrypt is deliberately slow)
```

Both suites use Node's built-in test runner (`node:test` + `node:assert/strict`), so there are no test-framework dependencies.

Tests run PBKDF2 with **1,000** iterations (`allowWeakKdf: true`) so they finish quickly. The app itself refuses anything below 100,000.

## Crypto core: `packages/crypto/test/` (46 tests)

### `vault.test.js`: functionality (the coursework tests, adapted)

| Coursework test | Tessera equivalent |
|---|---|
| inits without an error | creates an empty vault |
| can set and retrieve a password | can set and retrieve an entry |
| can set and retrieve multiple passwords | can set and retrieve multiple entries |
| returns null for non-existent passwords | returns null for entries that do not exist |
| can remove a password / returns false … | can remove an entry, and reports whether something was removed |
| can dump and restore the database | can dump and restore the vault |
| fails to restore if checksum is wrong | (now: rollback, fork and tamper tests below) |
| returns false for an incorrect password | rejects the wrong master password |

Plus new behaviour: several accounts per site, URL normalization, editing (keeping `createdAt`), moving an entry when its username changes, validation, version counting and re-keying.

### `vault.test.js`: security (simulated attacks)

| Test | Attack simulated |
|---|---|
| does not store sites, usernames, passwords or the master password in the clear | reading the dump |
| includes exactly one record per entry | (coursework `kvs` check) |
| produces ciphertexts of identical length | length analysis, with ASCII, accented, CJK, emoji and `\0` |
| rejects an entry too large for one padded record | byte-versus-character limit confusion |
| encrypts identical entries to different ciphertexts | equality analysis (IV reuse) |
| detects a swap attack via the whole-vault integrity tag | swap |
| **detects a swap attack via AES-GCM associated data alone** | swap, *with the integrity tag bypassed*, proving the defenses are independent |
| detects a modified ciphertext | bit-flipping |
| detects a deleted record | deletion |
| detects a forged version number | version forgery |
| detects a rollback to an older, genuine version | rollback (and shows that without trusted state it is undetectable: Short Answer 3) |
| detects a fork | equivocation |
| accepts a newer version made on another device | (no false positives) |
| produces pseudorandom locators that differ between vaults | locator linkability |

### `primitives.test.js`

Base64 round-trips, canonical JSON stability, constant-time compare, padding bounds, KDF determinism, key separation, salt uniqueness, **Unicode normalization**, **non-extractable keys and restricted usages**, KDF parameter validation (minimum iterations, salt length), and generator tests (length, classes, ambiguous characters, invalid options, a **chi-squared uniformity check**, entropy).

## Server: `server/test/api.test.js` (17 tests)

These start a real Express server on a random port with an in-memory SQLite database. The test client uses the **real crypto package** to derive keys and build vaults, exactly as the browser does.

- **Accounts:** register, sign in, session; duplicate email (case-insensitive); generic wrong-password message; **no account enumeration** (stable fake salt, same error); **authKey not stored in the clear**; **rate limiting** (429); sign out.
- **Vault storage:** auth required; stored vault is ciphertext and decrypts client-side; **409 on a stale save from another device**; version must advance by exactly one; **CSRF:** non-JSON (415) and cross-origin (403) refused; security headers present.
- **Malicious server:** the test edits the database directly to **serve an older vault**, and the client's `Vault.load` throws `RollbackError`.
- **Master password change:** data survives re-encryption, old password rejected, new one works, other devices signed out, current password required.

## Manual / browser verification

During development, the full UI was driven in headless Chromium (Playwright) against a production build: sign-up, adding items (including a pasted URL), duplicate detection, search, edit with the generator, delete confirmation, generator and settings views, lock, wrong password, unlock, reload-locks, a mobile layout, both colour schemes, and a **staged rollback attack** (the old vault written back into SQLite), which the UI refused with the "Possible rollback attack" warning. No CSP violations or script errors were logged.

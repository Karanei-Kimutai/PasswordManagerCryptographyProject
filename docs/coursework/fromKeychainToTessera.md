# From Keychain to Tessera

This page maps the original coursework (**ICS 3201 Project 1**, adapted from Stanford CS255) onto the web application. The original code is preserved, unchanged, on the **`keychain-coursework`** branch:

```bash
git checkout keychain-coursework   # the original Keychain library + Mocha tests
git checkout main                  # Tessera
```

The original materials are kept in this folder: [handout](proj1%20documentation.pdf), [README](KeychainReadme.md) and [short answers](ProjectShortAnswers.md).

## API mapping

| `Keychain` (coursework) | `Vault` (Tessera) | Notes |
|---|---|---|
| `static init(password)` | `deriveVaultKeys()` + `Vault.create(keys)` | Key derivation is split out, so sign-in can derive keys *before* fetching the vault |
| `static load(password, repr, trustedDataCheck)` | `Vault.load(keys, repr, { trustedState })` | Trusted SHA-256 checksum → trusted `{ version, checksum }` per device |
| `dump()` → `[repr, checksum]` | `dump()` → `{ serializedVault, checksum, version }` | |
| `get(name)` | `getEntry(site, username)`, `getEntryById(id)` | O(1) via HMAC locator |
| `set(name, value)` | `setEntry(fields, { previousId })` | Values are whole entries; edits can rename |
| `remove(name)` | `removeEntry(id)` | |
| (none) | `listEntries()`, `rekey(newKeys)` | The app needs a list view and password changes |

## Requirement-by-requirement

| Requirement | Coursework | Tessera |
|---|---|---|
| PBKDF2 from password + 128-bit salt, **once** | ✔ 100k iterations | ✔ **600k**, and the count is stored and validated |
| HMAC as PRF for sub-keys | 2 keys + password check | 5 values: `recordKey`, `indexKey`, `integrityKey`, `authKey`, `passwordCheck` |
| Encrypt each record separately (AES-GCM) | ✔ | ✔ AES-256-GCM, random 96-bit IV |
| Hide domains: KVS keys are HMACs | `HMAC(domain)` | `HMAC(normalizedSite ‖ \0 ‖ username)` |
| Hide password lengths (≤ 64 chars) | pad to 193 bytes | pad **whole entries** to 4,096 bytes |
| Swap defense | AAD = domain | AAD = locator, independently tested |
| Rollback defense | SHA-256 in trusted storage | whole-vault HMAC + monotonic version + per-device trusted state |
| Swap defense works without the checksum | ✔ | ✔ (test with a bypassed integrity tag) |
| Never store secrets | ✔ | ✔ and the server never even receives them |

## Short answers, revisited

1. **Hiding lengths:** implemented, generalized from passwords to whole entries ([record encryption](../concepts/recordEncryption.md)).
2. **Swap attacks:** implemented as AAD, now with a second, independent layer, the integrity tag ([record encryption](../concepts/recordEncryption.md)).
3. **Is trusted storage necessary for rollback defense?** Our answer was "yes, or an equivalent like a monotonic counter". Tessera *uses* a monotonic counter, protected by a MAC, and keeps the trusted state on each device, because in a web app the storage (the server) is the adversary. A test also shows the converse: without trusted state, a rollback is undetectable ([vault integrity](../concepts/vaultIntegrityAndRollback.md)).
4. **Randomized MAC lookup:** would be O(n). Tessera's deterministic HMAC locators keep O(1) lookup ([record indexing](../concepts/recordIndexing.md)).
5. **Leaking only log₂(k) records:** *not implemented*, by scope decision. The item count is visible to the server ([threat model](../threatModel.md)). Adding power-of-two dummy records would fit the current format without changes.
6. **Per-site sharing between users:** *not implemented*, by scope decision. The per-record design would allow it: give a shared record its own key, wrapped with each user's public key.

## What changed from the coursework, and why

| Change | Why |
|---|---|
| `lib.js` → `encoding.js` without Node's `Buffer` | The core must run in browsers |
| Mocha + expect.js → `node:test` | No test-framework dependencies; the same runner for both packages |
| 100k → 600k PBKDF2 iterations, stored with the salt | Current OWASP guidance; upgradeable |
| Domain → site + username | Several accounts per site |
| Password → full entry with notes and timestamps | A usable password manager |
| SHA-256 checksum → MAC + version + trusted state | Multiple devices legitimately change the vault, and the storage is the attacker |
| New `authKey` | Logging in to a server without revealing the password |

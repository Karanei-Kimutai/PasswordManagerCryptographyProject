# Changing the master password

**Code:** `VaultSession.changeMasterPassword` in [`client/src/services/vaultSession.js`](../../client/src/services/vaultSession.js), `Vault.rekey` in [`vault.js`](../../packages/crypto/src/vault.js), `POST /api/account/master-password` in [`vaultRoutes.js`](../../server/src/routes/vaultRoutes.js)

## Why it's more than updating a hash

In a conventional app, changing a password just replaces a hash. In Tessera, **every key is derived from the master password**, so a new password means:

- a **new salt** (fresh randomness for the new derivation),
- new `recordKey`, `indexKey`, `integrityKey`, `authKey` and `passwordCheck`,
- every record **decrypted with the old key and re-encrypted with the new one**, with new IVs and, because `indexKey` changed, new locators.

All of that has to happen in the browser, because only the browser ever holds the keys.

## The flow

```
Browser                                                   Server
───────                                                   ──────
1. derive keys from the *current* password + current salt
   and compare its authKey with the session's (constant time)
   → wrong? stop with "Current master password is incorrect"
2. newKdf  ← fresh salt, 600,000 iterations
   newKeys ← deriveVaultKeys(newPassword, newKdf)
3. rekeyed ← vault.rekey(newKeys)        (decrypt each → re-encrypt; version + 1)
4. POST /api/account/master-password
   { currentAuthKey, newAuthKey, newKdf, vault, expectedVersion } ─▶
                                         verify scrypt(currentAuthKey)
                                         in ONE transaction:
                                           UPDATE vault WHERE version = expected
                                           UPDATE users SET kdf, scrypt(newAuthKey)
                                           DELETE other sessions
                                         ◀─ 200 { version }
5. adopt newKeys and rekeyed vault; update trusted state
```

## Design decisions

- **The server re-checks the current password**, even though the request comes with a valid session. Someone who walks up to an unlocked, signed-in browser must not be able to take over the account by setting a new password.
- **One atomic transaction.** If the vault update and the credential update could happen separately, a crash between them would leave an account whose vault is encrypted under one password while the server checks another, so nobody could use it. SQLite's transaction makes it all-or-nothing.
- **`rekey` doesn't modify the original vault.** If the server rejects the change (wrong password, conflict, network error), the app keeps working with the old vault and keys.
- **Version + 1.** Re-keying counts as a change, so the version keeps increasing and the rollback defense stays intact. Old copies encrypted under the *old* password are older versions and will be refused.
- **Other devices are signed out**, because their in-memory keys are now stale. They sign in again with the new password.
- **Conflicts:** if another device saved in the meantime, the server answers 409. The client reloads and asks the user to try again.

## Test coverage

`server/test/api.test.js` → `master password change`: re-encrypts and keeps data, old password rejected, new password works, other device signed out, current password required.
`packages/crypto/test/vault.test.js` → `re-encrypts everything under new keys`.

# Vault integrity and rollback defense

**Code:** `Vault.load`, `Vault.dump` and `#integrityTagInput` in [`vault.js`](../../packages/crypto/src/vault.js); [`trustedStateStore.js`](../../client/src/services/trustedStateStore.js); version checks in [`vaultRoutes.js`](../../server/src/routes/vaultRoutes.js)

Per-record AES-GCM proves each record is genuine. It cannot prove that the vault *as a whole* is the right one. An attacker can still:

- **delete** a record (every remaining record is still genuine),
- **re-insert** a record the user deleted,
- **roll back** the entire vault to an older, genuine copy.

The coursework countered rollback with a SHA-256 checksum kept in "trusted storage". In a multi-device web app the vault legitimately changes on other devices, and the attacker is the storage itself, so Tessera uses three cooperating mechanisms.

## 1. The integrity tag: authenticate the whole vault

```
integrityTag = HMAC-SHA256( integrityKey,
                 "tessera/v1/vault-integrity-tag\n" +
                 canonicalJson({ format, formatVersion, kdf, version, passwordCheck, records }) )
```

Everything in the serialized vault except the tag itself is covered. Without `integrityKey`, nobody can produce a valid tag, so any deletion, insertion, swap, modification **or change to the version number** is detected when the vault is loaded (`VaultIntegrityError`).

### Why canonical JSON?

A MAC is computed over bytes, and `JSON.stringify` preserves key insertion order. If the record map came back from a database in a different order, the bytes would differ and an honest vault would fail verification. `canonicalJson` sorts object keys at every level and emits no whitespace, so the same logical vault always yields the same bytes. The vault is also *stored* in canonical form, so its checksum is reproducible.

### Why a context prefix?

The fixed string `tessera/v1/vault-integrity-tag\n` is **domain separation**: it guarantees that this HMAC input can never be confused with any other message authenticated under the same key, now or in future versions.

## 2. A monotonic version counter

Every change (add, edit, delete, re-key) increments `version` by exactly 1. The version is inside the integrity tag, so **it cannot be forged upward** by anyone without the key.

The server enforces the counter's monotonicity for honest clients through **optimistic concurrency**:

```sql
UPDATE vaults SET version = :new, data = :vault
WHERE userId = :user AND version = :expectedVersion
```

- The client sends `expectedVersion` (the version it edited) and a vault whose version is exactly `expectedVersion + 1`.
- If another device saved first, no row matches, and the server answers **409 Conflict**. The client reloads the latest vault and asks the user to redo the change, so neither device silently overwrites the other.
- The check and the write happen in a single SQL statement, so they are atomic.

## 3. Trusted state on each device

Coursework Short Answer 3 argued that rollback detection *requires* state the attacker cannot modify. Our attacker is the server, so that state lives on the **device**, in `localStorage`:

```js
{ version: 12, checksum: "Base64(SHA-256(serialized vault v12))" }
```

It is updated after every successful load and save, and never moves backwards. When loading, `Vault.load(keys, vault, { trustedState })` checks:

| Received vault | Verdict | Meaning |
|---|---|---|
| version **>** remembered | ✅ accept | Another device made changes |
| version **=** remembered, same checksum | ✅ accept | Nothing changed |
| version **=** remembered, **different** checksum | ❌ `VaultIntegrityError` ("fork") | Someone is showing different histories to different devices |
| version **<** remembered | ❌ `RollbackError` | Replay of an old vault |

The UI shows a rollback as a clear security warning that names both versions, and refuses to open the vault.

### Order of checks in `Vault.load`

1. Format recognized → otherwise `VaultFormatError`
2. KDF parameters match the derived keys
3. `passwordCheck` matches (constant-time) → otherwise `WrongPasswordError`
4. Integrity tag verifies → otherwise `VaultIntegrityError`
5. Rollback and fork check against trusted state
6. Structural check of every record (IV and ciphertext sizes)

Records are **not** decrypted during load. Each one is decrypted when read, and its own GCM tag and AAD are checked then.

## How the pieces fit

| Attack | Stopped by |
|---|---|
| Delete or re-insert a record | integrity tag |
| Change the version number | integrity tag |
| Replay an old genuine vault | version + trusted state |
| Fork histories across devices | checksum in trusted state |
| Two honest devices racing | optimistic concurrency (409) |

## Limitations

- **Trust on first use:** a new device (or one with cleared storage) has no memory and will accept whatever genuine vault it is given first.
- The server can always *withhold* updates (serve nothing, or keep serving the latest version a device already saw). Integrity does not guarantee freshness beyond what that device has seen. Only out-of-band communication between devices can close that gap.

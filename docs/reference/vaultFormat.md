# Serialized vault format (v1)

`Vault.dump()` produces this document. It is what the server stores and returns, so **every field is safe for the server to see**.

```json
{
  "format": "tessera-vault",
  "formatVersion": 1,
  "integrityTag": "pZ2…=",
  "kdf": { "algorithm": "PBKDF2-SHA256", "iterations": 600000, "salt": "q3c0jR2b…==" },
  "passwordCheck": "e1Zp…=",
  "records": {
    "Xb9Wf0…=": { "ciphertext": "Jd8f…(5,484 chars)…==", "iv": "pS1xYw…" },
    "7Hq2Lm…=": { "ciphertext": "Kq3n…==",                "iv": "Ww0aQe…" }
  },
  "version": 12
}
```

The document is serialized as **canonical JSON**: keys sorted at every level, no whitespace. That's why `integrityTag` appears near the top.

## Fields

| Field | Type | Content | Why it's safe to store |
|---|---|---|---|
| `format` | string | always `"tessera-vault"` | constant |
| `formatVersion` | integer | `1` | constant, and covered by the tag (no downgrade) |
| `kdf.algorithm` | string | `"PBKDF2-SHA256"` | public parameter |
| `kdf.iterations` | integer | `600000` for new vaults | public parameter |
| `kdf.salt` | Base64, 16 bytes | random salt | salts are not secret |
| `version` | integer | monotonic change counter | covered by the tag, so it can't be forged |
| `passwordCheck` | Base64, 32 bytes | `HMAC(masterKey, "tessera/v1/password-check")` | PRF output; reveals nothing about the password beyond allowing a (600k-iteration) guess check |
| `records` | object | `locator → { iv, ciphertext }` | see below |
| `integrityTag` | Base64, 32 bytes | HMAC over everything else | MAC tag |

### Records

| Part | Size | Content |
|---|---|---|
| key (locator) | 32 bytes → 44 Base64 chars | `HMAC(indexKey, normalizedSite ‖ "\0" ‖ username)` |
| `iv` | 12 bytes → 16 chars | random per encryption |
| `ciphertext` | 4,096 + 16 bytes → 5,484 chars | `AES-256-GCM(recordKey, iv, pad(entryJson), AAD = "tessera/v1/record\n" ‖ locator)` |

Every record has exactly these sizes. `Vault.load` rejects any record that doesn't (`VaultFormatError`).

### Decrypted record payload

Inside the padding (never visible to the server):

```json
{
  "site": "github.com",
  "username": "ada",
  "password": "…",
  "notes": "…",
  "createdAt": "2026-11-12T13:36:00.000Z",
  "updatedAt": "2026-11-12T13:36:00.000Z"
}
```

## Integrity tag input

```
"tessera/v1/vault-integrity-tag\n" + canonicalJson({ format, formatVersion, kdf, version, passwordCheck, records })
```

## Checksum

`computeChecksum(serializedVault)` = Base64(SHA-256(the exact serialized string)). Devices keep it as trusted state (see [vault integrity](../concepts/vaultIntegrityAndRollback.md)).

## Evolving the format

- A breaking change bumps `formatVersion`. Old clients reject vaults they don't understand rather than misreading them.
- Key-derivation labels are versioned (`tessera/v1/…`), so a v2 format can derive fresh, independent keys.
- KDF parameters travel with the vault, so the iteration count can grow without migrating existing vaults. Re-keying on the next password change upgrades them.

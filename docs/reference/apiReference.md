# HTTP API reference

Base path: `/api`. All request and response bodies are JSON.

**Common rules**

- Every non-GET request must send `Content-Type: application/json`, or it gets `415`.
- If an `Origin` header is present, it must match the server's host, or it gets `403`.
- Authenticated endpoints need the `tessera_session` cookie (set by register and login), or they get `401`.
- Errors look like `{ "error": "Human-readable message" }`.
- Responses carry `Cache-Control: no-store` and the security headers in [webSecurity.md](../concepts/webSecurity.md).

Types used below:

```ts
type Kdf = { algorithm: "PBKDF2-SHA256", iterations: number /* ≥ 100000 */, salt: string /* Base64, 16 bytes */ };
type AuthKey = string;          // Base64 of exactly 32 bytes
type SerializedVault = string;  // canonical JSON, see vaultFormat.md (≤ 8 MiB)
```

---

## Authentication

### `POST /api/auth/prelogin`

Returns the KDF parameters needed to derive keys for an email. **Never reveals whether the account exists:** unknown emails get a stable fake salt.

| | |
|---|---|
| Body | `{ email: string }` |
| 200 | `{ kdf: Kdf }` |
| 400 | invalid email |

### `POST /api/auth/register`

Creates an account with an empty (version 0) encrypted vault and starts a session.

| | |
|---|---|
| Body | `{ email, kdf: Kdf, authKey: AuthKey, vault: SerializedVault }` |
| 201 | `{ email }` + `Set-Cookie` |
| 400 | invalid fields; vault version ≠ 0; vault KDF ≠ `kdf` |
| 409 | email already registered |
| 429 | rate limited |

### `POST /api/auth/login`

| | |
|---|---|
| Body | `{ email, authKey: AuthKey }` |
| 200 | `{ email }` + `Set-Cookie` |
| 401 | `Incorrect email or master password` (same for unknown emails) |
| 429 | rate limited (10 per 15 min per IP + email), with a `Retry-After` header |

### `POST /api/auth/logout`

Ends the current session and clears the cookie. Body `{}`. Always `204`.

### `GET /api/auth/session` 🔒

| | |
|---|---|
| 200 | `{ email }` |
| 401 | no or expired session |

---

## Vault

### `GET /api/vault` 🔒

| | |
|---|---|
| 200 | `{ vault: SerializedVault, version: number, updatedAt: string }` |

### `PUT /api/vault` 🔒

Replaces the vault using **optimistic concurrency**.

| | |
|---|---|
| Body | `{ vault: SerializedVault, expectedVersion: number }` |
| Rule | `vault.version` must equal `expectedVersion + 1`, and its KDF must match the account's |
| 200 | `{ version }` |
| 400 | malformed, wrong version step, or KDF mismatch |
| 409 | `{ error, currentVersion }`: another device saved first. Reload and retry. |
| 413 | vault too large |

### `POST /api/account/master-password` 🔒

Atomically replaces credentials and the re-encrypted vault, and revokes all *other* sessions.

| | |
|---|---|
| Body | `{ currentAuthKey, newAuthKey, newKdf: Kdf, vault: SerializedVault, expectedVersion }` |
| Rule | `vault` must use `newKdf`, and `vault.version = expectedVersion + 1` |
| 200 | `{ version }` |
| 401 | current password incorrect (or no session) |
| 409 | vault changed on another device |

---

## Database schema (for reference)

```sql
users    (id, email UNIQUE NOCASE, kdfAlgorithm, kdfIterations, kdfSalt, authHash, authHashSalt, createdAt)
vaults   (userId PK → users, version, data, updatedAt)
sessions (tokenHash PK, userId → users, createdAt, expiresAt)
```

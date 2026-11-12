# Architecture

Tessera follows the **zero-knowledge** (or "end-to-end encrypted") model used by real password managers: **all cryptography happens in the browser, and the server is treated as untrusted storage.**

## The three parts

```
┌─────────────────────────── Browser (trusted while unlocked) ───────────────────────────┐
│                                                                                         │
│   React UI (client/src/components)                                                      │
│        │  plaintext entries, only in memory, only while unlocked                        │
│        ▼                                                                                │
│   VaultSession (client/src/services/vaultSession.js)                                    │
│        │  orchestrates: derive keys → authenticate → fetch → verify → decrypt           │
│        ▼                                                                                │
│   @tessera/crypto (packages/crypto)  ◀── Web Crypto API (SubtleCrypto, CSPRNG)          │
│        │  PBKDF2 · HMAC · AES-256-GCM · SHA-256 · padding · integrity tag               │
│        ▼                                                                                │
│   trustedStateStore (localStorage)  ── highest vault version seen + its checksum        │
│                                                                                         │
└──────────────────────────────┬──────────────────────────────────────────────────────────┘
                               │ HTTPS: email, salt, authKey, encrypted vault, nothing else
┌──────────────────────────────▼───────────────── Server (untrusted) ─────────────────────┐
│   Express 5 (server/src)                                                                │
│     security headers · CSRF guard · rate limiting · sessions (HttpOnly cookie)          │
│     routes: /api/auth/*  /api/vault  /api/account/master-password                       │
│        ▼                                                                                │
│   SQLite (better-sqlite3): users(kdf params, scrypt(authKey)) · vaults(ciphertext)      │
│                            sessions(SHA-256(token))                                     │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

### 1. `@tessera/crypto` (`packages/crypto/`)

The cryptographic core, the successor of the coursework's `password-manager.js` and `lib.js`. It uses **only** web-standard APIs (`crypto.subtle`, `crypto.getRandomValues`, `TextEncoder`, `btoa`/`atob`), so the same code runs:

- in the **browser**, where it does the real work;
- in **Node**, for the tests and for a few shared helpers on the server (validation constants, Base64).

| File | Responsibility |
|---|---|
| `constants.js` | Every tunable security parameter in one place |
| `encoding.js` | Bytes ↔ strings ↔ Base64, CSPRNG bytes, constant-time compare, canonical JSON |
| `keyDerivation.js` | Master password → PBKDF2 → master key → five sub-keys |
| `padding.js` | Fixed-size record padding (length hiding) |
| `vault.js` | The `Vault` class: encrypt, decrypt, index, serialize, verify and re-key |
| `passwordGenerator.js` | Unbiased password generation and entropy estimates |
| `errors.js` | Typed errors (`WrongPasswordError`, `RollbackError`, …) |

### 2. The server (`server/`)

A deliberately small Express 5 application. It **cannot** decrypt anything. Its jobs are:

- to authenticate users (by checking `scrypt(authKey)`, never a password),
- to store and return one opaque vault per user,
- to enforce **optimistic concurrency** (version numbers) so devices don't overwrite each other,
- to apply HTTP hardening: CSP, security headers, a CSRF guard and rate limiting.

| File | Responsibility |
|---|---|
| `index.js` / `config.js` | Startup and configuration |
| `app.js` | Express app assembly and the central error handler |
| `database.js` | SQLite schema and prepared statements |
| `validation.js` | Request-shape validation |
| `routes/authRoutes.js` | prelogin, register, login, logout, session |
| `routes/vaultRoutes.js` | get/put vault, change master password |
| `security/authHashing.js` | scrypt hashing of `authKey` |
| `security/sessions.js` | Session tokens and cookies |
| `security/httpProtections.js` | Headers, CSRF guard, rate limiter |

### 3. The client (`client/`)

A React 18 single-page app built with Vite.

| File | Responsibility |
|---|---|
| `App.jsx` | Top-level state machine: loading → signedOut / locked → unlocked |
| `services/vaultSession.js` | Sign up, sign in, save, delete, change password; owns the keys while unlocked |
| `services/apiClient.js` | `fetch` wrapper for the JSON API |
| `services/trustedStateStore.js` | Per-device rollback memory (localStorage) |
| `services/clipboard.js` | Copy with automatic clearing |
| `hooks/useIdleTimer.js` | Auto-lock after inactivity |
| `components/*` | Auth/lock screen, list, detail, form, generator, settings |
| `styles/tokens.css`, `styles/app.css` | Design tokens and component styles |

## Key flows

### Create an account

```
Browser                                               Server
───────                                               ──────
salt ← CSPRNG(16 bytes)
keys ← deriveVaultKeys(masterPassword, salt)          (PBKDF2 ×600k, then HMAC sub-keys)
vault ← Vault.create(keys); dump()                    (empty, version 0, integrity-tagged)
POST /api/auth/register {email, kdf, authKey, vault} ─▶ store kdf, scrypt(authKey), vault
                                                     ◀─ Set-Cookie: session
remember {version 0, checksum} as trusted state
```

### Sign in / unlock

```
POST /api/auth/prelogin {email}                     ─▶ {kdf: salt, iterations}
keys ← deriveVaultKeys(masterPassword, kdf)            (refuses iterations < 100,000)
POST /api/auth/login {email, authKey}               ─▶ verify scrypt(authKey)
                                                    ◀─ Set-Cookie: session
GET  /api/vault                                     ─▶ {vault}
Vault.load(keys, vault, {trustedState})                password check → integrity tag →
                                                       rollback/fork check
decrypt entries for display
```

### Save a change

```
expectedVersion ← vault.version
vault.setEntry(…)  (encrypt one record, version + 1)
PUT /api/vault {vault, expectedVersion}             ─▶ UPDATE … WHERE version = expectedVersion
                                                    ◀─ 200 {version} | 409 conflict
on success: trusted state ← {version, checksum}
on failure: reload the vault from the server (UI always shows what is actually stored)
```

### Lock

The `VaultSession` object, which holds the only references to the `CryptoKey`s, is discarded, along with every decrypted entry in React state. The session cookie remains, so unlocking skips nothing except retyping the email. The master password is required again, because the keys no longer exist.

## Why this split?

- **The server is the adversary in our threat model** (see [threatModel.md](threatModel.md)). Everything it stores is safe to leak.
- **The crypto core is a separate, framework-free package**, so it can be tested exhaustively in Node, including against simulated attacks, without a browser or a server.
- **The server is small**, so it is easy to review. It has no cryptographic secrets of its own that matter for vault confidentiality.

# Threat model

A security design is only meaningful relative to an adversary. This page states who Tessera defends against, what it guarantees, and where its protection ends.

## Assets

1. **Item contents:** websites, usernames, passwords, notes.
2. **The master password**, and every key derived from it.
3. **Metadata:** which sites a user has accounts on, how many, and how long their passwords are.
4. **Integrity:** the user sees exactly the latest vault they saved, unmodified.

## Adversaries

### A1. Someone who steals the server's database (or the server operator)

They can read everything the server stores: emails, salts, iteration counts, `scrypt(authKey)` hashes, session-token hashes, and every encrypted vault.

**Guarantees:**

| They want to… | Why they can't |
|---|---|
| Read items | Each record is AES-256-GCM encrypted under `recordKey`, which is derived from the master password, and the server never had either |
| Learn which sites are stored | Locators are HMAC outputs under `indexKey` (a PRF), and site names exist only inside ciphertexts |
| Learn password or note lengths | Every record is padded to exactly 4,096 bytes before encryption |
| Log in as the user | Only `scrypt(authKey)` is stored, so the hash cannot be replayed as a credential |
| Hijack sessions | Only `SHA-256(token)` is stored |
| Recover the master password | Offline guessing is possible (unavoidable for any password-based system), but each guess costs 600,000 PBKDF2-HMAC-SHA256 iterations, and checking a guess against the scrypt hash adds a memory-hard 32 MiB scrypt computation |

**What leaks (accepted):** the number of items, when the vault changes, its approximate size, and account emails.

### A2. A malicious or compromised server that *actively* modifies data

This is the coursework's adversary, who could "replace the database with anything it likes".

| Attack | Defense | Detected where |
|---|---|---|
| **Swap** two records | Record locator is GCM associated data, and the whole-vault integrity tag covers the record map | `Vault.load` (tag), `#decryptRecord` (AAD), independently |
| **Modify** a record | GCM authentication tag, plus the integrity tag | `Vault.load` |
| **Delete or re-insert** a record | Integrity tag covers the full record set | `Vault.load` |
| **Forge a higher version** | Version is covered by the integrity tag | `Vault.load` |
| **Roll back** to an older, genuine vault | Device remembers the highest version seen and refuses lower ones | `Vault.load` with `trustedState` |
| **Fork:** show different devices different histories | Same version but different checksum is rejected | `Vault.load` with `trustedState` |
| **Weaken the KDF** by advertising a low iteration count at prelogin | Client refuses fewer than 100,000 iterations | `validateKdfParameters` |
| **Substitute another user's vault** | Its salt and password check won't match this password | `Vault.load` |

### A3. A network attacker

Defended by HTTPS (HSTS in production). Even without TLS, a passive observer sees only what the server sees (A1), plus `authKey` in transit. Capturing `authKey` would let them log in and fetch the *encrypted* vault, but not decrypt it. TLS is still required.

### A4. Another website the user visits

| Attack | Defense |
|---|---|
| CSRF (forcing state-changing requests) | `SameSite=Strict` cookie, JSON-only bodies, `Origin` check |
| Clickjacking | `frame-ancestors 'none'`, `X-Frame-Options: DENY` |
| Reading API responses | No CORS headers are ever sent, so the browser blocks cross-origin reads |

### A5. Someone with brief physical access to an unlocked device

Mitigated, not prevented: auto-lock after inactivity (default 5 minutes), a manual Lock button, locking on every page reload, passwords masked by default with a reveal that times out, a clipboard that clears after 30 seconds, and re-entry of the current password to change it.

## Out of scope: honest limitations

1. **The server delivers the code.** This is the fundamental limitation of *every* web-based end-to-end encrypted app. A malicious server could ship JavaScript that captures the master password, and no in-page defense can stop that. Mitigations would be native or extension clients, reproducible builds, or Subresource Integrity with out-of-band verification. The strict CSP defends against *third-party* script injection (XSS), not against the origin itself.
2. **A compromised device** (malware, keylogger, malicious browser extension) can read anything the user can.
3. **Rollback protection starts at first use on each device.** A brand-new device, or one whose site data was cleared, has no trusted state to compare against. This is inherent: coursework Short Answer 3 shows that *some* trusted state is required.
4. **Memory hygiene in JavaScript is best-effort.** We zero the byte arrays we control and keep keys as non-extractable `CryptoKey`s, but decrypted strings live in the JS heap until garbage-collected, and we cannot wipe them.
5. **Metadata:** item count and change times are visible to the server. Coursework Short Answer 5 describes padding to the next power of two. It was not implemented here (by scope decision), but the format allows adding it later.
6. **Weak master passwords** remain guessable offline. PBKDF2 slows guessing but cannot make `password123` safe. The sign-up form requires 12+ characters and suggests a passphrase.
7. **No account recovery.** This is a direct consequence of zero knowledge, and the sign-up screen says so.

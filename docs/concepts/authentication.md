# Authentication without revealing the password

**Code:** [`server/src/routes/authRoutes.js`](../../server/src/routes/authRoutes.js), [`security/authHashing.js`](../../server/src/security/authHashing.js), [`security/sessions.js`](../../server/src/security/sessions.js), [`security/httpProtections.js`](../../server/src/security/httpProtections.js), [`client/src/services/vaultSession.js`](../../client/src/services/vaultSession.js)

## The tension

The server must know *who* is asking for a vault, or anyone could download anyone's ciphertext and attack it offline. But the usual approach, sending the password and having the server hash and compare it, would hand the server the very secret that protects the vault.

## The approach: send a derived key, not the password

```
authKey = HMAC(masterKey, "tessera/v1/server-authentication")
```

`authKey` is one of the PRF outputs from [key derivation](keyDerivation.md). It proves the client knows the master password, but it is **useless for decryption**: recovering `recordKey` from it would mean inverting HMAC. This is the same design used by Bitwarden-style password managers.

### Two-step sign-in

The salt is per-user and lives on the server, and the browser needs it before it can derive anything:

```
1. POST /api/auth/prelogin { email }        → { kdf: { algorithm, iterations, salt } }
2. browser: keys = deriveVaultKeys(masterPassword, kdf)    (PBKDF2 runs here, once)
3. POST /api/auth/login    { email, authKey } → Set-Cookie: tessera_session=…
```

## Server-side storage: scrypt(authKey)

The server does not store `authKey` itself. If it did, a database leak would let an attacker log in as every user immediately (though still not decrypt anything). Instead it stores:

```
authHash = scrypt(authKey, random 16-byte salt, N = 2^15, r = 8, p = 1) → 32 bytes
```

- **scrypt** is built into Node (no extra dependency) and **memory-hard**: each evaluation needs N × r × 128 bytes = 32 MiB of RAM, which makes massively parallel GPU or ASIC attacks expensive.
- Comparison uses `crypto.timingSafeEqual`, so response time doesn't reveal how many bytes matched.
- Combined with client-side PBKDF2, an attacker who steals the database and wants to test a password guess must pay **600,000 PBKDF2 iterations + one scrypt** per guess.

## Account-enumeration defenses

An attacker shouldn't be able to learn which emails have accounts:

| Channel | Defense |
|---|---|
| prelogin response | Unknown emails get a **fake but stable** salt, `HMAC(serverSecret, "prelogin:" + email)`. It looks like a real one, and asking twice gives the same answer. |
| login error message | Unknown email and wrong password both return `Incorrect email or master password`. |
| login timing | For unknown emails the server runs a dummy scrypt (`simulateAuthKeyVerification`), so both paths cost the same. |

Registration necessarily reveals that an email is taken (409). This is a common, accepted trade-off.

## Sessions

After login the server issues a session:

- **Token:** 32 bytes from the CSPRNG (256 bits, unguessable), sent as a cookie.
- **Storage:** only `SHA-256(token)` is stored, so a leaked database cannot be turned back into working cookies.
- **Cookie flags:**
  - `HttpOnly`: page JavaScript can't read it, which limits what an XSS bug could steal.
  - `SameSite=Strict`: the browser won't attach it to requests started by other sites (the primary CSRF defense).
  - `Secure` in production: sent over HTTPS only.
  - `Path=/api`, 12-hour lifetime.
- A session grants access to the **encrypted** vault only. Decryption still needs the master password, which is why a page reload shows the *lock* screen rather than the vault.

## CSRF guard

Cross-site request forgery tricks a logged-in browser into making requests. Besides `SameSite=Strict`, every non-GET request must:

1. have `Content-Type: application/json`. HTML forms can't send JSON, and a cross-site `fetch` with JSON triggers a CORS preflight, which this server never approves.
2. if it carries an `Origin` header, come from our own host.

## Rate limiting

Login and registration are limited to **10 attempts per 15 minutes per (IP, email)**, using an in-memory fixed-window counter. This slows *online* guessing. *Offline* guessing is what PBKDF2 and scrypt are for.

## Wrong-password handling in the client

A 401 from login becomes a `WrongPasswordError` in the browser. A vault that loads with a mismatched `passwordCheck` also raises `WrongPasswordError`, distinct from `VaultIntegrityError`, so the user is told "wrong password" rather than "your data was tampered with".

# Key derivation

**Code:** [`packages/crypto/src/keyDerivation.js`](../../packages/crypto/src/keyDerivation.js), parameters in [`constants.js`](../../packages/crypto/src/constants.js)

## The problem

Cryptographic keys must be uniformly random, typically 256 bits. A human-chosen password is neither: it is short, structured, and drawn from a small, guessable space. Using a password directly as a key would make the key only as strong as the password, and checking a guess would cost almost nothing.

A **key-derivation function (KDF)** bridges that gap. Tessera uses two kinds:

1. A **slow, salted password-based KDF** (PBKDF2), run once, to turn the password into a strong master key.
2. A **fast pseudorandom function** (HMAC) to expand that master key into several independent keys.

## Step 1: PBKDF2 (stretching)

```
masterBits = PBKDF2-HMAC-SHA256(password = NFKC(masterPassword),
                                salt     = 16 random bytes,
                                iterations = 600,000,
                                length   = 256 bits)
```

### The salt

A random **128-bit salt** is generated per vault (`createKdfParameters`) and stored in the clear. It is not a secret. Its job is to make every vault's derivation unique:

- Two users with the same password get unrelated keys.
- An attacker cannot build one precomputed table of `password → key` (a *rainbow table*) and reuse it against every user. Each salt needs its own work.

A new salt is generated whenever the master password changes.

### The iteration count

PBKDF2 applies HMAC-SHA256 `iterations` times in a chain. That makes every derivation, including every *guess* an attacker makes, cost 600,000 HMACs.

- The coursework used **100,000**. Tessera uses **600,000**, the OWASP Password Storage Cheat Sheet recommendation for PBKDF2-HMAC-SHA256.
- On a laptop this takes a few hundred milliseconds. That's imperceptible to a user who unlocks once, but crippling for an attacker trying billions of guesses.
- The count is **stored with the salt** (the `kdf` object), so it can be raised for new vaults without breaking old ones. The coursework hard-coded it, which its README listed as a limitation.
- The client **refuses fewer than 100,000 iterations** (`validateKdfParameters`). Otherwise a malicious server could advertise `iterations: 1` at prelogin and make the user's next derivation trivially brute-forceable.

### PBKDF2 runs exactly once

The coursework required this, and it still holds: PBKDF2 is called once per sign-up, unlock or password check, never per item. Everything else is derived from its output with cheap HMAC calls.

> **Why not Argon2 or scrypt in the browser?** They are memory-hard and therefore better against GPU attackers. But neither is part of the Web Crypto API, so they would need a WebAssembly dependency. We kept to native, audited primitives on the client and used scrypt on the server, where Node provides it (see [authentication](authentication.md)).

## Step 2: HMAC as a PRF (key separation)

The 256-bit PBKDF2 output is imported as an HMAC-SHA256 key, `masterKey`. HMAC with a secret key is a **pseudorandom function (PRF)**: to anyone without the key, its outputs are indistinguishable from random, and outputs for different inputs look independent. So we derive each sub-key by "asking the PRF" about a distinct label:

| Sub-key | Label | Type / usages | Purpose |
|---|---|---|---|
| `recordKey` | `tessera/v1/record-encryption` | AES-GCM, `encrypt`/`decrypt` | Encrypts each item |
| `indexKey` | `tessera/v1/record-index` | HMAC, `sign` | Computes record locators (hides sites) |
| `integrityKey` | `tessera/v1/vault-integrity` | HMAC, `sign`/`verify` | Tags the whole vault |
| `authKey` | `tessera/v1/server-authentication` | Base64 bytes | Proves knowledge of the password to the server |
| `passwordCheck` | `tessera/v1/password-check` | Base64 bytes | Stored in the vault; gives a clear "wrong password" error |

This is **key separation**: one key per purpose. It matters because:

- A weakness in how one key is used cannot spill into another.
- Most importantly, **`authKey` can be given to the server safely.** Learning it reveals nothing about `recordKey`, because both are independent PRF outputs and recovering `masterKey` from them would mean breaking HMAC.

The `tessera/v1/` prefix *versions* the labels, so a future format can derive fresh keys without colliding with these.

## Hardening details

### Unicode normalization

The password is normalized with **NFKC** before encoding. "é" can be typed as one code point (U+00E9) or as "e" plus a combining accent (U+0065 U+0301), and different keyboards and operating systems produce different forms. Without normalization, the same visible password could produce different keys on a phone and on a laptop. A test checks this (`normalizes Unicode in the master password`).

### Non-extractable keys and least privilege

Every `CryptoKey` is imported with `extractable: false`, so its bytes can never be read back out by JavaScript, including injected scripts. Only the ciphers can use it. Each key also gets **only the usages it needs**: the record key cannot sign, the index key cannot decrypt.

### Wiping intermediate bytes

The raw password bytes, the PBKDF2 output and each sub-key's raw bytes are overwritten with zeros (`.fill(0)`) as soon as they've been imported. This is best-effort hygiene: JavaScript gives no guarantee against copies, but it shortens how long secrets sit in plain arrays.

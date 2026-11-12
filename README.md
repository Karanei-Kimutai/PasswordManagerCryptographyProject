# Secure Password Manager (Cryptography Project)

The core library of a password manager (a "keychain"), written in JavaScript with the **Web Crypto API (`SubtleCrypto`)** on Node.js. It was built for **ICS 3201 – Computer Security and Cryptography, Project 1**, which is adapted from Stanford's CS255 password manager assignment.

The library keeps a key-value store (KVS) that maps domains to passwords. It protects both the **confidentiality** and the **integrity** of the passwords against a strong adversary who can read, modify, reorder and replace the stored database.

> ⚠️ **This is coursework, not a production password manager.** The project deliberately leaves out many real-world concerns, such as memory hygiene, UI, sync and key rotation.

---

## Table of Contents

1. [The Task](#the-task)
2. [Repository Layout](#repository-layout)
3. [How to Run It](#how-to-run-it)
4. [Design and Implementation](#design-and-implementation)
5. [Security Properties and How They Are Achieved](#security-properties-and-how-they-are-achieved)
6. [Serialized Format](#serialized-format)
7. [Testing](#testing)
8. [Known Limitations](#known-limitations)
9. [What We Learned](#what-we-learned)
10. [Short-Answer Questions](#short-answer-questions)
11. [References](#references)

---

## The Task

The assignment (full handout: [`proj1 documentation.pdf`](./proj1%20documentation.pdf)) was to implement the core of a password manager. We did not build an interactive front end or write to disk. Instead, the library had to **serialize** its state to a string and **deserialize** it again, so a full application could easily be built on top of it.

### Functional requirements

Implement a `Keychain` class in `password-manager.js` with this API:

| Method | Description | Required run-time |
|---|---|---|
| `static async init(password)` | Create a new, empty keychain protected by a master password | O(1) |
| `static async load(password, repr, trustedDataCheck?)` | Restore a keychain from its serialized form. Throw on a wrong password or a failed integrity check | O(n) |
| `async dump()` | Return `[jsonRepr, sha256Checksum]` | O(n) |
| `async set(name, value)` | Insert or update the password for a domain | O(1) |
| `async get(name)` | Return the password for a domain, or `null` | O(1) |
| `async remove(name)` | Delete a domain's record. Return `true` or `false` | O(1) |

### Security requirements

- **Encrypt each record separately** with AES-GCM. Do not encrypt the whole KVS as one blob, so a single lookup does not need to decrypt everything.
- **Hide domain names.** KVS keys must be `HMAC(k, domain)`, not the domain in plaintext.
- **Hide password lengths.** Passwords can be assumed to be at most 64 characters long.
- **Derive keys with PBKDF2** from the master password and a random 128-bit salt. Call PBKDF2 **only once** per operation, then use HMAC as a PRF to derive the sub-keys.
- **Never store** the master password or any secret key in the serialized output, and nothing that would leak information about them.
- **Defend against swap attacks**, where an attacker swaps the encrypted records of two domains.
- **Defend against rollback attacks**, where an attacker restores an older version of the database. The defense uses a SHA-256 checksum that is assumed to be kept in trusted storage.
- The swap and rollback defenses must **work independently**. Swap protection must hold even when no checksum is supplied.

### Threat model (summary)

Security is defined as a CPA-style indistinguishability game. The adversary can:

1. add `(domain, password0, password1)` entries, and the challenger stores one of the two depending on a secret bit `b`
2. remove entries
3. ask for the database to be serialized, then **replace it with anything it likes** before it is loaded again
4. ask for the password of a domain it controls

The adversary wins if it can guess `b` with a non-negligible advantage. The one restriction is that it cannot ask for the password of a domain where `password0 ≠ password1`.

---

## Repository Layout

```
.
├── README.md                     ← this file
├── ProjectShortAnswers.md        ← written answers to the six short-answer questions
├── proj1 documentation.pdf       ← original assignment handout
├── proj1.zip                     ← original starter code (git-ignored)
└── src/
    ├── password-manager.js       ← our implementation (the Keychain class)
    ├── lib.js                    ← provided helpers: buffer/string/Base64 conversion, randomness
    ├── package.json              ← npm metadata; `npm test` runs mocha
    ├── package-lock.json
    └── test/
        └── test-password-manager.js  ← provided Mocha + expect.js test suite
```

As the handout required, all of our code is in **`src/password-manager.js`**. `lib.js` and the tests come from the starter code.

---

## How to Run It

### Prerequisites

- **Node.js** (developed and tested on **v20.19.5**). The code uses `require('crypto').webcrypto.subtle`, so any modern Node version that has Web Crypto works.
- **npm**

### Install and test

```bash
cd src
npm install
npm test
```

Expected output:

```
  Password manager
    functionality
      ✔ inits without an error
      ✔ can set and retrieve a password
      ✔ can set and retrieve multiple passwords
      ✔ returns null for non-existent passwords
      ✔ can remove a password
      ✔ returns false if there is no password for the domain being removed
      ✔ can dump and restore the database
      ✔ fails to restore the database if checksum is wrong
      ✔ returns false if trying to load with an incorrect password
    security
      ✔ doesn't store domain names and passwords in the clear
      ✔ includes a kvs object in the serialized dump

  11 passing (2s)
```

Each test takes about 100–200 ms. Most of that is the deliberately slow PBKDF2 step (100,000 iterations).

### Using the library

Save the following as a file inside `src/` and run it with `node <file>.js`:

```js
const { Keychain } = require("./password-manager");

(async () => {
  // Create a new keychain
  const keychain = await Keychain.init("my master password");

  await keychain.set("www.google.com", "hunter2");
  await keychain.set("www.github.com", "correct horse battery staple");

  console.log(await keychain.get("www.google.com"));  // "hunter2"
  console.log(await keychain.get("www.unknown.com")); // null

  // Serialize. `repr` goes to disk; `checksum` goes to trusted storage.
  const [repr, checksum] = await keychain.dump();

  // Restore later, with the integrity check
  const restored = await Keychain.load("my master password", repr, checksum);
  console.log(await restored.get("www.github.com")); // "correct horse battery staple"

  await restored.remove("www.google.com");            // true
})();
```

---

## Design and Implementation

### Key hierarchy

```
            master password (string)         salt (16 random bytes, stored in plaintext)
                         \                        /
                          PBKDF2-SHA256, 100,000 iterations, 256-bit output
                                        │
                                   masterKey  (HMAC-SHA256 key, used as a PRF)
               ┌────────────────────────┼─────────────────────────┐
  HMAC(masterKey,             HMAC(masterKey,              HMAC(masterKey,
  "domain-key-derivation")    "encryption-key-derivation") "password-check")
               │                        │                          │
           domainKey                 encKey                  passwordCheck
   (HMAC-SHA256 key: hides     (AES-256-GCM key:          (public value: lets load()
     domain names)               encrypts passwords)        reject wrong passwords)
```

- **PBKDF2 runs exactly once** per `init` or `load`. That is the expensive step, and it slows down brute-force guessing of the master password.
- The 256-bit PBKDF2 output becomes an **HMAC key used as a PRF**. Evaluating that PRF on fixed, distinct labels gives independent-looking sub-keys. This is a simple form of key separation, so a weakness in how one key is used cannot spread to the others.
- Every `CryptoKey` is imported as **non-extractable** (`extractable: false`) and only with the usages it needs: `deriveBits`, `sign`, or `encrypt`/`decrypt`.

### State held by a `Keychain`

```js
this.data = {          // public: safe to serialize
  salt,                // Base64 PBKDF2 salt
  kvs,                 // { Base64(HMAC(domainKey, domain)) : { iv, cipher } }
  passwordCheck        // Base64(HMAC(masterKey, "password-check"))
};
this.secrets = {       // private: never serialized
  domainKey,           // CryptoKey (HMAC)
  encKey               // CryptoKey (AES-GCM)
};
```

`dump()` only calls `JSON.stringify(this.data)`, so secrets cannot end up in the output by mistake.

### Method walkthrough

**`init(password)`**
1. Generate a 16-byte random salt.
2. Import the password as PBKDF2 key material and derive 256 bits.
3. Import those bits as an HMAC master key and derive `domainKey`, `encKey` and `passwordCheck`.
4. Return a `Keychain` with an empty KVS.

**`set(name, value)`**
1. `kvsKey = Base64(HMAC(domainKey, name))`.
2. Pad the password to a fixed size with `padPassword` (see [Length-hiding padding](#length-hiding-padding)). Passwords longer than 64 characters are rejected.
3. Generate a fresh random 96-bit IV.
4. `cipher = AES-GCM-Encrypt(encKey, iv, padded, AAD = name)`.
5. Store `kvs[kvsKey] = { iv, cipher }`, overwriting any existing entry.

**`get(name)`**
1. Compute `kvsKey` the same way. If it is missing, return `null`.
2. Decrypt with AAD = `name`. If the GCM tag check fails, **throw** (the record was tampered with or swapped).
3. Remove the padding with `unpadPassword`, using the stored length prefix, and return the password.

**`remove(name)`**: compute `kvsKey`, then `delete` it if present. Returns `true` or `false`.

**`dump()`**: `repr = JSON.stringify(this.data)`, `checksum = Base64(SHA-256(repr))`. Returns `[repr, checksum]`.

**`load(password, repr, trustedDataCheck)`**
1. If a checksum is supplied, recompute `SHA-256(repr)` and **throw** if it does not match. This check runs *before* parsing or the costly key derivation.
2. Parse `repr` and recover the salt.
3. Run PBKDF2 once to re-derive `masterKey`.
4. Recompute `HMAC(masterKey, "password-check")` and **throw "Invalid password!"** if it differs from the stored value.
5. Re-derive `domainKey` and `encKey`, then return the restored `Keychain`.

### Length-hiding padding

Every password is encoded into the **same 193-byte plaintext** before encryption:

```
┌──────────┬──────────────────────────────┬──────────────────────┐
│ len (1B) │ password as UTF-8 (len bytes)│ 0x00 … (zero padding)│
└──────────┴──────────────────────────────┴──────────────────────┘
 └──────────────────────── 193 bytes total ───────────────────────┘
```

- We pad **bytes, not characters**. A JavaScript string of 64 characters (UTF-16 code units) takes at most 64 × 3 = **192 bytes** in UTF-8, so every allowed password fits, whether it is ASCII, accented, CJK or emoji.
- Passwords longer than `MAX_PASSWORD_LENGTH` (64) characters are **rejected** with an exception. Accepting them would produce a visibly longer ciphertext.
- The **length prefix** tells `get` exactly where the password ends. A password that contains `\x00` therefore round-trips correctly, and padding is never confused with data.

As a result, every ciphertext in the KVS is the same size: 193 bytes of plaintext plus a 16-byte GCM tag.

### Complexity

All lookups are a single HMAC plus one object-property access, which gives the required **O(1)** run-time for `get`, `set` and `remove`.

---

## Security Properties and How They Are Achieved

| Threat | Defense | Where in the code |
|---|---|---|
| Reading passwords from the dump | AES-256-GCM encryption under a key derived from the master password | `set` / `get` |
| Learning which domains are stored | KVS keys are `HMAC(domainKey, domain)`. A PRF output reveals nothing about its input without the key | `set` / `get` / `remove` |
| Learning password lengths | Every password is UTF-8 encoded and padded to a fixed 193-byte plaintext, so all ciphertexts are the same size | `padPassword` / `unpadPassword` |
| Linking identical passwords | A fresh random IV per encryption, so equal passwords produce different ciphertexts | `set` (`getRandomBytes(12)`) |
| **Swap attack** | The domain name is used as **AES-GCM associated data (AAD)**. A ciphertext moved under a different domain's key fails authentication when decrypted | `set` / `get` (`additionalData: nameBuffer`) |
| **Rollback attack** | A SHA-256 checksum of the whole serialized state is returned by `dump()`, kept in trusted storage, and checked in `load()` | `dump` / `load` |
| Tampering with any single record | The GCM authentication tag. Any bit flip in `iv` or `cipher` makes decryption throw | `get` |
| Offline brute force of the master password | A random 128-bit salt (rules out precomputed tables) plus 100,000 PBKDF2 iterations (each guess is expensive) | `init` / `load` |
| Leaking the master password or keys | Only the salt, the encrypted KVS and a PRF-derived check value are serialized. Keys are non-extractable `CryptoKey` objects | `constructor` / `dump` |

### Why the swap defense works without the checksum

The handout requires the swap defense to stand on its own. Suppose the adversary swaps the records stored under `HMAC(www.google.com)` and `HMAC(www.evil.com)`. When the user calls `get("www.evil.com")`, decryption uses `"www.evil.com"` as the AAD. That ciphertext's tag was computed with `"www.google.com"` as the AAD, so GCM verification fails and `get` throws. The Google password is never revealed. We checked this with a hand-written test (below).

### Empirical verification

Besides the provided test suite, we ran a separate script against the implementation to confirm these properties:

```
distinct ciphertext lengths: [ 280 ]   ← "", "x", "äöü", 32 emoji, 64×"x", "ab\x00cd" and CJK text all match
all passwords round-trip exactly
>64 chars: Password exceeds the maximum length of 64 characters
swap:      Integrity check failed: Swap attack detected or data corrupted
rollback:  Integrity check failed: Data tampering or rollback attack detected.
wrong pw:  Invalid password!
```

---

## Serialized Format

`dump()[0]` is a JSON string shaped like this:

```json
{
  "salt": "q3c0jR2b...==",
  "kvs": {
    "Xb9Wf0...=": { "iv": "pS1x...", "cipher": "Jd8f...==" },
    "7Hq2Lm...=": { "iv": "Ww0a...", "cipher": "Kq3n...==" }
  },
  "passwordCheck": "e1Zp...="
}
```

All binary values are Base64-encoded (using `encodeBuffer`/`decodeBuffer` from `lib.js`), so the result can be stored as JSON and used as object keys. The top-level `kvs` field is required by the autograder.

`dump()[1]` is the Base64 SHA-256 of that exact string.

---

## Testing

The provided suite, `src/test/test-password-manager.js` (Mocha + expect.js), covers:

- **Functionality:** init, set/get (single and multiple), `null` for missing domains, remove (`true` and `false` cases), dump and load round-trip, rejecting a bad checksum, rejecting a wrong master password.
- **Security:** the dump contains neither the master password, nor the domain, nor the site password in plaintext. The dump has a `kvs` object with exactly one entry per stored domain.

**Result: 11 / 11 passing.**

---

## Known Limitations

1. **Rollback protection is only as strong as the trusted storage.** If `load` is called without `trustedDataCheck`, record deletion and whole-database rollback cannot be detected. This is by design (see Short Answer 3).
2. **`passwordCheck` is a public verifier.** It lets an offline attacker test password guesses, though no faster than trying to decrypt any record with GCM already allows. PBKDF2 still makes each guess cost about 100k HMAC operations. It is a PRF output, so it reveals nothing about the password beyond that.
3. **The record count is leaked.** The handout allows this. Short Answer 5 describes how to reduce it to log₂(k).
4. **Not production-grade.** There is no zeroing of secrets in memory, no protection against side channels, no PBKDF2 iteration count stored for future upgrades, and no key rotation.

### Fixed after the first submission

Reviewing the original submission turned up three padding bugs, which have now been fixed:

- **It padded characters, not bytes.** The original `value.padEnd(64, "\x00")` padded to 64 UTF-16 code units before UTF-8 encoding, so non-ASCII passwords such as `"äöü"` produced longer ciphertexts and leaked length.
- **It accepted passwords over 64 characters.** They were encrypted with visibly longer ciphertexts. They are now rejected.
- **Unpadding stripped every `\x00`.** `replace(/\x00/g, "")` also removed null characters inside a password. An explicit length prefix now marks exactly where the password ends.

---

## What We Learned

- **Use vetted primitives and combine them carefully.** We wrote no cryptography ourselves. All the security comes from *how* PBKDF2, HMAC, AES-GCM and SHA-256 are put together. Most of the attacks the project covers (swap, rollback, length leakage) come from the composition, not from a weak primitive.
- **Encryption alone does not give integrity of meaning.** AES-GCM authenticates the ciphertext, but on its own it does not authenticate *which domain the ciphertext belongs to*. Associated data (AAD) is the clean way to bind context to a ciphertext. That is the whole swap-attack defense in a single parameter.
- **Authenticated encryption cannot stop replay of old, valid data.** A rolled-back database is made entirely of genuine ciphertexts. Detecting it needs state the attacker cannot change, such as a trusted hash, a monotonic counter or an append-only log.
- **Deterministic PRFs enable private lookup.** HMAC is deterministic, so `HMAC(k, domain)` serves as both a pseudonym and a hash-table key, which gives O(1) lookups without revealing domains. A randomized MAC would force an O(n) scan.
- **Ciphertext metadata leaks too.** Lengths, record counts and access patterns all leak information. Fixed-size padding handles length, but getting it right means thinking in **bytes**, not characters. Our first version got this wrong (see [Fixed after the first submission](#fixed-after-the-first-submission)).
- **Key separation and KDFs.** You stretch a low-entropy password once with a slow, salted KDF, then expand the result into many purpose-specific keys with a fast PRF. Each key gets only the minimum usages it needs.
- **Working with `SubtleCrypto`.** It is fully asynchronous (every call needs an `await`), works with buffers rather than strings, and models keys as `CryptoKey` objects that carry algorithm and usage metadata. Base64 is the bridge between binary data and JSON or object keys.

---

## Short-Answer Questions

Full answers are in [`ProjectShortAnswers.md`](./ProjectShortAnswers.md). In brief:

1. **Hiding password length:** encode every password into a fixed 193-byte plaintext (a length byte, the UTF-8 password, then zero padding) before AES-GCM encryption. Passwords over 64 characters are rejected.
2. **Preventing swap attacks:** bind each ciphertext to its domain through AES-GCM associated data, so a swapped record fails authentication.
3. **Is trusted storage required for rollback defense?** Yes, or some equivalent trusted or append-only state (a monotonic counter, an append-only log). Otherwise the attacker replaces the database and its hash together.
4. **Lookup with a randomized MAC:** scan and verify the tag on each record. Lookup goes from O(1) to O(n).
5. **Leaking only log₂(k) records:** pad the KVS with indistinguishable dummy records up to the next power of two.
6. **Multi-user sharing of one site:** encrypt the shared record under a per-record symmetric key, and wrap that key with each authorized user's public key.

---

## References

- Project handout: [`proj1 documentation.pdf`](./proj1%20documentation.pdf), ICS 3201, based on Stanford CS255 Project 1
- [MDN – SubtleCrypto](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto)
- [Node.js Web Crypto API](https://nodejs.org/api/webcrypto.html)
- NIST SP 800-38D – *Galois/Counter Mode (GCM)*
- RFC 8018 – *PKCS #5: Password-Based Cryptography (PBKDF2)*
- RFC 2104 – *HMAC: Keyed-Hashing for Message Authentication*
- [Mocha](https://mochajs.org/) · [expect.js](https://github.com/Automattic/expect.js)

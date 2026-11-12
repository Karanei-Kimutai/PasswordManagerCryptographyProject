# Tessera documentation

This folder documents **what** Tessera does, **why** each design decision was made, and **how** it is implemented, with pointers into the code.

## Suggested reading order

1. **[Getting started](gettingStarted.md):** install, run, test, configure.
2. **[Architecture](architecture.md):** the three parts (crypto core, server, client), how data flows between them, and a map of the code.
3. **[Threat model](threatModel.md):** who the adversary is, what Tessera guarantees, and its honest limitations.
4. **Concepts:** one page per cryptographic or security concept:

   | Page | Concepts covered |
   |---|---|
   | [Key derivation](concepts/keyDerivation.md) | PBKDF2, salts, iteration counts, HMAC as a PRF, key separation, Unicode normalization, non-extractable keys |
   | [Record encryption](concepts/recordEncryption.md) | AES-256-GCM, IVs and nonce reuse, associated data, swap attacks, length-hiding padding |
   | [Record indexing](concepts/recordIndexing.md) | Deterministic PRFs as private lookup keys, site normalization, O(1) lookup |
   | [Vault integrity and rollback](concepts/vaultIntegrityAndRollback.md) | Whole-vault MAC, canonical serialization, monotonic versions, trusted state, forks, optimistic concurrency |
   | [Authentication](concepts/authentication.md) | Zero-knowledge login, authKey, scrypt, account-enumeration defenses, sessions, CSRF, rate limiting |
   | [Master password change](concepts/masterPasswordChange.md) | Re-keying, atomic credential rotation, session revocation |
   | [Password generator](concepts/passwordGenerator.md) | CSPRNGs, modulo bias, rejection sampling, entropy |
   | [Web security](concepts/webSecurity.md) | Content Security Policy, security headers, clipboard hygiene, auto-lock, masking, third-party leakage |

5. **Reference:** [HTTP API](reference/apiReference.md) and the [serialized vault format](reference/vaultFormat.md).
6. **[Design system](design/designSystem.md):** visual language and the UX details of a password manager.
7. **[Testing](testing.md):** what the test suites cover, including simulated attacks.
8. **Coursework:** [From Keychain to Tessera](coursework/fromKeychainToTessera.md) maps the original project onto the web app. The original handout, README and short answers are kept alongside it in [`coursework/`](coursework/).

## Glossary

| Term | Meaning in Tessera |
|---|---|
| **Master password** | The one password the user remembers. Never leaves the browser. |
| **Vault** | The encrypted collection of a user's items, stored on the server as one JSON document. |
| **Entry / item** | One login: website, username, password and notes. |
| **Record** | The encrypted form of an entry: `{ iv, ciphertext }`. |
| **Locator** | A record's key in the vault: `Base64(HMAC(indexKey, site ‖ username))`. Also used as the entry's id. |
| **authKey** | A key derived from the master password that the browser sends to the server to prove it knows the password. |
| **Trusted state** | What a device remembers about the newest vault it has seen (version and checksum). Used to detect rollback. |
| **Lock** | Discarding keys and decrypted data from memory while staying signed in. |

# Tessera

**A zero-knowledge password manager for the web.** Every item is encrypted in your browser before it is stored. The server holds only ciphertext and never sees your master password, your keys, or which websites you have accounts on.

Tessera grew out of our **ICS 3201 Computer Security and Cryptography** project: a password-manager core (`Keychain`) adapted from Stanford's CS255 assignment. This repository turns that core into a complete client–server web application and keeps every security property the coursework required:

| Coursework requirement | How Tessera meets it |
|---|---|
| Derive keys from the master password with PBKDF2, called **once** | PBKDF2-SHA256, 600,000 iterations, random 128-bit salt; every other key comes from HMAC |
| Encrypt each record separately with AES-GCM | Each item is its own AES-256-GCM ciphertext with a fresh random IV |
| Hide domain names | Items are indexed by `HMAC(indexKey, site ‖ username)` |
| Hide password lengths | Every item is padded to a fixed 4 KB before encryption |
| Defend against **swap attacks** | The record's locator is GCM associated data |
| Defend against **rollback attacks** | A whole-vault HMAC, a monotonic version counter, and per-device trusted state |
| Never store the master password or keys | Only the salt, ciphertexts and tags are stored; every `CryptoKey` is non-extractable |

The original coursework code is preserved unchanged on the **`keychain-coursework`** branch.

---

## Why "Tessera"?

In ancient Rome, a *tessera* was a small tile or token. The word had three everyday uses, and each one describes part of what this application does.

**1. The mosaic tile.** Roman mosaics were made from thousands of small, uniform tesserae. A single tile means little on its own. The picture only appears when they are put together in the right places. Tessera's vault works the same way. Each item is its own sealed tile: encrypted separately, padded to exactly the same size, and stored under a locator that reveals nothing. To anyone without the key, the vault is a grid of identical, featureless tiles. Only the owner's key arranges them into a picture they can read. The integrity tag makes sure no tile can be swapped, removed or slipped back in unnoticed.

**2. The watchword token** (*tessera militaris*). Each evening the Roman army wrote the night's **watchword** on a tablet, the tessera, and passed it from unit to unit. The historian Polybius describes how the tablets were returned and checked, so the commander knew the word had arrived intact and on time. A password manager carries the same thing, a secret that grants entry, and Tessera's defenses do the same checking: every record is authenticated, and a vault that comes back older than expected is refused as a rollback.

**3. The token of trust** (*tessera hospitalis*). Two families bound by a pact of hospitality would break a token in two and each keep one half. Years later, a descendant could prove who they were by presenting a half that fitted the other perfectly, without having to say anything secret out loud. Tessera signs you in the same way. Your browser presents an `authKey` derived from your master password, the server checks that it matches its half, and the master password itself is never handed over.

All three meanings point to the idea the project is built on: **small, uniform pieces that each keep their own secret, and trust that comes from proof rather than disclosure.** The logo shows it literally: four tiles, one of them set apart in the accent colour.

---

## Quick start

Requirements: **Node.js 20.19+** and npm.

```bash
npm install          # installs all three workspaces
npm test             # 46 crypto tests + 17 API tests
npm run dev          # API on :3001, web app on http://localhost:5173
```

For a production-style run (one server for both the API and the built app):

```bash
npm run build
npm start            # http://localhost:3001
```

See [docs/gettingStarted.md](docs/gettingStarted.md) for configuration and troubleshooting.

---

## What's in the box

- **Vault:** add, edit, delete, search and sort logins (website, username, password, notes). Several accounts per site are supported.
- **Password generator:** unbiased (rejection sampling), with configurable character sets and a plain-language strength explanation.
- **Lock and auto-lock:** keys are discarded from memory on lock or after inactivity. A page reload always locks.
- **Master password change:** re-encrypts every item under new keys in the browser and signs out other devices.
- **Tamper detection:** swapped, edited, deleted or rolled-back vault data is detected and refused, with a clear explanation.
- **Careful details:** a fixed-length password mask, reveal that times out, a clipboard that clears itself after 30 s, no third-party requests (no favicon service, no font CDN) and a strict Content Security Policy.

---

## Repository layout

```
.
├── packages/crypto/      @tessera/crypto: the cryptographic core (browser + Node)
│   ├── src/              keyDerivation, vault, padding, encoding, passwordGenerator, …
│   └── test/             node:test suites (functionality + attacks)
├── server/               @tessera/server: Express 5 + SQLite API (stores ciphertext only)
│   ├── src/              routes, security (sessions, scrypt, headers), database
│   └── test/             end-to-end API tests using the real crypto package
├── client/               @tessera/client: React 18 + Vite web app (does all the crypto)
│   └── src/              components, services (vaultSession, apiClient, …), styles
└── docs/                 project documentation (start at docs/README.md)
```

---

## Documentation

Start at **[docs/README.md](docs/README.md)**. Highlights:

- [Architecture](docs/architecture.md): components, data flow and what runs where
- [Threat model](docs/threatModel.md): what we defend against, and what we don't
- Concepts: [key derivation](docs/concepts/keyDerivation.md) · [record encryption](docs/concepts/recordEncryption.md) · [record indexing](docs/concepts/recordIndexing.md) · [integrity and rollback](docs/concepts/vaultIntegrityAndRollback.md) · [authentication](docs/concepts/authentication.md) · [master password change](docs/concepts/masterPasswordChange.md) · [password generator](docs/concepts/passwordGenerator.md) · [web security](docs/concepts/webSecurity.md)
- Reference: [API](docs/reference/apiReference.md) · [vault format](docs/reference/vaultFormat.md)
- [Design system](docs/design/designSystem.md)
- [From Keychain to Tessera](docs/coursework/fromKeychainToTessera.md): how the coursework maps onto the app

> ⚠️ Tessera is an academic project. It applies real techniques carefully, but it has not been independently audited. Don't store anything irreplaceable in it.

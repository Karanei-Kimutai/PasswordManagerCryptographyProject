# Record indexing (hiding which sites are stored)

**Code:** `#computeLocator` and `normalizeSite` in [`packages/crypto/src/vault.js`](../../packages/crypto/src/vault.js)

## The problem

The vault is a key-value map. If the keys were site names (`"github.com" → ciphertext`), anyone holding the vault would learn exactly which services the user has accounts on, which is sensitive in itself (banks, health providers, dating sites).

## The solution: a deterministic PRF as the key

The coursework stored records under `HMAC(domainKey, domain)`. Tessera generalizes this to support several accounts per site:

```
locator = Base64( HMAC-SHA256( indexKey, normalizeSite(site) + "\0" + username ) )
```

Two properties of HMAC make this work:

- **Pseudorandom:** without `indexKey`, a locator looks like 32 random bytes. It reveals nothing about the site or username, and the same site gets unrelated locators in different users' vaults (different keys). There is a test for this.
- **Deterministic:** the same input always gives the same locator. That lets us use it as a hash-table key: to find GitHub/ada, compute one HMAC and index the map, giving **O(1)** lookup (`Vault.getEntry`).

Coursework Short Answer 4 explored the alternative: with a *randomized* MAC, lookups would need an O(n) scan, verifying each record's tag in turn. Determinism is what makes private O(1) lookup possible.

The locator doubles as the **entry id** used by the UI and as the **associated data** that binds a ciphertext to its slot (see [record encryption](recordEncryption.md)).

## Uniqueness and separators

- One record per (site, username) pair. Adding a second entry with the same pair raises `DuplicateEntryError`, rather than silently overwriting the first.
- The `"\0"` separator prevents ambiguity. Without it, (`"ab"`, `"c"`) and (`"a"`, `"bc"`) would both hash `"abc"`. A normalized site never contains `"\0"`.
- Editing the site or username changes the locator, so `setEntry({…}, { previousId })` writes the new record and deletes the old one in the same version step, preserving `createdAt`.

## Site normalization

Users type websites inconsistently: `https://www.GitHub.com/login`, `github.com`, `GitHub.com`. To make these the same entry, the locator is computed over a **normalized** site:

1. trim and lowercase;
2. strip a URL scheme (`https://`);
3. drop any path, query or fragment (only when the text looks like a URL or hostname, so a label like `work / personal` is preserved);
4. drop a leading `www.`.

| Input | Normalized |
|---|---|
| `https://www.GitHub.com/login?x=1` | `github.com` |
| `Example.org/path` | `example.org` |
| `localhost:8080` | `localhost:8080` |
| `My Bank / Savings` | `my bank / savings` |

The *displayed* site is what the user typed, except that the form stores a pasted full URL as its hostname for readability.

## Listing everything

The vault screen needs every entry to show and search the list, so after unlocking the client decrypts all records (`listEntries`). Each record is still encrypted separately. Searching happens entirely in browser memory, and nothing about a search is ever sent to the server.

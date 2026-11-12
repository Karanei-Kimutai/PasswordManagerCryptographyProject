# Record encryption

**Code:** `#encryptRecord` and `#decryptRecord` in [`packages/crypto/src/vault.js`](../../packages/crypto/src/vault.js); [`padding.js`](../../packages/crypto/src/padding.js)

Each item in the vault is encrypted **separately**, as the coursework required, so reading one item never requires decrypting the others.

```
entry JSON ──▶ UTF-8 ──▶ pad to 4,096 bytes ──▶ AES-256-GCM(recordKey, random IV, AAD = locator)
                                                         │
                                         { iv: Base64(12 bytes), ciphertext: Base64(4,096 + 16 bytes) }
```

## AES-256-GCM

**AES-GCM** (Galois/Counter Mode) is an **authenticated encryption with associated data (AEAD)** scheme. One operation provides:

- **Confidentiality:** AES in counter mode turns the key and IV into a keystream that is XORed with the plaintext.
- **Integrity and authenticity:** a 128-bit tag (GHASH) over the ciphertext *and* the associated data. Any modification makes decryption fail. SubtleCrypto throws instead of returning tampered plaintext.

We use a 256-bit key (`recordKey`).

### What is encrypted

The plaintext is the JSON of the whole entry:

```json
{"site":"github.com","username":"ada","password":"…","notes":"…","createdAt":"…","updatedAt":"…"}
```

Even the timestamps are inside the ciphertext. The server cannot tell *which* item changed, only that the vault did.

## IVs (nonces) and why uniqueness is critical

GCM requires a **unique IV for every encryption under the same key**. If an IV ever repeats:

- the two ciphertexts share a keystream, so XORing them reveals the XOR of the two plaintexts;
- worse, the attacker can recover the GHASH authentication key and **forge** valid ciphertexts.

Tessera draws a fresh **random 96-bit IV** from the CSPRNG for every encryption, including every edit and every re-encryption during a master-password change. NIST SP 800-38D recommends 96-bit IVs (GCM uses them directly). With random IVs, the chance of any collision stays negligible far beyond any realistic vault size (the usual bound is about 2³² encryptions per key).

A side effect is that **equal entries never produce equal ciphertexts**, so an observer cannot tell that two items share a password. A test checks this (`encrypts identical entries to different ciphertexts`).

## Associated data and swap attacks

AEAD lets you authenticate extra data that is *not* encrypted: the **associated data (AAD)**. Tessera uses the record's **locator** as AAD:

```
AAD = "tessera/v1/record\n" + locator
```

### The swap attack

The coursework's adversary can rearrange the stored key-value map. Suppose they move the ciphertext stored under `bank.com`'s locator to `evil.com`'s locator. Without AAD, GCM would decrypt it happily (the ciphertext itself is untouched), and the app would show the bank password as `evil.com`'s, a site the attacker controls.

### Why AAD stops it

The GCM tag was computed over the *original* locator. Decrypting under a different locator recomputes the tag over different AAD, verification fails, and `#decryptRecord` throws `VaultIntegrityError`. The swapped password is never revealed.

The coursework required the swap defense to **work independently of the rollback defense**. Tessera has two layers here: the whole-vault integrity tag also catches swaps (see [vault integrity](vaultIntegrityAndRollback.md)), but the AAD check works on its own. The test `detects a swap attack via AES-GCM associated data alone` proves this. It re-signs a swapped vault with the real integrity key (simulating a bypassed tag) and shows that reading either record still fails.

As defense in depth, after decrypting we also recompute the locator from the decrypted site and username and check that it matches where the record was stored.

## Length hiding: fixed-size padding

AES-GCM ciphertexts are exactly as long as their plaintexts (plus the 16-byte tag). Unpadded, the vault would reveal the length of every password and note.

Tessera pads every entry to **exactly 4,096 bytes**:

```
┌──────────────────┬──────────────────────────────┬───────────────────────┐
│ length (2 bytes, │ entry JSON (UTF-8, `length`  │ 0x00 … zero padding   │
│ big-endian)      │ bytes, ≤ 4,094)              │                       │
└──────────────────┴──────────────────────────────┴───────────────────────┘
 └────────────────────────────── 4,096 bytes ─────────────────────────────┘
```

So every record's ciphertext is exactly 4,112 bytes. The test `produces ciphertexts of identical length regardless of content` checks this with ASCII, accented, CJK and emoji content.

This generalizes the coursework's 193-byte password padding and carries over the three lessons from fixing it:

1. **Pad bytes, not characters.** `string.length` counts UTF-16 code units: an emoji is 2 "characters" but 4 bytes. Limits are enforced on the UTF-8 encoding.
2. **Use an explicit length prefix** instead of stripping zeros, so content containing `\0` round-trips exactly.
3. **Reject oversized input** (`RecordTooLargeError`) rather than emit a longer, length-leaking ciphertext.

The UI enforces friendlier per-field character limits (`FIELD_LIMITS`: notes ≤ 2,000 characters, and so on). The byte limit is still the final authority, because 2,000 emoji are 8,000 bytes.

**Trade-off:** 4 KB per item is about 5.5 KB in Base64, so 1,000 items is roughly a 5.5 MB vault. That's acceptable for a password manager. The server caps vaults at 8 MB.

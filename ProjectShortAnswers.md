# Password Manager Project — Questions and Answers

## Question 1

**Briefly describe your method for preventing the adversary from learning information about the lengths of the passwords stored in your password manager.**

**Answer:**

We prevent password-length leakage by padding every password to a fixed maximum length of 64 characters before encryption. Specifically, we append null bytes (`\x00`) until the plaintext reaches `MAX_PASSWORD_LENGTH`, then encrypt it using AES-GCM. Because every password has the same plaintext length before encryption, the resulting ciphertexts have the same length as well. This prevents an adversary from inferring the original password length from the ciphertext size.

## Question 2

**Briefly describe your method for preventing swap attacks (Section 2.2). Provide an argument for why the attack is prevented in your scheme.**

**Answer:**

We prevent swap attacks by binding each encrypted password to its corresponding domain using authenticated encryption with associated data (AEAD). Specifically, we supply the hashed domain name as the additional authenticated data (AAD) to the AES-GCM encryption and decryption functions. If an adversary swaps the ciphertext for `siteA` into the record for `siteB`, decryption will use `siteB`'s domain value as the AAD. Since the ciphertext's authentication tag was generated using `siteA`'s domain value, authentication fails and decryption is rejected. The adversary therefore cannot successfully substitute one site's encrypted password for another site's password.

## Question 3

**In our proposed defense against the rollback attack (Section 2.2), we assume that we can store the SHA-256 hash in a trusted location beyond the reach of an adversary. Is it necessary to assume that such a trusted location exists, in order to defend against rollback attacks? Briefly justify your answer.**

**Answer:**

Some form of trusted or append-only state is necessary to detect rollback attacks. In a rollback attack, an adversary replaces the current database with an older, previously valid version. If the SHA-256 hash is stored alongside the key-value store (KVS) in the same untrusted location, the adversary can replace both with an older valid pair. The hash of the old KVS will match the old hash, so the application will incorrectly accept the rolled-back state. Keeping the hash somewhere the adversary cannot modify—or using another trusted anti-rollback mechanism, such as a monotonic counter or an append-only log—prevents the adversary from making the old database state appear current.

## Question 4

**Because HMAC is a deterministic MAC (that is, its output is the same if it is run multiple times with the same input), we were able to look up domain names using their HMAC values. There are also randomized MACs, which can output different tags on multiple runs with the same input. Explain how you would do the look up if you had to use a randomized MAC instead of HMAC. Is there a performance penalty involved, and if so, what?**

**Answer:**

With a randomized MAC, we could not compute one deterministic tag for the queried domain and use it directly as a key to look up a record in the KVS. Instead, we would need to iterate through the stored records and verify each stored tag against the queried domain using the MAC verification function, stopping when we find a match. This introduces a performance penalty: lookup time would increase from expected **O(1)** for a direct hash-table lookup to **O(k)** in the worst case, where *k* is the number of records in the password manager.

## Question 5

**In our specification, we leak the number of records in the password manager. Describe an approach to reduce the information leaked about the number of records. Specifically, if there are *k* records, your scheme should only leak log₂(*k*) (that is, if *k*₁ and *k*₂ are such that log₂(*k*₁) = log₂(*k*₂), the attacker should not be able to distinguish between a case where the true number of records is *k*₁ and another case where the true number of records is *k*₂).**

**Answer:**

We can reduce record-count leakage by padding the KVS with dummy records until its total size is the next power of two. If the user has *k* real passwords, we add dummy records until the database contains \(2^{\lceil \log_2 k \rceil}\) records. For example, if there are 5 real passwords, we add 3 dummy records so that the KVS contains 8 records. The dummy records should be indistinguishable from real records to the adversary—for example, they can use pseudorandom-looking keys, initialization vectors, and ciphertexts. The adversary then learns only the power-of-two size class, represented by \(\lceil \log_2 k \rceil\), rather than the exact number of real records. Thus, counts within the same size class are not distinguishable from the database size alone.

## Question 6

**What is a way we can add multi-user support for specific sites to our password manager system without compromising security for other sites that these users may wish to store passwords of? That is, if Alice and Bob wish to access one stored password (say for nytimes) that either of them can get and update, without allowing the other to access their passwords for other websites.**

**Answer:**

We can support site-specific sharing using public-key cryptography and a separate symmetric share key for each shared record. Each user generates a public/private key pair. To share the `nytimes` password with Bob, Alice generates a random symmetric key for that record and encrypts the password with it. She then encrypts the symmetric share key separately with Alice's public key and Bob's public key, and stores the encrypted password and both encrypted copies of the share key in the KVS. Alice and Bob can each use their own private key to recover the share key and then decrypt or update the shared password. Because the share key is specific to the `nytimes` record, this does not give either user access to the other user's passwords for unrelated websites.

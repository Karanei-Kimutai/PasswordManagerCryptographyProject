"use strict";

/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters

/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load. 
   * Arguments:
   *  You may design the constructor with any parameters you would like. 
   * Return Type: void
   */
  constructor(domainKey,encKey,salt, kvs={}, passwordCheck=null) {
    this.data = { 
      /* Store member variables that you intend to be public here
         (i.e. information that will not compromise security if an adversary sees) */
      salt: salt, // Stored as an encoded string so it safely serializes during dump()
      kvs: kvs, // The encrypted Key-Value Store dictionary
      passwordCheck: passwordCheck
    };
    this.secrets = {
      /* Store member variables that you intend to be private here
         (information that an adversary should NOT see). */
      domainKey: domainKey, //CryptoKey for HMAC hashing domain names
      encKey: encKey  //Cryptokey for AES-GCM encrypting passwords
    };
  };

  /** 
    * Creates an empty keychain with the given password.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  static async init(password) {
    //1. Generate a 128-bit (16-byte) salt
    const saltBuffer= getRandomBytes(16); // 128-bit salt
    const saltString= encodeBuffer(saltBuffer);

    //2. Import the user's password for PBKDF2
    const passKey= await subtle.importKey(
      "raw",
      stringToBuffer(password),
      { name: "PBKDF2" },
      false,
      ["deriveBits"]
    );

    //3. Derive a 256-bit Master Key using PBKDF2
    const masterBits= await subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: saltBuffer,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256"
      },
      passKey,
      256
    );
    // Import the master bits as an HMAC key to act as our PRF
    const masterKey= await subtle.importKey(
      "raw",
      masterBits,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    //4. Derive Sub-keys using HMAC
    const domainKeyBits= await subtle.sign("HMAC", masterKey, stringToBuffer("domain-key-derivation"));
    const domainKey=await subtle.importKey(
      "raw",
      domainKeyBits,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    )
    const encKeyBits=await subtle.sign("HMAC", masterKey, stringToBuffer("encryption-key-derivation"));
    const encKey=await subtle.importKey(
      "raw",
      encKeyBits,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );

    const passwordCheckBits= await subtle.sign("HMAC", masterKey, stringToBuffer("password-check"));
    const passwordCheck= encodeBuffer(passwordCheckBits);

    //5. Return a new Keychain instance with the derived keys
    return new Keychain(domainKey, encKey, saltString, {}, passwordCheck);


  }

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the dump function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object).Returns a Keychain object that contains the data
    * from repr. 
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: Keychain
    */
  static async load(password, repr, trustedDataCheck) {
// 1. Verify the integrity of the data if a checksum is provided
    if (trustedDataCheck) {
      const computedChecksumBuffer = await subtle.digest("SHA-256", stringToBuffer(repr));
      const computedChecksum = encodeBuffer(computedChecksumBuffer);

      if (computedChecksum !== trustedDataCheck) {
        throw new Error("Integrity check failed: Data tampering or rollback attack detected.");
      }
    }

    // 2. Parse the KVS, Salt, and PasswordCheck from the JSON representation
    const parsedData = JSON.parse(repr);
    const saltString = parsedData.salt;
    const kvs = parsedData.kvs;
    const storedPasswordCheck = parsedData.passwordCheck; // <-- ADDED
    const saltBuffer = decodeBuffer(saltString);

    // 3. Import the password for PBKDF2
    const passKey = await subtle.importKey(
      "raw",
      stringToBuffer(password),
      { name: "PBKDF2" },
      false,
      ["deriveBits"]
    );

    // 4. Re-derive the Master Key using the EXACT SAME salt from the dump
    const masterBits = await subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: saltBuffer,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256"
      },
      passKey,
      256
    );

    const masterKey = await subtle.importKey(
      "raw",
      masterBits,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    // Validate the password before proceeding with sub-key derivation
    if (storedPasswordCheck) {
      const passwordCheckBits = await subtle.sign("HMAC", masterKey, stringToBuffer("password-check"));
      const computedPasswordCheck = encodeBuffer(passwordCheckBits);
      
      if (computedPasswordCheck !== storedPasswordCheck) {
        throw new Error("Invalid password!");
      }
    }

    // 5. Re-derive the Sub-keys identically to init()
    const domainKeyBits = await subtle.sign("HMAC", masterKey, stringToBuffer("domain-key-derivation"));
    const domainKey = await subtle.importKey(
      "raw",
      domainKeyBits,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const encKeyBits = await subtle.sign("HMAC", masterKey, stringToBuffer("encryption-key-derivation"));
    const encKey = await subtle.importKey(
      "raw",
      encKeyBits,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );

    // 6. Reconstruct and return the Keychain instance 
    return new Keychain(domainKey, encKey, saltString, kvs, storedPasswordCheck);
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity.
    *
    * Return Type: array
    */ 
  async dump() {
    // 1. Serialize the non-secret data (KVS and Salt) to a JSON string
    const repr = JSON.stringify(this.data);

    // 2. Compute a SHA-256 checksum over the stringified data for rollback defense
    const checksumBuffer = await subtle.digest("SHA-256", stringToBuffer(repr));
    const checksumString = encodeBuffer(checksumBuffer);

    // 3. Return the array containing the state and its cryptographic checksum
    return [repr, checksumString];
  };

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async get(name) {
    //1. Hash the domain name to find its KVS key
    const nameBuffer=stringToBuffer(name);
    const kvsKeyBits=await subtle.sign("HMAC", this.secrets.domainKey, nameBuffer);
    const kvsKey= encodeBuffer(kvsKeyBits);

    //2. Check if the domain exists in our KVS
    if (!(kvsKey in this.data.kvs)){
      return null;
    }

    const record= this.data.kvs[kvsKey];
    const iv= decodeBuffer(record.iv);
    const ciphertextBuffer= decodeBuffer(record.cipher);

    try{
      //3. Decrypt the password
      // We pass the domain name as 'additionalData' (AAD). If an adversary swapped this ciphertext with another domain's ciphertext, the AAD won't match and SubtleCrypto will automatically throw an error here preventing swap attacks
      const plaintextBuffer= await subtle.decrypt(
        {
          name: "AES-GCM",
          iv: iv,
          additionalData: nameBuffer,
        },
        this.secrets.encKey,
        ciphertextBuffer
      );
      const paddedPassword = bufferToString(plaintextBuffer);
      //4. Remove the padding to return the original password length
      const password = paddedPassword.replace(/\x00/g, "");
      return password;
    }catch (error){
    // Catch authentication tag failures (Swap attack or data tampering)
    throw new Error("Integrity check failed: Swap attack detected or data corrupted");
    }
  };

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  async set(name, value) {
    // 1. Hash the domain name to generate a secure KVS key
    const nameBuffer = stringToBuffer(name);
    const kvsKeyBits = await subtle.sign("HMAC", this.secrets.domainKey, nameBuffer);
    const kvsKey = encodeBuffer(kvsKeyBits);

    // 2. Pad the password to a consistent maximum length (64 chars) 
    // to hide the actual password length from adversaries.
    const paddedPassword = value.padEnd(MAX_PASSWORD_LENGTH, "\x00");
    const plaintextBuffer = stringToBuffer(paddedPassword);

    // 3. Generate a random Initialization Vector (12 bytes for AES-GCM)
    const iv = getRandomBytes(12);

    // 4. Encrypt the password. 
    // We bind the domain name as Additional Authenticated Data (AAD) 
    // to explicitly defend against swap attacks.
    const ciphertextBuffer = await subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv,
        additionalData: nameBuffer
      },
      this.secrets.encKey,
      plaintextBuffer
    );

    // 5. Store the encoded IV and ciphertext in the KVS object
    this.data.kvs[kvsKey] = {
      iv: encodeBuffer(iv),
      cipher: encodeBuffer(ciphertextBuffer)
    };
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {
    // 1. Hash the domain name to find its KVS key
    const nameBuffer = stringToBuffer(name);
    const kvsKeyBits = await subtle.sign("HMAC", this.secrets.domainKey, nameBuffer);
    const kvsKey = encodeBuffer(kvsKeyBits);

    // 2. Delete the record if it exists
    if (kvsKey in this.data.kvs) {
      delete this.data.kvs[kvsKey];
      return true;
    }
    return false;
  };
};

module.exports = { Keychain }

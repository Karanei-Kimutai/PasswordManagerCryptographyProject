/**
 * @file database.js
 *
 * SQLite storage via better-sqlite3 (synchronous, which makes transactions
 * simple and race-free in a single Node process).
 *
 * What the server stores, and why each item is safe to store:
 *
 *   users.kdfSalt, kdfIterations  Public by design. The client needs them
 *                                 before it can derive any key.
 *   users.authHash, authHashSalt  scrypt(authKey). authKey is one PRF output
 *                                 of the master key, and the hash is a
 *                                 second slow layer on top of it.
 *   vaults.data                   The serialized vault: ciphertexts, random
 *                                 IVs, pseudorandom locators and tags.
 *   sessions.tokenHash            SHA-256 of the session token. A leaked
 *                                 database cannot be replayed as a cookie.
 *
 * The server never stores or sees the master password, any decryption key,
 * any site name, username, password or note.
 */

import Database from "better-sqlite3";

const schema = `
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    kdfAlgorithm  TEXT NOT NULL,
    kdfIterations INTEGER NOT NULL,
    kdfSalt       TEXT NOT NULL,
    authHash      TEXT NOT NULL,
    authHashSalt  TEXT NOT NULL,
    createdAt     TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS vaults (
    userId    INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    version   INTEGER NOT NULL,
    data      TEXT NOT NULL,
    updatedAt TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    tokenHash TEXT PRIMARY KEY,
    userId    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    createdAt INTEGER NOT NULL,
    expiresAt INTEGER NOT NULL
  );

  CREATE INDEX IF NOT EXISTS sessionsByUser ON sessions(userId);
`;

/**
 * Opens (or creates) the database and returns a small data-access object.
 * Every query is a prepared statement, so user input is always bound as a
 * parameter and never concatenated into SQL (no SQL injection).
 *
 * @param {string} databasePath - A file path, or ":memory:" for tests.
 */
export function openDatabase(databasePath) {
  const database = new Database(databasePath);
  database.pragma("journal_mode = WAL");
  database.pragma("foreign_keys = ON");
  database.exec(schema);

  const statements = {
    findUserByEmail: database.prepare("SELECT * FROM users WHERE email = ?"),
    findUserById: database.prepare("SELECT * FROM users WHERE id = ?"),
    insertUser: database.prepare(`
      INSERT INTO users (email, kdfAlgorithm, kdfIterations, kdfSalt, authHash, authHashSalt, createdAt)
      VALUES (@email, @kdfAlgorithm, @kdfIterations, @kdfSalt, @authHash, @authHashSalt, @createdAt)
    `),
    updateUserCredentials: database.prepare(`
      UPDATE users
      SET kdfAlgorithm = @kdfAlgorithm, kdfIterations = @kdfIterations, kdfSalt = @kdfSalt,
          authHash = @authHash, authHashSalt = @authHashSalt
      WHERE id = @userId
    `),
    findVault: database.prepare("SELECT version, data, updatedAt FROM vaults WHERE userId = ?"),
    insertVault: database.prepare("INSERT INTO vaults (userId, version, data, updatedAt) VALUES (?, ?, ?, ?)"),
    updateVault: database.prepare("UPDATE vaults SET version = ?, data = ?, updatedAt = ? WHERE userId = ? AND version = ?"),
    insertSession: database.prepare("INSERT INTO sessions (tokenHash, userId, createdAt, expiresAt) VALUES (?, ?, ?, ?)"),
    findSession: database.prepare("SELECT * FROM sessions WHERE tokenHash = ? AND expiresAt > ?"),
    deleteSession: database.prepare("DELETE FROM sessions WHERE tokenHash = ?"),
    deleteOtherSessions: database.prepare("DELETE FROM sessions WHERE userId = ? AND tokenHash != ?"),
    deleteExpiredSessions: database.prepare("DELETE FROM sessions WHERE expiresAt <= ?"),
  };

  return {
    raw: database,
    statements,
    /** Runs `work` inside a transaction: all of its writes happen, or none do. */
    transaction: (work) => database.transaction(work)(),
    close: () => database.close(),
  };
}

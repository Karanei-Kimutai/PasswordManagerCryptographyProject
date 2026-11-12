/**
 * @file config.js
 *
 * Server configuration, read from environment variables with safe defaults.
 *
 *   PORT                   HTTP port (default 3001)
 *   TESSERA_DATA_DIR       Where the SQLite database and server secret live
 *                          (default server/data)
 *   NODE_ENV=production    Enables Secure cookies, HSTS, and serving the built client
 */

import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const serverRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/**
 * Loads the server secret, creating it on first run.
 *
 * The secret is used for exactly one thing: computing a stable *fake* salt
 * for email addresses that have no account (see routes/auth.js, "prelogin").
 * It protects nothing about user vaults, which the server cannot decrypt
 * whatever it knows.
 *
 * @param {string} dataDirectory
 * @returns {Buffer}
 */
function loadServerSecret(dataDirectory) {
  const secretPath = path.join(dataDirectory, "serverSecret");
  if (!existsSync(secretPath)) {
    writeFileSync(secretPath, randomBytes(32).toString("base64"), { mode: 0o600 });
  }
  return Buffer.from(readFileSync(secretPath, "utf8").trim(), "base64");
}

/**
 * Builds the runtime configuration.
 *
 * @returns {{
 *   port: number, isProduction: boolean, databasePath: string,
 *   serverSecret: Buffer, clientDistDirectory: string,
 *   sessionLifetimeMs: number, allowWeakKdf: boolean
 * }}
 */
export function loadConfig() {
  const dataDirectory = process.env.TESSERA_DATA_DIR ?? path.join(serverRoot, "data");
  mkdirSync(dataDirectory, { recursive: true });
  return {
    port: Number(process.env.PORT ?? 3001),
    isProduction: process.env.NODE_ENV === "production",
    databasePath: path.join(dataDirectory, "tessera.sqlite"),
    serverSecret: loadServerSecret(dataDirectory),
    clientDistDirectory: path.resolve(serverRoot, "..", "client", "dist"),
    sessionLifetimeMs: 12 * 60 * 60 * 1000, // 12 hours
    allowWeakKdf: false,
  };
}

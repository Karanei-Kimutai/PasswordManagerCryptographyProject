/**
 * @file sessions.js
 *
 * Opaque, server-side sessions carried in an HttpOnly cookie.
 *
 * - The token is 32 random bytes (256 bits), so it cannot be guessed.
 * - Only SHA-256(token) is stored, so a leaked database cannot be turned
 *   back into working cookies.
 * - The cookie is `HttpOnly` (page JavaScript cannot read it, which limits
 *   the damage of an XSS bug), `SameSite=Strict` (the browser will not send
 *   it on requests started by other sites, the main CSRF defense), and
 *   `Secure` in production (HTTPS only).
 *
 * A session only proves "this browser logged in as this account". It grants
 * access to the *encrypted* vault and nothing more. Decrypting still needs the
 * master password, which never leaves the browser.
 */

import { createHash, randomBytes } from "node:crypto";

export const SESSION_COOKIE_NAME = "tessera_session";

/** @param {string} token */
function hashToken(token) {
  return createHash("sha256").update(token).digest("base64");
}

/**
 * Starts a session for a user and sets the cookie on the response.
 *
 * @param {import("express").Response} response
 * @param {ReturnType<import("../database.js").openDatabase>} database
 * @param {number} userId
 * @param {{ sessionLifetimeMs: number, isProduction: boolean }} config
 * @returns {string} The token hash (used to keep this session when revoking others).
 */
export function startSession(response, database, userId, config) {
  const token = randomBytes(32).toString("base64url");
  const tokenHash = hashToken(token);
  const now = Date.now();
  database.statements.deleteExpiredSessions.run(now);
  database.statements.insertSession.run(tokenHash, userId, now, now + config.sessionLifetimeMs);
  response.cookie(SESSION_COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: "strict",
    secure: config.isProduction,
    path: "/api",
    maxAge: config.sessionLifetimeMs,
  });
  return tokenHash;
}

/**
 * Ends the current session (if any) and clears the cookie.
 *
 * @param {import("express").Request} request
 * @param {import("express").Response} response
 * @param {ReturnType<import("../database.js").openDatabase>} database
 */
export function endSession(request, response, database) {
  const token = request.cookies?.[SESSION_COOKIE_NAME];
  if (token) {
    database.statements.deleteSession.run(hashToken(token));
  }
  response.clearCookie(SESSION_COOKIE_NAME, { path: "/api" });
}

/**
 * Express middleware: requires a valid session and attaches
 * `request.session = { userId, tokenHash }`. Responds 401 otherwise.
 *
 * @param {ReturnType<import("../database.js").openDatabase>} database
 */
export function requireSession(database) {
  return (request, response, next) => {
    const token = request.cookies?.[SESSION_COOKIE_NAME];
    if (!token) {
      return response.status(401).json({ error: "Not signed in" });
    }
    const tokenHash = hashToken(token);
    const session = database.statements.findSession.get(tokenHash, Date.now());
    if (!session) {
      response.clearCookie(SESSION_COOKIE_NAME, { path: "/api" });
      return response.status(401).json({ error: "Session expired" });
    }
    request.session = { userId: session.userId, tokenHash };
    return next();
  };
}

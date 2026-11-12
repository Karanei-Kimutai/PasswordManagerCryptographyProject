/**
 * @file authRoutes.js
 *
 * Account creation and sign-in, without the server ever learning the master
 * password.
 *
 * Sign-in takes two round trips:
 *
 *   Browser                                              Server
 *   ───────                                              ──────
 *   POST /api/auth/prelogin { email }            ─────▶
 *                                                ◀─────  { kdf: { salt, iterations } }
 *   PBKDF2(masterPassword, salt) → masterKey
 *   authKey = HMAC(masterKey, "server-authentication")
 *   POST /api/auth/login { email, authKey }      ─────▶  scrypt(authKey) == stored hash?
 *                                                ◀─────  Set-Cookie: session
 *
 * The first step exists because the salt is per-user and the browser needs it
 * before it can derive anything.
 */

import { createHmac } from "node:crypto";
import { Router } from "express";
import { DEFAULT_PBKDF2_ITERATIONS, KDF_ALGORITHM } from "@tessera/crypto";

import { hashAuthKey, simulateAuthKeyVerification, verifyAuthKey } from "../security/authHashing.js";
import { rateLimiter } from "../security/httpProtections.js";
import { endSession, requireSession, startSession } from "../security/sessions.js";
import {
  RequestValidationError,
  validateAuthKey,
  validateEmail,
  validateKdf,
  validateSerializedVault,
} from "../validation.js";

const genericLoginFailure = "Incorrect email or master password";

/**
 * @param {{ database: ReturnType<import("../database.js").openDatabase>, config: object }} dependencies
 */
export function createAuthRouter({ database, config }) {
  const router = Router();
  const { statements } = database;

  // Online guessing is limited per (IP address, email) pair.
  const loginLimiter = rateLimiter({
    ...config.loginRateLimit,
    keyOf: (request) => `${request.ip}|${String(request.body?.email ?? "").toLowerCase()}`,
  });

  /**
   * POST /api/auth/prelogin
   *
   * Returns the KDF parameters for an email. For an email with no account we
   * return a *fake but stable* salt, HMAC(serverSecret, email), instead of an
   * error. Otherwise anyone could find out which emails are registered.
   */
  router.post("/prelogin", (request, response) => {
    const email = validateEmail(request.body?.email);
    const user = statements.findUserByEmail.get(email);
    if (user) {
      return response.json({
        kdf: { algorithm: user.kdfAlgorithm, iterations: user.kdfIterations, salt: user.kdfSalt },
      });
    }
    const fakeSalt = createHmac("sha256", config.serverSecret)
      .update(`prelogin:${email.toLowerCase()}`)
      .digest()
      .subarray(0, 16)
      .toString("base64");
    return response.json({
      kdf: { algorithm: KDF_ALGORITHM, iterations: DEFAULT_PBKDF2_ITERATIONS, salt: fakeSalt },
    });
  });

  /**
   * POST /api/auth/register
   * Body: { email, kdf, authKey, vault }
   *
   * The browser generated the salt, derived the keys and built an empty
   * vault (version 0) before calling this.
   */
  router.post("/register", loginLimiter, async (request, response) => {
    const email = validateEmail(request.body?.email);
    const kdf = validateKdf(request.body?.kdf, config);
    const authKey = validateAuthKey(request.body?.authKey);
    const vaultVersion = validateSerializedVault(request.body?.vault, { kdfSalt: kdf.salt, kdfIterations: kdf.iterations });
    if (vaultVersion !== 0) {
      throw new RequestValidationError("A new vault must start at version 0");
    }
    if (statements.findUserByEmail.get(email)) {
      return response.status(409).json({ error: "An account with this email already exists" });
    }

    const { authHash, authHashSalt } = await hashAuthKey(authKey);
    const now = new Date().toISOString();
    let userId;
    try {
      database.transaction(() => {
        const result = statements.insertUser.run({
          email,
          kdfAlgorithm: kdf.algorithm,
          kdfIterations: kdf.iterations,
          kdfSalt: kdf.salt,
          authHash,
          authHashSalt,
          createdAt: now,
        });
        userId = Number(result.lastInsertRowid);
        statements.insertVault.run(userId, 0, request.body.vault, now);
      });
    } catch (error) {
      // Two simultaneous registrations for the same email: the UNIQUE constraint wins.
      if (String(error.code).startsWith("SQLITE_CONSTRAINT")) {
        return response.status(409).json({ error: "An account with this email already exists" });
      }
      throw error;
    }
    startSession(response, database, userId, config);
    return response.status(201).json({ email });
  });

  /**
   * POST /api/auth/login
   * Body: { email, authKey }
   *
   * Unknown emails and wrong passwords get the same message and take the
   * same time, so the response reveals nothing about which emails exist.
   */
  router.post("/login", loginLimiter, async (request, response) => {
    const email = validateEmail(request.body?.email);
    const authKey = validateAuthKey(request.body?.authKey);
    const user = statements.findUserByEmail.get(email);
    if (!user) {
      await simulateAuthKeyVerification();
      return response.status(401).json({ error: genericLoginFailure });
    }
    const isValid = await verifyAuthKey(authKey, user.authHash, user.authHashSalt);
    if (!isValid) {
      return response.status(401).json({ error: genericLoginFailure });
    }
    startSession(response, database, user.id, config);
    return response.json({ email: user.email });
  });

  /** POST /api/auth/logout: ends the session. Always succeeds. */
  router.post("/logout", (request, response) => {
    endSession(request, response, database);
    response.status(204).end();
  });

  /** GET /api/auth/session: who am I? Used when the page loads. */
  router.get("/session", requireSession(database), (request, response) => {
    const user = statements.findUserById.get(request.session.userId);
    response.json({ email: user.email });
  });

  return router;
}

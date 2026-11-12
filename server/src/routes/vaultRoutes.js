/**
 * @file vaultRoutes.js
 *
 * Storing and fetching the encrypted vault, plus changing the master password.
 *
 * ─── Optimistic concurrency ─────────────────────────────────────────────
 *
 * The same account may be open on several devices. Every save says which
 * version it was built on (`expectedVersion`) and must carry exactly the
 * next version number. If another device saved first, the versions no
 * longer line up and the server answers 409 Conflict. The client then
 * reloads the latest vault rather than silently overwriting the other
 * device's change.
 *
 * This also keeps the version counter monotonic on the server, which is what
 * the client-side rollback defense relies on. The server does not *enforce*
 * that defense (it cannot, since a malicious server is the threat). The
 * client does, by refusing any version older than one it has already seen.
 */

import { Router } from "express";

import { hashAuthKey, verifyAuthKey } from "../security/authHashing.js";
import { requireSession } from "../security/sessions.js";
import {
  RequestValidationError,
  validateAuthKey,
  validateExpectedVersion,
  validateKdf,
  validateSerializedVault,
} from "../validation.js";

/**
 * @param {{ database: ReturnType<import("../database.js").openDatabase>, config: object }} dependencies
 */
export function createVaultRouter({ database, config }) {
  const router = Router();
  const { statements } = database;
  router.use(requireSession(database));

  /** GET /api/vault → { vault, version, updatedAt } */
  router.get("/vault", (request, response) => {
    const vault = statements.findVault.get(request.session.userId);
    response.json({ vault: vault.data, version: vault.version, updatedAt: vault.updatedAt });
  });

  /**
   * PUT /api/vault
   * Body: { vault, expectedVersion }
   * The new vault's version must be expectedVersion + 1.
   */
  router.put("/vault", (request, response) => {
    const user = statements.findUserById.get(request.session.userId);
    const expectedVersion = validateExpectedVersion(request.body?.expectedVersion);
    const newVersion = validateSerializedVault(request.body?.vault, user);
    if (newVersion !== expectedVersion + 1) {
      throw new RequestValidationError("The new vault version must be expectedVersion + 1");
    }

    const result = statements.updateVault.run(
      newVersion,
      request.body.vault,
      new Date().toISOString(),
      user.id,
      expectedVersion, // the WHERE clause makes the check-and-write atomic
    );
    if (result.changes === 0) {
      const current = statements.findVault.get(user.id);
      return response.status(409).json({
        error: "The vault was changed on another device",
        currentVersion: current.version,
      });
    }
    return response.json({ version: newVersion });
  });

  /**
   * POST /api/account/master-password
   * Body: { currentAuthKey, newAuthKey, newKdf, vault, expectedVersion }
   *
   * The browser has already re-encrypted the whole vault under keys derived
   * from the new password and a new salt. Here we atomically swap in the new
   * credentials and the re-encrypted vault, and sign out every other device,
   * since their in-memory keys are now stale.
   */
  router.post("/account/master-password", async (request, response) => {
    const user = statements.findUserById.get(request.session.userId);
    const currentAuthKey = validateAuthKey(request.body?.currentAuthKey);
    const newAuthKey = validateAuthKey(request.body?.newAuthKey);
    const newKdf = validateKdf(request.body?.newKdf, config);
    const expectedVersion = validateExpectedVersion(request.body?.expectedVersion);
    const newVersion = validateSerializedVault(request.body?.vault, {
      kdfSalt: newKdf.salt,
      kdfIterations: newKdf.iterations,
    });
    if (newVersion !== expectedVersion + 1) {
      throw new RequestValidationError("The new vault version must be expectedVersion + 1");
    }

    // Re-check the current password even though a session exists. Someone who
    // walks up to an unlocked browser should not be able to take over the account.
    if (!(await verifyAuthKey(currentAuthKey, user.authHash, user.authHashSalt))) {
      return response.status(401).json({ error: "Current master password is incorrect" });
    }

    const { authHash, authHashSalt } = await hashAuthKey(newAuthKey);
    let conflict = false;
    database.transaction(() => {
      const result = statements.updateVault.run(newVersion, request.body.vault, new Date().toISOString(), user.id, expectedVersion);
      if (result.changes === 0) {
        conflict = true;
        return;
      }
      statements.updateUserCredentials.run({
        userId: user.id,
        kdfAlgorithm: newKdf.algorithm,
        kdfIterations: newKdf.iterations,
        kdfSalt: newKdf.salt,
        authHash,
        authHashSalt,
      });
      statements.deleteOtherSessions.run(user.id, request.session.tokenHash);
    });
    if (conflict) {
      return response.status(409).json({ error: "The vault was changed on another device. Reload and try again." });
    }
    return response.json({ version: newVersion });
  });

  return router;
}

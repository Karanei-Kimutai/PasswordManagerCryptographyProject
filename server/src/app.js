/**
 * @file app.js
 *
 * Builds the Express application. Kept separate from index.js so tests can
 * create an app backed by an in-memory database without opening a port.
 */

import { existsSync } from "node:fs";
import path from "node:path";
import cookieParser from "cookie-parser";
import express from "express";

import { createAuthRouter } from "./routes/authRoutes.js";
import { createVaultRouter } from "./routes/vaultRoutes.js";
import { csrfGuard, securityHeaders } from "./security/httpProtections.js";
import { MAX_VAULT_CHARACTERS, RequestValidationError } from "./validation.js";

/**
 * @param {{ database: ReturnType<import("./database.js").openDatabase>, config: object }} dependencies
 * @returns {import("express").Express}
 */
export function createApp({ database, config }) {
  const app = express();
  const fullConfig = {
    loginRateLimit: { windowMs: 15 * 60 * 1000, maxAttempts: 10 },
    ...config,
  };

  app.disable("x-powered-by"); // don't advertise the framework
  if (fullConfig.trustProxy) {
    app.set("trust proxy", fullConfig.trustProxy);
  }
  app.use(securityHeaders(fullConfig));
  // The vault travels as a JSON string inside the body, so allow a little
  // more than the vault limit itself for the surrounding fields.
  app.use(express.json({ limit: MAX_VAULT_CHARACTERS + 64 * 1024 }));
  app.use(cookieParser());
  app.use("/api", csrfGuard());

  app.use("/api/auth", createAuthRouter({ database, config: fullConfig }));
  app.use("/api", createVaultRouter({ database, config: fullConfig }));
  app.use("/api", (request, response) => response.status(404).json({ error: "Not found" }));

  // In production the same server also serves the built React app.
  if (fullConfig.isProduction && existsSync(fullConfig.clientDistDirectory)) {
    app.use(express.static(fullConfig.clientDistDirectory, { index: false }));
    // Express 5 syntax for "any other path": send index.html so the SPA loads.
    app.get("/{*anyPath}", (request, response) => {
      response.sendFile(path.join(fullConfig.clientDistDirectory, "index.html"));
    });
  }

  // Central error handler: validation problems become 400s. Anything else is
  // logged and reported as a generic 500, so internals never leak to clients.
  // eslint-disable-next-line no-unused-vars
  app.use((error, request, response, next) => {
    if (error instanceof RequestValidationError) {
      return response.status(400).json({ error: error.message });
    }
    if (error.type === "entity.too.large") {
      return response.status(413).json({ error: "Vault is too large" });
    }
    if (error.type === "entity.parse.failed") {
      return response.status(400).json({ error: "Malformed JSON" });
    }
    console.error(error);
    return response.status(500).json({ error: "Internal server error" });
  });

  return app;
}

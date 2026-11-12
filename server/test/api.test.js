/**
 * @file api.test.js
 *
 * End-to-end tests of the API. Each test plays the role of the browser,
 * deriving keys and building vaults with the real @tessera/crypto package, and
 * talks to a real server instance backed by an in-memory database.
 */

import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";

import {
  RollbackError,
  Vault,
  createKdfParameters,
  deriveVaultKeys,
} from "@tessera/crypto";

import { createApp } from "../src/app.js";
import { openDatabase } from "../src/database.js";

const testConfig = {
  isProduction: false,
  serverSecret: Buffer.alloc(32, 7),
  clientDistDirectory: "/nonexistent",
  sessionLifetimeMs: 60_000,
  allowWeakKdf: true, // so tests can use 1,000 PBKDF2 iterations
  loginRateLimit: { windowMs: 60_000, maxAttempts: 5 },
};
const fastKdf = () => createKdfParameters({ iterations: 1000 });
const weak = { allowWeakKdf: true };

let server;
let baseUrl;
let database;

before(async () => {
  database = openDatabase(":memory:");
  const app = createApp({ database, config: testConfig });
  await new Promise((resolve) => {
    server = app.listen(0, "127.0.0.1", resolve);
  });
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => {
  server.close();
  database.close();
});

/** A minimal browser stand-in: remembers its session cookie between requests. */
class TestClient {
  cookie = null;

  async request(method, path, body) {
    const headers = {};
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
    }
    if (this.cookie) {
      headers.Cookie = this.cookie;
    }
    const response = await fetch(baseUrl + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const setCookie = response.headers.get("set-cookie");
    if (setCookie) {
      this.cookie = setCookie.split(";")[0];
    }
    const text = await response.text();
    return { status: response.status, headers: response.headers, body: text ? JSON.parse(text) : null };
  }

  /** The full sign-up flow a browser performs. */
  async register(email, masterPassword) {
    const keys = await deriveVaultKeys(masterPassword, fastKdf(), weak);
    const { serializedVault } = await Vault.create(keys).dump();
    const response = await this.request("POST", "/api/auth/register", {
      email,
      kdf: keys.kdf,
      authKey: keys.authKey,
      vault: serializedVault,
    });
    return { response, keys };
  }

  /** The full sign-in flow: prelogin → derive → login → fetch vault. */
  async login(email, masterPassword) {
    const prelogin = await this.request("POST", "/api/auth/prelogin", { email });
    const keys = await deriveVaultKeys(masterPassword, prelogin.body.kdf, weak);
    const response = await this.request("POST", "/api/auth/login", { email, authKey: keys.authKey });
    return { response, keys };
  }
}

let emailCounter = 0;
const uniqueEmail = () => `user${++emailCounter}@example.com`;

describe("accounts", () => {
  it("registers, signs in and reports the session", async () => {
    const email = uniqueEmail();
    const client = new TestClient();
    const { response } = await client.register(email, "master password");
    assert.equal(response.status, 201);

    const fresh = new TestClient();
    const login = await fresh.login(email, "master password");
    assert.equal(login.response.status, 200);
    const session = await fresh.request("GET", "/api/auth/session");
    assert.equal(session.body.email, email);
  });

  it("rejects a duplicate email", async () => {
    const email = uniqueEmail();
    await new TestClient().register(email, "pw");
    const { response } = await new TestClient().register(email.toUpperCase(), "pw");
    assert.equal(response.status, 409);
  });

  it("rejects a wrong master password with a generic message", async () => {
    const email = uniqueEmail();
    await new TestClient().register(email, "right");
    const { response } = await new TestClient().login(email, "wrong");
    assert.equal(response.status, 401);
    assert.equal(response.body.error, "Incorrect email or master password");
  });

  it("does not reveal whether an email is registered", async () => {
    const unknownEmail = "nobody@example.com";
    const client = new TestClient();
    const first = await client.request("POST", "/api/auth/prelogin", { email: unknownEmail });
    const second = await client.request("POST", "/api/auth/prelogin", { email: unknownEmail });
    assert.equal(first.status, 200);
    assert.deepEqual(first.body, second.body); // stable fake salt
    const login = await client.request("POST", "/api/auth/login", {
      email: unknownEmail,
      authKey: Buffer.alloc(32).toString("base64"),
    });
    assert.equal(login.body.error, "Incorrect email or master password");
  });

  it("never stores the authKey or anything readable", async () => {
    const email = uniqueEmail();
    const { keys } = await new TestClient().register(email, "pw");
    const dump = JSON.stringify(database.raw.prepare("SELECT * FROM users WHERE email = ?").get(email));
    assert.ok(!dump.includes(keys.authKey));
  });

  it("rate-limits repeated login attempts", async () => {
    const email = uniqueEmail();
    await new TestClient().register(email, "pw");
    const client = new TestClient();
    const statuses = [];
    for (let attempt = 0; attempt < 7; attempt++) {
      statuses.push(
        (await client.request("POST", "/api/auth/login", { email, authKey: Buffer.alloc(32).toString("base64") })).status,
      );
    }
    assert.ok(statuses.includes(429));
  });

  it("signs out", async () => {
    const client = new TestClient();
    await client.register(uniqueEmail(), "pw");
    await client.request("POST", "/api/auth/logout", {});
    assert.equal((await client.request("GET", "/api/vault")).status, 401);
  });
});

describe("vault storage", () => {
  it("requires a session", async () => {
    assert.equal((await new TestClient().request("GET", "/api/vault")).status, 401);
  });

  it("stores and returns the encrypted vault", async () => {
    const client = new TestClient();
    const { keys } = await client.register(uniqueEmail(), "pw");
    const vault = Vault.create(keys);
    await vault.setEntry({ site: "github.com", username: "me", password: "s3cret" });
    const { serializedVault } = await vault.dump();

    const save = await client.request("PUT", "/api/vault", { vault: serializedVault, expectedVersion: 0 });
    assert.equal(save.status, 200);
    assert.equal(save.body.version, 1);

    const fetched = await client.request("GET", "/api/vault");
    const loaded = await Vault.load(keys, fetched.body.vault);
    assert.equal((await loaded.getEntry("github.com", "me")).password, "s3cret");
    assert.ok(!fetched.body.vault.includes("s3cret"));
  });

  it("refuses a stale save from another device (409 Conflict)", async () => {
    const email = uniqueEmail();
    const deviceA = new TestClient();
    const { keys } = await deviceA.register(email, "pw");
    const deviceB = new TestClient();
    await deviceB.login(email, "pw");

    const vaultA = Vault.create(keys);
    await vaultA.setEntry({ site: "a.com", password: "x" });
    assert.equal((await deviceA.request("PUT", "/api/vault", { vault: (await vaultA.dump()).serializedVault, expectedVersion: 0 })).status, 200);

    const vaultB = Vault.create(keys);
    await vaultB.setEntry({ site: "b.com", password: "y" });
    const conflict = await deviceB.request("PUT", "/api/vault", { vault: (await vaultB.dump()).serializedVault, expectedVersion: 0 });
    assert.equal(conflict.status, 409);
    assert.equal(conflict.body.currentVersion, 1);
  });

  it("rejects versions that do not advance by exactly one", async () => {
    const client = new TestClient();
    const { keys } = await client.register(uniqueEmail(), "pw");
    const vault = Vault.create(keys);
    await vault.setEntry({ site: "a.com", password: "x" });
    await vault.setEntry({ site: "b.com", password: "x" });
    const response = await client.request("PUT", "/api/vault", { vault: (await vault.dump()).serializedVault, expectedVersion: 0 });
    assert.equal(response.status, 400);
  });

  it("rejects non-JSON requests (CSRF guard)", async () => {
    const response = await fetch(`${baseUrl}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "email=a@b.c",
    });
    assert.equal(response.status, 415);
  });

  it("rejects cross-origin requests", async () => {
    const response = await fetch(`${baseUrl}/api/auth/prelogin`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: "https://evil.example" },
      body: JSON.stringify({ email: "a@b.co" }),
    });
    assert.equal(response.status, 403);
  });

  it("sends security headers", async () => {
    const response = await new TestClient().request("POST", "/api/auth/prelogin", { email: "a@b.co" });
    assert.match(response.headers.get("content-security-policy"), /script-src 'self'/);
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.equal(response.headers.get("x-powered-by"), null);
  });
});

describe("attacks by a malicious server", () => {
  it("a rolled-back vault is detected by the client", async () => {
    const client = new TestClient();
    const { keys } = await client.register(uniqueEmail(), "pw");
    const vault = Vault.create(keys);
    await vault.setEntry({ site: "bank.com", password: "old" });
    const oldDump = await vault.dump();
    await client.request("PUT", "/api/vault", { vault: oldDump.serializedVault, expectedVersion: 0 });

    await vault.setEntry({ site: "bank.com", password: "new" }, { previousId: (await vault.getEntry("bank.com", "")).id });
    const newDump = await vault.dump();
    await client.request("PUT", "/api/vault", { vault: newDump.serializedVault, expectedVersion: 1 });
    const trustedState = { version: newDump.version, checksum: newDump.checksum };

    // The "server" swaps the old vault back in, directly in its database.
    database.raw.prepare("UPDATE vaults SET data = ?, version = 1").run(oldDump.serializedVault);
    const fetched = await client.request("GET", "/api/vault");
    await assert.rejects(Vault.load(keys, fetched.body.vault, { trustedState }), RollbackError);
  });
});

describe("master password change", () => {
  it("re-encrypts the vault, replaces credentials and signs out other devices", async () => {
    const email = uniqueEmail();
    const deviceA = new TestClient();
    const { keys: oldKeys } = await deviceA.register(email, "old password");
    const deviceB = new TestClient();
    await deviceB.login(email, "old password");

    const vault = Vault.create(oldKeys);
    await vault.setEntry({ site: "a.com", password: "kept" });
    await deviceA.request("PUT", "/api/vault", { vault: (await vault.dump()).serializedVault, expectedVersion: 0 });

    const newKeys = await deriveVaultKeys("new password", fastKdf(), weak);
    const rekeyed = await vault.rekey(newKeys);
    const change = await deviceA.request("POST", "/api/account/master-password", {
      currentAuthKey: oldKeys.authKey,
      newAuthKey: newKeys.authKey,
      newKdf: newKeys.kdf,
      vault: (await rekeyed.dump()).serializedVault,
      expectedVersion: 1,
    });
    assert.equal(change.status, 200);

    // Device B was signed out.
    assert.equal((await deviceB.request("GET", "/api/vault")).status, 401);
    // The old password no longer works; the new one does, and the data survived.
    assert.equal((await new TestClient().login(email, "old password")).response.status, 401);
    const deviceC = new TestClient();
    const { keys } = await deviceC.login(email, "new password");
    const fetched = await deviceC.request("GET", "/api/vault");
    const loaded = await Vault.load(keys, fetched.body.vault);
    assert.equal((await loaded.getEntry("a.com", "")).password, "kept");
    await assert.rejects(Vault.load(oldKeys, fetched.body.vault));
  });

  it("requires the current password", async () => {
    const client = new TestClient();
    const { keys } = await client.register(uniqueEmail(), "pw");
    const newKeys = await deriveVaultKeys("new", fastKdf(), weak);
    const rekeyed = await Vault.create(keys).rekey(newKeys);
    const response = await client.request("POST", "/api/account/master-password", {
      currentAuthKey: newKeys.authKey, // wrong
      newAuthKey: newKeys.authKey,
      newKdf: newKeys.kdf,
      vault: (await rekeyed.dump()).serializedVault,
      expectedVersion: 0,
    });
    assert.equal(response.status, 401);
  });
});

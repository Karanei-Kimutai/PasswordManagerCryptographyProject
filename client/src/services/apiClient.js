/**
 * @file apiClient.js
 *
 * Thin wrapper around `fetch` for Tessera's JSON API.
 *
 * Everything sent through here is either public (email, salt, iteration
 * count), a derived credential (authKey), or already encrypted (the vault).
 * Plaintext entries and the master password never pass through this module.
 */

/** An API error carrying the HTTP status and the server's response body. */
export class ApiError extends Error {
  constructor(status, body) {
    super(body?.error ?? `Request failed (${status})`);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

/**
 * Sends a JSON request to the API. The session cookie is HttpOnly and
 * SameSite=Strict, so the browser attaches it automatically and page scripts
 * can never read it.
 *
 * @param {"GET" | "POST" | "PUT"} method
 * @param {string} path
 * @param {object} [body]
 */
async function request(method, path, body) {
  let response;
  try {
    response = await fetch(`/api${path}`, {
      method,
      credentials: "same-origin",
      headers: body === undefined ? {} : { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, { error: "Cannot reach the server. Check your connection." });
  }
  const text = await response.text();
  let parsed = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = { error: `Unexpected response from server (${response.status})` };
  }
  if (!response.ok) {
    throw new ApiError(response.status, parsed);
  }
  return parsed;
}

export const apiClient = {
  getSession: () => request("GET", "/auth/session"),
  prelogin: (email) => request("POST", "/auth/prelogin", { email }),
  register: (payload) => request("POST", "/auth/register", payload),
  login: (email, authKey) => request("POST", "/auth/login", { email, authKey }),
  logout: () => request("POST", "/auth/logout", {}),
  getVault: () => request("GET", "/vault"),
  putVault: (vault, expectedVersion) => request("PUT", "/vault", { vault, expectedVersion }),
  changeMasterPassword: (payload) => request("POST", "/account/master-password", payload),
};

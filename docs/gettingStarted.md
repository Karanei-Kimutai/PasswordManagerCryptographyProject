# Getting started

## Requirements

- **Node.js 20.19 or newer** (Vite 7 needs 20.19+; the code relies on the global `crypto`, `btoa`/`atob` and `TextEncoder`, all built into Node 20).
- **npm** 9+ (for workspaces).
- A C/C++ toolchain is *not* normally needed: `better-sqlite3` ships prebuilt binaries for common platforms.

## Install

From the repository root:

```bash
npm install
```

This is an **npm workspaces** monorepo. One install sets up all three packages and links `@tessera/crypto` into the server and the client.

## Run in development

```bash
npm run dev
```

This starts two processes (via `concurrently`):

| Process | URL | What it does |
|---|---|---|
| `server` | http://localhost:3001 | Express API, restarted on file changes (`node --watch`) |
| `client` | **http://localhost:5173** | Vite dev server with hot reload; proxies `/api` to :3001 |

Open **http://localhost:5173**. The proxy makes the browser see one origin, as in production, which matters because the session cookie is `SameSite=Strict` and the CSRF guard checks the `Origin` header.

## Run in production mode

```bash
npm run build   # builds client/dist
npm start       # NODE_ENV=production; serves the API *and* client/dist on :3001
```

In production mode the server also:

- marks the session cookie `Secure` (HTTPS only; browsers treat `http://localhost` as secure, so local testing still works),
- sends `Strict-Transport-Security`,
- serves `client/dist` with a single-page-app fallback.

Deploy behind HTTPS. If you put a reverse proxy in front, configure `trustProxy` in `server/src/app.js` (see [Express "trust proxy"](https://expressjs.com/en/guide/behind-proxies.html)) so rate limiting sees real client IPs.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `3001` | HTTP port |
| `TESSERA_DATA_DIR` | `server/data` | Folder for `tessera.sqlite` and `serverSecret` |
| `NODE_ENV` | (unset) | `production` enables Secure cookies, HSTS and static serving |

`server/data/` is git-ignored. Delete it to reset all accounts.

## Test

```bash
npm test
```

This runs both suites with Node's built-in test runner (`node:test`):

- `packages/crypto/test/`: 46 tests of the cryptographic core, including simulated attacks.
- `server/test/`: 17 end-to-end API tests against a real server with an in-memory database.

See [testing.md](testing.md) for details.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `Cannot reach the server` in the app | The API process isn't running. Use `npm run dev`, not only the client. |
| Sign-in takes about a second | Expected: PBKDF2 with 600,000 iterations runs in the browser on every unlock. |
| "Possible rollback attack" after resetting `server/data` | This browser remembers a newer vault version for that email. Clear the site's data (localStorage) or use another email. This is the rollback defense doing its job. |
| `better-sqlite3` install fails | Your platform lacks a prebuilt binary. Install build tools (Python 3, make, a C++ compiler) and reinstall. |

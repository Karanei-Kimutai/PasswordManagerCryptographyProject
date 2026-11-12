# Web application security

The cryptography protects data on the server and in transit. This page covers the threats that exist *because Tessera runs in a browser*, and the UI behaviours that protect the user.

## Content Security Policy (CSP)

**Code:** `securityHeaders` in [`server/src/security/httpProtections.js`](../../server/src/security/httpProtections.js)

In a web password manager, the most dangerous bug is **cross-site scripting (XSS)**. An injected script runs inside the unlocked page and can read every decrypted password. Our CSP:

```
default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;
font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none';
form-action 'self'; frame-ancestors 'none'
```

- **`script-src 'self'`:** only script files from our own origin run. No inline `<script>`, no `eval`, no CDNs. The production build was checked to contain no inline scripts.
- **`style-src 'self'`:** no inline styles either, which is why the React code never uses `style={…}`. All styling is in CSS files.
- **`connect-src 'self'`:** even if a script did get injected, it could not `fetch` stolen data to another host.
- **`frame-ancestors 'none'`:** the app cannot be embedded in an iframe, which prevents clickjacking.

React also escapes everything it renders by default, and Tessera never uses `dangerouslySetInnerHTML`.

## Other headers

| Header | Value | Why |
|---|---|---|
| `X-Content-Type-Options` | `nosniff` | Browsers must not guess content types (stops script-as-image tricks) |
| `Referrer-Policy` | `no-referrer` | Leaving Tessera (e.g. "Open website") never tells the destination where you came from |
| `X-Frame-Options` | `DENY` | Clickjacking defense for older browsers |
| `Cross-Origin-Opener-Policy` | `same-origin` | Isolates the window from pages it opens |
| `Permissions-Policy` | camera, microphone, geolocation, payment disabled | Least privilege |
| `Cache-Control` (API) | `no-store` | The vault must never sit in a browser or proxy cache |
| `Strict-Transport-Security` | 1 year (production) | Always HTTPS |
| `X-Powered-By` | removed | Don't advertise the framework |

Links that open websites use `rel="noopener noreferrer"`.

## No third-party requests

- **Fonts** (IBM Plex) are bundled from npm (`@fontsource`), not loaded from a font CDN.
- **No favicons are fetched.** Many password managers show site icons by asking an icon service for `https://icons.example/github.com`. That tells the service which sites are in your vault. Tessera shows a neutral letter tile (`Monogram`) instead.
- No analytics, no trackers.

## Protecting the unlocked session

| Behaviour | Code | Rationale |
|---|---|---|
| **Lock on reload** | `App.jsx` | Keys exist only in memory. A reload always lands on the lock screen. |
| **Auto-lock** after 1/5/15/30/60 min idle (default 5) | `useIdleTimer.js` | A periodic check also catches the computer waking from sleep after the deadline. |
| **Manual Lock** button | `VaultScreen.jsx` | Discards keys and decrypted entries but keeps you signed in. |
| **Masked by default** with a fixed 12-dot mask | `SecretValue` in `common.jsx` | The mask is the same for every password, so it doesn't reveal the length to an onlooker. |
| **Reveal times out** after 20 s | `SecretValue` | Revealing is a deliberate act, and the password doesn't stay on screen if the user walks away. |
| **Clipboard clears** after 30 s | `clipboard.js` | Only if it still holds what we copied, so it won't wipe something the user copied since. Also cleared on lock and sign-out. |
| **Contextual copy confirmation** ("Copied · clears in 30s") | `CopyButton` | Tells the user both that it worked and what will happen. |
| `autocomplete` hints | forms | `current-password` / `new-password` let the browser and OS behave correctly. Item passwords use `new-password` so the browser doesn't try to autofill Tessera's own fields. |

## What's still in memory

While unlocked, decrypted entries live in React state as JavaScript strings. JavaScript gives no way to wipe strings, so they remain in the heap until garbage-collected. This is a limitation shared by every browser-based password manager. Locking drops all references so they can be collected.

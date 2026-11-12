/**
 * @file httpProtections.js
 *
 * HTTP-level hardening: security headers, a CSRF guard and a rate limiter.
 *
 * A web password manager has one weakness a native app does not: the server
 * delivers the code that does the encryption. If an attacker can inject a
 * script into the page (XSS), that script runs after the user unlocks the
 * vault and can read the plaintext. The Content Security Policy below is the
 * main defense: the browser will only run scripts loaded from our own origin,
 * never inline scripts or scripts from other hosts.
 */

/**
 * Sets security headers on every response.
 *
 * @param {{ isProduction: boolean }} config
 */
export function securityHeaders(config) {
  const contentSecurityPolicy = [
    "default-src 'self'",
    "script-src 'self'", // no inline scripts, no third-party scripts, no eval
    "style-src 'self'", // no inline styles either
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'", // the page can only talk to our own API
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'", // the page cannot be framed (prevents clickjacking)
  ].join("; ");

  return (request, response, next) => {
    response.setHeader("Content-Security-Policy", contentSecurityPolicy);
    response.setHeader("X-Content-Type-Options", "nosniff");
    response.setHeader("Referrer-Policy", "no-referrer");
    response.setHeader("X-Frame-Options", "DENY");
    response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    response.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
    if (request.path.startsWith("/api")) {
      // Never let a browser or proxy cache API responses (they include the vault).
      response.setHeader("Cache-Control", "no-store");
    }
    if (config.isProduction) {
      response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    }
    next();
  };
}

/**
 * CSRF guard for state-changing requests (anything except GET/HEAD).
 *
 * The session cookie is already SameSite=Strict. As a second layer, we
 * require:
 * - `Content-Type: application/json`. A plain HTML form on another site
 *   cannot send JSON, and a cross-site `fetch` with a JSON body triggers a
 *   CORS preflight, which this server never approves.
 * - If an `Origin` header is present, it must match our own host.
 */
export function csrfGuard() {
  return (request, response, next) => {
    if (request.method === "GET" || request.method === "HEAD") {
      return next();
    }
    if (!request.is("application/json")) {
      return response.status(415).json({ error: "Requests must be JSON" });
    }
    const origin = request.get("origin");
    if (origin) {
      let originHost;
      try {
        originHost = new URL(origin).host;
      } catch {
        return response.status(403).json({ error: "Bad origin" });
      }
      if (originHost !== request.get("host")) {
        return response.status(403).json({ error: "Cross-origin request refused" });
      }
    }
    return next();
  };
}

/**
 * A small fixed-window rate limiter kept in memory. It slows down online
 * guessing against the login endpoint. (Offline guessing is what PBKDF2 and
 * scrypt are for.)
 *
 * @param {{ windowMs: number, maxAttempts: number, keyOf: (request) => string }} options
 */
export function rateLimiter({ windowMs, maxAttempts, keyOf }) {
  /** @type {Map<string, { count: number, windowStart: number }>} */
  const attempts = new Map();

  return (request, response, next) => {
    const now = Date.now();
    const key = keyOf(request);
    let bucket = attempts.get(key);
    if (!bucket || now - bucket.windowStart >= windowMs) {
      bucket = { count: 0, windowStart: now };
      attempts.set(key, bucket);
    }
    bucket.count += 1;

    // Occasionally drop stale buckets so memory does not grow without bound.
    if (attempts.size > 10_000) {
      for (const [bucketKey, value] of attempts) {
        if (now - value.windowStart >= windowMs) {
          attempts.delete(bucketKey);
        }
      }
    }

    if (bucket.count > maxAttempts) {
      const retryAfterSeconds = Math.ceil((bucket.windowStart + windowMs - now) / 1000);
      response.setHeader("Retry-After", String(retryAfterSeconds));
      return response.status(429).json({ error: "Too many attempts. Try again later." });
    }
    return next();
  };
}

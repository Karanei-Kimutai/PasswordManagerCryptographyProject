/**
 * @file App.jsx
 *
 * The top-level state machine:
 *
 *   loading ──▶ signedOut ◀──────────────────────────┐
 *      │            │ sign in / create vault          │ sign out / session expired
 *      │            ▼                                 │
 *      └──▶ locked ──unlock──▶ unlocked ──────────────┘
 *              ▲                   │
 *              └── lock / idle ────┘
 *
 * "locked" means the server session is still valid but the keys are gone
 * from memory. Unlocking needs the master password again, because the keys
 * exist only while unlocked.
 */

import { useCallback, useEffect, useState } from "react";

import { AuthScreen } from "./components/AuthScreen.jsx";
import { ProgressLine } from "./components/common.jsx";
import { VaultScreen } from "./components/VaultScreen.jsx";
import { useIdleTimer } from "./hooks/useIdleTimer.js";
import { usePreference } from "./hooks/usePreference.js";
import { apiClient } from "./services/apiClient.js";
import { clearClipboardIfOurs } from "./services/clipboard.js";

export default function App() {
  const [phase, setPhase] = useState("loading");
  const [email, setEmail] = useState("");
  const [session, setSession] = useState(null);
  const [notice, setNotice] = useState(null);
  const [autoLockMinutes, setAutoLockMinutes] = usePreference("autoLockMinutes", 5);
  const [sortOrder, setSortOrder] = usePreference("sortOrder", "name");

  // On page load, a valid session cookie means "signed in but locked": the
  // keys never survive a reload, so the master password is needed again.
  useEffect(() => {
    apiClient
      .getSession()
      .then((result) => {
        setEmail(result.email);
        setPhase("locked");
      })
      .catch(() => setPhase("signedOut"));
  }, []);

  const handleUnlocked = useCallback((newSession) => {
    setSession(newSession);
    setEmail(newSession.email);
    setNotice(null);
    setPhase("unlocked");
  }, []);

  /** Drops the keys and decrypted data. The server session stays. */
  const lock = useCallback((reason = null) => {
    clearClipboardIfOurs();
    setSession(null);
    setNotice(reason);
    setPhase("locked");
  }, []);

  const signOut = useCallback(async () => {
    clearClipboardIfOurs();
    setSession(null);
    try {
      await apiClient.logout();
    } catch {
      // Even if the request fails, forget everything locally.
    }
    setNotice(null);
    setPhase("signedOut");
  }, []);

  const handleSessionExpired = useCallback(() => {
    clearClipboardIfOurs();
    setSession(null);
    setNotice({ severity: "info", text: "Your session ended. Please sign in again." });
    setPhase("signedOut");
  }, []);

  useIdleTimer(phase === "unlocked" ? autoLockMinutes : 0, () =>
    lock({
      severity: "info",
      text: `Locked after ${autoLockMinutes} minute${autoLockMinutes === 1 ? "" : "s"} without activity.`,
    }),
  );

  if (phase === "loading") {
    return (
      <div className="authScreen">
        <div />
        <div className="authMain">
          <ProgressLine label="Loading…" />
        </div>
      </div>
    );
  }

  if (phase === "unlocked" && session) {
    return (
      <VaultScreen
        session={session}
        autoLockMinutes={autoLockMinutes}
        onAutoLockMinutesChange={setAutoLockMinutes}
        onLock={() => lock({ severity: "info", text: "Vault locked. Your keys were cleared from memory." })}
        onSignOut={signOut}
        onSessionExpired={handleSessionExpired}
        sortOrder={sortOrder}
        onSortOrderChange={setSortOrder}
      />
    );
  }

  return (
    <AuthScreen
      key={phase}
      initialMode={phase === "locked" ? "unlock" : "signIn"}
      knownEmail={phase === "locked" ? email : ""}
      notice={notice}
      onUnlocked={handleUnlocked}
      onSignOut={signOut}
    />
  );
}

/**
 * @file AuthScreen.jsx
 *
 * One screen, three modes:
 * - "signIn": email + master password.
 * - "signUp": email + master password + confirmation, with an honest warning
 *   that the password cannot be recovered.
 * - "unlock": the vault is locked but the session is still valid. The email
 *   is known, and the screen states plainly that the vault is locked and
 *   what is needed to open it.
 *
 * The master password typed here is used only inside this browser, by
 * deriveVaultKeys(). It is never sent to the server.
 */

import { Lock, ShieldCheck } from "lucide-react";
import { useState } from "react";

import { VaultSession } from "../services/vaultSession.js";
import { describeError } from "../utils/formatting.js";
import { Brand, Message, ProgressLine } from "./common.jsx";

/** Minimum length for a new master password. */
const MIN_MASTER_PASSWORD_LENGTH = 12;

/**
 * @param {{
 *   initialMode: "signIn" | "signUp" | "unlock",
 *   knownEmail?: string,
 *   notice?: { severity: string, text: string } | null,
 *   onUnlocked: (session: VaultSession) => void,
 *   onSignOut: () => void,
 * }} props
 */
export function AuthScreen({ initialMode, knownEmail = "", notice = null, onUnlocked, onSignOut }) {
  const [mode, setMode] = useState(initialMode);
  const [email, setEmail] = useState(knownEmail);
  const [masterPassword, setMasterPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [progress, setProgress] = useState(null);
  const [error, setError] = useState(null);

  const isUnlock = mode === "unlock";
  const isSignUp = mode === "signUp";
  const isBusy = progress !== null;

  const switchMode = (newMode) => {
    setMode(newMode);
    setError(null);
    setMasterPassword("");
    setConfirmation("");
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError(null);
    if (isSignUp) {
      if (masterPassword.length < MIN_MASTER_PASSWORD_LENGTH) {
        setError({ severity: "warning", text: `Use at least ${MIN_MASTER_PASSWORD_LENGTH} characters.` });
        return;
      }
      if (masterPassword !== confirmation) {
        setError({ severity: "warning", text: "The two passwords do not match." });
        return;
      }
    }
    setProgress("Starting");
    try {
      const session = isSignUp
        ? await VaultSession.signUp(email, masterPassword, setProgress)
        : await VaultSession.signIn(email, masterPassword, setProgress);
      setMasterPassword("");
      setConfirmation("");
      onUnlocked(session);
    } catch (caught) {
      setError(describeError(caught));
      setProgress(null);
    }
  };

  const title = isUnlock ? "Vault locked" : isSignUp ? "Create your vault" : "Sign in to Tessera";
  const lead = isUnlock
    ? "Enter your master password to decrypt your vault on this device."
    : isSignUp
      ? "Your master password encrypts everything in this browser before it is stored. Tessera's server never sees it."
      : "Your vault is decrypted here, in your browser, never on the server.";

  return (
    <div className="authScreen">
      <header>
        <Brand />
      </header>

      <main className="authMain">
        <div className="authPanel">
          <div className="authStatus">
            {isUnlock ? <Lock aria-hidden="true" /> : <ShieldCheck aria-hidden="true" />}
            {isUnlock ? "Locked" : "End-to-end encrypted"}
          </div>
          <h1 className="authTitle">{title}</h1>
          <p className="authLead">{lead}</p>

          <form className="authForm" onSubmit={handleSubmit} noValidate>
            {notice && !error && <Message severity={notice.severity}>{notice.text}</Message>}
            {error && (
              <Message severity={error.severity} title={error.title}>
                {error.text}
              </Message>
            )}

            <label className="field">
              <span className="fieldLabel">Email</span>
              <input
                className="input"
                type="email"
                autoComplete="username"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                readOnly={isUnlock}
                required
                autoFocus={!isUnlock}
              />
            </label>

            <label className="field">
              <span className="fieldLabel">Master password</span>
              <input
                className="input mono"
                type="password"
                autoComplete={isSignUp ? "new-password" : "current-password"}
                value={masterPassword}
                onChange={(event) => setMasterPassword(event.target.value)}
                required
                autoFocus={isUnlock}
              />
              {isSignUp && (
                <span className="fieldHint">
                  At least {MIN_MASTER_PASSWORD_LENGTH} characters. A few unrelated words is long and easy to remember.
                </span>
              )}
            </label>

            {isSignUp && (
              <>
                <label className="field">
                  <span className="fieldLabel">Confirm master password</span>
                  <input
                    className="input mono"
                    type="password"
                    autoComplete="new-password"
                    value={confirmation}
                    onChange={(event) => setConfirmation(event.target.value)}
                    required
                  />
                </label>
                <Message severity="info">
                  There is no password reset. Tessera never has your master password, so if you forget it, nobody
                  (including us) can decrypt your vault.
                </Message>
              </>
            )}

            {isBusy ? (
              <ProgressLine label={`${progress}…`} />
            ) : (
              <button className="button buttonPrimary buttonWide" type="submit" disabled={!email || !masterPassword}>
                {isUnlock ? "Unlock" : isSignUp ? "Create vault" : "Sign in"}
              </button>
            )}
          </form>

          <div className="authSwitch">
            {isUnlock && (
              <>
                Not {email}?{" "}
                <button type="button" className="linkButton" onClick={onSignOut}>
                  Sign out
                </button>
              </>
            )}
            {mode === "signIn" && (
              <>
                New to Tessera?{" "}
                <button type="button" className="linkButton" onClick={() => switchMode("signUp")}>
                  Create a vault
                </button>
              </>
            )}
            {isSignUp && (
              <>
                Already have a vault?{" "}
                <button type="button" className="linkButton" onClick={() => switchMode("signIn")}>
                  Sign in
                </button>
              </>
            )}
          </div>
        </div>
      </main>

      <footer className="authFooter">
        PBKDF2-SHA256 key derivation · AES-256-GCM encryption · zero-knowledge server
      </footer>
    </div>
  );
}

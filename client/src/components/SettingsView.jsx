/**
 * @file SettingsView.jsx
 *
 * Account and security settings: change the master password, choose the
 * auto-lock timeout, and see exactly how this vault is protected.
 */

import { useEffect, useState } from "react";

import { readTrustedState } from "../services/trustedStateStore.js";
import { describeError } from "../utils/formatting.js";
import { Message, ProgressLine } from "./common.jsx";

export const AUTO_LOCK_CHOICES = [1, 5, 15, 30, 60];

/**
 * @param {{
 *   session: import("../services/vaultSession.js").VaultSession,
 *   autoLockMinutes: number,
 *   onAutoLockMinutesChange: (minutes: number) => void,
 *   onVaultChanged: () => void,
 *   onSessionExpired: () => void,
 * }} props
 */
export function SettingsView({ session, autoLockMinutes, onAutoLockMinutesChange, onVaultChanged, onSessionExpired }) {
  const [trustedVersion, setTrustedVersion] = useState(null);

  useEffect(() => {
    readTrustedState(session.email).then((state) => setTrustedVersion(state?.version ?? null));
  }, [session, session.version]);

  return (
    <div className="pageView">
      <header className="pageHeader">
        <h1 className="pageTitle">Settings</h1>
        <p className="pageLead">{session.email}</p>
      </header>

      <div className="pageBody">
        <ChangeMasterPasswordSection session={session} onChanged={onVaultChanged} onSessionExpired={onSessionExpired} />

        <section className="section">
          <div>
            <h2 className="sectionTitle">Auto-lock</h2>
            <p className="sectionDescription">
              After this long without activity, the keys are discarded from memory and the vault locks.
            </p>
          </div>
          <div className="sectionContent">
            <label className="field">
              <span className="fieldLabel">Lock after</span>
              <select
                className="select"
                value={autoLockMinutes}
                onChange={(event) => onAutoLockMinutesChange(Number(event.target.value))}
              >
                {AUTO_LOCK_CHOICES.map((minutes) => (
                  <option key={minutes} value={minutes}>
                    {minutes === 1 ? "1 minute" : minutes === 60 ? "1 hour" : `${minutes} minutes`}
                  </option>
                ))}
              </select>
            </label>
          </div>
        </section>

        <section className="section">
          <div>
            <h2 className="sectionTitle">How this vault is protected</h2>
            <p className="sectionDescription">What the server stores is ciphertext. These are the parameters.</p>
          </div>
          <div className="sectionContent">
            <dl className="factList">
              <dt>Key derivation</dt>
              <dd className="mono">
                {session.kdf.algorithm}, {session.kdf.iterations.toLocaleString()} iterations, 128-bit salt
              </dd>
              <dt>Encryption</dt>
              <dd>AES-256-GCM, each item separately, padded to 4 KB so lengths stay hidden</dd>
              <dt>Item index</dt>
              <dd>HMAC-SHA256 of website and username; the server cannot see either</dd>
              <dt>Integrity</dt>
              <dd>HMAC-SHA256 over the whole vault; swaps, deletions and edits are detected</dd>
              <dt>Items</dt>
              <dd className="mono">{session.entryCount}</dd>
              <dt>Vault version</dt>
              <dd className="mono">{session.version}</dd>
              <dt>Rollback check</dt>
              <dd>
                {trustedVersion === null
                  ? "No record on this device yet"
                  : `This device has seen version ${trustedVersion} and will refuse anything older`}
              </dd>
            </dl>
          </div>
        </section>
      </div>
    </div>
  );
}

/**
 * Changing the master password re-encrypts every item in the browser under
 * new keys (new salt), then replaces the vault and credentials on the server
 * in one step. Other devices are signed out.
 */
function ChangeMasterPasswordSection({ session, onChanged, onSessionExpired }) {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [progress, setProgress] = useState(null);
  const [result, setResult] = useState(null);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setResult(null);
    if (newPassword.length < 12) {
      setResult({ severity: "warning", text: "Use at least 12 characters for the new master password." });
      return;
    }
    if (newPassword !== confirmation) {
      setResult({ severity: "warning", text: "The new passwords do not match." });
      return;
    }
    if (newPassword === currentPassword) {
      setResult({ severity: "warning", text: "The new password is the same as the current one." });
      return;
    }
    setProgress("Starting");
    try {
      await session.changeMasterPassword(currentPassword, newPassword, setProgress);
      setCurrentPassword("");
      setNewPassword("");
      setConfirmation("");
      setResult({
        severity: "success",
        text: "Master password changed. Every item was re-encrypted, and other devices have been signed out.",
      });
      onChanged();
    } catch (error) {
      if (error?.status === 401 && error.message !== "Current master password is incorrect") {
        onSessionExpired();
        return;
      }
      setResult(describeError(error));
    } finally {
      setProgress(null);
    }
  };

  return (
    <section className="section">
      <div>
        <h2 className="sectionTitle">Master password</h2>
        <p className="sectionDescription">
          Changing it generates a new salt and new keys, and re-encrypts all {session.entryCount} item
          {session.entryCount === 1 ? "" : "s"} in this browser.
        </p>
      </div>
      <form className="sectionContent" onSubmit={handleSubmit}>
        {result && <Message severity={result.severity} title={result.title}>{result.text}</Message>}
        <input type="text" className="visuallyHidden" autoComplete="username" value={session.email} readOnly tabIndex={-1} aria-hidden="true" />
        <label className="field">
          <span className="fieldLabel">Current master password</span>
          <input
            className="input mono"
            type="password"
            autoComplete="current-password"
            value={currentPassword}
            onChange={(event) => setCurrentPassword(event.target.value)}
            required
          />
        </label>
        <label className="field">
          <span className="fieldLabel">New master password</span>
          <input
            className="input mono"
            type="password"
            autoComplete="new-password"
            value={newPassword}
            onChange={(event) => setNewPassword(event.target.value)}
            required
          />
        </label>
        <label className="field">
          <span className="fieldLabel">Confirm new master password</span>
          <input
            className="input mono"
            type="password"
            autoComplete="new-password"
            value={confirmation}
            onChange={(event) => setConfirmation(event.target.value)}
            required
          />
        </label>
        <div>
          {progress ? (
            <ProgressLine label={`${progress}…`} />
          ) : (
            <button
              type="submit"
              className="button buttonPrimary"
              disabled={!currentPassword || !newPassword || !confirmation}
            >
              Change master password
            </button>
          )}
        </div>
      </form>
    </section>
  );
}

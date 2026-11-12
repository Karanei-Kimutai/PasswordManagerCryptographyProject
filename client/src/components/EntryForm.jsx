/**
 * @file EntryForm.jsx
 *
 * Create or edit an item. Character limits mirror FIELD_LIMITS in the crypto
 * package, so problems show up while typing rather than on save. The crypto
 * layer still enforces the final 4 KB byte limit.
 */

import { ArrowLeft, Eye, EyeOff, Wand2 } from "lucide-react";
import { useState } from "react";

import { FIELD_LIMITS, generatePassword, normalizeSite } from "@tessera/crypto";

import { usePreference } from "../hooks/usePreference.js";
import { Message } from "./common.jsx";
import { DEFAULT_GENERATOR_OPTIONS } from "./GeneratorView.jsx";

/**
 * @param {{
 *   initialEntry: import("@tessera/crypto").Entry | null,
 *   onSave: (fields: object) => Promise<void>,
 *   onCancel: () => void,
 *   error: { severity: string, title?: string, text: string } | null,
 * }} props
 */
export function EntryForm({ initialEntry, onSave, onCancel, error }) {
  const [fields, setFields] = useState({
    site: initialEntry?.site ?? "",
    username: initialEntry?.username ?? "",
    password: initialEntry?.password ?? "",
    notes: initialEntry?.notes ?? "",
  });
  const [isPasswordVisible, setIsPasswordVisible] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [generatorOptions] = usePreference("generatorOptions", DEFAULT_GENERATOR_OPTIONS);
  const isEditing = initialEntry !== null;

  const updateField = (name) => (event) => setFields((current) => ({ ...current, [name]: event.target.value }));

  /** Fills the password with a new one using the Generator view's settings. */
  const fillGeneratedPassword = () => {
    setFields((current) => ({ ...current, password: generatePassword(generatorOptions) }));
    setIsPasswordVisible(true); // show what was generated
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    setIsSaving(true);
    // A pasted URL ("https://www.example.com/login") is stored as its hostname
    // ("example.com"), which reads better in the list. Free-text labels are kept.
    const site = /^[a-z][a-z0-9+.-]*:\/\//i.test(fields.site.trim()) ? normalizeSite(fields.site) : fields.site;
    try {
      await onSave({ ...fields, site });
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <section className="detailPanel" aria-label={isEditing ? "Edit item" : "New item"}>
      <header className="detailHeader">
        <button type="button" className="iconButton backButton" onClick={onCancel} aria-label="Cancel">
          <ArrowLeft aria-hidden="true" />
        </button>
        <div className="detailHeaderText">
          <h2 className="detailTitle">{isEditing ? `Edit ${initialEntry.site}` : "New login"}</h2>
          <p className="detailSubtitle">Encrypted on this device when you save.</p>
        </div>
      </header>

      <div className="detailBody">
        <form
          className="entryForm"
          onSubmit={handleSubmit}
          onKeyDown={(event) => event.key === "Escape" && onCancel()}
        >
          {error && (
            <Message severity={error.severity} title={error.title}>
              {error.text}
            </Message>
          )}

          <label className="field">
            <span className="fieldLabel">Website</span>
            <input
              className="input"
              value={fields.site}
              onChange={updateField("site")}
              placeholder="github.com"
              maxLength={FIELD_LIMITS.site}
              autoComplete="off"
              spellCheck={false}
              required
              autoFocus
            />
            <span className="fieldHint">A domain such as github.com, or any label you like.</span>
          </label>

          <label className="field">
            <span className="fieldLabel">Username</span>
            <input
              className="input"
              value={fields.username}
              onChange={updateField("username")}
              maxLength={FIELD_LIMITS.username}
              autoComplete="off"
              spellCheck={false}
            />
          </label>

          <div className="field">
            <label className="fieldLabel" htmlFor="entryPassword">
              Password
            </label>
            <div className="inputWithActions">
              <input
                id="entryPassword"
                className="input mono"
                type={isPasswordVisible ? "text" : "password"}
                value={fields.password}
                onChange={updateField("password")}
                maxLength={FIELD_LIMITS.password}
                autoComplete="new-password"
                spellCheck={false}
                required
              />
              <span className="inputActions">
                <button
                  type="button"
                  className="iconButton"
                  onClick={() => setIsPasswordVisible((visible) => !visible)}
                  aria-label={isPasswordVisible ? "Hide password" : "Show password"}
                  title={isPasswordVisible ? "Hide password" : "Show password"}
                >
                  {isPasswordVisible ? <EyeOff aria-hidden="true" /> : <Eye aria-hidden="true" />}
                </button>
                <button
                  type="button"
                  className="iconButton"
                  onClick={fillGeneratedPassword}
                  aria-label="Generate a password"
                  title={`Generate (${generatorOptions.length} characters; change in Generator)`}
                >
                  <Wand2 aria-hidden="true" />
                </button>
              </span>
            </div>
          </div>

          <label className="field">
            <span className="fieldLabel">Notes</span>
            <textarea
              className="textarea"
              value={fields.notes}
              onChange={updateField("notes")}
              maxLength={FIELD_LIMITS.notes}
              rows={4}
            />
            <span className="fieldHintRow fieldHint">
              <span>Security questions, recovery codes, anything else.</span>
              <span className="mono">
                {fields.notes.length}/{FIELD_LIMITS.notes}
              </span>
            </span>
          </label>

          <div className="formActions">
            <button type="submit" className="button buttonPrimary" disabled={isSaving}>
              {isSaving ? "Encrypting…" : isEditing ? "Save changes" : "Save item"}
            </button>
            <button type="button" className="button buttonQuiet" onClick={onCancel} disabled={isSaving}>
              Cancel
            </button>
          </div>
        </form>
      </div>
    </section>
  );
}

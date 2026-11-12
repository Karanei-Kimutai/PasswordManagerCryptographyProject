/**
 * @file common.jsx
 *
 * Small, reusable pieces: the brand mark, status messages, the copy button,
 * the masked secret display and site monograms.
 */

import { AlertTriangle, Check, CheckCircle2, Copy, Eye, EyeOff, Info, ShieldAlert } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { CLIPBOARD_CLEAR_SECONDS, copyWithAutoClear } from "../services/clipboard.js";
import { monogramFor } from "../utils/formatting.js";

/**
 * Tessera's mark: four tiles, one in the accent colour. A *tessera* was a
 * small tile in a Roman mosaic. Roman soldiers also passed the night's
 * watchword on a tessera, which makes it an apt name for a password manager.
 */
export function BrandMark() {
  return (
    <svg className="brandMark" viewBox="0 0 18 18" aria-hidden="true">
      <rect x="1" y="1" width="7" height="7" rx="1" fill="currentColor" />
      <rect x="10" y="1" width="7" height="7" rx="1" fill="currentColor" />
      <rect x="1" y="10" width="7" height="7" rx="1" fill="currentColor" />
      <rect className="brandMarkAccent" x="10" y="10" width="7" height="7" rx="1" />
    </svg>
  );
}

export function Brand() {
  return (
    <span className="brand">
      <BrandMark />
      Tessera
    </span>
  );
}

const messageIcons = {
  danger: ShieldAlert,
  warning: AlertTriangle,
  info: Info,
  success: CheckCircle2,
};

const messageClasses = {
  danger: "messageDanger",
  warning: "messageWarning",
  info: "messageInfo",
  success: "messageSuccess",
};

/**
 * An inline status message. The severity decides both the icon and the
 * colour, and each colour has exactly one meaning across the app.
 *
 * @param {{ severity: "danger" | "warning" | "info" | "success", title?: string, children: React.ReactNode }} props
 */
export function Message({ severity, title, children }) {
  const Icon = messageIcons[severity];
  return (
    <div className={`message ${messageClasses[severity]}`} role={severity === "danger" ? "alert" : "status"}>
      <Icon aria-hidden="true" />
      <div>
        {title && <div className="messageTitle">{title}</div>}
        {children}
      </div>
    </div>
  );
}

/**
 * Copies a value and confirms it in context: the icon becomes a check and a
 * short note explains that the clipboard will be cleared.
 *
 * @param {{ value: string, label: string, isSecret?: boolean }} props
 */
export function CopyButton({ value, label, isSecret = false }) {
  const [isConfirmed, setIsConfirmed] = useState(false);
  const resetTimer = useRef(null);

  useEffect(() => () => clearTimeout(resetTimer.current), []);

  const handleCopy = async () => {
    try {
      await copyWithAutoClear(value);
      setIsConfirmed(true);
      clearTimeout(resetTimer.current);
      resetTimer.current = setTimeout(() => setIsConfirmed(false), 2500);
    } catch {
      // Clipboard access denied; leave the button as it was.
    }
  };

  return (
    <>
      {isConfirmed && (
        <span className="copyConfirmation" role="status">
          {isSecret ? `Copied · clears in ${CLIPBOARD_CLEAR_SECONDS}s` : "Copied"}
        </span>
      )}
      <button
        type="button"
        className={`iconButton ${isConfirmed ? "iconButtonConfirmed" : ""}`}
        onClick={handleCopy}
        aria-label={label}
        title={label}
      >
        {isConfirmed ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
      </button>
    </>
  );
}

/** How long a revealed secret stays visible before it is masked again. */
const REVEAL_SECONDS = 20;

/**
 * Shows a secret masked by default. Revealing is deliberate (a click) and
 * temporary (it re-masks itself after REVEAL_SECONDS).
 *
 * The mask is always the same number of dots, so it does not reveal the
 * password's length to someone looking over the user's shoulder.
 *
 * @param {{ value: string }} props
 */
export function SecretValue({ value }) {
  const [secondsLeft, setSecondsLeft] = useState(0);
  const isRevealed = secondsLeft > 0;

  useEffect(() => {
    if (!isRevealed) {
      return undefined;
    }
    const timer = setTimeout(() => setSecondsLeft((current) => current - 1), 1000);
    return () => clearTimeout(timer);
  }, [isRevealed, secondsLeft]);

  // Re-mask whenever the secret itself changes (e.g. another entry selected).
  useEffect(() => setSecondsLeft(0), [value]);

  return (
    <>
      <span className={`detailRowValue secretValue ${isRevealed ? "" : "secretMasked"}`}>
        {isRevealed ? value : "••••••••••••"}
        {isRevealed && <span className="revealCountdown">Hides in {secondsLeft}s</span>}
      </span>
      <span className="detailRowActions">
        <button
          type="button"
          className="iconButton"
          onClick={() => setSecondsLeft(isRevealed ? 0 : REVEAL_SECONDS)}
          aria-label={isRevealed ? "Hide password" : "Reveal password"}
          title={isRevealed ? "Hide password" : "Reveal password"}
        >
          {isRevealed ? <EyeOff aria-hidden="true" /> : <Eye aria-hidden="true" />}
        </button>
        <CopyButton value={value} label="Copy password" isSecret />
      </span>
    </>
  );
}

/**
 * A neutral letter tile for a site.
 *
 * @param {{ site: string, isLarge?: boolean }} props
 */
export function Monogram({ site, isLarge = false }) {
  return (
    <span className={`monogram ${isLarge ? "monogramLarge" : ""}`} aria-hidden="true">
      {monogramFor(site)}
    </span>
  );
}

/** @param {{ label: string }} props */
export function ProgressLine({ label }) {
  return (
    <span className="progressLine" role="status">
      <span className="spinner" aria-hidden="true" />
      {label}
    </span>
  );
}

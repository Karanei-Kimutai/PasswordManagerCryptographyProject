/**
 * @file EntryDetail.jsx
 *
 * Shows one item beside the list, with no navigation away. Fields are rows
 * separated by hairlines rather than separate cards. The password is masked
 * until deliberately revealed. Deleting asks for confirmation inline.
 */

import { ArrowLeft, Clock, ExternalLink, Pencil, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";

import { formatFullDate, websiteUrlFor } from "../utils/formatting.js";
import { CopyButton, Message, Monogram, SecretValue } from "./common.jsx";

/**
 * @param {{
 *   entry: import("@tessera/crypto").Entry,
 *   onEdit: () => void,
 *   onDelete: () => Promise<void>,
 *   onBack: () => void,
 *   error: { severity: string, title?: string, text: string } | null,
 * }} props
 */
export function EntryDetail({ entry, onEdit, onDelete, onBack, error }) {
  const [isConfirmingDelete, setIsConfirmingDelete] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const websiteUrl = websiteUrlFor(entry.site);

  // Reset the confirmation whenever a different entry is shown.
  useEffect(() => setIsConfirmingDelete(false), [entry.id]);

  const confirmDelete = async () => {
    setIsDeleting(true);
    try {
      await onDelete();
    } finally {
      setIsDeleting(false);
    }
  };

  return (
    <section className="detailPanel" aria-label={`Details for ${entry.site}`}>
      <header className="detailHeader">
        <button type="button" className="iconButton backButton" onClick={onBack} aria-label="Back to list">
          <ArrowLeft aria-hidden="true" />
        </button>
        <Monogram site={entry.site} isLarge />
        <div className="detailHeaderText">
          <h2 className="detailTitle">{entry.site}</h2>
          <p className="detailSubtitle">{entry.username || "No username"}</p>
        </div>
        <div className="detailHeaderActions">
          <button type="button" className="button" onClick={onEdit}>
            <Pencil aria-hidden="true" />
            Edit
          </button>
          <button
            type="button"
            className="button buttonQuiet"
            onClick={() => setIsConfirmingDelete(true)}
            aria-label="Delete item"
            title="Delete item"
          >
            <Trash2 aria-hidden="true" />
          </button>
        </div>
      </header>

      <div className="detailBody">
        {error && (
          <Message severity={error.severity} title={error.title}>
            {error.text}
          </Message>
        )}

        <div className="detailRow">
          <span className="detailRowLabel">Username</span>
          <span className={`detailRowValue ${entry.username ? "" : "detailRowValueEmpty"}`}>
            {entry.username || "None"}
          </span>
          <span className="detailRowActions">
            {entry.username && <CopyButton value={entry.username} label="Copy username" />}
          </span>
        </div>

        <div className="detailRow">
          <span className="detailRowLabel">Password</span>
          <SecretValue value={entry.password} />
        </div>

        <div className="detailRow">
          <span className="detailRowLabel">Website</span>
          <span className="detailRowValue">
            {websiteUrl ? (
              <a href={websiteUrl} target="_blank" rel="noopener noreferrer">
                {entry.site}
              </a>
            ) : (
              entry.site
            )}
          </span>
          <span className="detailRowActions">
            {websiteUrl && (
              <a
                className="iconButton"
                href={websiteUrl}
                target="_blank"
                rel="noopener noreferrer"
                aria-label="Open website in a new tab"
                title="Open website"
              >
                <ExternalLink aria-hidden="true" />
              </a>
            )}
          </span>
        </div>

        <div className="detailRow">
          <span className="detailRowLabel">Notes</span>
          <span className={`detailRowValue notesValue ${entry.notes ? "" : "detailRowValueEmpty"}`}>
            {entry.notes || "None"}
          </span>
          <span className="detailRowActions">
            {entry.notes && <CopyButton value={entry.notes} label="Copy notes" />}
          </span>
        </div>

        <div className="detailMeta">
          <span>
            <Clock aria-hidden="true" />
            Updated {formatFullDate(entry.updatedAt)}
          </span>
          <span>Created {formatFullDate(entry.createdAt)}</span>
        </div>

        {isConfirmingDelete && (
          <div className="confirmBar" role="alertdialog" aria-label="Confirm deletion">
            <p>
              Delete <strong>{entry.site}</strong>
              {entry.username ? ` (${entry.username})` : ""}? This cannot be undone.
            </p>
            <button type="button" className="button" onClick={() => setIsConfirmingDelete(false)} disabled={isDeleting}>
              Cancel
            </button>
            <button type="button" className="button buttonDanger" onClick={confirmDelete} disabled={isDeleting}>
              {isDeleting ? "Deleting…" : "Delete"}
            </button>
          </div>
        )}
      </div>
    </section>
  );
}

/**
 * @file VaultScreen.jsx
 *
 * The unlocked vault: sidebar | searchable list | detail panel.
 *
 * Decrypted entries live in React state only while the vault is unlocked.
 * Locking unmounts this component, which drops them along with the session
 * (and the keys inside it).
 */

import { KeyRound, Lock, LogOut, Settings, ShieldCheck, Wand2 } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { ApiError } from "../services/apiClient.js";
import { describeError } from "../utils/formatting.js";
import { Brand, Message, ProgressLine } from "./common.jsx";
import { EntryDetail } from "./EntryDetail.jsx";
import { EntryForm } from "./EntryForm.jsx";
import { EntryList } from "./EntryList.jsx";
import { GeneratorView } from "./GeneratorView.jsx";
import { SettingsView } from "./SettingsView.jsx";

/**
 * @param {{
 *   session: import("../services/vaultSession.js").VaultSession,
 *   autoLockMinutes: number,
 *   onAutoLockMinutesChange: (minutes: number) => void,
 *   onLock: () => void,
 *   onSignOut: () => void,
 *   onSessionExpired: () => void,
 *   sortOrder: string,
 *   onSortOrderChange: (order: string) => void,
 * }} props
 */
export function VaultScreen({
  session,
  autoLockMinutes,
  onAutoLockMinutesChange,
  onLock,
  onSignOut,
  onSessionExpired,
  sortOrder,
  onSortOrderChange,
}) {
  const [view, setView] = useState("items"); // "items" | "generator" | "settings"
  const [entries, setEntries] = useState(null); // null while decrypting
  const [loadError, setLoadError] = useState(null);
  const [selectedId, setSelectedId] = useState(null);
  const [panelMode, setPanelMode] = useState("view"); // "view" | "create" | "edit"
  const [panelError, setPanelError] = useState(null);
  const [query, setQuery] = useState("");
  const [vaultVersion, setVaultVersion] = useState(session.version);
  const searchInputRef = useRef(null);

  /** Re-reads every entry from the (possibly reloaded) vault. */
  const refreshEntries = useCallback(async () => {
    try {
      setEntries(await session.listEntries());
      setVaultVersion(session.version);
      setLoadError(null);
    } catch (error) {
      setLoadError(describeError(error));
    }
  }, [session]);

  useEffect(() => {
    refreshEntries();
  }, [refreshEntries]);

  // "/" focuses search from anywhere outside a text field.
  useEffect(() => {
    const handleKeyDown = (event) => {
      const isTyping = ["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement?.tagName);
      if (event.key === "/" && !isTyping && view === "items") {
        event.preventDefault();
        searchInputRef.current?.focus();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [view]);

  const visibleEntries = useMemo(() => {
    if (!entries) {
      return [];
    }
    const needle = query.trim().toLowerCase();
    const matching = needle
      ? entries.filter((entry) =>
          [entry.site, entry.username, entry.notes].some((text) => text.toLowerCase().includes(needle)),
        )
      : entries;
    const sorted = [...matching];
    if (sortOrder === "updated") {
      sorted.sort((left, right) => right.updatedAt.localeCompare(left.updatedAt));
    } else {
      sorted.sort(
        (left, right) =>
          left.site.localeCompare(right.site, undefined, { sensitivity: "base" }) ||
          left.username.localeCompare(right.username, undefined, { sensitivity: "base" }),
      );
    }
    return sorted;
  }, [entries, query, sortOrder]);

  const selectedEntry = entries?.find((entry) => entry.id === selectedId) ?? null;

  /** Handles errors from saves and deletes in one place. */
  const handleWriteError = async (error) => {
    if (error instanceof ApiError && error.status === 401) {
      onSessionExpired();
      return;
    }
    // The session reloads the vault after a failed save; show what is stored.
    await refreshEntries();
    setPanelError(describeError(error));
  };

  const handleSave = async (fields) => {
    setPanelError(null);
    try {
      const saved = await session.saveEntry(fields, panelMode === "edit" ? selectedId : null);
      await refreshEntries();
      setSelectedId(saved.id);
      setPanelMode("view");
    } catch (error) {
      await handleWriteError(error);
    }
  };

  const handleDelete = async () => {
    setPanelError(null);
    try {
      await session.deleteEntry(selectedId);
      await refreshEntries();
      setSelectedId(null);
    } catch (error) {
      await handleWriteError(error);
    }
  };

  const showView = (newView) => {
    setView(newView);
    setPanelError(null);
  };

  const startCreate = () => {
    setView("items");
    setPanelMode("create");
    setPanelError(null);
  };

  const selectEntry = (id) => {
    setSelectedId(id);
    setPanelMode("view");
    setPanelError(null);
  };

  const cancelForm = () => {
    setPanelMode("view");
    setPanelError(null);
  };

  const isShowingDetail = view === "items" && (panelMode !== "view" || selectedEntry !== null);
  const layoutClasses = [
    "vaultLayout",
    view === "items" ? "" : "vaultLayoutWide",
    isShowingDetail ? "vaultLayoutShowingDetail" : "",
  ].join(" ");

  return (
    <div className={layoutClasses}>
      <aside className="sidebar">
        <div className="sidebarHeader">
          <Brand />
        </div>
        <nav className="sidebarNav" aria-label="Sections">
          <button
            type="button"
            className={`navItem ${view === "items" ? "navItemActive" : ""}`}
            onClick={() => showView("items")}
          >
            <KeyRound aria-hidden="true" />
            All items
            <span className="navItemCount">{entries?.length ?? "–"}</span>
          </button>
          <button
            type="button"
            className={`navItem ${view === "generator" ? "navItemActive" : ""}`}
            onClick={() => showView("generator")}
          >
            <Wand2 aria-hidden="true" />
            Generator
          </button>
          <button
            type="button"
            className={`navItem ${view === "settings" ? "navItemActive" : ""}`}
            onClick={() => showView("settings")}
          >
            <Settings aria-hidden="true" />
            Settings
          </button>
        </nav>
        <div className="sidebarFooter">
          <div className="sidebarAccount" title={session.email}>
            {session.email}
          </div>
          <div className="syncStatus">
            <ShieldCheck aria-hidden="true" />
            Encrypted · version {vaultVersion} · locks after {autoLockMinutes} min
          </div>
          <div className="sidebarActions">
            <button type="button" className="button" onClick={onLock} title="Lock now (keeps you signed in)">
              <Lock aria-hidden="true" />
              Lock
            </button>
            <button type="button" className="button buttonQuiet" onClick={onSignOut} title="Sign out" aria-label="Sign out">
              <LogOut aria-hidden="true" />
            </button>
          </div>
        </div>
      </aside>

      {view === "generator" && <GeneratorView />}

      {view === "settings" && (
        <SettingsView
          session={session}
          autoLockMinutes={autoLockMinutes}
          onAutoLockMinutesChange={onAutoLockMinutesChange}
          onVaultChanged={refreshEntries}
          onSessionExpired={onSessionExpired}
        />
      )}

      {view === "items" && (
        <>
          {entries === null && !loadError ? (
            <section className="listPanel">
              <div className="emptyState">
                <ProgressLine label="Decrypting items…" />
              </div>
            </section>
          ) : loadError ? (
            <section className="listPanel">
              <div className="emptyState">
                <Message severity={loadError.severity} title={loadError.title}>
                  {loadError.text}
                </Message>
              </div>
            </section>
          ) : (
            <EntryList
              ref={searchInputRef}
              entries={visibleEntries}
              totalCount={entries.length}
              query={query}
              onQueryChange={setQuery}
              sortOrder={sortOrder}
              onSortOrderChange={onSortOrderChange}
              selectedId={selectedId}
              onSelect={selectEntry}
              onCreate={startCreate}
            />
          )}

          {panelMode === "create" && (
            <EntryForm key="new" initialEntry={null} onSave={handleSave} onCancel={cancelForm} error={panelError} />
          )}
          {panelMode === "edit" && selectedEntry && (
            <EntryForm
              key={`edit-${selectedEntry.id}`}
              initialEntry={selectedEntry}
              onSave={handleSave}
              onCancel={cancelForm}
              error={panelError}
            />
          )}
          {panelMode === "view" && selectedEntry && (
            <EntryDetail
              entry={selectedEntry}
              onEdit={() => {
                setPanelMode("edit");
                setPanelError(null);
              }}
              onDelete={handleDelete}
              onBack={() => setSelectedId(null)}
              error={panelError}
            />
          )}
          {panelMode === "view" && !selectedEntry && (
            <section className="detailPanel">
              {panelError ? (
                <div className="emptyState">
                  <Message severity={panelError.severity} title={panelError.title}>
                    {panelError.text}
                  </Message>
                </div>
              ) : (
                <div className="emptyState">
                  <h2 className="emptyStateTitle">No item selected</h2>
                  <p className="emptyStateBody">Choose an item from the list to see its details.</p>
                  <ul className="emptyStateList">
                    <li>
                      Press <span className="kbd">/</span> to search
                    </li>
                    <li>Passwords stay masked until you choose to reveal them</li>
                    <li>Copied passwords are cleared from the clipboard after 30 seconds</li>
                  </ul>
                </div>
              )}
            </section>
          )}
        </>
      )}
    </div>
  );
}

/**
 * @file EntryList.jsx
 *
 * The searchable, sortable list of vault items. Search filters as the user
 * types, across website, username and notes. All of this happens on the
 * decrypted entries in memory; nothing is ever sent to the server for
 * searching.
 */

import { Plus, Search } from "lucide-react";
import { forwardRef } from "react";

import { formatRelativeTime } from "../utils/formatting.js";
import { Monogram } from "./common.jsx";

/**
 * @param {{
 *   entries: import("@tessera/crypto").Entry[],
 *   totalCount: number,
 *   query: string,
 *   onQueryChange: (query: string) => void,
 *   sortOrder: "name" | "updated",
 *   onSortOrderChange: (order: string) => void,
 *   selectedId: string | null,
 *   onSelect: (id: string) => void,
 *   onCreate: () => void,
 * }} props
 */
export const EntryList = forwardRef(function EntryList(
  { entries, totalCount, query, onQueryChange, sortOrder, onSortOrderChange, selectedId, onSelect, onCreate },
  searchInputRef,
) {
  return (
    <section className="listPanel" aria-label="Vault items">
      <div className="listToolbar">
        <div className="searchBox">
          <Search aria-hidden="true" />
          <input
            ref={searchInputRef}
            className="input"
            type="search"
            placeholder="Search vault"
            aria-label="Search vault"
            value={query}
            onChange={(event) => onQueryChange(event.target.value)}
            autoComplete="off"
            spellCheck={false}
          />
          {!query && <span className="searchShortcut" aria-hidden="true">/</span>}
        </div>
        <div className="listMeta">
          <span>
            {query ? `${entries.length} of ${totalCount}` : `${totalCount} item${totalCount === 1 ? "" : "s"}`}
          </span>
          <select
            className="select sortSelect"
            value={sortOrder}
            onChange={(event) => onSortOrderChange(event.target.value)}
            aria-label="Sort items"
          >
            <option value="name">Name</option>
            <option value="updated">Recently updated</option>
          </select>
          <button type="button" className="button" onClick={onCreate}>
            <Plus aria-hidden="true" />
            New item
          </button>
        </div>
      </div>

      {totalCount === 0 ? (
        <div className="emptyState">
          <h2 className="emptyStateTitle">Your vault is empty</h2>
          <p className="emptyStateBody">
            Add your first login. It is encrypted in this browser with AES-256-GCM before anything is sent to the server.
          </p>
          <button type="button" className="button buttonPrimary" onClick={onCreate}>
            <Plus aria-hidden="true" />
            Add a login
          </button>
        </div>
      ) : entries.length === 0 ? (
        <div className="emptyState">
          <h2 className="emptyStateTitle">No matches for “{query}”</h2>
          <p className="emptyStateBody">Search looks at the website, username and notes of every item.</p>
          <button type="button" className="button" onClick={() => onQueryChange("")}>
            Clear search
          </button>
        </div>
      ) : (
        <ul className="entryList">
          {entries.map((entry) => (
            <li key={entry.id}>
              <button
                type="button"
                className={`entryRow ${entry.id === selectedId ? "entryRowSelected" : ""}`}
                onClick={() => onSelect(entry.id)}
                aria-current={entry.id === selectedId ? "true" : undefined}
              >
                <Monogram site={entry.site} />
                <span className="entryRowText">
                  <span className="entryRowTitle">{entry.site}</span>
                  <span className="entryRowSubtitle">{entry.username || "No username"}</span>
                </span>
                <span className="entryRowDate" title={`Updated ${entry.updatedAt}`}>
                  {formatRelativeTime(entry.updatedAt)}
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
});

/**
 * @file formatting.js
 *
 * Small display helpers: user-facing error messages, relative dates and
 * website links.
 */

import {
  DuplicateEntryError,
  EntryValidationError,
  RecordTooLargeError,
  RollbackError,
  VaultFormatError,
  VaultIntegrityError,
  WrongPasswordError,
  normalizeSite,
} from "@tessera/crypto";

import { ApiError } from "../services/apiClient.js";
import { SyncConflictError } from "../services/vaultSession.js";

/**
 * Turns any error into something to show the user, with a severity that
 * decides its colour. Security failures (integrity, rollback) get a clear
 * explanation, because they mean the stored data may have been tampered with.
 *
 * @param {unknown} error
 * @returns {{ severity: "danger" | "warning", title?: string, text: string }}
 */
export function describeError(error) {
  if (error instanceof RollbackError) {
    return {
      severity: "danger",
      title: "Possible rollback attack",
      text:
        `The server returned vault version ${error.receivedVersion}, but this device has already seen ` +
        `version ${error.seenVersion}. Someone may be replaying an old copy of your vault to undo recent ` +
        "changes. Tessera refused to open it. Nothing has been changed.",
    };
  }
  if (error instanceof VaultIntegrityError) {
    return {
      severity: "danger",
      title: "Vault integrity check failed",
      text: `${error.message}. The stored data was modified by someone without your keys, so Tessera refused to use it.`,
    };
  }
  if (error instanceof VaultFormatError) {
    return { severity: "danger", title: "Unreadable vault", text: error.message };
  }
  if (error instanceof WrongPasswordError) {
    return { severity: "warning", text: error.message || "Incorrect email or master password." };
  }
  if (
    error instanceof DuplicateEntryError ||
    error instanceof EntryValidationError ||
    error instanceof RecordTooLargeError ||
    error instanceof SyncConflictError
  ) {
    return { severity: "warning", text: error.message };
  }
  if (error instanceof ApiError) {
    return { severity: "warning", text: error.message };
  }
  console.error(error);
  return { severity: "danger", text: "Something went wrong. Please try again." };
}

const relativeTimeFormatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
const dateFormatter = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

/**
 * "just now", "5 min ago", "yesterday", or a short date for older items.
 *
 * @param {string} isoTimestamp
 * @returns {string}
 */
export function formatRelativeTime(isoTimestamp) {
  const seconds = Math.round((new Date(isoTimestamp).getTime() - Date.now()) / 1000);
  const absolute = Math.abs(seconds);
  if (absolute < 45) {
    return "just now";
  }
  if (absolute < 3600) {
    return relativeTimeFormatter.format(Math.round(seconds / 60), "minute");
  }
  if (absolute < 86400) {
    return relativeTimeFormatter.format(Math.round(seconds / 3600), "hour");
  }
  if (absolute < 7 * 86400) {
    return relativeTimeFormatter.format(Math.round(seconds / 86400), "day");
  }
  return new Date(isoTimestamp).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
}

/** @param {string} isoTimestamp */
export function formatFullDate(isoTimestamp) {
  return dateFormatter.format(new Date(isoTimestamp));
}

/**
 * Returns an https:// link for a site that looks like a hostname, or null
 * for free-text labels such as "Home router".
 *
 * @param {string} site
 * @returns {string | null}
 */
export function websiteUrlFor(site) {
  const host = normalizeSite(site);
  if (/^[a-z0-9-]+(\.[a-z0-9-]+)+(:\d+)?$/.test(host)) {
    return `https://${host}`;
  }
  return null;
}

/**
 * The letter shown in an entry's monogram tile. We deliberately do not fetch
 * real favicons: that would tell a third-party icon service which sites are
 * in the vault.
 *
 * @param {string} site
 * @returns {string}
 */
export function monogramFor(site) {
  const match = normalizeSite(site).match(/[a-z0-9]/i);
  return match ? match[0].toUpperCase() : "?";
}

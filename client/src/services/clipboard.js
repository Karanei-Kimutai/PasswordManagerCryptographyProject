/**
 * @file clipboard.js
 *
 * Copy-to-clipboard that clears itself.
 *
 * Copied passwords sit on the system clipboard, where any app (and any later
 * paste) can read them. We clear the clipboard CLIPBOARD_CLEAR_SECONDS after
 * a copy, but only if it still holds what we put there, so we don't wipe
 * something the user copied since.
 */

export const CLIPBOARD_CLEAR_SECONDS = 30;

let pendingClear = null;
let lastCopiedValue = null;

/**
 * Copies text and schedules the clipboard to be cleared.
 *
 * @param {string} text
 * @returns {Promise<void>}
 */
export async function copyWithAutoClear(text) {
  await navigator.clipboard.writeText(text);
  lastCopiedValue = text;
  clearTimeout(pendingClear);
  pendingClear = setTimeout(clearClipboardIfOurs, CLIPBOARD_CLEAR_SECONDS * 1000);
}

/**
 * Clears the clipboard if it still contains the value we copied.
 *
 * Reading the clipboard can be refused (it needs permission in some
 * browsers). If we cannot check, we clear anyway: overwriting something the
 * user copied is a smaller harm than leaving a password on the clipboard.
 */
export async function clearClipboardIfOurs() {
  clearTimeout(pendingClear);
  pendingClear = null;
  if (lastCopiedValue === null) {
    return;
  }
  try {
    let shouldClear = true;
    try {
      shouldClear = (await navigator.clipboard.readText()) === lastCopiedValue;
    } catch {
      shouldClear = true;
    }
    if (shouldClear) {
      await navigator.clipboard.writeText("");
    }
  } catch {
    // The page lost focus or clipboard access; nothing more we can do.
  } finally {
    lastCopiedValue = null;
  }
}

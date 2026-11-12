/**
 * @file usePreference.js
 *
 * A useState that remembers its value in localStorage. Only used for harmless
 * per-device preferences (auto-lock timeout, generator settings, sort
 * order), never for anything secret.
 */

import { useCallback, useState } from "react";

/**
 * @template T
 * @param {string} key
 * @param {T} defaultValue
 * @returns {[T, (value: T) => void]}
 */
export function usePreference(key, defaultValue) {
  const storageKey = `tessera.preference.${key}`;
  const [value, setValue] = useState(() => {
    try {
      const stored = localStorage.getItem(storageKey);
      return stored === null ? defaultValue : JSON.parse(stored);
    } catch {
      return defaultValue;
    }
  });

  const update = useCallback(
    (newValue) => {
      setValue(newValue);
      try {
        localStorage.setItem(storageKey, JSON.stringify(newValue));
      } catch {
        // Storage unavailable: the preference lasts for this page load only.
      }
    },
    [storageKey],
  );

  return [value, update];
}

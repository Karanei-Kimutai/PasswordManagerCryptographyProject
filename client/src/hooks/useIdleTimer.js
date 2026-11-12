/**
 * @file useIdleTimer.js
 *
 * Calls `onIdle` after `timeoutMinutes` with no user activity. Used to lock
 * the vault automatically, so an unattended browser does not stay unlocked.
 */

import { useEffect, useRef } from "react";

const activityEvents = ["pointerdown", "pointermove", "keydown", "wheel", "touchstart"];

/**
 * @param {number} timeoutMinutes - 0 disables the timer.
 * @param {() => void} onIdle
 */
export function useIdleTimer(timeoutMinutes, onIdle) {
  // Keep the latest callback without restarting the timer on every render.
  const onIdleRef = useRef(onIdle);
  onIdleRef.current = onIdle;

  useEffect(() => {
    if (!timeoutMinutes) {
      return undefined;
    }
    const timeoutMs = timeoutMinutes * 60 * 1000;
    let deadline = Date.now() + timeoutMs;
    const markActive = () => {
      deadline = Date.now() + timeoutMs;
    };
    // A periodic check (instead of one long setTimeout) also catches the case
    // where the computer slept: on wake-up, the deadline has already passed.
    const interval = setInterval(() => {
      if (Date.now() >= deadline) {
        onIdleRef.current();
      }
    }, 5000);
    for (const eventName of activityEvents) {
      window.addEventListener(eventName, markActive, { passive: true });
    }
    return () => {
      clearInterval(interval);
      for (const eventName of activityEvents) {
        window.removeEventListener(eventName, markActive);
      }
    };
  }, [timeoutMinutes]);
}

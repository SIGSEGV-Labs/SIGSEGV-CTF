/**
 * state.js
 * -----------------------------------------------------------------------
 * Central challenge-state module for the Corvus Security Institute
 * Security Lab CTF.
 *
 * This is intentionally written as a small, isolated "state service" with
 * a synchronous-looking API (get/set/require) so that, if this project is
 * ever moved to a real backend, every call site here maps 1:1 onto a
 * future API request (e.g. GET /api/progress, POST /api/progress) instead
 * of talking to sessionStorage directly. Nothing outside this file touches
 * sessionStorage.
 *
 * Progress is stored per-tab (sessionStorage), not per-browser, so a
 * player can't get a stale "solved" state days later just because a
 * cookie never expired.
 * -----------------------------------------------------------------------
 */

const CTFState = (() => {
  const NAMESPACE = 'corvus_ctf';

  const KEYS = Object.freeze({
    IP_IDENTIFIED: 'ip_identified',
    IP_BLOCKED: 'ip_blocked',
    HARDENING_COMPLETE: 'hardening_complete',
    FINAL_CODE: 'final_code',
  });

  function storageKey(key) {
    return `${NAMESPACE}_${key}`;
  }

  /** Read a boolean/string flag. Returns `fallback` if unset. */
  function get(key, fallback = null) {
    const raw = sessionStorage.getItem(storageKey(key));
    if (raw === null) return fallback;
    try {
      return JSON.parse(raw);
    } catch {
      return raw;
    }
  }

  /** Persist a flag. */
  function set(key, value) {
    sessionStorage.setItem(storageKey(key), JSON.stringify(value));
  }

  /** Clear all challenge progress (used by the "Reset Lab" control). */
  function resetAll() {
    Object.values(KEYS).forEach((k) => sessionStorage.removeItem(storageKey(k)));
  }

  /**
   * Guard a page: if `condition` is false, bounce the player back to
   * `redirectTo` with a reason flag so that page can show an explanation
   * banner instead of silently redirecting.
   *
   * Returns true if the page is allowed to render, false if a redirect
   * was triggered (caller should stop further script execution).
   */
  function requireStep(condition, redirectTo, reasonParam = 'locked') {
    if (!condition) {
      const url = new URL(redirectTo, window.location.href);
      url.searchParams.set('denied', reasonParam);
      window.location.replace(url.toString());
      return false;
    }
    return true;
  }

  /** SHA-256 hash helper (hex string) — used so answers aren't stored in plaintext. */
  async function sha256(text) {
    const enc = new TextEncoder().encode(text.trim().toLowerCase());
    const digest = await crypto.subtle.digest('SHA-256', enc);
    return Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /** Cryptographically strong random pick from an array (unbiased via rejection sampling). */
  function secureRandomChoice(list) {
    const max = list.length;
    const range = 256 - (256 % max); // avoid modulo bias
    let byte;
    do {
      byte = crypto.getRandomValues(new Uint8Array(1))[0];
    } while (byte >= range);
    return list[byte % max];
  }

  return { KEYS, get, set, resetAll, requireStep, sha256, secureRandomChoice };
})();

/**
 * compliance.js — RFC compliance status tracker.
 *
 * Manages a deterministic map of RFC → compliance status.
 * No network calls. No non-deterministic entropy.
 */

"use strict";

const compliance = (() => {
  const STATUS = Object.freeze({
    PASS: "pass",
    FAIL: "fail",
    SKIP: "skip",
    PENDING: "pending",
  });

  /** @type {Map<string, string>} */
  const _status = new Map();

  /**
   * Record a compliance result for an RFC.
   * @param {string} rfc  e.g. "RFC-0014"
   * @param {string} result  one of STATUS values
   * @param {object} [details]
   */
  function record(rfc, result, details = {}) {
    if (!Object.values(STATUS).includes(result)) {
      throw new Error(`Invalid compliance result: ${result}`);
    }
    _status.set(rfc, { result, details, recordedAt: new Date().toISOString() });
  }

  /**
   * Get the status for a given RFC.
   * @param {string} rfc
   * @returns {{ result: string, details: object, recordedAt: string } | undefined}
   */
  function get(rfc) {
    return _status.get(rfc);
  }

  /**
   * Return all compliance results as a plain object.
   * @returns {object}
   */
  function snapshot() {
    const out = {};
    for (const [rfc, data] of _status.entries()) {
      out[rfc] = data;
    }
    return out;
  }

  /**
   * Return true if all recorded RFCs have status 'pass'.
   * @returns {boolean}
   */
  function allPass() {
    for (const data of _status.values()) {
      if (data.result !== STATUS.PASS) return false;
    }
    return true;
  }

  /**
   * Load a compliance snapshot (e.g., from fixture JSON).
   * @param {object} data  { "RFC-0014": "pass", ... }
   */
  function loadSnapshot(data) {
    for (const [rfc, result] of Object.entries(data)) {
      _status.set(rfc, {
        result: typeof result === "string" ? result : result.result,
        details: typeof result === "object" ? result.details || {} : {},
        recordedAt: new Date().toISOString(),
      });
    }
  }

  return { STATUS, record, get, snapshot, allPass, loadSnapshot };
})();

if (typeof module !== "undefined" && module.exports) {
  module.exports = compliance;
}

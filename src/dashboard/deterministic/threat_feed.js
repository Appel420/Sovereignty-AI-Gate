/**
 * threat_feed.js — Local, offline threat indicator registry.
 *
 * Threat data is loaded from local signed bundles only.
 * No network calls. No Math.random().
 */

"use strict";

const threatFeed = (() => {
  /** @type {Array<{id: string, severity: string, description: string, addedAt: string}>} */
  const _indicators = [];

  /**
   * Add a threat indicator to the local feed.
   * @param {object} indicator
   * @param {string} indicator.id
   * @param {string} indicator.severity  "critical"|"high"|"medium"|"low"
   * @param {string} indicator.description
   */
  function addIndicator({ id, severity, description }) {
    if (!id || !severity || !description) {
      throw new Error("Threat indicator must have id, severity, description");
    }
    const VALID_SEVERITIES = ["critical", "high", "medium", "low"];
    if (!VALID_SEVERITIES.includes(severity)) {
      throw new Error(`Invalid severity: ${severity}`);
    }
    // Prevent duplicates
    if (_indicators.some((i) => i.id === id)) {
      return;
    }
    _indicators.push({
      id,
      severity,
      description,
      addedAt: new Date().toISOString(),
    });
  }

  /**
   * Load a batch of indicators from a signed local bundle.
   * @param {Array<object>} bundle
   */
  function loadBundle(bundle) {
    if (!Array.isArray(bundle)) {
      throw new Error("Threat feed bundle must be an array");
    }
    for (const indicator of bundle) {
      addIndicator(indicator);
    }
  }

  /**
   * Return all indicators with severity >= minSeverity.
   * Order: critical > high > medium > low
   * @param {string} [minSeverity="low"]
   * @returns {Array<object>}
   */
  function getIndicators(minSeverity = "low") {
    const ORDER = { critical: 4, high: 3, medium: 2, low: 1 };
    const minLevel = ORDER[minSeverity] ?? 1;
    return _indicators.filter((i) => (ORDER[i.severity] ?? 0) >= minLevel);
  }

  /** Clear all indicators (for testing). */
  function clear() {
    _indicators.length = 0;
  }

  return { addIndicator, loadBundle, getIndicators, clear };
})();

if (typeof module !== "undefined" && module.exports) {
  module.exports = threatFeed;
}

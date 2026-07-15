/**
 * tpm.js — Software measurement helpers; this module does not claim TPM access.
 *
 * All entropy comes from crypto.getRandomValues() or is derived
 * deterministically from system state. Non-deterministic entropy is NEVER used.
 */

"use strict";

const tpm = (() => {
  /**
   * Generate a software measurement by hashing input bytes.
   * @param {Uint8Array} inputBytes
   * @returns {Promise<string>} hex-encoded SHA-512 digest
   */
  async function measureBytes(inputBytes) {
    const digest = await crypto.subtle.digest("SHA-512", inputBytes);
    return Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  /**
   * Extend a software measurement: new = SHA-512(current || measurement).
   * This does not access or attest a hardware TPM.
   * @param {string} currentPcrHex current measurement hex string (128 chars)
   * @param {string} measurementHex new measurement hex string (128 chars)
   * @returns {Promise<string>} new PCR hex string
   */
  async function extendPcr(currentPcrHex, measurementHex) {
    const combined = hexToBytes(currentPcrHex + measurementHex);
    return measureBytes(combined);
  }

  /**
   * Generate a cryptographically-secure random nonce via crypto.getRandomValues().
   * @param {number} byteLength
   * @returns {string} hex-encoded nonce
   */
  function generateNonce(byteLength = 32) {
    const buf = new Uint8Array(byteLength);
    crypto.getRandomValues(buf);
    return Array.from(buf)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  /** @param {string} hex @returns {Uint8Array} */
  function hexToBytes(hex) {
    if (hex.length % 2 !== 0) throw new Error("Invalid hex string length");
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
  }

  return { measureBytes, extendPcr, generateNonce };
})();

if (typeof module !== "undefined" && module.exports) {
  module.exports = tpm;
}

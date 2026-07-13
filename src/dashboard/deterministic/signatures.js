/**
 * signatures.js — Deterministic Ed25519/ECDSA signature helpers.
 *
 * Uses the Web Crypto API exclusively. Non-deterministic entropy is NEVER used.
 */

"use strict";

const signatures = (() => {
  /**
   * Generate an ECDSA P-256 key pair for signing authority records.
   * @returns {Promise<CryptoKeyPair>}
   */
  async function generateKeyPair() {
    return crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
  }

  /**
   * Sign *data* with the given ECDSA private key.
   * @param {CryptoKey} privateKey
   * @param {ArrayBuffer|Uint8Array} data
   * @returns {Promise<string>} hex-encoded DER signature
   */
  async function sign(privateKey, data) {
    const raw = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      privateKey,
      data instanceof Uint8Array ? data : new Uint8Array(data)
    );
    return Array.from(new Uint8Array(raw))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  /**
   * Verify an ECDSA signature.
   * @param {CryptoKey} publicKey
   * @param {string} signatureHex
   * @param {ArrayBuffer|Uint8Array} data
   * @returns {Promise<boolean>}
   */
  async function verify(publicKey, signatureHex, data) {
    const sigBytes = hexToBytes(signatureHex);
    return crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      sigBytes,
      data instanceof Uint8Array ? data : new Uint8Array(data)
    );
  }

  /**
   * Export a public key as a JWK object.
   * @param {CryptoKey} publicKey
   * @returns {Promise<JsonWebKey>}
   */
  async function exportPublicKeyJwk(publicKey) {
    return crypto.subtle.exportKey("jwk", publicKey);
  }

  /**
   * Import a public key from a JWK object.
   * @param {JsonWebKey} jwk
   * @returns {Promise<CryptoKey>}
   */
  async function importPublicKeyJwk(jwk) {
    return crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["verify"]
    );
  }

  /** @param {string} hex @returns {Uint8Array} */
  function hexToBytes(hex) {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
  }

  return { generateKeyPair, sign, verify, exportPublicKeyJwk, importPublicKeyJwk };
})();

if (typeof module !== "undefined" && module.exports) {
  module.exports = signatures;
}

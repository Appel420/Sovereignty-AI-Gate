# RFC-0021 — Cryptographic Profile

**Status:** Draft  
**Version:** 0.1.0  
**Author:** Appel420  

---

## Abstract

Defines the cryptographic algorithm profiles that SIA implementations MUST use for
signatures, key management, and integrity. Two profiles are defined:

- **DEV-HMAC-SHA256** — development-only integrity simulation.
- **PROD-Ed25519** / **PROD-ML-DSA-87** — production-grade asymmetric signatures.

---

## Motivation

Without a declared algorithm profile, implementations may diverge on signing schemes,
key formats, and rotation policies. This RFC anchors the algorithm set so that export
bundles, SCAR attestations, and inter-instance compatibility can be reasoned about
deterministically.

---

## Profiles

### Profile 1: DEV-HMAC-SHA256 (Development Only)

| Property | Value |
|---|---|
| **Algorithm identifier** | `DEV-HMAC-SHA256` |
| **Purpose** | Local integration testing and interface validation |
| **Primitive** | HMAC-SHA256 over canonical JSON |
| **Key material** | Shared 32-byte secret derived from `secrets.token_bytes(32)` at session start |
| **Production cryptographic assurance** | **NO** — this is not a public-key scheme |

> **IMPORTANT**: DEV-HMAC-SHA256 MUST be labeled `[DEV]` in all log output, attestation
> records, and exported bundles. It MUST NOT be accepted by production authority gates.
> Any code path that uses this profile MUST emit a visible, human-readable warning to the
> developer console at startup.

### Profile 2: PROD-Ed25519 (Production — Standard)

| Property | Value |
|---|---|
| **Algorithm identifier** | `Ed25519` |
| **Primitive** | Ed25519 (RFC 8032) |
| **Key size** | 32-byte private key, 32-byte public key |
| **Signature size** | 64 bytes |
| **Key ID format** | `ed25519:<base64url(SHA256(public_key)[:12])>` |
| **Rotation** | Rotate on: scheduled interval (≤ 365 days), compromise indicator, hardware re-provisioning |
| **Revocation** | Add key ID to identity's revocation list; revocation is append-only and SCAR-audited |
| **Downgrade prevention** | Attestation records MUST include `signature_algorithm`; verifiers MUST reject DEV profile in production context |
| **Hardware binding** | Private key MUST reside in a hardware-backed secure enclave when available (TPM 2.0, Apple Secure Enclave, Android StrongBox) |

### Profile 3: PROD-ML-DSA-87 (Production — Post-Quantum)

| Property | Value |
|---|---|
| **Algorithm identifier** | `ML-DSA-87` |
| **Standard** | NIST FIPS 204 (Module-Lattice-Based Digital Signature Standard) |
| **Security level** | NIST Level 5 (post-quantum) |
| **Key ID format** | `mldsa87:<base64url(SHA256(public_key)[:12])>` |
| **Rotation** | Same policy as Ed25519; rotate at ≤ 365 days or on any cryptographic event |
| **Revocation** | Same as Ed25519; add key ID to revocation list, SCAR-audited |
| **Downgrade prevention** | Implementations that support ML-DSA-87 MUST NOT fall back to Ed25519 without explicit user instruction and SCAR audit event |
| **Hardware binding** | Where hardware does not natively support ML-DSA-87, a software implementation running inside an HSM or enclave boundary is acceptable |

---

## Key ID Scheme

All public keys are referenced by a stable key ID so that rotating keys does not break
references. Key IDs are computed deterministically from the public key material:

```
key_id = "<algorithm_prefix>:<base64url(SHA256(public_key_bytes)[:12])>"
```

Key IDs MUST be stored in `SCARAttestation.device_id` and in identity root-of-trust
records. Multiple key IDs for the same identity MAY be active simultaneously during
rotation windows (at most one rotation-window overlap allowed).

---

## Rotation Policy

1. Rotation MUST produce a new key pair under the same identity.
2. The old public key remains valid for signature verification for the duration of the
   rotation-window overlap (recommended: 30 days).
3. New signatures MUST use the new key immediately after rotation.
4. Rotation events MUST be recorded as a `KEY_ROTATED` SCAR event including both old
   and new key IDs.

---

## Revocation

1. Compromised keys are added to the identity's key revocation list (KRL).
2. The KRL is append-only; removals from the KRL are not permitted.
3. Adding an entry to the KRL generates a `KEY_REVOKED` SCAR event.
4. Verifiers MUST check the KRL before accepting a signature. A signature from a revoked
   key MUST be rejected regardless of mathematical validity.

---

## Downgrade Prevention

1. Every signed document MUST include the `signature_algorithm` field set to one of the
   registered algorithm identifiers above.
2. Verifiers MUST compare the `signature_algorithm` field to the expected profile.
3. If a production verifier receives a document with `signature_algorithm = "DEV-HMAC-SHA256"`
   it MUST reject the document and record a `DOWNGRADE_ATTEMPT` SCAR event.

---

## Conformance

Implementations MUST:
- [ ] Set `signature_algorithm` in every signed document
- [ ] Reject DEV profile signatures in production authority gates
- [ ] Label all DEV-profile output with `[DEV]` visible to the developer
- [ ] Record `KEY_ROTATED` events in the SCAR ledger on rotation
- [ ] Record `KEY_REVOKED` events in the SCAR ledger on revocation
- [ ] Check the KRL before accepting any signature
- [ ] Record `DOWNGRADE_ATTEMPT` when a production verifier receives a DEV-profile document

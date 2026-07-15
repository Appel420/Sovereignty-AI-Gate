# Deterministic Dashboard Behavior

The SIA dashboard guarantees deterministic behavior through the following mechanisms:

## No Math.random()

All JS source files in `src/dashboard/` are checked by CI for `Math.random()` usage.
Any occurrence fails the `dashboard-lint.yml` workflow.

## Deterministic Entropy

| Purpose | API Used |
|---------|----------|
| Nonce generation | `crypto.getRandomValues()` |
| Key generation | `crypto.subtle.generateKey()` |
| Signing | `crypto.subtle.sign()` |
| Hashing | `crypto.subtle.digest()` |

## State Hashing

The dashboard footer displays a truncated SHA-256 of the current state object.
This hash changes deterministically with state mutations.

## TPM PCR Simulation

> **[DEV/SOFTWARE SIMULATION]** `tpm.js` implements PCR-style measurements in
> software using `crypto.subtle.digest("SHA-256", ...)`. This is **not** hardware TPM
> attestation. It does not bind measurements to a hardware root of trust and must not
> be represented as such.

`tpm.js` provides a deterministic, testable PCR-measurement interface. When a real
hardware TPM 2.0 backend is integrated, it can satisfy the same interface contract.
Until then, all PCR values produced by this module are software-computed and carry no
hardware attestation guarantee.

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

`tpm.js` simulates TPM PCR measurement by hashing input bytes with SHA-256.
When a hardware TPM is available, it can be substituted without changing the interface.

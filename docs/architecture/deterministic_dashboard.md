# Deterministic Dashboard

The SIA dashboard is a pure HTML/CSS/JS single-page application with no build toolchain
and no external dependencies.

## Determinism Requirements

- All entropy MUST come from `crypto.getRandomValues()` or `crypto.subtle`.
- `Math.random()` is PROHIBITED.
- State hashes are computed with `crypto.subtle.digest("SHA-256", ...)`.
- The dashboard renders from local state (localStorage) only; no network calls.

## Modules

| Module | Purpose |
|--------|---------|
| `tpm.js` | TPM PCR measurement and nonce generation |
| `signatures.js` | ECDSA P-256 key generation and signing |
| `compliance.js` | RFC compliance status tracking |
| `threat_feed.js` | Local threat indicator registry |

## Lint Rule

The CI workflow `dashboard-lint.yml` rejects any JS file containing `Math.random`.

# ADR-0001 — Package Ownership

**Status:** Proposed  
**Date:** 2026-07-14  
**Deciders:** Appel420  

---

## Context

The repository contains two Python source packages:

- `src/sia` — the public-facing SIA framework API used by applications and conformance tests.
- `src/sovereignty_core` — the low-level, SAMA-foundation implementation layer.

During the initial sprint the packages grew organically; this ADR formalises ownership so that
future contributors know which package owns each domain and what the migration path looks like.

---

## Decision

### Canonical Package: `src/sia`

`src/sia` is the **canonical** package for application-facing authority management. It provides
the stable public API surface that application code and conformance tests depend on.

### Legacy Compatibility Layer: `src/sovereignty_core`

`src/sovereignty_core` is a **legacy compatibility layer** that houses the SAMA foundation
primitives. It will remain in place and is accessed from `sia` through adapters. New feature
work should extend `sia` and reference `sovereignty_core` only where existing battle-tested
primitives exist (identity, SCAR, Merkle, memory chain).

A full migration from `sovereignty_core` to a consolidated `sia` internal package is out of
scope for this ADR. Adapters in `sia` will be updated incrementally.

---

## Module Ownership Table

| Domain | Canonical Location | Notes |
|---|---|---|
| **Identity / Root Trust** | `sovereignty_core.identity` | `RootOfTrust`, `TrustBackend`, `DevelopmentSigner` — stable foundation; do not duplicate in `sia` |
| **Proofs** | `sia.authority` (planned) | Proof types are immutable data objects; `ProofVerifier` is the evaluation boundary |
| **Authority Gates / Transactions** | `sia.authority` | `SovereignAuthority`, gate logic, SCAR transaction orchestration |
| **Memory Vault** | `sia.memory` + `sovereignty_core.vault` | `sia.memory` is the authority/enforcement boundary; `sovereignty_core.vault.memory_chain` is the storage/provenance engine |
| **Delegation** | `sia.delegation` | Delegation tokens, depth limits, revocation — see RFC-0015 |
| **Audit / SCAR / Merkle** | `sovereignty_core.audit` | `SCARLedger`, `MerkleTree`, `SCARAttestation` — canonical; `sia.audit` re-exports for compatibility |
| **Export / Import** | `sia.export` + `sia.imports` | Bundle schema, hash validation, signature gate — see RFC-0018, RFC-0019 |
| **Conformance** | `sia.conformance` | `ConformanceHarness`, `EvidenceRecord` — see RFC-0016 |
| **AuthorityTypeRegistry** | `sia` (planned RFC-0023) | Exact-type enforcement boundary for authority-bearing value objects only |

---

## MemoryChain vs. MemoryVault Clarification

| Component | Role |
|---|---|
| `MemoryChain` (`sovereignty_core.vault.memory_chain`) | Storage and provenance engine: append-only, hash-chained blocks with classification and source metadata. Knows nothing about authority grants. |
| `MemoryVault` (`sia.memory`) | Authority and enforcement boundary: applies consent rules, calls `ProofVerifier` before allowing cross-model access, enforces AES-256-GCM encryption at rest. |

**Rule**: code that needs to _read or write_ memory blocks uses `MemoryChain`. Code that needs
to _decide whether access is permitted_ uses `MemoryVault`.

---

## Existing vs. Planned Modules

The table below flags which modules are **implemented** today vs. **planned** (not yet present
in the repository). Planned modules MUST NOT be documented as if they exist.

| Module | State |
|---|---|
| `sovereignty_core.identity` | Implemented |
| `sovereignty_core.audit.scar` | Implemented |
| `sovereignty_core.audit.merkle` | Implemented |
| `sovereignty_core.audit.ledger` | Implemented (backwards-compat re-export) |
| `sovereignty_core.vault.memory_chain` | Implemented |
| `sovereignty_core.permissions.capability` | Implemented |
| `sovereignty_core.permissions.consent` | Implemented |
| `sia.authority` | Implemented (`authority.py`) |
| `sia.memory` | Implemented |
| `sia.delegation` | Implemented |
| `sia.export` | Implemented |
| `sia.imports` | Implemented |
| `sia.conformance` | Implemented |
| `sia.security` | Implemented |
| `ProofVerifier` | **Planned** — RFC-0024 |
| `AuthorityTypeRegistry` | **Planned** — RFC-0023 |

---

## Consequences

- New authority-layer code goes into `sia`.
- Low-level cryptographic primitives and tamper-evident data structures remain in `sovereignty_core`.
- Adapters that bridge the two packages live in `sia` and are the only coupling points.
- Documentation MUST accurately reflect whether a module is implemented or planned.

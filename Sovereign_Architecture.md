# Sovereign Architecture

## Overview

The Sovereignty AI Gate (SIA) is composed of five interconnected layers:

```
┌─────────────────────────────────────────────┐
│              User / Operator                │
├─────────────────────────────────────────────┤
│         Authority & Policy Engine           │
│  (identity, delegation, boundary registry)  │
├─────────────────────────────────────────────┤
│       Conformance & Evidence Layer          │
│  (RFC harness, proof-of-compliance records) │
├─────────────────────────────────────────────┤
│    Memory / Import / Export / Audit         │
│  (encrypted memory, ledger, data lifecycle) │
├─────────────────────────────────────────────┤
│         Deterministic Dashboard             │
│  (TPM sealing, signatures, compliance UI)   │
└─────────────────────────────────────────────┘
```

## Layer Descriptions

### 1. Authority & Policy Engine (`src/sia/authority.py`, `src/sia/security/`)

- Manages sovereign identity for users and AI models.
- Enforces boundary policies defined per model.
- Maintains the boundary registry (which models are active, their scope, their constraints).
- Implements the no-conversion authority rule: a model's creator boundary cannot be changed
  by any delegation chain.

### 2. Conformance & Evidence Layer (`src/sia/conformance/`)

- Runs RFC-numbered conformance tests against running instances.
- Records cryptographically-signed evidence objects for each conformance assertion.
- Evidence is stored locally and can be exported as a conformance bundle.

### 3. Memory / Import / Export / Audit (`src/sia/memory/`, `src/sia/imports/`, `src/sia/export/`, `src/sia/audit/`)

- **Memory**: per-model encrypted memory store. Cross-model sharing requires user consent.
- **Import**: loads external authority bundles with full validation.
- **Export**: produces signed, portable authority bundles.
- **Audit**: append-only ledger recording every authority event with SHA-256 chained hashes.

### 4. Delegation (`src/sia/delegation/`)

- Allows a user to delegate a subset of authority to an AI model or sub-process.
- Delegation chains are bounded: a delegate cannot grant more than they received.
- All delegations expire unless renewed; renewal requires re-confirmation.

### 5. Deterministic Dashboard (`src/dashboard/`)

- Pure HTML/JS/CSS — no framework dependencies, no build toolchain required.
- All random values come from `crypto.getRandomValues()` or TPM-backed sources.
- `Math.random()` is explicitly forbidden and detected by the lint rule.
- The dashboard displays live authority state, audit tail, and conformance status.

## Trust Hierarchy

```
User Root Key (hardware-backed where available)
  └─ Model Boundary Certificate
       └─ Delegation Token (scoped, time-limited)
            └─ Action Authorization Record
                 └─ Audit Ledger Entry (chained hash)
```

## Offline Operation

All components run without network access. The authority engine, memory store, and dashboard
serve from localhost. External interoperability (e.g., sharing a conformance bundle with
another operator) uses signed, exportable bundles transported out-of-band.

## Deployment Modes

| Mode | Description |
|------|-------------|
| `local` | Single-user, single-machine. All state on device. |
| `self-hosted` | LAN or VPN deployment. Shared authority server. |
| `federated` | Multiple independent operators with cross-signed root certificates. |

# Sovereign Architecture

## Overview

Sovereignty AI Gate (SIA) is a deterministic authority framework built on a strict separation between representation, evidence, and authority.

## Frozen Authority Model

### Representation
May transform, encode, decode, normalize, transport, hash, and validate structure.
Must not mint authority.

### Evidence
May record that an event occurred.
Must not create trust.

### Authority
May only be created by a registered canonical boundary creator.
Must use exact type identity.
Must have explicit RFC ownership and explicit rejection semantics.

## Registry Governance

Canonical authority types are registered in a sealed manifest.
Transformers and creators are disjoint.
A transformer must never emit a canonical authority type.
A subclass must never be treated as equivalent authority.

## RFC Chain

- RFC-0000: Core principles
- RFC-0001 through RFC-0010: execution and authority pipeline
- RFC-0013: root trust boundary
- RFC-0014: sovereign memory authority
- RFC-0015: delegated access control
- RFC-0016: conformance harness
- RFC-0017: audit ledger
- RFC-0018: external export contract
- RFC-0019: import / rehydration verification
- RFC-0020: cross-system compatibility profile

## Deterministic Dashboard

The dashboard must remain free of randomized behavior. All validation, scan, and compliance flows must be reproducible.

## Import and Export Rules

Import produces evidence-only reconstructed state.
Export produces canonical portable evidence.
Neither side may silently create authority.

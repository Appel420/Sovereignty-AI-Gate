# FedRAMP Package Overview Schema — Layering and Integration Guide

## Overview

This directory contains two JSON Schema Draft 2020-12 definitions for the
Sovereignty AI Gate FedRAMP evidence automation pipeline:

| File | Purpose |
|------|---------|
| `fedramp-package-overview.schema.json` | Core FedRAMP Certification Package Overview metadata (FRC-CSO-PKG) |
| `x-sovereignty-extension.schema.json` | Sovereign extension namespace (`x-sovereignty`) for authority-chain, Merkle-ledger, and ML-DSA attestation metadata |

> **Disclaimer**: Validation against these schemas does not constitute FedRAMP
> authorization or compliance certification. These schemas are internal
> evidence-readiness tools only.

---

## Schema Layering

```
┌──────────────────────────────────────────────────────────────┐
│  fedramp-package-overview.schema.json                        │
│  (Core FedRAMP shape — standards compatible, not modified)   │
│                                                              │
│  Required top-level blocks:                                  │
│    schemaCompatibility  serviceIdentification  contacts      │
│    controlMappings      artifactManifest        disclaimer   │
│                                                              │
│  Optional extension block:                                   │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  x-sovereignty                                         │  │
│  │  (x-sovereignty-extension.schema.json)                 │  │
│  │                                                        │  │
│  │  authorityId      merkleRoot      auditChainId         │  │
│  │  scarLedgerReference              mlDsaAttestation     │  │
│  │  authorityPolicyVersion           evidenceDigest       │  │
│  │  implementation metadata                               │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

### Design principle

The core FedRAMP schema is intentionally kept standards-compatible with the
official FedRAMP program shape. Sovereignty AI–specific governance, audit, and
cryptographic metadata is placed entirely within the `x-sovereignty` extension
namespace. This ensures:

- Core FedRAMP tooling and reviewers can consume the package overview without
  modification.
- Sovereignty AI metadata can evolve independently.
- The two schemas can be validated separately or together.

---

## Relationship to NIST SP 800-53 Rev. 5

FedRAMP Rev. 5 builds directly on the NIST SP 800-53 Rev. 5 control catalog.
This schema represents that relationship through:

1. **`schemaCompatibility.nistRevision`** — explicitly identifies which NIST
   catalog revision applies (`SP800-53r5`).
2. **`controlMappings[]`** — each entry carries a `control` identifier in NIST
   format (e.g. `AC-2`, `AU-9(4)`), an `implementationStatus`, and references
   to evidence artifacts by `documentId`.

The table below maps Sovereignty AI platform components to the NIST SP 800-53
Rev. 5 control families they primarily address:

| Sovereignty Component | Related NIST Control Families |
|-----------------------|-------------------------------|
| GateOne Authority Engine | AC (Access Control), IA (Identification & Authentication) |
| SCAR Audit Ledger | AU (Audit & Accountability), AU-9, AU-10 |
| Merkle evidence chain | AU, SI (System & Information Integrity) |
| ML-DSA attestations | SC (System & Communications Protection), IA |
| Immutable NDJSON logs | AU-9 (Protection of Audit Information) |
| Branch governance | AC-2, AC-3, AC-6 |
| RootOfTrust key management | IA-5, SC-12, SC-13 |
| MCP tool authorization | AC-3, AC-4 |

---

## ML-DSA Attestation Representation

### Implementation reference

ML-DSA cryptographic operations are performed by
[`Appel420/sovereign-mldsa-native`](https://github.com/Appel420/sovereign-mldsa-native),
a portable C90 implementation of **ML-DSA / NIST FIPS 204** supporting all
three standardized parameter sets.

> **Note**: The JSON schemas in this directory describe *metadata* and
> *references* for ML-DSA attestation artifacts. The schemas themselves do not
> perform any cryptographic signing operation.

### FIPS 204 parameter sets

| Identifier | NIST Security Level | Typical use in GateOne |
|------------|--------------------|-----------------------|
| `ML-DSA-44` | Level 2 | Lightweight evidence signatures |
| `ML-DSA-65` | Level 3 | Standard package integrity attestation |
| `ML-DSA-87` | Level 5 | High-assurance / FedRAMP High packages |

### Attestation discriminator: inline vs. external reference

The `mlDsaAttestation` field in `x-sovereignty` uses a `oneOf` discriminator
based on the `kind` property:

**`inline-signature`** — The signature bytes are embedded directly in the
document. Use when the package document itself is the signed artifact and the
signature is small enough to include inline:

```json
{
  "kind": "inline-signature",
  "parameterSet": "ML-DSA-65",
  "signerPublicKeyId": "key-mldsa65-root-001",
  "signatureEncoding": "hex",
  "signatureValue": "<hex-encoded signature bytes>",
  "signedPayloadDigestAlgorithm": "sha3-512",
  "signedPayloadDigest": "<hex-encoded digest of the signed payload>"
}
```

**`attestation-reference`** — The signature is stored in an external bundle
(e.g. a SCAR ledger entry or a `.bin` file in the artifact manifest). Use when
the signature is produced by `sovereign-mldsa-native` as a separate artifact:

```json
{
  "kind": "attestation-reference",
  "parameterSet": "ML-DSA-87",
  "attestationBundleId": "attestation-bundle-pkg-20260717",
  "attestationBundleUri": "file:evidence/mldsa87-attestation.bin",
  "bundleDigestAlgorithm": "sha-512",
  "bundleDigest": "<hex-encoded digest of the bundle>",
  "signerPublicKeyId": "key-mldsa87-gateone-root-001",
  "issuedAt": "2026-07-17T07:00:00Z"
}
```

---

## Package Integrity

Per-artifact digests are recorded in `artifactManifest.artifacts[]`. The
overall manifest is committed by a `cryptographicMetadata.manifestDigest`
covering a canonical serialization of all artifact entries.

Supported digest algorithms: `sha-256`, `sha-384`, `sha-512`, `sha3-256`,
`sha3-512`.

Supported `signatureAlgorithm` values (manifest-level):
`RSA-PSS-SHA256/384/512`, `ECDSA-P256-SHA256`, `ECDSA-P384-SHA384`,
`ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`.

---

## Examples

| File | Description |
|------|-------------|
| `examples/valid-core-package.json` | Minimum valid core package without x-sovereignty |
| `examples/valid-with-sovereignty.json` | Full valid package with x-sovereignty extension and ML-DSA attestation reference |
| `examples/invalid-missing-required.json` | Missing required top-level fields (expected to fail validation) |
| `examples/invalid-bad-format.json` | Present fields but with invalid enum/format values (expected to fail validation) |

---

## Automated Validation Tests

Tests live at `tests/conformance/test_fedramp_package_schema.py` and use the
project's standard pytest infrastructure.

Run:

```bash
python3 -m pytest tests/conformance/test_fedramp_package_schema.py -v
```

Test coverage includes:

- Valid core documents and valid x-sovereignty extension documents
- All ML-DSA FIPS 204 parameter sets (`ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`)
- Both attestation discriminator kinds (`inline-signature`, `attestation-reference`)
- Missing required fields (schemaCompatibility, packageId, disclaimer, contacts, etc.)
- Invalid format / enum values (authorizationLevel, service type, email format, control identifier)
- Conditional authenticated-repository validation (`authenticationRequired → authenticationMechanism`)
- Digest algorithm and pattern validation (artifacts and manifest)
- x-sovereignty field constraints (versioned authority, Merkle, audit-chain, and evidence digest metadata)

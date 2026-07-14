# Proof Model

## Proof Objects are Immutable Evidence

A **proof** is an immutable data object that carries cryptographic evidence of a past
authority decision. Proof objects:

- Are frozen at construction time.
- Carry no mutable state.
- Do NOT expose a `.verify()` method that grants authority.
- Are evaluated exclusively by `ProofVerifier.verify(proof, context)`.

The distinction matters: having a proof does not grant authority. Authority is granted
only when `ProofVerifier` accepts the proof in the current context.

---

## ProofVerifier

All proof evaluation is centralized in a single boundary:

```python
class ProofVerifier:
    def verify(self, proof: BaseProof, context: AuthorityContext) -> VerificationResult:
        ...
```

`VerificationResult` carries `accepted: bool`, `reason: str`, and `audit_ref: str` so
that every evaluation decision is traceable.

**No other code path MUST grant authority based on proof content.**

---

## Proof Matrix

The table below defines every proof type, what evidence it carries, what authority action
it unlocks, and which context fields are required for evaluation.

| Proof Type | Evidence Carried | Authority Unlocks | Required Context |
|---|---|---|---|
| `BootstrapProof` | Initial device identity attestation | Authority instance initialization; first identity binding | Device key, genesis timestamp |
| `ConsentProof` | Explicit human consent event with timestamp and scope | Memory persistence, cross-model sharing, deletion | `action`, `model_id`, `record_id` |
| `CapabilityProof` | Issued `CapabilityToken` with scopes and expiry | AI-suggested memory, restricted read operations | Current time (expiry check), token signature |
| `DelegationProof` | Signed `DelegationToken` with scope, depth, parent | Delegated authority grant; cross-model capability | `grantor_id`, `grantee_id`, `scope`, depth chain |
| `ExportProof` | Signed export attestation with payload hash | Export bundle production | Ledger state, payload hash, device key |
| `ImportProof` | Verified import authority grant | Import bundle loading (Stage 4 gate) | Signer public key, bundle `payload_hash` |
| `RecoveryProof` | Multi-factor recovery ceremony evidence | Identity recovery, root key re-binding | Recovery ceremony transcript, witness signatures |
| `PolicyProof` | Human-authorized policy change authorization | `policy.mutate` scope — policy mutation | Policy diff hash, human actor SCAR reference |

---

## Exact-Type Enforcement Scope

`AuthorityTypeRegistry` (planned RFC-0023) enforces **exact Python types** for
authority-bearing value objects at gate boundaries. This prevents subclass substitution
attacks and duck-typed authority bypasses.

Exact-type enforcement applies **only** to:

- Authority-bearing value objects that cross a gate boundary (e.g., `CapabilityToken`,
  `DelegationToken`).

Exact-type enforcement does **NOT** apply to:

- Proof types and proof hierarchies (proofs are evidence, not authority grants).
- Serializer and deserializer return types.
- Audit events and SCAR records.
- Export/import bundle representations.
- Internal adapter types.

---

## Policy Mutation as Authority-Bearing

Modifying a policy definition is an authority-bearing action because it changes what
future authority evaluations will permit. Therefore:

- `policy.mutate` operations require a `PolicyProof`.
- `ProofVerifier` evaluates the `PolicyProof` before any mutation is applied.
- The mutation is wrapped in the 10-step SCAR transaction order (RFC-0000, Section 6).
- A `POLICY_MUTATED` SCAR event is appended with actor `HUMAN`.

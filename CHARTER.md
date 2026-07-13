# Sovereignty AI Gate — Charter

## Mission

Sovereignty AI Gate establishes a user-rooted authority framework for deterministic, auditable,
and provider-independent AI governance. The project ensures that humans retain explicit control
over AI actions, memory, identity, permissions, and delegation — without reliance on any
third-party cloud authority.

## Principles

1. **Human Sovereignty First** — Every action taken by or on behalf of an AI model must be
   traceable to an explicit human grant of authority.

2. **Offline-First** — All core workflows operate without external network calls. Cloud
   interoperability is an opt-in extension, never a requirement.

3. **Deterministic Trust** — Identity, signatures, compliance checks, and audit entries are
   computed deterministically. Non-deterministic entropy (e.g., `Math.random()`) is forbidden
   in the authority pipeline.

4. **No Backdoors, No Fakes** — Every function in this codebase is real and operational.
   Mock flows, stub deployments, and non-functional demos are prohibited.

5. **Encrypted User Memory** — AI conversation memory is stored on the user's device,
   encrypted at rest, scoped per model, and shared across models only with explicit user consent.

6. **Root Chain of Authority** — Trust is rooted in locally-generated cryptographic material
   (keys, certificates, TPM-backed seals) with no dependency on third-party certificate
   authorities for internal governance. Let's Encrypt is used only for public-facing TLS.

7. **Auditable Ledger** — Every authority grant, delegation, memory access, import, and export
   is recorded in an append-only, tamper-evident audit ledger.

8. **Provider Independence** — The framework supports OpenAI, Anthropic/Claude, Grok, and
   GitHub Copilot. Google/Gemini, Meta/Llama, Firebase, and Vertex are prohibited.

## Governance

This project is governed by the owner (Appel420). RFC documents define the protocol. Changes
to core authority semantics require an RFC update before code changes are accepted.

## Versioning

The project follows semantic versioning. Breaking changes to the authority wire format require
a major version bump and an RFC update.

# Sovereignty AI Gate

Sovereignty AI Gate is a **user-rooted authority framework** for AI governance.
It is built to be **offline-first, deterministic, auditable, and enforceable**.

This project is serious by design:
- It says what it does.
- It does what it says.
- Every critical behavior is expected to be verifiable in code and tests.

## What This Project Guarantees

- **Human authority is explicit**: AI actions must trace back to a human grant.
- **Offline-first operation**: core workflows run locally without required cloud calls.
- **Deterministic execution**: random behavior in authority-critical paths is not allowed.
- **Tamper-evident auditability**: authority events are recorded in an append-only chain.
- **Provider independence**: governance logic is not tied to a single vendor stack.

## Non-Negotiable Rules

- No hidden synchronization.
- No silent external persistence.
- No backdoors.
- No fake demos or non-functional flows presented as real.
- No implicit network behavior in core local workflows.

## Provider and Platform Policy

- Supported providers: OpenAI, Anthropic/Claude, Grok, GitHub Copilot.
- Prohibited stacks in this governance surface: Google/Gemini, Meta/Llama, Firebase, Vertex.
- Dashboard configs, docs, and fixtures must not hard-code promotional vendor catalogs.

## Branch and Contribution Policy

Do not push directly to `main`.

Use dedicated branches for agent work and open a Pull Request for review:
- `ara-hardened` for direct owner hardening work
- `copilot` for GitHub Copilot changes
- `GPT` for GPT/Codex changes

## Quick Verification

Run the checks used in this repository:

```bash
npm install
npm test
python -m pip install -e '.[dev]'
pytest
```

Note: `npm run lint` currently requires an `eslint.config.*` file for ESLint v9.

## Start Here

- Governance intent: `CHARTER.md`
- Collaboration mode: `PLAYGROUND.md`
- Security expectations: `SECURITY.md`

If a behavior cannot be audited, explained, and tested, it does not belong in this project.

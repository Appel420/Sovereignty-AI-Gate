# Contributing to Sovereignty AI Gate

Thank you for your interest in contributing. This is a security-sensitive project with strict
rules. Please read this document fully before submitting any contribution.

## Ground Rules

1. **Read before touching.** Read all relevant source files before proposing changes.
2. **No fakes.** Every function must be real and operational. Stubs and mocks are allowed
   only inside test files, never in `src/`.
3. **No backdoors.** Any code that creates undocumented execution paths will be rejected.
4. **No external dependencies** for core workflows. New runtime dependencies require explicit
   approval and a security review.
5. **Offline-first.** New features must work without internet access.
6. **Deterministic.** `Math.random()` is banned in all non-test JS. Use `crypto.getRandomValues()`.

## Workflow

1. Fork the repository.
2. Create a feature branch (`feature/<rfc-number>-<description>`).
3. Implement changes with full test coverage.
4. Run the full test suite: `bash scripts/run_tests.sh`
5. Run conformance checks: `bash scripts/run_conformance.sh`
6. Open a pull request targeting `main`.

## RFC Process

Non-trivial changes to the authority protocol require an RFC:

1. Copy `docs/rfc/RFC-0000.md` as a template.
2. Assign the next available RFC number.
3. Fill in all required sections (motivation, specification, conformance, security).
4. Open a draft PR with just the RFC document for discussion.
5. After approval, implement and open the code PR referencing the RFC number.

## Code Style

- Python: follow PEP 8. Use type hints. No `Any` unless absolutely necessary.
- JavaScript: ES2022+. No frameworks. No `Math.random()`. Use `const`/`let`, never `var`.
- Commit messages: `<type>(<scope>): <summary>` — e.g., `feat(memory): add consent gate`.

## Testing

- All new Python code must have corresponding tests in `tests/`.
- Test file names mirror source file names: `src/sia/memory/validator.py` →
  `tests/conformance/test_rfc0014_memory.py`.
- Dashboard JS must pass the no-Math.random lint check.

## Security Reviews

All PRs that touch `src/sia/security/`, `src/sia/audit/`, or cryptographic code require a
security review before merge. Do not merge your own security-sensitive PRs.

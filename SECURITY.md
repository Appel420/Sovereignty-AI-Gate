# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Yes    |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately by emailing the repository owner directly (see GitHub profile
for contact details) or by using GitHub's private security advisory feature:
<https://github.com/Appel420/Sovereignty-AI-Gate/security/advisories/new>

Please include:
- A description of the vulnerability and its potential impact
- Steps to reproduce
- Affected version(s)
- Any suggested mitigation or fix

You will receive an acknowledgment within 48 hours and a full response within 7 days.

## Security Principles

This project enforces the following non-negotiable security rules:

1. **No backdoors.** Every execution path is auditable and deterministic.
2. **No fake flows.** All functions perform real cryptographic or validation operations.
3. **No external authority.** The trust root is always a locally-generated key, never a
   third-party SaaS service.
4. **No non-deterministic entropy** in the authority pipeline. `Math.random()` is banned.
5. **No secrets in source code.** Any key material found in the codebase is a critical bug.
6. **Encrypted memory at rest.** User memory files are AES-256-GCM encrypted before storage.
7. **Audit immutability.** Ledger entries use chained SHA3-512 hashes; any tampering breaks
   the chain and is detected at startup.

## Scope

The following are in scope for security reports:

- Authority bypass (escalating privileges without a valid delegation token)
- Cryptographic weaknesses in key generation, signing, or verification
- Memory leakage (reading another model's memory without consent)
- Audit ledger tampering or bypass
- Dashboard XSS or injection vulnerabilities
- Import/export validation bypasses

## Out of Scope

- Issues in third-party dependencies (report to the upstream project)
- Social engineering attacks
- Physical access attacks

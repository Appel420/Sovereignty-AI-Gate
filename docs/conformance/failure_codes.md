# Failure Codes

All SIA error codes follow the pattern `E<four-digit-number>`.

## Quick Reference

| Code | Name | Description |
|------|------|-------------|
| E0001 | NOT_INITIALIZED | Authority not initialized |
| E0002 | INVALID_IDENTITY | Invalid identity material |
| E0003 | BOUNDARY_VIOLATION | Boundary policy violation |
| E0004 | POLICY_DENIED | Action denied by authority policy |
| E0005 | SIGNATURE_INVALID | Cryptographic signature is invalid |
| E1000 | MEMORY_DECRYPT_FAILED | Memory decryption failed |
| E1001 | MEMORY_CONSENT_DENIED | Cross-model memory access denied |
| E1003 | MEMORY_SCHEMA_INVALID | Memory record schema is invalid |
| E2000 | DELEGATION_EXPIRED | Delegation token has expired |
| E2001 | DELEGATION_SCOPE_EXCEEDED | Delegation scope exceeded |
| E2002 | DELEGATION_CHAIN_TOO_DEEP | Chain depth limit exceeded |
| E2003 | DELEGATION_REVOKED | Delegation has been revoked |
| E3001 | EXPORT_SCHEMA_INVALID | Export schema invalid |
| E4000 | IMPORT_SCHEMA_INVALID | Import schema invalid |
| E4002 | IMPORT_VERSION_UNSUPPORTED | Import version not supported |
| E4003 | IMPORT_DUPLICATE | Bundle already imported |
| E5000 | AUDIT_CHAIN_BROKEN | Ledger chain integrity failed |
| E5001 | AUDIT_TAMPERED | Ledger entry tampered |
| E7001 | REGISTRY_DUPLICATE | Boundary already registered |
| E7002 | REGISTRY_CONVERSION_DENIED | Boundary type conversion denied |
| E7003 | REGISTRY_CREATOR_LOCKED | Creator boundary locked |

Full list: `src/sia/errors/codes.py`

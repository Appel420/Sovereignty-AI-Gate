# Authority Lifecycle

```
[Created] ──initialize()──▶ [Operational]
    │                            │
    │ (no ops allowed)      register_boundary()
    │                        issue_delegation()
    │                        store_memory()
    │                        create_export()
    │                        load_import()
    │                        enforce_policy()
    │                        verify_ledger()
    └─────────────────────────────────────────▶ [Audit Ledger]
```

Every operation writes at least one audit ledger entry. The ledger is append-only
and verified on demand via `verify_ledger()`.

# Security Decision Record Index — FedRAMP Phase 4 (Internal)

| SDR ID | Decision | Evidence |
|---|---|---|
| SDR-P4-001 | Treat “FedRAMP Phase 4” as an internal hardening/evidence phase only; no official FedRAMP phase claim. | `docs/compliance/fedramp_phase4/cloud_dependency_inventory.json`; this file |
| SDR-P4-002 | Enforce deterministic dependency policy and reject floating versions. | `constraints/py312.txt`; `scripts/check_dependency_policy.py`; `.github/workflows/tests.yml` |
| SDR-P4-003 | Require reproducible SBOM generation and verification in-repo. | `scripts/generate_sbom.py`; `docs/compliance/fedramp_phase4/sbom.json` |
| SDR-P4-004 | Harden workflow execution by pinning third-party actions to commit SHA and read-only permissions. | `.github/workflows/*.yml`; `scripts/validate_cloud_config.py` |
| SDR-P4-005 | Enforce fail-closed cloud boundary defaults for compose/nginx and explicit offline defaults. | `deploy/docker/docker-compose.yml`; `deploy/nginx/default.conf`; `scripts/validate_cloud_config.py` |

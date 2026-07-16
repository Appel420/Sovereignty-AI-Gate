# FedRAMP Rev. 5 / NIST SP 800-53 Mapping (Internal Phase 4)

This matrix is for internal evidence readiness only. It does **not** assert FedRAMP authorization/certification.

| Family | Item | Repository implementation/evidence | Status |
|---|---|---|---|
| CA | Security assessment evidence | `tests.yml` dependency-hardening job; `scripts/validate_cloud_config.py`; `scripts/check_dependency_policy.py` | partial |
| CM | Baseline/configuration management | `constraints/py312.txt`; pinned workflow actions; `package-lock.json`; compose/nginx validation | implemented |
| CP | Recovery/continuity | Existing local-first/offline mode architecture; no cloud-only control plane dependency | partial |
| IA | Identity/authentication | Authority identity+capability model, provider key-file loading, denied-by-default behavior | implemented |
| IR | Incident response traceability | Audit events and provider failure evidence paths; incident model in `continuous_monitoring.md` | partial |
| RA | Risk/vulnerability assessment | CI dependency policy checks; repository security policy; CodeQL/security scan requirement in workflow process | partial |
| SA | System/services acquisition & supply-chain integrity | Deterministic pinning, SBOM generation/verification, undeclared dependency checks | implemented |
| SC | Boundary protection | Offline-first MCP, provider allowlist/banlist, docker/nginx fail-closed checks, internal compose network | implemented |
| SI | Integrity/monitoring | Conformance tests, dashboard lint, dependency/SBOM/config validation checks | partial |
| SR | Supply-chain risk management | Cloud/dependency inventory, dependency policy checks, SBOM evidence file | implemented |

## Status definitions

- **implemented**: code/tests/checks currently enforce behavior.
- **partial**: some evidence or controls exist, but additional operational process evidence is still required.
- **not implemented**: control area has no current implementation in this repository.
- **not applicable**: control does not apply to this repository scope.

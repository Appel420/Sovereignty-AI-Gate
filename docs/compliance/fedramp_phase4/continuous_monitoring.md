# FedRAMP Phase 4 Continuous Monitoring and Evidence Model (Internal)

Internal hardening/evidence model for FedRAMP Rev. 5 readiness work. This is not an authorization claim.

## Continuous evidence checks

1. **Dependency changes**
   - Run `python scripts/check_dependency_policy.py`.
   - Run `python scripts/generate_sbom.py --check docs/compliance/fedramp_phase4/sbom.json`.
   - Evidence: CI logs + updated SBOM when dependencies change.
2. **Cloud/deployment config changes**
   - Run `python scripts/validate_cloud_config.py`.
   - Evidence: CI logs proving fail-closed docker/nginx/workflow policy checks passed.
3. **Python/conformance/dashboard behavior**
   - Run `bash scripts/run_tests.sh`, `bash scripts/run_conformance.sh`, and `npm test`.
   - Evidence: test logs.
4. **Secrets control**
   - Run repository secret scanning as a release gate before merge.
   - Evidence: scan report result and review sign-off.
5. **Vulnerability/security review**
   - Run CodeQL/equivalent static security review in CI process.
   - Evidence: tool results and remediation notes in PR.

## Incident and exception tracking requirements

- Any provider failure, dependency vulnerability, cloud configuration failure, or supply-chain policy violation must identify:
  - affected dependency/service ID,
  - detection timestamp/check source,
  - impacted code/config path,
  - linked evidence record (test/log/report),
  - mitigation decision and owner.
- Exceptions require explicit expiration date and review owner; expired exceptions fail review.

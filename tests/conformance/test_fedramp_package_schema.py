"""
FedRAMP Package Overview schema conformance tests.

Validates the JSON Schema Draft 2020-12 definitions at:
  docs/compliance/fedramp/fedramp-package-overview.schema.json
  docs/compliance/fedramp/x-sovereignty-extension.schema.json

Coverage:
  - Valid core package documents
  - Valid x-sovereignty extension blocks
  - Missing required fields
  - Invalid format / enum values
  - Conditional authenticated-repository validation (authenticationRequired → authenticationMechanism)
  - Digest pattern validation
  - ML-DSA attestation discriminator (inline-signature vs. attestation-reference)
  - x-sovereignty required fields
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_DIR = REPO_ROOT / "docs" / "compliance" / "fedramp"
EXAMPLES_DIR = SCHEMA_DIR / "examples"


def _load_schema(name: str) -> dict[str, Any]:
    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))


def _load_example(name: str) -> dict[str, Any]:
    return json.loads((EXAMPLES_DIR / name).read_text(encoding="utf-8"))


def _make_validator(schema: dict[str, Any]) -> Draft202012Validator:
    """Return a Draft202012Validator with the x-sovereignty schema loaded from disk."""
    x_sov_schema = _load_schema("x-sovereignty-extension.schema.json")
    store = {
        schema["$id"]: schema,
        x_sov_schema["$id"]: x_sov_schema,
    }
    from jsonschema import RefResolver  # noqa: PLC0415

    resolver = RefResolver(base_uri=schema["$id"], referrer=schema, store=store)
    return Draft202012Validator(schema, resolver=resolver, format_checker=FormatChecker())


def _assert_valid(doc: dict[str, Any]) -> None:
    schema = _load_schema("fedramp-package-overview.schema.json")
    validator = _make_validator(schema)
    errors = list(validator.iter_errors(doc))
    assert errors == [], f"Expected valid but got {len(errors)} error(s):\n" + "\n".join(
        str(e) for e in errors
    )


def _assert_invalid(doc: dict[str, Any]) -> list[ValidationError]:
    schema = _load_schema("fedramp-package-overview.schema.json")
    validator = _make_validator(schema)
    errors = list(validator.iter_errors(doc))
    assert errors, "Expected validation errors but document was valid."
    return errors


# ---------------------------------------------------------------------------
# Valid core package
# ---------------------------------------------------------------------------


def test_valid_core_package_example() -> None:
    """The valid-core-package.json example must pass schema validation."""
    doc = _load_example("valid-core-package.json")
    _assert_valid(doc)


# ---------------------------------------------------------------------------
# Valid x-sovereignty extension
# ---------------------------------------------------------------------------


def test_valid_with_sovereignty_extension() -> None:
    """The valid-with-sovereignty.json example must pass schema validation."""
    doc = _load_example("valid-with-sovereignty.json")
    _assert_valid(doc)


def test_x_sovereignty_attestation_reference_kind() -> None:
    """x-sovereignty mlDsaAttestation with kind=attestation-reference must validate."""
    doc = _load_example("valid-with-sovereignty.json")
    attestation = doc["x-sovereignty"]["mlDsaAttestation"]
    assert attestation["kind"] == "attestation-reference"
    _assert_valid(doc)


def test_x_sovereignty_inline_signature_kind() -> None:
    """x-sovereignty mlDsaAttestation with kind=inline-signature must validate."""
    doc = _load_example("valid-with-sovereignty.json")
    doc["x-sovereignty"]["mlDsaAttestation"] = {
        "kind": "inline-signature",
        "parameterSet": "ML-DSA-65",
        "signerPublicKeyId": "key-mldsa65-root-001",
        "signatureEncoding": "hex",
        "signatureValue": "aabbccddeeff001122334455" * 8,
        "signedPayloadDigestAlgorithm": "sha3-512",
        "signedPayloadDigest": "a" * 96,
    }
    _assert_valid(doc)


def test_x_sovereignty_all_parameter_sets() -> None:
    """ML-DSA parameter sets ML-DSA-44, ML-DSA-65, ML-DSA-87 must all be accepted."""
    doc = _load_example("valid-with-sovereignty.json")
    for param_set in ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87"):
        d = copy.deepcopy(doc)
        d["x-sovereignty"]["mlDsaAttestation"]["parameterSet"] = param_set
        _assert_valid(d)


def test_x_sovereignty_missing_authority_root_invalid() -> None:
    """Removing authorityRoot from x-sovereignty must fail validation."""
    doc = _load_example("valid-with-sovereignty.json")
    del doc["x-sovereignty"]["authorityRoot"]
    _assert_invalid(doc)


def test_x_sovereignty_missing_audit_chain_id_invalid() -> None:
    """Removing auditChainId from x-sovereignty must fail validation."""
    doc = _load_example("valid-with-sovereignty.json")
    del doc["x-sovereignty"]["auditChainId"]
    _assert_invalid(doc)


def test_x_sovereignty_evidence_digest_pattern() -> None:
    """evidenceDigest must match '<algorithm>:<hex>' prefix pattern."""
    doc = _load_example("valid-with-sovereignty.json")
    # Valid prefixes
    for prefix in ("sha-256", "sha-384", "sha-512", "sha3-256", "sha3-512", "blake3"):
        d = copy.deepcopy(doc)
        d["x-sovereignty"]["evidenceDigest"] = f"{prefix}:" + "a" * 64
        _assert_valid(d)
    # Invalid prefix
    bad = copy.deepcopy(doc)
    bad["x-sovereignty"]["evidenceDigest"] = "md5:aabbcc"
    _assert_invalid(bad)


def test_x_sovereignty_invalid_parameter_set() -> None:
    """An unrecognized ML-DSA parameter set (e.g. ML-DSA-99) must fail."""
    doc = _load_example("valid-with-sovereignty.json")
    doc["x-sovereignty"]["mlDsaAttestation"]["parameterSet"] = "ML-DSA-99"
    _assert_invalid(doc)


def test_x_sovereignty_authority_policy_version_pattern() -> None:
    """authorityPolicyVersion must match 'policy-v<semver>' pattern."""
    doc = _load_example("valid-with-sovereignty.json")
    # Valid
    doc["x-sovereignty"]["authorityPolicyVersion"] = "policy-v2.3.4"
    _assert_valid(doc)
    # Invalid pattern
    bad = copy.deepcopy(doc)
    bad["x-sovereignty"]["authorityPolicyVersion"] = "v2.0"
    _assert_invalid(bad)


# ---------------------------------------------------------------------------
# Missing required fields
# ---------------------------------------------------------------------------


def test_invalid_missing_required_example() -> None:
    """The invalid-missing-required.json example must fail schema validation."""
    doc = _load_example("invalid-missing-required.json")
    _assert_invalid(doc)


def test_missing_schema_compatibility() -> None:
    doc = _load_example("valid-core-package.json")
    del doc["schemaCompatibility"]
    _assert_invalid(doc)


def test_missing_package_id() -> None:
    doc = _load_example("valid-core-package.json")
    del doc["packageId"]
    _assert_invalid(doc)


def test_missing_disclaimer() -> None:
    doc = _load_example("valid-core-package.json")
    del doc["disclaimer"]
    _assert_invalid(doc)


def test_missing_contacts() -> None:
    doc = _load_example("valid-core-package.json")
    del doc["contacts"]
    _assert_invalid(doc)


def test_missing_control_mappings() -> None:
    doc = _load_example("valid-core-package.json")
    del doc["controlMappings"]
    _assert_invalid(doc)


def test_missing_artifact_manifest() -> None:
    doc = _load_example("valid-core-package.json")
    del doc["artifactManifest"]
    _assert_invalid(doc)


def test_missing_authorized_official_contact() -> None:
    doc = _load_example("valid-core-package.json")
    del doc["contacts"]["authorizedOfficial"]
    _assert_invalid(doc)


def test_missing_isso_contact() -> None:
    doc = _load_example("valid-core-package.json")
    del doc["contacts"]["informationSystemSecurityOfficer"]
    _assert_invalid(doc)


# ---------------------------------------------------------------------------
# Invalid formats and enums
# ---------------------------------------------------------------------------


def test_invalid_bad_format_example() -> None:
    """The invalid-bad-format.json example must fail schema validation."""
    doc = _load_example("invalid-bad-format.json")
    _assert_invalid(doc)


def test_invalid_fedramp_revision_enum() -> None:
    doc = _load_example("valid-core-package.json")
    doc["schemaCompatibility"]["fedrampRevision"] = "Rev99"
    _assert_invalid(doc)


def test_invalid_nist_revision_enum() -> None:
    doc = _load_example("valid-core-package.json")
    doc["schemaCompatibility"]["nistRevision"] = "SP800-53r3"
    _assert_invalid(doc)


def test_invalid_authorization_level_enum() -> None:
    doc = _load_example("valid-core-package.json")
    doc["serviceIdentification"]["authorizationLevel"] = "UltraHigh"
    _assert_invalid(doc)


def test_invalid_service_type_enum() -> None:
    doc = _load_example("valid-core-package.json")
    doc["serviceIdentification"]["serviceType"] = "BaaS"
    _assert_invalid(doc)


def test_invalid_email_format_in_contact() -> None:
    doc = _load_example("valid-core-package.json")
    doc["contacts"]["authorizedOfficial"]["email"] = "not-an-email"
    _assert_invalid(doc)


def test_invalid_control_identifier_pattern() -> None:
    doc = _load_example("valid-core-package.json")
    doc["controlMappings"][0]["control"] = "bad-control"
    _assert_invalid(doc)


def test_invalid_implementation_status_enum() -> None:
    doc = _load_example("valid-core-package.json")
    doc["controlMappings"][0]["implementationStatus"] = "Unknown Status"
    _assert_invalid(doc)


def test_invalid_digest_pattern_in_artifact() -> None:
    doc = _load_example("valid-core-package.json")
    doc["artifactManifest"]["artifacts"][0]["digest"] = "notvalidhex!!!"
    _assert_invalid(doc)


def test_invalid_digest_algorithm_enum_in_artifact() -> None:
    doc = _load_example("valid-core-package.json")
    doc["artifactManifest"]["artifacts"][0]["digestAlgorithm"] = "md5"
    _assert_invalid(doc)


def test_invalid_manifest_digest_pattern() -> None:
    doc = _load_example("valid-core-package.json")
    doc["artifactManifest"]["cryptographicMetadata"]["manifestDigest"] = "NOTVALIDHEX"
    _assert_invalid(doc)


def test_invalid_signature_algorithm_enum() -> None:
    doc = _load_example("valid-core-package.json")
    doc["artifactManifest"]["cryptographicMetadata"]["signatureAlgorithm"] = "RSA-PKCS1v15"
    _assert_invalid(doc)


# ---------------------------------------------------------------------------
# Conditional authenticated-repository validation
# ---------------------------------------------------------------------------


def test_repo_authenticated_true_requires_mechanism() -> None:
    """authenticationRequired=true without authenticationMechanism must fail."""
    doc = _load_example("valid-core-package.json")
    doc["repositories"] = [
        {
            "type": "git",
            "uri": "https://github.com/Appel420/Sovereignty-AI-Gate",
            "authenticationRequired": True,
            # missing authenticationMechanism
        }
    ]
    _assert_invalid(doc)


def test_repo_authenticated_false_no_mechanism_required() -> None:
    """authenticationRequired=false without authenticationMechanism must pass."""
    doc = _load_example("valid-core-package.json")
    doc["repositories"] = [
        {
            "type": "git",
            "uri": "https://github.com/Appel420/Sovereignty-AI-Gate",
            "authenticationRequired": False,
        }
    ]
    _assert_valid(doc)


def test_repo_authenticated_true_with_mechanism_valid() -> None:
    """authenticationRequired=true with valid authenticationMechanism must pass."""
    doc = _load_example("valid-core-package.json")
    doc["repositories"] = [
        {
            "type": "git",
            "uri": "https://github.com/Appel420/Sovereignty-AI-Gate",
            "authenticationRequired": True,
            "authenticationMechanism": "SovereignAuthority",
        }
    ]
    _assert_valid(doc)


def test_repo_invalid_authentication_mechanism_enum() -> None:
    """An unrecognized authenticationMechanism enum value must fail."""
    doc = _load_example("valid-core-package.json")
    doc["repositories"] = [
        {
            "type": "git",
            "uri": "https://github.com/Appel420/Sovereignty-AI-Gate",
            "authenticationRequired": True,
            "authenticationMechanism": "BasicAuth",
        }
    ]
    _assert_invalid(doc)


# ---------------------------------------------------------------------------
# Digest / signature metadata
# ---------------------------------------------------------------------------


def test_digest_all_valid_algorithms() -> None:
    """All permitted digest algorithms should be accepted in artifact entries."""
    doc = _load_example("valid-core-package.json")
    algorithm_digest_map = {
        "sha-256": "a" * 64,
        "sha-384": "b" * 96,
        "sha-512": "c" * 128,
        "sha3-256": "d" * 64,
        "sha3-512": "e" * 128,
    }
    for alg, digest in algorithm_digest_map.items():
        d = copy.deepcopy(doc)
        d["artifactManifest"]["artifacts"][0]["digestAlgorithm"] = alg
        d["artifactManifest"]["artifacts"][0]["digest"] = digest
        _assert_valid(d)


def test_ml_dsa_signature_algorithm_accepted_in_manifest() -> None:
    """ML-DSA-44/65/87 are valid signatureAlgorithm values in cryptographicMetadata."""
    doc = _load_example("valid-core-package.json")
    for alg in ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87"):
        d = copy.deepcopy(doc)
        d["artifactManifest"]["cryptographicMetadata"]["signatureAlgorithm"] = alg
        _assert_valid(d)


def test_scar_entry_digest_pattern() -> None:
    """SCAR ledger entry digests must match the hex pattern."""
    doc = _load_example("valid-with-sovereignty.json")
    bad = copy.deepcopy(doc)
    bad["x-sovereignty"]["scarLedgerReference"]["entryDigest"] = "GGGG"
    _assert_invalid(bad)


def test_merkle_root_pattern() -> None:
    """Merkle root must be a 64-128 char lowercase hex string."""
    doc = _load_example("valid-with-sovereignty.json")
    bad = copy.deepcopy(doc)
    bad["x-sovereignty"]["merkleRoot"] = "ZZZZ"
    _assert_invalid(bad)

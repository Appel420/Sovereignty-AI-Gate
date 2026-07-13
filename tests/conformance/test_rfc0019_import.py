"""
RFC-0019: Import bundle conformance tests.
"""
import json
from pathlib import Path

import pytest

from sia.imports.models import ImportBundle
from sia.imports.validator import validate_import
from sia.imports.loader import BundleLoader
from sia.errors import codes
from sia.errors.exceptions import ImportError as SIAImportError
from sia.utils.hashing import sha256_object

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_valid_import_fixture():
    data = json.loads((FIXTURES / "valid_import.json").read_text())
    bundle = ImportBundle.from_dict(data)
    validate_import(bundle)  # must not raise


def test_import_duplicate_rejected():
    loader = BundleLoader()
    payload = {"boundaries": []}
    h = sha256_object(payload)
    bundle = ImportBundle(
        bundle_id="imp-dup",
        created_by="user:bob",
        payload=payload,
        payload_hash=h,
        signature="c" * 128,
        created_at="2026-01-01T00:00:00+00:00",
    )
    loader.load(bundle)
    with pytest.raises(SIAImportError) as exc_info:
        loader.load(bundle)
    assert exc_info.value.code == codes.E_IMPORT_DUPLICATE


def test_import_hash_mismatch():
    bundle = ImportBundle(
        bundle_id="imp-bad",
        created_by="user:bob",
        payload={"data": "x"},
        payload_hash="wrong",
        signature="c" * 128,
        created_at="2026-01-01T00:00:00+00:00",
    )
    with pytest.raises(SIAImportError) as exc_info:
        validate_import(bundle)
    assert exc_info.value.code == codes.E_IMPORT_SCHEMA_INVALID


def test_import_unsupported_version():
    payload = {"data": "x"}
    h = sha256_object(payload)
    bundle = ImportBundle(
        bundle_id="imp-v99",
        created_by="user:bob",
        payload=payload,
        payload_hash=h,
        signature="c" * 128,
        created_at="2026-01-01T00:00:00+00:00",
        schema_version="99.0",
    )
    with pytest.raises(SIAImportError) as exc_info:
        validate_import(bundle)
    assert exc_info.value.code == codes.E_IMPORT_VERSION_UNSUPPORTED


def test_import_roundtrip():
    payload = {"k": "v"}
    h = sha256_object(payload)
    bundle = ImportBundle(
        bundle_id="imp-rt",
        created_by="user:bob",
        payload=payload,
        payload_hash=h,
        signature="d" * 128,
        created_at="2026-01-01T00:00:00+00:00",
    )
    restored = ImportBundle.from_dict(bundle.to_dict())
    assert restored.bundle_id == bundle.bundle_id


def test_import_loader_list():
    loader = BundleLoader()
    payload = {"x": 1}
    h = sha256_object(payload)
    for i in range(3):
        bundle = ImportBundle(
            bundle_id=f"imp-list-{i}",
            created_by="user:bob",
            payload=payload,
            payload_hash=h,
            signature="e" * 128,
            created_at="2026-01-01T00:00:00+00:00",
        )
        loader.load(bundle)
    assert len(loader.list_bundles()) == 3

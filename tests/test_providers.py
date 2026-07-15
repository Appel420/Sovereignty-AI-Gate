"""
Tests for the provider routing layer:
  - Layer 1: Provider Registry
  - Layer 2: Per-Provider Memory Store
  - Layer 3: Concrete provider drivers (key-missing and unauthorized-packet paths)
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sia.authority_gate import AuthorizedContextPacket
from sia.errors.exceptions import (
    BannedProviderError,
    MemoryConsentDeniedError,
    MemoryDecryptError,
    ProviderCallError,
    ProviderConfigError,
    RegistryNotFoundError,
)
from sia.memory.models import MemoryRecord
from sia.providers.registry import (
    BANNED_PROVIDER_PREFIXES,
    KNOWN_BANNED_PROVIDERS,
    PROVIDER_REGISTRY,
    ProviderID,
    lookup_provider,
)
from sia.providers.memory_store import ProviderMemoryStore
from sovereignty_core.identity.root_of_trust import RootOfTrust, SoftwareTrustBackend


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def root_of_trust() -> RootOfTrust:
    return RootOfTrust(SoftwareTrustBackend())


@pytest.fixture()
def tmp_store_dir(tmp_path: Path) -> Path:
    return tmp_path / "providers"


@pytest.fixture()
def authorized_packet() -> AuthorizedContextPacket:
    return AuthorizedContextPacket(
        packet_id="pkt-001",
        provider_id="xai.grok",
        owner_identity="user:test",
        capability_id="cap-001",
        operation="CALL_PROVIDER",
        policy_hash="abc123",
        memory_context=({"record_id": "r1", "model_id": "xai.grok", "content": "hello"},),
        metadata={"prompt": "Hello, world!"},
        authorized=True,
    )


# ---------------------------------------------------------------------------
# Layer 1: Provider Registry
# ---------------------------------------------------------------------------

class TestProviderRegistry:
    def test_all_canonical_ids_present(self):
        for pid in ProviderID:
            assert pid in PROVIDER_REGISTRY

    def test_lookup_allowed_providers(self):
        for pid in ProviderID:
            entry = lookup_provider(pid.value)
            assert entry.canonical_id == pid.value

    def test_entry_has_roles(self):
        for pid in ProviderID:
            entry = PROVIDER_REGISTRY[pid]
            assert isinstance(entry.roles, frozenset)
            assert len(entry.roles) > 0

    def test_entry_has_model_family(self):
        for pid in ProviderID:
            entry = PROVIDER_REGISTRY[pid]
            assert isinstance(entry.model_family, tuple)
            assert len(entry.model_family) > 0

    def test_entry_has_memory_file_path(self):
        for pid in ProviderID:
            entry = PROVIDER_REGISTRY[pid]
            assert isinstance(entry.dedicated_memory_file, Path)
            assert entry.dedicated_memory_file.suffix == ".json"

    def test_copilot_is_never_use_as_primary(self):
        entry = PROVIDER_REGISTRY[ProviderID.GITHUB_COPILOT]
        assert entry.never_use_as_primary is True, (
            "GitHub Copilot is the Heavy Judge provider and must have "
            "never_use_as_primary=True"
        )

    def test_primary_providers_are_not_restricted(self):
        for pid in (ProviderID.XAI_GROK, ProviderID.OPENAI_GPT, ProviderID.ANTHROPIC_CLAUDE):
            entry = PROVIDER_REGISTRY[pid]
            assert entry.never_use_as_primary is False

    def test_banned_google_raises(self):
        with pytest.raises(BannedProviderError) as exc_info:
            lookup_provider("google.gemini")
        assert exc_info.value.provider_id == "google.gemini"

    def test_banned_meta_raises(self):
        with pytest.raises(BannedProviderError) as exc_info:
            lookup_provider("meta.llama")
        assert exc_info.value.provider_id == "meta.llama"

    def test_banned_firebase_raises(self):
        with pytest.raises(BannedProviderError):
            lookup_provider("firebase.genai")

    def test_banned_vertex_raises(self):
        with pytest.raises(BannedProviderError):
            lookup_provider("vertex.ai")

    def test_all_known_banned_providers_raise(self):
        for banned_id in KNOWN_BANNED_PROVIDERS:
            with pytest.raises(BannedProviderError):
                lookup_provider(banned_id)

    def test_unknown_provider_raises_registry_not_found(self):
        with pytest.raises(RegistryNotFoundError):
            lookup_provider("unknown.provider")

    def test_banned_error_carries_provider_id(self):
        with pytest.raises(BannedProviderError) as exc_info:
            lookup_provider("google.something")
        assert "google.something" in str(exc_info.value)

    def test_banned_prefixes_cover_correct_roots(self):
        assert "google." in BANNED_PROVIDER_PREFIXES
        assert "meta." in BANNED_PROVIDER_PREFIXES
        assert "firebase." in BANNED_PROVIDER_PREFIXES
        assert "vertex." in BANNED_PROVIDER_PREFIXES

    def test_memory_file_uses_underscores_not_dots(self):
        entry = PROVIDER_REGISTRY[ProviderID.XAI_GROK]
        assert "." not in entry.dedicated_memory_file.name.replace(".json", "")


# ---------------------------------------------------------------------------
# Layer 2: Per-Provider Memory Store
# ---------------------------------------------------------------------------

class TestProviderMemoryStore:
    def test_file_does_not_exist_initially(self, root_of_trust, tmp_store_dir):
        store = ProviderMemoryStore("xai.grok", root_of_trust, base_dir=tmp_store_dir)
        assert not store.file_exists()

    def test_read_empty_returns_empty_list(self, root_of_trust, tmp_store_dir):
        store = ProviderMemoryStore("xai.grok", root_of_trust, base_dir=tmp_store_dir)
        records = store.read_records("xai.grok")
        assert records == []

    def test_write_and_read_back(self, root_of_trust, tmp_store_dir):
        store = ProviderMemoryStore("xai.grok", root_of_trust, base_dir=tmp_store_dir)
        record = MemoryRecord(
            record_id="r001",
            model_id="xai.grok",
            content="test content",
        )
        store.write_records([record])
        assert store.file_exists()
        records = store.read_records("xai.grok")
        assert len(records) == 1
        assert records[0].record_id == "r001"
        assert records[0].content == "test content"

    def test_file_is_not_plaintext_json(self, root_of_trust, tmp_store_dir):
        """Verify the file is actually encrypted (not plaintext JSON)."""
        store = ProviderMemoryStore("xai.grok", root_of_trust, base_dir=tmp_store_dir)
        record = MemoryRecord(record_id="r001", model_id="xai.grok", content="secret")
        store.write_records([record])
        raw = store.file_path.read_bytes()
        with pytest.raises((json.JSONDecodeError, UnicodeDecodeError)):
            json.loads(raw.decode("utf-8"))

    def test_consent_owner_can_read_own_record(self, root_of_trust, tmp_store_dir):
        store = ProviderMemoryStore("xai.grok", root_of_trust, base_dir=tmp_store_dir)
        record = MemoryRecord(
            record_id="r001", model_id="xai.grok", content="owned", consent=[]
        )
        store.write_records([record])
        records = store.read_records("xai.grok")
        assert len(records) == 1

    def test_consent_denied_cross_provider_returns_empty(self, root_of_trust, tmp_store_dir):
        """A record owned by xai.grok is not returned when openai.gpt reads it."""
        store = ProviderMemoryStore("xai.grok", root_of_trust, base_dir=tmp_store_dir)
        record = MemoryRecord(
            record_id="r001", model_id="xai.grok", content="private", consent=[]
        )
        store.write_records([record])
        accessible = store.read_records("openai.gpt")
        assert accessible == []

    def test_explicit_consent_allows_cross_provider_read(self, root_of_trust, tmp_store_dir):
        store = ProviderMemoryStore("xai.grok", root_of_trust, base_dir=tmp_store_dir)
        record = MemoryRecord(
            record_id="r001",
            model_id="xai.grok",
            content="shared",
            consent=["openai.gpt"],
        )
        store.write_records([record])
        accessible = store.read_records("openai.gpt")
        assert len(accessible) == 1
        assert accessible[0].record_id == "r001"

    def test_read_record_strict_raises_on_missing_consent(self, root_of_trust, tmp_store_dir):
        store = ProviderMemoryStore("xai.grok", root_of_trust, base_dir=tmp_store_dir)
        record = MemoryRecord(record_id="r001", model_id="xai.grok", content="private")
        store.write_records([record])
        with pytest.raises(MemoryConsentDeniedError):
            store.read_record_strict("r001", "anthropic.claude")

    def test_read_record_strict_raises_on_missing_id(self, root_of_trust, tmp_store_dir):
        store = ProviderMemoryStore("xai.grok", root_of_trust, base_dir=tmp_store_dir)
        store.write_records([])
        with pytest.raises(KeyError):
            store.read_record_strict("nonexistent", "xai.grok")

    def test_append_adds_to_existing(self, root_of_trust, tmp_store_dir):
        store = ProviderMemoryStore("xai.grok", root_of_trust, base_dir=tmp_store_dir)
        r1 = MemoryRecord(record_id="r001", model_id="xai.grok", content="first")
        r2 = MemoryRecord(record_id="r002", model_id="xai.grok", content="second")
        store.write_records([r1])
        store.append_record(r2)
        records = store.read_records("xai.grok")
        assert len(records) == 2
        ids = {r.record_id for r in records}
        assert ids == {"r001", "r002"}

    def test_wrong_key_raises_decrypt_error(self, tmp_store_dir):
        """Writing with one key and reading with another raises MemoryDecryptError."""
        rot1 = RootOfTrust(SoftwareTrustBackend())
        rot2 = RootOfTrust(SoftwareTrustBackend())
        store1 = ProviderMemoryStore("xai.grok", rot1, base_dir=tmp_store_dir)
        store2 = ProviderMemoryStore("xai.grok", rot2, base_dir=tmp_store_dir)
        record = MemoryRecord(record_id="r001", model_id="xai.grok", content="locked")
        store1.write_records([record])
        with pytest.raises(MemoryDecryptError):
            store2.read_records("xai.grok")

    def test_atomic_write_leaves_no_tmp_file(self, root_of_trust, tmp_store_dir):
        store = ProviderMemoryStore("xai.grok", root_of_trust, base_dir=tmp_store_dir)
        record = MemoryRecord(record_id="r001", model_id="xai.grok", content="atomic")
        store.write_records([record])
        tmp_file = Path(str(store.file_path) + ".tmp")
        assert not tmp_file.exists()

    def test_different_providers_use_separate_files(self, root_of_trust, tmp_store_dir):
        store_xai = ProviderMemoryStore("xai.grok", root_of_trust, base_dir=tmp_store_dir)
        store_oai = ProviderMemoryStore("openai.gpt", root_of_trust, base_dir=tmp_store_dir)
        assert store_xai.file_path != store_oai.file_path

    def test_memory_file_path_uses_underscores(self, root_of_trust, tmp_store_dir):
        store = ProviderMemoryStore("xai.grok", root_of_trust, base_dir=tmp_store_dir)
        assert "xai_grok" in store.file_path.name


# ---------------------------------------------------------------------------
# Layer 3: Provider Drivers — key-missing path
# ---------------------------------------------------------------------------

class TestGrokProviderKeyMissing:
    def test_raises_provider_config_error(self, authorized_packet, tmp_path):
        from sia.providers.xai import GrokProvider
        provider = GrokProvider(key_file=tmp_path / "nokey.key")
        with pytest.raises(ProviderConfigError) as exc_info:
            provider.execute(authorized_packet)
        assert exc_info.value.provider_id == "xai.grok"
        assert "[REAL DRIVER" in str(exc_info.value)

    def test_provider_id_is_correct(self):
        from sia.providers.xai import GrokProvider
        assert GrokProvider().provider_id == "xai.grok"

    def test_rejects_unauthorized_packet(self, tmp_path):
        from sia.providers.xai import GrokProvider
        bad_packet = AuthorizedContextPacket(
            packet_id="p1", provider_id="xai.grok", owner_identity="u",
            capability_id=None, operation="CALL_PROVIDER", policy_hash="h",
            memory_context=(), authorized=False,
        )
        provider = GrokProvider(key_file=tmp_path / "nokey.key")
        with pytest.raises(ValueError, match="authorized context packet"):
            provider.execute(bad_packet)


class TestOpenAIProviderKeyMissing:
    def test_raises_provider_config_error(self, authorized_packet, tmp_path):
        from sia.providers.openai import OpenAIProvider
        provider = OpenAIProvider(key_file=tmp_path / "nokey.key")
        with pytest.raises(ProviderConfigError) as exc_info:
            provider.execute(
                AuthorizedContextPacket(
                    packet_id="p", provider_id="openai.gpt", owner_identity="u",
                    capability_id=None, operation="CALL_PROVIDER", policy_hash="h",
                    memory_context=(), metadata={"prompt": "hi"}, authorized=True,
                )
            )
        assert exc_info.value.provider_id == "openai.gpt"

    def test_provider_id_is_correct(self):
        from sia.providers.openai import OpenAIProvider
        assert OpenAIProvider().provider_id == "openai.gpt"


class TestAnthropicProviderKeyMissing:
    def test_raises_provider_config_error(self, tmp_path):
        from sia.providers.anthropic import AnthropicProvider
        provider = AnthropicProvider(key_file=tmp_path / "nokey.key")
        with pytest.raises(ProviderConfigError) as exc_info:
            provider.execute(
                AuthorizedContextPacket(
                    packet_id="p", provider_id="anthropic.claude", owner_identity="u",
                    capability_id=None, operation="CALL_PROVIDER", policy_hash="h",
                    memory_context=(), metadata={"prompt": "hi"}, authorized=True,
                )
            )
        assert exc_info.value.provider_id == "anthropic.claude"

    def test_provider_id_is_correct(self):
        from sia.providers.anthropic import AnthropicProvider
        assert AnthropicProvider().provider_id == "anthropic.claude"


class TestCopilotProviderKeyMissing:
    def test_raises_provider_config_error(self, tmp_path):
        from sia.providers.copilot import CopilotProvider
        provider = CopilotProvider(key_file=tmp_path / "nokey.key")
        with pytest.raises(ProviderConfigError) as exc_info:
            provider.execute(
                AuthorizedContextPacket(
                    packet_id="p", provider_id="github.copilot", owner_identity="u",
                    capability_id=None, operation="CALL_PROVIDER", policy_hash="h",
                    memory_context=(), metadata={"prompt": "hi"}, authorized=True,
                )
            )
        assert exc_info.value.provider_id == "github.copilot"

    def test_provider_id_is_correct(self):
        from sia.providers.copilot import CopilotProvider
        assert CopilotProvider().provider_id == "github.copilot"


# ---------------------------------------------------------------------------
# Driver HTTP-error path (key present, server returns error)
# ---------------------------------------------------------------------------

class TestGrokProviderHTTPError:
    def test_http_error_raises_provider_call_error(self, authorized_packet, tmp_path):
        import urllib.error
        from sia.providers.xai import GrokProvider

        key_file = tmp_path / "xai.grok.key"
        key_file.write_text("sk-test-key")

        http_err = urllib.error.HTTPError(
            url=None, code=401, msg="Unauthorized", hdrs=None, fp=None
        )
        provider = GrokProvider(key_file=key_file)
        with patch("urllib.request.urlopen", side_effect=http_err):
            with pytest.raises(ProviderCallError) as exc_info:
                provider.execute(authorized_packet)
        assert exc_info.value.provider_id == "xai.grok"
        assert exc_info.value.status == 401

    def test_network_error_raises_provider_call_error(self, authorized_packet, tmp_path):
        import urllib.error
        from sia.providers.xai import GrokProvider

        key_file = tmp_path / "xai.grok.key"
        key_file.write_text("sk-test-key")

        provider = GrokProvider(key_file=key_file)
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("no route")):
            with pytest.raises(ProviderCallError):
                provider.execute(authorized_packet)


class TestAnthropicProviderHTTPError:
    def test_http_error_raises_provider_call_error(self, tmp_path):
        import urllib.error
        from sia.providers.anthropic import AnthropicProvider

        key_file = tmp_path / "anthropic.claude.key"
        key_file.write_text("sk-ant-test")

        packet = AuthorizedContextPacket(
            packet_id="p", provider_id="anthropic.claude", owner_identity="u",
            capability_id=None, operation="CALL_PROVIDER", policy_hash="h",
            memory_context=(), metadata={"prompt": "hi"}, authorized=True,
        )
        http_err = urllib.error.HTTPError(
            url=None, code=403, msg="Forbidden", hdrs=None, fp=None
        )
        provider = AnthropicProvider(key_file=key_file)
        with patch("urllib.request.urlopen", side_effect=http_err):
            with pytest.raises(ProviderCallError) as exc_info:
                provider.execute(packet)
        assert exc_info.value.status == 403


# ---------------------------------------------------------------------------
# BannedProviderError and ProviderConfigError — exception surface
# ---------------------------------------------------------------------------

class TestProviderExceptions:
    def test_banned_provider_error_code(self):
        from sia.errors import codes
        err = BannedProviderError("google.gemini")
        assert err.code == codes.E_BANNED_PROVIDER
        assert "google.gemini" in str(err)

    def test_provider_config_error_code(self):
        from sia.errors import codes
        err = ProviderConfigError("xai.grok")
        assert err.code == codes.E_PROVIDER_CONFIG

    def test_provider_call_error_code(self):
        from sia.errors import codes
        err = ProviderCallError("xai.grok", status=500)
        assert err.code == codes.E_PROVIDER_CALL_FAILED
        assert err.status == 500

"""
SBP Branch primitive.

A Branch is a cryptographic namespace derived from a Root Authority.  It
carries:

- A deterministic branch identity derived from its inputs (so the same
  inputs always produce the same ``branch_id``).
- Parent lineage linking the branch to its root and, optionally, a parent
  branch.
- Owner reference (typically the Root ``root_id``).
- An explicit capability set limiting what operations actors may perform
  within this branch.
- A policy hash committing to the branch-level policy document.
- A creation timestamp.
- Branch-scoped key material derived from root-controlled material via a
  one-way KDF (``RootAuthority.derive_branch_key``).

Sibling-branch isolation
------------------------
Each branch derivation encodes the unique ``branch_id`` in the KDF context,
so two sibling branches derived from the same root cannot recover each
other's key material:

    branch_A_key = derive(root_secret, "SBP_BRANCH_KEY:" + branch_A_id)
    branch_B_key = derive(root_secret, "SBP_BRANCH_KEY:" + branch_B_id)

Neither key can be recovered from the other without access to root secret
material.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from sia.utils.canonical import canonical_bytes
from sbp.root import RootAuthority


# ── Capability vocabulary ─────────────────────────────────────────────────────

class BranchCapability(StrEnum):
    """
    Capabilities that may be granted to actors operating within a Branch.

    A branch with an empty capability set is valid but unusable; callers
    should populate at least one capability for a functional branch.
    """

    READ = "READ"
    WRITE = "WRITE"
    APPEND_AUDIT = "APPEND_AUDIT"
    ISSUE_OBJECT = "ISSUE_OBJECT"
    DELEGATE = "DELEGATE"
    ADMIN = "ADMIN"


# ── Public data structures ────────────────────────────────────────────────────

@dataclass(frozen=True)
class BranchMetadata:
    """
    Public, serializable metadata for a Branch.

    Invariants
    ----------
    - ``branch_id`` is deterministic: the same inputs always produce the
      same value.
    - ``root_id`` links this branch to its Root Authority.
    - ``parent_branch_id`` is ``None`` for first-generation branches.
    - ``capabilities`` is a sorted tuple so the representation is stable.
    """

    branch_id: str
    root_id: str
    parent_branch_id: str | None
    owner_id: str
    capabilities: tuple[str, ...]
    policy_hash: str
    created_at: int
    label: str
    version: int = 1

    def to_dict(self) -> dict[str, Any]:
        """Return a serializable branch metadata document."""
        return {
            "version": self.version,
            "branch_id": self.branch_id,
            "root_id": self.root_id,
            "parent_branch_id": self.parent_branch_id,
            "owner_id": self.owner_id,
            "capabilities": list(self.capabilities),
            "policy_hash": self.policy_hash,
            "created_at": self.created_at,
            "label": self.label,
        }


class Branch:
    """
    SBP Branch: cryptographic namespace derived from a Root Authority.

    Parameters
    ----------
    root:
        The ``RootAuthority`` that anchors this branch.
    label:
        A human-readable name for the branch (not used in identity derivation).
    capabilities:
        An explicit list of ``BranchCapability`` values permitted in this branch.
    parent_branch_id:
        The ``branch_id`` of the parent branch, or ``None`` for a root-level
        branch.
    policy:
        An optional policy document.  When omitted the default branch policy
        is used.
    created_at:
        Creation timestamp (Unix seconds, UTC).  Defaults to ``time.time()``.
    """

    def __init__(
        self,
        root: RootAuthority,
        *,
        label: str,
        capabilities: list[BranchCapability | str],
        parent_branch_id: str | None = None,
        policy: dict[str, Any] | None = None,
        created_at: int | None = None,
    ) -> None:
        self._root = root
        self._label = label
        self._capabilities: tuple[str, ...] = tuple(
            sorted(str(c) for c in capabilities)
        )
        self._parent_branch_id = parent_branch_id
        self._created_at = created_at if created_at is not None else int(time.time())
        self._policy = policy if policy is not None else _default_branch_policy()
        self._metadata = self._build_metadata()

    # ── Public interface ──────────────────────────────────────────────────────

    @property
    def metadata(self) -> BranchMetadata:
        """Return the public, serializable Branch metadata."""
        return self._metadata

    def derive_key(self, *, length: int = 32) -> bytes:
        """
        Derive branch-scoped key material from the root.

        Sibling branches have distinct key material because each derivation
        uses this branch's unique ``branch_id`` as the KDF context seed.
        The returned bytes are caller-controlled and are never stored.
        """
        return self._root.derive_branch_key(self._metadata.branch_id, length=length)

    def has_capability(self, cap: BranchCapability | str) -> bool:
        """Return whether *cap* is granted in this branch."""
        return str(cap) in self._metadata.capabilities

    # ── Private helpers ───────────────────────────────────────────────────────

    def _build_metadata(self) -> BranchMetadata:
        root_meta = self._root.metadata
        identity_doc = {
            "root_id": root_meta.root_id,
            "parent_branch_id": self._parent_branch_id,
            "owner_id": root_meta.root_id,
            "capabilities": list(self._capabilities),
            "policy_hash": _hash_policy(self._policy),
            "created_at": self._created_at,
            "label": self._label,
        }
        branch_id = hashlib.sha3_512(
            b"SBP_BRANCH_ID:" + canonical_bytes(identity_doc)
        ).hexdigest()

        return BranchMetadata(
            branch_id=branch_id,
            root_id=root_meta.root_id,
            parent_branch_id=self._parent_branch_id,
            owner_id=root_meta.root_id,
            capabilities=self._capabilities,
            policy_hash=identity_doc["policy_hash"],
            created_at=self._created_at,
            label=self._label,
        )


# ── Internal helpers ──────────────────────────────────────────────────────────


def _default_branch_policy() -> dict[str, Any]:
    """Return the minimal default branch policy document."""
    return {
        "version": 1,
        "type": "branch-default",
        "inherits_root": True,
    }


def _hash_policy(policy: dict[str, Any]) -> str:
    """Return the SHA3-512 hex digest of a canonical policy document."""
    return hashlib.sha3_512(canonical_bytes(policy)).hexdigest()

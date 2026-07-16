"""
SBP append-only audit entry foundation.

Provides an honest, hash-chained audit log suitable for later Merkle
verification.  Every entry is:

- Assigned a monotonically increasing sequence number.
- Timestamped (UTC ISO-8601).
- Linked to a branch and an actor.
- Committed to an action string and an optional object hash.
- Chained via ``previous_hash`` (genesis sentinel for sequence 0).
- Signed with the Root Authority's private material (real Ed25519 signature).
- Hashed deterministically so the chain cannot be silently modified.

There are no fake signatures and no simulated production flows.  The
``AuditChain.append`` method calls ``root.sign()`` with real root private
material and stores the resulting hex signature.

The chain can be verified offline without network access.

Chain structure
---------------
    genesis_hash = "0" * 128        # sentinel for the first entry

    entry_hash = SHA3-512(
        canonical_bytes({...signing_document..., "signature": sig_hex})
    )

    entry[n].previous_hash == entry[n-1].entry_hash  (for n > 0)
    entry[0].previous_hash == GENESIS_HASH
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sia.utils.canonical import canonical_bytes
from sbp.root import RootAuthority


# ── Constants ─────────────────────────────────────────────────────────────────

GENESIS_HASH: str = "0" * 128  # 128 hex chars = SHA3-512 zero sentinel


# ── Audit entry ───────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class AuditEntry:
    """
    A single signed, hash-chained SBP audit entry.

    Fields match the problem specification exactly:
    sequence, timestamp, branch_id, actor_id, action, object_id,
    metadata_hash, previous_hash, signature, entry_hash.
    """

    sequence: int
    entry_id: str
    timestamp: str           # UTC ISO-8601 with trailing Z
    branch_id: str
    actor_id: str
    action: str
    object_id: str | None    # object manifest ID, or None if not object-bound
    metadata_hash: str | None  # SHA3-512 of additional metadata, or None
    previous_hash: str       # SHA3-512 hex of the previous entry (or genesis)
    signature: str           # Ed25519 signature hex (real, not fake)
    entry_hash: str          # SHA3-512 of the complete signed record

    def signing_document(self) -> dict[str, Any]:
        """Return the canonical fields protected by the signature."""
        return {
            "sequence": self.sequence,
            "entry_id": self.entry_id,
            "timestamp": self.timestamp,
            "branch_id": self.branch_id,
            "actor_id": self.actor_id,
            "action": self.action,
            "object_id": self.object_id,
            "metadata_hash": self.metadata_hash,
            "previous_hash": self.previous_hash,
        }

    def to_dict(self) -> dict[str, Any]:
        """Return the complete serializable audit record."""
        return {
            **self.signing_document(),
            "signature": self.signature,
            "entry_hash": self.entry_hash,
        }


# ── Audit chain ───────────────────────────────────────────────────────────────

class AuditChainError(RuntimeError):
    """Raised when an audit chain invariant is violated."""


class AuditChain:
    """
    In-memory, append-only SBP audit chain for one branch.

    Parameters
    ----------
    branch_id:
        The branch this chain belongs to.
    root:
        The ``RootAuthority`` whose private material signs each entry.
    """

    def __init__(self, *, branch_id: str, root: RootAuthority) -> None:
        if not branch_id:
            raise ValueError("AuditChain requires a non-empty branch_id")
        self._branch_id = branch_id
        self._root = root
        self._entries: list[AuditEntry] = []

    @property
    def branch_id(self) -> str:
        return self._branch_id

    @property
    def entries(self) -> tuple[AuditEntry, ...]:
        """Return an immutable snapshot of append-ordered entries."""
        return tuple(self._entries)

    def append(
        self,
        *,
        actor_id: str,
        action: str,
        object_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        timestamp: str | None = None,
    ) -> AuditEntry:
        """
        Append a signed, hash-chained audit entry.

        Parameters
        ----------
        actor_id:
            Identifier of the actor performing the action (e.g. a root_id or
            branch actor string).
        action:
            A short action string (e.g. ``"OBJECT_ISSUED"``, ``"BRANCH_CREATED"``).
        object_id:
            Optional object manifest ID this entry relates to.
        metadata:
            Optional additional metadata dict.  Its SHA3-512 hash is stored;
            plaintext metadata is not retained in the chain.
        timestamp:
            Optional UTC ISO-8601 timestamp.  Defaults to ``time.time()``.
        """
        if not action:
            raise ValueError("AuditChain.append requires a non-empty action")

        sequence = len(self._entries)
        previous_hash = (
            self._entries[-1].entry_hash if self._entries else GENESIS_HASH
        )
        ts = timestamp or _utc_timestamp()
        metadata_hash: str | None = None
        if metadata is not None:
            metadata_hash = hashlib.sha3_512(
                canonical_bytes(metadata)
            ).hexdigest()

        signing_doc: dict[str, Any] = {
            "sequence": sequence,
            "entry_id": str(uuid4()),
            "timestamp": ts,
            "branch_id": self._branch_id,
            "actor_id": actor_id,
            "action": action,
            "object_id": object_id,
            "metadata_hash": metadata_hash,
            "previous_hash": previous_hash,
        }
        signature = self._root.sign(canonical_bytes(signing_doc))
        entry_hash = _hash_entry(signing_doc, signature)

        entry = AuditEntry(
            sequence=sequence,
            entry_id=signing_doc["entry_id"],
            timestamp=ts,
            branch_id=self._branch_id,
            actor_id=actor_id,
            action=action,
            object_id=object_id,
            metadata_hash=metadata_hash,
            previous_hash=previous_hash,
            signature=signature,
            entry_hash=entry_hash,
        )
        self._entries.append(entry)
        return entry

    def verify_integrity(self) -> bool:
        """
        Return ``True`` iff the chain hash-links and signatures all verify.

        Uses ``root.verify()`` (real Ed25519 verification) for every entry.
        """
        expected_previous = GENESIS_HASH
        for sequence, entry in enumerate(self._entries):
            if entry.sequence != sequence:
                return False
            if entry.branch_id != self._branch_id:
                return False
            if entry.previous_hash != expected_previous:
                return False
            doc = entry.signing_document()
            if not self._root.verify(canonical_bytes(doc), entry.signature):
                return False
            if entry.entry_hash != _hash_entry(doc, entry.signature):
                return False
            expected_previous = entry.entry_hash
        return True

    def export_bundle(self) -> dict[str, Any]:
        """Export a non-secret, auditable bundle of the chain."""
        return {
            "format": "SBP-AUDIT-BUNDLE-0.1",
            "branch_id": self._branch_id,
            "root_id": self._root.metadata.root_id,
            "entry_count": len(self._entries),
            "entries": [entry.to_dict() for entry in self._entries],
        }


# ── Internal helpers ──────────────────────────────────────────────────────────


def _utc_timestamp() -> str:
    """Return a canonical UTC timestamp."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _hash_entry(signing_doc: dict[str, Any], signature: str) -> str:
    """Hash the complete signed entry for chain linkage."""
    return hashlib.sha3_512(
        canonical_bytes({**signing_doc, "signature": signature})
    ).hexdigest()

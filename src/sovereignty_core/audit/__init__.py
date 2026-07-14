"""SAMA RFC-001 — SCAR Merkle audit package."""

from sovereignty_core.audit.merkle import (
    MerkleError,
    MerkleProof,
    MerkleTree,
    build_merkle_from_audit_ledger,
    build_merkle_from_scarlog,
    canonicalize,
    generate_proof,
    hash_entry,
    hash_pair,
    verify_merkle_proof,
)

__all__ = [
    "MerkleError",
    "MerkleProof",
    "MerkleTree",
    "build_merkle_from_audit_ledger",
    "build_merkle_from_scarlog",
    "canonicalize",
    "generate_proof",
    "hash_entry",
    "hash_pair",
    "verify_merkle_proof",
]

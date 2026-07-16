"""Versioned, portable authenticated-encryption envelopes for cloud egress.

This module performs no network I/O.  A caller must explicitly seal data
before sending it to storage or a recipient that can decrypt this format.
"""
from __future__ import annotations

import base64
import binascii
import secrets
from dataclasses import dataclass
from typing import Any, Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from sia.utils.canonical import canonical_bytes, canonical_json

_SCHEMA = "sia.cloud-egress.v1"
_KDF = "scrypt"
_CIPHER = "aes-256-gcm"
_SALT_BYTES = 16
_NONCE_BYTES = 12
_KEY_BYTES = 32
_SCRYPT_N = 2**15
_SCRYPT_R = 8
_SCRYPT_P = 1
_AAD_FIELDS = ("schema", "kdf", "cipher", "recipient_id", "content_type")


class EgressEnvelopeError(ValueError):
    """Raised for malformed, tampered, or undecryptable egress envelopes."""


@dataclass(frozen=True)
class CloudEgressEnvelope:
    """A JSON-serializable envelope shared across language implementations.

    The recipient identifier and content type are authenticated as AES-GCM
    additional authenticated data.  They are deliberately visible so routing
    does not require decryption; payload bytes and the passphrase never appear
    in the envelope.
    """

    schema: str
    kdf: str
    cipher: str
    recipient_id: str
    content_type: str
    salt: str
    nonce: str
    ciphertext: str

    @classmethod
    def seal(
        cls,
        plaintext: bytes,
        *,
        passphrase: str,
        recipient_id: str,
        content_type: str = "application/octet-stream",
    ) -> "CloudEgressEnvelope":
        """Encrypt bytes for explicit egress with a user-supplied shared secret."""
        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")
        if not isinstance(passphrase, str) or not passphrase:
            raise ValueError("passphrase must be a non-empty string")
        if not recipient_id:
            raise ValueError("recipient_id is required")
        if not content_type:
            raise ValueError("content_type is required")

        salt = secrets.token_bytes(_SALT_BYTES)
        nonce = secrets.token_bytes(_NONCE_BYTES)
        header = {
            "schema": _SCHEMA,
            "kdf": _KDF,
            "cipher": _CIPHER,
            "recipient_id": recipient_id,
            "content_type": content_type,
        }
        ciphertext = AESGCM(cls._derive_key(passphrase, salt)).encrypt(
            nonce, plaintext, canonical_bytes(header)
        )
        return cls(
            **header,
            salt=_b64encode(salt),
            nonce=_b64encode(nonce),
            ciphertext=_b64encode(ciphertext),
        )

    def open(self, *, passphrase: str, recipient_id: str) -> bytes:
        """Authenticate metadata and decrypt the payload for its recipient."""
        if recipient_id != self.recipient_id:
            raise EgressEnvelopeError("Envelope recipient does not match")
        try:
            salt = _b64decode(self.salt, "salt")
            nonce = _b64decode(self.nonce, "nonce")
            ciphertext = _b64decode(self.ciphertext, "ciphertext")
        except ValueError as exc:
            raise EgressEnvelopeError("Envelope encoding is invalid") from exc
        if len(salt) != _SALT_BYTES or len(nonce) != _NONCE_BYTES or not ciphertext:
            raise EgressEnvelopeError("Envelope parameters are invalid")
        try:
            return AESGCM(self._derive_key(passphrase, salt)).decrypt(
                nonce, ciphertext, canonical_bytes(self._authenticated_header())
            )
        except (InvalidTag, ValueError) as exc:
            raise EgressEnvelopeError(
                "Envelope authentication failed or passphrase is incorrect"
            ) from exc

    def to_dict(self) -> dict[str, str]:
        """Return the portable JSON envelope object."""
        return {
            "schema": self.schema,
            "kdf": self.kdf,
            "cipher": self.cipher,
            "recipient_id": self.recipient_id,
            "content_type": self.content_type,
            "salt": self.salt,
            "nonce": self.nonce,
            "ciphertext": self.ciphertext,
        }

    def to_json(self) -> str:
        """Return canonical JSON suitable for storage or transmission."""
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CloudEgressEnvelope":
        """Validate and construct a portable envelope from decoded JSON."""
        expected = {
            "schema", "kdf", "cipher", "recipient_id", "content_type",
            "salt", "nonce", "ciphertext",
        }
        if set(value) != expected or any(not isinstance(value[key], str) for key in expected):
            raise EgressEnvelopeError("Envelope schema is invalid")
        envelope = cls(**{key: value[key] for key in expected})
        if envelope.schema != _SCHEMA or envelope.kdf != _KDF or envelope.cipher != _CIPHER:
            raise EgressEnvelopeError("Envelope algorithm suite is not supported")
        return envelope

    def _authenticated_header(self) -> dict[str, str]:
        return {key: getattr(self, key) for key in _AAD_FIELDS}

    @staticmethod
    def _derive_key(passphrase: str, salt: bytes) -> bytes:
        if not isinstance(passphrase, str) or not passphrase:
            raise ValueError("passphrase must be a non-empty string")
        return Scrypt(
            salt=salt,
            length=_KEY_BYTES,
            n=_SCRYPT_N,
            r=_SCRYPT_R,
            p=_SCRYPT_P,
        ).derive(passphrase.encode("utf-8"))


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _b64decode(value: str, name: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), altchars=b"-_", validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise ValueError(f"{name} is not URL-safe base64") from exc

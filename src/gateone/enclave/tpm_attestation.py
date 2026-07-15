"""TPM quote verification boundary backed by the local tpm2_checkquote utility."""
from __future__ import annotations

import base64
import hashlib
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class TPMQuote:
    """Opaque TPM2 quote artifacts emitted by a real TPM attestation flow."""

    quoted_b64: str
    signature_b64: str
    ak_public_b64: str
    pcr_values_b64: str
    pcr_selection: str


@dataclass(frozen=True)
class TPMVerification:
    """The outcome of local TPM quote verification."""

    verified: bool
    available: bool
    reason_code: str
    reason: str


class TPMQuoteVerifier:
    """Verify a TPM2 quote, nonce, PCR values, and pinned attestation key."""

    def __init__(self, *, executable: str = "tpm2_checkquote", timeout_seconds: int = 10) -> None:
        self._executable = executable
        self._timeout_seconds = timeout_seconds

    def verify(
        self,
        quote: TPMQuote,
        *,
        nonce: str,
        trusted_ak_hash: str,
    ) -> TPMVerification:
        """Verify quote artifacts using tpm2_checkquote; unavailable tooling quarantines."""
        if not nonce:
            return self._invalid("TPM_NONCE_MISSING", "TPM quote verification requires a nonce.")
        if not quote.pcr_selection:
            return self._invalid("TPM_PCR_SELECTION_MISSING", "TPM PCR selection is required.")
        try:
            quoted = base64.b64decode(quote.quoted_b64, validate=True)
            signature = base64.b64decode(quote.signature_b64, validate=True)
            ak_public = base64.b64decode(quote.ak_public_b64, validate=True)
            pcr_values = base64.b64decode(quote.pcr_values_b64, validate=True)
        except (TypeError, ValueError) as exc:
            return self._invalid("TPM_ARTIFACT_ENCODING_INVALID", f"TPM artifact is not valid base64: {exc}")
        if not quoted or not signature or not ak_public or not pcr_values:
            return self._invalid("TPM_ARTIFACT_EMPTY", "TPM quote artifacts must be non-empty.")
        if hashlib.sha3_512(ak_public).hexdigest() != trusted_ak_hash:
            return self._invalid(
                "TPM_AK_BINDING_INVALID",
                "TPM attestation key does not match the identity-bound trusted key.",
            )

        try:
            with tempfile.TemporaryDirectory(prefix="gateone-tpm-") as directory:
                root = Path(directory)
                quote_path = self._write(root / "quote.msg", quoted)
                signature_path = self._write(root / "quote.sig", signature)
                ak_public_path = self._write(root / "ak.pub", ak_public)
                pcr_values_path = self._write(root / "pcr.bin", pcr_values)
                command = [
                    self._executable,
                    "-u",
                    str(ak_public_path),
                    "-m",
                    str(quote_path),
                    "-s",
                    str(signature_path),
                    "-f",
                    str(pcr_values_path),
                    "-l",
                    quote.pcr_selection,
                    "-q",
                    nonce,
                ]
                completed = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=self._timeout_seconds,
                    check=False,
                )
        except FileNotFoundError:
            return TPMVerification(
                verified=False,
                available=False,
                reason_code="TPM_VERIFIER_UNAVAILABLE",
                reason="tpm2_checkquote is not installed; hardware attestation cannot be verified.",
            )
        except subprocess.TimeoutExpired:
            return self._invalid("TPM_VERIFICATION_TIMEOUT", "TPM quote verification timed out.")
        except OSError as exc:
            return self._invalid("TPM_VERIFICATION_ERROR", f"TPM quote verification failed closed: {exc}")

        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            return self._invalid(
                "TPM_QUOTE_INVALID",
                f"tpm2_checkquote rejected the TPM quote: {detail or 'no diagnostic output'}",
            )
        return TPMVerification(
            verified=True,
            available=True,
            reason_code="TPM_QUOTE_VERIFIED",
            reason="TPM quote, nonce, PCR values, and attestation key verified.",
        )

    @staticmethod
    def _write(path: Path, data: bytes) -> Path:
        path.write_bytes(data)
        os.chmod(path, 0o600)
        return path

    @staticmethod
    def _invalid(reason_code: str, reason: str) -> TPMVerification:
        return TPMVerification(False, True, reason_code, reason)

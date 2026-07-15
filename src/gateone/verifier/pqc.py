"""ML-DSA-87 verification through the local liboqs-python binding."""
from __future__ import annotations

import base64
from dataclasses import dataclass


@dataclass(frozen=True)
class PQCVerification:
    """The outcome of an ML-DSA-87 signature verification attempt."""

    verified: bool
    available: bool
    reason_code: str
    reason: str


class MLDSA87Verifier:
    """Verify ML-DSA-87 signatures without generating or handling private keys."""

    algorithm = "ML-DSA-87"

    def verify(
        self,
        *,
        payload: bytes,
        signature_b64: str,
        public_key_b64: str,
    ) -> PQCVerification:
        """Verify a base64-encoded ML-DSA-87 signature over canonical payload bytes."""
        try:
            signature = base64.b64decode(signature_b64, validate=True)
            public_key = base64.b64decode(public_key_b64, validate=True)
        except (TypeError, ValueError) as exc:
            return PQCVerification(
                verified=False,
                available=True,
                reason_code="PQC_ENCODING_INVALID",
                reason=f"ML-DSA-87 material is not valid base64: {exc}",
            )

        try:
            import oqs
        except ImportError:
            return PQCVerification(
                verified=False,
                available=False,
                reason_code="PQC_BACKEND_UNAVAILABLE",
                reason=(
                    "ML-DSA-87 verification requires the locally installed "
                    "liboqs-python backend; install the project's 'pqc' extra."
                ),
            )

        try:
            with oqs.Signature(self.algorithm) as verifier:
                verified = verifier.verify(payload, signature, public_key)
        except Exception as exc:
            return PQCVerification(
                verified=False,
                available=True,
                reason_code="PQC_VERIFICATION_ERROR",
                reason=f"ML-DSA-87 verification failed closed: {exc}",
            )

        if not verified:
            return PQCVerification(
                verified=False,
                available=True,
                reason_code="PQC_SIGNATURE_INVALID",
                reason="ML-DSA-87 signature verification failed.",
            )
        return PQCVerification(
            verified=True,
            available=True,
            reason_code="PQC_VERIFIED",
            reason="ML-DSA-87 signature verified.",
        )

"""Gate One integration layer for voice/text quota awareness."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from quota_manager import VoiceTextQuotaManager


@dataclass
class QuotaPrompt:
    title: str
    message: str
    can_proceed: bool
    guidance: list[str]


class GateOneQuotaIntegration:
    """Bridge between the UI and VoiceTextQuotaManager.

    Responsibilities:
    - estimate usage before sending a request
    - surface warning prompts when a request may exceed quota
    - record usage after a request completes
    - expose a compact status payload for the UI
    """

    def __init__(self, user_tier: str = "free") -> None:
        self.manager = VoiceTextQuotaManager(user_tier=user_tier)

    def preview_request(self, tokens: int, is_voice: bool = False) -> QuotaPrompt:
        estimate = self.manager.estimate_usage(tokens=tokens, is_voice=is_voice)
        if estimate["would_throttle"]:
            return QuotaPrompt(
                title="Quota warning",
                message=(
                    f"This request would exceed your {estimate['tier']} weekly quota. "
                    f"Used: {estimate['total_used']}/{self.manager.get_limits().total_tokens}."
                ),
                can_proceed=False,
                guidance=list(estimate["guidance"]),
            )

        return QuotaPrompt(
            title="Quota check passed",
            message=(
                f"Remaining quota: {estimate['remaining']} tokens. "
                f"Voice used: {estimate['voice_used']}, text used: {estimate['text_used']}."
            ),
            can_proceed=True,
            guidance=list(estimate["guidance"]),
        )

    def commit_request(self, tokens: int, is_voice: bool = False) -> Dict[str, Any]:
        return self.manager.record_usage(tokens=tokens, is_voice=is_voice)

    def status(self) -> Dict[str, Any]:
        return self.manager.get_status()

    def next_best_action(self) -> Optional[str]:
        status = self.manager.get_status()
        if status["remaining"] <= 0:
            return "wait_for_reset"
        if status["remaining"] < 2000:
            return "reduce_context"
        return None

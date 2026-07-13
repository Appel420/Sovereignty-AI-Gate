from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict


@dataclass
class TierLimits:
    voice_tokens: int
    text_tokens: int
    total_tokens: int
    can_bypass_throttle: bool
    guidance_options: list[str]


class VoiceTextQuotaManager:
    TIER_LIMITS = {
        "root": TierLimits(1_000_000, 1_000_000, 2_000_000, True, []),
        "admin": TierLimits(500_000, 500_000, 800_000, True, []),
        "developer": TierLimits(250_000, 250_000, 400_000, True, ["reduce_context", "split_request", "switch_mode"]),
        "supergrok": TierLimits(120_000, 120_000, 200_000, False, ["reduce_context", "switch_mode", "wait_for_reset"]),
        "paid": TierLimits(60_000, 60_000, 100_000, False, ["reduce_context", "wait_for_reset", "switch_mode"]),
        "free": TierLimits(25_000, 25_000, 40_000, False, ["reduce_context", "wait_for_reset", "switch_mode"]),
    }

    def __init__(self, user_tier: str = "free") -> None:
        self.tier = user_tier.lower()
        self.current_usage: Dict[str, int] = {"voice": 0, "text": 0, "total": 0}
        self.last_reset = datetime.now(timezone.utc)
        self.weekly_reset = self.last_reset + timedelta(days=7)

    def get_limits(self) -> TierLimits:
        return self.TIER_LIMITS.get(self.tier, self.TIER_LIMITS["free"])

    def _maybe_reset(self) -> None:
        if datetime.now(timezone.utc) >= self.weekly_reset:
            self.reset()

    def estimate_usage(self, tokens: int, is_voice: bool = False) -> Dict[str, Any]:
        self._maybe_reset()
        limits = self.get_limits()
        voice = self.current_usage["voice"] + (tokens if is_voice else 0)
        text = self.current_usage["text"] + (0 if is_voice else tokens)
        total = voice + text
        return {
            "tier": self.tier,
            "voice_used": voice,
            "text_used": text,
            "total_used": total,
            "remaining": limits.total_tokens - total,
            "would_throttle": total > limits.total_tokens,
            "can_bypass": limits.can_bypass_throttle,
            "guidance": limits.guidance_options,
        }

    def record_usage(self, tokens: int, is_voice: bool = False) -> Dict[str, Any]:
        self._maybe_reset()
        limits = self.get_limits()
        if is_voice:
            self.current_usage["voice"] += tokens
        else:
            self.current_usage["text"] += tokens
        self.current_usage["total"] = self.current_usage["voice"] + self.current_usage["text"]
        remaining = limits.total_tokens - self.current_usage["total"]
        if self.current_usage["total"] > limits.total_tokens:
            return {
                "status": "throttled",
                "tier": self.tier,
                "voice_used": self.current_usage["voice"],
                "text_used": self.current_usage["text"],
                "total_used": self.current_usage["total"],
                "remaining": remaining,
                "message": f"Shared weekly limit reached for {self.tier} tier.",
                "guidance": limits.guidance_options,
            }
        return {
            "status": "ok",
            "tier": self.tier,
            "voice_used": self.current_usage["voice"],
            "text_used": self.current_usage["text"],
            "total_used": self.current_usage["total"],
            "remaining": remaining,
            "can_bypass": limits.can_bypass_throttle,
        }

    def reset(self) -> None:
        self.current_usage = {"voice": 0, "text": 0, "total": 0}
        self.last_reset = datetime.now(timezone.utc)
        self.weekly_reset = self.last_reset + timedelta(days=7)

    def get_status(self) -> Dict[str, Any]:
        self._maybe_reset()
        limits = self.get_limits()
        return {
            "tier": self.tier,
            "voice_used": self.current_usage["voice"],
            "text_used": self.current_usage["text"],
            "total_used": self.current_usage["total"],
            "voice_limit": limits.voice_tokens,
            "text_limit": limits.text_tokens,
            "total_limit": limits.total_tokens,
            "remaining": limits.total_tokens - self.current_usage["total"],
            "can_bypass": limits.can_bypass_throttle,
            "guidance": limits.guidance_options,
            "weekly_reset": self.weekly_reset.isoformat(),
        }

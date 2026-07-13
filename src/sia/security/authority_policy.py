"""
Security: authority policy engine.

Policies are evaluated before any action is executed. The engine
accepts a policy definition dict and evaluates a request against it,
returning an allow/deny decision with an audit trail.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sia.errors.exceptions import PolicyDeniedError


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str
    matched_rule: str | None = None


class AuthorityPolicy:
    """
    Evaluates authority policy rules for a given context.

    Policy format (dict)::

        {
          "default": "deny",          # or "allow"
          "rules": [
            {
              "id": "r001",
              "match": {"action": "memory.read", "model_id": "*"},
              "effect": "allow"
            }
          ]
        }

    Rules are evaluated in order; the first match wins. If no rule
    matches, the default effect is applied.
    """

    def __init__(self, policy: dict[str, Any]) -> None:
        self._default: str = policy.get("default", "deny")
        self._rules: list[dict[str, Any]] = policy.get("rules", [])

    # ── Evaluation ────────────────────────────────────────────────────────────

    def evaluate(self, request: dict[str, Any]) -> PolicyDecision:
        """
        Evaluate *request* against this policy.

        Returns a :class:`PolicyDecision`. Does **not** raise on deny;
        callers that want an exception should call :meth:`enforce`.
        """
        for rule in self._rules:
            if self._matches(rule.get("match", {}), request):
                effect = rule.get("effect", "deny")
                return PolicyDecision(
                    allowed=(effect == "allow"),
                    reason=f"Matched rule '{rule.get('id', '?')}'",
                    matched_rule=rule.get("id"),
                )
        allowed = self._default == "allow"
        return PolicyDecision(
            allowed=allowed,
            reason=f"No matching rule; default is '{self._default}'",
        )

    def enforce(self, request: dict[str, Any]) -> None:
        """Evaluate *request* and raise :exc:`PolicyDeniedError` if denied."""
        decision = self.evaluate(request)
        if not decision.allowed:
            raise PolicyDeniedError(decision.reason)

    # ── Internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _matches(pattern: dict[str, Any], request: dict[str, Any]) -> bool:
        """Return True if all pattern fields match the corresponding
        request fields. ``"*"`` is a wildcard that matches anything."""
        for key, value in pattern.items():
            if value == "*":
                continue
            if request.get(key) != value:
                return False
        return True

    # ── Serialization ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        return {"default": self._default, "rules": list(self._rules)}

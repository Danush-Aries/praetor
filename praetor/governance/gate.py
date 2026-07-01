"""The policy gate — defense-in-depth enforcement for every action.

The gate is the single choke point through which every :class:`~praetor.models.Action`
must pass before execution. It re-checks authorization, scope, phase ceiling, and
destructive-action confirmation *in order*, so that the first (most fundamental)
failure wins and produces a clear human-readable reason.

The gate never raises: it always returns a :class:`GateDecision`.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from ..config import Scope, Settings
from ..models import Action


@dataclass
class GateDecision:
    """The verdict for a single action.

    Attributes:
        allowed: True if the action may execute.
        reason: A human-readable explanation, always non-empty.
    """

    allowed: bool
    reason: str


class Gate:
    """Evaluates actions against scope + settings policy."""

    def __init__(self, scope: Scope, settings: Settings) -> None:
        self.scope = scope
        self.settings = settings

    def evaluate(
        self,
        action: Action,
        confirm_fn: Optional[Callable[[Action], bool]] = None,
    ) -> GateDecision:
        """Approve or block an action. First failing check wins.

        Order of enforcement:
            a) engagement must be authorized;
            b) target (if any) must be in scope;
            c) phase must not exceed the scope's max_phase;
            d) destructive actions require allow_destructive, and (when
               settings.confirm_destructive) an affirmative confirm_fn;
            e) otherwise the action is allowed.
        """
        # a) authorization attestation
        if not self.scope.authorized:
            return GateDecision(
                False, "engagement not authorized (scope.authorized is false)"
            )

        # b) scope allowlist
        if action.target and not self.scope.is_in_scope(action.target):
            return GateDecision(
                False, f"target {action.target} is out of scope"
            )

        # c) phase ceiling
        if action.phase.rank > self.scope.max_phase.rank:
            return GateDecision(
                False,
                f"phase {action.phase.value} exceeds max_phase "
                f"{self.scope.max_phase.value}",
            )

        # d) destructive-action controls
        if action.destructive:
            if not self.scope.allow_destructive:
                return GateDecision(
                    False,
                    "destructive action blocked (allow_destructive is false)",
                )
            if self.settings.confirm_destructive:
                confirmed = bool(confirm_fn(action)) if confirm_fn else False
                if not confirmed:
                    return GateDecision(
                        False, "destructive action not confirmed"
                    )

        # e) all checks passed
        return GateDecision(True, "ok")

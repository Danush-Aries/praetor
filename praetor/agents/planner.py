"""Planners decide, per phase, which candidate actions to run (and in what order)
and whether to escalate to the next phase.

- DeterministicPlanner: runs every candidate in order, always escalates up to the
  scope's max phase. Fully offline, reproducible — the default.
- LLMPlanner: asks a model to prioritise candidate actions and to judge whether the
  findings so far justify escalation. Falls back to deterministic behaviour on any
  error or unparusable response, so it can never wedge the loop.
"""
from __future__ import annotations

import json
from typing import Optional, Protocol

from ..config import Settings
from ..models import Action, EngagementState, Phase
from .base import LLMClient, make_client

_SYSTEM = (
    "You are the planning core of PRAETOR, an AUTHORIZED penetration-testing "
    "orchestrator operating only against in-scope, permission-granted targets. "
    "You never invent new commands; you only order and select from the candidate "
    "actions given to you, and decide whether findings justify escalating to the "
    "next phase. Respond with strict JSON only."
)


class Planner(Protocol):
    name: str

    def prioritize(self, state: EngagementState, phase: Phase,
                   candidates: list[Action]) -> list[Action]: ...

    def should_escalate(self, state: EngagementState, next_phase: Phase) -> bool: ...


class DeterministicPlanner:
    name = "deterministic"

    def prioritize(self, state: EngagementState, phase: Phase,
                   candidates: list[Action]) -> list[Action]:
        return list(candidates)

    def should_escalate(self, state: EngagementState, next_phase: Phase) -> bool:
        return next_phase.rank <= state.max_phase.rank


class LLMPlanner:
    name = "llm"

    def __init__(self, client: LLMClient):
        self.client = client
        self._fallback = DeterministicPlanner()

    def prioritize(self, state: EngagementState, phase: Phase,
                   candidates: list[Action]) -> list[Action]:
        if not candidates:
            return []
        listing = "\n".join(
            f"[{i}] tool={a.tool} target={a.target} phase={a.phase.value} "
            f"destructive={a.destructive} :: {a.rationale}"
            for i, a in enumerate(candidates)
        )
        recent = [f.title for f in state.findings[-8:]]
        user = (
            f"Phase: {phase.value}\n"
            f"Findings so far: {json.dumps(recent)}\n"
            f"Candidate actions:\n{listing}\n\n"
            'Return JSON {"order": [<indices, best first, omit useless ones>]}.'
        )
        try:
            raw = self.client.complete(_SYSTEM, user)
            order = json.loads(_extract_json(raw))["order"]
            picked = [candidates[i] for i in order if isinstance(i, int) and 0 <= i < len(candidates)]
            return picked or list(candidates)
        except Exception:
            return self._fallback.prioritize(state, phase, candidates)

    def should_escalate(self, state: EngagementState, next_phase: Phase) -> bool:
        if next_phase.rank > state.max_phase.rank:
            return False
        summary = [
            {"title": f.title, "severity": f.severity.value, "phase": f.phase.value}
            for f in state.findings[-12:]
        ]
        user = (
            f"Findings so far: {json.dumps(summary)}\n"
            f"Proposed next phase: {next_phase.value}\n"
            'Do the findings justify advancing? Return JSON {"escalate": true|false}.'
        )
        try:
            raw = self.client.complete(_SYSTEM, user)
            return bool(json.loads(_extract_json(raw))["escalate"])
        except Exception:
            return self._fallback.should_escalate(state, next_phase)


def _extract_json(text: str) -> str:
    """Pull the first {...} block out of a model response."""
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError("no json object in response")
    return text[start:end + 1]


def make_planner(settings: Settings, client: Optional[LLMClient] = None) -> Planner:
    client = client if client is not None else make_client(settings)
    if client is None:
        return DeterministicPlanner()
    return LLMPlanner(client)

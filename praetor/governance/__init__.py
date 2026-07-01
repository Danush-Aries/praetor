"""Governance: the safety spine of PRAETOR.

Two responsibilities live here:

* :class:`~praetor.governance.audit.AuditLogger` — an append-only, crash-safe
  JSONL trail of everything the orchestrator did or was blocked from doing.
* :class:`~praetor.governance.gate.Gate` — the defense-in-depth policy gate that
  approves or blocks every :class:`~praetor.models.Action` against scope.
"""
from __future__ import annotations

from .audit import AuditLogger
from .gate import Gate, GateDecision

__all__ = ["AuditLogger", "Gate", "GateDecision"]

"""Append-only JSONL audit logger.

Every governance-relevant event — actions proposed, gate decisions, and
observations — is written as one JSON object per line. The log is the tamper-
evident record of an engagement, so it is written defensively:

* each event opens the file, appends, flushes, and closes (crash-safe);
* parent directories are created on demand;
* logging never raises — a broken audit sink must not abort a pentest.

Stdlib only (``json``, ``time``, ``pathlib``) to keep this dependency-free.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Union

from ..models import Action, Observation


class AuditLogger:
    """Append-only JSONL sink for governance events."""

    def __init__(self, path: Union[str, Path], engagement_id: str = "") -> None:
        self.path = Path(path)
        self.engagement_id = engagement_id
        self._ensure_parent()

    # --- internals --------------------------------------------------------
    def _ensure_parent(self) -> None:
        """Create the parent directory tree, swallowing any error."""
        try:
            parent = self.path.parent
            if parent and not parent.exists():
                parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

    # --- public API -------------------------------------------------------
    def event(self, kind: str, payload: dict) -> None:
        """Append one JSON line: ``{ts, engagement_id, kind, **payload}``.

        Never raises: any I/O or serialization failure is swallowed so that a
        failing audit sink can never crash the orchestrator.
        """
        record: dict[str, Any] = {
            "ts": time.time(),
            "engagement_id": self.engagement_id,
            "kind": kind,
        }
        if payload:
            record.update(payload)
        try:
            line = json.dumps(record, default=str)
        except (TypeError, ValueError):
            # Fall back to a stringified payload rather than losing the event.
            try:
                line = json.dumps(
                    {
                        "ts": record["ts"],
                        "engagement_id": self.engagement_id,
                        "kind": kind,
                        "payload_repr": repr(payload),
                    }
                )
            except (TypeError, ValueError):
                return
        try:
            self._ensure_parent()
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
        except OSError:
            # Swallow & continue — audit failures must not stop the engagement.
            return

    def action(self, action: Action) -> None:
        """Record a proposed action."""
        self.event("action", action.to_dict())

    def decision(self, action_id: str, allowed: bool, reason: str) -> None:
        """Record a gate decision for an action."""
        self.event(
            "decision",
            {"action_id": action_id, "allowed": allowed, "reason": reason},
        )

    def observation(self, obs: Observation) -> None:
        """Record the observation resulting from (or blocking) an action."""
        self.event("observation", obs.to_dict())

    def close(self) -> None:
        """No persistent handle is held; provided for lifecycle symmetry."""
        return

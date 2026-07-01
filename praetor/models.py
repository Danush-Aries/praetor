"""Core data contract for PRAETOR.

Every module (governance, tools, agents, blueteam, report) codes against the
types in this file. Keep it dependency-free (stdlib only) so it stays the stable
center of the package.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class Phase(str, Enum):
    """Ordered pentest phases. `rank` defines the mode-gate ordering."""
    RECON = "recon"
    SCAN = "scan"
    EXPLOIT = "exploit"
    LOOT = "loot"
    REPORT = "report"

    @property
    def rank(self) -> int:
        return {"recon": 0, "scan": 1, "exploit": 2, "loot": 3, "report": 4}[self.value]


class Mode(str, Enum):
    """Engagement mode. LAB permits the full autonomous exploit chain against
    intentionally-vulnerable targets; AUTHORIZED is conservative and scope-locked."""
    LAB = "lab"
    AUTHORIZED = "authorized"


@dataclass
class Target:
    """A single target. `raw` is what the user wrote; host/port are parsed."""
    raw: str
    host: str = ""
    port: Optional[int] = None
    scheme: Optional[str] = None  # http/https for web targets
    in_scope: bool = False
    labels: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.host:
            self.host = self.raw.split("://")[-1].split("/")[0].split(":")[0]


@dataclass
class Finding:
    """A single observed fact worth reporting."""
    title: str
    severity: Severity = Severity.INFO
    phase: Phase = Phase.RECON
    target: str = ""
    description: str = ""
    evidence: str = ""
    source_tool: str = ""
    cve: Optional[str] = None
    remediation: str = ""
    # Blue-team mirror: the detection artifact this activity would generate.
    detection: Optional["DetectionSignature"] = None
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: _new_id("find"))

    def to_dict(self) -> dict[str, Any]:
        d = {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "phase": self.phase.value,
            "target": self.target,
            "description": self.description,
            "evidence": self.evidence,
            "source_tool": self.source_tool,
            "cve": self.cve,
            "remediation": self.remediation,
            "metadata": self.metadata,
        }
        if self.detection is not None:
            d["detection"] = self.detection.to_dict()
        return d


@dataclass
class Action:
    """An action the orchestrator wants to take. Tools build these; the gate
    approves/blocks them; the runner executes them."""
    phase: Phase
    tool: str
    argv: list[str] = field(default_factory=list)  # command as argv list (no shell)
    target: str = ""
    rationale: str = ""
    destructive: bool = False  # submit/delete/pay/write-side-effect
    requires_confirmation: bool = False
    id: str = field(default_factory=lambda: _new_id("act"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "phase": self.phase.value,
            "tool": self.tool,
            "argv": self.argv,
            "target": self.target,
            "rationale": self.rationale,
            "destructive": self.destructive,
            "requires_confirmation": self.requires_confirmation,
        }


@dataclass
class Observation:
    """The result of executing (or blocking) an Action."""
    action_id: str
    ok: bool
    raw_output: str = ""
    findings: list[Finding] = field(default_factory=list)
    duration_s: float = 0.0
    error: Optional[str] = None
    blocked_reason: Optional[str] = None  # set when the gate/scope blocked it

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "ok": self.ok,
            "findings": [f.to_dict() for f in self.findings],
            "duration_s": round(self.duration_s, 3),
            "error": self.error,
            "blocked_reason": self.blocked_reason,
        }


@dataclass
class DetectionSignature:
    """Blue-team mirror of an offensive action — what a defender would see.

    This is PRAETOR's differentiator: every action can emit the log/alert it
    would trip, turning the tool into a detection-engineering teaching aid.
    """
    name: str
    description: str
    log_source: str = ""       # e.g. "zeek:conn", "auditd", "web:access"
    mitre_attack: list[str] = field(default_factory=list)  # e.g. ["T1046"]
    sigma_yaml: str = ""       # a minimal Sigma-style rule (string)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "log_source": self.log_source,
            "mitre_attack": self.mitre_attack,
            "sigma_yaml": self.sigma_yaml,
        }


@dataclass
class EngagementState:
    """Mutable state threaded through the orchestrator loop."""
    name: str
    mode: Mode
    max_phase: Phase = Phase.REPORT
    targets: list[Target] = field(default_factory=list)
    actions: list[Action] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: _new_id("eng"))

    def add_findings(self, findings: list[Finding]) -> None:
        self.findings.extend(findings)

    def findings_by_phase(self, phase: Phase) -> list[Finding]:
        return [f for f in self.findings if f.phase == phase]

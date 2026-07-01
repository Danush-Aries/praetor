"""Configuration + scope loading.

The scope file is the heart of PRAETOR's governance model: nothing runs against
a target unless that target matches the scope allowlist AND the engagement
carries an explicit authorization attestation.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from .models import Mode, Phase, Target


class ScopeError(Exception):
    """Raised when a scope file is missing required governance fields."""


@dataclass
class Scope:
    """Parsed scope.yaml. `authorized` must be explicitly true to run anything."""
    name: str
    mode: Mode
    authorized: bool
    allow_hosts: list[str] = field(default_factory=list)      # exact hostnames
    allow_domains: list[str] = field(default_factory=list)    # suffix match (sub.example.com)
    allow_cidrs: list[str] = field(default_factory=list)      # ip ranges
    deny_hosts: list[str] = field(default_factory=list)       # always-block, wins over allow
    max_phase: Phase = Phase.REPORT
    allow_destructive: bool = False
    targets: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    # --- scope evaluation -------------------------------------------------
    def is_in_scope(self, target: str) -> bool:
        host = _extract_host(target)
        if not host:
            return False
        if host in self.deny_hosts:
            return False
        if host in self.allow_hosts:
            return True
        for dom in self.allow_domains:
            d = dom.lstrip(".")
            if host == d or host.endswith("." + d):
                return True
        ip = _as_ip(host)
        if ip is not None:
            for cidr in self.allow_cidrs:
                try:
                    if ip in ipaddress.ip_network(cidr, strict=False):
                        return True
                except ValueError:
                    continue
        return False

    def parsed_targets(self) -> list[Target]:
        out: list[Target] = []
        for raw in self.targets:
            scheme = raw.split("://")[0] if "://" in raw else None
            t = Target(raw=raw, scheme=scheme)
            t.in_scope = self.is_in_scope(raw)
            out.append(t)
        return out


def _extract_host(target: str) -> str:
    return target.split("://")[-1].split("/")[0].split(":")[0].strip().lower()


def _as_ip(host: str) -> Optional[ipaddress._BaseAddress]:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def load_scope(path: str | Path) -> Scope:
    """Load and validate a scope file. Missing governance fields are hard errors."""
    p = Path(path)
    if not p.exists():
        raise ScopeError(f"scope file not found: {p}")
    data = yaml.safe_load(p.read_text()) or {}

    if "authorized" not in data:
        raise ScopeError(
            "scope file must contain `authorized: true` — an explicit attestation "
            "that you have permission to test the listed targets."
        )
    mode = Mode(str(data.get("mode", "lab")).lower())
    max_phase = Phase(str(data.get("max_phase", "report")).lower())

    scope = Scope(
        name=str(data.get("name", "unnamed-engagement")),
        mode=mode,
        authorized=bool(data.get("authorized", False)),
        allow_hosts=[h.lower() for h in data.get("allow_hosts", [])],
        allow_domains=[d.lower() for d in data.get("allow_domains", [])],
        allow_cidrs=list(data.get("allow_cidrs", [])),
        deny_hosts=[h.lower() for h in data.get("deny_hosts", [])],
        max_phase=max_phase,
        allow_destructive=bool(data.get("allow_destructive", False)),
        targets=list(data.get("targets", [])),
        raw=data,
    )
    return scope


@dataclass
class Settings:
    """Runtime knobs, separate from scope. Env-overridable by the CLI."""
    audit_path: Path = Path("praetor-audit.jsonl")
    report_dir: Path = Path("praetor-report")
    llm_provider: str = "auto"      # auto | openai | anthropic | none(deterministic)
    llm_model: Optional[str] = None
    tool_timeout_s: int = 120
    max_steps: int = 40             # orchestrator loop budget
    confirm_destructive: bool = True

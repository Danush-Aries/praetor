"""End-to-end tests for the orchestration loop (deterministic / offline)."""
from __future__ import annotations

import json

from praetor.agents.orchestrator import Orchestrator
from praetor.config import Scope, Settings
from praetor.models import Mode, Phase


def _scope(**kw) -> Scope:
    base = dict(
        name="t", mode=Mode.LAB, authorized=True,
        allow_hosts=[], allow_domains=[".lab"], allow_cidrs=[], deny_hosts=[],
        max_phase=Phase.LOOT, allow_destructive=True,
        targets=["metasploitable.lab", "dvwa.lab"],
    )
    base.update(kw)
    return Scope(**base)


def _settings(tmp_path) -> Settings:
    return Settings(audit_path=tmp_path / "audit.jsonl", report_dir=tmp_path / "report")


def test_full_chain_offline(tmp_path):
    state = Orchestrator(_scope(), _settings(tmp_path), confirm_fn=lambda a: True,
                         offline=True).run()
    phases = {f.phase for f in state.findings}
    assert Phase.RECON in phases and Phase.SCAN in phases
    assert Phase.EXPLOIT in phases  # allow_destructive=True + confirm -> exploit runs
    assert any(f.severity.value == "critical" for f in state.findings)
    # blue-team enrichment attached to at least some findings
    assert any(f.detection is not None for f in state.findings)


def test_governance_blocks_destructive(tmp_path):
    sc = _scope(allow_destructive=False, max_phase=Phase.EXPLOIT)
    state = Orchestrator(sc, _settings(tmp_path), offline=True).run()
    # recon/scan produced findings, but no exploit-phase findings got through
    assert not state.findings_by_phase(Phase.EXPLOIT)
    blocked = [o for o in state.observations if o.blocked_reason]
    assert blocked and "destructive" in blocked[0].blocked_reason


def test_out_of_scope_target_dropped(tmp_path):
    sc = _scope(targets=["metasploitable.lab", "notallowed.example.com"])
    state = Orchestrator(sc, _settings(tmp_path), confirm_fn=lambda a: True,
                         offline=True).run()
    # only the in-scope target should appear in findings
    assert all("example.com" not in f.target for f in state.findings)


def test_audit_and_report_written(tmp_path):
    settings = _settings(tmp_path)
    Orchestrator(_scope(), settings, confirm_fn=lambda a: True, offline=True).run()
    assert settings.audit_path.exists()
    lines = [json.loads(x) for x in settings.audit_path.read_text().splitlines() if x.strip()]
    kinds = {ln["kind"] for ln in lines}
    assert {"action", "decision", "observation"} <= kinds
    assert (settings.report_dir / "report.md").exists()
    assert (settings.report_dir / "report.sarif.json").exists()


def test_max_phase_ceiling(tmp_path):
    sc = _scope(max_phase=Phase.RECON)
    state = Orchestrator(sc, _settings(tmp_path), offline=True).run()
    assert state.findings  # recon ran
    assert all(f.phase == Phase.RECON for f in state.findings)

"""Tests for :mod:`praetor.tools.simulator`."""
from __future__ import annotations

from praetor.models import Phase, Severity, Target
from praetor.tools.simulator import is_simulated, sim_actions, simulate


def test_is_simulated() -> None:
    assert is_simulated("sim.lab") is True
    assert is_simulated("metasploitable.lab") is True
    assert is_simulated("https://dvwa.lab:8080/app") is True
    assert is_simulated("anything.lab") is True
    assert is_simulated("google.com") is False


def _run(phase: Phase):
    target = Target("sim.lab")
    action = sim_actions(target, phase)[0]
    return simulate(action)


def test_recon_findings() -> None:
    obs = _run(Phase.RECON)
    assert obs.ok is True
    ports = {f.metadata["port"] for f in obs.findings}
    assert {22, 80, 445} <= ports
    assert all(f.severity is Severity.INFO for f in obs.findings)
    assert all(f.source_tool == "sim" for f in obs.findings)


def test_scan_findings_include_cve() -> None:
    obs = _run(Phase.SCAN)
    cves = {f.cve for f in obs.findings}
    assert "CVE-2021-41773" in cves
    severities = {f.severity for f in obs.findings}
    assert Severity.HIGH in severities
    assert Severity.MEDIUM in severities


def test_exploit_findings_critical() -> None:
    obs = _run(Phase.EXPLOIT)
    assert any(f.severity is Severity.CRITICAL for f in obs.findings)
    assert any("uid=0(root)" in f.evidence for f in obs.findings)


def test_loot_findings() -> None:
    obs = _run(Phase.LOOT)
    assert any(f.severity is Severity.HIGH for f in obs.findings)
    assert any("passwd" in f.title for f in obs.findings)


def test_sim_actions_flags_destructive_phases() -> None:
    target = Target("sim.lab")
    assert sim_actions(target, Phase.RECON)[0].destructive is False
    assert sim_actions(target, Phase.EXPLOIT)[0].destructive is True
    assert sim_actions(target, Phase.LOOT)[0].destructive is True


def test_simulate_is_deterministic() -> None:
    for phase in (Phase.RECON, Phase.SCAN, Phase.EXPLOIT, Phase.LOOT):
        a = [f.to_dict() for f in _run(phase).findings]
        b = [f.to_dict() for f in _run(phase).findings]
        # Compare content, ignoring the identity-only auto id field.
        for d in a + b:
            d.pop("id")
        assert a == b

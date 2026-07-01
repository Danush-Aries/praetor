"""Tests for :mod:`praetor.tools.wrappers`."""
from __future__ import annotations

from pathlib import Path

from praetor.models import Phase, Target
from praetor.tools.wrappers import (
    REGISTRY,
    HttpProbeWrapper,
    NmapWrapper,
    available_wrappers,
    wrappers_for_phase,
)

FIXTURE = Path(__file__).parent / "fixtures" / "nmap_scanme.txt"


def test_nmap_parse_extracts_open_ports() -> None:
    raw = FIXTURE.read_text()
    findings = NmapWrapper().parse(raw, Target("scanme.nmap.org"))
    assert len(findings) >= 2
    ports = {f.metadata["port"] for f in findings}
    assert 22 in ports
    assert 80 in ports
    assert all(f.source_tool == "nmap" for f in findings)
    # 'filtered' and 'closed' ports must not become findings.
    assert 443 not in ports
    assert 25 not in ports


def test_nmap_build_argv() -> None:
    action = NmapWrapper().build(Target("scanme.nmap.org"))
    assert action.argv[0] == "nmap"
    assert "scanme.nmap.org" in action.argv
    assert action.phase is Phase.RECON


def test_http_probe_applies_to() -> None:
    # scheme is populated by the target parser upstream; emulate that here.
    web = Target("http://example.com", scheme="http")
    assert HttpProbeWrapper().applies_to(web) is True
    # a web port alone is also sufficient.
    assert HttpProbeWrapper().applies_to(Target("example.com", port=8080)) is True

    bare = Target("192.168.1.1", port=22)
    assert HttpProbeWrapper().applies_to(bare) is False


def test_http_probe_build_is_argvless() -> None:
    action = HttpProbeWrapper().build(Target("http://example.com", scheme="http"))
    assert action.argv == []
    assert action.tool == "http-probe"


def test_registry_helpers() -> None:
    assert any(isinstance(w, NmapWrapper) for w in REGISTRY)
    recon = wrappers_for_phase(Phase.RECON)
    assert len(recon) == len(REGISTRY)  # both shipped wrappers are RECON
    # available_wrappers is a subset of REGISTRY.
    assert set(id(w) for w in available_wrappers()) <= set(id(w) for w in REGISTRY)

"""Tests for the blue-team detection mirror."""
from __future__ import annotations

from praetor.blueteam import signatures
from praetor.blueteam.signatures import enrich, enrich_all, signature_for
from praetor.models import DetectionSignature, Finding, Phase, Severity


def test_signature_for_nmap() -> None:
    sig = signature_for("nmap")
    assert isinstance(sig, DetectionSignature)
    assert "T1046" in sig.mitre_attack
    assert sig.sigma_yaml.strip() != ""


def test_signature_for_cve_substring_case_insensitive() -> None:
    sig = signature_for("CVE-2021-41773")
    assert isinstance(sig, DetectionSignature)
    assert sig is signatures.CVE_EXPLOIT
    assert "T1190" in sig.mitre_attack


def test_signature_for_nonsense_is_none() -> None:
    assert signature_for("nonsense") is None
    assert signature_for("") is None


def test_enrich_sets_detection() -> None:
    finding = Finding(
        title="Open ports discovered",
        severity=Severity.INFO,
        phase=Phase.SCAN,
        source_tool="nmap",
    )
    assert finding.detection is None
    out = enrich(finding)
    assert out is finding
    assert out.detection is not None
    assert "T1046" in out.detection.mitre_attack


def test_enrich_prefers_cve_when_no_tool_match() -> None:
    finding = Finding(
        title="Apache path traversal",
        severity=Severity.CRITICAL,
        phase=Phase.EXPLOIT,
        source_tool="unknown-scanner",
        cve="CVE-2021-41773",
    )
    enrich(finding)
    assert finding.detection is signatures.CVE_EXPLOIT


def test_enrich_no_match_leaves_detection_none() -> None:
    finding = Finding(title="totally unrelated", source_tool="somethingelse")
    enrich(finding)
    assert finding.detection is None


def test_enrich_all_preserves_length() -> None:
    findings = [
        Finding(title="a", source_tool="nmap"),
        Finding(title="b", source_tool="http-probe"),
        Finding(title="c", source_tool="mystery"),
    ]
    out = enrich_all(findings)
    assert len(out) == len(findings) == 3
    assert out is findings
    assert out[0].detection is not None
    assert out[1].detection is not None
    assert out[2].detection is None

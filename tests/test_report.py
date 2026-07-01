"""Tests for engagement report rendering (Markdown / JSON / SARIF)."""
from __future__ import annotations

import json

from praetor.blueteam import enrich
from praetor.models import (
    EngagementState,
    Finding,
    Mode,
    Phase,
    Severity,
)
from praetor.report.render import (
    render_json,
    render_markdown,
    render_sarif,
    write_report,
)


def _state() -> EngagementState:
    critical = enrich(
        Finding(
            title="Apache 2.4.49 path traversal RCE",
            severity=Severity.CRITICAL,
            phase=Phase.EXPLOIT,
            target="10.0.0.5",
            description="Unauthenticated path traversal leading to RCE.",
            evidence="GET /cgi-bin/.%2e/%2e%2e/etc/passwd -> root:x:0:0",
            source_tool="praetor-exploit",
            cve="CVE-2021-41773",
            remediation="Upgrade Apache to 2.4.51 or later.",
        )
    )
    scan = enrich(
        Finding(
            title="Open service ports",
            severity=Severity.MEDIUM,
            phase=Phase.SCAN,
            target="10.0.0.5",
            description="Several TCP services exposed.",
            evidence="22/tcp, 80/tcp, 445/tcp open",
            source_tool="nmap",
        )
    )
    info = Finding(
        title="Banner disclosed server version",
        severity=Severity.INFO,
        phase=Phase.RECON,
        target="10.0.0.5",
        description="HTTP Server header leaks version.",
        source_tool="banner-grab",
    )
    return EngagementState(
        name="ACME Lab Assessment",
        mode=Mode.LAB,
        findings=[critical, scan, info],
    )


def test_render_markdown_contents() -> None:
    state = _state()
    md = render_markdown(state)
    assert isinstance(md, str)
    assert "ACME Lab Assessment" in md
    assert "critical" in md  # a severity word
    assert "CVE-2021-41773" in md  # the cve id
    assert "```" in md  # sigma code fence from an enriched detection


def test_render_json_summary_counts() -> None:
    state = _state()
    data = render_json(state)
    assert data["engagement"]["name"] == "ACME Lab Assessment"
    by_sev = data["summary"]["by_severity"]
    assert sum(by_sev.values()) == len(state.findings) == 3
    assert data["summary"]["total"] == 3
    assert len(data["findings"]) == 3


def test_render_sarif_shape() -> None:
    state = _state()
    sarif = render_sarif(state)
    assert sarif["version"] == "2.1.0"
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "PRAETOR"
    results = sarif["runs"][0]["results"]
    assert len(results) == len(state.findings) == 3

    # The critical finding must map to a SARIF "error" level.
    crit = next(r for r in results if r["ruleId"] == "CVE-2021-41773")
    assert crit["level"] == "error"


def test_write_report_creates_all_files(tmp_path) -> None:
    state = _state()
    paths = write_report(state, tmp_path)
    assert set(paths) == {"markdown", "json", "sarif"}
    for path in paths.values():
        assert path.exists()
        assert path.stat().st_size > 0

    # SARIF must parse back as valid JSON.
    reparsed = json.loads(paths["sarif"].read_text(encoding="utf-8"))
    assert reparsed["version"] == "2.1.0"
    assert reparsed["runs"][0]["tool"]["driver"]["name"] == "PRAETOR"

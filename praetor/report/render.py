"""Report rendering — turn an :class:`~praetor.models.EngagementState` into
human- and machine-readable artifacts.

Three formats are produced:

* **Markdown** (:func:`render_markdown`) — a recruiter-readable narrative with an
  executive summary, per-phase findings, and — the distinctive part — a
  blue-team detection subsection for any finding carrying a
  :class:`~praetor.models.DetectionSignature`.
* **JSON** (:func:`render_json`) — a flat, stable serialization for tooling.
* **SARIF 2.1.0** (:func:`render_sarif`) — the static-analysis interchange
  format, so PRAETOR findings drop straight into GitHub code scanning / any
  SARIF viewer.

:func:`write_report` writes all three to disk.

Stdlib only (``json``, ``pathlib``, ``datetime``); Sigma rules travel as plain
strings on the signature, so no YAML dependency is needed.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Union

from ..models import EngagementState, Finding, Phase, Severity

# SARIF ``level`` for each severity. critical/high are errors, medium is a
# warning, low/info are notes.
_SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

_TOOL_NAME = "PRAETOR"
_TOOL_VERSION = "0.1.0"


# --------------------------------------------------------------------------- #
# Helpers                                                                       #
# --------------------------------------------------------------------------- #
def _fmt_ts(epoch: float) -> str:
    """Render an epoch timestamp as an ISO-8601 UTC string."""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    """Return a count of findings per severity, one entry per severity level."""
    counts = {sev.value: 0 for sev in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return counts


# --------------------------------------------------------------------------- #
# Markdown                                                                      #
# --------------------------------------------------------------------------- #
def render_markdown(state: EngagementState) -> str:
    """Render ``state`` as a human-readable Markdown report."""
    findings = state.findings
    counts = _severity_counts(findings)
    lines: list[str] = []

    # --- Header ----------------------------------------------------------- #
    lines.append(f"# PRAETOR Engagement Report — {state.name}")
    lines.append("")
    lines.append(f"- **Mode:** {state.mode.value}")
    lines.append(f"- **Engagement ID:** {state.id}")
    lines.append(f"- **Started:** {_fmt_ts(state.started_at)}")
    lines.append(f"- **Generated:** {_fmt_ts(datetime.now(tz=timezone.utc).timestamp())}")
    lines.append("")

    # --- Executive summary ------------------------------------------------ #
    summary = ", ".join(
        f"{counts[sev.value]} {sev.value}"
        for sev in reversed(list(Severity))  # critical → info
    )
    lines.append("## Executive summary")
    lines.append("")
    lines.append(f"{len(findings)} findings: {summary}.")
    lines.append("")

    # --- Per-phase findings ---------------------------------------------- #
    for phase in Phase:
        phase_findings = state.findings_by_phase(phase)
        if not phase_findings:
            continue
        lines.append(f"## Phase: {phase.value.capitalize()}")
        lines.append("")
        for f in phase_findings:
            lines.append(f"### {f.title}")
            lines.append("")
            lines.append(f"- **Severity:** {f.severity.value}")
            lines.append(f"- **Target:** {f.target or 'n/a'}")
            if f.cve:
                lines.append(f"- **CVE:** {f.cve}")
            lines.append(f"- **Source tool:** {f.source_tool or 'n/a'}")
            if f.description:
                lines.append(f"- **Description:** {f.description}")
            if f.evidence:
                lines.append(f"- **Evidence:** {f.evidence}")
            if f.remediation:
                lines.append(f"- **Remediation:** {f.remediation}")
            lines.append("")

            # --- Blue-team detection subsection --------------------------- #
            det = f.detection
            if det is not None:
                lines.append("#### Blue-team detection")
                lines.append("")
                lines.append(f"- **Detection:** {det.name}")
                lines.append(
                    f"- **MITRE ATT&CK:** {', '.join(det.mitre_attack) or 'n/a'}"
                )
                lines.append(f"- **Log source:** {det.log_source or 'n/a'}")
                if det.description:
                    lines.append(f"- **What a defender sees:** {det.description}")
                lines.append("")
                if det.sigma_yaml:
                    lines.append("```yaml")
                    lines.append(det.sigma_yaml.rstrip("\n"))
                    lines.append("```")
                    lines.append("")

    # --- Footer ----------------------------------------------------------- #
    lines.append("---")
    lines.append("")
    lines.append(f"**Total findings: {len(findings)}**")
    lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# JSON                                                                          #
# --------------------------------------------------------------------------- #
def render_json(state: EngagementState) -> dict[str, Any]:
    """Render ``state`` as a plain, JSON-serializable dict."""
    return {
        "engagement": {
            "name": state.name,
            "mode": state.mode.value,
            "id": state.id,
            "started_at": state.started_at,
        },
        "summary": {
            "total": len(state.findings),
            "by_severity": _severity_counts(state.findings),
        },
        "findings": [f.to_dict() for f in state.findings],
    }


# --------------------------------------------------------------------------- #
# SARIF 2.1.0                                                                   #
# --------------------------------------------------------------------------- #
def _sarif_rule(finding: Finding) -> dict[str, Any]:
    """Build the SARIF ``rule`` object describing ``finding``'s rule id."""
    rule_id = finding.cve or finding.id
    return {
        "id": rule_id,
        "name": finding.title,
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description or finding.title},
        "defaultConfiguration": {"level": _SARIF_LEVEL[finding.severity]},
        "properties": {
            "phase": finding.phase.value,
            "severity": finding.severity.value,
            "tags": (["external/cwe"] if finding.cve else []),
        },
    }


def _sarif_result(finding: Finding) -> dict[str, Any]:
    """Build one SARIF ``result`` object for ``finding``."""
    props: dict[str, Any] = {
        "target": finding.target,
        "phase": finding.phase.value,
        "severity": finding.severity.value,
        "source_tool": finding.source_tool,
    }
    if finding.cve:
        props["cve"] = finding.cve
    if finding.detection is not None:
        props["detection"] = finding.detection.to_dict()

    return {
        "ruleId": finding.cve or finding.id,
        "level": _SARIF_LEVEL[finding.severity],
        "message": {"text": finding.title},
        "properties": props,
    }


def render_sarif(state: EngagementState) -> dict[str, Any]:
    """Render ``state`` as a valid SARIF 2.1.0 log document."""
    findings = state.findings
    # Deduplicate rules by id while preserving order.
    rules: list[dict[str, Any]] = []
    seen: set[str] = set()
    for f in findings:
        rule = _sarif_rule(f)
        if rule["id"] not in seen:
            seen.add(rule["id"])
            rules.append(rule)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "version": _TOOL_VERSION,
                        "informationUri": "https://github.com/Dhanush-Aries/praetor",
                        "rules": rules,
                    }
                },
                "results": [_sarif_result(f) for f in findings],
            }
        ],
    }


# --------------------------------------------------------------------------- #
# Disk output                                                                   #
# --------------------------------------------------------------------------- #
def write_report(state: EngagementState, out_dir: Union[str, Path]) -> dict[str, Path]:
    """Write Markdown, JSON, and SARIF reports into ``out_dir``.

    The directory is created if missing. Returns a mapping of format name to the
    path written: ``{"markdown": ..., "json": ..., "sarif": ...}``.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    md_path = out / "report.md"
    json_path = out / "report.json"
    sarif_path = out / "report.sarif.json"

    md_path.write_text(render_markdown(state), encoding="utf-8")
    json_path.write_text(
        json.dumps(render_json(state), indent=2, default=str), encoding="utf-8"
    )
    sarif_path.write_text(
        json.dumps(render_sarif(state), indent=2, default=str), encoding="utf-8"
    )

    return {"markdown": md_path, "json": json_path, "sarif": sarif_path}


__all__ = [
    "render_markdown",
    "render_json",
    "render_sarif",
    "write_report",
]

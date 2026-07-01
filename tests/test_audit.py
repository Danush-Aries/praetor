"""Tests for the append-only JSONL audit logger."""
from __future__ import annotations

import json
from pathlib import Path

from praetor.governance.audit import AuditLogger
from praetor.models import Action, Finding, Observation, Phase, Severity


def _read_lines(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_logs_action_decision_observation(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path, engagement_id="eng_test")

    action = Action(
        phase=Phase.RECON,
        tool="nmap",
        argv=["nmap", "-sV", "scanme.example.com"],
        target="scanme.example.com",
        rationale="service discovery",
    )
    finding = Finding(
        title="Open port 80",
        severity=Severity.LOW,
        phase=Phase.RECON,
        target="scanme.example.com",
    )
    obs = Observation(
        action_id=action.id,
        ok=True,
        raw_output="80/tcp open http",
        findings=[finding],
        duration_s=1.234,
    )

    logger.action(action)
    logger.decision(action.id, allowed=True, reason="ok")
    logger.observation(obs)
    logger.close()

    lines = _read_lines(log_path)
    assert len(lines) == 3

    # Every record carries the shared envelope keys.
    for rec in lines:
        assert set(("ts", "engagement_id", "kind")).issubset(rec.keys())
        assert isinstance(rec["ts"], float)
        assert rec["engagement_id"] == "eng_test"

    act_rec, dec_rec, obs_rec = lines
    assert act_rec["kind"] == "action"
    assert act_rec["id"] == action.id
    assert act_rec["tool"] == "nmap"

    assert dec_rec["kind"] == "decision"
    assert dec_rec["action_id"] == action.id
    assert dec_rec["allowed"] is True
    assert dec_rec["reason"] == "ok"

    assert obs_rec["kind"] == "observation"
    assert obs_rec["action_id"] == action.id
    assert obs_rec["ok"] is True
    assert len(obs_rec["findings"]) == 1


def test_event_appends_and_is_valid_json(tmp_path: Path) -> None:
    log_path = tmp_path / "events.jsonl"
    logger = AuditLogger(log_path)
    logger.event("custom", {"foo": "bar", "n": 3})
    logger.event("custom", {"foo": "baz"})

    lines = _read_lines(log_path)
    assert len(lines) == 2
    assert lines[0]["kind"] == "custom"
    assert lines[0]["foo"] == "bar"
    assert lines[0]["n"] == 3
    assert isinstance(lines[0]["ts"], float)


def test_creates_nested_nonexistent_dir(tmp_path: Path) -> None:
    log_path = tmp_path / "deep" / "nested" / "path" / "audit.jsonl"
    assert not log_path.parent.exists()

    logger = AuditLogger(log_path, engagement_id="eng_nested")
    logger.event("start", {"note": "hello"})

    assert log_path.exists()
    lines = _read_lines(log_path)
    assert len(lines) == 1
    assert lines[0]["kind"] == "start"
    assert lines[0]["engagement_id"] == "eng_nested"


def test_logging_never_raises_on_bad_payload(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path)

    # A non-serializable object must not blow up the logger.
    logger.event("weird", {"obj": object()})

    lines = _read_lines(log_path)
    assert len(lines) == 1
    assert lines[0]["kind"] == "weird"
    assert isinstance(lines[0]["ts"], float)

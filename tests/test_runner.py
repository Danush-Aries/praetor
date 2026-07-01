"""Tests for :mod:`praetor.tools.runner`."""
from __future__ import annotations

from praetor.models import Action, Phase
from praetor.tools.runner import ToolRunner


def _action(argv: list[str]) -> Action:
    return Action(phase=Phase.RECON, tool="test", argv=argv, target="localhost")


def test_run_success() -> None:
    obs = ToolRunner().run(_action(["echo", "hello"]))
    assert obs.ok is True
    assert "hello" in obs.raw_output
    assert obs.duration_s >= 0
    assert obs.error is None


def test_run_empty_argv() -> None:
    obs = ToolRunner().run(_action([]))
    assert obs.ok is False
    assert obs.error == "empty argv"


def test_run_missing_tool() -> None:
    obs = ToolRunner().run(_action(["this-cmd-does-not-exist-zzz"]))
    assert obs.ok is False
    assert obs.error is not None
    assert "not installed" in obs.error


def test_run_rejects_shell_metacharacters() -> None:
    obs = ToolRunner().run(_action(["echo", "hi; rm -rf /"]))
    assert obs.ok is False
    assert obs.error is not None
    assert "unsafe argv element" in obs.error


def test_run_timeout() -> None:
    obs = ToolRunner(timeout_s=1).run(_action(["sleep", "5"]))
    assert obs.ok is False
    assert obs.error is not None
    assert "timeout" in obs.error

"""Tests for :mod:`praetor.tools.detect`."""
from __future__ import annotations

from praetor.tools import detect


def test_available_tools_covers_known_tools() -> None:
    result = detect.available_tools()
    assert isinstance(result, dict)
    assert set(result) == set(detect.KNOWN_TOOLS)
    assert all(isinstance(v, bool) for v in result.values())


def test_which_finds_installed_tool() -> None:
    # nmap is installed on this host per the environment contract.
    assert detect.which("nmap")
    assert detect.is_available("nmap") is True


def test_which_returns_none_for_missing_tool() -> None:
    assert detect.which("definitely-not-a-tool-xyz") is None
    assert detect.is_available("definitely-not-a-tool-xyz") is False

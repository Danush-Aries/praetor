"""Tool detection.

A thin, dependency-free layer over :func:`shutil.which` that answers one
question: *which pentest binaries can we actually run on this host?*

The orchestrator uses this to decide whether to dispatch a real tool, fall back
to the deterministic :mod:`praetor.tools.simulator`, or skip a wrapper entirely.
"""
from __future__ import annotations

import shutil

#: Binaries PRAETOR knows how to drive (directly or via a wrapper). Presence in
#: this list does *not* imply the tool is installed — call :func:`available_tools`.
KNOWN_TOOLS: list[str] = [
    "nmap",
    "masscan",
    "nuclei",
    "httpx",
    "subfinder",
    "amass",
    "ffuf",
    "gobuster",
    "naabu",
    "katana",
    "sqlmap",
    "nikto",
    "whatweb",
    "wpscan",
    "hydra",
]


def which(name: str) -> str | None:
    """Return the absolute path to ``name`` on ``PATH``, or ``None`` if absent.

    A direct pass-through to :func:`shutil.which`; kept as a named function so
    callers depend on this module rather than the stdlib import site.
    """
    return shutil.which(name)


def is_available(name: str) -> bool:
    """Return ``True`` if the binary ``name`` is installed and on ``PATH``."""
    return which(name) is not None


def available_tools() -> dict[str, bool]:
    """Map every :data:`KNOWN_TOOLS` name to whether it is installed.

    Returns a fresh dict on every call, so callers may mutate it freely.
    """
    return {name: is_available(name) for name in KNOWN_TOOLS}

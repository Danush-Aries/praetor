"""PRAETOR tools module.

Everything the orchestrator needs to *do* things against a target lives here:

- ``detect``    — discover which pentest binaries are installed on this host.
- ``runner``    — safely execute an :class:`~praetor.models.Action` (argv only,
                  never a shell) and capture the result as an
                  :class:`~praetor.models.Observation`.
- ``wrappers``  — per-tool adapters that *build* Actions and *parse* their raw
                  output into structured :class:`~praetor.models.Finding` objects.
- ``simulator`` — a deterministic, fully-offline vulnerable lab so the entire
                  pipeline (and CI) can run with zero external tools installed.

The public surface is intentionally small and stdlib-only; nothing here reaches
for a third-party dependency.
"""
from __future__ import annotations

from praetor.tools import detect, runner, simulator, wrappers
from praetor.tools.detect import (
    KNOWN_TOOLS,
    available_tools,
    is_available,
    which,
)
from praetor.tools.runner import ToolRunner
from praetor.tools.simulator import (
    SIM_HOSTS,
    is_simulated,
    sim_actions,
    simulate,
)
from praetor.tools.wrappers import (
    REGISTRY,
    HttpProbeWrapper,
    NmapWrapper,
    Wrapper,
    available_wrappers,
    wrappers_for_phase,
)

__all__ = [
    # submodules
    "detect",
    "runner",
    "wrappers",
    "simulator",
    # detect
    "KNOWN_TOOLS",
    "which",
    "available_tools",
    "is_available",
    # runner
    "ToolRunner",
    # wrappers
    "Wrapper",
    "NmapWrapper",
    "HttpProbeWrapper",
    "REGISTRY",
    "wrappers_for_phase",
    "available_wrappers",
    # simulator
    "SIM_HOSTS",
    "is_simulated",
    "simulate",
    "sim_actions",
]

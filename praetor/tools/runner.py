"""Action execution.

:class:`ToolRunner` turns an approved :class:`~praetor.models.Action` into an
:class:`~praetor.models.Observation` by executing its ``argv`` as a child
process.

Security posture
----------------
Commands are executed as an **argv list only** — ``shell=False``, always. There
is no command string, no shell interpolation, and therefore no shell-injection
surface: every element of ``argv`` is passed verbatim as a distinct execve
argument. As a defence-in-depth belt-and-braces measure we additionally *reject*
any argv element that carries shell metacharacters, so that even a future
refactor that (wrongly) reintroduced ``shell=True`` would fail closed rather
than open.
"""
from __future__ import annotations

import subprocess
import time

from praetor.models import Action, Observation

#: Characters that only carry meaning to a shell. argv execution never
#: interprets these, but we screen for them so a value that *would* be dangerous
#: under ``shell=True`` is refused loudly instead of silently trusted.
_SHELL_METACHARS: frozenset[str] = frozenset(";&|`$><\n\\")


class ToolRunner:
    """Execute :class:`~praetor.models.Action` objects and capture their output.

    Parameters
    ----------
    timeout_s:
        Wall-clock ceiling handed to :func:`subprocess.run`. A process that
        outlives it is killed and reported as a timeout Observation.
    """

    def __init__(self, timeout_s: int = 120) -> None:
        self.timeout_s = timeout_s

    def run(self, action: Action) -> Observation:
        """Run ``action.argv`` and return the resulting :class:`Observation`.

        Failure modes are all returned as ``ok=False`` Observations rather than
        raised, so the orchestrator loop never has to wrap this in a try/except:

        - empty ``argv``                 -> ``error="empty argv"``
        - a shell metachar in an element -> ``error="unsafe argv element: ..."``
        - binary not found               -> ``error="tool not installed: <cmd>"``
        - exceeds ``timeout_s``          -> ``error="timeout after <n>s"``

        On a completed process, ``ok`` mirrors ``returncode == 0`` and
        ``raw_output`` is ``stdout + stderr``. Parsing into findings is the
        wrapper's job, so ``findings`` is always left empty here.
        """
        argv = list(action.argv)
        if not argv:
            return Observation(action_id=action.id, ok=False, error="empty argv")

        unsafe = self._unsafe_element(argv)
        if unsafe is not None:
            return Observation(
                action_id=action.id,
                ok=False,
                error=f"unsafe argv element: {unsafe!r}",
            )

        start = time.monotonic()
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=self.timeout_s,
                shell=False,  # NEVER shell=True — argv only.
            )
        except FileNotFoundError:
            duration = time.monotonic() - start
            return Observation(
                action_id=action.id,
                ok=False,
                duration_s=duration,
                error=f"tool not installed: {argv[0]}",
            )
        except subprocess.TimeoutExpired:
            duration = time.monotonic() - start
            return Observation(
                action_id=action.id,
                ok=False,
                duration_s=duration,
                error=f"timeout after {self.timeout_s}s",
            )

        duration = time.monotonic() - start
        raw = (proc.stdout or "") + (proc.stderr or "")
        return Observation(
            action_id=action.id,
            ok=(proc.returncode == 0),
            raw_output=raw,
            findings=[],
            duration_s=duration,
        )

    @staticmethod
    def _unsafe_element(argv: list[str]) -> str | None:
        """Return the first argv element containing a shell metachar, else ``None``."""
        for element in argv:
            if any(ch in _SHELL_METACHARS for ch in element):
                return element
        return None

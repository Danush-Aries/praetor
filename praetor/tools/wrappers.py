"""Tool wrappers.

A wrapper adapts one external tool (or one built-in probe) to a uniform,
orchestrator-friendly interface. Each wrapper knows how to:

- report whether its underlying tool is :meth:`~Wrapper.available`,
- decide whether it :meth:`~Wrapper.applies_to` a given target,
- :meth:`~Wrapper.build` an :class:`~praetor.models.Action` (argv set), and
- :meth:`~Wrapper.parse` raw tool output into :class:`~praetor.models.Finding`s.

Parsing is deliberately kept pure (regex over a string), so every wrapper is
unit-testable from a captured-output fixture without touching the network.

Some wrappers execute themselves rather than shelling out — notably
:class:`HttpProbeWrapper`, which builds an argv-less Action and exposes
:meth:`~HttpProbeWrapper.probe` for the orchestrator to call directly.
"""
from __future__ import annotations

import re
import urllib.error
import urllib.request
from typing import Protocol, runtime_checkable

from praetor.models import Action, Finding, Phase, Severity, Target
from praetor.tools import detect


@runtime_checkable
class Wrapper(Protocol):
    """Uniform interface every tool adapter implements.

    Attributes
    ----------
    name:
        Stable identifier, also used as ``Action.tool`` / ``Finding.source_tool``.
    phase:
        The pentest phase this wrapper contributes to.
    """

    name: str
    phase: Phase

    def available(self) -> bool:
        """Return ``True`` if this wrapper can actually run on this host."""
        ...

    def applies_to(self, target: Target) -> bool:
        """Return ``True`` if this wrapper is meaningful for ``target``."""
        ...

    def build(self, target: Target) -> Action:
        """Return an :class:`Action` (argv populated) to run against ``target``."""
        ...

    def parse(self, raw_output: str, target: Target) -> list[Finding]:
        """Turn captured ``raw_output`` into structured findings."""
        ...


# nmap normal-output lines look like:  "22/tcp open  ssh"  /  "80/tcp   open http syn-ack"
_NMAP_PORT_RE = re.compile(
    r"^(?P<port>\d{1,5})/(?P<proto>tcp|udp)\s+open\s+(?P<service>\S+)?",
    re.IGNORECASE,
)


class NmapWrapper:
    """Wrap the ``nmap`` port scanner (RECON phase).

    ``build`` emits a fast, ping-less top-100-ports TCP scan; ``parse`` reads the
    human-readable port table and yields one INFO finding per open port.
    """

    name = "nmap"
    phase = Phase.RECON

    def available(self) -> bool:
        """``True`` when the ``nmap`` binary is installed."""
        return detect.is_available("nmap")

    def applies_to(self, target: Target) -> bool:  # noqa: ARG002 - uniform signature
        """nmap applies to any host, so this is always ``True``."""
        return True

    def build(self, target: Target) -> Action:
        """Build a top-100-ports, no-ping, aggressive-timing TCP scan Action."""
        argv = ["nmap", "-T4", "-Pn", "--top-ports", "100", target.host]
        return Action(
            phase=self.phase,
            tool=self.name,
            argv=argv,
            target=target.raw,
            rationale=f"top-100 TCP port scan of {target.host}",
            destructive=False,
        )

    def parse(self, raw_output: str, target: Target) -> list[Finding]:
        """Extract one INFO :class:`Finding` per ``<port>/<proto> open`` line."""
        findings: list[Finding] = []
        for line in raw_output.splitlines():
            match = _NMAP_PORT_RE.match(line.strip())
            if not match:
                continue
            port = int(match.group("port"))
            proto = match.group("proto").lower()
            service = (match.group("service") or "unknown").strip()
            findings.append(
                Finding(
                    title=f"Open port {port}/{proto} ({service})",
                    severity=Severity.INFO,
                    phase=self.phase,
                    target=target.raw,
                    description=f"nmap reported {port}/{proto} open running {service}.",
                    evidence=line.strip(),
                    source_tool=self.name,
                    metadata={"port": port, "proto": proto, "service": service},
                )
            )
        return findings


class HttpProbeWrapper:
    """A built-in HTTP(S) banner probe (RECON phase), using only the stdlib.

    Unlike :class:`NmapWrapper`, this wrapper executes *itself*: ``build`` returns
    an argv-less Action (there is no external binary to run), and the orchestrator
    calls :meth:`probe` to perform the request and collect findings.
    """

    name = "http-probe"
    phase = Phase.RECON

    #: Ports that strongly imply a web service when no scheme is given.
    _WEB_PORTS: frozenset[int] = frozenset({80, 443, 8080, 8000})

    def available(self) -> bool:
        """Always ``True`` — the probe relies only on :mod:`urllib`."""
        return True

    def applies_to(self, target: Target) -> bool:
        """``True`` for http/https targets or common web ports."""
        return target.scheme in ("http", "https") or target.port in self._WEB_PORTS

    def build(self, target: Target) -> Action:
        """Return an argv-less Action; execution happens in :meth:`probe`."""
        return Action(
            phase=self.phase,
            tool=self.name,
            argv=[],
            target=target.raw,
            rationale=f"HTTP banner probe of {target.host}",
            destructive=False,
        )

    def parse(self, raw_output: str, target: Target) -> list[Finding]:  # noqa: ARG002
        """Unused for this wrapper — findings come from :meth:`probe`."""
        return []

    def _url_for(self, target: Target) -> str:
        """Best-effort URL: honour an explicit scheme/port, else default to http."""
        scheme = target.scheme or ("https" if target.port == 443 else "http")
        if target.port and target.port not in (80, 443):
            return f"{scheme}://{target.host}:{target.port}/"
        return f"{scheme}://{target.host}/"

    def probe(self, target: Target, timeout: float = 5.0) -> list[Finding]:
        """Issue one HTTP request and report status + ``Server`` header.

        Any network error (DNS failure, connection refused, timeout, bad TLS) is
        swallowed and yields an empty list — this method never raises.
        """
        url = self._url_for(target)
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": "praetor/0.1"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - http/https only
                status = resp.status
                server = resp.headers.get("Server", "unknown")
        except (urllib.error.URLError, OSError, ValueError):
            return []

        return [
            Finding(
                title=f"HTTP {status} from {target.host} (Server: {server})",
                severity=Severity.INFO,
                phase=self.phase,
                target=target.raw,
                description=f"HTTP probe of {url} returned status {status}.",
                evidence=f"{url} -> {status}; Server: {server}",
                source_tool=self.name,
                metadata={"url": url, "status": status, "server": server},
            )
        ]


#: All wrappers PRAETOR ships with, in dispatch order.
REGISTRY: list[Wrapper] = [NmapWrapper(), HttpProbeWrapper()]


def wrappers_for_phase(phase: Phase) -> list[Wrapper]:
    """Return every registered wrapper that contributes to ``phase``."""
    return [w for w in REGISTRY if w.phase == phase]


def available_wrappers() -> list[Wrapper]:
    """Return the registered wrappers whose underlying tool is installed."""
    return [w for w in REGISTRY if w.available()]

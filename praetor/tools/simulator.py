"""Deterministic offline lab.

Real pentest tooling is heavy, noisy, and — for CI and demos — often simply not
installed. The simulator provides a *fake vulnerable host* so the entire
recon -> scan -> exploit -> loot pipeline runs end-to-end with zero external
binaries and byte-for-byte reproducible output.

Every function here is pure and deterministic: no randomness, no clock, no
network. Calling :func:`simulate` twice with the same Action yields equal
Observations (modulo the auto-generated ``action_id``/``Finding.id`` fields,
which are identity, not content).
"""
from __future__ import annotations

from praetor.models import Action, Finding, Observation, Phase, Severity, Target

#: Hostnames that always resolve to the simulated lab.
SIM_HOSTS: set[str] = {"sim.lab", "metasploitable.lab", "dvwa.lab"}

#: Marker tool name that routes an Action to :func:`simulate` instead of a real
#: process. :func:`sim_actions` stamps every Action it builds with this.
SIM_TOOL = "sim"


def is_simulated(target: str) -> bool:
    """Return ``True`` if ``target`` should be handled by the simulator.

    A target is simulated when its host is a known :data:`SIM_HOSTS` entry or
    when it lives under the reserved ``.lab`` suffix. ``target`` may be a raw
    string (``https://sim.lab:8080/x``); the host is extracted the same way
    :class:`~praetor.models.Target` does it.
    """
    host = target.split("://")[-1].split("/")[0].split(":")[0]
    return host in SIM_HOSTS or host.endswith(".lab")


def _recon_findings(target: str) -> list[Finding]:
    """Canned RECON findings: three classic open ports."""
    ports = [(22, "ssh"), (80, "http"), (445, "microsoft-ds")]
    return [
        Finding(
            title=f"Open port {port}/tcp ({service})",
            severity=Severity.INFO,
            phase=Phase.RECON,
            target=target,
            description=f"Simulated host exposes {port}/tcp ({service}).",
            evidence=f"{port}/tcp open {service}",
            source_tool=SIM_TOOL,
            metadata={"port": port, "proto": "tcp", "service": service},
        )
        for port, service in ports
    ]


def _scan_findings(target: str) -> list[Finding]:
    """Canned SCAN findings: a critical CVE and a misconfigured SMB share."""
    return [
        Finding(
            title="Apache 2.4.49 - Path Traversal",
            severity=Severity.HIGH,
            phase=Phase.SCAN,
            target=target,
            description=(
                "The simulated web server runs Apache httpd 2.4.49, vulnerable to "
                "path traversal / RCE via crafted URLs."
            ),
            evidence="Server: Apache/2.4.49 (Unix)",
            source_tool=SIM_TOOL,
            cve="CVE-2021-41773",
            remediation="Upgrade Apache httpd to 2.4.51 or later.",
            metadata={"service": "http", "port": 80, "product": "Apache 2.4.49"},
        ),
        Finding(
            title="Anonymous SMB share",
            severity=Severity.MEDIUM,
            phase=Phase.SCAN,
            target=target,
            description="SMB permits anonymous (null-session) access to a share.",
            evidence="IPC$ accessible with empty credentials",
            source_tool=SIM_TOOL,
            remediation="Disable guest/null-session access; require authentication on shares.",
            metadata={"service": "smb", "port": 445, "share": "IPC$"},
        ),
    ]


def _exploit_findings(target: str) -> list[Finding]:
    """Canned EXPLOIT finding: a simulated root RCE."""
    return [
        Finding(
            title="Exploited CVE-2021-41773 -> RCE (simulated)",
            severity=Severity.CRITICAL,
            phase=Phase.EXPLOIT,
            target=target,
            description=(
                "Path-traversal was chained to remote command execution against the "
                "simulated Apache 2.4.49 host, yielding a root shell."
            ),
            evidence="id=uid=0(root)",
            source_tool=SIM_TOOL,
            cve="CVE-2021-41773",
            remediation=(
                "Upgrade Apache to 2.4.51+, run the service as an unprivileged user, "
                "and restrict CGI aliases."
            ),
            metadata={"technique": "T1190", "shell": "root"},
        )
    ]


def _loot_findings(target: str) -> list[Finding]:
    """Canned LOOT finding: recovered credential material."""
    return [
        Finding(
            title="Recovered /etc/passwd (simulated)",
            severity=Severity.HIGH,
            phase=Phase.LOOT,
            target=target,
            description="Post-exploitation read of /etc/passwd from the simulated host.",
            evidence="root:x:0:0:root:/root:/bin/bash",
            source_tool=SIM_TOOL,
            remediation="Rotate credentials and audit account list after any compromise.",
            metadata={"artifact": "/etc/passwd"},
        )
    ]


# Phase -> (findings factory, raw-output banner). Kept as a table so behaviour is
# obvious at a glance and trivially extensible.
_PHASE_TABLE = {
    Phase.RECON: (_recon_findings, "SIM RECON: 22/tcp, 80/tcp, 445/tcp open"),
    Phase.SCAN: (_scan_findings, "SIM SCAN: Apache 2.4.49 (CVE-2021-41773), anon SMB"),
    Phase.EXPLOIT: (_exploit_findings, "SIM EXPLOIT: CVE-2021-41773 -> uid=0(root)"),
    Phase.LOOT: (_loot_findings, "SIM LOOT: dumped /etc/passwd"),
}


def simulate(action: Action) -> Observation:
    """Return a deterministic :class:`Observation` for a simulated ``action``.

    The action's :class:`~praetor.models.Phase` selects the canned findings and
    raw-output banner. Phases without a scripted scenario (e.g. ``REPORT``) come
    back as a successful, finding-free Observation.
    """
    factory_banner = _PHASE_TABLE.get(action.phase)
    if factory_banner is None:
        return Observation(
            action_id=action.id,
            ok=True,
            raw_output=f"SIM {action.phase.value.upper()}: no scripted scenario",
            findings=[],
            duration_s=0.0,
        )

    factory, banner = factory_banner
    findings = factory(action.target)
    return Observation(
        action_id=action.id,
        ok=True,
        raw_output=banner,
        findings=findings,
        duration_s=0.0,
    )


def sim_actions(target: Target, phase: Phase) -> list[Action]:
    """Build the simulated Action(s) to run against ``target`` for ``phase``.

    EXPLOIT and LOOT are flagged ``destructive`` so the governance gate treats
    the simulated chain with the same caution as the real one.
    """
    return [
        Action(
            phase=phase,
            tool=SIM_TOOL,
            argv=[],
            target=target.raw,
            rationale=f"simulated {phase.value} against {target.host}",
            destructive=phase in (Phase.EXPLOIT, Phase.LOOT),
        )
    ]

"""Blue-team detection mirror — PRAETOR's differentiator.

For every offensive action PRAETOR can take, a defender's telemetry would light
up somewhere: a Zeek connection log, a web access log, a Windows security event,
an ``auditd`` file-read record. This module maps a technique/tool key to the
:class:`~praetor.models.DetectionSignature` that describes exactly what that
activity looks like from the blue side — including a minimal, real-ish Sigma
rule stored as a plain string (no PyYAML dependency).

The intent is purple-team teaching: run the attack, then hand the defender the
detection they *should* have written. Signatures are deterministic module-level
constants so a given input always maps to the same artifact.

Public API
----------
* :func:`signature_for` — case-insensitive substring lookup by key.
* :func:`enrich` — attach a matching signature to a single Finding.
* :func:`enrich_all` — enrich a list of findings in place.

Stdlib only.
"""
from __future__ import annotations

from ..models import DetectionSignature, Finding

# --------------------------------------------------------------------------- #
# Signature constants                                                          #
# --------------------------------------------------------------------------- #
# Each is a minimal Sigma-style rule. Sigma is stored as a plain string; we do
# not parse it here, so no YAML library is required.

NMAP_PORT_SCAN = DetectionSignature(
    name="Network service discovery (port scan)",
    description=(
        "A single source opening connections to many distinct destination ports "
        "in a short window — the signature of an nmap-style port scan."
    ),
    log_source="zeek:conn",
    mitre_attack=["T1046"],
    sigma_yaml="""\
title: Network Service Discovery - Horizontal Port Scan
id: 6b1d5c9a-2f0e-4a11-8c3d-0a1b2c3d4e5f
status: experimental
logsource:
    product: zeek
    service: conn
detection:
    selection:
        proto: tcp
    timeframe: 1m
    condition: selection | count(id.resp_p) by id.orig_h > 20
falsepositives:
    - Vulnerability scanners
    - Load balancers health-checking many ports
level: medium
""",
)

HTTP_PROBE = DetectionSignature(
    name="Web reconnaissance requests",
    description=(
        "A burst of 4xx responses and/or an atypical User-Agent from one client — "
        "content discovery / directory brute-forcing against a web application."
    ),
    log_source="web:access",
    mitre_attack=["T1594"],
    sigma_yaml="""\
title: Web Reconnaissance - 4xx Burst / Suspicious User-Agent
id: 9c4e7b21-3a5d-4c6f-9e10-1b2c3d4e5f60
status: experimental
logsource:
    category: webserver
    service: access
detection:
    status_4xx:
        sc_status:
            - 400
            - 403
            - 404
    scanner_ua:
        c_useragent|contains:
            - gobuster
            - dirbuster
            - nikto
            - sqlmap
            - curl
            - python-requests
    condition: status_4xx or scanner_ua
    timeframe: 30s
falsepositives:
    - Broken links crawled by legitimate bots
level: low
""",
)

CVE_EXPLOIT = DetectionSignature(
    name="Exploitation of public-facing application",
    description=(
        "A request URI matching a known CVE exploitation pattern (e.g. the "
        "CVE-2021-41773 path-traversal ``%2e%2e`` sequence) against an "
        "internet-facing service."
    ),
    log_source="web:access",
    mitre_attack=["T1190"],
    sigma_yaml="""\
title: Exploitation of Public-Facing Application - Path Traversal
id: 1f8a3d47-6b2c-4e09-8a5f-2c3d4e5f6071
status: experimental
logsource:
    category: webserver
    service: access
detection:
    traversal:
        cs_uri_stem|contains:
            - '%2e%2e%2f'
            - '%2e%2e/'
            - '..%2f'
            - '/etc/passwd'
            - '/bin/sh'
    condition: traversal
falsepositives:
    - Rare application paths that legitimately encode dots
level: high
""",
)

SMB_ENUM = DetectionSignature(
    name="SMB session enumeration",
    description=(
        "Anonymous / null-session logons enumerating SMB shares — reconnaissance "
        "of network shares via Windows security events 4624/4625."
    ),
    log_source="windows:security",
    mitre_attack=["T1135"],
    sigma_yaml="""\
title: SMB Anonymous Session Enumeration
id: 2a9b4c58-7d3e-4f1a-9b6c-3d4e5f607182
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4624
            - 4625
        LogonType: 3
        TargetUserName:
            - 'ANONYMOUS LOGON'
            - 'Guest'
    condition: selection
falsepositives:
    - Legacy applications using null sessions
level: medium
""",
)

LOOT_EXFIL = DetectionSignature(
    name="Sensitive file access",
    description=(
        "A read of a sensitive local file such as ``/etc/passwd`` or ``/etc/shadow`` "
        "— data collection from the local system prior to exfiltration."
    ),
    log_source="auditd",
    mitre_attack=["T1005"],
    sigma_yaml="""\
title: Sensitive File Access - Local Credential / Config Read
id: 3b0c5d69-8e4f-4a2b-8c7d-4e5f60718293
status: experimental
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: SYSCALL
        syscall:
            - open
            - openat
        name:
            - '/etc/passwd'
            - '/etc/shadow'
            - '/etc/sudoers'
            - '/root/.ssh/id_rsa'
    condition: selection
falsepositives:
    - Backup and configuration-management tooling
level: medium
""",
)

# --------------------------------------------------------------------------- #
# Lookup table                                                                 #
# --------------------------------------------------------------------------- #
# Keys are lowercase substrings matched against the caller's input. Order is
# deterministic; the first key contained in the input wins.
_SIGNATURES: dict[str, DetectionSignature] = {
    "nmap": NMAP_PORT_SCAN,
    "port-scan": NMAP_PORT_SCAN,
    "portscan": NMAP_PORT_SCAN,
    "http-probe": HTTP_PROBE,
    "http": HTTP_PROBE,
    "web": HTTP_PROBE,
    "dirbuster": HTTP_PROBE,
    "gobuster": HTTP_PROBE,
    "cve": CVE_EXPLOIT,
    "exploit": CVE_EXPLOIT,
    "smb": SMB_ENUM,
    "loot": LOOT_EXFIL,
    "exfil": LOOT_EXFIL,
}


# --------------------------------------------------------------------------- #
# Public API                                                                   #
# --------------------------------------------------------------------------- #
def signature_for(key: str) -> DetectionSignature | None:
    """Return the detection signature matching ``key``, or ``None``.

    Matching is case-insensitive substring: a known key is matched if it appears
    anywhere inside ``key``. For example ``"CVE-2021-41773"`` contains ``"cve"``
    and therefore maps to the exploitation signature.
    """
    if not key:
        return None
    haystack = key.lower()
    for known, sig in _SIGNATURES.items():
        if known in haystack:
            return sig
    return None


def enrich(finding: Finding) -> Finding:
    """Attach a detection signature to ``finding`` if one matches.

    The lookup key is derived, in priority order, from the finding's
    ``source_tool``, then its ``cve``, then its ``title``. The first field that
    yields a match sets ``finding.detection``. The (mutated) finding is returned
    for convenient chaining.
    """
    for candidate in (finding.source_tool, finding.cve, finding.title):
        if not candidate:
            continue
        sig = signature_for(candidate)
        if sig is not None:
            finding.detection = sig
            break
    return finding


def enrich_all(findings: list[Finding]) -> list[Finding]:
    """Enrich every finding in ``findings`` in place and return the same list."""
    for finding in findings:
        enrich(finding)
    return findings


__all__ = [
    "signature_for",
    "enrich",
    "enrich_all",
    "NMAP_PORT_SCAN",
    "HTTP_PROBE",
    "CVE_EXPLOIT",
    "SMB_ENUM",
    "LOOT_EXFIL",
]

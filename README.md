<h1 align="center">PRAETOR</h1>
<p align="center"><b>Policy-governed Reconnaissance, Exploitation And Testing ORchestrator</b></p>
<p align="center">
An LLM-driven <b>autonomous penetration-testing orchestrator</b> that you can actually run safely —
because scope, phase limits, destructive-action confirmation, and a full audit trail are built into its core,
and every offensive action ships with the <b>blue-team detection</b> it would trip.
</p>

<p align="center">
<a href="#quickstart">Quickstart</a> ·
<a href="#why-praetor-is-different">Why it's different</a> ·
<a href="#how-it-works">How it works</a> ·
<a href="#governance">Governance</a> ·
<a href="#safety--legal">Safety</a>
</p>

---

> **Authorized use only.** PRAETOR is for systems you own or have **written permission** to test, and for CTF / lab environments. The scope file *is* the authorization boundary — the tool refuses to touch anything outside it, and refuses to run at all without an explicit `authorized: true` attestation. See [Safety & legal](#safety--legal).

## What it is

Point PRAETOR at a **scope file** and it drives a full engagement autonomously:

```
recon ──▶ scan ──▶ exploit ──▶ loot ──▶ report
   │        │         │          │         │
   └── every step is gated by scope + phase + destructive policy,
       logged to an append-only audit trail, and mirrored into the
       blue-team detection a defender would have seen.
```

It orchestrates the standard toolchain (`nmap`, `nuclei`, `httpx`, `ffuf`, …) when those tools are installed, and falls back to a **deterministic simulator** so the entire chain — and the whole test suite — runs offline with zero external dependencies.

## Why PRAETOR is different

The current crop of autonomous pentest frameworks optimizes for raw power. PRAETOR optimizes for **governed, auditable autonomy** and **purple-team value**:

| | Typical autonomous pentest tool | **PRAETOR** |
|---|---|---|
| Scope enforcement | often advisory | **hard gate** — out-of-scope targets are refused, not scanned |
| Authorization | implicit | **explicit `authorized: true` attestation required to run** |
| Destructive actions | just runs | **policy + confirmation gate**, off by default |
| Auditability | logs, maybe | **append-only JSONL of every action, decision, and result** |
| Defensive value | none | **blue-team mirror** — every action emits its MITRE ATT&CK id + Sigma rule |
| Runs with no tools installed | no | **yes** — deterministic simulator mode |
| LLM outage / no key | breaks | **degrades to a deterministic planner** |

The **blue-team mirror** is the headline: PRAETOR is simultaneously an attacker *and* a detection-engineering teaching tool. Run it against a lab box and it hands you the Sigma rules and log sources that would have caught it.

## Quickstart

```bash
git clone https://github.com/Danush-Aries/praetor && cd praetor
uv venv && uv pip install -e .          # or: pip install -e .

# 1. See what tools you have
praetor tools

# 2. Validate a scope (dry, no scanning)
praetor scope-check -s scope.example.yaml

# 3. Run fully offline against the built-in simulated lab (no tools, no network)
praetor run -s scope.example.yaml --offline --yes

# 4. Real recon against nmap's permission-granted test host
praetor recon -s scope.example.yaml
```

Every run writes `praetor-audit.jsonl` (the audit trail) and `praetor-report/` (Markdown + JSON + **SARIF 2.1**).

## How it works

```
                    ┌──────────────────────────────────────────────┐
   scope.yaml ─────▶│  Orchestrator loop  (recon→scan→exploit→loot) │
                    │                                               │
   Planner ────────▶│  1. build candidate actions (wrappers / sim)  │
   (LLM or          │  2. planner orders / selects                  │
    deterministic)  │  3. ── Gate ──▶ scope? phase? destructive?    │──▶ block / allow
                    │  4. ToolRunner (argv, no shell) or simulator  │
                    │  5. parse → findings → blue-team enrich       │
                    │  6. append to audit log                       │
                    └───────────────────────┬──────────────────────┘
                                             ▼
                              report.md · report.json · report.sarif.json
```

- **Planner** — an LLM (Anthropic/OpenAI, auto-detected from env keys) orders candidate actions and decides escalation; with no key it transparently falls back to a deterministic planner.
- **Tool wrappers** — uniform `build()/parse()` interface around real CLIs; `nmap` output is parsed into structured findings.
- **Simulator** — deterministic vulnerable lab (`*.lab` hosts) so the exploit chain is reproducible for demos and CI.

## Governance

The scope file is the contract:

```yaml
name: "local-lab-demo"
mode: lab                 # lab = full chain permitted; authorized = conservative
authorized: true          # explicit attestation — REQUIRED to run
max_phase: exploit        # recon | scan | exploit | loot | report
allow_destructive: false  # writes/deletes/submits need this + confirmation
allow_hosts:  [scanme.nmap.org, localhost]
allow_cidrs:  [127.0.0.0/8, 10.0.2.0/24]
deny_hosts:   []          # always-block wins over allow
targets:      [scanme.nmap.org, http://localhost:8080]
```

The **Gate** evaluates every action in order — authorization → in-scope → phase ceiling → destructive policy — and records an allow/block decision (with a human-readable reason) to the audit log before anything executes.

## Safety & legal

PRAETOR is a **defensive-minded offensive tool** built for authorized engagements, CTFs, and labs. Scanning or exploiting systems you do not own or have explicit permission to test is illegal in most jurisdictions. The author does not condone unauthorized use. The scope gate and audit trail exist precisely to keep usage lawful and accountable — do not remove them.

## License

MIT — see [LICENSE](LICENSE).


---

<p align="center">
  <b>⭐ If this project helps you, star it</b> — stars are how open-source tools get found, and every one directly supports more development.
  <br/><sub>· Found a bug? Open an <a href="https://github.com/Danush-Aries/praetor/issues">issue</a> · Want to chat? <a href="https://github.com/Danush-Aries/praetor/discussions">Discussions</a> · Contribute? See <a href="https://github.com/Danush-Aries/praetor/blob/main/CONTRIBUTING.md">CONTRIBUTING.md</a> ·</sub>
</p>


"""PRAETOR command-line interface.

    praetor scope-check -s scope.yaml     # validate scope + show in/out targets
    praetor tools                         # which pentest CLIs are installed
    praetor recon    -s scope.yaml        # recon only
    praetor scan     -s scope.yaml        # recon -> scan
    praetor exploit  -s scope.yaml --yes  # full chain (lab), auto-confirm destructive
    praetor run      -s scope.yaml        # run up to the scope's max_phase
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .config import Phase, ScopeError, Settings, load_scope
from .models import Action, EngagementState

app = typer.Typer(add_completion=False, help="PRAETOR — governed autonomous pentest orchestrator.")
console = Console()

_SEV_STYLE = {
    "critical": "bold white on red", "high": "red",
    "medium": "yellow", "low": "cyan", "info": "dim",
}


def _banner() -> None:
    console.print(Panel.fit(
        "[bold]PRAETOR[/bold] [dim]v%s[/dim]\n"
        "[dim]Policy-governed Reconnaissance, Exploitation And Testing ORchestrator[/dim]" % __version__,
        border_style="magenta"))


@app.command()
def version() -> None:
    """Print version."""
    console.print(f"praetor {__version__}")


@app.command()
def tools() -> None:
    """Show which supported pentest CLIs are installed."""
    from .tools.detect import available_tools
    t = Table(title="Detected tools")
    t.add_column("tool")
    t.add_column("status")
    for name, ok in available_tools().items():
        t.add_row(name, "[green]installed[/green]" if ok else "[dim]missing[/dim]")
    console.print(t)


@app.command("scope-check")
def scope_check(scope: Path = typer.Option(..., "-s", "--scope", help="scope.yaml path")) -> None:
    """Validate a scope file and show which targets are in/out of scope."""
    try:
        sc = load_scope(scope)
    except ScopeError as e:
        console.print(f"[red]scope error:[/red] {e}")
        raise typer.Exit(2)
    console.print(f"[bold]{sc.name}[/bold]  mode=[cyan]{sc.mode.value}[/cyan]  "
                  f"authorized=[{'green' if sc.authorized else 'red'}]{sc.authorized}[/]  "
                  f"max_phase=[cyan]{sc.max_phase.value}[/cyan]  "
                  f"allow_destructive={sc.allow_destructive}")
    t = Table(title="Targets")
    t.add_column("target")
    t.add_column("in scope")
    for tg in sc.parsed_targets():
        t.add_row(tg.raw, "[green]yes[/green]" if tg.in_scope else "[red]no[/red]")
    console.print(t)
    if not sc.authorized:
        console.print("[red]refusing to run:[/red] scope.authorized is not true")
        raise typer.Exit(2)


def _confirm(action: Action) -> bool:
    return typer.confirm(f"  destructive action {action.tool} -> {action.target}. proceed?",
                         default=False)


def _run(scope_path: Path, offline: bool, yes: bool, max_phase: Optional[str],
         audit: Path, report_dir: Path) -> EngagementState:
    from .agents.orchestrator import Orchestrator
    try:
        sc = load_scope(scope_path)
    except ScopeError as e:
        console.print(f"[red]scope error:[/red] {e}")
        raise typer.Exit(2)
    if max_phase:
        capped = Phase(max_phase.lower())
        if capped.rank < sc.max_phase.rank:
            sc.max_phase = capped

    settings = Settings(audit_path=audit, report_dir=report_dir)
    confirm_fn = (lambda a: True) if yes else _confirm

    _banner()
    console.print(f"[dim]engagement[/dim] [bold]{sc.name}[/bold]  "
                  f"[dim]mode[/dim] {sc.mode.value}  [dim]max_phase[/dim] {sc.max_phase.value}"
                  + ("  [yellow](offline/simulated)[/yellow]" if offline else ""))

    def on_event(kind: str, payload: dict) -> None:
        if kind == "scope.filter" and payload.get("dropped"):
            console.print(f"  [red]out of scope, dropped:[/red] {', '.join(payload['dropped'])}")
        elif kind == "phase.start":
            console.print(f"[bold magenta]▸ {payload['phase']}[/bold magenta] "
                          f"[dim]({payload['candidates']} candidate actions)[/dim]")
        elif kind == "action.done":
            if payload.get("blocked"):
                console.print(f"    [yellow]⛔ blocked[/yellow] {payload['tool']} -> "
                              f"{payload['target']}  [dim]{payload['blocked']}[/dim]")
            else:
                mark = "[green]✓[/green]" if payload["ok"] else "[red]✗[/red]"
                console.print(f"    {mark} {payload['tool']} -> {payload['target']}  "
                              f"[dim]{payload['findings']} findings[/dim]")
        elif kind == "report.written":
            console.print(f"  [dim]report:[/dim] {payload.get('markdown')}")

    orch = Orchestrator(sc, settings, confirm_fn=confirm_fn, offline=offline, on_event=on_event)
    state = orch.run()
    _summary(state, audit)
    return state


def _summary(state: EngagementState, audit: Path) -> None:
    counts: dict[str, int] = {}
    for f in state.findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    t = Table(title=f"Findings — {state.name}")
    t.add_column("severity")
    t.add_column("count", justify="right")
    for sev in ["critical", "high", "medium", "low", "info"]:
        if counts.get(sev):
            t.add_row(f"[{_SEV_STYLE[sev]}]{sev}[/]", str(counts[sev]))
    console.print(t)
    n_det = sum(1 for f in state.findings if f.detection is not None)
    console.print(f"[dim]total findings[/dim] {len(state.findings)}  "
                  f"[dim]with blue-team detections[/dim] {n_det}  "
                  f"[dim]audit[/dim] {audit}")


# --- phase commands (thin wrappers over _run) ----------------------------
def _phase_cmd(name: str):
    def cmd(
        scope: Path = typer.Option(..., "-s", "--scope"),
        offline: bool = typer.Option(False, "--offline", help="force deterministic simulator"),
        yes: bool = typer.Option(False, "--yes", help="auto-confirm destructive actions"),
        audit: Path = typer.Option(Path("praetor-audit.jsonl"), "--audit"),
        report_dir: Path = typer.Option(Path("praetor-report"), "--report-dir"),
    ) -> None:
        _run(scope, offline, yes, name, audit, report_dir)
    return cmd


app.command("recon", help="Run recon phase.")(_phase_cmd("recon"))
app.command("scan", help="Run through scan phase.")(_phase_cmd("scan"))
app.command("exploit", help="Run the full chain through exploit (lab).")(_phase_cmd("exploit"))


@app.command()
def run(
    scope: Path = typer.Option(..., "-s", "--scope"),
    offline: bool = typer.Option(False, "--offline", help="force deterministic simulator (no external tools)"),
    yes: bool = typer.Option(False, "--yes", help="auto-confirm destructive actions"),
    max_phase: Optional[str] = typer.Option(None, "--max-phase", help="cap phase: recon|scan|exploit|loot"),
    audit: Path = typer.Option(Path("praetor-audit.jsonl"), "--audit"),
    report_dir: Path = typer.Option(Path("praetor-report"), "--report-dir"),
) -> None:
    """Run an engagement up to the scope's max_phase (or --max-phase)."""
    _run(scope, offline, yes, max_phase, audit, report_dir)


if __name__ == "__main__":
    app()

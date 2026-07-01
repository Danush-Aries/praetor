"""The orchestration loop — PRAETOR's spine.

Per phase (recon -> scan -> exploit -> loot), for every in-scope target it:
  1. builds candidate actions (real tool wrappers, or the deterministic simulator
     for `.lab` hosts / --offline runs),
  2. lets the planner order/select them,
  3. runs each through the governance Gate (scope + phase + destructive checks),
  4. executes allowed actions and enriches findings with blue-team detections,
  5. records everything to the JSONL audit log,
then asks the planner whether to escalate. Finally it writes the report.

Cross-module imports are deferred to call time so this module stays importable
even while sibling modules are being built.
"""
from __future__ import annotations

from typing import Callable, Optional

from ..config import Scope, Settings
from ..models import Action, EngagementState, Observation, Phase, Target
from .planner import Planner, make_planner

ConfirmFn = Callable[[Action], bool]

_PHASE_ORDER = [Phase.RECON, Phase.SCAN, Phase.EXPLOIT, Phase.LOOT]


class Orchestrator:
    def __init__(
        self,
        scope: Scope,
        settings: Settings,
        planner: Optional[Planner] = None,
        confirm_fn: Optional[ConfirmFn] = None,
        offline: bool = False,
        on_event: Optional[Callable[[str, dict], None]] = None,
    ):
        self.scope = scope
        self.settings = settings
        self.planner = planner if planner is not None else make_planner(settings)
        self.confirm_fn = confirm_fn
        self.offline = offline
        self.on_event = on_event or (lambda kind, payload: None)

        # Deferred imports — resolved once, here.
        from ..governance.audit import AuditLogger
        from ..governance.gate import Gate
        from ..tools.runner import ToolRunner
        from .. import blueteam  # noqa: F401  (ensure package import)

        self._Gate = Gate
        self.audit = AuditLogger(settings.audit_path)
        self.gate = Gate(scope, settings)
        self.runner = ToolRunner(settings.tool_timeout_s)

    # ------------------------------------------------------------------
    def run(self) -> EngagementState:
        state = EngagementState(
            name=self.scope.name,
            mode=self.scope.mode,
            max_phase=self.scope.max_phase,
            targets=self.scope.parsed_targets(),
        )
        self.audit = self._reopen_audit(state.id)
        self.on_event("engagement.start", {"name": state.name, "mode": state.mode.value,
                                            "max_phase": state.max_phase.value,
                                            "targets": [t.raw for t in state.targets]})

        in_scope = [t for t in state.targets if t.in_scope]
        self.on_event("scope.filter", {"in_scope": [t.raw for t in in_scope],
                                        "dropped": [t.raw for t in state.targets if not t.in_scope]})

        steps = 0
        for phase in _PHASE_ORDER:
            if phase.rank > state.max_phase.rank:
                break
            candidates = self._candidates(state, phase, in_scope)
            candidates = self.planner.prioritize(state, phase, candidates)
            self.on_event("phase.start", {"phase": phase.value, "candidates": len(candidates)})

            for action in candidates:
                if steps >= self.settings.max_steps:
                    self.on_event("budget.exhausted", {"max_steps": self.settings.max_steps})
                    break
                steps += 1
                state.actions.append(action)
                obs = self._gated_execute(action)
                state.observations.append(obs)
                if obs.findings:
                    from ..blueteam.signatures import enrich_all
                    obs.findings = enrich_all(obs.findings)
                    state.add_findings(obs.findings)
                self.audit.observation(obs)
                self.on_event("action.done", {"tool": action.tool, "target": action.target,
                                              "ok": obs.ok, "blocked": obs.blocked_reason,
                                              "findings": len(obs.findings)})

            next_idx = _PHASE_ORDER.index(phase) + 1
            if next_idx < len(_PHASE_ORDER):
                nxt = _PHASE_ORDER[next_idx]
                if not self.planner.should_escalate(state, nxt):
                    self.on_event("phase.halt", {"after": phase.value})
                    break

        self._write_report(state)
        self.audit.event("engagement.end", {"findings": len(state.findings)})
        self.audit.close()
        return state

    # ------------------------------------------------------------------
    def _candidates(self, state: EngagementState, phase: Phase,
                    targets: list[Target]) -> list[Action]:
        from ..tools import simulator, wrappers

        actions: list[Action] = []
        for t in targets:
            if self.offline or simulator.is_simulated(t.raw):
                actions.extend(simulator.sim_actions(t, phase))
                continue
            applicable = [w for w in wrappers.wrappers_for_phase(phase)
                          if w.available() and w.applies_to(t)]
            if not applicable:
                # Real target, no real tool installed for this phase: SKIP.
                # PRAETOR never fabricates findings against a real host — the
                # simulator only runs for explicit *.lab hosts or --offline.
                self.on_event("phase.skip", {"phase": phase.value, "target": t.raw,
                                             "reason": "no installed tool for this phase"})
                continue
            for w in applicable:
                actions.append(w.build(t))
        return actions

    def _gated_execute(self, action: Action) -> Observation:
        self.audit.action(action)
        decision = self.gate.evaluate(action, self.confirm_fn)
        self.audit.decision(action.id, decision.allowed, decision.reason)
        if not decision.allowed:
            return Observation(action_id=action.id, ok=False,
                               blocked_reason=decision.reason)
        return self._execute(action)

    def _execute(self, action: Action) -> Observation:
        from ..tools import simulator, wrappers

        if action.tool == "sim":
            return simulator.simulate(action)

        # argv-less wrappers (e.g. http-probe) execute themselves.
        if not action.argv:
            for w in wrappers.REGISTRY:
                if getattr(w, "name", "") == action.tool and hasattr(w, "probe"):
                    tgt = Target(raw=action.target)
                    findings = w.probe(tgt)  # type: ignore[attr-defined]
                    return Observation(action_id=action.id, ok=True, findings=findings)
            return Observation(action_id=action.id, ok=False, error="no executor for action")

        obs = self.runner.run(action)
        # Let the matching wrapper parse raw output into findings.
        for w in wrappers.REGISTRY:
            if getattr(w, "name", "") == action.tool and obs.ok:
                obs.findings = w.parse(obs.raw_output, Target(raw=action.target))
                break
        return obs

    def _write_report(self, state: EngagementState) -> None:
        from ..report import render
        paths = render.write_report(state, self.settings.report_dir)
        self.on_event("report.written", {k: str(v) for k, v in paths.items()})

    def _reopen_audit(self, engagement_id: str):
        from ..governance.audit import AuditLogger
        return AuditLogger(self.settings.audit_path, engagement_id)

"""Tests for the defense-in-depth policy gate."""
from __future__ import annotations

from praetor.config import Scope, Settings
from praetor.governance.gate import Gate, GateDecision
from praetor.models import Action, Mode, Phase


def _scope(**overrides) -> Scope:
    base = dict(
        name="test-engagement",
        mode=Mode.AUTHORIZED,
        authorized=True,
        allow_hosts=["target.example.com"],
        allow_domains=["example.com"],
        allow_cidrs=["10.0.0.0/24"],
        deny_hosts=["forbidden.example.com"],
        max_phase=Phase.SCAN,
        allow_destructive=False,
    )
    base.update(overrides)
    return Scope(**base)


def _settings(**overrides) -> Settings:
    s = Settings()
    for k, v in overrides.items():
        setattr(s, k, v)
    return s


def _recon(target: str = "target.example.com", **kw) -> Action:
    return Action(phase=Phase.RECON, tool="nmap", target=target, **kw)


def _assert_decision(dec: GateDecision) -> None:
    assert isinstance(dec, GateDecision)
    assert isinstance(dec.reason, str)
    assert dec.reason  # non-empty


def test_unauthorized_scope_blocks() -> None:
    gate = Gate(_scope(authorized=False), _settings())
    dec = gate.evaluate(_recon())
    _assert_decision(dec)
    assert dec.allowed is False
    assert "not authorized" in dec.reason


def test_out_of_scope_target_blocks() -> None:
    gate = Gate(_scope(), _settings())
    dec = gate.evaluate(_recon(target="notallowed.other.com"))
    _assert_decision(dec)
    assert dec.allowed is False
    assert "out of scope" in dec.reason


def test_phase_over_max_phase_blocks() -> None:
    gate = Gate(_scope(max_phase=Phase.SCAN), _settings())
    action = Action(phase=Phase.EXPLOIT, tool="msf", target="target.example.com")
    dec = gate.evaluate(action)
    _assert_decision(dec)
    assert dec.allowed is False
    assert "exceeds max_phase" in dec.reason


def test_destructive_blocked_when_not_allowed() -> None:
    gate = Gate(_scope(allow_destructive=False), _settings())
    action = Action(
        phase=Phase.SCAN, tool="sqlmap", target="target.example.com", destructive=True
    )
    dec = gate.evaluate(action, confirm_fn=lambda a: True)
    _assert_decision(dec)
    assert dec.allowed is False
    assert "allow_destructive is false" in dec.reason


def test_destructive_allowed_when_confirmed() -> None:
    gate = Gate(
        _scope(allow_destructive=True), _settings(confirm_destructive=True)
    )
    action = Action(
        phase=Phase.SCAN, tool="sqlmap", target="target.example.com", destructive=True
    )
    dec = gate.evaluate(action, confirm_fn=lambda a: True)
    _assert_decision(dec)
    assert dec.allowed is True
    assert dec.reason == "ok"


def test_destructive_blocked_when_confirm_fn_false() -> None:
    gate = Gate(
        _scope(allow_destructive=True), _settings(confirm_destructive=True)
    )
    action = Action(
        phase=Phase.SCAN, tool="sqlmap", target="target.example.com", destructive=True
    )
    dec = gate.evaluate(action, confirm_fn=lambda a: False)
    _assert_decision(dec)
    assert dec.allowed is False
    assert "not confirmed" in dec.reason


def test_destructive_blocked_when_no_confirm_fn() -> None:
    gate = Gate(
        _scope(allow_destructive=True), _settings(confirm_destructive=True)
    )
    action = Action(
        phase=Phase.SCAN, tool="sqlmap", target="target.example.com", destructive=True
    )
    dec = gate.evaluate(action)  # no confirm_fn provided
    _assert_decision(dec)
    assert dec.allowed is False
    assert "not confirmed" in dec.reason


def test_destructive_allowed_when_confirm_disabled() -> None:
    gate = Gate(
        _scope(allow_destructive=True), _settings(confirm_destructive=False)
    )
    action = Action(
        phase=Phase.SCAN, tool="sqlmap", target="target.example.com", destructive=True
    )
    dec = gate.evaluate(action)  # confirmation off, so no confirm_fn needed
    _assert_decision(dec)
    assert dec.allowed is True
    assert dec.reason == "ok"


def test_normal_in_scope_recon_allowed() -> None:
    gate = Gate(_scope(), _settings())
    dec = gate.evaluate(_recon())
    _assert_decision(dec)
    assert dec.allowed is True
    assert dec.reason == "ok"


def test_no_target_action_allowed() -> None:
    gate = Gate(_scope(), _settings())
    action = Action(phase=Phase.RECON, tool="whoami", target="")
    dec = gate.evaluate(action)
    _assert_decision(dec)
    assert dec.allowed is True

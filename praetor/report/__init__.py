"""Reporting: render an engagement into human and machine artifacts.

Markdown for humans, JSON for tooling, and SARIF 2.1.0 for security dashboards.
"""
from __future__ import annotations

from .render import render_json, render_markdown, render_sarif, write_report

__all__ = ["render_markdown", "render_json", "render_sarif", "write_report"]

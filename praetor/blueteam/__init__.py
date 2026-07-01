"""Blue-team detection mirror.

Turns PRAETOR from a pure red-team tool into a purple-team teaching aid: every
offensive :class:`~praetor.models.Finding` can be paired with the
:class:`~praetor.models.DetectionSignature` a defender would have used to catch
it (log source, MITRE ATT&CK technique, and a minimal Sigma rule).
"""
from __future__ import annotations

from .signatures import enrich, enrich_all, signature_for

__all__ = ["signature_for", "enrich", "enrich_all"]

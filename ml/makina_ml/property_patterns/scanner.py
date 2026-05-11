"""Structural property-pattern checks for security-relevant correctness bugs."""

from __future__ import annotations

from .detectors import DETECTORS
from .functions import extract_functions
from .models import Finding
from .utils import dedupe


def analyze(code: str, language: str | None = None) -> dict:
    lang = (language or "unknown").lower()
    findings = _analyze_functions(code.splitlines(), lang)
    return {
        "status": "ok",
        "language": lang,
        "findings": [finding.as_dict() for finding in dedupe(findings)],
    }


def _analyze_functions(lines: list[str], language: str) -> list[Finding]:
    findings: list[Finding] = []
    for fn in extract_functions(lines, language):
        for detector in DETECTORS:
            findings.extend(detector(fn, language))
    return findings

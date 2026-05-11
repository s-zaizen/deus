"""Shared data types for structural property-pattern checks."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FunctionBlock:
    name: str
    params: list[str]
    start_line: int
    end_line: int
    lines: list[str]


@dataclass(frozen=True)
class Finding:
    rule_id: str
    message: str
    severity: str
    line_start: int
    line_end: int
    code_snippet: str
    confidence: float
    cwe: str | None

    def as_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "message": self.message,
            "severity": self.severity,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "code_snippet": self.code_snippet,
            "confidence": self.confidence,
            "cwe": self.cwe,
        }

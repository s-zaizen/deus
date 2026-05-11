"""Small shared helpers for property-pattern detectors."""

from __future__ import annotations

from .models import Finding


def snippet(lines: list[str], start_line: int, end_line: int, base_line: int) -> str:
    start_idx = max(0, start_line - base_line)
    end_idx = min(len(lines), end_line - base_line + 1)
    return "\n".join(lines[start_idx:end_idx])[:600]


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, int, int]] = set()
    out: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.line_start, finding.line_end)
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out

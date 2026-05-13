from __future__ import annotations

from pathlib import Path

from makina_ml import semgrep_scanner


def _semgrep_result(line: int) -> dict:
    return {
        "check_id": "custom.taint-python-sqli",
        "start": {"line": line},
        "end": {"line": line},
        "extra": {
            "message": "SQL Injection (taint)",
            "metadata": {"cwe": "CWE-89"},
            "severity": "ERROR",
        },
    }


def test_parse_suppresses_parameterized_sql_taint_result():
    lines = [
        "def handler(cursor, name):",
        '    cursor.execute("SELECT id FROM users WHERE name = ?", (name,))',
    ]

    findings = semgrep_scanner._parse([_semgrep_result(2)], Path("/rules"), lines)

    assert findings == []


def test_parse_keeps_unsafe_sql_taint_result():
    lines = [
        "def handler(cursor, name):",
        "    query = f\"SELECT id FROM users WHERE name = '{name}'\"",
        "    cursor.execute(query)",
    ]

    findings = semgrep_scanner._parse([_semgrep_result(2)], Path("/rules"), lines)

    assert len(findings) == 1
    assert findings[0]["cwe"] == "CWE-89"

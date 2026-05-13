"""Shared SQL sink safety helpers.

These helpers intentionally stay conservative: they only suppress a SQL
sink when the call visibly uses a placeholder-bearing query string and a
separate argument vector/value. Unknown shapes remain reportable.
"""

from __future__ import annotations

import re

_SQL_SINK_PATTERN = re.compile(
    r"\.(?:execute|executemany|query|prepare|raw|Query|QueryRow|Exec)\s*\(",
    re.MULTILINE,
)

_SQL_PLACEHOLDER = r"(?:\?|%s|:\w+|\$\d+)"
_QUOTED_SQL = rf"(?:[rubfRUBF]{{0,4}}(['\"])(?:(?!\1).)*{_SQL_PLACEHOLDER}(?:(?!\1).)*\1|`[^`]*{_SQL_PLACEHOLDER}[^`]*`)"
_PARAMETERIZED_SQL_CALL = re.compile(
    rf"^\.(?:execute|executemany|query|prepare|raw|Query|QueryRow|Exec)\s*\(\s*{_QUOTED_SQL}\s*,",
    re.DOTALL,
)
_GO_URL_QUERY_ACCESSOR = re.compile(r"^\.Query\s*\(\s*\)\s*\.\s*Get\s*\(")


def is_safe_parameterized_sql_call(fragment: str) -> bool:
    """Return true for common DB-API / JS / Go parameterized SQL calls."""
    return bool(_PARAMETERIZED_SQL_CALL.search(fragment))


def is_safe_parameterized_sql_line(line: str, start: int = 0) -> bool:
    return is_safe_parameterized_sql_call(line[start : start + 400])


def is_non_sql_query_accessor(fragment: str) -> bool:
    return bool(_GO_URL_QUERY_ACCESSOR.search(fragment))


def has_unsafe_sql_sink(source: str) -> bool:
    """Return true if a function body contains a SQL sink not visibly safe."""
    for match in _SQL_SINK_PATTERN.finditer(source):
        fragment = source[match.start() : match.start() + 400]
        if is_non_sql_query_accessor(fragment):
            continue
        if not is_safe_parameterized_sql_call(fragment):
            return True
    return False

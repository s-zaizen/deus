"""Detector rules for structural correctness and security patterns."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable

from .models import Finding, FunctionBlock
from .utils import snippet

Detector = Callable[[FunctionBlock, str], list[Finding]]

_SECURITY_CONTEXT_RE = re.compile(
    r"\b("
    r"verify|validate|valid|proof|signature|commit|challenge|hash|auth|"
    r"token|credential|permission|access|dedup|cache|memo|parse|decode"
    r")\w*",
    re.IGNORECASE,
)
_CACHE_WORD_RE = re.compile(
    r"\b(cache|cached|memo|memoized|dedup|seen|visited|lru|sync\.Map|HashMap|map\[)",
    re.IGNORECASE,
)
_KEY_ASSIGN_RE = re.compile(
    r"\b(?:cache_?key|dedup_?key|lookup_?key|memo_?key|key)\s*(?::=|=|:)\s*(.+)"
)
_KEY_CALL_RE = re.compile(
    r"\b(?:hash|sha\d*|digest|serialize|format|join)\s*\((.+)\)",
    re.IGNORECASE,
)

_PY_RANGE_LEN_RE = re.compile(
    r"\bfor\s+([A-Za-z_]\w*)\s+in\s+range\s*\(\s*len\s*\(\s*([A-Za-z_]\w*)\s*\)\s*\)"
)
_JS_LEN_LOOP_RE = re.compile(
    r"\bfor\s*\([^;]*\b([A-Za-z_]\w*)\s*=\s*0\s*;"
    r"[^;]*\b\1\s*<\s*([A-Za-z_]\w*)\.length\b"
)
_GO_RANGE_RE = re.compile(
    r"\bfor\s+([A-Za-z_]\w*)(?:\s*,\s*[A-Za-z_]\w*)?\s*"
    r"(?::=|=)\s*range\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)"
)
_GO_LEN_LOOP_RE = re.compile(
    r"\bfor\s+([A-Za-z_]\w*)\s*:=\s*0\s*;"
    r"\s*\1\s*<\s*len\s*\(\s*([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*\)"
)
_RUST_LEN_LOOP_RE = re.compile(
    r"\bfor\s+([A-Za-z_]\w*)\s+in\s+0\s*\.\.\s*([A-Za-z_]\w*)\.len\s*\(\s*\)"
)

_MUTABLE_CALL_RE = re.compile(
    r"\b((?:[A-Za-z_]\w*\.)*"
    r"(?:(?:get_?)?(?:current|latest|state|config|balance|nonce|epoch|"
    r"height|header|version|capabilit\w*)|read|load|fetch)\w*"
    r"\s*\([^;\n]*\))",
    re.IGNORECASE,
)
_MUTABLE_NAME_RE = re.compile(
    r"(current|latest|state|config|balance|nonce|epoch|height|header|version|"
    r"capabilit)",
    re.IGNORECASE,
)
_SIDE_EFFECT_RE = re.compile(
    r"\b(await|yield|sleep|send|write|save|update|delete|insert|commit|lock|"
    r"unlock|request|fetch|http|rpc|execute|exec|emit)\b|"
    r"\b[A-Za-z_]\w*\s*\(",
    re.IGNORECASE,
)
_PURE_CALL_PREFIXES = (
    "len(",
    "str(",
    "int(",
    "float(",
    "bool(",
    "list(",
    "dict(",
    "set(",
    "tuple(",
)
_GO_BOOL_ERR_RE = re.compile(
    r"^\s*([A-Za-z_]\w*)\s*,\s*([A-Za-z_]\w*)\s*(?::=|=)\s*"
    r"([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*\(",
    re.IGNORECASE,
)
_VERIFY_LIKE_RE = re.compile(r"(verify|validate|check)", re.IGNORECASE)
_BOOL_RESULT_NAME_RE = re.compile(
    r"^(ok|valid|verified|allowed|accepted|trusted|matched|authorized|"
    r"authenticated|is[A-Z_].*|has[A-Z_].*|can[A-Z_].*)$",
    re.IGNORECASE,
)
_UNBOUNDED_ALLOC_RE = re.compile(
    r"\b(?:make\s*\(\s*\[\][^,]+,\s*|new\s+Array\s*\(|range\s*\(|"
    r"Vec::with_capacity\s*\(|with_capacity\s*\()\s*([A-Za-z_]\w*)",
    re.IGNORECASE,
)
_SIZE_NAME_RE = re.compile(
    r"(count|size|length|len|limit|num|capacity|cap|total)", re.IGNORECASE
)
_EXTERNAL_SOURCE_RE = re.compile(
    r"\b(req|request|param|params|query|body|header|peer|remote|message|msg|"
    r"payload|packet|input|user)\b|\.Header|\.Query|\.Body",
    re.IGNORECASE,
)
_UPPER_LIMIT_RE = (
    r"(?:MAX[A-Za-z0-9_]*|[A-Za-z_]\w*MAX[A-Za-z0-9_]*|"
    r"[A-Za-z_]\w*_MAX|[A-Za-z_]\w*Limit|[A-Za-z_]\w*_LIMIT|[0-9][0-9_]*)"
)
_COMMAND_EXECUTOR_NAME_RE = re.compile(
    r"(^|[_.$>])(?:cmd|command|shell|exec(?:ute)?|eval(?:uate)?|"
    r"interpret|interpreter|script|dispatch|run|invoke)(?:$|[_.$>])|"
    r"call_str",
    re.IGNORECASE,
)
_FORMAT_ONLY_NAME_RE = re.compile(
    r"(^|[_.$>])(?:printf|sprintf|snprintf|asprintf|vasprintf|format|"
    r"fmt|strdup|free|malloc|calloc|realloc)(?:$|[_.$>])",
    re.IGNORECASE,
)
_FORMAT_TOKEN_RE = re.compile(
    r"%[-+#0-9.*]*(?:hh|h|l|ll|j|z|t|L)?[A-Za-z]|"
    r"\{\s*[A-Za-z_]\w*(?:[^{}]*)\}|\{\}|\$\{",
)
_STRING_LITERAL_RE = re.compile(
    r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`(?:\\.|[^`\\])*`'
)
_CALL_NAME_RE = re.compile(r"\b([A-Za-z_]\w*(?:(?:\.|::|->)[A-Za-z_]\w*)*)\s*\(")
_ASSIGN_RE = re.compile(r"\b([A-Za-z_]\w*)\s*(?::=|=)\s*(.+)")
_SAFE_VALUE_RE = re.compile(
    r"\b(?:sanitize|sanitise|escape|quote|encode|validate|valid|allowlist|"
    r"whitelist|check|filter|clean|canonical)\w*\s*\(",
    re.IGNORECASE,
)


def _detect_incomplete_cache_key(fn: FunctionBlock, language: str) -> list[Finding]:
    del language
    body = "\n".join(fn.lines)
    if len(fn.params) < 2:
        return []
    if not _CACHE_WORD_RE.search(body):
        return []
    if not _SECURITY_CONTEXT_RE.search(fn.name) and not _SECURITY_CONTEXT_RE.search(
        body
    ):
        return []

    used_params = {
        param for param in fn.params if re.search(rf"\b{re.escape(param)}\b", body)
    }
    if len(used_params) < 2:
        return []

    findings: list[Finding] = []
    for offset, line in enumerate(fn.lines, start=fn.start_line):
        key_expr = _extract_key_expression(line)
        if not key_expr:
            continue
        params_in_key = {
            param
            for param in used_params
            if re.search(rf"\b{re.escape(param)}\b", key_expr)
        }
        missing = sorted(used_params - params_in_key)
        if not params_in_key or not missing:
            continue
        if not _near_cache_use(fn.lines, offset - fn.start_line):
            continue

        findings.append(
            Finding(
                rule_id="PROP-CACHE-KEY",
                message=(
                    "Cache or deduplication key may omit security-relevant "
                    f"inputs: {', '.join(missing[:4])}"
                ),
                severity="high",
                line_start=offset,
                line_end=offset,
                code_snippet=snippet(fn.lines, offset, offset, fn.start_line),
                confidence=0.68,
                cwe="CWE-345",
            )
        )
        break
    return findings


def _extract_key_expression(line: str) -> str:
    match = _KEY_ASSIGN_RE.search(line)
    if match:
        return match.group(1)
    match = _KEY_CALL_RE.search(line)
    if match and "key" in line.lower():
        return match.group(1)
    return ""


def _near_cache_use(lines: list[str], idx: int) -> bool:
    start = max(0, idx - 4)
    end = min(len(lines), idx + 8)
    nearby = "\n".join(lines[start:end])
    return bool(_CACHE_WORD_RE.search(nearby))


def _detect_parallel_collection_mismatch(
    fn: FunctionBlock, language: str
) -> list[Finding]:
    del language
    findings: list[Finding] = []
    for local_idx, line in enumerate(fn.lines):
        loop = _match_indexed_loop(line)
        if loop is None:
            continue
        index_var, driver = loop
        window = fn.lines[local_idx : min(len(fn.lines), local_idx + 14)]
        indexed_vars = _indexed_variables(window, index_var)
        targets = sorted(var for var in indexed_vars if var != driver)
        if not targets:
            continue
        if _has_length_guard(fn.lines, local_idx, index_var, driver, targets):
            continue

        line_no = fn.start_line + local_idx
        findings.append(
            Finding(
                rule_id="PROP-LENGTH-PAIR",
                message=(
                    f"Loop is bounded by {driver} but indexes "
                    f"{', '.join(targets[:3])} without a visible length check"
                ),
                severity="medium",
                line_start=line_no,
                line_end=min(fn.end_line, line_no + len(window) - 1),
                code_snippet="\n".join(window[:8])[:500],
                confidence=0.64,
                cwe="CWE-129",
            )
        )
    return findings


def _match_indexed_loop(line: str) -> tuple[str, str] | None:
    for regex in (
        _PY_RANGE_LEN_RE,
        _JS_LEN_LOOP_RE,
        _GO_RANGE_RE,
        _GO_LEN_LOOP_RE,
        _RUST_LEN_LOOP_RE,
    ):
        match = regex.search(line)
        if match:
            index_var, driver = match.group(1), match.group(2)
            if regex in (_GO_RANGE_RE, _GO_LEN_LOOP_RE) and "." in driver:
                return None
            return index_var, driver
    return None


def _indexed_variables(lines: Iterable[str], index_var: str) -> set[str]:
    pattern = re.compile(
        rf"\b([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)"
        rf"\s*\[\s*{re.escape(index_var)}\s*\]"
    )
    found: set[str] = set()
    for line in lines:
        found.update(pattern.findall(line))
    return found


def _has_length_guard(
    lines: list[str],
    loop_idx: int,
    index_var: str,
    driver: str,
    targets: list[str],
) -> bool:
    guard_text = "\n".join(lines[max(0, loop_idx - 10) : loop_idx + 12])
    for target in targets:
        pairs = [
            rf"len\s*\(\s*{driver}\s*\)\s*(?:==|!=)\s*len\s*\(\s*{target}\s*\)",
            rf"len\s*\(\s*{target}\s*\)\s*(?:==|!=)\s*len\s*\(\s*{driver}\s*\)",
            rf"{driver}\.length\s*(?:===|!==|==|!=)\s*{target}\.length",
            rf"{target}\.length\s*(?:===|!==|==|!=)\s*{driver}\.length",
            rf"{driver}\.len\s*\(\s*\)\s*(?:==|!=)\s*{target}\.len\s*\(\s*\)",
            rf"{target}\.len\s*\(\s*\)\s*(?:==|!=)\s*{driver}\.len\s*\(\s*\)",
            rf"{target}\.length\s*>=?\s*{index_var}\s*\+\s*1",
            rf"{index_var}\s*<\s*{target}\.length",
            rf"len\s*\(\s*{target}\s*\)\s*>\s*{index_var}",
            rf"{index_var}\s*<\s*len\s*\(\s*{target}\s*\)",
            rf"{target}\.len\s*\(\s*\)\s*>\s*{index_var}",
            rf"{index_var}\s*<\s*{target}\.len\s*\(\s*\)",
        ]
        if any(re.search(pat, guard_text) for pat in pairs):
            return True
    return False


def _detect_repeated_mutable_reads(fn: FunctionBlock, language: str) -> list[Finding]:
    del language
    calls: dict[str, list[int]] = {}
    for local_idx, line in enumerate(fn.lines):
        for raw in _MUTABLE_CALL_RE.findall(line):
            call = re.sub(r"\s+", "", raw)
            if call.startswith(_PURE_CALL_PREFIXES):
                continue
            if not _MUTABLE_NAME_RE.search(call):
                continue
            calls.setdefault(call, []).append(fn.start_line + local_idx)

    findings: list[Finding] = []
    for call, line_numbers in calls.items():
        unique_lines = list(dict.fromkeys(line_numbers))
        if len(unique_lines) < 2:
            continue
        line_no = unique_lines[0]
        if not _has_interleaving_side_effect(
            fn.lines, unique_lines, fn.start_line, call
        ):
            continue
        findings.append(
            Finding(
                rule_id="PROP-REPEATED-READ",
                message=(
                    f"Repeated mutable read {call} without a local snapshot may "
                    "observe inconsistent state"
                ),
                severity="low",
                line_start=line_no,
                line_end=unique_lines[-1],
                code_snippet=snippet(
                    fn.lines, line_no, unique_lines[-1], fn.start_line
                ),
                confidence=0.52,
                cwe="CWE-367",
            )
        )
    return findings


def _has_interleaving_side_effect(
    lines: list[str], unique_lines: list[int], base_line: int, call: str
) -> bool:
    start_idx = max(0, unique_lines[0] - base_line + 1)
    end_idx = max(start_idx, unique_lines[-1] - base_line)
    for line in lines[start_idx:end_idx]:
        compact = re.sub(r"\s+", "", line)
        if call in compact:
            continue
        if _SIDE_EFFECT_RE.search(line):
            return True
    return False


def _detect_unchecked_go_verifier_result(
    fn: FunctionBlock, language: str
) -> list[Finding]:
    if language != "go":
        return []
    findings: list[Finding] = []
    for local_idx, line in enumerate(fn.lines):
        match = _GO_BOOL_ERR_RE.search(line)
        if not match:
            continue
        ok_var, err_var, callee = match.groups()
        if not _VERIFY_LIKE_RE.search(callee):
            continue
        if ok_var == "_" or not _BOOL_RESULT_NAME_RE.search(ok_var):
            continue
        following = "\n".join(fn.lines[local_idx + 1 : local_idx + 12])
        if re.search(rf"\b{re.escape(ok_var)}\b", following):
            continue
        if not re.search(rf"\b{re.escape(err_var)}\b", following):
            continue
        line_no = fn.start_line + local_idx
        findings.append(
            Finding(
                rule_id="PROP-VERIFY-BOOL",
                message=(
                    f"{callee} boolean result is assigned to {ok_var} but only "
                    f"{err_var} appears to be checked"
                ),
                severity="high",
                line_start=line_no,
                line_end=min(fn.end_line, line_no + 10),
                code_snippet=snippet(
                    fn.lines, line_no, min(fn.end_line, line_no + 10), fn.start_line
                ),
                confidence=0.66,
                cwe="CWE-252",
            )
        )
    return findings


def _detect_unbounded_external_size(fn: FunctionBlock, language: str) -> list[Finding]:
    del language
    findings: list[Finding] = []
    for local_idx, line in enumerate(fn.lines):
        match = _UNBOUNDED_ALLOC_RE.search(line)
        if not match:
            continue
        size_var = match.group(1)
        if not _SIZE_NAME_RE.search(size_var):
            continue
        prior = "\n".join(fn.lines[max(0, local_idx - 8) : local_idx + 1])
        if not _EXTERNAL_SOURCE_RE.search(prior):
            continue
        if _has_upper_bound_guard(prior, size_var):
            continue

        line_no = fn.start_line + local_idx
        findings.append(
            Finding(
                rule_id="PROP-UNBOUNDED-SIZE",
                message=(
                    f"Externally derived size {size_var} controls allocation or "
                    "iteration without a visible upper bound"
                ),
                severity="medium",
                line_start=line_no,
                line_end=line_no,
                code_snippet=snippet(fn.lines, line_no, line_no, fn.start_line),
                confidence=0.58,
                cwe="CWE-770",
            )
        )
    return findings


def _detect_formatted_command_injection(
    fn: FunctionBlock, language: str
) -> list[Finding]:
    del language
    if not fn.params:
        return []

    param_names = [
        param for param in fn.params if len(param) > 1 and not param.startswith("_")
    ]
    if not param_names:
        return []

    findings: list[Finding] = []
    built_command_vars: dict[str, tuple[int, str, str]] = {}
    scan_lines = fn.lines
    scan_start = fn.start_line
    if fn.name != "<module>" and len(fn.lines) > 1:
        scan_lines = fn.lines[1:]
        scan_start = fn.start_line + 1

    for line_no, stmt in _statements(scan_lines, scan_start):
        normalized = _strip_comments(stmt)
        if not normalized.strip():
            continue

        assigned = _assignment_target(normalized)
        param = _formatted_external_param(normalized, param_names)
        if assigned and param:
            built_command_vars[assigned] = (line_no, stmt, param)

        call = _command_executor_call_name(normalized)
        if call is None:
            continue

        direct_param = _formatted_external_param(normalized, param_names)
        if direct_param:
            findings.append(
                _formatted_command_finding(
                    fn, line_no, stmt, direct_param, call, "direct"
                )
            )
            break

        for var, (source_line, source_stmt, source_param) in built_command_vars.items():
            if not re.search(rf"\b{re.escape(var)}\b", normalized):
                continue
            findings.append(
                _formatted_command_finding(
                    fn,
                    source_line,
                    f"{source_stmt.rstrip()}\n{stmt.lstrip()}",
                    source_param,
                    call,
                    "constructed",
                )
            )
            break
        if findings:
            break

    return findings


def _statements(lines: list[str], start_line: int) -> Iterable[tuple[int, str]]:
    pending: list[str] = []
    pending_start = start_line
    paren_depth = 0
    for offset, line in enumerate(lines):
        if not pending:
            pending_start = start_line + offset
        pending.append(line)
        paren_depth += _paren_delta(line)
        stripped = line.rstrip()
        if paren_depth <= 0 and (
            stripped.endswith(";")
            or stripped.endswith(")")
            or stripped.endswith("}")
            or stripped.endswith(":")
        ):
            yield pending_start, "\n".join(pending)
            pending = []
            paren_depth = 0
    if pending:
        yield pending_start, "\n".join(pending)


def _paren_delta(line: str) -> int:
    text = re.sub(_STRING_LITERAL_RE, '""', line)
    return text.count("(") - text.count(")")


def _strip_comments(stmt: str) -> str:
    stripped_lines = []
    for line in stmt.splitlines():
        line = line.split("//", 1)[0]
        stripped_lines.append(line)
    text = "\n".join(stripped_lines)
    return re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)


def _assignment_target(stmt: str) -> str | None:
    first_line = stmt.strip().splitlines()[0] if stmt.strip() else ""
    match = _ASSIGN_RE.search(first_line)
    return match.group(1) if match else None


def _command_executor_call_name(stmt: str) -> str | None:
    for match in _CALL_NAME_RE.finditer(stmt):
        name = match.group(1)
        if _is_command_executor(name):
            return name
    return None


def _is_command_executor(name: str) -> bool:
    if _FORMAT_ONLY_NAME_RE.search(name):
        return False
    return bool(_COMMAND_EXECUTOR_NAME_RE.search(name))


def _formatted_external_param(stmt: str, params: list[str]) -> str | None:
    format_start = _format_construction_start(stmt)
    if format_start is None:
        return None
    concat_construction = _is_concat_construction(stmt)
    for param in params:
        matches = list(re.finditer(rf"\b{re.escape(param)}\b", stmt))
        if not matches:
            continue
        if not concat_construction and all(
            match.start() < format_start for match in matches
        ):
            continue
        if _is_sanitized_use(stmt, param):
            continue
        return param
    return None


def _format_construction_start(stmt: str) -> int | None:
    token_match = _FORMAT_TOKEN_RE.search(stmt)
    if token_match:
        return token_match.start()
    format_call = re.search(
        r"\b(?:format|sprintf|snprintf|asprintf|Sprintf)\s*\(", stmt
    )
    if format_call:
        return format_call.start()
    if _is_concat_construction(stmt):
        return 0
    return None


def _is_concat_construction(stmt: str) -> bool:
    literals = _STRING_LITERAL_RE.findall(stmt)
    if literals and re.search(r'(?:["\'`]\s*\+|\+\s*["\'`])', stmt):
        return True
    return False


def _is_sanitized_use(stmt: str, param: str) -> bool:
    sanitized_call = (
        rf"\b(?:sanitize|sanitise|escape|quote|encode|validate|valid|allowlist|"
        rf"whitelist|check|filter|clean|canonical)\w*\s*\([^)]*\b{re.escape(param)}\b"
    )
    if re.search(sanitized_call, stmt, re.IGNORECASE):
        return True

    prefix = stmt[: max(0, stmt.find(param))]
    return bool(_SAFE_VALUE_RE.search(prefix[-80:]))


def _formatted_command_finding(
    fn: FunctionBlock,
    line_no: int,
    stmt: str,
    param: str,
    sink_name: str,
    mode: str,
) -> Finding:
    flow = "directly" if mode == "direct" else "after command string construction"
    return Finding(
        rule_id="PROP-FORMATTED-COMMAND",
        message=(
            f"Formatted command or interpreter input uses externally derived "
            f"value `{param}` {flow} before `{sink_name}`"
        ),
        severity="critical",
        line_start=line_no,
        line_end=min(fn.end_line, line_no + max(0, len(stmt.splitlines()) - 1)),
        code_snippet=snippet(fn.lines, line_no, line_no, fn.start_line)
        if "\n" not in stmt
        else stmt[:600],
        confidence=0.72,
        cwe="CWE-78",
    )


def _has_upper_bound_guard(text: str, var: str) -> bool:
    clamp_patterns = [
        rf"\bmin\s*\(\s*{re.escape(var)}\s*,",
        rf"\bclamp\s*\(\s*{re.escape(var)}\s*,",
        rf"\b{re.escape(var)}\s*=\s*min\s*\(",
        rf"\b{re.escape(var)}\s*=\s*.*\.min\s*\(",
    ]
    if any(re.search(pattern, text) for pattern in clamp_patterns):
        return True

    named_limit = (
        r"(?:MAX[A-Za-z0-9_]*|[A-Za-z_]\w*MAX[A-Za-z0-9_]*|"
        r"[A-Za-z_]\w*_MAX|[A-Za-z_]\w*Limit|[A-Za-z_]\w*_LIMIT)"
    )
    positive_guard_patterns = [
        rf"\bif\s+{re.escape(var)}\s*<=\s*{named_limit}",
        rf"\bif\s+{named_limit}\s*>=\s*{re.escape(var)}",
    ]
    if any(re.search(pattern, text) for pattern in positive_guard_patterns):
        return True

    rejecting_guard_patterns = [
        rf"\bif\s+{re.escape(var)}\s*>=?\s*{_UPPER_LIMIT_RE}",
        rf"\bif\s+{_UPPER_LIMIT_RE}\s*<\s*{re.escape(var)}",
    ]
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        if not any(re.search(pattern, line) for pattern in rejecting_guard_patterns):
            continue
        branch = _guard_branch(lines, idx)
        if _UNBOUNDED_ALLOC_RE.search(branch):
            continue
        if re.search(
            r"\b(raise|return|break|continue|throw|panic|abort)\b|"
            r"\b(?:Err|error)\s*\(",
            branch,
        ):
            return True
    return False


def _guard_branch(lines: list[str], idx: int) -> str:
    guard = lines[idx]
    branch = [guard]
    suffix = guard.split(":", 1)[1].strip() if ":" in guard else ""
    if suffix:
        return "\n".join(branch)

    guard_indent = len(guard) - len(guard.lstrip(" \t"))
    for line in lines[idx + 1 : min(len(lines), idx + 5)]:
        stripped = line.strip()
        if stripped:
            indent = len(line) - len(line.lstrip(" \t"))
            if indent <= guard_indent:
                break
        branch.append(line)
    return "\n".join(branch)


DETECTORS: tuple[Detector, ...] = (
    _detect_incomplete_cache_key,
    _detect_parallel_collection_mismatch,
    _detect_repeated_mutable_reads,
    _detect_unchecked_go_verifier_result,
    _detect_unbounded_external_size,
    _detect_formatted_command_injection,
)

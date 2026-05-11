"""Lightweight function extraction used by property-pattern detectors."""

from __future__ import annotations

import re

from .models import FunctionBlock

_IGNORE_PARAMS = {
    "self",
    "cls",
    "ctx",
    "context",
    "logger",
    "log",
    "w",
    "r",
    "req",
    "request",
    "res",
    "response",
}

_PY_DEF_RE = re.compile(r"^(\s*)def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*:")
_JS_FUNC_RE = re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\(([^)]*)\)")
_JS_ARROW_RE = re.compile(
    r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_]\w*)\s*=\s*"
    r"(?:async\s*)?\(([^)]*)\)\s*=>\s*\{?"
)
_GO_FUNC_RE = re.compile(r"\bfunc\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(([^)]*)\)")
_RUST_FUNC_RE = re.compile(r"\bfn\s+([A-Za-z_]\w*)\s*\(([^)]*)\)")
_JAVA_FUNC_RE = re.compile(
    r"^\s*(?:public|private|protected|static|final|synchronized|\s)+"
    r"[\w<>\[\], ?]+\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*\{?"
)
_C_FUNC_RE = re.compile(
    r"^\s*(?:static\s+|inline\s+|extern\s+)?"
    r"[A-Za-z_][\w:*<>\[\]\s]*(?:\s+[\w:*<>\[\]]+)*[\s*&]+"
    r"([A-Za-z_]\w*)\s*\(([^;{}]*)\)\s*\{"
)


def extract_functions(lines: list[str], language: str) -> list[FunctionBlock]:
    if language == "python":
        blocks = _extract_python_functions(lines)
    else:
        blocks = _extract_brace_functions(lines, language)

    if blocks:
        return blocks
    return [FunctionBlock("<module>", [], 1, max(1, len(lines)), lines)]


def _extract_python_functions(lines: list[str]) -> list[FunctionBlock]:
    blocks: list[FunctionBlock] = []
    idx = 0
    while idx < len(lines):
        match = _PY_DEF_RE.match(lines[idx])
        if not match:
            idx += 1
            continue

        indent = len(match.group(1).replace("\t", "    "))
        name = match.group(2)
        params = _parse_params(match.group(3), "python")
        end = idx + 1
        probe = idx + 1
        while probe < len(lines):
            stripped = lines[probe].strip()
            if stripped:
                probe_indent = len(lines[probe]) - len(lines[probe].lstrip(" \t"))
                if probe_indent <= indent and not lines[probe].lstrip().startswith("#"):
                    break
            end = probe + 1
            probe += 1

        blocks.append(FunctionBlock(name, params, idx + 1, end, lines[idx:end]))
        idx = max(probe, idx + 1)
    return blocks


def _extract_brace_functions(lines: list[str], language: str) -> list[FunctionBlock]:
    regexes = _function_regexes(language)
    blocks: list[FunctionBlock] = []
    idx = 0
    while idx < len(lines):
        line = lines[idx]
        matched = _match_function_signature(line, regexes)
        if not matched:
            idx += 1
            continue

        name = matched.group(1)
        params = _parse_params(matched.group(2), language)
        start = idx
        brace_count = line.count("{") - line.count("}")
        probe = idx + 1
        while probe < len(lines):
            brace_count += lines[probe].count("{") - lines[probe].count("}")
            if brace_count <= 0 and "{" in "\n".join(lines[start : probe + 1]):
                break
            probe += 1
        end = min(probe + 1, len(lines))
        blocks.append(FunctionBlock(name, params, start + 1, end, lines[start:end]))
        idx = max(end, idx + 1)
    return blocks


def _match_function_signature(line: str, regexes: list[re.Pattern]) -> re.Match | None:
    for regex in regexes:
        match = regex.search(line)
        if match:
            return match
    return None


def _function_regexes(language: str) -> list[re.Pattern]:
    by_language = {
        "go": [_GO_FUNC_RE],
        "rust": [_RUST_FUNC_RE],
        "javascript": [_JS_FUNC_RE, _JS_ARROW_RE],
        "typescript": [_JS_FUNC_RE, _JS_ARROW_RE],
        "java": [_JAVA_FUNC_RE],
        "c": [_C_FUNC_RE],
        "cpp": [_C_FUNC_RE],
    }
    return by_language.get(
        language,
        [
            _JS_FUNC_RE,
            _JS_ARROW_RE,
            _GO_FUNC_RE,
            _RUST_FUNC_RE,
            _JAVA_FUNC_RE,
            _C_FUNC_RE,
        ],
    )


def _parse_params(raw: str, language: str) -> list[str]:
    params: list[str] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        part = part.split("=")[0].strip()
        if language in ("python", "javascript", "typescript"):
            name = part.lstrip("*").strip()
            if ":" in name:
                name = name.split(":", 1)[0].strip()
        elif language == "rust":
            name = part.split(":", 1)[0].strip().lstrip("&mut ").lstrip("&")
        elif language == "go":
            name = part.split()[0].strip()
        else:
            tokens = re.findall(r"[A-Za-z_]\w*", part)
            name = tokens[-1] if tokens else ""
        if name and name not in _IGNORE_PARAMS and re.match(r"^[A-Za-z_]\w*$", name):
            params.append(name)
    return list(dict.fromkeys(params))

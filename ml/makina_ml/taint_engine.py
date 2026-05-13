"""
Interprocedural taint engine using tree-sitter for function boundary detection.
Detects cross-function flows: source reads tainted input → calls func → sink executes it.

Two detection strategies:
1. BFS from source functions through their callees to find sinks.
2. Broker pattern: a function calls both a source function and a sink function.
"""

from __future__ import annotations
import re
from dataclasses import dataclass
from collections import deque

from .sql_safety import has_unsafe_sql_sink

_CALL_RE = re.compile(r"\b([a-zA-Z_]\w*)\s*\(")

_KEYWORDS = frozenset(
    {
        "if",
        "for",
        "while",
        "switch",
        "return",
        "print",
        "len",
        "range",
        "isinstance",
        "str",
        "int",
        "float",
        "bool",
        "list",
        "dict",
        "set",
        "tuple",
        "True",
        "False",
        "None",
        "type",
        "repr",
        "super",
        "object",
        "map",
        "filter",
        "zip",
        "sorted",
        "reversed",
        "enumerate",
        "hasattr",
        "getattr",
        "setattr",
        "delattr",
        "callable",
        "new",
        "delete",
        "typeof",
        "instanceof",
        "make",
        "append",
        "copy",
        "panic",
        "recover",
        "defer",
        "println",
        "printf",
        "sprintf",
        "Println",
        "Printf",
        "Sprintf",
        "assert",
        "raise",
        "except",
        "finally",
        "with",
        "lambda",
        "yield",
        "async",
        "await",
    }
)

_TS_LANG_MAP = {
    "python": "python",
    "javascript": "javascript",
    "typescript": "typescript",
    "go": "go",
    "java": "java",
    "ruby": "ruby",
    "rust": "rust",
    "c": "c",
    "cpp": "cpp",
}

_FUNC_NODE_TYPES: dict[str, frozenset[str]] = {
    "python": frozenset({"function_definition"}),
    "javascript": frozenset(
        {
            "function_declaration",
            "function_expression",
            "method_definition",
            "arrow_function",
        }
    ),
    "typescript": frozenset(
        {
            "function_declaration",
            "function_expression",
            "method_definition",
            "arrow_function",
        }
    ),
    "go": frozenset({"function_declaration", "method_declaration"}),
    "java": frozenset({"method_declaration", "constructor_declaration"}),
    "ruby": frozenset({"method", "singleton_method"}),
    "rust": frozenset({"function_item"}),
    "c": frozenset({"function_definition"}),
    "cpp": frozenset({"function_definition"}),
}


@dataclass
class SinkPattern:
    pattern: re.Pattern
    cwe: str
    message: str


@dataclass
class SourceConfig:
    patterns: list[re.Pattern]
    sinks: list[SinkPattern]


def _src(pats: list[str]) -> list[re.Pattern]:
    return [re.compile(p) for p in pats]


def _sinks(items: list[tuple[str, str, str]]) -> list[SinkPattern]:
    return [SinkPattern(re.compile(p), cwe, msg) for p, cwe, msg in items]


TAINT_CONFIGS: dict[str, SourceConfig] = {
    "python": SourceConfig(
        patterns=_src(
            [
                r"\brequest\.args\b",
                r"\brequest\.form\b",
                r"\brequest\.json\b",
                r"\brequest\.data\b",
                r"\brequest\.get_json\s*\(",
                r"\binput\s*\(",
                r"\bsys\.stdin\b",
            ]
        ),
        sinks=_sinks(
            [
                (
                    r"\.execute\s*\(",
                    "CWE-89",
                    "SQL Injection: tainted input flows into DB execute",
                ),
                (
                    r"\.executemany\s*\(",
                    "CWE-89",
                    "SQL Injection: tainted input flows into DB executemany",
                ),
                (
                    r"\bos\.system\s*\(",
                    "CWE-78",
                    "Command Injection: tainted input flows into os.system",
                ),
                (
                    r"\bos\.popen\s*\(",
                    "CWE-78",
                    "Command Injection: tainted input flows into os.popen",
                ),
                (
                    r"\bsubprocess\.(run|call|Popen|check_output)\s*\(",
                    "CWE-78",
                    "Command Injection: tainted input flows into subprocess",
                ),
                (
                    r"\beval\s*\(",
                    "CWE-94",
                    "Code Injection: tainted input flows into eval",
                ),
                (
                    r"\bexec\s*\(",
                    "CWE-94",
                    "Code Injection: tainted input flows into exec",
                ),
                (
                    r"\bopen\s*\(",
                    "CWE-22",
                    "Path Traversal: tainted input flows into open",
                ),
            ]
        ),
    ),
    "javascript": SourceConfig(
        patterns=_src(
            [
                r"\breq\.query\b",
                r"\breq\.body\b",
                r"\breq\.params\b",
                r"\brequest\.query\b",
                r"\brequest\.body\b",
            ]
        ),
        sinks=_sinks(
            [
                (
                    r"\.query\s*\(",
                    "CWE-89",
                    "SQL Injection: tainted input flows into DB query",
                ),
                (
                    r"\.execute\s*\(",
                    "CWE-89",
                    "SQL Injection: tainted input flows into DB execute",
                ),
                (
                    r"\bexec\s*\(",
                    "CWE-78",
                    "Command Injection: tainted input flows into exec",
                ),
                (
                    r"\bexecSync\s*\(",
                    "CWE-78",
                    "Command Injection: tainted input flows into execSync",
                ),
                (
                    r"\beval\s*\(",
                    "CWE-94",
                    "Code Injection: tainted input flows into eval",
                ),
                (
                    r"\.innerHTML\s*=",
                    "CWE-79",
                    "XSS: tainted input assigned to innerHTML",
                ),
                (
                    r"\bdocument\.write\s*\(",
                    "CWE-79",
                    "XSS: tainted input written to document",
                ),
            ]
        ),
    ),
    "go": SourceConfig(
        patterns=_src(
            [
                r"\bFormValue\s*\(",
                r"\bPostFormValue\s*\(",
                r"\.Query\(\)\.Get\s*\(",
                r"\.Header\.Get\s*\(",
            ]
        ),
        sinks=_sinks(
            [
                (
                    r"\.Query\s*\(",
                    "CWE-89",
                    "SQL Injection: tainted input flows into DB Query",
                ),
                (
                    r"\.QueryRow\s*\(",
                    "CWE-89",
                    "SQL Injection: tainted input flows into DB QueryRow",
                ),
                (
                    r"\.Exec\s*\(",
                    "CWE-89",
                    "SQL Injection: tainted input flows into DB Exec",
                ),
                (
                    r"\bexec\.Command\s*\(",
                    "CWE-78",
                    "Command Injection: tainted input flows into exec.Command",
                ),
            ]
        ),
    ),
}

TAINT_CONFIGS["typescript"] = TAINT_CONFIGS["javascript"]


# ─── Function extraction via tree-sitter ─────────────────────────────────────


def _extract_functions(code: str, language: str) -> dict:
    ts_lang = _TS_LANG_MAP.get(language)
    if not ts_lang:
        return {}

    try:
        from tree_sitter_languages import get_parser

        parser = get_parser(ts_lang)
    except Exception:
        return {}

    try:
        tree = parser.parse(code.encode("utf-8"))
    except Exception:
        return {}

    lines = code.splitlines()
    target_types = _FUNC_NODE_TYPES.get(language, frozenset())
    result: dict = {}

    stack = [tree.root_node]
    while stack:
        node = stack.pop()

        if node.type in target_types:
            name_node = node.child_by_field_name("name")
            if name_node is None:
                for child in node.children:
                    if child.type in ("identifier", "property_identifier"):
                        name_node = child
                        break

            name: str | None = None
            if name_node:
                name = name_node.text.decode("utf-8", errors="replace")
            else:
                # Arrow / anonymous function — try to recover a binding
                # name from the surrounding context so the broker pattern
                # (Strategy 2) can still match against this scope.
                parent = node.parent
                if parent is not None:
                    if parent.type == "variable_declarator":
                        n = parent.child_by_field_name("name")
                        if n is not None:
                            name = n.text.decode("utf-8", errors="replace")
                    elif parent.type in ("pair", "property"):
                        n = parent.child_by_field_name("key")
                        if n is not None:
                            name = n.text.decode("utf-8", errors="replace")
                    elif parent.type == "assignment_expression":
                        n = parent.child_by_field_name("left")
                        if n is not None:
                            name = n.text.decode("utf-8", errors="replace")
                if name is None:
                    name = f"__anon_l{node.start_point[0] + 1}"

            if name:
                start_line = node.start_point[0] + 1
                end_line = node.end_point[0] + 1
                src = "\n".join(lines[start_line - 1 : end_line])

                callees = list(
                    dict.fromkeys(
                        c
                        for c in _CALL_RE.findall(src)
                        if c not in _KEYWORDS and len(c) > 2 and c != name
                    )
                )

                result[name] = {
                    "source": src,
                    "callees": callees,
                    "line_start": start_line,
                    "line_end": end_line,
                }

        for child in reversed(node.children):
            stack.append(child)

    return result


# ─── Taint flow detection ─────────────────────────────────────────────────────


def _has_source(src: str, config: SourceConfig) -> bool:
    return any(p.search(src) for p in config.patterns)


def _matching_sinks(src: str, config: SourceConfig) -> list[SinkPattern]:
    sinks: list[SinkPattern] = []
    for sink in config.sinks:
        if not sink.pattern.search(src):
            continue
        if sink.cwe == "CWE-89" and not has_unsafe_sql_sink(src):
            continue
        sinks.append(sink)
    return sinks


def _node_id(kind: str, name: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_.:-]+", "_", name).strip("_") or "unknown"
    return f"{kind}:{safe}"


def _trace_graph(
    functions: dict,
    source_name: str,
    sink_name: str,
    sink: SinkPattern,
    path: list[str],
) -> dict:
    ordered_path = list(dict.fromkeys(path))
    nodes: list[dict] = []
    edges: list[dict] = []
    seen_nodes: set[str] = set()

    for name in ordered_path:
        info = functions[name]
        kind = (
            "source"
            if name == source_name
            else "sink"
            if name == sink_name
            else "function"
        )
        node_id = _node_id(kind, name)
        if node_id in seen_nodes:
            continue
        seen_nodes.add(node_id)
        nodes.append(
            {
                "id": node_id,
                "kind": kind,
                "label": name,
                "line_start": info["line_start"],
                "line_end": info["line_end"],
                "detail": info["source"][:400],
            }
        )

    for left, right in zip(ordered_path, ordered_path[1:]):
        left_kind = (
            "source"
            if left == source_name
            else "sink"
            if left == sink_name
            else "function"
        )
        right_kind = (
            "source"
            if right == source_name
            else "sink"
            if right == sink_name
            else "function"
        )
        source_id = _node_id(left_kind, left)
        target_id = _node_id(right_kind, right)
        edges.append(
            {
                "id": f"{source_id}->{target_id}",
                "source": source_id,
                "target": target_id,
                "kind": "flows_to",
                "label": "flows to",
            }
        )

    finding_id = _node_id("finding", f"{sink.cwe}:{source_name}:{sink_name}")
    snk_info = functions[sink_name]
    nodes.append(
        {
            "id": finding_id,
            "kind": "finding",
            "label": sink.cwe,
            "line_start": snk_info["line_start"],
            "line_end": snk_info["line_end"],
            "detail": sink.message,
        }
    )
    sink_id = _node_id("sink", sink_name)
    edges.append(
        {
            "id": f"{sink_id}->{finding_id}",
            "source": sink_id,
            "target": finding_id,
            "kind": "reports",
            "label": "reports",
        }
    )
    return {"nodes": nodes, "edges": edges}


def _step_kind(name: str, source_name: str, sink_name: str) -> str:
    if name == source_name:
        return "source"
    if name == sink_name:
        return "sink"
    return "function"


def _step_detail(kind: str, name: str, sink: SinkPattern) -> str:
    if kind == "source":
        return (
            f"Confirm whether `{name}` is reachable from an untrusted caller or "
            "external entry point."
        )
    if kind == "sink":
        return (
            f"Confirm whether data derived from the source reaches `{name}` "
            f"at the reported {sink.cwe} sink without an effective guard."
        )
    return f"Confirm data propagation through `{name}` and record any sanitizers or guards."


def _feedback_signals(cwe: str) -> list[str]:
    common = [
        "source function is reachable from an untrusted caller or external entry point",
        "runtime coverage reaches each function in the ordered path",
        "sink receives data derived from the source without sanitizer or guard evidence",
    ]
    cwe_specific = {
        "CWE-89": [
            "constructed SQL syntax changes under safe malformed input",
            "query execution is not using bound parameters for source-derived data",
        ],
        "CWE-78": [
            "command arguments or shell syntax are influenced by source-derived data",
            "execution API is invoked without argument-vector isolation or allowlisting",
        ],
        "CWE-94": [
            "code interpreter input is influenced by source-derived data",
            "input grammar is not constrained before dynamic evaluation",
        ],
        "CWE-22": [
            "filesystem path resolution is influenced by source-derived data",
            "path normalization or root containment checks are missing or bypassable",
        ],
    }
    return common + cwe_specific.get(cwe, [])


def _exploration_plan(
    functions: dict,
    source_name: str,
    sink_name: str,
    sink: SinkPattern,
    path: list[str],
) -> dict:
    ordered_path = list(dict.fromkeys(path))
    steps = []

    for name in ordered_path:
        info = functions[name]
        kind = _step_kind(name, source_name, sink_name)
        steps.append(
            {
                "id": _node_id(kind, name),
                "kind": kind,
                "label": name,
                "line_start": info["line_start"],
                "line_end": info["line_end"],
                "detail": _step_detail(kind, name, sink),
            }
        )

    snk_info = functions[sink_name]
    steps.append(
        {
            "id": _node_id("finding", f"{sink.cwe}:{source_name}:{sink_name}"),
            "kind": "finding",
            "label": sink.cwe,
            "line_start": snk_info["line_start"],
            "line_end": snk_info["line_end"],
            "detail": sink.message,
        }
    )

    path_str = " -> ".join(ordered_path)
    return {
        "kind": "source_to_sink",
        "title": f"Validate {sink.cwe} path from {source_name} to {sink_name}",
        "objective": (
            "Confirm whether attacker-controlled input can traverse the reported "
            "call path and reach the sink without effective sanitization."
        ),
        "priority": 0.82,
        "rationale": f"Interprocedural taint analysis found path: {path_str}.",
        "steps": steps,
        "feedback_signals": _feedback_signals(sink.cwe),
        "required_evidence": [
            "caller, route, handler, job, or message consumer that exposes the source",
            "sanitizer, allowlist, authorization, or parser constraints on the path",
            "minimal non-destructive input showing source influence over the sink",
        ],
    }


def _find_taint_flows(functions: dict, config: SourceConfig) -> list[dict]:
    if not functions:
        return []

    func_has_source = {
        n: _has_source(i["source"], config) for n, i in functions.items()
    }
    func_sinks = {n: _matching_sinks(i["source"], config) for n, i in functions.items()}

    source_func_names = {n for n, v in func_has_source.items() if v}
    sink_func_names = {n for n, sinks in func_sinks.items() if sinks}

    findings = []
    seen_keys: set[tuple] = set()

    def record(
        source_name: str, sink_name: str, sink: SinkPattern, path: list[str]
    ) -> None:
        key = (source_name, sink_name, sink.cwe)
        if key in seen_keys:
            return
        seen_keys.add(key)
        src_info = functions[source_name]
        snk_info = functions[sink_name]
        path_str = " → ".join(dict.fromkeys(path))
        findings.append(
            {
                "rule_id": f"taint-interproc-{sink.cwe.lower().replace('-', '')}",
                "message": f"{sink.message}. Taint path: {path_str}",
                "severity": "high",
                "line_start": src_info["line_start"],
                "line_end": snk_info["line_end"],
                "code_snippet": (
                    f"# Source in: {source_name}\n{src_info['source'][:400]}"
                    f"\n# Sink in: {sink_name}\n{snk_info['source'][:400]}"
                ),
                "confidence": 0.75,
                "cwe": sink.cwe,
                "trace_graph": _trace_graph(
                    functions, source_name, sink_name, sink, path
                ),
                "exploration_plan": _exploration_plan(
                    functions, source_name, sink_name, sink, path
                ),
            }
        )

    # Strategy 1: BFS from source functions through callees to find sinks.
    # Catches: source_func itself (or its callees) eventually calls a sink function.
    for start_name in source_func_names:
        q: deque[tuple[str, list[str]]] = deque([(start_name, [start_name])])
        visited: set[str] = {start_name}
        while q:
            cur_name, path = q.popleft()
            for callee in functions[cur_name]["callees"]:
                if callee not in functions or callee in visited:
                    continue
                new_path = path + [callee]
                for sink in func_sinks[callee]:
                    record(start_name, callee, sink, new_path)
                visited.add(callee)
                q.append((callee, new_path))

    # Strategy 2: Broker pattern — a function calls both a source function and a sink function.
    # Catches: handle() calls get_user_input() [source func] and run_query() [sink func].
    for broker_name, broker_info in functions.items():
        callees_in_scope = [c for c in broker_info["callees"] if c in functions]
        src_callees = [c for c in callees_in_scope if c in source_func_names]
        snk_callees = [c for c in callees_in_scope if c in sink_func_names]
        if not src_callees or not snk_callees:
            continue
        for sc in src_callees:
            for sk in snk_callees:
                if sc == sk:
                    continue
                for sink in func_sinks[sk]:
                    record(sc, sk, sink, [sc, broker_name, sk])

    return findings


# ─── Public API ───────────────────────────────────────────────────────────────


def analyze(code: str, language: str) -> dict:
    config = TAINT_CONFIGS.get(language)
    if not config:
        return {"status": "ok", "findings": [], "language": language}

    functions = _extract_functions(code, language)
    findings = _find_taint_flows(functions, config)
    return {"status": "ok", "findings": findings, "language": language}

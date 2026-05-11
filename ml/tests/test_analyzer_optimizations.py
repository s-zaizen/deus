from __future__ import annotations

import numpy as np

from makina_ml import analyzer, embedder, semgrep_scanner


class FailingGbdt:
    def predict_proba(self, arr):
        raise AssertionError("sink-only windows must not call GBDT")


def test_auto_language_detection_handles_short_function_snippets():
    py_code = """\
def run_code(request):
    return eval(request.args["code"])
"""
    rust_code = """\
fn verify(input: &str) -> bool {
    input.len() > 0
}

pub(crate) async fn verify_scoped(input: &str) -> bool {
    input.len() > 0
}
"""
    go_code = """\
func handler(w http.ResponseWriter, r *http.Request) {
    exec.Command("sh", "-c", r.FormValue("cmd")).Run()
}
"""

    assert analyzer._detect_language(py_code, "auto") == "python"
    assert semgrep_scanner._detect_language(py_code) == "python"
    assert analyzer._detect_language(rust_code, "auto") == "rust"
    assert semgrep_scanner._detect_language(rust_code) == "rust"
    assert analyzer._detect_language(go_code, "auto") == "go"
    assert semgrep_scanner._detect_language(go_code) == "go"


def test_embed_batch_size_env_is_bounded(monkeypatch):
    monkeypatch.setenv("MAKINA_EMBED_BATCH_SIZE", "16")
    assert embedder._embed_batch_size() == 16

    monkeypatch.setenv("MAKINA_EMBED_BATCH_SIZE", "0")
    assert embedder._embed_batch_size() == 1

    monkeypatch.setenv("MAKINA_EMBED_BATCH_SIZE", "not-an-int")
    assert embedder._embed_batch_size() == embedder.DEFAULT_BATCH_SIZE


def test_gbdt_first_sink_path_skips_embeddings_and_gbdt(monkeypatch):
    def fail_embed_batch(_snippets):
        raise AssertionError("sink-only windows must not call CodeBERT")

    monkeypatch.setattr(analyzer.embedder, "embed_batch", fail_embed_batch)
    code = """\
from flask import request

def run_code():
    user_code = request.args.get("code")
    return eval(user_code)
"""
    cwe_index = [
        {
            "cwe": "CWE-94",
            "name": "Code Injection",
            "severity": "critical",
            "pattern_vecs": np.zeros((1, 768), dtype=np.float32),
        }
    ]

    out = analyzer._analyze_gbdt_first(code, "python", FailingGbdt(), cwe_index)

    assert out["mode"] == "hybrid-gbdt-first"
    assert len(out["findings"]) == 1
    finding = out["findings"][0]
    assert finding["cwe"] == "CWE-94"
    assert finding["gate"] == "sink"
    assert finding["refined_by"] == "sink_regex"


def test_analyze_returns_sink_findings_while_embedder_loading(monkeypatch):
    def fail_embed_batch(_snippets):
        raise AssertionError("sink-only fallback must not call CodeBERT")

    monkeypatch.setattr(analyzer.embedder, "is_ready", lambda: False)
    monkeypatch.setattr(analyzer.embedder, "status", lambda: "loading")
    monkeypatch.setattr(analyzer.embedder, "embed_batch", fail_embed_batch)
    code = """\
def run_code(request):
    return eval(request.args["code"])
"""

    out = analyzer.analyze(code, "python")

    assert out["status"] == "ready"
    assert out["mode"] == "sink-only"
    assert len(out["findings"]) == 1
    assert out["findings"][0]["cwe"] == "CWE-94"


def test_analyze_returns_sink_findings_when_cwe_index_is_unavailable(monkeypatch):
    def fail_embed_batch(_snippets):
        raise AssertionError("sink fallback must not call CodeBERT")

    monkeypatch.setattr(analyzer.embedder, "is_ready", lambda: True)
    monkeypatch.setattr(analyzer, "_load_gbdt", lambda: FailingGbdt())
    monkeypatch.setattr(analyzer, "_get_cwe_index", lambda: None)
    monkeypatch.setattr(analyzer.embedder, "embed_batch", fail_embed_batch)
    code = """\
def run_code(request):
    return eval(request.args["code"])
"""

    out = analyzer.analyze(code, "python")

    assert out["status"] == "ready"
    assert out["mode"] == "sink-only"
    assert len(out["findings"]) == 1
    assert out["findings"][0]["cwe"] == "CWE-94"


def test_sink_only_handles_short_snippets(monkeypatch):
    def fail_embed_batch(_snippets):
        raise AssertionError("short sink snippets must not call CodeBERT")

    monkeypatch.setattr(analyzer.embedder, "embed_batch", fail_embed_batch)

    code_injection = analyzer._analyze_sink_only("eval(x)", "python")
    command_injection = analyzer._analyze_sink_only("os.system(cmd)", "python")

    assert code_injection["findings"][0]["cwe"] == "CWE-94"
    assert command_injection["findings"][0]["cwe"] == "CWE-78"


def test_sink_only_reports_multiple_cwes_in_one_window(monkeypatch):
    def fail_embed_batch(_snippets):
        raise AssertionError("multi-sink windows must not call CodeBERT")

    monkeypatch.setattr(analyzer.embedder, "embed_batch", fail_embed_batch)
    code = """\
def handler(cmd, user_code):
    os.system(cmd)
    return eval(user_code)
"""

    out = analyzer._analyze_sink_only(code, "python")

    cwes = {finding["cwe"] for finding in out["findings"]}
    assert cwes == {"CWE-78", "CWE-94"}


def test_exec_sink_is_classified_by_language(monkeypatch):
    def fail_embed_batch(_snippets):
        raise AssertionError("sink classification must not call CodeBERT")

    monkeypatch.setattr(analyzer.embedder, "embed_batch", fail_embed_batch)

    python_exec = analyzer._analyze_sink_only("exec(user_code)", "python")
    js_exec = analyzer._analyze_sink_only("exec(req.query.cmd)", "javascript")

    assert python_exec["findings"][0]["cwe"] == "CWE-94"
    assert js_exec["findings"][0]["cwe"] == "CWE-78"


def test_legacy_sink_path_skips_embeddings(monkeypatch):
    def fail_embed_batch(_snippets):
        raise AssertionError("legacy sink-only window must not call CodeBERT")

    index = [
        {
            "cwe": "CWE-78",
            "name": "Command Injection",
            "severity": "critical",
            "pattern_vecs": np.zeros((1, 768), dtype=np.float32),
        }
    ]
    monkeypatch.setattr(analyzer, "_get_index", lambda: index)
    monkeypatch.setattr(analyzer.embedder, "embed_batch", fail_embed_batch)
    code = """\
import os

def run_command(cmd):
    return os.system(cmd)
"""

    out = analyzer._analyze_legacy(code, "python")

    assert out["mode"] == "similarity-first"
    assert len(out["findings"]) == 1
    assert out["findings"][0]["gate"] == "sink"
    assert out["findings"][0]["cwe"] == "CWE-78"


def test_embed_line_window_embeds_only_requested_range(monkeypatch):
    captured: list[list[str]] = []

    def fake_embed_batch(snippets):
        captured.append(snippets)
        return np.ones((len(snippets), 768), dtype=np.float32)

    monkeypatch.setattr(analyzer.embedder, "embed_batch", fake_embed_batch)
    lines = [f"line {i}" for i in range(1, 101)]

    out = analyzer._embed_line_window(lines, 40, 44)

    assert out is not None
    assert out.shape == (5, 768)
    assert len(captured) == 1
    assert len(captured[0]) == 5
    assert "line 40" in captured[0][0]
    assert "line 44" in captured[0][-1]

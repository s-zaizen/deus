"""Regression tests for lightweight structural property-pattern checks."""

from __future__ import annotations

from makina_ml import property_patterns


def _rules(code: str, language: str) -> set[str]:
    return {
        finding["rule_id"]
        for finding in property_patterns.analyze(code, language)["findings"]
    }


def test_incomplete_cache_key_in_security_sensitive_function():
    code = """\
cache = {}

def verify_commitment(commitment, proof, domain):
    key = proof
    cached = cache.get(key)
    if cached is not None:
        return cached
    result = crypto_verify(commitment, proof, domain)
    cache[key] = result
    return result
"""
    assert "PROP-CACHE-KEY" in _rules(code, "python")


def test_parallel_collection_loop_without_length_guard():
    code = """\
def validate_pairs(hashes, payloads):
    for i in range(len(hashes)):
        validate(payloads[i], hashes[i])
"""
    assert "PROP-LENGTH-PAIR" in _rules(code, "python")


def test_parallel_collection_loop_with_length_guard_is_quiet():
    code = """\
def validate_pairs(hashes, payloads):
    if len(hashes) != len(payloads):
        raise ValueError("mismatch")
    for i in range(len(hashes)):
        validate(payloads[i], hashes[i])
"""
    assert "PROP-LENGTH-PAIR" not in _rules(code, "python")


def test_index_bounds_guard_inside_loop_is_quiet():
    code = """\
function copyMatching(patternParts, pathParts) {
    for (let i = 0; i < patternParts.length; i++) {
        if (pathParts.length >= i + 1) {
            validate(pathParts[i], patternParts[i]);
        }
    }
}
"""
    assert "PROP-LENGTH-PAIR" not in _rules(code, "javascript")


def test_go_verifier_boolean_result_must_be_checked():
    code = """\
package main

func handle(commitment []byte, proof []byte) error {
    ok, err := VerifyProof(commitment, proof)
    if err != nil {
        return err
    }
    return nil
}
"""
    assert "PROP-VERIFY-BOOL" in _rules(code, "go")


def test_go_selector_verifier_boolean_result_must_be_checked():
    code = """\
package main

func handle(commitment []byte, proof []byte) error {
    ok, err := verifier.VerifyProof(commitment, proof)
    if err != nil {
        return err
    }
    return nil
}
"""
    assert "PROP-VERIFY-BOOL" in _rules(code, "go")


def test_go_parse_multi_return_is_quiet():
    code = """\
package main

func handle(header string) error {
    mediaType, _, err := mime.ParseMediaType(header)
    if err != nil {
        return err
    }
    _ = mediaType
    return nil
}
"""
    assert "PROP-VERIFY-BOOL" not in _rules(code, "go")


def test_go_range_pair_loop_without_length_guard():
    code = """\
package main

func validatePairs(hashes [][]byte, payloads [][]byte) {
    for i, hash := range hashes {
        validate(payloads[i], hash)
    }
}
"""
    assert "PROP-LENGTH-PAIR" in _rules(code, "go")


def test_go_selector_range_is_quiet():
    code = """\
package main

func copyLabels(opt Options) {
    labels := map[string]string{}
    for k, v := range opt.Metadata.Labels {
        labels[k] = v
    }
}
"""
    assert "PROP-LENGTH-PAIR" not in _rules(code, "go")


def test_unbounded_external_size_controls_allocation():
    code = """\
def parse_request(request):
    item_count = int(request.args["count"])
    values = range(item_count)
    return list(values)
"""
    assert "PROP-UNBOUNDED-SIZE" in _rules(code, "python")


def test_lower_bound_check_does_not_hide_unbounded_size():
    code = """\
def parse_request(request):
    item_count = int(request.args["count"])
    if item_count < 0:
        raise ValueError("negative")
    values = range(item_count)
    return list(values)
"""
    assert "PROP-UNBOUNDED-SIZE" in _rules(code, "python")


def test_positive_branch_does_not_hide_unbounded_size():
    code = """\
def parse_request(request):
    item_count = int(request.args["count"])
    if item_count > 0:
        values = range(item_count)
        return list(values)
    return []
"""
    assert "PROP-UNBOUNDED-SIZE" in _rules(code, "python")


def test_inline_positive_branch_does_not_hide_unbounded_size():
    code = """\
def parse_request(request):
    item_count = int(request.args["count"])
    if item_count > 0:
        return list(range(item_count))
    return []
"""
    assert "PROP-UNBOUNDED-SIZE" in _rules(code, "python")


def test_rejecting_upper_bound_guard_is_quiet():
    code = """\
def parse_request(request):
    item_count = int(request.args["count"])
    if item_count > MAX_ITEMS:
        raise ValueError("too many")
    values = range(item_count)
    return list(values)
"""
    assert "PROP-UNBOUNDED-SIZE" not in _rules(code, "python")


def test_repeated_mutable_reads_are_caught_when_assigned():
    code = """\
def validate_state(account):
    first = account.get_nonce()
    do_work()
    second = account.get_nonce()
    return first == second
"""
    assert "PROP-REPEATED-READ" in _rules(code, "python")


def test_repeated_generic_reads_are_quiet():
    code = """\
def read_header(stream):
    secret = stream.readUTF()
    node = stream.readUTF()
    return secret, node
"""
    assert "PROP-REPEATED-READ" not in _rules(code, "python")


def test_javascript_arrow_function_is_scanned():
    code = """\
const validatePairs = (hashes, payloads) => {
    for (let i = 0; i < hashes.length; i++) {
        validate(payloads[i], hashes[i]);
    }
}
"""
    assert "PROP-LENGTH-PAIR" in _rules(code, "javascript")


def test_formatted_command_dsl_sink_with_external_parameter():
    code = """\
static char *print_fcn_arg(RCore *core, const char *type, const char *name, const char *fmt, const ut64 addr) {
    char *res = r_core_cmd_strf(core, "pfq %s%s %s @ 0x%08" PFMT64x,
        "*", fmt, name, addr);
    return res;
}
"""
    assert "PROP-FORMATTED-COMMAND" in _rules(code, "c")


def test_formatted_command_dsl_sink_inside_guard_block():
    code = """\
static char *print_fcn_arg(RCore *core, const char *type, const char *name, const char *fmt, const ut64 addr, const int on_stack, int asm_types) {
    if (*type && on_stack == 1 && asm_types > 1) {
        return strdup(type);
    }
    if (addr != UT32_MAX && addr != UT64_MAX && addr != 0) {
        return r_core_cmd_strf(core, "pfq %s%s %s @ 0x%08" PFMT64x,
            (on_stack == 1) ? "*" : "", fmt, name, addr);
    }
    return strdup("-1");
}
"""
    assert "PROP-FORMATTED-COMMAND" in _rules(code, "c")


def test_formatted_command_detector_is_not_tied_to_c_api_names():
    code = """\
function renderDebugCommand(userName) {
    const command = `print object ${userName}`;
    return commandRunner.execute(command);
}
"""
    assert "PROP-FORMATTED-COMMAND" in _rules(code, "javascript")


def test_formatting_without_interpreter_sink_is_quiet():
    code = """\
static char *describe_name(const char *name) {
    char buf[128];
    snprintf(buf, sizeof(buf), "name=%s", name);
    return strdup(buf);
}
"""
    assert "PROP-FORMATTED-COMMAND" not in _rules(code, "c")


def test_sanitized_formatted_command_input_is_quiet():
    code = """\
function renderDebugCommand(userName) {
    const command = `print object ${escapeCommandArg(userName)}`;
    return commandRunner.execute(command);
}
"""
    assert "PROP-FORMATTED-COMMAND" not in _rules(code, "javascript")

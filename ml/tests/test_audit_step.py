from types import SimpleNamespace

from makina_ml.server import _extract_anthropic_tool_json


def test_extract_anthropic_tool_json_returns_compact_json():
    response = SimpleNamespace(
        content=[
            SimpleNamespace(type="text", text="ignored"),
            SimpleNamespace(
                type="tool_use",
                name="submit_makina_audit_report",
                input={
                    "findings": [
                        {
                            "id": "MAKINA-001",
                            "summary": "Confirmed.",
                        }
                    ]
                },
            ),
        ]
    )

    assert (
        _extract_anthropic_tool_json(response, "submit_makina_audit_report")
        == '{"findings":[{"id":"MAKINA-001","summary":"Confirmed."}]}'
    )


def test_extract_anthropic_tool_json_ignores_other_tools():
    response = SimpleNamespace(
        content=[
            SimpleNamespace(type="tool_use", name="other_tool", input={"value": True}),
        ]
    )

    assert _extract_anthropic_tool_json(response, "submit_makina_audit_report") == ""

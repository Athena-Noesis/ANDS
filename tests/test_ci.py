import json
import os
import pytest
from tools.ands_ci import calculate_delta

def test_calculate_delta():
    old = "1.1.1.1.1.1"
    new = "2.1.2.1.3.1"
    delta = calculate_delta(old, new)
    assert delta["C"] == 1
    assert delta["A"] == 0
    assert delta["M"] == 1
    assert delta["G"] == 0
    assert delta["R"] == 2
    assert delta["E"] == 0

def test_ci_execution(tmp_path):
    doc = {
        "system_id": "test.ci",
        "ands_version": "1.2",
        "declared_ands": "2.1.1.2.3.1",
        "certification_level": "SELF",
        "signatures": []
    }
    p = tmp_path / "ands.json"
    p.write_text(json.dumps(doc))

    from tools.ands_ci import generate_markdown_report

    report = generate_markdown_report(
        str(p), doc, (True, "Valid"), (False, "Missing sigs"),
        delta={"C": 1}, compliance={}
    )
    assert "ANDS CI/CD Compliance Dashboard" in report
    # report includes path, not necessarily system_id in the header
    assert str(p) in report
    assert "C:** 2 🔺 (+1)" in report

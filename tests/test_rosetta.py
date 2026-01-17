import pytest
from ands.rosetta import RosettaEngine

def test_rosetta_evaluation():
    engine = RosettaEngine()
    declaration = {
        "declared_ands": "1.1.1.2.2.1",
        "attestation_urls": ["http://example.com/attestation.md"],
        "ands_version": "1.1"
    }

    results = engine.evaluate(declaration)

    # Check EU AI Act Article 9 (Risk Management)
    # Logic: R <= 3. Input R=2 -> Compliant
    eu_art9 = results["eu_ai_act"]["articles"]["9"]
    assert eu_art9["status"] == "Compliant"

def test_rosetta_conditional_compliance():
    engine = RosettaEngine()
    declaration = {
        "declared_ands": "1.1.1.2.2.1",
        # Missing evidence
        "ands_version": "1.1"
    }

    results = engine.evaluate(declaration)

    # Check EU AI Act Article 14 (Human Oversight)
    # Logic: A=1, G=2 -> Satisfied.
    # Required evidence: ["attestation"]. Found: no. -> Conditional
    eu_art14 = results["eu_ai_act"]["articles"]["14"]
    assert eu_art14["status"] == "Conditional"
    assert "attestation" in eu_art14["missing_evidence"]

def test_rosetta_non_compliance():
    engine = RosettaEngine()
    declaration = {
        "declared_ands": "5.5.5.5.5.5", # High everything
        "ands_version": "1.1"
    }

    results = engine.evaluate(declaration)

    # Article 9: R <= 3. Input R=5 -> Non-Compliant
    eu_art9 = results["eu_ai_act"]["articles"]["9"]
    assert eu_art9["status"] == "Non-Compliant"

def test_rosetta_translate_cli():
    import subprocess
    import os
    result = subprocess.run(
        ["python3", "tools/ands_rosetta.py", "translate", "1.1.1.2.2.1"],
        capture_output=True, text=True, env={**os.environ, "PYTHONPATH": "."}
    )
    assert result.returncode == 0
    assert "[✓] Article 9" in result.stdout

def test_rosetta_checklist_cli(tmp_path):
    import json
    import subprocess
    import os
    doc = {
        "declared_ands": "1.1.1.2.2.1",
        "ands_version": "1.1"
    }
    p = tmp_path / "ands.json"
    p.write_text(json.dumps(doc))

    result = subprocess.run(
        ["python3", "tools/ands_rosetta.py", "checklist", str(p)],
        capture_output=True, text=True, env={**os.environ, "PYTHONPATH": "."}
    )
    assert result.returncode == 0
    assert "EU AI Act Compliance Checklist" in result.stdout
    assert "Conditional:" in result.stdout

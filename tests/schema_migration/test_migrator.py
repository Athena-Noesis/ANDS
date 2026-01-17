import json
import os
import pytest
from ands.schema_migrator import SchemaMigrator
from ands.validator import validate_declaration

@pytest.fixture
def example_v10():
    return {
        "system_id": "test.v10",
        "ands_version": "1.0",
        "declared_ands": "1.1.1.1.1",
        "certification_level": "SELF"
    }

def test_detect_version(example_v10):
    migrator = SchemaMigrator()
    assert migrator.detect_version(example_v10) == "1.0"
    assert migrator.detect_version({}) == "1.0"
    assert migrator.detect_version({"ands_version": "1.1"}) == "1.1"

def test_available_versions():
    migrator = SchemaMigrator()
    versions = migrator.get_available_versions()
    assert "1.0" in versions
    assert "1.1" in versions
    # Check sorting
    assert versions.index("1.0") < versions.index("1.1")

def test_normalize_10_to_11(example_v10):
    migrator = SchemaMigrator()
    migrated = migrator.normalize(example_v10, target_version="1.1")
    assert migrated["ands_version"] == "1.1"
    # Sustainability axis should be added if we have capabilities (actually current logic adds it if capabilities is present)

    doc_with_caps = example_v10.copy()
    doc_with_caps["capabilities"] = {"tool_use": True}
    migrated_caps = migrator.normalize(doc_with_caps, target_version="1.1")
    assert migrated_caps["capabilities"]["sustainability_axis"] is False

def test_validate_versioned(example_v10):
    # Should validate as 1.0
    valid, errors = validate_declaration(example_v10)
    assert valid, f"Validation failed: {errors}"

    # Change to 1.1, should still validate (since we copied 1.0 schema to 1.1)
    v11 = example_v10.copy()
    v11["ands_version"] = "1.1"
    valid, errors = validate_declaration(v11)
    assert valid, f"Validation failed: {errors}"

    # Invalid version
    v_bad = example_v10.copy()
    v_bad["ands_version"] = "99.9"
    valid, errors = validate_declaration(v_bad)
    assert not valid
    assert "Unsupported or missing schema version" in errors[0]

def test_migrate_file(tmp_path, example_v10):
    p = tmp_path / "ands.json"
    p.write_text(json.dumps(example_v10))

    migrator = SchemaMigrator()
    success, msg = migrator.migrate_file(str(p), target_version="1.1")
    assert success

    with open(p, 'r') as f:
        migrated = json.load(f)
    assert migrated["ands_version"] == "1.1"

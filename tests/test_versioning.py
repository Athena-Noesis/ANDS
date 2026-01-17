import json
import pytest
from pathlib import Path
from ands.migrations.engine import MigrationEngine
from ands.utils import SchemaRegistry

def test_migration_1_0_to_1_1():
    doc = {
        "system_id": "test.system",
        "ands_version": "1.0",
        "declared_ands": "2.1.2.3.4",
        "certification_level": "SELF",
        "signed": {"sig": "dummy"}
    }

    new_doc = MigrationEngine.migrate(doc, "1.1")

    assert new_doc["ands_version"] == "1.1"
    assert new_doc["environment"] == 3
    assert "signed" not in new_doc
    assert new_doc["system_id"] == "test.system"

def test_schema_registry_loading():
    schema10 = SchemaRegistry.load_schema("1.0")
    assert schema10["title"] == "ANDS Well-Known Declaration"

    schema11 = SchemaRegistry.load_schema("1.1")
    assert "environment" in schema11["properties"]

def test_migration_cli(tmp_path):
    doc = {
        "system_id": "test.system",
        "ands_version": "1.0",
        "declared_ands": "2.1.2.3.4",
        "certification_level": "SELF"
    }
    p = tmp_path / "ands.json"
    p.write_text(json.dumps(doc))

    import subprocess
    result = subprocess.run(
        ["python3", "tools/ands_migrate.py", str(p), "--to", "1.1"],
        capture_output=True, text=True, env={**os.environ, "PYTHONPATH": "."}
    )

    assert result.returncode == 0
    assert "Migrated declaration from 1.0 → 1.1" in result.stdout

    migrated = json.loads(p.read_text())
    assert migrated["ands_version"] == "1.1"
    assert migrated["environment"] == 3

import os

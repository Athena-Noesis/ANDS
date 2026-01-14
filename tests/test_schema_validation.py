import json
import os

from jsonschema import Draft202012Validator

ROOT = os.path.dirname(os.path.dirname(__file__))
WELL_KNOWN_SCHEMA = os.path.join(ROOT, "spec", "well-known-ands.schema.json")
EXAMPLE_DECL = os.path.join(ROOT, "spec", "examples", "ands-declaration-example.json")


def test_example_declaration_validates():
    with open(WELL_KNOWN_SCHEMA, "r", encoding="utf-8") as f:
        schema = json.load(f)
    with open(EXAMPLE_DECL, "r", encoding="utf-8") as f:
        doc = json.load(f)

    v = Draft202012Validator(schema)
    errors = list(v.iter_errors(doc))
    assert errors == [], [e.message for e in errors]

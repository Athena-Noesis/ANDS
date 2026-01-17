import json
import os

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = os.path.dirname(os.path.dirname(__file__))
SPEC_DIR = os.path.join(ROOT, "spec")
WELL_KNOWN_SCHEMA = os.path.join(SPEC_DIR, "well-known-ands.schema.json")
EXAMPLE_DECL = os.path.join(SPEC_DIR, "examples", "ands-declaration-example.json")


def test_example_declaration_validates():
    with open(WELL_KNOWN_SCHEMA, "r", encoding="utf-8") as f:
        schema_data = json.load(f)

    registry: Registry = Registry()
    for filename in os.listdir(SPEC_DIR):
        if filename.endswith(".schema.json"):
            with open(os.path.join(SPEC_DIR, filename), "r", encoding="utf-8") as f:
                s = json.load(f)
                resource = Resource.from_contents(s)
                registry = registry.with_resource(uri=s.get("$id", filename), resource=resource)

    with open(EXAMPLE_DECL, "r", encoding="utf-8") as f:
        doc = json.load(f)

    v = Draft202012Validator(schema_data, registry=registry)
    errors = list(v.iter_errors(doc))
    assert errors == [], [e.message for e in errors]

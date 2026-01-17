import json
import os

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from ands.utils import SchemaRegistry

ROOT = os.path.dirname(os.path.dirname(__file__))
EXAMPLE_DECL = os.path.join(ROOT, "spec", "examples", "ands-declaration-example.json")


def test_example_declaration_validates():
    version = "1.0"
    schema_data = SchemaRegistry.load_schema(version)
    spec_dir = SchemaRegistry.get_schema_path(version).parent

    registry: Registry = Registry()
    for filename in os.listdir(spec_dir):
        if filename.endswith(".schema.json"):
            with open(os.path.join(spec_dir, filename), "r", encoding="utf-8") as f:
                s = json.load(f)
                resource = Resource.from_contents(s)
                registry = registry.with_resource(uri=s.get("$id", filename), resource=resource)

    with open(EXAMPLE_DECL, "r", encoding="utf-8") as f:
        doc = json.load(f)

    v = Draft202012Validator(schema_data, registry=registry)
    errors = list(v.iter_errors(doc))
    assert errors == [], [e.message for e in errors]

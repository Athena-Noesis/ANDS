from typing import Any, Dict

def migrate(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Migrates an ANDS 1.0 declaration to 1.1."""
    doc["ands_version"] = "1.1"

    # Add Environment axis if not present (default to 3 - Neutral)
    if "environment" not in doc:
        doc["environment"] = 3

    # Optional: Update declared_ands format if it's 5-axis
    # (though 1.1 schema allows both 5 and 6 axes in the string)

    return doc

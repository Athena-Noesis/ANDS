from typing import Any, Dict, List
from . import m1_0_to_1_1

MIGRATIONS = {
    ("1.0", "1.1"): m1_0_to_1_1.migrate,
}

class MigrationEngine:
    @staticmethod
    def get_supported_migrations() -> List[str]:
        return [f"{src} -> {dst}" for src, dst in MIGRATIONS.keys()]

    @staticmethod
    def migrate(doc: Dict[str, Any], target_version: str) -> Dict[str, Any]:
        current_version = doc.get("ands_version", "1.0")
        if current_version == target_version:
            return doc

        # Basic linear migration path finder
        while current_version != target_version:
            # Find a migration from current_version
            found = False
            for (src, dst), func in MIGRATIONS.items():
                if src == current_version:
                    doc = func(doc)
                    current_version = dst
                    found = True
                    break

            if not found:
                raise ValueError(f"No migration path from {current_version} to {target_version}")

        # Invalidate signature after migration
        if "signed" in doc:
            doc.pop("signed")

        return doc

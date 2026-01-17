import json
import os
import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("ands")

class SchemaMigrator:
    """Handles detection, loading, and migration of ANDS declaration schemas."""

    def __init__(self, schemas_root: Optional[str] = None):
        if schemas_root is None:
            self.schemas_root = os.path.join(os.path.dirname(__file__), "schemas")
        else:
            self.schemas_root = schemas_root

    def get_available_versions(self) -> List[str]:
        """List all available schema versions sorted by version number."""
        if not os.path.exists(self.schemas_root):
            return []
        versions = [
            d for d in os.listdir(self.schemas_root)
            if os.path.isdir(os.path.join(self.schemas_root, d)) and not d.startswith("__")
        ]
        # Sort semantically (e.g., 1.0, 1.1, 1.10)
        return sorted(versions, key=lambda x: [int(i) for i in x.split('.')])

    def get_latest_version(self) -> str:
        """Return the highest version number available."""
        versions = self.get_available_versions()
        return versions[-1] if versions else "1.0"

    def get_schema_dir(self, version: str) -> str:
        """Get the directory path for a specific schema version."""
        return os.path.join(self.schemas_root, version)

    def load_schema(self, version: str, schema_name: str = "well-known-ands.schema.json") -> Dict[str, Any]:
        """Load a specific schema by version and name."""
        path = os.path.join(self.get_schema_dir(version), schema_name)
        if not os.path.exists(path):
            raise FileNotFoundError(f"Schema version {version} ({schema_name}) not found at {path}")
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def detect_version(self, declaration: Dict[str, Any]) -> str:
        """Detect the ANDS version of a declaration."""
        return str(declaration.get("ands_version", "1.0"))

    def normalize(self, declaration: Dict[str, Any], target_version: Optional[str] = None) -> Dict[str, Any]:
        """
        Normalize a declaration to a target version in-memory.
        If no target_version is provided, uses the latest available.
        """
        current_version = self.detect_version(declaration)
        if target_version is None:
            target_version = self.get_latest_version()

        if current_version == target_version:
            return declaration

        # Logic for migration steps
        migrated = dict(declaration)

        # Simple incremental migration simulation
        # In a real scenario, this would loop through versions 1.0 -> 1.1 -> 1.2
        if current_version == "1.0" and target_version == "1.1":
            migrated = self._migrate_10_to_11(migrated)

        return migrated

    def _migrate_10_to_11(self, doc: Dict[str, Any]) -> Dict[str, Any]:
        """Example migration from 1.0 to 1.1."""
        new_doc = dict(doc)
        new_doc["ands_version"] = "1.1"

        # Example: Add an empty sustainability field if missing in capabilities
        if "capabilities" in new_doc:
            if "sustainability_axis" not in new_doc["capabilities"]:
                new_doc["capabilities"]["sustainability_axis"] = False

        # Example: Upgrade single 'signed' to 'signatures' array if desired
        if "signed" in new_doc and "signatures" not in new_doc:
            new_doc["signatures"] = [new_doc["signed"]]
            # We keep 'signed' for backward compatibility or remove it?
            # Usually we update to the new schema's structure.

        return new_doc

    def migrate_file(self, file_path: str, target_version: Optional[str] = None) -> Tuple[bool, str]:
        """Read, migrate, and write a declaration file back to disk."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                doc = json.load(f)

            old_version = self.detect_version(doc)
            new_doc = self.normalize(doc, target_version)
            new_version = self.detect_version(new_doc)

            if old_version == new_version:
                return True, f"File is already at version {old_version}."

            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(new_doc, f, indent=2)

            return True, f"Successfully migrated {file_path} from {old_version} to {new_version}."
        except Exception as e:
            return False, f"Migration failed: {e}"

import argparse
import sys
import json
import os
from pathlib import Path
from ands.migrations.engine import MigrationEngine

def main():
    parser = argparse.ArgumentParser(prog="ands migrate", description="Migrate ANDS declarations between versions")
    parser.add_argument("input", help="Path to the ands.json declaration to migrate")
    parser.add_argument("--to", required=True, help="Target version (e.g., 1.1)")
    parser.add_argument("--out", help="Output path (default: overwrite input)")
    parser.add_argument("--auto-sign", help="Path to private key for auto-signing (not implemented yet)")

    args = parser.parse_args(sys.argv[1:])

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: File {input_path} does not exist.")
        return 1

    try:
        with open(input_path, "r") as f:
            doc = json.load(f)
    except Exception as e:
        print(f"Error reading input file: {e}")
        return 1

    old_version = doc.get("ands_version", "1.0")
    try:
        new_doc = MigrationEngine.migrate(doc, args.to)
    except ValueError as e:
        print(f"Migration error: {e}")
        return 1

    output_path = Path(args.out) if args.out else input_path
    try:
        with open(output_path, "w") as f:
            json.dump(new_doc, f, indent=2)
        print(f"✅ Migrated declaration from {old_version} → {args.to}")
        if "signed" not in new_doc and "signed" in doc:
            print("⚠️ Signature invalidated: please re-sign with 'ands init' (or future 'ands sign').")
    except Exception as e:
        print(f"Error writing output file: {e}")
        return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())

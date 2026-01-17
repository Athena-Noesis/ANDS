import argparse
import sys
from .schema_migrator import SchemaMigrator

def main():
    parser = argparse.ArgumentParser(prog="ands migrate", description="Migrate ANDS declaration files to newer versions.")
    parser.add_argument("path", help="Path to the ANDS declaration JSON file.")
    parser.add_argument("--to", dest="target_version", help="Target version to migrate to (default: latest).")

    args = parser.parse_args()

    migrator = SchemaMigrator()
    success, message = migrator.migrate_file(args.path, args.target_version)

    if success:
        print(f"SUCCESS: {message}")
        return 0
    else:
        print(f"ERROR: {message}")
        return 1

if __name__ == "__main__":
    sys.exit(main())

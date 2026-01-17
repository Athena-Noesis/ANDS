import argparse
import sys
from tools import ands_scan, validate_declaration, ands_init, ands_badge, ands_guard, ands_mcp, ands_dry_run, ands_sbom_gen, ands_audit_review, ands_rosetta, ands_config
from ands import migrate

def main():
    parser = argparse.ArgumentParser(prog="ands", description="ANDS Toolkit CLI")
    subparsers = parser.add_subparsers(dest="command", help="ANDS commands")

    # Mapping of commands to their respective main functions
    commands = {
        "scan": ands_scan.main,
        "validate": validate_declaration.main,
        "migrate": migrate.main,
        "init": ands_init.main,
        "badge": ands_badge.main,
        "guard": ands_guard.main,
        "mcp": ands_mcp.main,
        "dry-run": ands_dry_run.main,
        "sbom-gen": ands_sbom_gen.main,
        "audit": ands_audit_review.main,
        "rosetta": ands_rosetta.main,
        "config": ands_config.main
    }

    # Simplified dispatch: pass remaining args to the sub-command
    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd in commands:
        # Patch sys.argv for the subcommand
        sys.argv = [f"ands {cmd}"] + sys.argv[2:]
        sys.exit(commands[cmd]())
    else:
        print(f"Unknown command: {cmd}")
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()

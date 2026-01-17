import argparse
import sys
import os
from pathlib import Path
from ands.config import config

def cmd_init(args):
    """Initializes a default ands.config.yaml in the current directory."""
    target = Path.cwd() / "ands.config.yaml"
    if target.exists() and not args.overwrite:
        print(f"Error: {target} already exists. Use --overwrite to replace it.")
        return 1

    try:
        with open(target, "w") as f:
            f.write(config.to_yaml())
        print(f"✅ Created default configuration: {target}")
    except Exception as e:
        print(f"Error writing configuration: {e}")
        return 1
    return 0

def cmd_show(args):
    """Displays the active merged configuration."""
    print(config.to_yaml())
    return 0

def main():
    parser = argparse.ArgumentParser(prog="ands config", description="Manage ANDS configuration")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # init
    parser_init = subparsers.add_parser("init", help="Initialize a default ands.config.yaml")
    parser_init.add_argument("--overwrite", action="store_true", help="Overwrite existing configuration file")

    # show
    parser_show = subparsers.add_parser("show", help="Show active merged configuration")

    args = parser.parse_args(sys.argv[1:])

    if args.subcommand == "init":
        return cmd_init(args)
    elif args.subcommand == "show":
        return cmd_show(args)
    return 0

if __name__ == "__main__":
    sys.exit(main())

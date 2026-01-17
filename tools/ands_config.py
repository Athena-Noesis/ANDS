import argparse
import sys
import os
import yaml
from pathlib import Path
from ands.config import config, ANDSConfigError

def cmd_init(args):
    """Initializes a default ands.config.yaml in the current directory."""
    target = Path.cwd() / "ands.config.yaml"
    if target.exists() and not args.force:
        print(f"Error: {target} already exists. Use --force to overwrite.")
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
    """Shows the effective configuration."""
    print(config.to_yaml())
    return 0

def cmd_validate(args):
    """Validates the current configuration."""
    # Basic validation is already done by ands.config on load (YAML parsing)
    # We could add schema validation here if needed.
    try:
        config.reload()
        print("✅ Configuration is valid (YAML syntax and basic structure).")
    except ANDSConfigError as e:
        print(f"❌ Configuration error: {e}")
        return 1
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return 1
    return 0

def main():
    parser = argparse.ArgumentParser(prog="ands config", description="Manage ANDS configuration")
    subparsers = parser.add_subparsers(dest="subcommand", help="Config subcommands")

    # init
    parser_init = subparsers.add_parser("init", help="Initialize a default configuration file")
    parser_init.add_argument("-f", "--force", action="store_true", help="Force overwrite existing config")

    # show
    parser_show = subparsers.add_parser("show", help="Show effective configuration")

    # validate
    parser_validate = subparsers.add_parser("validate", help="Validate configuration")

    args = parser.parse_args(sys.argv[1:])

    if args.subcommand == "init":
        return cmd_init(args)
    elif args.subcommand == "show":
        return cmd_show(args)
    elif args.subcommand == "validate":
        return cmd_validate(args)
    else:
        parser.print_help()
        return 1

if __name__ == "__main__":
    sys.exit(main())

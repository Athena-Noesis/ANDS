#!/usr/bin/env python3
"""ands_ci.py — CI-optimized ANDS validator.

Provides clean output and distinct exit codes for automation.
"""

import json
import os
import subprocess
import sys

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 tools/ands_ci.py <path_to_ands.json>")
        sys.exit(1)

    path = sys.argv[1]

    print(f"::group::ANDS Validation for {path}")

    # Run the standard validator
    cmd = [sys.executable, "tools/validate_declaration.py", path, "--verify-signature"]
    result = subprocess.run(cmd, capture_output=True, text=True)

    # Check for basic file existence and JSON validity if validator failed
    if result.returncode != 0:
        print(f"❌ FAILED: {path}")
        print(result.stdout)
        print(result.stderr)

        # GitHub Action error annotation
        print(f"::error file={path}::ANDS validation failed. See logs for details.")
        sys.exit(result.returncode)

    print(f"✅ PASSED: {path}")
    print("::endgroup::")

    # Success Summary for CI
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
            f.write(f"### ANDS Validation Passed\n- File: `{path}`\n- Signature: Valid\n")

if __name__ == "__main__":
    main()

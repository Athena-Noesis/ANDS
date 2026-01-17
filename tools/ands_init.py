#!/usr/bin/env python3
"""ands_init.py — Interactive wizard for creating ANDS declarations.

Usage:
  python3 tools/ands_init.py
"""

import base64
import json
import os
import sys
from typing import Any, Dict, List

import jcs
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

def get_input(prompt: str, default: str = "") -> str:
    p = f"{prompt} [{default}]: " if default else f"{prompt}: "
    val = input(p).strip()
    return val if val else default

def get_choice(prompt: str, choices: List[str], default: str) -> str:
    print(f"\n{prompt}")
    for i, c in enumerate(choices, 1):
        print(f"  {i}. {c}")
    while True:
        val = input(f"Select option (default {default}): ").strip()
        if not val:
            return default
        if val.isdigit():
            idx = int(val) - 1
            if 0 <= idx < len(choices):
                return choices[idx]
        print("Invalid selection.")

def main():
    import argparse
    ap = argparse.ArgumentParser(prog="ands init")
    ap.add_argument("--multi", action="store_true", help="Initialize for multiple signers")
    args_cli = ap.parse_args(sys.argv[1:])

    print("====================================================")
    print("   ANDS DECLARATION WIZARD (v1.2)")
    print("====================================================\n")
    print("This tool will guide you through creating a compliant")
    print("/.well-known/ands.json file for your AI system.\n")

    # Basic Info
    system_id = get_input("System ID (e.g., vendor.product)", "my-org.ai-v1")
    ands_ver = "1.2"
    cert_level = get_choice("Certification Level", ["SELF", "VERIFIED", "AUDITED"], "SELF")

    # ANDS Code
    print("\n--- ANDS SCORING (C.A.M.G.R) ---")
    c = get_input("Cognition (1-5)", "2")
    a = get_input("Authority (1-5)", "1")
    m = get_input("Memory (1-5)", "1")
    g = get_input("Governance (1-5)", "1")
    r = get_input("Risk (1-5)", "3")
    ands_code = f"{c}.{a}.{m}.{g}.{r}"

    # Capabilities
    print("\n--- CAPABILITIES ---")
    cap_tool = get_input("Tool Use? (y/n)", "n").lower().startswith('y')
    cap_mem = get_input("Memory Persistence? (y/n)", "n").lower().startswith('y')
    cap_exec = get_input("Autonomous Execution? (y/n)", "n").lower().startswith('y')
    cap_state = get_input("State Mutation? (y/n)", "n").lower().startswith('y')
    cap_code = get_input("Code Execution? (y/n)", "n").lower().startswith('y')

    # Links & Contact
    print("\n--- METADATA ---")
    attest_urls = get_input("Attestation URLs (comma-separated)", "")
    attest_list = [u.strip() for u in attest_urls.split(",")] if attest_urls else []
    contact = get_input("Contact info (email or URL)", "")

    # Build Doc
    doc = {
        "system_id": system_id,
        "ands_version": ands_ver,
        "declared_ands": ands_code,
        "certification_level": cert_level,
        "capabilities": {
            "tool_use": cap_tool,
            "memory_persistence": cap_mem,
            "autonomous_execution": cap_exec,
            "state_mutation": cap_state,
            "code_execution": cap_code
        }
    }

    if args_cli.multi:
        doc["signatures"] = []
        print("\n--- MULTI-SIGNER INITIALIZATION ---")
        while True:
            role = get_choice("Role for next signer", ["vendor", "auditor", "legal", "regulator"], "vendor")
            name = get_input("Signer Name/Organization")
            doc["signatures"].append({
                "role": role,
                "signer": name,
                "sig": None,
                "alg": "ed25519",
                "pubkey": None
            })
            if get_input("Add another expected signer? (y/n)", "n").lower() != 'y':
                break
    if attest_list:
        doc["attestation_urls"] = attest_list
    if contact:
        doc["contact"] = contact

    # Signing
    print("\n--- SIGNING ---")
    do_sign = get_input("Sign this declaration now? (y/n)", "y").lower().startswith('y')

    if do_sign:
        role = "vendor"
        if args_cli.multi:
            role = get_choice("Signing as which role?", [s["role"] for s in doc["signatures"]], doc["signatures"][0]["role"] if doc["signatures"] else "vendor")

        key_choice = get_choice("Key Selection", ["Generate new Ed25519 key pair", "Use existing private key (Base64)"], "Generate new Ed25519 key pair")

        priv = None
        if "Generate" in key_choice:
            priv = Ed25519PrivateKey.generate()
            priv_b64 = base64.b64encode(priv.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )).decode('utf-8')
            print(f"\nIMPORTANT: Your new private key (Base64):\n{priv_b64}")
            print("SAVE THIS KEY OFFLINE. It will not be stored in the declaration.")
        else:
            while not priv:
                kb64 = get_input("Paste Base64 Private Key")
                try:
                    kbytes = base64.b64decode(kb64)
                    priv = Ed25519PrivateKey.from_private_bytes(kbytes)
                except Exception as e:
                    print(f"Error loading key: {e}")

        pub = priv.public_key()
        pub_b64 = base64.b64encode(pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )).decode('utf-8')

        # Canonicalize and Sign (Multi-sig format)
        doc_to_sign = dict(doc)
        doc_to_sign.pop("signatures", None)
        msg = jcs.canonicalize(doc_to_sign)
        sig = priv.sign(msg)
        sig_b64 = base64.b64encode(sig).decode('utf-8')

        sig_obj = {
            "role": role,
            "signer": system_id,
            "sig": sig_b64,
            "alg": "ed25519",
            "pubkey": pub_b64,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        if "signatures" not in doc:
            doc["signatures"] = []

        # Replace placeholder if exists
        found_placeholder = False
        for i, s in enumerate(doc["signatures"]):
            if s["role"] == role and s["sig"] is None:
                doc["signatures"][i] = sig_obj
                found_placeholder = True
                break

        if not found_placeholder:
            doc["signatures"].append(sig_obj)

        print(f"\nDeclaration signed successfully as {role}.")

    # Save
    out_path = "ands.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)

    print(f"\nSUCCESS: Written to {out_path}")
    print("Move this file to your system's /.well-known/ands.json path.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(1)

import base64
import json
import os
from typing import Any, Dict, List, Tuple

import jcs
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .schema_migrator import SchemaMigrator
from .utils import logger

def validate_declaration(doc: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Validate an ANDS declaration against its specified schema version.
    Returns (is_valid, list_of_errors).
    """
    migrator = SchemaMigrator()
    version = migrator.detect_version(doc)

    try:
        schema_data = migrator.load_schema(version)
        schema_dir = migrator.get_schema_dir(version)
    except FileNotFoundError as e:
        return False, [f"Unsupported or missing schema version: {version}"]

    # Pre-load local schemas into a registry to handle relative $refs
    registry: Registry = Registry()
    try:
        for filename in os.listdir(schema_dir):
            if filename.endswith(".schema.json"):
                with open(os.path.join(schema_dir, filename), "r", encoding="utf-8") as f:
                    s = json.load(f)
                    resource = Resource.from_contents(s)
                    # Use $id if present, otherwise fallback to filename
                    uri = s.get("$id", filename)
                    registry = registry.with_resource(uri=uri, resource=resource)
    except Exception as e:
        return False, [f"Failed to load schema registry: {e}"]

    v = Draft202012Validator(schema_data, registry=registry)
    errors = sorted(v.iter_errors(doc), key=lambda e: e.path)

    if errors:
        error_msgs = []
        for e in errors:
            loc = ".".join([str(x) for x in e.path]) if e.path else "<root>"
            error_msgs.append(f"{loc}: {e.message}")
        return False, error_msgs

    return True, []

def verify_declaration_signature(doc: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Verify the Ed25519 signature in an ANDS declaration.
    Returns (is_valid, message).
    """
    signed = doc.get("signed")
    if not isinstance(signed, dict):
        return False, "Missing 'signed' block."

    alg = signed.get("alg")
    sig_b64 = signed.get("sig")
    pub_b64 = signed.get("pubkey")

    if alg != "ed25519":
        return False, f"Unsupported algorithm: {alg}. Only 'ed25519' is supported."

    if not sig_b64 or not pub_b64:
        return False, "Missing 'sig' or 'pubkey' in signed block."

    try:
        sig = base64.b64decode(sig_b64)
        pub = base64.b64decode(pub_b64)

        # Canonicalize for signing (excluding the signed block itself)
        d = dict(doc)
        d.pop("signed", None)
        msg = jcs.canonicalize(d)

        pk = Ed25519PublicKey.from_public_bytes(pub)
        pk.verify(sig, msg)
        return True, "Signature VALID."
    except Exception as e:
        return False, f"Signature INVALID: {e}"

import base64
import json
from typing import Any, Dict, Tuple
import jcs
from jsonschema import validate, ValidationError
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .utils import SchemaRegistry

def validate_schema(doc: Dict[str, Any]) -> Tuple[bool, str]:
    """Validates the declaration against its specified version's schema."""
    version = doc.get("ands_version", "1.0")
    try:
        schema = SchemaRegistry.load_schema(version)
        validate(instance=doc, schema=schema)
        return True, f"Valid ANDS {version} declaration."
    except ValidationError as e:
        return False, f"Schema validation failed: {e.message}"
    except Exception as e:
        return False, f"Error during validation: {str(e)}"

def verify_declaration_signature(doc: Dict[str, Any]) -> Tuple[bool, str]:
    signed = doc.get("signed")
    if not isinstance(signed, dict):
        return False, "Missing 'signed' block."
    alg = signed.get("alg")
    sig_b64 = signed.get("sig")
    pub_b64 = signed.get("pubkey")
    if alg != "ed25519":
        return False, f"Unsupported algorithm: {alg}"
    if not sig_b64 or not pub_b64:
        return False, "Missing sig or pubkey."
    try:
        sig = base64.b64decode(sig_b64)
        pub = base64.b64decode(pub_b64)
        d = dict(doc)
        d.pop("signed", None)
        msg = jcs.canonicalize(d)
        pk = Ed25519PublicKey.from_public_bytes(pub)
        pk.verify(sig, msg)
        return True, "Signature VALID."
    except Exception as e:
        return False, f"Signature INVALID: {e}"

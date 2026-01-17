import base64
import json
import os
from typing import Any, Dict, Tuple
import jcs
from jsonschema import Draft202012Validator, ValidationError
from referencing import Registry, Resource
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .utils import SchemaRegistry

def validate_schema(doc: Dict[str, Any]) -> Tuple[bool, str]:
    """Validates the declaration against its specified version's schema."""
    version = doc.get("ands_version", "1.0")
    try:
        schema_data = SchemaRegistry.load_schema(version)
        spec_dir = SchemaRegistry.get_schema_path(version).parent

        # Build local registry for relative $refs
        registry: Registry = Registry()
        for filename in os.listdir(spec_dir):
            if filename.endswith(".schema.json"):
                with open(os.path.join(spec_dir, filename), "r", encoding="utf-8") as f:
                    s = json.load(f)
                    resource = Resource.from_contents(s)
                    registry = registry.with_resource(uri=s.get("$id", filename), resource=resource)

        v = Draft202012Validator(schema_data, registry=registry)
        errors = list(v.iter_errors(doc))
        if errors:
            first = errors[0]
            loc = ".".join([str(x) for x in first.path]) if first.path else "<root>"
            return False, f"Schema validation failed: {loc}: {first.message}"

        return True, f"Valid ANDS {version} declaration."
    except ValidationError as e:
        return False, f"Schema validation failed: {e.message}"
    except Exception as e:
        return False, f"Error during validation: {str(e)}"

def verify_declaration_signature(doc: Dict[str, Any]) -> Tuple[bool, str]:
    version = doc.get("ands_version", "1.0")

    # Handle legacy single signature
    if "signed" in doc and "signatures" not in doc:
        return _verify_single_sig(doc, doc["signed"])

    # Handle multi-signature (ANDS 1.2+)
    signatures = doc.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        return False, "Missing 'signatures' array."

    from .config import config
    policy = config.get("validation.signature_policy", "all")
    quorum = config.get("validation.quorum", 1)

    valid_count = 0
    errors = []

    # Prepare message for multi-sig (exclude 'signatures' and legacy 'signed')
    d = dict(doc)
    d.pop("signatures", None)
    d.pop("signed", None)
    msg = jcs.canonicalize(d)

    for i, sig_obj in enumerate(signatures):
        ok, err = _verify_sig_obj(msg, sig_obj)
        if ok:
            valid_count += 1
        else:
            errors.append(f"Sig #{i} ({sig_obj.get('role', 'unknown')}): {err}")

    if policy == "all":
        if valid_count == len(signatures):
            return True, f"All {valid_count} signatures VALID."
        else:
            return False, f"Signature verification failed: {'; '.join(errors)}"
    elif policy == "any":
        if valid_count > 0:
            return True, f"At least one signature VALID ({valid_count}/{len(signatures)})."
        else:
            return False, "No valid signatures found."
    elif policy == "quorum":
        if valid_count >= quorum:
            return True, f"Quorum reached: {valid_count}/{len(signatures)} signatures VALID (needs {quorum})."
        else:
            return False, f"Quorum NOT reached: {valid_count}/{len(signatures)} VALID (needs {quorum})."

    return False, f"Unknown signature policy: {policy}"

def _verify_single_sig(doc: Dict[str, Any], signed: Dict[str, Any]) -> Tuple[bool, str]:
    d = dict(doc)
    d.pop("signed", None)
    msg = jcs.canonicalize(d)
    return _verify_sig_obj(msg, signed)

def _verify_sig_obj(msg: bytes, sig_obj: Dict[str, Any]) -> Tuple[bool, str]:
    alg = sig_obj.get("alg")
    sig_b64 = sig_obj.get("sig")
    pub_b64 = sig_obj.get("pubkey")
    if alg != "ed25519":
        return False, f"Unsupported algorithm: {alg}"
    if not sig_b64 or not pub_b64:
        return False, "Missing sig or pubkey."
    try:
        sig = base64.b64decode(sig_b64)
        pub = base64.b64decode(pub_b64)
        pk = Ed25519PublicKey.from_public_bytes(pub)
        pk.verify(sig, msg)
        return True, "VALID"
    except Exception as e:
        return False, str(e)

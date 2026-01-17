from typing import Any, Dict

def migrate(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Migrates an ANDS 1.1 declaration to 1.2 (Multi-Signature)."""
    doc["ands_version"] = "1.2"

    # Transform 'signed' object to 'signatures' array
    if "signed" in doc:
        signed = doc.pop("signed")

        # Build initial vendor signature from existing data
        sig_obj = {
            "role": "vendor",
            "signer": doc.get("system_id", "Unknown Vendor"),
            "sig": signed.get("sig"),
            "alg": signed.get("alg", "ed25519"),
            "pubkey": signed.get("pubkey")
        }

        # Add timestamp if missing
        from datetime import datetime, timezone
        sig_obj["timestamp"] = datetime.now(timezone.utc).isoformat()

        doc["signatures"] = [sig_obj]

    return doc

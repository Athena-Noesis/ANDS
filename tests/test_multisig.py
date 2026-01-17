import json
import base64
import pytest
from pathlib import Path
from ands.migrations.engine import MigrationEngine
from ands.validator import verify_declaration_signature, validate_schema
from ands.config import config
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def test_migration_1_1_to_1_2_multisig():
    doc = {
        "system_id": "test.system",
        "ands_version": "1.1",
        "declared_ands": "2.1.2.3.4.1",
        "certification_level": "SELF",
        "signed": {
            "sig": "sig1",
            "alg": "ed25519",
            "pubkey": "pub1"
        }
    }

    new_doc = MigrationEngine.migrate(doc, "1.2")

    assert new_doc["ands_version"] == "1.2"
    assert "signed" not in new_doc
    assert len(new_doc["signatures"]) == 1
    assert new_doc["signatures"][0]["role"] == "vendor"
    assert new_doc["signatures"][0]["sig"] == "sig1"

def test_multi_sign_cli(tmp_path):
    # Generate two keys
    priv1 = Ed25519PrivateKey.generate()
    priv2 = Ed25519PrivateKey.generate()

    def to_b64(key):
        from cryptography.hazmat.primitives import serialization
        return base64.b64encode(key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )).decode('utf-8')

    key1 = to_b64(priv1)
    key2 = to_b64(priv2)

    doc = {
        "system_id": "test.system",
        "ands_version": "1.2",
        "declared_ands": "2.1.2.3.4.1",
        "certification_level": "SELF"
    }
    p = tmp_path / "ands.json"
    p.write_text(json.dumps(doc))

    import subprocess
    import os
    env = {**os.environ, "PYTHONPATH": "."}

    # Sign as vendor
    subprocess.run(["python3", "tools/ands_sign.py", str(p), "--role", "vendor", "--key", key1, "--name", "Vendor"], env=env, check=True)

    # Sign as auditor
    subprocess.run(["python3", "tools/ands_sign.py", str(p), "--role", "auditor", "--key", key2, "--name", "Auditor"], env=env, check=True)

    migrated = json.loads(p.read_text())
    assert len(migrated["signatures"]) == 2

    # Validate
    config.set("validation.signature_policy", "all")
    ok, msg = verify_declaration_signature(migrated)
    assert ok, msg
    assert "All 2 signatures VALID" in msg

def test_quorum_policy():
    # Setup doc with 2 valid and 1 invalid sig
    priv = Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives import serialization
    pub_b64 = base64.b64encode(priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode('utf-8')

    doc = {
        "system_id": "test",
        "ands_version": "1.2",
        "declared_ands": "1.1.1.1.1.1",
        "certification_level": "SELF"
    }
    import jcs
    msg = jcs.canonicalize(doc)
    sig_b64 = base64.b64encode(priv.sign(msg)).decode('utf-8')

    doc["signatures"] = [
        {"role": "vendor", "signer": "v", "sig": sig_b64, "alg": "ed25519", "pubkey": pub_b64},
        {"role": "auditor", "signer": "a", "sig": "invalid", "alg": "ed25519", "pubkey": pub_b64}
    ]

    config.set("validation.signature_policy", "quorum")
    config.set("validation.quorum", 1)
    ok, msg = verify_declaration_signature(doc)
    assert ok
    assert "Quorum reached: 1/2" in msg

    config.set("validation.quorum", 2)
    ok, msg = verify_declaration_signature(doc)
    assert not ok
    assert "Quorum NOT reached: 1/2" in msg

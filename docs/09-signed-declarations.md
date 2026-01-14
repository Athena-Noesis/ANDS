# Signed ANDS Declarations (Ed25519)

ANDS supports optional signatures for `/.well-known/ands.json`.

## Why sign?
A signature does not prove the system behaves as declared, but it:
- provides non-repudiation for the declaration text
- prevents silent tampering of the published declaration
- supports VERIFIED/AUDITED workflows that keep evidence on file

## Canonical signing input (v1.0)
To avoid ambiguity, the signature is computed over a canonical JSON string of the declaration **excluding** the `signed` object.

Algorithm:
1. Parse the JSON into an object.
2. Remove the top-level key `signed` if present.
3. Serialize using:
   - UTF-8
   - `sort_keys=True`
   - `separators=(",", ":")`
   - no pretty printing
4. Sign the resulting bytes with Ed25519.

## Fields
`/.well-known/ands.json` may include:

```json
"signed": {
  "alg": "ed25519",
  "sig": "<base64 signature>",
  "pubkey": "<base64 public key>"
}
```

## Verification
Use:

```bash
python3 tools/validate_declaration.py path/to/ands.json --verify-signature
```

If signature fields are missing or empty, verification will fail in `--verify-signature` mode.

## Notes
- Use standard base64 (not URL-safe) for `sig` and `pubkey`.
- Keep the private key offline; publish only the public key.

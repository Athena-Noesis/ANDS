# Multi-Signature Notarization

ANDS 1.2 introduces support for collaborative signing, allowing multiple parties (Vendors, Auditors, Legal teams) to notarize a single declaration.

## Signature Array

Declarations now use a `signatures` array instead of a single `signed` block. Each signature object includes the following:

- **`role`**: One of `vendor`, `auditor`, `legal`, or `regulator`.
- **`signer`**: Name of the organization or person signing.
- **`sig`**: Base64 encoded Ed25519 signature.
- **`pubkey`**: Base64 encoded Ed25519 public key.
- **`timestamp`**: ISO-8601 timestamp of the signature.

### Example
```json
"signatures": [
  {
    "role": "vendor",
    "signer": "Athena Noesis",
    "sig": "...",
    "pubkey": "...",
    "timestamp": "2026-01-17T12:00:00Z"
  },
  {
    "role": "auditor",
    "signer": "Independent Audit Corp",
    "sig": "...",
    "pubkey": "...",
    "timestamp": "2026-01-17T14:30:00Z"
  }
]
```

## CLI: `ands sign`

The `ands sign` command is used to append or update signatures in a declaration.

```bash
ands sign declaration.json --role auditor --name "Independent Audit Corp" --key <PRIVATE_KEY_B64>
```

## Trust Policies

The toolkit supports configurable trust policies for multi-signature verification, defined in `ands.config.yaml`.

- **`all` (Default)**: All signatures in the array must be valid.
- **`any`**: At least one signature must be valid.
- **`quorum`**: At least `N` signatures must be valid (defined by `validation.quorum`).

```yaml
validation:
  signature_policy: "quorum"
  quorum: 2
```

## Initialization: `ands init --multi`

You can pre-define expected signers when creating a declaration using the `--multi` flag:

```bash
ands init --multi
```
This will create placeholders in the `signatures` array that can be populated later using `ands sign`.

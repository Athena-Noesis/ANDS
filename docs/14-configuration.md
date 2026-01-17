# ANDS Configuration Management

The ANDS toolkit supports a centralized configuration system that allows you to define global settings for all tools.

## Configuration File: `ands.config.yaml`

The toolkit looks for the configuration file in the following locations, in order of priority:

1.  **Environment Variable**: Path specified by `$ANDS_CONFIG`.
2.  **Local Project**: `ands.config.yaml` in the current working directory.
3.  **User Home**: `~/.ands/config.yaml`.
4.  **Internal Defaults**: Built-in baseline settings in `ands/config.py`.

### Default Configuration Structure

```yaml
general:
  schema_version: "1.2"          # default schema version
  language: "en"                 # default language for reports
  timezone: "UTC"                # for timestamp consistency

network:
  timeout: 10                    # default request timeout (seconds)
  retries: 3                     # retry count for failed requests
  backoff_factor: 1.5            # exponential backoff multiplier
  user_agent: "ANDS-Toolkit/1.2"
  proxy: null                    # optional proxy (e.g., http://proxy:8080)

security:
  verify_tls: true               # verify SSL/TLS certificates
  ca_bundle: null                # optional path to custom CA
  mtls_cert: null                # optional mutual TLS cert
  mtls_key: null                 # optional mutual TLS key

scanner:
  live_scan_enabled: false       # for CI/CD pipelines
  max_response_size: 5242880     # 5 MB limit on downloaded files
  openapi_paths:                 # fallback discovery paths
    - openapi.json
    - api/v1/openapi.json
    - swagger.json
  signature_policy: "all"        # "all", "any", or "quorum"
  quorum: 2                      # used when signature_policy=quorum

logging:
  level: "INFO"                  # DEBUG | INFO | WARNING | ERROR
  format: "json"                 # "text" | "json"
  file: null                     # path to log file, or null for stdout

audit:
  evidence_dir: "./evidence"     # default directory for evidence files
  bundle_signing: true           # automatically sign .andsz bundles
  keep_history: true             # retain old bundle versions

paths:
  schema_dir: "./schemas"
  policy_dir: "./policies"
  reports_dir: "./reports"
```

## Environment Variable Overrides

Every configuration key can be overridden by environment variables using the pattern `ANDS_{SECTION}_{KEY}`.

| Config Key | Environment Variable |
|------------|----------------------|
| `network.timeout` | `ANDS_NETWORK_TIMEOUT` |
| `network.retries` | `ANDS_NETWORK_RETRIES` |
| `network.proxy` | `ANDS_NETWORK_PROXY` |
| `logging.level` | `ANDS_LOGGING_LEVEL` |
| `scanner.signature_policy` | `ANDS_SCANNER_SIGNATURE_POLICY` |

## CLI Commands

### `ands config init`
Generates a default `ands.config.yaml` in the current directory.
```bash
ands config init
```

### `ands config show`
Displays the active merged configuration.
```bash
ands config show
```

## Usage in Custom Tools

If you are developing custom tools for the ANDS ecosystem, you can access the global configuration as follows:

```python
from ands.config import config

# Get a value with dot-notation and a default
timeout = config.get("network.timeout")

# Get a path (automatically expands '~' to home directory)
schema_dir = config.get_path("paths.schema_dir")
```

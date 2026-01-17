# ANDS Configuration Management

The ANDS toolkit supports a centralized configuration system that allows you to define global settings for all tools.

## Configuration File: `ands.config.yaml`

The toolkit looks for the configuration file in the following locations, in order of priority:

1.  **Environment Variable**: Path specified by `$ANDS_CONFIG`.
2.  **Local Project**: `ands.config.yaml` in the current working directory.
3.  **User Home**: `~/.ands/config.yaml`.
4.  **Internal Defaults**: Built-in baseline settings.

### Default Configuration Structure

```yaml
general:
  version: 1.0
  default_language: "en"
  schema_path: "./schemas"
  cache_dir: "~/.ands/cache"

network:
  timeout: 20                # seconds
  retries: 3
  retry_backoff: 2.0         # exponential backoff factor
  user_agent: "ANDS-Scanner/1.0"
  proxy: null                # e.g. "http://proxy.local:8080"

security:
  verify_ssl: true
  ca_bundle: null            # custom CA path
  private_key: "~/.ands/keys/auditor.key"
  public_key: "~/.ands/keys/auditor.pub"

logging:
  level: "INFO"              # DEBUG, INFO, WARNING, ERROR
  log_file: "~/.ands/logs/ands.log"

scanner:
  default_openapi_paths:
    - "openapi.json"
    - "v1/openapi.json"
    - "api/v1/openapi.json"
  max_response_size_mb: 5
  signature_algorithm: "ed25519"
```

## Environment Variable Overrides

Every critical setting can be overridden by environment variables:

| Config Key | Environment Variable |
|------------|----------------------|
| `network.timeout` | `ANDS_TIMEOUT` |
| `network.retries` | `ANDS_RETRIES` |
| `network.proxy` | `ANDS_PROXY` |
| `logging.level` | `ANDS_LOG_LEVEL` |
| `security.private_key` | `ANDS_PRIVATE_KEY` |
| `security.verify_ssl` | `ANDS_VERIFY_SSL` |

## CLI Commands

The `ands config` command allows you to manage your configuration:

### `ands config init`
Generates a default `ands.config.yaml` in the current directory.
```bash
ands config init
```

### `ands config show`
Displays the active configuration with all overrides and merges applied.
```bash
ands config show
```

### `ands config validate`
Validates the current configuration for syntax and structure.
```bash
ands config validate
```

## Usage in Custom Tools

If you are developing custom tools for the ANDS ecosystem, you can access the global configuration as follows:

```python
from ands.config import config

# Get a value with dot-notation and a default
timeout = config.get("network.timeout", 20)

# Set a value at runtime
config.set("network.proxy", "http://localhost:8080")
```

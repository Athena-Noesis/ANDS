import os
import yaml
from pathlib import Path
from typing import Any, Dict, Optional

class ANDSConfigError(Exception):
    """Custom exception for ANDS configuration errors."""
    pass

class Config:
    _instance = None

    def __new__(cls):
        if not cls._instance:
            cls._instance = super(Config, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self.load()
        self._initialized = True

    def load(self):
        """Loads configuration from available sources and applies overrides."""
        self.data = self._load_from_files()
        self._apply_env_overrides()

    def reload(self):
        """Reloads the configuration."""
        self.load()

    def _default_config(self) -> Dict[str, Any]:
        """Returns the default baseline configuration."""
        return {
            "general": {
                "version": 1.0,
                "default_language": "en",
                "schema_path": "./schemas",
                "cache_dir": "~/.ands/cache"
            },
            "network": {
                "timeout": 20,
                "retries": 3,
                "retry_backoff": 2.0,
                "user_agent": "ANDS-Scanner/1.0",
                "proxy": None
            },
            "security": {
                "verify_ssl": True,
                "ca_bundle": None,
                "private_key": "~/.ands/keys/auditor.key",
                "public_key": "~/.ands/keys/auditor.pub"
            },
            "logging": {
                "level": "INFO",
                "log_file": "~/.ands/logs/ands.log"
            },
            "scanner": {
                "default_openapi_paths": [
                    "openapi.json",
                    "v1/openapi.json",
                    "api/v1/openapi.json"
                ],
                "max_response_size_mb": 5,
                "signature_algorithm": "ed25519"
            },
            "validation": {
                "signature_policy": "all",
                "quorum": 1
            }
        }

    def _load_from_files(self) -> Dict[str, Any]:
        """Resolves configuration from tiered file paths."""
        sources = [
            os.getenv("ANDS_CONFIG"),
            Path.cwd() / "ands.config.yaml",
            Path.home() / ".ands" / "config.yaml"
        ]

        # Start with defaults
        merged_config = self._default_config()

        # Iterate in reverse order of priority to merge (lower priority first)
        # Actually, if we find one, should we stop or merge?
        # ChatGPT said: ANDS_CONFIG > local config > user config > defaults.
        # So we should probably merge them in that order.

        # To merge properly: defaults < user < local < env_var
        paths_to_load = [
            Path.home() / ".ands" / "config.yaml",
            Path.cwd() / "ands.config.yaml"
        ]
        if os.getenv("ANDS_CONFIG"):
            paths_to_load.append(Path(os.getenv("ANDS_CONFIG")))

        for path in paths_to_load:
            if path and Path(path).is_file():
                try:
                    with open(path, "r") as f:
                        file_data = yaml.safe_load(f)
                        if isinstance(file_data, dict):
                            self._deep_update(merged_config, file_data)
                        elif file_data is not None:
                            raise ANDSConfigError(f"Configuration file {path} must be a dictionary.")
                except Exception as e:
                    raise ANDSConfigError(f"Failed to load config from {path}: {e}")

        return merged_config

    def _deep_update(self, base_dict: Dict[str, Any], update_dict: Dict[str, Any]):
        """Recursively updates a dictionary."""
        for key, value in update_dict.items():
            if isinstance(value, dict) and key in base_dict and isinstance(base_dict[key], dict):
                self._deep_update(base_dict[key], value)
            else:
                base_dict[key] = value

    def _apply_env_overrides(self):
        """Applies environment variable overrides."""
        mapping = {
            "ANDS_TIMEOUT": "network.timeout",
            "ANDS_RETRIES": "network.retries",
            "ANDS_PROXY": "network.proxy",
            "ANDS_LOG_LEVEL": "logging.level",
            "ANDS_PRIVATE_KEY": "security.private_key",
            "ANDS_VERIFY_SSL": "security.verify_ssl"
        }

        for env_var, config_key in mapping.items():
            value = os.getenv(env_var)
            if value is not None:
                # Convert types if necessary
                if config_key == "network.timeout" or config_key == "network.retries":
                    try:
                        value = int(value)
                    except ValueError:
                        pass
                elif config_key == "security.verify_ssl":
                    value = value.lower() in ("true", "1", "yes")

                self.set(config_key, value)

    def get(self, key: str, default: Any = None) -> Any:
        """Gets a configuration value using dot-notation."""
        parts = key.split(".")
        value = self.data
        for part in parts:
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return default
        return value

    def set(self, key: str, value: Any):
        """Sets a configuration value using dot-notation."""
        parts = key.split(".")
        target = self.data
        for part in parts[:-1]:
            if part not in target or not isinstance(target[part], dict):
                target[part] = {}
            target = target[part]
        target[parts[-1]] = value

    def to_yaml(self) -> str:
        """Returns the configuration as a YAML string."""
        return yaml.dump(self.data, default_flow_style=False)

# Singleton instance
config = Config()

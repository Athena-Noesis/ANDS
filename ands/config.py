import os
import yaml
from pathlib import Path
from typing import Any, Dict, Optional

class Config:
    """Singleton configuration manager for the ANDS toolkit."""
    _instance = None
    _config_data: Dict[str, Any] = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Config, cls).__new__(cls)
            cls._instance._load_config()
        return cls._instance

    def _get_defaults(self) -> Dict[str, Any]:
        """Returns internal default configuration."""
        return {
            "general": {
                "schema_version": "1.0",
                "language": "en",
                "timezone": "UTC"
            },
            "network": {
                "timeout": 10,
                "retries": 3,
                "backoff_factor": 1.5,
                "user_agent": "ANDS-Toolkit/1.2",
                "proxy": None
            },
            "security": {
                "verify_tls": True,
                "ca_bundle": None,
                "mtls_cert": None,
                "mtls_key": None
            },
            "scanner": {
                "live_scan_enabled": False,
                "max_response_size": 5242880,
                "openapi_paths": [
                    "openapi.json",
                    "api/v1/openapi.json",
                    "swagger.json"
                ],
                "signature_policy": "all",
                "quorum": 2
            },
            "logging": {
                "level": "INFO",
                "format": "json",
                "file": None
            },
            "audit": {
                "evidence_dir": "./evidence",
                "bundle_signing": True,
                "keep_history": True
            },
            "paths": {
                "schema_dir": "./schemas",
                "policy_dir": "./policies",
                "reports_dir": "./reports"
            }
        }

    def _load_config(self):
        """Resolves configuration from tiered sources and environment overrides."""
        # 1. Start with internal defaults
        data = self._get_defaults()

        # 2. Merge from files (Home < Local < ANDS_CONFIG)
        paths = [
            Path.home() / ".ands" / "config.yaml",
            Path.cwd() / "ands.config.yaml",
            Path(os.getenv("ANDS_CONFIG", "")) if os.getenv("ANDS_CONFIG") else None
        ]

        for path in paths:
            if path and path.is_file():
                try:
                    with open(path, "r") as f:
                        file_data = yaml.safe_load(f)
                        if isinstance(file_data, dict):
                            self._deep_update(data, file_data)
                except Exception as e:
                    print(f"Warning: Failed to load config from {path}: {e}")

        # 3. Apply Environment Variable Overrides
        self._apply_env_overrides(data)

        self._config_data = data

    def _deep_update(self, base_dict: Dict[str, Any], update_dict: Dict[str, Any]):
        """Recursively updates a dictionary."""
        for key, value in update_dict.items():
            if isinstance(value, dict) and key in base_dict and isinstance(base_dict[key], dict):
                self._deep_update(base_dict[key], value)
            else:
                base_dict[key] = value

    def _apply_env_overrides(self, data: Dict[str, Any]):
        """Maps environment variables to configuration keys."""
        for section, settings in data.items():
            if not isinstance(settings, dict):
                continue
            for key, value in settings.items():
                env_key = f"ANDS_{section.upper()}_{key.upper()}"
                if env_key in os.environ:
                    env_val = os.environ[env_key]
                    # Attempt type conversion based on default value
                    if isinstance(value, bool):
                        data[section][key] = env_val.lower() in ("true", "1", "yes")
                    elif isinstance(value, int):
                        try:
                            data[section][key] = int(env_val)
                        except ValueError:
                            pass
                    elif isinstance(value, float):
                        try:
                            data[section][key] = float(env_val)
                        except ValueError:
                            pass
                    elif isinstance(value, list):
                        data[section][key] = [v.strip() for v in env_val.split(",")]
                    else:
                        data[section][key] = env_val

    def get(self, key: str, default: Any = None) -> Any:
        """Gets a configuration value using dot-notation (e.g., 'network.timeout')."""
        parts = key.split(".")
        val = self._config_data
        for p in parts:
            if isinstance(val, dict) and p in val:
                val = val[p]
            else:
                return default
        return val

    def get_path(self, key: str, default: Any = None) -> Optional[Path]:
        """Gets a configuration value as a Path object, expanding '~'."""
        val = self.get(key, default)
        if val is None:
            return None
        return Path(os.path.expanduser(str(val)))

    def to_yaml(self) -> str:
        """Returns the current merged configuration as YAML."""
        return yaml.dump(self._config_data, default_flow_style=False)

# Global singleton instance
config = Config()

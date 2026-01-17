import importlib.util
import os
from pathlib import Path
from typing import List, Any, Dict
from .models import Evidence, ProbeResult

class BaseScannerPlugin:
    """Base class for all ANDS scanner plugins."""
    def name(self) -> str:
        return self.__class__.__name__

    def execute_probe(self, target_url: str, session: Any, evidence: List[Evidence], gaps: List[str]):
        """Override to perform network-based probes."""
        pass

    def analyze_hints(self, openapi: Dict[str, Any], hints: List[str]):
        """Override to add specialized hints from OpenAPI specs."""
        pass

def load_plugins(plugin_dir: str = None) -> List[BaseScannerPlugin]:
    if not plugin_dir:
        plugin_dir = os.path.join(os.path.dirname(__file__), "plugins")

    plugins = []
    if not os.path.exists(plugin_dir):
        return plugins

    for f in os.listdir(plugin_dir):
        if f.endswith(".py") and not f.startswith("__"):
            path = os.path.join(plugin_dir, f)
            spec = importlib.util.spec_from_file_location(f[:-3], path)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (isinstance(attr, type) and
                        issubclass(attr, BaseScannerPlugin) and
                        attr is not BaseScannerPlugin):
                        plugins.append(attr())
    return plugins

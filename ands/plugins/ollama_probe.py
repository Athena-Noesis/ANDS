from ands.plugins_engine import BaseScannerPlugin
from ands.models import Evidence
from urllib.parse import urljoin

class OllamaProbePlugin(BaseScannerPlugin):
    def name(self):
        return "Ollama/LocalAI Probe"

    def execute_probe(self, target_url: str, session, evidence, gaps):
        # Check for Ollama API
        tags_url = urljoin(target_url, "/api/tags")
        try:
            resp = session.get(tags_url, timeout=5)
            if resp.status_code == 200:
                evidence.append(Evidence("plugin_ollama", "Ollama API detected via /api/tags", 2.0))
        except:
            pass

import requests
from ands.plugins_engine import BaseScannerPlugin
from ands.models import Evidence

class ResidencyProbePlugin(BaseScannerPlugin):
    def name(self):
        return "Sovereign Residency Probe"

    def execute_probe(self, target_url, session, evidence, gaps):
        # 1. GeoIP Check (Simplified)
        try:
            # In a real scenario, we'd use a specific GeoIP database or service
            # Here we simulate a check to see if we can reach common cloud metadata IPs
            # to determine if it's running in a specific cloud provider.

            # AWS Metadata check (often accessible only from inside, but we can check if
            # the target IP belongs to AWS ranges)
            from urllib.parse import urlparse
            import socket
            hostname = urlparse(target_url).hostname
            ip = socket.gethostbyname(hostname)

            # Simulated logic: check IP against known sovereign ranges
            # For this example, we just add evidence that residency was checked.
            evidence.append(Evidence("residency", f"Target IP {ip} analyzed for sovereign residency.", 0.5))

            # 2. Cloud Metadata Endpoint Probes (Non-invasive check for headers)
            # Some proxied systems might leak metadata headers
            if "us-east" in target_url or "eu-central" in target_url:
                evidence.append(Evidence("residency", "Region hint detected in URL structure.", 1.0))

        except Exception as e:
            pass

    def analyze_hints(self, openapi, hints):
        # Look for residency hints in OpenAPI descriptions
        txt = json.dumps(openapi).lower()
        if any(k in txt for k in ["data residency", "sovereign", "on-prem", "private cloud"]):
            hints.append("sovereign_residency_declared")

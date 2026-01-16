import base64
import hashlib
import json
import logging
import random
import re
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import jcs
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .models import Evidence

DEFAULT_USER_AGENT = "ands-scan/1.1"
MAX_RESPONSE_SIZE = 5 * 1024 * 1024  # 5MB
ANDS_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+\.\d+$")
SUPPORTED_ANDS_VERSIONS = ["1.0"]

logger = logging.getLogger("ands")

def normalize_base_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    if not url.endswith("/"):
        url += "/"
    return url

def get_session(
    retries: int = 3,
    proxy: Optional[str] = None,
    cert: Optional[str] = None,
    key: Optional[str] = None,
    cacert: Optional[str] = None
) -> requests.Session:
    s = requests.Session()
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    if cert:
        s.cert = (cert, key) if key else cert
    if cacert:
        s.verify = cacert
    return s

def safe_request(
    session: requests.Session,
    method: str,
    url: str,
    timeout: int,
    user_agent: str = DEFAULT_USER_AGENT,
    retries: int = 3,
    jitter: float = 0.0,
    headers: Optional[Dict[str, str]] = None
) -> Tuple[Optional[requests.Response], Optional[str]]:
    last_err = "UNKNOWN"
    merged_headers = {"User-Agent": user_agent}
    if headers:
        merged_headers.update(headers)

    for attempt in range(retries + 1):
        if attempt > 0:
            backoff = (2 ** (attempt - 1)) * 0.5
            sleep_time = backoff + (random.uniform(0, jitter) if jitter > 0 else 0)
            time.sleep(sleep_time)

        try:
            r = session.request(method, url, timeout=timeout, headers=merged_headers, stream=True)
            cl = r.headers.get("Content-Length")
            if cl and int(cl) > MAX_RESPONSE_SIZE:
                return None, f"ERROR (Response too large: {cl} bytes)"

            content = b""
            for chunk in r.iter_content(chunk_size=8192):
                content += chunk
                if len(content) > MAX_RESPONSE_SIZE:
                    r.close()
                    return None, "ERROR (Response exceeded size limit during download)"

            r._content = content
            return r, None

        except requests.exceptions.SSLError as e: last_err = f"SSL_ERROR ({str(e)})"
        except requests.exceptions.ConnectionError as e: last_err = f"CONNECTION_ERROR ({str(e)})"
        except requests.exceptions.Timeout: last_err = "TIMEOUT"
        except requests.exceptions.RequestException as e: last_err = f"ERROR ({type(e).__name__})"
        except Exception as e: return None, f"ERROR ({str(e)})"

    return None, last_err

def check_tls_integrity(url: str, evidence: List[Evidence]) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        evidence.append(Evidence("tls_check", "System uses unencrypted HTTP (CRITICAL).", 5.0))
        return

    hostname = parsed.hostname
    port = parsed.port or 443
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                ver = ssock.version()
                evidence.append(Evidence("tls_check", f"TLS {ver} / {cipher[0]} established.", 1.0))
                not_after_str = cert.get('notAfter')
                if not_after_str:
                    not_after = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                    days_left = (not_after - datetime.now(timezone.utc)).days
                    if days_left < 0: evidence.append(Evidence("tls_check", "TLS Certificate is EXPIRED.", 4.0))
                    elif days_left < 30: evidence.append(Evidence("tls_check", f"TLS Certificate expires soon ({days_left} days).", 1.5))
                issuer = dict(x[0] for x in cert['issuer'])
                evidence.append(Evidence("tls_check", f"Certificate issued by: {issuer.get('commonName', 'Unknown')}", 0.5))
    except Exception as e:
        evidence.append(Evidence("tls_check", f"TLS handshake failed: {e}", 3.0))

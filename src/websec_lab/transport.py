"""Verified loopback transport for the five explicitly configured HTTPS hosts.

The URL, Host header, TLS SNI and certificate hostname remain the public
origin. Only the TCP destination is mapped, without changing global DNS.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3 import HTTPSConnectionPool

from websec_lab.config import repository_root

LAB_HOSTS = ("victim.test", "attacker.test", "same.victim.test", "partner.test", "audit.test")
LAB_PORT = 8443


def is_lab_https(url: str) -> bool:
    parts = urlsplit(url)
    return parts.scheme == "https" and parts.hostname in LAB_HOSTS and parts.port == LAB_PORT


def ca_path() -> Path:
    return repository_root() / ".websec-local/certs/root-ca.crt"


class LabHTTPSAdapter(HTTPAdapter):
    def __init__(self):
        super().__init__()
        self.lab_pools: dict[str, HTTPSConnectionPool] = {}

    def get_connection_with_tls_context(self, request, verify, proxies=None, cert=None):
        if not is_lab_https(request.url):
            return super().get_connection_with_tls_context(request, verify, proxies, cert)
        host = urlsplit(request.url).hostname
        if host not in self.lab_pools:
            self.lab_pools[host] = HTTPSConnectionPool(
                "127.0.0.1",
                LAB_PORT,
                server_hostname=host,
                assert_hostname=host,
                cert_reqs="CERT_REQUIRED",
                ca_certs=str(ca_path()),
            )
        return self.lab_pools[host]

    def cert_verify(self, conn, url, verify, cert):
        super().cert_verify(conn, url, str(ca_path()) if is_lab_https(url) else verify, cert)

    def send(self, request, **kwargs):
        if is_lab_https(request.url):
            request.headers["Host"] = urlsplit(request.url).netloc
        return super().send(request, **kwargs)

    def close(self):
        for pool in self.lab_pools.values():
            pool.close()
        super().close()


def lab_session() -> requests.Session:
    session = requests.Session()
    session.trust_env = False
    session.mount("https://", LabHTTPSAdapter())
    return session


def local_get(url: str, **kwargs) -> requests.Response:
    if not is_lab_https(url):
        return requests.get(url, **kwargs)
    with lab_session() as session:
        return session.get(url, **kwargs)

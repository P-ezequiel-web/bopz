"""Cliente HTTP compartido por el crawler y todos los checks.

Centraliza: User-Agent identificable (buena práctica: cualquier víctima
de un escaneo mal dirigido puede ver en sus logs que fue BopZ), delay
entre requests para no comportarse como un DoS accidental, timeout, y
un contador global de requests para el resumen final.
"""
from __future__ import annotations

import time
from urllib.parse import urlparse

import requests

USER_AGENT = "BopZ-Scanner/1.0 (+https://github.com/P-ezequiel-web/bopz; pentest-lab-tool)"


class BopzSession:
    def __init__(self, delay: float = 0.2, timeout: float = 8.0, verify_tls: bool = True):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.delay = delay
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.request_count = 0
        self._base_host: str | None = None

    def bind_scope(self, base_url: str) -> None:
        """Fija el host objetivo; same-origin check lo usa para no salirse de scope."""
        self._base_host = urlparse(base_url).netloc

    def in_scope(self, url: str) -> bool:
        if self._base_host is None:
            return True
        return urlparse(url).netloc == self._base_host

    def _throttle(self) -> None:
        if self.delay > 0:
            time.sleep(self.delay)

    def get(self, url: str, **kwargs) -> requests.Response | None:
        if not self.in_scope(url):
            return None
        self._throttle()
        self.request_count += 1
        try:
            return self.session.get(
                url, timeout=self.timeout, verify=self.verify_tls,
                allow_redirects=True, **kwargs,
            )
        except requests.RequestException:
            return None

    def post(self, url: str, data: dict | None = None, **kwargs) -> requests.Response | None:
        if not self.in_scope(url):
            return None
        self._throttle()
        self.request_count += 1
        try:
            return self.session.post(
                url, data=data, timeout=self.timeout, verify=self.verify_tls,
                allow_redirects=True, **kwargs,
            )
        except requests.RequestException:
            return None

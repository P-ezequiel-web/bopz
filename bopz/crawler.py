"""Crawler same-origin: construye el mapa del sitio que consumen los checks.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, urldefrag

from bs4 import BeautifulSoup

from bopz.http_client import BopzSession


@dataclass
class FormInfo:
    action: str
    method: str
    inputs: list[dict] = field(default_factory=list)
    found_on: str = ""

    @property
    def has_csrf_token(self) -> bool:
        csrf_patterns = ("csrf", "_token", "authenticity_token", "csrfmiddlewaretoken")
        return any(
            any(p in (inp.get("name") or "").lower() for p in csrf_patterns)
            for inp in self.inputs
        )


@dataclass
class SiteMap:
    base_url: str
    pages: dict[str, int] = field(default_factory=dict)   # url -> status_code
    forms: list[FormInfo] = field(default_factory=list)
    query_params: dict[str, set] = field(default_factory=dict)  # url_sin_query -> {params}
    cookies: dict = field(default_factory=dict)
    request_count: int = 0


class Crawler:
    def __init__(self, session: BopzSession, max_depth: int = 2, max_pages: int = 60):
        self.session = session
        self.max_depth = max_depth
        self.max_pages = max_pages

    def crawl(self, base_url: str) -> SiteMap:
        self.session.bind_scope(base_url)
        sitemap = SiteMap(base_url=base_url)
        visited: set[str] = set()
        queue: list[tuple[str, int]] = [(base_url, 0)]

        while queue and len(visited) < self.max_pages:
            url, depth = queue.pop(0)
            url = urldefrag(url)[0]
            if url in visited or depth > self.max_depth:
                continue
            visited.add(url)

            resp = self.session.get(url)
            if resp is None:
                continue
            sitemap.pages[url] = resp.status_code
            sitemap.cookies.update(self.session.session.cookies.get_dict())

            self._extract_query_params(url, sitemap)

            if "text/html" not in resp.headers.get("Content-Type", ""):
                continue

            soup = BeautifulSoup(resp.text, "html.parser")

            for form_tag in soup.find_all("form"):
                sitemap.forms.append(self._parse_form(form_tag, url))

            if depth < self.max_depth:
                for a in soup.find_all("a", href=True):
                    next_url = urldefrag(urljoin(url, a["href"]))[0]
                    if self.session.in_scope(next_url) and next_url not in visited:
                        queue.append((next_url, depth + 1))

        sitemap.request_count = self.session.request_count
        return sitemap

    @staticmethod
    def _parse_form(form_tag, found_on: str) -> FormInfo:
        action = form_tag.get("action") or found_on
        action = urljoin(found_on, action)
        method = (form_tag.get("method") or "GET").upper()
        inputs = []
        for tag in form_tag.find_all(["input", "textarea", "select"]):
            inputs.append({
                "name": tag.get("name"),
                "type": tag.get("type", "text"),
            })
        return FormInfo(action=action, method=method, inputs=inputs, found_on=found_on)

    @staticmethod
    def _extract_query_params(url: str, sitemap: SiteMap) -> None:
        parsed = urlparse(url)
        if not parsed.query:
            return
        base = url.split("?")[0]
        params = {p.split("=")[0] for p in parsed.query.split("&") if p}
        sitemap.query_params.setdefault(base, set()).update(params)

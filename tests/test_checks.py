"""Tests unitarios de BopZ — se ejecutan sin levantar ningún servidor.

Se mockan las respuestas HTTP para que los checks puedan probarse de
forma determinista y rápida (< 1 s total) sin necesidad de un objetivo
real. Útil para CI y para verificar que refactors no rompen la lógica
de detección.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import unittest
from unittest.mock import MagicMock, patch

from bopz.checks.base import Severity
from bopz.checks.csrf import CsrfCheck
from bopz.checks.headers import HeadersCheck
from bopz.checks.xss import XssCheck
from bopz.crawler import FormInfo, SiteMap


def _make_sitemap(base="http://localhost:5001", forms=None, params=None, cookies=None):
    sm = SiteMap(base_url=base)
    sm.forms = forms or []
    sm.query_params = params or {}
    sm.cookies = cookies or {}
    return sm


def _make_session(responses: dict):
    """responses: {url: mock_response_obj}"""
    sess = MagicMock()
    sess.request_count = 0

    def fake_get(url, **kwargs):
        sess.request_count += 1
        for pattern, resp in responses.items():
            if pattern in url:
                return resp
        return None

    def fake_post(url, data=None, **kwargs):
        sess.request_count += 1
        for pattern, resp in responses.items():
            if pattern in url:
                return resp
        return None

    sess.get = fake_get
    sess.post = fake_post
    return sess


def _make_resp(status=200, text="", headers=None, url=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    r.url = url or "http://localhost:5001/"
    r.raw = MagicMock()
    r.raw.headers.get_all = MagicMock(return_value=[])
    return r


class TestCsrfCheck(unittest.TestCase):
    def test_detects_form_without_csrf_token(self):
        form = FormInfo(
            action="http://localhost:5001/login",
            method="POST",
            inputs=[{"name": "username", "type": "text"},
                    {"name": "password", "type": "password"}],
            found_on="http://localhost:5001/login",
        )
        sitemap = _make_sitemap(forms=[form])
        session = _make_session({})
        check = CsrfCheck(session, sitemap)
        findings = check.run()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.MEDIUM)
        self.assertEqual(findings[0].cwe, "CWE-352")

    def test_ignores_form_with_csrf_token(self):
        form = FormInfo(
            action="http://localhost:5001/register",
            method="POST",
            inputs=[{"name": "csrf_token", "type": "hidden"},
                    {"name": "username", "type": "text"}],
            found_on="http://localhost:5001/register",
        )
        sitemap = _make_sitemap(forms=[form])
        session = _make_session({})
        check = CsrfCheck(session, sitemap)
        findings = check.run()
        self.assertEqual(len(findings), 0)

    def test_ignores_get_forms(self):
        form = FormInfo(
            action="http://localhost:5001/search",
            method="GET",
            inputs=[{"name": "q", "type": "text"}],
            found_on="http://localhost:5001/",
        )
        sitemap = _make_sitemap(forms=[form])
        session = _make_session({})
        check = CsrfCheck(session, sitemap)
        findings = check.run()
        self.assertEqual(len(findings), 0)


class TestHeadersCheck(unittest.TestCase):
    def test_detects_missing_security_headers(self):
        resp = _make_resp(headers={"Content-Type": "text/html"})
        session = _make_session({"localhost": resp})
        sitemap = _make_sitemap()
        check = HeadersCheck(session, sitemap)
        findings = check.run()
        titles = [f.title for f in findings]
        self.assertTrue(any("Content-Security-Policy" in t for t in titles))
        self.assertTrue(any("X-Frame-Options" in t for t in titles))
        self.assertTrue(any("Strict-Transport-Security" in t for t in titles))

    def test_no_findings_when_headers_present(self):
        resp = _make_resp(headers={
            "Content-Type": "text/html",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Strict-Transport-Security": "max-age=31536000",
            "Referrer-Policy": "strict-origin",
        })
        session = _make_session({"localhost": resp})
        sitemap = _make_sitemap()
        check = HeadersCheck(session, sitemap)
        findings = check.run()
        header_findings = [f for f in findings if "Header" in f.title]
        self.assertEqual(len(header_findings), 0)

    def test_detects_debug_mode_in_body(self):
        resp = _make_resp(
            headers={"Content-Type": "text/html"},
            text="500 Internal Error: Werkzeug Debugger — click to expand the local vars",
        )
        session = _make_session({"localhost": resp})
        sitemap = _make_sitemap()
        check = HeadersCheck(session, sitemap)
        findings = check.run()
        debug_findings = [f for f in findings if "debug" in f.title.lower()]
        self.assertEqual(len(debug_findings), 1)
        self.assertEqual(debug_findings[0].severity, Severity.CRITICAL)


class TestXssReflectedCheck(unittest.TestCase):
    def test_detects_reflected_xss(self):
        def fake_get(url, **kwargs):
            params = kwargs.get("params", {})
            payload = params.get("q", "")
            return _make_resp(text=f"<h2>Resultados: {payload}</h2>")

        session = MagicMock()
        session.get = fake_get
        session.post = MagicMock(return_value=None)
        sitemap = _make_sitemap(params={"http://localhost:5001/search": {"q"}})
        check = XssCheck(session, sitemap)
        findings = check.run()
        reflected = [f for f in findings if "reflejado" in f.title]
        self.assertEqual(len(reflected), 1)
        self.assertEqual(reflected[0].cwe, "CWE-79")

    def test_no_xss_when_escaped(self):
        def fake_get(url, **kwargs):
            params = kwargs.get("params", {})
            payload = params.get("q", "")
            escaped = payload.replace("<", "&lt;").replace(">", "&gt;")
            return _make_resp(text=f"<h2>Resultados: {escaped}</h2>")

        session = MagicMock()
        session.get = fake_get
        session.post = MagicMock(return_value=None)
        sitemap = _make_sitemap(params={"http://localhost:5001/search": {"q"}})
        check = XssCheck(session, sitemap)
        findings = check.run()
        reflected = [f for f in findings if "reflejado" in f.title]
        self.assertEqual(len(reflected), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)

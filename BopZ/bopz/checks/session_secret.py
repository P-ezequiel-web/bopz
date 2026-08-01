"""Secret key débil de Flask -> cookies de sesión forjables.

Esto es exactamente lo que un SAST NO puede ver desde el análisis
estático del código si la clave se carga en runtime, y lo que un DAST
"tonto" tampoco ve si solo mira status codes: hay que descifrar la firma
de la cookie para probar que la sesión es forjable.

Reutiliza las clases del propio Flask (`SecureCookieSessionInterface`)
en vez de reimplementar a mano el esquema de firma de itsdangerous, así
la lógica queda correcta sin importar la versión de Flask instalada.
"""
from __future__ import annotations

import os

from bopz.checks.base import Check, Severity

DEFAULT_WORDLIST_PATH = os.path.join(
    os.path.dirname(__file__), "..", "wordlists", "flask_secrets_common.txt"
)


def _load_wordlist(path: str) -> list[str]:
    try:
        with open(path, encoding="utf-8") as f:
            return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    except OSError:
        return []


def _looks_like_flask_session(value: str) -> bool:
    return value.count(".") in (1, 2) and len(value) > 20


class SessionSecretCheck(Check):
    id_prefix = "SECRET"
    name = "Flask secret_key débil / cookie de sesión forjable"

    def __init__(self, session, sitemap, wordlist_path: str | None = None):
        super().__init__(session, sitemap)
        self.wordlist_path = wordlist_path or DEFAULT_WORDLIST_PATH

    def run(self) -> list:
        candidates = {
            name: value for name, value in self.sitemap.cookies.items()
            if _looks_like_flask_session(value)
        }
        if not candidates:
            return self.findings

        try:
            from flask import Flask
            from flask.sessions import SecureCookieSessionInterface
        except ImportError:
            return self.findings

        wordlist = _load_wordlist(self.wordlist_path)
        if not wordlist:
            return self.findings

        for cookie_name, cookie_value in candidates.items():
            cracked_key, data = self._crack(
                cookie_value, wordlist, Flask, SecureCookieSessionInterface
            )
            if not cracked_key:
                continue

            self.add(
                title=f"Secret key débil — cookie '{cookie_name}' forjable",
                severity=Severity.CRITICAL,
                cwe="CWE-330",
                url=self.sitemap.base_url,
                param=cookie_name,
                evidence=(
                    f"La cookie '{cookie_name}' está firmada con una clave del "
                    f"wordlist ('{cracked_key}').\n"
                    f"Contenido de sesión decodificado: {dict(data) if hasattr(data, 'items') else data}"
                ),
                description=(
                    "Flask firma (no cifra) la cookie de sesión con `secret_key`. "
                    "Con una clave débil o reutilizada de un tutorial, cualquiera "
                    "puede firmar su propia cookie -por ejemplo "
                    "{'user': 'admin', 'is_admin': True}- sin pasar nunca por "
                    "/login ni conocer una contraseña."
                ),
                remediation=(
                    "Generar una secret_key aleatoria y única con "
                    "`secrets.token_hex(32)`, nunca versionarla en el "
                    "repositorio, y cargarla desde una variable de entorno."
                ),
            )
        return self.findings

    @staticmethod
    def _crack(cookie_value, wordlist, flask_cls, interface_cls):
        for candidate_key in wordlist:
            app = flask_cls("bopz-probe")
            app.secret_key = candidate_key
            serializer = interface_cls().get_signing_serializer(app)
            if serializer is None:
                continue
            try:
                data = serializer.loads(cookie_value)
                return candidate_key, data
            except Exception:
                continue
        return None, None

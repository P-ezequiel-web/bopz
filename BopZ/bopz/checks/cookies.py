"""Flags de seguridad en cookies: HttpOnly, Secure, SameSite.

requests expone las cookies parseadas pero no siempre sus flags via la
API de alto nivel, así que se lee el header crudo `Set-Cookie` de la
respuesta para inspeccionar los atributos tal como los manda el servidor.
"""
from __future__ import annotations

from bopz.checks.base import Check, Severity


class CookiesCheck(Check):
    id_prefix = "COOKIE"
    name = "Flags de seguridad en cookies"

    def run(self) -> list:
        resp = self.session.get(self.sitemap.base_url)
        if resp is None:
            return self.findings

        raw_cookies = resp.raw.headers.get_all("Set-Cookie") if resp.raw else None
        if not raw_cookies:
            sc = resp.headers.get("Set-Cookie")
            raw_cookies = [sc] if sc else []

        seen = set()
        for raw in raw_cookies:
            name = raw.split("=", 1)[0].strip()
            if name in seen:
                continue
            seen.add(name)
            low = raw.lower()
            missing = []
            if "httponly" not in low:
                missing.append("HttpOnly")
            if "secure" not in low:
                missing.append("Secure")
            if "samesite" not in low:
                missing.append("SameSite")

            if not missing:
                continue

            is_session_like = "session" in name.lower() or "auth" in name.lower() or "token" in name.lower()
            self.add(
                title=f"Cookie '{name}' sin flags de seguridad: {', '.join(missing)}",
                severity=Severity.HIGH if (is_session_like and "HttpOnly" in missing) else Severity.LOW,
                cwe="CWE-1004" if "HttpOnly" in missing else "CWE-1275",
                url=self.sitemap.base_url,
                param=name,
                evidence=f"Set-Cookie observado: {raw}",
                description=(
                    "Sin HttpOnly, JavaScript (incluyendo un XSS) puede leer la "
                    "cookie con document.cookie. Sin Secure, la cookie puede "
                    "viajar en texto plano por HTTP. Sin SameSite, la cookie se "
                    "envía en requests cross-site, facilitando CSRF."
                ),
                remediation=(
                    "En Flask: SESSION_COOKIE_HTTPONLY=True, "
                    "SESSION_COOKIE_SECURE=True (con HTTPS), "
                    "SESSION_COOKIE_SAMESITE='Lax' o 'Strict'."
                ),
            )
        return self.findings

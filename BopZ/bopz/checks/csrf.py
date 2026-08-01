"""CSRF — formularios que cambian estado (POST) sin token anti-falsificación.

No se envían requests cross-site reales (eso requeriría un navegador de
verdad); el check es estructural: si un formulario POST no trae ningún
campo cuyo nombre calce con los patrones habituales de token CSRF, se
reporta como ausencia de protección. Es el mismo criterio que revisaría
un pentester leyendo el HTML manualmente.
"""
from __future__ import annotations

from bopz.checks.base import Check, Severity

SENSITIVE_HINTS = ("login", "password", "admin", "delete", "remove",
                    "checkout", "pay", "transfer", "account", "cart")


class CsrfCheck(Check):
    id_prefix = "CSRF"
    name = "Cross-Site Request Forgery (tokens ausentes)"

    def run(self) -> list:
        seen_actions = set()
        for form in self.sitemap.forms:
            if form.method != "POST" or form.action in seen_actions:
                continue
            seen_actions.add(form.action)
            if form.has_csrf_token:
                continue

            is_sensitive = any(h in form.action.lower() for h in SENSITIVE_HINTS)
            self.add(
                title=f"Formulario POST sin token CSRF ({form.action})",
                severity=Severity.MEDIUM if is_sensitive else Severity.LOW,
                cwe="CWE-352",
                url=form.action,
                param=None,
                evidence=(
                    f"Campos del formulario: {[i.get('name') for i in form.inputs]}\n"
                    "Ninguno coincide con patrones típicos de token CSRF "
                    "(csrf_token, _token, authenticity_token, csrfmiddlewaretoken...)"
                ),
                description=(
                    "Un sitio malicioso podría auto-enviar este formulario desde "
                    "el navegador de una víctima autenticada (con un <form> oculto "
                    "que se auto-envía), ejecutando la acción en su nombre sin que "
                    "lo note."
                ),
                remediation=(
                    "Agregar un token CSRF único por sesión (Flask-WTF lo genera "
                    "automáticamente) y validarlo en el backend antes de procesar "
                    "el POST. Alternativa/complemento: SameSite=Strict en la "
                    "cookie de sesión."
                ),
            )
        return self.findings

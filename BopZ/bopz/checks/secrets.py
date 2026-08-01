"""Detección de secretos hardcodeados en el código fuente.

Usa expresiones regulares sobre cada archivo del repositorio para
detectar patrones de:
  - Claves de APIs conocidas (Stripe, AWS, SendGrid, GitHub, etc.)
  - Contraseñas literales en el código
  - Connection strings con credenciales
  - secret_key de Flask con valores débiles o hardcodeados
  - Archivos .env comiteados accidentalmente

No depende de librerías externas (es puro regex + stdlib) y funciona
sobre código fuente local o clonado desde GitHub, por eso complementa al
pipeline de Gitleaks: BopZ detecta la misma clase de problemas desde la
perspectiva del "revisor de código que tiene acceso al repositorio" y
puede mostrarlo junto al reporte DAST en un único HTML.

Cada regla tiene:
  - id único
  - descripción de qué detecta
  - severidad
  - CWE
  - si el match merece redactar el valor encontrado o solo indicar
    que "hay un secreto" (para no filtrar el valor real en el reporte).
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import List

from bopz.checks.base import Severity

# Máximo de bytes a leer por archivo (evita colgar en binarios enormes)
MAX_FILE_BYTES = 512_000


@dataclass
class SecretRule:
    rule_id: str
    name: str
    pattern: re.Pattern
    severity: Severity
    cwe: str
    description: str
    remediation: str
    show_value: bool = False   # si True, se muestra el valor en evidencia


RULES: list[SecretRule] = [
    SecretRule(
        rule_id="SEC-STRIPE",
        name="Stripe API Key hardcodeada",
        pattern=re.compile(r"sk_(?:live|test)_[0-9A-Za-z]{24,}"),
        severity=Severity.CRITICAL,
        cwe="CWE-798",
        description="Clave de Stripe en texto plano en el código. Permite realizar"
                    " cargos, reembolsos y acceder a datos de clientes.",
        remediation="Cargar desde variable de entorno (os.environ['STRIPE_API_KEY'])."
                    " Rotar la clave inmediatamente en el dashboard de Stripe.",
        show_value=False,
    ),
    SecretRule(
        rule_id="SEC-AWS-KEY",
        name="AWS Access Key ID hardcodeada",
        pattern=re.compile(r"AKIA[0-9A-Z]{16}"),
        severity=Severity.CRITICAL,
        cwe="CWE-798",
        description="Access Key ID de AWS en texto plano. Combinada con la Secret "
                    "Access Key, da acceso completo a los servicios AWS de la cuenta.",
        remediation="Usar IAM Roles o variables de entorno. Revocar la clave en la "
                    "consola de IAM inmediatamente.",
        show_value=True,  # el ID sin la Secret Key no es secreto por sí solo
    ),
    SecretRule(
        rule_id="SEC-AWS-SECRET",
        name="AWS Secret Access Key hardcodeada",
        pattern=re.compile(
            r"""(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key)\s*=\s*['"]([^'"]{20,})['"]"""
        ),
        severity=Severity.CRITICAL,
        cwe="CWE-798",
        description="Secret Access Key de AWS en texto plano. Junto al Access Key ID "
                    "permite acceso completo a AWS.",
        remediation="Rotar inmediatamente en IAM. Cargar desde variable de entorno o "
                    "AWS Secrets Manager.",
        show_value=False,
    ),
    SecretRule(
        rule_id="SEC-FLASK-KEY",
        name="Flask secret_key hardcodeada en código fuente",
        pattern=re.compile(
            r"""(?:secret_key|SECRET_KEY)\s*=\s*['"]([^'"]{4,})['"]""",
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
        cwe="CWE-798",
        description="La secret_key de Flask está versionada en el repositorio. "
                    "Cualquiera que lea el código puede forjar cookies de sesión "
                    "firmadas con esa clave sin conocer ninguna contraseña.",
        remediation="Generar con secrets.token_hex(32) y cargar desde variable de "
                    "entorno: app.secret_key = os.environ['SECRET_KEY']",
        show_value=False,
    ),
    SecretRule(
        rule_id="SEC-DB-CONN",
        name="Connection string con credenciales hardcodeadas",
        pattern=re.compile(
            r"""(?:postgresql|mysql|mongodb|mssql|oracle)://[^@\s'"]+:[^@\s'"]+@[^'"\s]+""",
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
        cwe="CWE-798",
        description="URL de base de datos con usuario y contraseña en texto plano. "
                    "Expone las credenciales de producción a cualquier lector del repo.",
        remediation="Usar variable de entorno DATABASE_URL o un gestor de secretos "
                    "(HashiCorp Vault, AWS Secrets Manager).",
        show_value=False,
    ),
    SecretRule(
        rule_id="SEC-GENERIC-PASSWORD",
        name="Contraseña literal en el código",
        pattern=re.compile(
            r"""(?:password|passwd|ADMIN_PASSWORD|DB_PASS)\s*=\s*['"]([^'"]{4,})['"]""",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        cwe="CWE-798",
        description="Variable con nombre relacionado a contraseña asignada con un "
                    "valor literal en el código fuente.",
        remediation="Cargar desde variable de entorno. Nunca almacenar contraseñas "
                    "en texto plano ni en el código ni en la base de datos "
                    "(usar bcrypt/argon2).",
        show_value=False,
    ),
    SecretRule(
        rule_id="SEC-GITHUB-TOKEN",
        name="GitHub Personal Access Token hardcodeado",
        pattern=re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}"),
        severity=Severity.CRITICAL,
        cwe="CWE-798",
        description="Token de GitHub personal en el código. Permite acceso a la "
                    "API de GitHub con los permisos del token.",
        remediation="Revocar el token en github.com/settings/tokens y usar GitHub "
                    "Actions secrets o variables de entorno.",
        show_value=False,
    ),
    SecretRule(
        rule_id="SEC-DOTENV-COMMITTED",
        name="Archivo .env comiteado al repositorio",
        pattern=re.compile(r"^\.env$"),
        severity=Severity.HIGH,
        cwe="CWE-312",
        description="El archivo .env suele contener claves API, contraseñas y "
                    "tokens. Al estar en el repositorio queda expuesto a cualquier "
                    "persona con acceso al mismo.",
        remediation="Agregar .env al .gitignore. Usar .env.example sin valores "
                    "reales como referencia para otros desarrolladores.",
        show_value=False,
    ),
]


@dataclass
class SecretFinding:
    rule_id: str
    name: str
    severity: Severity
    cwe: str
    file: str
    line: int
    snippet: str
    description: str
    remediation: str


def scan_files(source_files: list[str],
               repo_root: str | None = None) -> list[SecretFinding]:
    """Escanea una lista de archivos con todas las reglas y devuelve hallazgos."""
    findings = []
    for filepath in source_files:
        fname = os.path.basename(filepath)
        rel_path = os.path.relpath(filepath, repo_root) if repo_root else filepath

        # Regla especial: .env comiteado — la detectamos por nombre de archivo
        for rule in RULES:
            if rule.rule_id == "SEC-DOTENV-COMMITTED":
                if rule.pattern.match(fname):
                    findings.append(SecretFinding(
                        rule_id=rule.rule_id, name=rule.name,
                        severity=rule.severity, cwe=rule.cwe,
                        file=rel_path, line=0,
                        snippet=f"Archivo: {rel_path}",
                        description=rule.description, remediation=rule.remediation,
                    ))

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read(MAX_FILE_BYTES)
        except OSError:
            continue

        for lineno, line in enumerate(content.splitlines(), start=1):
            for rule in RULES:
                if rule.rule_id == "SEC-DOTENV-COMMITTED":
                    continue
                if rule.pattern.search(line):
                    # Redactar si show_value=False
                    if rule.show_value:
                        snippet = line.strip()[:120]
                    else:
                        snippet = _redact(line.strip()[:120])
                    findings.append(SecretFinding(
                        rule_id=rule.rule_id, name=rule.name,
                        severity=rule.severity, cwe=rule.cwe,
                        file=rel_path, line=lineno,
                        snippet=snippet,
                        description=rule.description, remediation=rule.remediation,
                    ))
    return findings


def _redact(text: str) -> str:
    """Reemplaza la parte del valor del secreto con asteriscos."""
    eq = text.find("=")
    if eq == -1:
        eq = text.find(":")
    if eq != -1 and eq < len(text) - 1:
        key_part = text[: eq + 1]
        return key_part + " ****REDACTED****"
    return "****REDACTED****"

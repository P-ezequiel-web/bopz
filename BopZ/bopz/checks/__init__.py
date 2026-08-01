from bopz.checks.base import Check, Finding, Severity
from bopz.checks.sqli import SqliCheck
from bopz.checks.xss import XssCheck
from bopz.checks.csrf import CsrfCheck
from bopz.checks.headers import HeadersCheck
from bopz.checks.cookies import CookiesCheck
from bopz.checks.session_secret import SessionSecretCheck

# Orden deliberado: primero lo que da contexto rápido (headers/cookies),
# luego las inyecciones, luego lo más costoso (fuerza bruta de session key).
ALL_CHECKS: list[type[Check]] = [
    HeadersCheck,
    CookiesCheck,
    CsrfCheck,
    SqliCheck,
    XssCheck,
    SessionSecretCheck,
]

__all__ = ["Check", "Finding", "Severity", "ALL_CHECKS"]

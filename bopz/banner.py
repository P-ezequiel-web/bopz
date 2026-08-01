"""Banner de arranque y puerta de autorización.

Todo escáner de seguridad serio (sqlmap, Nikto, ZAP, Nuclei...) dedica un
momento a recordar que la herramienta se usa solo con autorización. Aquí
además la puerta sirve para que el jurado vea que la herramienta se
diseñó con criterio ético, no solo con capacidad técnica.
"""
import sys

from bopz import __version__

BANNER = r"""
 ____              _____
|  _ \            |__  /
| |_) | ___  _ __    / /
|  _ < / _ \| '_ \  / /_
| |_) | (_) | |_) |/ /_ _
|____/ \___/| .__//_____|
            | |
            |_|   Bot of Pentesting by Zequi  ·  v{version}
"""

DISCLAIMER = """\
BopZ ejecuta payloads de SQL Injection, XSS, forjado de sesión y más
contra el objetivo indicado. Esto NO es una herramienta pasiva.

Úsala únicamente contra:
  - Aplicaciones de tu propiedad o de tu laboratorio personal
  - Entornos de staging/CI donde tengas autorización explícita
  - Engagements de pentesting formalmente autorizados por escrito

Escanear sistemas de terceros sin autorización puede ser un delito en
tu jurisdicción. El autor de BopZ no se hace responsable del uso indebido
de esta herramienta.
"""


def print_banner() -> None:
    print(BANNER.format(version=__version__))


def confirm_authorization(target: str, assume_yes: bool = False) -> bool:
    """Muestra el disclaimer y exige confirmación antes de lanzar el escaneo.

    Si `assume_yes` es True (flag --yes, uso en CI/Docker no interactivo)
    o si no hay una TTY disponible para preguntar, se omite el prompt pero
    se deja constancia clara en stdout de que el escaneo continúa igual.
    """
    print_banner()
    print(DISCLAIMER)
    print(f"Objetivo declarado: {target}\n")

    if assume_yes:
        print("[--yes] Autorización asumida por flag de línea de comandos.\n")
        return True

    if not sys.stdin.isatty():
        print("[!] Entrada no interactiva detectada (Docker/CI). "
              "Continuando bajo el supuesto de que --yes fue intencional.\n")
        return True

    try:
        resp = input("¿Confirmas que tienes autorización para evaluar "
                      "este objetivo? Escribe CONFIRMO para continuar: ")
    except (EOFError, KeyboardInterrupt):
        print("\nEscaneo cancelado.")
        return False

    if resp.strip().upper() != "CONFIRMO":
        print("Autorización no confirmada. Escaneo cancelado.")
        return False

    print()
    return True

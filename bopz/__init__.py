"""
BopZ — Bot of Pentesting by Zequi
==================================

Herramienta de pentesting web semi-automatizado que combina checks de
seguridad dinámicos (DAST casero) con un agente de IA (Claude) que razona
sobre los hallazgos, los prioriza y sugiere remediaciones.

Pensada para complementar —no reemplazar— un pipeline DevSecOps: detecta
específicamente lo que el SAST/SCA/gitleaks de la etapa de CI/CD no puede
ver porque requiere ejecutar la aplicación y observar su comportamiento
(session forgery, CSRF, XSS almacenado, lógica de negocio, etc.)

Uso responsable: solo contra objetivos sobre los que tengas autorización
explícita (tu propio laboratorio, un entorno de staging, o un engagement
de pentesting formalmente autorizado). Ver README.md.
"""

__version__ = "1.0.0"
__author__ = "Zequi"
__all__ = ["__version__"]

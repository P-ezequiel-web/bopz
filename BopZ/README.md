# BopZ 🔍
### Bot of Pentesting by Zequi

> Herramienta de pentesting web semi-automatizado que combina checks de seguridad dinámicos (DAST) con un agente de IA (Claude API) que razona sobre los hallazgos, los prioriza y genera reportes de consultoría.


## Instalación rápida

### Opción A — Python directo
```bash
git clone https://github.com/zequi/bopz.git
cd bopz
pip install -r requirements.txt
```

### Opción B — Docker (recomendado, zero configuración)
```bash
git clone https://github.com/zequi/bopz.git
cd bopz
docker build -t bopz .
```

---

## Uso

### CLI — escaneo básico
```bash
python main.py http://localhost:5001
```

### CLI — con análisis de IA y búsqueda web
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
python main.py http://localhost:5001 --ai --web-search
```

### CLI — con URL de GitHub
```bash
python main.py http://localhost:5001 \
  --repo https://github.com/tu-usuario/shopmart
```

### CLI — con path local (más rápido, sin clonar)
```bash
python main.py http://localhost:5001 \
  --repo /ruta/local/a/shopmart
```

### CLI — cruzando con reportes del pipeline de CI/CD
```bash
python main.py http://localhost:5001 \
  --semgrep  semgrep-report.json   \
  --trivy    trivy-report.json     \
  --gitleaks gitleaks-report.json  \
  --ai
```

### CLI — Todo junto — el combo completo
```bash
python main.py http://localhost:5001 \
  --repo https://github.com/tu-usuario/shopmart \
  --ai \
  --semgrep semgrep-report.json \
  --gitleaks gitleaks-report.json \
  --output-prefix reportes/bopz-final
```
BopZ lee los reportes de tu pipeline y genera automáticamente la tabla
**"¿el pipeline lo detectó?"** para cada hallazgo.

### Dashboard web (interfaz gráfica)
```bash
# Python directo
python web/app.py
# Abrir http://localhost:8090

# Docker
docker-compose --profile web up
# Abrir http://localhost:8090
```

### Docker CLI — escaneo con reportes persistidos
```bash
docker run --rm \
  -v $(pwd)/reports:/reports \
  -e ANTHROPIC_API_KEY="sk-ant-..." \
  bopz main.py http://host.docker.internal:5001 \
       --yes --ai \
       --output-prefix /reports/bopz-report
```

---

## Flags disponibles

```
Positional:
  target                URL base del objetivo (http://...)

Crawling:
  --depth INT           Profundidad máxima del crawler (default: 2)
  --max-pages INT       Máximo de páginas a visitar (default: 60)
  --delay FLOAT         Segundos entre requests (default: 0.2)
  --timeout FLOAT       Timeout por request (default: 8.0)
  --no-verify-tls       Desactivar verificación TLS

Checks:
  --wordlist PATH       Wordlist de secret_keys alternativa

IA:
  --ai                  Habilitar análisis con Claude API
  --web-search          Permitir búsqueda web al agente IA
  --api-key KEY         API key de Anthropic (alternativa a env var)

Cruce con pipeline:
  --semgrep  JSON       Reporte JSON de Semgrep
  --trivy    JSON       Reporte JSON de Trivy
  --gitleaks JSON       Reporte JSON de Gitleaks

Salida:
  --output-prefix STR   Prefijo de archivos de reporte (default: bopz-report)
  --formats html md json Formatos a generar (default: todos)
  -y / --yes            Omitir confirmación interactiva
```

---

## Arquitectura

```
BopZ/
├── main.py                    # Entrada CLI
├── bopz/
│   ├── scanner.py             # Orquestador central
│   ├── crawler.py             # Crawler same-origin (BFS)
│   ├── http_client.py         # Wrapper HTTP con rate limiting
│   ├── agent.py               # Integración Claude API
│   ├── report.py              # Generador HTML / Markdown / JSON
│   ├── banner.py              # Banner + puerta de autorización
│   ├── wordlists/
│   │   └── flask_secrets_common.txt
│   └── checks/
│       ├── base.py            # Clases abstractas Finding, Check
│       ├── sqli.py            # Boolean-based, error-based, UNION
│       ├── xss.py             # Reflejado (GET) y almacenado (POST)
│       ├── csrf.py            # Detección estructural de tokens faltantes
│       ├── headers.py         # Headers de seguridad + debug mode
│       ├── cookies.py         # HttpOnly / Secure / SameSite
│       └── session_secret.py  # Flask secret_key débil (wordlist attack)
├── web/
│   ├── app.py                 # Dashboard Flask con SSE
│   └── templates/
│       ├── index.html         # Formulario de inicio
│       └── progress.html      # Progreso en tiempo real
├── tests/
│   └── test_checks.py         # Tests unitarios (sin servidor real)
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## Ejecutar tests

```bash
python -m pytest tests/ -v
# o sin pytest:
python tests/test_checks.py
```

---

## Agregar un check nuevo

1. Crea `bopz/checks/mi_check.py` heredando de `Check`:
```python
from bopz.checks.base import Check, Severity

class MiCheck(Check):
    id_prefix = "MI"
    name = "Descripción de mi check"

    def run(self) -> list:
        # lógica...
        self.add(
            title="Hallazgo encontrado",
            severity=Severity.HIGH,
            cwe="CWE-XXX",
            url="http://...",
            evidence="...",
            description="...",
            remediation="...",
        )
        return self.findings
```

2. Regístralo en `bopz/checks/__init__.py`:
```python
from bopz.checks.mi_check import MiCheck
ALL_CHECKS = [..., MiCheck]
```

¡Y listo! El check aparece automáticamente en la CLI y el dashboard.

---

## ⚠️ Uso responsable

BopZ lanza payloads activos (SQLi, XSS, forjado de sesión) contra el objetivo.

**Úsalo únicamente contra:**
- Aplicaciones de tu propiedad o de tu laboratorio personal
- Entornos de staging/CI donde tengas autorización explícita
- Engagements de pentesting formalmente autorizados por escrito

Escanear sistemas de terceros sin autorización puede ser un delito en tu jurisdicción.

---

## Contribuciones

Pull requests bienvenidas. Para cambios grandes, abre un issue primero para discutir el alcance. Ver [CONTRIBUTING.md](CONTRIBUTING.md) (próximamente).

---

## Licencia

MIT — libre para usar, modificar y distribuir con atribución.

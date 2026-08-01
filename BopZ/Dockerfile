# ── Build stage ─────────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Runtime stage ────────────────────────────────────────────────────────────
FROM python:3.12-slim

LABEL maintainer="Zequi"
LABEL description="BopZ — Bot of Pentesting by Zequi"
LABEL version="1.0.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    BOPZ_MODEL=claude-sonnet-4-6

WORKDIR /bopz

# Copiar dependencias preinstaladas
COPY --from=builder /install /usr/local

# Copiar código fuente
COPY bopz/       ./bopz/
COPY web/        ./web/
COPY main.py     .

# Directorio de salida de reportes (se puede montar como volumen)
RUN mkdir -p /reports

# Puerto del dashboard web
EXPOSE 8090

# ── Modos de uso ─────────────────────────────────────────────────────────────
# CLI (default):
#   docker run --rm bopz http://host.docker.internal:5001 --yes
#
# Dashboard web:
#   docker run --rm -p 8090:8090 bopz web
#
# CLI con reportes persistidos:
#   docker run --rm -v $(pwd)/reports:/reports bopz \
#     http://host.docker.internal:5001 --yes \
#     --output-prefix /reports/bopz-report
# ─────────────────────────────────────────────────────────────────────────────
ENTRYPOINT ["python"]
CMD ["main.py", "--help"]

# Para modo web: override con "web/app.py"
# docker-compose lo hace automáticamente con el perfil "web"

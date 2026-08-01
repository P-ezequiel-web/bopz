#!/usr/bin/env python3
"""BopZ — CLI principal.

Ejemplos rápidos:
  python main.py http://localhost:5001

  python main.py http://localhost:5001 --ai

  python main.py http://localhost:5001 --ai --web-search \
      --semgrep semgrep-report.json --gitleaks gitleaks-report.json

  python main.py http://localhost:5001 --output-prefix informes/bopz \
      --formats html md --yes
"""
import argparse
import os
import sys

from bopz.banner import confirm_authorization
from bopz.report import save_reports
from bopz.scanner import ScanConfig, run_scan


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bopz",
        description="BopZ — Bot of Pentesting by Zequi",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("target", help="URL base del objetivo, p.ej. http://localhost:5001")

    # ── Opciones de crawling ───────────────────────────────────────────────
    crawl = p.add_argument_group("Opciones de crawling")
    crawl.add_argument("--depth", type=int, default=2,
                        help="Profundidad máxima del crawler (default: 2)")
    crawl.add_argument("--max-pages", type=int, default=60,
                        help="Máximo de páginas a visitar (default: 60)")
    crawl.add_argument("--delay", type=float, default=0.2,
                        help="Delay entre requests en segundos (default: 0.2)")
    crawl.add_argument("--timeout", type=float, default=8.0,
                        help="Timeout por request en segundos (default: 8.0)")
    crawl.add_argument("--no-verify-tls", action="store_true",
                        help="Deshabilitar verificación TLS (para labs con cert auto-firmado)")

    # ── Análisis estático ─────────────────────────────────────────────────
    static = p.add_argument_group("Análisis estático de código fuente (SAST/SCA)")
    static.add_argument(
        "--repo", metavar="URL_O_PATH",
        help="URL de GitHub (https://github.com/user/repo) o path local al "
             "código fuente. Activa detección de secretos hardcodeados y "
             "dependencias con CVE conocido.",
    )
    static.add_argument(
        "--branch", metavar="BRANCH", default=None,
        help="Rama a clonar si se pasa una URL de GitHub (default: rama por defecto del repo)",
    )

    # ── Checks ────────────────────────────────────────────────────────────
    checks = p.add_argument_group("Opciones de checks")
    checks.add_argument("--wordlist", metavar="PATH",
                         help="Wordlist de secret_keys a probar (default: integrada)")

    # ── IA ────────────────────────────────────────────────────────────────
    ai = p.add_argument_group("Integración con IA")
    ai.add_argument("--ai", action="store_true",
                     help="Habilitar análisis con Claude API (requiere ANTHROPIC_API_KEY)")
    ai.add_argument("--web-search", action="store_true",
                     help="Permitir que el agente busque en la web para enriquecer hallazgos")
    ai.add_argument("--api-key", metavar="KEY",
                     help="Anthropic API key (alternativa a la variable de entorno)")

    # ── Cruce con pipeline ────────────────────────────────────────────────
    pipeline = p.add_argument_group("Cruce con reportes del pipeline (Semana 2)")
    pipeline.add_argument("--semgrep", metavar="JSON",
                           help="Ruta al reporte JSON de Semgrep")
    pipeline.add_argument("--trivy", metavar="JSON",
                           help="Ruta al reporte JSON de Trivy")
    pipeline.add_argument("--gitleaks", metavar="JSON",
                           help="Ruta al reporte JSON de Gitleaks")

    # ── Salida ────────────────────────────────────────────────────────────
    out = p.add_argument_group("Opciones de salida")
    out.add_argument("--output-prefix", default="bopz-report",
                      help="Prefijo de los archivos de salida (default: bopz-report)")
    out.add_argument("--formats", nargs="+",
                      choices=["html", "md", "json"], default=["html", "md", "json"],
                      help="Formatos de reporte a generar (default: html md json)")

    # ── Miscelánea ────────────────────────────────────────────────────────
    p.add_argument("--yes", "-y", action="store_true",
                    help="Omitir confirmación interactiva de autorización")

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not confirm_authorization(args.target, assume_yes=args.yes):
        return 1

    config = ScanConfig(
        target=args.target,
        max_depth=args.depth,
        max_pages=args.max_pages,
        delay=args.delay,
        timeout=args.timeout,
        verify_tls=not args.no_verify_tls,
        wordlist_path=args.wordlist,
        repo=args.repo,
        repo_branch=args.branch,
        enable_ai=args.ai,
        enable_web_search=args.web_search,
        anthropic_api_key=args.api_key or os.environ.get("ANTHROPIC_API_KEY"),
        pipeline_semgrep=args.semgrep,
        pipeline_trivy=args.trivy,
        pipeline_gitleaks=args.gitleaks,
        output_formats=args.formats,
        output_prefix=args.output_prefix,
    )

    result = run_scan(config)

    saved = save_reports(
        findings=result.findings,
        meta=result.meta,
        output_prefix=config.output_prefix,
        formats=config.output_formats,
        executive_summary=result.executive_summary,
        coverage_rows=result.coverage_rows,
    )

    print("\n── Hallazgos ─────────────────────────────────────")
    if not result.findings:
        print("  No se encontraron hallazgos.")
    for f in sorted(result.findings, key=lambda x: -x.severity.value):
        print(f"  [{f.severity.name:8s}] {f.check_id} — {f.title}")

    print("\n── Reportes generados ─────────────────────────────")
    for path in saved:
        print(f"  {path}")

    print(f"\n── Total: {len(result.findings)} hallazgo(s) "
          f"en {result.duration} / {result.request_count} requests ──\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

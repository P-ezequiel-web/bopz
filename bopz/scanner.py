"""Orquestador central de BopZ.

Separa claramente tres fases:
  1. Reconocimiento (crawler)
  2. Checks paralelos por módulo (cada check es independiente)
  3. Enriquecimiento con IA (opcional, solo si hay API key)

Se puede importar como librería (web/app.py lo hace) o llamar directamente
desde la CLI (main.py).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

from bopz.agent import SecurityAgent
from bopz.checks import ALL_CHECKS, Finding
from bopz.checks.session_secret import SessionSecretCheck
from bopz.crawler import Crawler, SiteMap
from bopz.http_client import BopzSession
from bopz.report import now_iso


@dataclass
class ScanConfig:
    target: str
    max_depth: int = 2
    max_pages: int = 60
    delay: float = 0.2
    timeout: float = 8.0
    verify_tls: bool = True
    wordlist_path: str | None = None
    # ── Análisis estático (nuevo) ──────────────────────────────────────────
    repo: str | None = None          # URL de GitHub o path local al código fuente
    repo_branch: str | None = None   # rama a clonar (default: main/master)
    # ─────────────────────────────────────────────────────────────────────
    enable_ai: bool = False
    enable_web_search: bool = False
    anthropic_api_key: str | None = None
    pipeline_semgrep: str | None = None
    pipeline_trivy: str | None = None
    pipeline_gitleaks: str | None = None
    output_formats: list = field(default_factory=lambda: ["html", "md", "json"])
    output_prefix: str = "bopz-report"


@dataclass
class ScanResult:
    target: str
    start_time: str
    duration: str
    findings: list[Finding]
    sitemap: SiteMap
    executive_summary: str | None
    coverage_rows: list[dict]
    request_count: int
    meta: dict


def run_scan(config: ScanConfig,
             progress_cb: Callable[[str], None] | None = None) -> ScanResult:
    """Función de punto de entrada única para un escaneo completo.

    `progress_cb` permite que la web UI reciba actualizaciones sin polling.
    """
    def log(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)
        else:
            print(msg)

    t0 = time.time()
    start_time = now_iso()

    # ── 0. Análisis estático (opcional, si se pasa --repo) ─────────────────
    static_findings: list = []
    if config.repo:
        log(f"[BopZ] Iniciando análisis estático sobre: {config.repo}")
        try:
            from bopz.source_scanner import run_static_analysis
            static_findings = run_static_analysis(
                config.repo, branch=config.repo_branch, log=log
            )
            log(f"[BopZ] Análisis estático completo — "
                f"{len(static_findings)} hallazgo(s) estáticos.")
        except Exception as exc:
            log(f"[BopZ] [SAST/SCA] Error durante análisis estático: {exc}")


    # ── 1. Reconocimiento ──────────────────────────────────────────────────
    log("[BopZ] Iniciando crawler...")
    session = BopzSession(
        delay=config.delay, timeout=config.timeout, verify_tls=config.verify_tls
    )
    crawler = Crawler(session, max_depth=config.max_depth, max_pages=config.max_pages)
    sitemap = crawler.crawl(config.target)
    log(
        f"[BopZ] Crawl completo — {len(sitemap.pages)} páginas, "
        f"{len(sitemap.forms)} formularios, "
        f"{sum(len(v) for v in sitemap.query_params.values())} parámetros GET."
    )

    # ── 2. Checks ─────────────────────────────────────────────────────────
    all_findings: list[Finding] = []
    for check_cls in ALL_CHECKS:
        if check_cls is SessionSecretCheck and config.wordlist_path:
            check = check_cls(session, sitemap, wordlist_path=config.wordlist_path)
        else:
            check = check_cls(session, sitemap)
        log(f"[BopZ] Ejecutando: {check.name}...")
        try:
            found = check.run()
            all_findings.extend(found)
            if found:
                log(f"         ↳ {len(found)} hallazgo(s) encontrado(s)")
        except Exception as exc:
            log(f"         ↳ Error en {check.name}: {exc}")

    # ── 3. Cruce con pipeline de Semana 2 ─────────────────────────────────
    from bopz.report import merge_pipeline_reports
    coverage_rows = merge_pipeline_reports(
        all_findings,
        semgrep_path=config.pipeline_semgrep,
        trivy_path=config.pipeline_trivy,
        gitleaks_path=config.pipeline_gitleaks,
    )

    # ── 4. Análisis con IA ────────────────────────────────────────────────
    executive_summary = None
    if config.enable_ai:
        log("[BopZ] Consultando agente IA (Claude API)...")
        agent = SecurityAgent(
            api_key=config.anthropic_api_key,
            enable_web_search=config.enable_web_search,
        )
        if agent.available:
            analysis = agent.analyze_findings(
                all_findings,
                app_context=f"Aplicación web en {config.target}",
            )
            if analysis:
                agent.apply_analysis(all_findings, analysis)
                executive_summary = analysis.get("executive_summary")
                if config.enable_web_search:
                    for f in all_findings:
                        if f.severity.value >= 3 and not f.ai_notes:
                            notes = agent.research_finding(f)
                            if notes:
                                f.ai_notes = notes
            log("[BopZ] Análisis IA completado.")
        else:
            log("[BopZ] Agente IA no disponible (verifica ANTHROPIC_API_KEY).")

    # ── 5. Meta para el reporte ────────────────────────────────────────────
    duration_s = time.time() - t0
    duration = f"{duration_s:.1f}s" if duration_s < 120 else f"{duration_s / 60:.1f}min"
    meta = {
        "target": config.target,
        "date": start_time,
        "duration": duration,
        "request_count": session.request_count,
    }

    log(
        f"[BopZ] Escaneo finalizado — {len(all_findings)} hallazgo(s) en {duration}."
    )

    # Combinar hallazgos estáticos + dinámicos
    all_findings = static_findings + all_findings

    return ScanResult(
        target=config.target,
        start_time=start_time,
        duration=duration,
        findings=all_findings,
        sitemap=sitemap,
        executive_summary=executive_summary,
        coverage_rows=coverage_rows,
        request_count=session.request_count,
        meta=meta,
    )

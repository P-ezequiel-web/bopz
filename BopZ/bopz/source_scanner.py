"""Orquestador de análisis estático sobre el código fuente del repositorio.

Se llama antes de los checks DAST si el usuario pasa --repo. Devuelve
los hallazgos en el mismo formato Finding para que el report.py los
incluya en el mismo reporte HTML junto a los hallazgos dinámicos.
"""
from __future__ import annotations

from typing import Callable

from bopz.checks.base import Finding, Severity
from bopz.checks.dependencies import scan_dependencies
from bopz.checks.secrets import scan_files
from bopz.repo_reader import collect_source_files, open_repo


def run_static_analysis(repo: str, branch: str | None = None,
                         log: Callable[[str], None] | None = None
                         ) -> list[Finding]:
    """Clona (si es URL) o lee el repo y ejecuta secrets + dep checks.

    Devuelve lista de Finding unificada, igual a la del DAST, para que
    report.py los trate de forma homogénea.
    """
    if log is None:
        log = print

    all_findings: list[Finding] = []

    with open_repo(repo, branch=branch) as repo_path:

        # ── 1. Secretos hardcodeados ──────────────────────────────────────
        log("[BopZ] [SAST] Buscando secretos hardcodeados en el código fuente...")
        source_files = collect_source_files(repo_path)
        log(f"[BopZ] [SAST]   {len(source_files)} archivos de código encontrados.")
        secret_hits = scan_files(source_files, repo_root=repo_path)

        for i, hit in enumerate(secret_hits, start=1):
            all_findings.append(Finding(
                check_id=f"STATIC-SEC-{i:03d}",
                title=hit.name,
                severity=hit.severity,
                cwe=hit.cwe,
                url=f"repo:{hit.file}:{hit.line}",
                evidence=f"Archivo: {hit.file}  línea: {hit.line}\n{hit.snippet}",
                description=hit.description,
                remediation=hit.remediation,
                param=None,
                detected_by_pipeline=None,
            ))

        if secret_hits:
            log(f"[BopZ] [SAST]   ↳ {len(secret_hits)} secreto(s) encontrado(s).")
        else:
            log("[BopZ] [SAST]   ↳ No se encontraron secretos hardcodeados.")

        # ── 2. Dependencias con CVE ───────────────────────────────────────
        log("[BopZ] [SCA]  Analizando dependencias contra OSV.dev...")
        dep_findings = scan_dependencies(repo_path, log=log)

        sev_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH":     Severity.HIGH,
            "MEDIUM":   Severity.MEDIUM,
            "LOW":      Severity.LOW,
        }
        for i, df in enumerate(dep_findings, start=1):
            sev = sev_map.get(df.worst_severity, Severity.MEDIUM)
            vuln_lines = []
            for v in df.vulnerabilities:
                cves = ", ".join(v.aliases) if v.aliases else v.vuln_id
                vuln_lines.append(f"  [{v.severity}] {v.vuln_id} — {v.summary} ({cves})")

            all_findings.append(Finding(
                check_id=f"STATIC-DEP-{i:03d}",
                title=f"Dependencia vulnerable: {df.package}=={df.version}",
                severity=sev,
                cwe="CWE-1395",
                url=f"repo:{df.dep_file}",
                evidence=(
                    f"Paquete: {df.package}=={df.version}  "
                    f"(declarado en {df.dep_file})\n"
                    + "\n".join(vuln_lines)
                ),
                description=(
                    f"La versión {df.version} de {df.package} tiene "
                    f"{len(df.vulnerabilities)} vulnerabilidad(es) conocida(s) "
                    f"registrada(s) en OSV.dev / National Vulnerability Database."
                    + (f"\nCVEs: {', '.join(df.cve_ids)}" if df.cve_ids else "")
                ),
                remediation=(
                    f"Actualizar {df.package} a la versión más reciente estable "
                    f"(`pip install --upgrade {df.package}`) y anclar la versión "
                    f"en requirements.txt."
                ),
                param=None,
                detected_by_pipeline=None,
            ))

        if dep_findings:
            log(f"[BopZ] [SCA]   ↳ {len(dep_findings)} dependencia(s) con CVE(s).")
        else:
            log("[BopZ] [SCA]   ↳ Todas las dependencias están OK según OSV.dev.")

    return all_findings

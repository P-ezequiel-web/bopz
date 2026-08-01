"""Detección de dependencias con CVEs conocidos vía OSV.dev.

OSV (Open Source Vulnerabilities) es la base de datos que usa:
  - pip audit
  - GitHub Dependabot
  - Google OSS-Fuzz

Su API es completamente gratuita, no requiere autenticación y cubre
el ecosistema PyPI (además de npm, Go, Maven, etc.).

Endpoint:  POST https://api.osv.dev/v1/query
Payload:   {"package": {"name": "pyyaml", "ecosystem": "PyPI"}, "version": "5.3.1"}
Respuesta: lista de vulnerabilidades si las hay, array vacío si está OK.

Se parsea el requirements.txt del repo para extraer paquete + versión y
se hace una request por dependencia. Para no saturar la API, se hace
un pequeño delay entre requests (respetando el mismo principio de
throttling que el crawler DAST).
"""
from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field

import requests

OSV_API = "https://api.osv.dev/v1/query"
REQUEST_DELAY = 0.3   # segundos entre requests a OSV
REQUEST_TIMEOUT = 8.0

# Archivos de dependencias que BopZ sabe leer
DEP_FILES = ("requirements.txt", "requirements-dev.txt", "requirements_dev.txt",
              "requirements_test.txt", "Pipfile")


@dataclass
class VulnInfo:
    vuln_id: str       # ej. "GHSA-8q59-q68h-6hv4"
    summary: str
    severity: str      # CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN
    aliases: list[str] = field(default_factory=list)   # CVE-XXXX-YYYY


@dataclass
class DepFinding:
    package: str
    version: str
    dep_file: str
    vulnerabilities: list[VulnInfo]

    @property
    def worst_severity(self) -> str:
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
        for sev in order:
            if any(v.severity == sev for v in self.vulnerabilities):
                return sev
        return "UNKNOWN"

    @property
    def cve_ids(self) -> list[str]:
        cves = []
        for v in self.vulnerabilities:
            cves.extend(a for a in v.aliases if a.startswith("CVE-"))
        return list(dict.fromkeys(cves))   # deduplicar preservando orden


def _parse_requirements(content: str) -> list[tuple[str, str]]:
    """Extrae (nombre, versión) de un requirements.txt.

    Soporta:
        pyyaml==5.3.1       -> ("pyyaml", "5.3.1")
        requests>=2.31.0    -> ("requests", "2.31.0")  # versión mínima declarada
        flask~=3.0.0        -> ("flask", "3.0.0")
        boto3               -> ("boto3", "")            # sin versión, no consultamos
    """
    pairs = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-", "http", "git+")):
            continue
        m = re.match(
            r"^([A-Za-z0-9_.\-]+)\s*(?:==|>=|~=|<=|!=|>|<)\s*([0-9][^\s;#]*)",
            line,
        )
        if m:
            name, ver = m.group(1).strip(), m.group(2).strip()
            pairs.append((name, ver))
    return pairs


def _query_osv(package: str, version: str, ecosystem: str = "PyPI") -> list[VulnInfo]:
    """Consulta OSV.dev para un paquete/versión y devuelve vulnerabilidades."""
    payload = {
        "version": version,
        "package": {"name": package, "ecosystem": ecosystem},
    }
    try:
        resp = requests.post(OSV_API, json=payload, timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            return []
        data = resp.json()
    except (requests.RequestException, ValueError):
        return []

    vulns = []
    for v in data.get("vulns", []):
        # Extraer severidad del campo database_specific o severity
        severity = "UNKNOWN"
        db_sev = (v.get("database_specific") or {}).get("severity", "")
        if db_sev:
            severity = db_sev.upper()
        else:
            for sev_entry in v.get("severity", []):
                score = sev_entry.get("score", "")
                if "CRITICAL" in score:
                    severity = "CRITICAL"; break
                elif "HIGH" in score:
                    severity = "HIGH"; break
                elif "MEDIUM" in score:
                    severity = "MEDIUM"; break
                elif "LOW" in score:
                    severity = "LOW"; break

        aliases = v.get("aliases", [])
        summary = v.get("summary", v.get("id", "Sin descripción"))[:200]
        vulns.append(VulnInfo(
            vuln_id=v.get("id", ""),
            summary=summary,
            severity=severity,
            aliases=aliases,
        ))
    return vulns


def scan_dependencies(repo_path: str, log=None) -> list[DepFinding]:
    """Lee los archivos de dependencias del repo y consulta OSV por cada una."""
    if log is None:
        log = print

    findings = []
    for dep_file in DEP_FILES:
        full_path = os.path.join(repo_path, dep_file)
        if not os.path.isfile(full_path):
            continue

        log(f"[BopZ] Leyendo dependencias de {dep_file}...")
        with open(full_path, encoding="utf-8", errors="ignore") as fh:
            content = fh.read()

        pairs = _parse_requirements(content)
        log(f"[BopZ]   {len(pairs)} dependencias con versión declarada. Consultando OSV.dev...")

        for package, version in pairs:
            time.sleep(REQUEST_DELAY)
            vulns = _query_osv(package, version)
            if vulns:
                findings.append(DepFinding(
                    package=package, version=version,
                    dep_file=dep_file, vulnerabilities=vulns,
                ))
                cves = ", ".join(v.aliases[0] if v.aliases else v.vuln_id for v in vulns)
                log(f"[BopZ]   ⚠ {package}=={version} → {len(vulns)} CVE(s): {cves}")

    return findings

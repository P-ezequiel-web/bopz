"""Contrato común de todos los checks: qué es un hallazgo y cómo se reporta."""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """IntEnum para poder ordenar hallazgos por severidad directamente."""
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name


@dataclass
class Finding:
    check_id: str            # p.ej. "SQLI-001"
    title: str
    severity: Severity
    cwe: str | None
    url: str
    evidence: str
    description: str
    remediation: str = ""
    param: str | None = None
    # Se completa después, si el usuario pasa reportes del pipeline (Semana 2)
    detected_by_pipeline: bool | None = None
    # Se completa por el agente de IA, si está habilitado
    ai_notes: str = ""

    def to_dict(self) -> dict:
        d = dict(
            check_id=self.check_id, title=self.title, severity=str(self.severity),
            severity_rank=int(self.severity), cwe=self.cwe, url=self.url,
            evidence=self.evidence, description=self.description,
            remediation=self.remediation, param=self.param,
            detected_by_pipeline=self.detected_by_pipeline, ai_notes=self.ai_notes,
        )
        return d


class Check(abc.ABC):
    id_prefix: str = "GEN"
    name: str = "Check genérico"

    def __init__(self, session, sitemap):
        self.session = session
        self.sitemap = sitemap
        self.findings: list[Finding] = []

    def add(self, **kwargs) -> None:
        n = len(self.findings) + 1
        kwargs.setdefault("check_id", f"{self.id_prefix}-{n:03d}")
        self.findings.append(Finding(**kwargs))

    @abc.abstractmethod
    def run(self) -> list[Finding]:
        """Ejecuta el check y devuelve la lista de Finding encontrados."""
        raise NotImplementedError

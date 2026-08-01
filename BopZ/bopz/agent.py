"""Capa de razonamiento con IA sobre los hallazgos crudos.

Se separan dos llamadas a propósito:

1. `analyze_findings` — sin herramientas, se le exige JSON estricto. Da
   prioridad real (no solo la severidad cruda), impacto de negocio y un
   resumen ejecutivo. Al no mezclar herramientas con la exigencia de JSON
   puro, el parseo es confiable.

2. `research_finding` — SÍ usa la tool de búsqueda web de la API
   (server-side, una sola llamada) para enriquecer un hallazgo puntual
   con info vigente (CVEs de una dependencia, guía OWASP actual, etc.)
   devuelve texto libre, no JSON. Se llama solo para hallazgos
   CRITICAL/HIGH para no gastar cuota de más.

Si no hay ANTHROPIC_API_KEY configurada, el agente queda "no disponible"
y el resto del pipeline sigue funcionando con el reporte crudo (BopZ
nunca debe fallar solo porque falte la IA).
"""
from __future__ import annotations

import json
import os

SYSTEM_PROMPT_ANALYSIS = """Eres un pentester senior revisando hallazgos crudos generados por un \
scanner automatizado (BopZ) contra una aplicación de laboratorio. Para cada \
hallazgo, evalúa severidad real, impacto de negocio en 1-2 frases, y una \
recomendación de remediación priorizada. Responde EXCLUSIVAMENTE con JSON \
válido, sin texto antes ni después, sin backticks de markdown.

Formato exacto esperado:
{
  "executive_summary": "resumen ejecutivo de 3-5 frases sobre el estado de seguridad general",
  "findings": [
    {"check_id": "...", "priority": 1, "business_impact": "...", "ai_remediation_notes": "..."}
  ]
}

"priority" es un entero de 1 (arreglar primero) a N (arreglar al final), \
ordenando TODOS los hallazgos recibidos por urgencia real de explotación \
e impacto combinado, no solo por la severidad que ya traen."""

SYSTEM_PROMPT_RESEARCH = """Eres un analista de amenazas. Se te da un hallazgo de seguridad \
puntual. Usa la herramienta de búsqueda web si ayuda a enriquecer la \
respuesta (por ejemplo, CVEs conocidos de una librería o guía OWASP \
vigente) y responde en 3-6 frases, en español, con contexto actualizado \
y accionable para remediarlo. No repitas la descripción del hallazgo, \
agrega valor nuevo."""


class SecurityAgent:
    def __init__(self, api_key: str | None = None, model: str | None = None,
                 enable_web_search: bool = False):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.model = model or os.environ.get("BOPZ_MODEL", "claude-sonnet-5")
        self.enable_web_search = enable_web_search
        self._client = None

        if self.api_key:
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=self.api_key)
            except ImportError:
                print("[agent] Paquete 'anthropic' no instalado; IA deshabilitada.")

    @property
    def available(self) -> bool:
        return self._client is not None

    def analyze_findings(self, findings: list, app_context: str = "") -> dict | None:
        if not self.available or not findings:
            return None

        payload = [f.to_dict() for f in findings]
        user_content = (
            f"Contexto de la aplicación: {app_context or 'no especificado'}\n\n"
            f"Hallazgos crudos (JSON):\n{json.dumps(payload, ensure_ascii=False, indent=2)}"
        )
        try:
            resp = self._client.messages.create(
                model=self.model,
                max_tokens=4000,
                system=SYSTEM_PROMPT_ANALYSIS,
                messages=[{"role": "user", "content": user_content}],
            )
        except Exception as e:
            print(f"[agent] No se pudo contactar a Claude API: {e}")
            return None

        text = "".join(
            block.text for block in resp.content if getattr(block, "type", "") == "text"
        ).strip()
        if text.startswith("```"):
            text = text.strip("`")
            if text.lower().startswith("json"):
                text = text[4:]
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            print("[agent] La respuesta del modelo no fue JSON válido; se omite el análisis IA.")
            return None

    def research_finding(self, finding) -> str | None:
        if not self.available or not self.enable_web_search:
            return None

        user_content = (
            f"Hallazgo: {finding.title}\n"
            f"CWE: {finding.cwe}\nSeveridad: {finding.severity}\n"
            f"Descripción: {finding.description}\n"
            f"Evidencia: {finding.evidence}"
        )
        try:
            resp = self._client.messages.create(
                model=self.model,
                max_tokens=1000,
                system=SYSTEM_PROMPT_RESEARCH,
                tools=[{"type": "web_search_20250305", "name": "web_search"}],
                messages=[{"role": "user", "content": user_content}],
            )
        except Exception as e:
            print(f"[agent] Investigación web omitida ({finding.check_id}): {e}")
            return None

        return "".join(
            block.text for block in resp.content if getattr(block, "type", "") == "text"
        ).strip()

    def apply_analysis(self, findings: list, analysis: dict) -> None:
        """Aplica priority/business_impact/ai_remediation_notes de vuelta a los Finding."""
        if not analysis:
            return
        by_id = {f.check_id: f for f in findings}
        for item in analysis.get("findings", []):
            f = by_id.get(item.get("check_id"))
            if not f:
                continue
            notes = item.get("business_impact", "")
            remediation_notes = item.get("ai_remediation_notes", "")
            f.ai_notes = " ".join(x for x in (notes, remediation_notes) if x)

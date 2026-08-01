"""Generación de reportes: HTML autocontenido, Markdown y JSON crudo.

"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from jinja2 import Template

COLORS = {
    "CRITICAL": ("#4A1B0C", "#F0997B"),
    "HIGH":     ("#412402", "#EF9F27"),
    "MEDIUM":   ("#3A3410", "#E8D24D"),
    "LOW":      ("#042C53", "#85B7EB"),
    "INFO":     ("#2C2C2A", "#B4B2A9"),
}

CWE_KEYWORDS = {
    "CWE-89": ["sql injection", "cwe-89", "sqli"],
    "CWE-79": ["xss", "cross-site scripting", "cwe-79"],
    "CWE-798": ["hardcoded", "secret", "cwe-798", "credential"],
    "CWE-352": ["csrf", "cwe-352"],
    "CWE-330": ["weak", "predictable", "cwe-330", "secret_key", "secret key"],
    "CWE-489": ["debug", "cwe-489"],
}

HTML_TEMPLATE = Template(r"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>BopZ — Reporte de Pentesting — {{ meta.target }}</title>
<style>
  :root { --bg:#0B1220; --card:#141B2C; --border:#232C42; --text:#E7EAF0; --muted:#8A93A6; --accent:#EF9F27; }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--text); font-family:'Space Mono','Courier New',monospace; line-height:1.55; }
  .wrap { max-width:920px; margin:0 auto; padding:32px 24px 80px; }
  header { border-bottom:1px solid var(--border); padding-bottom:20px; margin-bottom:28px; }
  header h1 { font-size:26px; margin:0 0 4px; color:var(--accent); letter-spacing:1px; }
  header .meta { color:var(--muted); font-size:13px; }
  .stats { display:flex; gap:12px; margin:24px 0 32px; flex-wrap:wrap; }
  .stat { background:var(--card); border:1px solid var(--border); border-radius:6px; padding:10px 16px; min-width:92px; }
  .stat .n { font-size:22px; font-weight:bold; }
  .stat .l { font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.05em; }
  .summary { background:var(--card); border:1px solid var(--border); border-left:3px solid var(--accent); border-radius:6px; padding:18px 20px; margin-bottom:32px; font-size:14px; }
  .summary h2 { margin:0 0 8px; font-size:14px; color:var(--accent); text-transform:uppercase; letter-spacing:.05em; }
  .finding { background:var(--card); border:1px solid var(--border); border-radius:8px; padding:20px 22px; margin-bottom:16px; }
  .finding-head { display:flex; align-items:center; gap:10px; flex-wrap:wrap; margin-bottom:10px; }
  .badge { font-size:11px; font-weight:bold; padding:3px 9px; border-radius:999px; text-transform:uppercase; letter-spacing:.04em; }
  .finding h3 { margin:0; font-size:16px; flex:1; min-width:200px; }
  .cwe { font-size:12px; color:var(--muted); }
  .finding .url { font-size:12px; color:var(--muted); margin-bottom:12px; word-break:break-all; }
  .finding pre { background:#0B1220; border:1px solid var(--border); border-radius:6px; padding:12px 14px; font-size:12.5px; overflow-x:auto; white-space:pre-wrap; word-break:break-word; }
  .finding .desc,.finding .rem,.finding .ai { font-size:13.5px; margin-top:10px; }
  .finding .rem strong,.finding .ai strong { color:var(--accent); }
  .pipeline-tag { font-size:11px; padding:2px 8px; border-radius:4px; }
  .pipeline-yes { background:#173404; color:#97C459; }
  .pipeline-no { background:#4A1B0C; color:#F0997B; }
  .coverage-table { width:100%; border-collapse:collapse; font-size:13px; margin-top:10px; }
  .coverage-table th,.coverage-table td { border:1px solid var(--border); padding:8px 10px; text-align:left; }
  .coverage-table th { color:var(--muted); font-weight:normal; text-transform:uppercase; font-size:11px; }
  h2.section { color:var(--accent); font-size:15px; text-transform:uppercase; letter-spacing:.05em; margin-top:40px; }
  footer { color:var(--muted); font-size:12px; margin-top:40px; border-top:1px solid var(--border); padding-top:16px; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>&gt; BopZ_ Reporte de Pentesting</h1>
    <div class="meta">
      Objetivo: {{ meta.target }} &middot; Fecha: {{ meta.date }} &middot;
      Duración: {{ meta.duration }} &middot; Requests enviados: {{ meta.request_count }}
    </div>
  </header>

  <div class="stats">
    {% for name, count in stats %}
    <div class="stat" style="border-left:3px solid {{ colors[name][1] }};">
      <div class="n">{{ count }}</div><div class="l">{{ name }}</div>
    </div>
    {% endfor %}
  </div>

  {% if executive_summary %}
  <div class="summary">
    <h2>Resumen ejecutivo (IA)</h2>
    <div>{{ executive_summary }}</div>
  </div>
  {% endif %}

  {% for f in findings %}
  <div class="finding">
    <div class="finding-head">
      <span class="badge" style="background:{{ colors[f.severity.name][0] }};color:{{ colors[f.severity.name][1] }};">{{ f.severity.name }}</span>
      <h3>{{ f.title }}</h3>
      {% if f.cwe %}<span class="cwe">{{ f.cwe }}</span>{% endif %}
      {% if f.detected_by_pipeline is not none %}
        {% if f.detected_by_pipeline %}<span class="pipeline-tag pipeline-yes">detectado por pipeline</span>
        {% else %}<span class="pipeline-tag pipeline-no">NO detectado por pipeline</span>{% endif %}
      {% endif %}
    </div>
    <div class="url">{{ f.check_id }} &middot; {{ f.url }}</div>
    <pre>{{ f.evidence }}</pre>
    <div class="desc">{{ f.description }}</div>
    <div class="rem"><strong>Remediación:</strong> {{ f.remediation }}</div>
    {% if f.ai_notes %}<div class="ai"><strong>Análisis IA:</strong> {{ f.ai_notes }}</div>{% endif %}
  </div>
  {% endfor %}

  {% if coverage_rows %}
  <h2 class="section">Cobertura del pipeline vs BopZ</h2>
  <table class="coverage-table">
    <tr><th>Hallazgo</th><th>CWE</th><th>Pipeline (Semana 2)</th><th>BopZ (Semana 3)</th></tr>
    {% for row in coverage_rows %}
    <tr><td>{{ row.title }}</td><td>{{ row.cwe }}</td>
        <td>{{ '✅' if row.pipeline else '❌' }}</td><td>✅</td></tr>
    {% endfor %}
  </table>
  {% endif %}

  <footer>Generado por BopZ v{{ version }} · Solo para uso en objetivos autorizados.</footer>
</div>
</body>
</html>
""")


def _counts_by_severity(findings) -> list[tuple[str, int]]:
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    counts = {name: 0 for name in order}
    for f in findings:
        counts[f.severity.name] += 1
    return [(name, counts[name]) for name in order if counts[name] > 0]


def merge_pipeline_reports(findings, semgrep_path=None, trivy_path=None,
                            gitleaks_path=None) -> list[dict]:
    """Cruce best-effort (por palabra clave) contra los reportes JSON del pipeline."""
    blob = ""
    for path in (semgrep_path, trivy_path, gitleaks_path):
        if not path:
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                blob += fh.read().lower()
        except OSError:
            print(f"[report] No se pudo leer {path}, se ignora en el cruce de cobertura.")

    if not blob:
        return []

    coverage_rows = []
    for f in findings:
        keywords = CWE_KEYWORDS.get(f.cwe or "", [])
        hit = any(kw in blob for kw in keywords) if keywords else False
        f.detected_by_pipeline = hit
        coverage_rows.append({"title": f.title, "cwe": f.cwe, "pipeline": hit})
    return coverage_rows


def generate_html(findings, meta, executive_summary=None, coverage_rows=None, version="1.0.0") -> str:
    return HTML_TEMPLATE.render(
        meta=meta, findings=sorted(findings, key=lambda x: -x.severity.value),
        stats=_counts_by_severity(findings), colors=COLORS,
        executive_summary=executive_summary, coverage_rows=coverage_rows, version=version,
    )


def generate_markdown(findings, meta, executive_summary=None, coverage_rows=None) -> str:
    lines = ["# BopZ — Reporte de Pentesting\n"]
    lines.append(f"**Objetivo:** {meta['target']}  ")
    lines.append(f"**Fecha:** {meta['date']}  ")
    lines.append(f"**Duración:** {meta['duration']}  ")
    lines.append(f"**Requests enviados:** {meta['request_count']}\n")

    if executive_summary:
        lines.append("## Resumen ejecutivo (IA)\n")
        lines.append(executive_summary + "\n")

    lines.append("## Resumen de hallazgos\n")
    lines.append("| Severidad | Cantidad |")
    lines.append("|---|---|")
    for name, count in _counts_by_severity(findings):
        lines.append(f"| {name} | {count} |")
    lines.append("")

    lines.append("## Detalle de hallazgos\n")
    for f in sorted(findings, key=lambda x: -x.severity.value):
        lines.append(f"### [{f.severity.name}] {f.title} ({f.check_id})")
        if f.cwe:
            lines.append(f"**CWE:** {f.cwe}  ")
        lines.append(f"**URL:** `{f.url}`  ")
        if f.detected_by_pipeline is not None:
            tag = "sí" if f.detected_by_pipeline else "**NO**"
            lines.append(f"**¿Detectado por el pipeline?:** {tag}  ")
        lines.append("\n**Evidencia:**\n```\n" + f.evidence + "\n```\n")
        lines.append(f.description + "\n")
        lines.append(f"**Remediación:** {f.remediation}\n")
        if f.ai_notes:
            lines.append(f"**Análisis IA:** {f.ai_notes}\n")
        lines.append("---\n")

    if coverage_rows:
        lines.append("## Cobertura del pipeline vs BopZ\n")
        lines.append("| Hallazgo | CWE | Pipeline (Semana 2) | BopZ (Semana 3) |")
        lines.append("|---|---|---|---|")
        for row in coverage_rows:
            mark = "✅" if row["pipeline"] else "❌"
            lines.append(f"| {row['title']} | {row['cwe']} | {mark} | ✅ |")

    return "\n".join(lines)


def save_reports(findings, meta, output_prefix, formats, executive_summary=None,
                  coverage_rows=None, version="1.0.0") -> list[str]:
    saved = []
    if "html" in formats:
        path = f"{output_prefix}.html"
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(generate_html(findings, meta, executive_summary, coverage_rows, version))
        saved.append(path)
    if "md" in formats:
        path = f"{output_prefix}.md"
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(generate_markdown(findings, meta, executive_summary, coverage_rows))
        saved.append(path)
    if "json" in formats:
        path = f"{output_prefix}.json"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({
                "meta": meta, "executive_summary": executive_summary,
                "findings": [f.to_dict() for f in findings], "coverage": coverage_rows,
            }, fh, ensure_ascii=False, indent=2)
        saved.append(path)
    return saved


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M %Z")

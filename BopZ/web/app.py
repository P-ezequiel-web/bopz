"""Dashboard web de BopZ — interfaz gráfica local para el scanner.

Nota de path: este archivo vive en web/ pero necesita importar el paquete
bopz/ que está un nivel arriba. Las dos líneas de sys.path más abajo
resuelven eso sin importar desde dónde se ejecute el script:
  python web/app.py          ← desde la raíz del proyecto
  PYTHONPATH=. python web/app.py  ← equivalente explícito

Expone tres rutas:
  GET  /           Formulario de configuración del escaneo
  POST /scan       Lanza el escaneo en background y redirige a /progress/<id>
  GET  /progress/<id>  Server-Sent Events: logs en tiempo real + resultado
  GET  /report/<id>    Reporte HTML embebido inline tras el escaneo

"""
from __future__ import annotations

import os
import sys
import threading
import uuid

# ── Fix de path ──────────────────────────────────────────────────────────────
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
# ─────────────────────────────────────────────────────────────────────────────

from flask import Flask, Response, redirect, render_template, request, url_for

from bopz.scanner import ScanConfig, ScanResult, run_scan

app = Flask(__name__)
_scans: dict[str, dict] = {}   # scan_id -> {"status", "logs", "result"}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def start_scan():
    target = request.form.get("target", "").strip()
    if not target:
        return redirect(url_for("index"))

    scan_id = uuid.uuid4().hex[:10]
    _scans[scan_id] = {"status": "running", "logs": [], "result": None}

    repo = request.form.get("repo", "").strip() or None
    config = ScanConfig(
        target=target,
        max_depth=int(request.form.get("depth", 2)),
        max_pages=int(request.form.get("max_pages", 60)),
        delay=float(request.form.get("delay", 0.2)),
        repo=repo,
        repo_branch=request.form.get("branch", "").strip() or None,
        enable_ai=bool(request.form.get("enable_ai")),
        enable_web_search=bool(request.form.get("web_search")),
        anthropic_api_key=(request.form.get("api_key") or
                            os.environ.get("ANTHROPIC_API_KEY")),
        output_formats=[],   # la web no guarda archivos, solo devuelve HTML
    )

    def run(sid: str, cfg: ScanConfig) -> None:
        def log(msg: str) -> None:
            _scans[sid]["logs"].append(msg)
        try:
            result = run_scan(cfg, progress_cb=log)
            _scans[sid]["result"] = result
            _scans[sid]["status"] = "done"
        except Exception as exc:
            _scans[sid]["logs"].append(f"[ERROR] {exc}")
            _scans[sid]["status"] = "error"

    threading.Thread(target=run, args=(scan_id, config), daemon=True).start()
    return redirect(url_for("progress", scan_id=scan_id))


@app.route("/progress/<scan_id>")
def progress(scan_id: str):
    if scan_id not in _scans:
        return "Escaneo no encontrado", 404
    return render_template("progress.html", scan_id=scan_id)


@app.route("/stream/<scan_id>")
def stream(scan_id: str):
    """Server-Sent Events: envía logs conforme aparecen y el estado final."""
    scan = _scans.get(scan_id)
    if not scan:
        return "Scan not found", 404

    def generate():
        sent = 0
        while True:
            logs = scan["logs"]
            while sent < len(logs):
                yield f"data: {logs[sent]}\n\n"
                sent += 1
            if scan["status"] in ("done", "error"):
                yield f"event: status\ndata: {scan['status']}\n\n"
                break
            import time; time.sleep(0.4)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/report/<scan_id>")
def report(scan_id: str):
    scan = _scans.get(scan_id)
    if not scan or scan["status"] != "done":
        return redirect(url_for("progress", scan_id=scan_id))

    result: ScanResult = scan["result"]
    from bopz.report import generate_html
    html = generate_html(
        findings=result.findings, meta=result.meta,
        executive_summary=result.executive_summary,
        coverage_rows=result.coverage_rows,
    )
    return html


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8090, debug=False)

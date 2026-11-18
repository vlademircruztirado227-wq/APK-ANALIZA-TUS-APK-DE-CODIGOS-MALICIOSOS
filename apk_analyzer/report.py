"""Generación de reportes: JSON y HTML autocontenido."""

from __future__ import annotations

import html
import json
import os

from .models import AnalysisResult

SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#f97316",
    "medium": "#f59e0b",
    "low": "#3b82f6",
    "info": "#64748b",
}


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024 # pyright: ignore[reportAssignmentType]
    return f"{n:.1f} TB"


def write_json(result: AnalysisResult, out_path: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(result.to_dict(), fh, ensure_ascii=False, indent=2)
    return out_path


def _esc(value: object) -> str:
    return html.escape(str(value))


def _version_suffix(app: dict) -> str:
    """' · v1.0 (1)' solo si hay datos de versión."""
    name = app.get("version_name") or ""
    code = app.get("version_code") or ""
    if not name and not code:
        return ""
    if name and code:
        return f" · v{_esc(name)} ({_esc(code)})"
    return f" · v{_esc(name or code)}"


def render_html(result: AnalysisResult) -> str:
    d = result.to_dict()
    app = d["app"]
    sig = d["signature"]
    risk = d["risk"]
    counts = risk["counts"]
    level_color = SEVERITY_COLORS.get(risk["level"], "#64748b")

    findings_html = []
    for f in d["findings"]:
        color = SEVERITY_COLORS.get(f["severity"], "#64748b")
        evidence = ""
        if f["evidence"]:
            items = "".join(f"<li><code>{_esc(e)}</code></li>" for e in f["evidence"])
            evidence = f'<details><summary>Evidencia ({len(f["evidence"])})</summary><ul class="ev">{items}</ul></details>'
        rec = f'<p class="rec"><strong>Recomendación:</strong> {_esc(f["recommendation"])}</p>' if f["recommendation"] else ""
        findings_html.append(
            f"""
            <article class="finding" style="--c:{color}">
              <header>
                <span class="badge">{_esc(f["severity_label"])}</span>
                <h3>{_esc(f["title"])}</h3>
                <span class="rid">{_esc(f["rule_id"])}</span>
              </header>
              <p>{_esc(f["description"])}</p>
              {rec}
              {evidence}
            </article>"""
        )

    vt = d.get("virustotal")
    if vt and vt.get("found"):
        vt_color = (SEVERITY_COLORS["critical"] if vt["malicious"] >= 10
                    else SEVERITY_COLORS["high"] if vt["malicious"] >= 3
                    else SEVERITY_COLORS["medium"] if vt["malicious"] >= 1
                    else "#22c55e")
        names = ", ".join(vt["threat_names"]) or "—"
        vt_html = f"""
    <section class="card">
      <h2>VirusTotal</h2>
      <p style="font-size:1.4rem;font-weight:700;color:{vt_color}">{_esc(vt["detection_ratio"])} motores</p>
      <p class="muted">Maliciosos: {vt["malicious"]} · Sospechosos: {vt["suspicious"]} · Sin detectar: {vt["undetected"]} · Reputación: {vt["reputation"]}</p>
      <p class="muted" style="margin-top:8px">Detecciones: <code>{_esc(names)}</code></p>
      <p class="muted" style="margin-top:8px"><a href="{_esc(vt["permalink"])}" style="color:#93c5fd">Ver en VirusTotal</a></p>
    </section>"""
    elif vt and vt.get("error"):
        vt_html = f'<section class="card"><h2>VirusTotal</h2><p class="muted">{_esc(vt["error"])}</p></section>'
    else:
        vt_html = ""

    perms_html = "".join(f"<li><code>{_esc(p)}</code></li>" for p in app["permissions"]) or "<li>—</li>"
    exported_html = "".join(f"<li><code>{_esc(c)}</code></li>" for c in app["exported_components"]) or "<li>—</li>"

    stats_rows = "".join(
        f"<tr><th>{_esc(k)}</th><td>{_esc(v)}</td></tr>" for k, v in d["stats"].items()
    )
    errors_html = ""
    if d["errors"]:
        errors_html = (
            '<section class="card"><h2>Errores durante el análisis</h2><ul>'
            + "".join(f"<li>{_esc(e)}</li>" for e in d["errors"])
            + "</ul></section>"
        )

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Análisis estático — {_esc(d["file"]["name"])}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:#0f172a;color:#e2e8f0;padding:24px;line-height:1.5}}
  .wrap{{max-width:1000px;margin:0 auto;display:flex;flex-direction:column;gap:18px}}
  .card{{background:#1e293b;border:1px solid #334155;border-radius:14px;padding:20px}}
  h1{{font-size:1.3rem;margin-bottom:4px}}
  h2{{font-size:1rem;margin-bottom:12px;color:#cbd5e1}}
  .muted{{color:#94a3b8;font-size:.85rem}}
  .score{{display:flex;align-items:center;gap:20px;flex-wrap:wrap}}
  .ring{{width:110px;height:110px;border-radius:50%;display:grid;place-items:center;
        background:conic-gradient({level_color} {risk["score"]}%, #334155 0);flex:0 0 auto}}
  .ring span{{width:86px;height:86px;border-radius:50%;background:#1e293b;display:grid;place-items:center;
        font-size:1.5rem;font-weight:700;color:{level_color}}}
  .verdict{{font-size:1.15rem;font-weight:700;color:{level_color}}}
  .chips{{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}}
  .chip{{font-size:.75rem;font-weight:600;padding:4px 10px;border-radius:999px;background:#0f172a;border:1px solid #334155}}
  table{{width:100%;border-collapse:collapse;font-size:.85rem}}
  th,td{{text-align:left;padding:6px 8px;border-bottom:1px solid #334155;vertical-align:top}}
  th{{color:#94a3b8;font-weight:600;width:45%}}
  code{{font-family:ui-monospace,Consolas,monospace;font-size:.8rem;word-break:break-all;color:#93c5fd}}
  ul{{list-style:none;display:flex;flex-direction:column;gap:4px}}
  .finding{{background:#0f172a;border-left:4px solid var(--c);border-radius:10px;padding:14px 16px;margin-bottom:10px}}
  .finding header{{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:6px}}
  .finding h3{{font-size:.95rem}}
  .badge{{font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.5px;
         padding:3px 8px;border-radius:6px;background:var(--c);color:#fff}}
  .rid{{margin-left:auto;font-size:.7rem;color:#64748b;font-family:ui-monospace,monospace}}
  .rec{{margin-top:6px;font-size:.85rem;color:#a5b4fc}}
  details{{margin-top:8px;font-size:.82rem}}
  summary{{cursor:pointer;color:#94a3b8}}
  .ev{{margin-top:6px;max-height:220px;overflow:auto;background:#111c33;padding:8px;border-radius:8px}}
  .grid{{display:grid;grid-template-columns:1fr 1fr;gap:18px}}
  @media(max-width:760px){{.grid{{grid-template-columns:1fr}}}}
</style>
</head>
<body>
<div class="wrap">

  <section class="card">
    <h1>{_esc(app["app_name"] or d["file"]["name"])}</h1>
    <p class="muted">{_esc(app["package"])}{_version_suffix(app)}</p>
    <p class="muted">SHA-256: <code>{_esc(d["file"]["sha256"])}</code></p>
    <p class="muted">Tamaño: {_human_size(d["file"]["size"])} · Analizado: {_esc(d["analyzed_at"])}</p>
  </section>

  <section class="card">
    <h2>Veredicto</h2>
    <div class="score">
      <div class="ring"><span>{risk["score"]}</span></div>
      <div>
        <div class="verdict">{_esc(risk["verdict"])}</div>
        <div class="muted">Nivel de riesgo: {_esc(risk["level_label"])} · {len(d["findings"])} hallazgos</div>
        <div class="chips">
          <span class="chip" style="color:{SEVERITY_COLORS['critical']}">Críticos: {counts.get("critical",0)}</span>
          <span class="chip" style="color:{SEVERITY_COLORS['high']}">Altos: {counts.get("high",0)}</span>
          <span class="chip" style="color:{SEVERITY_COLORS['medium']}">Medios: {counts.get("medium",0)}</span>
          <span class="chip" style="color:{SEVERITY_COLORS['low']}">Bajos: {counts.get("low",0)}</span>
          <span class="chip" style="color:{SEVERITY_COLORS['info']}">Info: {counts.get("info",0)}</span>
        </div>
      </div>
    </div>
  </section>

  <div class="grid">
    <section class="card">
      <h2>Firma</h2>
      <table>
        <tr><th>Firmado</th><td>{"Sí" if sig["is_signed"] else "No"}</td></tr>
        <tr><th>Esquema</th><td>{_esc(sig["scheme"] or "—")}</td></tr>
        <tr><th>Sujeto</th><td><code>{_esc(sig["subject"] or "—")}</code></td></tr>
        <tr><th>Emisor</th><td><code>{_esc(sig["issuer"] or "—")}</code></td></tr>
        <tr><th>SHA-256 cert</th><td><code>{_esc(sig["sha256"] or "—")}</code></td></tr>
        <tr><th>Válido hasta</th><td>{_esc(sig["valid_to"] or "—")}</td></tr>
        <tr><th>Autofirmado</th><td>{"Sí" if sig["is_self_signed"] else "No"}</td></tr>
        <tr><th>Cert. de debug</th><td>{"Sí" if sig["is_debug_cert"] else "No"}</td></tr>
      </table>
    </section>

    <section class="card">
      <h2>Estadísticas</h2>
      <table>{stats_rows}</table>
    </section>
  </div>

  {vt_html}

  <div class="grid">
    <section class="card">
      <h2>Permisos ({len(app["permissions"])})</h2>
      <ul>{perms_html}</ul>
    </section>
    <section class="card">
      <h2>Componentes exportados ({len(app["exported_components"])})</h2>
      <ul>{exported_html}</ul>
    </section>
  </div>

  <section class="card">
    <h2>Hallazgos ({len(d["findings"])})</h2>
    {"".join(findings_html) or "<p class='muted'>Sin hallazgos.</p>"}
  </section>

  {errors_html}

  <p class="muted" style="text-align:center;padding:10px">
    Generado por Analizador Estático de APKs · análisis 100% offline, el APK no se ejecuta.
  </p>
</div>
</body>
</html>
"""


def render_summary(results: list[AnalysisResult]) -> str:
    """Resumen comparativo HTML de varios APKs analizados."""
    ordered = sorted(results, key=lambda r: -r.risk_score)

    rows = []
    for r in ordered:
        counts = r.counts_by_severity()
        vt = r.vt
        if vt is not None and vt.found:
            vt_cell = f'<span style="color:{SEVERITY_COLORS["critical"] if vt.malicious >= 3 else "#22c55e"}">{_esc(vt.detection_ratio)}</span>'
        else:
            vt_cell = '<span class="muted">—</span>'
        rows.append(
            f"""
      <tr>
        <td><strong>{_esc(r.file_name)}</strong><br><span class="muted">{_esc(r.app.package or "—")}</span></td>
        <td><span class="score-pill" style="--c:{SEVERITY_COLORS.get(r.risk_level, '#64748b')}">{r.risk_score}</span></td>
        <td style="color:{SEVERITY_COLORS.get(r.risk_level, '#64748b')};font-weight:600">{_esc(r.verdict)}</td>
        <td>{vt_cell}</td>
        <td class="muted">C{counts.get("critical", 0)} · A{counts.get("high", 0)} · M{counts.get("medium", 0)} · B{counts.get("low", 0)}</td>
        <td><code>{_esc(r.sha256[:16])}…</code></td>
      </tr>"""
        )

    total = len(results)
    critical = sum(1 for r in results if r.risk_level == "critical")
    high = sum(1 for r in results if r.risk_level == "high")
    clean = sum(1 for r in results if r.risk_level in ("info", "low"))

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Resumen comparativo — {total} APKs</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:#0f172a;color:#e2e8f0;padding:24px;line-height:1.5}}
  .wrap{{max-width:1100px;margin:0 auto;display:flex;flex-direction:column;gap:18px}}
  .card{{background:#1e293b;border:1px solid #334155;border-radius:14px;padding:20px}}
  h1{{font-size:1.3rem;margin-bottom:4px}}
  .muted{{color:#94a3b8;font-size:.85rem}}
  .kpis{{display:flex;gap:12px;flex-wrap:wrap}}
  .kpi{{flex:1 1 150px;background:#0f172a;border:1px solid #334155;border-radius:10px;padding:14px}}
  .kpi b{{display:block;font-size:1.6rem}}
  table{{width:100%;border-collapse:collapse;font-size:.88rem}}
  th,td{{text-align:left;padding:10px 8px;border-bottom:1px solid #334155;vertical-align:middle}}
  th{{color:#94a3b8;font-weight:600;font-size:.78rem;text-transform:uppercase;letter-spacing:.5px}}
  code{{font-family:ui-monospace,Consolas,monospace;font-size:.78rem;color:#93c5fd}}
  .score-pill{{display:inline-block;min-width:44px;text-align:center;font-weight:700;padding:4px 8px;
              border-radius:8px;background:var(--c);color:#fff}}
</style>
</head>
<body>
<div class="wrap">
  <section class="card">
    <h1>Resumen comparativo</h1>
    <p class="muted">{total} APK(s) analizados · ordenados por riesgo</p>
  </section>

  <section class="card">
    <div class="kpis">
      <div class="kpi"><b style="color:{SEVERITY_COLORS['critical']}">{critical}</b><span class="muted">Críticos</span></div>
      <div class="kpi"><b style="color:{SEVERITY_COLORS['high']}">{high}</b><span class="muted">Altos</span></div>
      <div class="kpi"><b style="color:#22c55e">{clean}</b><span class="muted">Bajo riesgo</span></div>
      <div class="kpi"><b>{total}</b><span class="muted">Total</span></div>
    </div>
  </section>

  <section class="card">
    <table>
      <thead>
        <tr><th>Archivo</th><th>Riesgo</th><th>Veredicto</th><th>VirusTotal</th><th>Hallazgos</th><th>SHA-256</th></tr>
      </thead>
      <tbody>
        {"".join(rows)}
      </tbody>
    </table>
  </section>

  <p class="muted" style="text-align:center;padding:10px">
    Generado por Analizador Estático de APKs · análisis 100% offline (salvo la consulta de hash a VirusTotal).
  </p>
</div>
</body>
</html>
"""

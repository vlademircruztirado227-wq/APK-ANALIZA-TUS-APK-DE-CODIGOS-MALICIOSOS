"""Interfaz de línea de comandos."""

from __future__ import annotations

import argparse
import logging
import os
import sys

from . import __version__
from .analyzer import analyze
from .models import SEVERITY_LABEL_ES
from .report import render_html, render_summary, write_json
from .virustotal import RateLimiter

# Códigos de salida (útiles para CI / scripts)
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "critical": "\033[91m",
    "high": "\033[38;5;208m",
    "medium": "\033[93m",
    "low": "\033[94m",
    "info": "\033[90m",
    "ok": "\033[92m",
}


def _color(text: str, key: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{ANSI.get(key, '')}{text}{ANSI['reset']}"


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1023 # type: ignore
    return f"{n:.1f} TB"


def _print_report(result, use_color: bool, show_all: bool) -> None:
    c = lambda t, k: _color(t, k, use_color)  # noqa: E731
    app = result.app

    print()
    print(c("═" * 66, "dim"))
    print(c("  ANALIZADOR ESTÁTICO DE APKs", "bold"))
    print(c("═" * 66, "dim"))
    print(f"  Archivo   : {result.file_name}  ({_human_size(result.file_size)})")
    print(f"  Paquete   : {app.package or '—'}")
    print(f"  App       : {app.app_name or '—'}  v{app.version_name or '?'}")
    print(f"  SDK       : min {app.min_sdk or '?'} / target {app.target_sdk or '?'}")
    print(f"  SHA-256   : {result.sha256}")
    print(f"  Firma     : {'sí' if result.signature.is_signed else 'NO'}"
          f"{' (debug)' if result.signature.is_debug_cert else ''}"
          f"{' (autofirmado)' if result.signature.is_self_signed else ''}")

    vt = result.vt
    if vt is not None and vt.queried and vt.found:
        vt_color = "critical" if vt.malicious >= 10 else "high" if vt.malicious >= 3 \
            else "medium" if vt.malicious >= 1 else "ok"
        print(f"  VirusTotal: {c(vt.detection_ratio + ' motores', vt_color)}"
              f"  {c(vt.permalink, 'dim')}")
    elif vt is not None and vt.error:
        print(f"  VirusTotal: {c(vt.error, 'dim')}")
    print()

    level = result.risk_level
    bar_len = 30
    filled = int(result.risk_score / 100 * bar_len)
    bar = "█" * filled + "░" * (bar_len - filled)
    print(f"  Riesgo    : {c(bar, level)}  {c(str(result.risk_score) + '/100', level)}")
    print(f"  Veredicto : {c(result.verdict, level)}  ({SEVERITY_LABEL_ES[level]})")

    counts = result.counts_by_severity()
    print("  Hallazgos : " + "  ".join(
        c(f"{SEVERITY_LABEL_ES[k]}: {v}", k) for k, v in counts.items() if v
    ) if any(counts.values()) else "  Hallazgos : ninguno")
    print()

    findings = result.sorted_findings()
    if not show_all:
        findings = [f for f in findings if f.severity != "info"]

    if findings:
        print(c("  ── Hallazgos ─────────────────────────────────────────────", "dim"))
        for f in findings:
            tag = c(f"[{SEVERITY_LABEL_ES[f.severity].upper():<11}]", f.severity)
            print(f"  {tag} {f.title}  {c('(' + f.rule_id + ')', 'dim')}")
            if f.evidence:
                preview = ", ".join(f.evidence[:3])
                if len(f.evidence) > 3:
                    preview += f" … (+{len(f.evidence) - 3})"
                print(f"              {c(preview[:110], 'dim')}")
        print()

    if result.errors:
        print(c("  ── Avisos del analizador ─────────────────────────────────", "dim"))
        for e in result.errors:
            print(f"  ! {e}")
        print()


_SEV_ABBR = {"critical": "C", "high": "A", "medium": "M", "low": "B", "info": "I"}


def _print_summary(results, use_color: bool) -> None:
    """Tabla comparativa de todos los APKs analizados."""
    c = lambda t, k: _color(t, k, use_color)  # noqa: E731
    print(c("═" * 78, "dim"))
    print(c("  RESUMEN COMPARATIVO", "bold"))
    print(c("═" * 78, "dim"))
    print(f"  {'ARCHIVO':<28} {'RIESGO':>7}  {'NIVEL':<11} {'VT':>8}  HALLAZGOS")
    print(c("  " + "─" * 74, "dim"))

    for r in sorted(results, key=lambda x: -x.risk_score):
        name = r.file_name if len(r.file_name) <= 27 else r.file_name[:24] + "..."
        counts = r.counts_by_severity()
        summary = " ".join(f"{_SEV_ABBR[k]}{v}" for k, v in counts.items() if v) or "—"
        vt = r.vt.detection_ratio if (r.vt is not None and r.vt.found) else "—"
        print(f"  {name:<28} {c(f'{r.risk_score:>5}/100', r.risk_level)}  "
              f"{c(f'{SEVERITY_LABEL_ES[r.risk_level]:<11}', r.risk_level)} {vt:>8}  {summary}")

    print(c("  " + "─" * 74, "dim"))
    print(f"  {len(results)} APK(s) · C=crítico A=alto M=medio B=bajo I=info")
    print()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="apk-analyzer",
        description="Analizador estático de APKs: detecta indicadores de riesgo sin ejecutar la app.",
    )
    p.add_argument("apk", nargs="+", help="Ruta(s) al archivo .apk")
    p.add_argument("-o", "--output", help="Directorio donde guardar los reportes (JSON + HTML)")
    p.add_argument("--json", metavar="FILE", help="Guardar reporte JSON en esta ruta")
    p.add_argument("--html", metavar="FILE", help="Guardar reporte HTML en esta ruta")
    p.add_argument("--all", action="store_true", help="Mostrar también hallazgos informativos")
    p.add_argument("--no-color", action="store_true", help="Desactivar colores en la terminal")
    p.add_argument("--fail-on", choices=["low", "medium", "high", "critical"],
                   help="Salir con código 1 si el riesgo alcanza este nivel (para CI)")
    p.add_argument("--vt-key", metavar="KEY",
                   help="Clave de API de VirusTotal (por defecto: variable VT_API_KEY)")
    p.add_argument("--no-vt", action="store_true",
                   help="No consultar VirusTotal aunque haya clave")
    p.add_argument("--summary", metavar="FILE",
                   help="Guardar un resumen comparativo HTML de todos los APKs analizados")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _setup_console() -> None:
    """Evita UnicodeEncodeError en consolas Windows (cp1252)."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            pass


def main(argv: list[str] | None = None) -> int:
    _setup_console()
    args = build_parser().parse_args(argv)
    # androguard es muy verboso en DEBUG; solo mostramos errores reales.
    logging.getLogger("androguard").setLevel(logging.CRITICAL)
    use_color = not args.no_color and sys.stdout.isatty()

    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    exit_code = EXIT_OK
    results = []
    limiter = RateLimiter()
    vt_enabled = not args.no_vt and bool(args.vt_key or os.environ.get("VT_API_KEY"))

    for index, apk_path in enumerate(args.apk):
        try:
            if vt_enabled and index > 0:
                limiter.wait()
            result = analyze(apk_path, vt_key=args.vt_key, use_vt=vt_enabled)
        except Exception as exc:  # noqa: BLE001
            print(f"ERROR analizando {apk_path}: {exc}", file=sys.stderr)
            exit_code = EXIT_ERROR
            continue

        results.append(result)
        _print_report(result, use_color, args.all)

        stem = os.path.splitext(os.path.basename(apk_path))[0]
        if args.output:
            os.makedirs(args.output, exist_ok=True)
            json_path = os.path.join(args.output, f"{stem}.json")
            html_path = os.path.join(args.output, f"{stem}.html")
            write_json(result, json_path)
            with open(html_path, "w", encoding="utf-8") as fh:
                fh.write(render_html(result))
            print(f"  Reportes: {json_path}")
            print(f"            {html_path}")
            print()
        if args.json:
            write_json(result, args.json)
            print(f"  JSON: {args.json}")
        if args.html:
            with open(args.html, "w", encoding="utf-8") as fh:
                fh.write(render_html(result))
            print(f"  HTML: {args.html}")

        if args.fail_on and order[result.risk_level] >= order[args.fail_on]:
            exit_code = EXIT_FINDINGS

    if args.summary and results:
        with open(args.summary, "w", encoding="utf-8") as fh:
            fh.write(render_summary(results))
        print(f"  Resumen comparativo: {args.summary}")
        print()

    if len(results) > 1:
        _print_summary(results, use_color)

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

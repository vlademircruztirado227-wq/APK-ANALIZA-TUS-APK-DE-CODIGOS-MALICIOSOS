"""Orquestador del análisis estático."""

from __future__ import annotations

import os
from datetime import datetime, timezone

from .apk_reader import file_hashes, read_apk
from .models import AnalysisResult, Finding
from .rules import run_rules
from .virustotal import VTResult, lookup


def _vt_finding(vt: VTResult) -> Finding | None:
    """Convierte el veredicto de VirusTotal en un hallazgo puntuable."""
    if not vt.queried or not vt.found:
        return None

    if vt.malicious >= 10:
        severity, score = "critical", 40
    elif vt.malicious >= 3:
        severity, score = "high", 25
    elif vt.malicious >= 1:
        severity, score = "medium", 12
    elif vt.suspicious >= 1:
        severity, score = "low", 5
    else:
        return Finding(
            rule_id="VT-CLEAN",
            title="VirusTotal: sin detecciones",
            severity="info",
            description=(
                f"Ningún motor de VirusTotal marca el hash como malicioso "
                f"({vt.detection_ratio})."
            ),
            category="reputación",
            score=0,
            evidence=[vt.permalink] if vt.permalink else [],
        )

    return Finding(
        rule_id="VT-DETECTIONS",
        title=f"VirusTotal: {vt.malicious} detecciones",
        severity=severity,
        description=(
            f"{vt.detection_ratio} motores marcan el hash como malicioso. "
            "La reputación es un indicador fuerte, aunque puede incluir "
            "falsos positivos."
        ),
        category="reputación",
        score=score,
        evidence=vt.threat_names[:10] + ([vt.permalink] if vt.permalink else []),
        recommendation="No instalar sin una revisión manual; contrastar con un sandbox.",
    )


def analyze(path: str, vt_key: str | None = None, use_vt: bool = True) -> AnalysisResult:
    """Analiza un APK y devuelve el resultado completo.

    No ejecuta el archivo: solo lo lee como ZIP y parsea su contenido.
    Si ``use_vt`` y hay clave de API, consulta el hash en VirusTotal.
    """
    path = os.path.abspath(path)
    sha256, md5 = file_hashes(path)

    result = AnalysisResult(
        file_path=path,
        file_name=os.path.basename(path),
        file_size=os.path.getsize(path),
        sha256=sha256,
        md5=md5,
        analyzed_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )

    data = read_apk(path)
    result.app = data.app
    result.signature = data.signature
    result.errors.extend(data.errors)

    result.findings = run_rules(data)

    if use_vt:
        result.vt = lookup(sha256, api_key=vt_key)
        vt_finding = _vt_finding(result.vt)
        if vt_finding is not None:
            result.findings.append(vt_finding)

    result.stats = {
        "dex_count": data.dex_count,
        "dex_total_size": data.total_dex_size,
        "classes": len(data.dex_classes),
        "methods": len(data.dex_methods),
        "strings": len(data.dex_strings),
        "native_libs": len(data.native_libs),
        "assets": len(data.assets),
        "zip_entries": len(data.entries),
        "permissions": len(data.app.permissions),
        "exported_components": len(data.app.exported_components),
    }
    return result

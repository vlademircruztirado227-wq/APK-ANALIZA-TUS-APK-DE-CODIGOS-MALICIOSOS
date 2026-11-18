"""Modelos de datos del analizador."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

SEVERITY_LABEL_ES = {
    "info": "Informativo",
    "low": "Bajo",
    "medium": "Medio",
    "high": "Alto",
    "critical": "Crítico",
}

@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    description: str
    category: str = "general"
    evidence: list[str] = field(default_factory=list)
    recommendation: str = ""
    score: int = 0

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity_label"] = SEVERITY_LABEL_ES.get(self.severity, self.severity)
        return data

@dataclass
class AppInfo:
    package: str = ""
    app_name: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: str = ""
    target_sdk: str = ""
    main_activity: str = ""
    permissions: list[str] = field(default_factory=list)
    activities: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    receivers: list[str] = field(default_factory=list)
    providers: list[str] = field(default_factory=list)
    exported_components: list[str] = field(default_factory=list)
    debuggable: bool = False
    allow_backup: bool = False
    uses_cleartext: bool = False
    network_security_config: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass
class SignatureInfo:
    is_signed: bool = False
    scheme: str = ""
    subject: str = ""
    issuer: str = ""
    serial: str = ""
    sha256: str = ""
    valid_from: str = ""
    valid_to: str = ""
    is_self_signed: bool = False
    is_debug_cert: bool = False
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass
class AnalysisResult:
    file_path: str = ""
    file_name: str = ""
    file_size: int = 0
    sha256: str = ""
    md5: str = ""
    analyzed_at: str = ""
    app: AppInfo = field(default_factory=AppInfo)
    signature: SignatureInfo = field(default_factory=SignatureInfo)
    findings: list[Finding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    vt: Any = None

    @property
    def risk_score(self) -> int:
        return min(100, sum(f.score for f in self.findings))

    @property
    def risk_level(self) -> str:
        score = self.risk_score
        if score >= 70:
            return "critical"
        if score >= 45:
            return "high"
        if score >= 20:
            return "medium"
        if score > 0:
            return "low"
        return "info"

    @property
    def verdict(self) -> str:
        return {
            "critical": "Muy sospechoso",
            "high": "Sospechoso",
            "medium": "Requiere revisión",
            "low": "Probablemente legítimo",
            "info": "Sin indicadores",
        }[self.risk_level]

    def counts_by_severity(self) -> dict[str, int]:
        counts = {k: 0 for k in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), -f.score, f.rule_id),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": {"path": self.file_path, "name": self.file_name, "size": self.file_size, "sha256": self.sha256, "md5": self.md5},
            "analyzed_at": self.analyzed_at,
            "app": self.app.to_dict(),
            "signature": self.signature.to_dict(),
            "risk": {"score": self.risk_score, "level": self.risk_level, "level_label": SEVERITY_LABEL_ES.get(self.risk_level, self.risk_level), "verdict": self.verdict, "counts": self.counts_by_severity()},
            "stats": self.stats,
            "virustotal": self.vt.to_dict() if self.vt is not None else None,
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "errors": self.errors,
        }

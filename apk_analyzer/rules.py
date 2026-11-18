"""Motor de reglas heurísticas.

Cada regla recibe los datos crudos del APK y devuelve una lista de
`Finding`. Las reglas son independientes entre sí, de modo que se
pueden añadir o quitar sin tocar el resto del analizador.
"""

from __future__ import annotations

import re
from typing import Callable

from .apk_reader import DANGEROUS_PERMISSIONS, RawApkData
from .models import Finding

Rule = Callable[[RawApkData], list[Finding]]

# ---------------------------------------------------------------------------
# Patrones de interés
# ---------------------------------------------------------------------------

# Permisos que por sí solos son señal fuerte de abuso (spyware / banker).
CRITICAL_PERMISSIONS = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE": (
        "Servicio de accesibilidad",
        "Permite leer la pantalla y simular toques: base de troyanos bancarios "
        "y de apps que roban credenciales de otras aplicaciones.",
    ),
    "android.permission.BIND_DEVICE_ADMIN": (
        "Administrador de dispositivos",
        "Permite bloquear, borrar datos o impedir la desinstalación: usado por "
        "ransomware y por apps que se resisten a ser eliminadas.",
    ),
    "android.permission.SYSTEM_ALERT_WINDOW": (
        "Superposición de ventanas (overlay)",
        "Habilita ataques de superposición de pantalla para capturar pulsaciones "
        "sobre otras apps (clickjacking / overlay phishing).",
    ),
    "android.permission.REQUEST_INSTALL_PACKAGES": (
        "Instalación de paquetes",
        "Permite instalar otros APKs: vector típico de droppers que descargan "
        "un segundo payload malicioso.",
    ),
    "android.permission.SEND_SMS": (
        "Envío de SMS",
        "Usado para suscripción a servicios premium y para propagar el malware "
        "por SMS sin conocimiento del usuario.",
    ),
    "android.permission.READ_SMS": (
        "Lectura de SMS",
        "Permite interceptar códigos OTP de banca y de doble factor.",
    ),
    "android.permission.RECEIVE_SMS": (
        "Recepción de SMS",
        "Permite interceptar y suprimir SMS entrantes (OTP, alertas del banco).",
    ),
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": (
        "Acceso a notificaciones",
        "Lee todas las notificaciones del dispositivo, incluidos códigos de "
        "verificación de otras apps.",
    ),
    "android.permission.READ_CALL_LOG": (
        "Lectura del registro de llamadas",
        "Recolecta historial de llamadas: dato sensible usado en spyware.",
    ),
    "android.permission.CALL_PHONE": (
        "Realizar llamadas",
        "Puede marcar números de tarificación especial sin intervención del usuario.",
    ),
    "android.permission.PACKAGE_USAGE_STATS": (
        "Estadísticas de uso de apps",
        "Permite saber qué apps usa la víctima y cuándo, para lanzar overlays "
        "en el momento adecuado.",
    ),
    "android.permission.QUERY_ALL_PACKAGES": (
        "Consulta de todas las apps instaladas",
        "Inventario completo del dispositivo: usado para detectar apps bancarias "
        "y antivirus instalados.",
    ),
    "android.permission.WRITE_SECURE_SETTINGS": (
        "Escritura de ajustes seguros",
        "Permite cambiar ajustes protegidos del sistema (solo vía ADB/root).",
    ),
    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS": (
        "Montaje de sistemas de archivos",
        "Permiso de sistema con capacidad de manipular el almacenamiento.",
    ),
    "android.permission.READ_LOGS": (
        "Lectura de logs del sistema",
        "Puede exponer datos de otras aplicaciones registrados en logcat.",
    ),
}

# APIs / clases que indican capacidades de evasión o carga dinámica.
SUSPICIOUS_APIS = {
    "Ldalvik/system/DexClassLoader;": (
        "Carga dinámica de DEX (DexClassLoader)",
        "Carga código ejecutable que no viene en el APK: técnica habitual para "
        "ocultar el payload real a los antivirus.",
        "high",
    ),
    "Ldalvik/system/PathClassLoader;": (
        "Carga dinámica de clases (PathClassLoader)",
        "Puede cargar código desde almacenamiento externo en tiempo de ejecución.",
        "medium",
    ),
    "Ldalvik/system/InMemoryDexClassLoader;": (
        "Carga de DEX en memoria",
        "Ejecuta código desde memoria sin tocar disco: evasión de análisis.",
        "high",
    ),
    "Ljava/lang/Runtime;->exec": (
        "Ejecución de comandos del sistema (Runtime.exec)",
        "Permite lanzar binarios o scripts del sistema operativo.",
        "high",
    ),
    "Ljava/lang/ProcessBuilder": (
        "Ejecución de procesos (ProcessBuilder)",
        "Permite lanzar procesos externos.",
        "medium",
    ),
    "Ljava/lang/reflect/Method;->invoke": (
        "Reflexión (Method.invoke)",
        "Uso intensivo de reflexión para ocultar llamadas a APIs sensibles.",
        "low",
    ),
    "Ljava/lang/Class;->forName": (
        "Carga de clases por nombre (Class.forName)",
        "Resuelve clases en tiempo de ejecución: técnica habitual para ocultar "
        "dependencias y evadir el análisis estático.",
        "low",
    ),
    "Landroid/telephony/SmsManager": (
        "API de SMS (SmsManager)",
        "Envío o gestión de SMS desde código.",
        "medium",
    ),
    "Landroid/accessibilityservice/AccessibilityService": (
        "API de accesibilidad",
        "Implementa un servicio de accesibilidad: puede leer y controlar la pantalla.",
        "high",
    ),
    "Landroid/app/admin/DeviceAdminReceiver": (
        "API de administrador de dispositivos",
        "Implementa un receptor de administración del dispositivo.",
        "high",
    ),
    "Landroid/media/projection/MediaProjection": (
        "Captura de pantalla (MediaProjection)",
        "Permite grabar la pantalla del usuario en tiempo real.",
        "high",
    ),
    "Landroid/hardware/camera2/CameraManager": (
        "Acceso a cámara (Camera2)",
        "Control de la cámara del dispositivo.",
        "low",
    ),
    "Landroid/location/LocationManager": (
        "Acceso a ubicación",
        "Seguimiento de la posición del usuario.",
        "low",
    ),
    "Landroid/content/pm/PackageInstaller": (
        "Instalador de paquetes (PackageInstaller)",
        "Instala APKs adicionales en el dispositivo.",
        "high",
    ),
    "Ljava/net/Socket": (
        "Sockets TCP directos",
        "Comunicación de red de bajo nivel, frecuente en backdoors.",
        "low",
    ),
    "Ljavax/crypto/Cipher": (
        "Criptografía (Cipher)",
        "Cifrado de datos: legítimo, pero también usado para ocultar strings y C2.",
        "info",
    ),
    "Landroid/util/Base64": (
        "Codificación Base64",
        "Ofuscación ligera de cadenas o payloads.",
        "info",
    ),
}

# Paquetes de empaquetadores / protectores comerciales conocidos.
PACKERS = {
    "com/tencent/StubShell": "Tencent Legu",
    "com/qihoo/util": "Qihoo 360 Jiagu",
    "com/baidu/protect": "Baidu Protect",
    "com/secneo/apkwrapper": "SecNeo",
    "com/ali/mobisecenhance": "Alibaba SecShell",
    "com/nqshield": "NQ Shield",
    "com/payegis": "PayEgis",
    "com/netease/nis": "NetEase Yidun",
    "libshella": "Bangcle",
    "com/tencent/bugly": "Tencent Bugly (no es packer, telemetría)",
}

# Dominios / TLDs frecuentes en infraestructura maliciosa.
SUSPICIOUS_TLDS = (
    ".top", ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".click",
    ".work", ".loan", ".rest", ".icu", ".cyou", ".sbs", ".monster",
)

URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,200}")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TELEGRAM_RE = re.compile(r"api\.telegram\.org/bot[0-9]+:[A-Za-z0-9_-]+")
ONION_RE = re.compile(r"\b[a-z2-7]{16,56}\.onion\b")

# Indicadores de texto típicos de apps fraudulentas.
FRAUD_KEYWORDS = {
    "sms premium": "medium",
    "premium sms": "medium",
    "send sms": "low",
    "root exploit": "high",
    "su binary": "high",
    "superuser": "medium",
    "keylogger": "critical",
    "screen capture": "medium",
    "accessibility service": "medium",
    "device admin": "medium",
    "overlay": "medium",
    "inject": "medium",
    "hook": "low",
    "frida": "high",
    "xposed": "high",
    "magisk": "medium",
    "emulator": "low",
    "isdebuggerconnected": "medium",
    "getinstalledpackages": "low",
    "otp": "low",
    "2fa": "low",
    "bank": "low",
    "wallet": "low",
    "crypto": "low",
}


def _finding(
    rule_id: str,
    title: str,
    severity: str,
    description: str,
    category: str,
    score: int,
    evidence: list[str] | None = None,
    recommendation: str = "",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        description=description,
        category=category,
        score=score,
        evidence=evidence or [],
        recommendation=recommendation,
    )


# ---------------------------------------------------------------------------
# Reglas
# ---------------------------------------------------------------------------

def rule_critical_permissions(data: RawApkData) -> list[Finding]:
    out: list[Finding] = []
    perms = set(data.app.permissions)
    for perm, (label, why) in CRITICAL_PERMISSIONS.items():
        if perm in perms:
            out.append(
                _finding(
                    rule_id=f"PERM-{perm.rsplit('.', 1)[-1]}",
                    title=f"Permiso sensible: {label}",
                    severity="high",
                    description=why,
                    category="permisos",
                    score=12,
                    evidence=[perm],
                    recommendation="Verificar si la funcionalidad declarada justifica este permiso.",
                )
            )
    return out


def rule_dangerous_permission_count(data: RawApkData) -> list[Finding]:
    perms = set(data.app.permissions)
    dangerous = sorted(perms & DANGEROUS_PERMISSIONS)
    if len(dangerous) >= 12:
        return [
            _finding(
                rule_id="PERM-COUNT-HIGH",
                title=f"Exceso de permisos peligrosos ({len(dangerous)})",
                severity="high",
                description=(
                    "La app solicita un número muy elevado de permisos peligrosos. "
                    "Las apps legítimas suelen limitarse a los estrictamente necesarios."
                ),
                category="permisos",
                score=15,
                evidence=dangerous,
                recommendation="Revisar cada permiso y su relación con la funcionalidad real.",
            )
        ]
    if len(dangerous) >= 7:
        return [
            _finding(
                rule_id="PERM-COUNT-MEDIUM",
                title=f"Muchos permisos peligrosos ({len(dangerous)})",
                severity="medium",
                description="Número elevado de permisos sensibles para una sola app.",
                category="permisos",
                score=8,
                evidence=dangerous,
            )
        ]
    return []


def rule_exported_components(data: RawApkData) -> list[Finding]:
    exported = data.app.exported_components
    if not exported:
        return []
    severity = "high" if len(exported) >= 5 else "medium"
    return [
        _finding(
            rule_id="COMP-EXPORTED",
            title=f"Componentes exportados ({len(exported)})",
            severity=severity,
            description=(
                "Componentes accesibles desde otras aplicaciones. Si no están "
                "protegidos con permisos, pueden ser invocados por terceros."
            ),
            category="componentes",
            score=10 if severity == "high" else 6,
            evidence=exported[:40],
            recommendation="Revisar cada componente exportado y añadir android:permission si no es necesario.",
        )
    ]


def rule_debuggable(data: RawApkData) -> list[Finding]:
    if not data.app.debuggable:
        return []
    return [
        _finding(
            rule_id="APP-DEBUGGABLE",
            title="Aplicación compilada en modo depurable",
            severity="high",
            description=(
                "android:debuggable=\"true\" permite adjuntar un depurador y "
                "ejecutar código arbitrario en el contexto de la app. Un APK de "
                "producción nunca debería estar en este estado."
            ),
            category="configuración",
            score=15,
            evidence=["android:debuggable=true"],
            recommendation="Compilar en modo release.",
        )
    ]


def rule_backup(data: RawApkData) -> list[Finding]:
    if not data.app.allow_backup:
        return []
    return [
        _finding(
            rule_id="APP-ALLOW-BACKUP",
            title="Copias de seguridad habilitadas (allowBackup)",
            severity="low",
            description=(
                "Permite extraer los datos privados de la app mediante adb backup "
                "en dispositivos con depuración USB habilitada."
            ),
            category="configuración",
            score=4,
            evidence=["android:allowBackup=true"],
        )
    ]


def rule_cleartext(data: RawApkData) -> list[Finding]:
    if not data.app.uses_cleartext:
        return []
    return [
        _finding(
            rule_id="NET-CLEARTEXT",
            title="Tráfico HTTP en claro permitido",
            severity="medium",
            description=(
                "usesCleartextTraffic=\"true\" permite conexiones sin TLS: los "
                "datos pueden ser interceptados en redes Wi-Fi públicas."
            ),
            category="red",
            score=8,
            evidence=["android:usesCleartextTraffic=true"],
            recommendation="Usar HTTPS y una network security config restrictiva.",
        )
    ]


def rule_signature(data: RawApkData) -> list[Finding]:
    out: list[Finding] = []
    sig = data.signature
    if not sig.is_signed:
        out.append(
            _finding(
                rule_id="SIG-UNSIGNED",
                title="APK sin firma válida",
                severity="high",
                description="No se encontró un certificado de firma legible en el APK.",
                category="firma",
                score=15,
            )
        )
        return out
    if sig.is_debug_cert:
        out.append(
            _finding(
                rule_id="SIG-DEBUG",
                title="Firmado con certificado de depuración",
                severity="high",
                description=(
                    "El APK está firmado con el certificado de debug de Android. "
                    "No es una build oficial de producción."
                ),
                category="firma",
                score=15,
                evidence=[sig.subject],
            )
        )
    if sig.is_self_signed:
        out.append(
            _finding(
                rule_id="SIG-SELF-SIGNED",
                title="Certificado autofirmado",
                severity="low",
                description=(
                    "La firma es autofirmada. Es lo normal en Android para apps "
                    "fuera de Google Play, pero impide verificar la identidad del autor."
                ),
                category="firma",
                score=3,
                evidence=[sig.subject],
            )
        )
    return out


def rule_suspicious_apis(data: RawApkData) -> list[Finding]:
    out: list[Finding] = []
    classes = set(data.dex_classes)
    methods = set(data.dex_methods)
    strings = data.dex_strings

    for api, (label, why, severity) in SUSPICIOUS_APIS.items():
        # Las clases se buscan en la tabla de tipos; los métodos, en la tabla
        # de métodos y en los strings (que contienen descriptores completos).
        if api.startswith("L") and api.endswith(";"):
            hits = [c for c in classes if api in c]
        else:
            hits = [m for m in methods if api in m]
            hits += [s for s in strings if api in s][:5]
        if not hits:
            continue
        score = {"critical": 20, "high": 12, "medium": 6, "low": 3, "info": 0}[severity]
        out.append(
            _finding(
                rule_id=f"API-{re.sub(r'[^A-Za-z0-9]+', '-', api).strip('-')[:40]}",
                title=f"Uso de {label}",
                severity=severity,
                description=why,
                category="código",
                score=score,
                evidence=sorted(hits)[:10],
            )
        )
    return out


def rule_packers(data: RawApkData) -> list[Finding]:
    out: list[Finding] = []
    classes = set(data.dex_classes)
    for prefix, name in PACKERS.items():
        hits = [c for c in classes if prefix in c]
        if hits:
            out.append(
                _finding(
                    rule_id=f"PACKER-{name.split()[0].upper()}",
                    title=f"Empaquetador / protector detectado: {name}",
                    severity="medium",
                    description=(
                        "El APK está protegido con un empaquetador comercial. "
                        "El código real se carga en tiempo de ejecución, por lo que "
                        "el análisis estático solo ve el stub."
                    ),
                    category="ofuscación",
                    score=10,
                    evidence=sorted(hits)[:5],
                )
            )
    return out


def rule_obfuscation(data: RawApkData) -> list[Finding]:
    if not data.has_obfuscation_hint:
        return []
    return [
        _finding(
            rule_id="OBF-NAMES",
            title="Código ofuscado (nombres de clase mínimos)",
            severity="low",
            description=(
                "Gran proporción de clases con nombres de 1-2 caracteres, "
                "típico de ProGuard/R8 o de ofuscación deliberada."
            ),
            category="ofuscación",
            score=4,
        )
    ]


def rule_native_libs(data: RawApkData) -> list[Finding]:
    if not data.native_libs:
        return []
    return [
        _finding(
            rule_id="NATIVE-LIBS",
            title=f"Librerías nativas incluidas ({len(data.native_libs)})",
            severity="info",
            description=(
                "El APK incluye código nativo (.so). Es habitual en apps legítimas "
                "(motores gráficos, códecs), pero también en malware que oculta "
                "lógica fuera del DEX."
            ),
            category="código",
            score=2,
            evidence=data.native_libs[:20],
        )
    ]


def rule_network_iocs(data: RawApkData) -> list[Finding]:
    out: list[Finding] = []
    strings = data.dex_strings

    urls = sorted({m.group(0) for s in strings for m in [URL_RE.search(s)] if m})
    ips = sorted({m.group(0) for s in strings for m in [IP_RE.search(s)] if m})
    telegram = sorted({m.group(0) for s in strings for m in [TELEGRAM_RE.search(s)] if m})
    onion = sorted({m.group(0) for s in strings for m in [ONION_RE.search(s)] if m})

    if telegram:
        out.append(
            _finding(
                rule_id="IOC-TELEGRAM-BOT",
                title="Token de bot de Telegram embebido",
                severity="critical",
                description=(
                    "El APK contiene un token de bot de Telegram. Es el canal de "
                    "C2/exfiltración más común en el malware Android reciente."
                ),
                category="red",
                score=30,
                evidence=telegram[:5],
            )
        )
    if onion:
        out.append(
            _finding(
                rule_id="IOC-ONION",
                title="Dirección .onion embebida",
                severity="high",
                description="Referencia a un servicio oculto de Tor.",
                category="red",
                score=20,
                evidence=onion[:5],
            )
        )

    suspicious = [u for u in urls if any(t in u.lower() for t in SUSPICIOUS_TLDS)]
    if suspicious:
        out.append(
            _finding(
                rule_id="IOC-SUSPICIOUS-TLD",
                title=f"URLs con TLD de bajo coste ({len(suspicious)})",
                severity="medium",
                description=(
                    "Dominios en TLDs gratuitos o de bajo coste, frecuentes en "
                    "infraestructura de phishing y C2."
                ),
                category="red",
                score=8,
                evidence=suspicious[:15],
            )
        )

    raw_ips = [ip for ip in ips if not ip.startswith(("0.", "127.", "255."))]
    if raw_ips:
        out.append(
            _finding(
                rule_id="IOC-RAW-IP",
                title=f"Direcciones IP literales ({len(raw_ips)})",
                severity="low",
                description=(
                    "Conexiones a IPs sin dominio: habitual en C2 y en apps que "
                    "evitan DNS."
                ),
                category="red",
                score=4,
                evidence=raw_ips[:15],
            )
        )

    if urls:
        out.append(
            _finding(
                rule_id="INFO-URLS",
                title=f"URLs embebidas ({len(urls)})",
                severity="info",
                description="Listado informativo de endpoints encontrados en el código.",
                category="red",
                score=0,
                evidence=urls[:30],
            )
        )
    return out


def rule_fraud_keywords(data: RawApkData) -> list[Finding]:
    out: list[Finding] = []
    blob = "\n".join(data.dex_strings).lower()
    for kw, severity in FRAUD_KEYWORDS.items():
        if kw in blob:
            score = {"critical": 20, "high": 10, "medium": 5, "low": 2}[severity]
            out.append(
                _finding(
                    rule_id=f"KW-{re.sub(r'[^A-Za-z0-9]+', '-', kw).upper()}",
                    title=f"Indicador textual: «{kw}»",
                    severity=severity,
                    description="Cadena asociada a comportamientos sensibles o de evasión.",
                    category="strings",
                    score=score,
                    evidence=[kw],
                )
            )
    return out


def rule_anti_analysis(data: RawApkData) -> list[Finding]:
    out: list[Finding] = []
    blob = "\n".join(data.dex_strings).lower()
    checks = {
        "isdebuggerconnected": ("Detección de depurador", "high", 12),
        "frida": ("Detección de Frida", "high", 12),
        "xposed": ("Detección de Xposed", "high", 12),
        "ro.debuggable": ("Comprobación de build depurable", "medium", 6),
        "ro.kernel.qemu": ("Detección de emulador (QEMU)", "medium", 6),
        "goldfish": ("Detección de emulador (goldfish)", "medium", 6),
        "genymotion": ("Detección de emulador (Genymotion)", "medium", 6),
    }
    for needle, (label, severity, score) in checks.items():
        if needle in blob:
            out.append(
                _finding(
                    rule_id=f"ANTI-{re.sub(r'[^A-Za-z0-9]+', '-', needle).upper()}",
                    title=label,
                    severity=severity,
                    description=(
                        "La app intenta detectar entornos de análisis. Es una "
                        "técnica de evasión típica de malware."
                    ),
                    category="evasión",
                    score=score,
                    evidence=[needle],
                )
            )
    return out


def rule_dex_size(data: RawApkData) -> list[Finding]:
    if data.dex_count <= 1:
        return []
    return [
        _finding(
            rule_id="DEX-MULTI",
            title=f"APK multidex ({data.dex_count} archivos DEX)",
            severity="info",
            description=(
                "Varios DEX en el APK. Normal en apps grandes, pero también usado "
                "para esconder código en DEX secundarios."
            ),
            category="código",
            score=1,
            evidence=[f"{data.dex_count} DEX, {data.total_dex_size} bytes"],
        )
    ]


RULES: list[Rule] = [
    rule_critical_permissions,
    rule_dangerous_permission_count,
    rule_exported_components,
    rule_debuggable,
    rule_backup,
    rule_cleartext,
    rule_signature,
    rule_suspicious_apis,
    rule_packers,
    rule_obfuscation,
    rule_native_libs,
    rule_network_iocs,
    rule_fraud_keywords,
    rule_anti_analysis,
    rule_dex_size,
]


def run_rules(data: RawApkData) -> list[Finding]:
    findings: list[Finding] = []
    for rule in RULES:
        try:
            findings.extend(rule(data))
        except Exception as exc:  # noqa: BLE001 - una regla rota no debe tumbar el análisis
            data.errors.append(f"Regla {rule.__name__} falló: {exc}")
    return findings

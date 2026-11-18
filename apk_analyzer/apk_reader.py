"""Lectura y extracción de datos de un APK.

Usa androguard para parsear el manifiesto binario, los DEX y el
certificado de firma. Todo el trabajo es estático: el APK nunca se
ejecuta ni se instala.
"""

from __future__ import annotations

import hashlib
import os
import zipfile
from dataclasses import dataclass, field
from typing import Any

from .models import AppInfo, SignatureInfo

# Permisos de Android que se consideran peligrosos (grupo "dangerous"
# de la plataforma) más algunos de alto impacto usados por malware.
DANGEROUS_PERMISSIONS = {
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_MMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.CALL_PHONE",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.BODY_SENSORS",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.REQUEST_DELETE_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
    "android.permission.BIND_VPN_SERVICE",
    "android.permission.BIND_INPUT_METHOD",
    "android.permission.WRITE_SETTINGS",
    "android.permission.WRITE_SECURE_SETTINGS",
    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
    "android.permission.REBOOT",
    "android.permission.DISABLE_KEYGUARD",
    "android.permission.EXPAND_STATUS_BAR",
    "android.permission.KILL_BACKGROUND_PROCESSES",
    "android.permission.GET_TASKS",
    "android.permission.READ_LOGS",
    "android.permission.DUMP",
    "android.permission.CAPTURE_AUDIO_OUTPUT",
    "android.permission.CAPTURE_VIDEO_OUTPUT",
    "android.permission.MODIFY_AUDIO_SETTINGS",
    "android.permission.CHANGE_WIFI_STATE",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.INTERNET",
}


@dataclass
class RawApkData:
    """Datos crudos extraídos del APK, antes de aplicar reglas."""

    app: AppInfo = field(default_factory=AppInfo)
    signature: SignatureInfo = field(default_factory=SignatureInfo)
    dex_strings: list[str] = field(default_factory=list)
    dex_classes: list[str] = field(default_factory=list)
    dex_methods: list[str] = field(default_factory=list)
    native_libs: list[str] = field(default_factory=list)
    assets: list[str] = field(default_factory=list)
    entries: list[str] = field(default_factory=list)
    dex_count: int = 0
    total_dex_size: int = 0
    has_obfuscation_hint: bool = False
    errors: list[str] = field(default_factory=list)


def file_hashes(path: str) -> tuple[str, str]:
    """Devuelve (sha256, md5) del archivo."""
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            sha256.update(chunk)
            md5.update(chunk)
    return sha256.hexdigest(), md5.hexdigest()


def _is_apk(path: str) -> bool:
    return zipfile.is_zipfile(path)


ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


COMPONENT_TAGS = {"activity", "activity-alias", "service", "receiver", "provider"}


def _read_manifest_xml(apk, app: AppInfo) -> None:
    """Recorre el manifiesto binario para flags y componentes exportados.

    Se usa el parser de eventos de androguard (AXMLParser) en lugar de
    convertirlo a XML: es más robusto y no depende de lxml.
    """
    from androguard.core.axml import AXMLParser, START_TAG, END_TAG

    raw = apk.get_file("AndroidManifest.xml")
    if not raw:
        raise ValueError("AndroidManifest.xml no encontrado en el APK")

    # Algunos APKs de prueba traen el manifiesto como XML de texto plano.
    if raw.lstrip().startswith(b"<"):
        _read_plain_xml_manifest(raw, app)
        return

    parser = AXMLParser(raw)

    exported: list[str] = []
    current: dict | None = None  # componente en curso
    in_application = False

    while parser.is_valid():
        event = parser.next()
        if event is None:
            break
        if event == START_TAG:
            tag = parser.getName()
            attrs = {}
            for i in range(parser.getAttributeCount()):
                attrs[parser.getAttributeName(i)] = parser.getAttributeValue(i)

            if tag == "application":
                in_application = True
                app.debuggable = str(attrs.get("debuggable", "")).lower() == "true"
                app.allow_backup = str(attrs.get("allowBackup", "")).lower() == "true"
                app.network_security_config = attrs.get("networkSecurityConfig", "") or ""
                app.uses_cleartext = str(attrs.get("usesCleartextTraffic", "")).lower() == "true"
            elif tag in COMPONENT_TAGS and in_application:
                current = {"tag": tag, "name": attrs.get("name", ""),
                           "exported": str(attrs.get("exported", "")).lower(),
                           "filter": False}
            elif tag == "intent-filter" and current is not None:
                current["filter"] = True
        elif event == END_TAG:
            tag = parser.getName()
            if tag in COMPONENT_TAGS and current is not None:
                name = current["name"]
                if name and (current["exported"] == "true"
                             or (current["exported"] == "" and current["filter"])):
                    exported.append(f"{current['tag']}:{name}")
                current = None
            elif tag == "application":
                in_application = False

    app.exported_components = sorted(set(exported))


def _fill_from_raw_manifest(apk, app: AppInfo) -> None:
    """Completa package/permisos/componentes leyendo el manifiesto en crudo."""
    import xml.etree.ElementTree as ET

    raw = apk.get_file("AndroidManifest.xml")
    if not raw:
        return

    if raw.lstrip().startswith(b"<"):
        root = ET.fromstring(raw)
        app.package = app.package or root.get("package", "")
        app.permissions = app.permissions or sorted({
            e.get(f"{ANDROID_NS}name", "") for e in root.iter("uses-permission")
        } - {""})
        app.activities = app.activities or sorted({
            e.get(f"{ANDROID_NS}name", "") for e in root.iter("activity")
        } - {""})
        app.services = app.services or sorted({
            e.get(f"{ANDROID_NS}name", "") for e in root.iter("service")
        } - {""})
        app.receivers = app.receivers or sorted({
            e.get(f"{ANDROID_NS}name", "") for e in root.iter("receiver")
        } - {""})
        app.providers = app.providers or sorted({
            e.get(f"{ANDROID_NS}name", "") for e in root.iter("provider")
        } - {""})
        return

    from androguard.core.axml import AXMLParser, START_TAG

    parser = AXMLParser(raw)
    while parser.is_valid():
        event = parser.next()
        if event is None:
            break
        if event != START_TAG:
            continue
        tag = parser.getName()
        attrs = {parser.getAttributeName(i): parser.getAttributeValue(i)
                 for i in range(parser.getAttributeCount())}
        if tag == "manifest":
            app.package = app.package or attrs.get("package", "")
        elif tag == "uses-permission":
            name = attrs.get("name")
            if name and name not in app.permissions:
                app.permissions.append(name)
        elif tag in COMPONENT_TAGS:
            name = attrs.get("name")
            if not name:
                continue
            bucket = {
                "activity": app.activities,
                "activity-alias": app.activities,
                "service": app.services,
                "receiver": app.receivers,
                "provider": app.providers,
            }[tag]
            if name not in bucket:
                bucket.append(name)
    app.permissions.sort()


def _read_plain_xml_manifest(raw: bytes, app: AppInfo) -> None:
    """Fallback para manifiestos en XML de texto (no binario)."""
    import xml.etree.ElementTree as ET

    root = ET.fromstring(raw)
    application = root.find("application")
    if application is not None:
        app.debuggable = str(application.get(f"{ANDROID_NS}debuggable", "")).lower() == "true"
        app.allow_backup = str(application.get(f"{ANDROID_NS}allowBackup", "")).lower() == "true"
        app.network_security_config = application.get(f"{ANDROID_NS}networkSecurityConfig", "") or ""
        app.uses_cleartext = str(application.get(f"{ANDROID_NS}usesCleartextTraffic", "")).lower() == "true"

    exported: list[str] = []
    for tag in COMPONENT_TAGS:
        for element in root.iter(tag):
            name = element.get(f"{ANDROID_NS}name")
            if not name:
                continue
            flag = str(element.get(f"{ANDROID_NS}exported", "")).lower()
            has_filter = element.find("intent-filter") is not None
            if flag == "true" or (flag == "" and has_filter):
                exported.append(f"{tag}:{name}")
    app.exported_components = sorted(set(exported))


def _read_manifest(apk_path: str, data: RawApkData) -> None:
    """Extrae la información del AndroidManifest.xml."""
    try:
        from androguard.core.apk import APK
    except ImportError:  # androguard < 4
        from androguard.core.bytecodes.apk import APK  # type: ignore

    apk = APK(apk_path)
    app = data.app

    # Cada getter de androguard puede lanzar excepciones con manifiestos
    # raros o dañados: se aíslan para no perder el resto del análisis.
    def safe(fn, default=""):
        try:
            value = fn()
            return value if value is not None else default
        except Exception:  # noqa: BLE001
            return default

    app.package = safe(apk.get_package)
    app.app_name = safe(apk.get_app_name)
    app.version_name = safe(apk.get_androidversion_name)
    app.version_code = safe(apk.get_androidversion_code)
    app.min_sdk = safe(apk.get_min_sdk_version)
    app.target_sdk = safe(apk.get_target_sdk_version)
    app.main_activity = safe(apk.get_main_activity)

    app.permissions = sorted(set(safe(apk.get_permissions, [])))
    app.activities = sorted(set(safe(apk.get_activities, [])))
    app.services = sorted(set(safe(apk.get_services, [])))
    app.receivers = sorted(set(safe(apk.get_receivers, [])))
    app.providers = sorted(set(safe(apk.get_providers, [])))

    # Si androguard no pudo parsear el manifiesto (p. ej. XML de texto),
    # se completan los datos con un parseo directo del archivo.
    if not app.package or not app.permissions:
        try:
            _fill_from_raw_manifest(apk, app)
        except Exception as exc:  # noqa: BLE001
            data.errors.append(f"No se pudo leer el manifiesto en crudo: {exc}")

    # Componentes exportados y flags de <application> (parseo del AXML)
    try:
        _read_manifest_xml(apk, app)
    except Exception as exc:  # noqa: BLE001
        data.errors.append(f"No se pudo parsear el XML del manifiesto: {exc}")

    # Certificado de firma
    try:
        certs = apk.get_certificates()
        if certs:
            cert = certs[0]
            sig = data.signature
            sig.is_signed = True
            sig.scheme = "v1/v2/v3"
            sig.subject = cert.subject.rfc4514_string()
            sig.issuer = cert.issuer.rfc4514_string()
            sig.serial = str(cert.serial_number)
            sig.sha256 = cert.sha256_fingerprint.replace(" ", "").lower()
            sig.valid_from = _cert_date(cert, "not_valid_before")
            sig.valid_to = _cert_date(cert, "not_valid_after")
            sig.is_self_signed = cert.subject == cert.issuer
            sig.is_debug_cert = "Android Debug" in sig.subject
    except Exception as exc:  # noqa: BLE001
        data.errors.append(f"No se pudo leer el certificado de firma: {exc}")


def _cert_date(cert, attr: str) -> str:
    """Fecha del certificado, compatible con cryptography 3.x y 4x."""
    value = getattr(cert, f"{attr}_utc", None) or getattr(cert, attr, None)
    if value is None:
        return ""
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


def _read_dex(apk_path: str, data: RawApkData) -> None:
    """Extrae clases, métodos y strings de todos los DEX."""
    try:
        from androguard.core.dex import DEX
    except ImportError:  # androguard < 4
        from androguard.core.bytecodes.dvm import DalvikVMFormat as DEX  # type: ignore

    strings: set[str] = set()
    classes: set[str] = set()
    methods: set[str] = set()

    with zipfile.ZipFile(apk_path) as zf:
        dex_names = [n for n in zf.namelist() if n.endswith(".dex")]
        data.dex_count = len(dex_names)
        data.total_dex_size = sum(zf.getinfo(n).file_size for n in dex_names)

        for name in dex_names:
            try:
                dex = DEX(zf.read(name))
            except Exception as exc:  # noqa: BLE001
                data.errors.append(f"No se pudo parsear {name}: {exc}")
                continue

            try:
                strings.update(dex.get_strings())
            except Exception:  # noqa: BLE001
                pass

            try:
                classes.update(dex.get_classes_names())
            except Exception:  # noqa: BLE001
                pass

            try:
                for method in dex.get_methods():
                    methods.add(method.get_name())
            except Exception:  # noqa: BLE001
                pass

    data.dex_strings = sorted(strings)
    data.dex_classes = sorted(classes)
    data.dex_methods = sorted(methods)


def _read_zip_entries(apk_path: str, data: RawApkData) -> None:
    """Lista entradas del ZIP: librerías nativas, assets, etc."""
    with zipfile.ZipFile(apk_path) as zf:
        names = zf.namelist()
    data.entries = names
    data.native_libs = sorted({n for n in names if n.startswith("lib/") and n.endswith(".so")})
    data.assets = sorted({n for n in names if n.startswith("assets/")})


def read_apk(path: str) -> RawApkData:
    """Punto de entrada: lee un APK y devuelve los datos crudos."""
    data = RawApkData()

    if not os.path.isfile(path):
        raise FileNotFoundError(f"No existe el archivo: {path}")
    if not _is_apk(path):
        raise ValueError(f"El archivo no es un APK/ZIP válido: {path}")

    _read_zip_entries(path, data)
    _read_manifest(path, data)
    _read_dex(path, data)

    # Heurística simple de ofuscación: nombres de clase de 1-2 caracteres
    short = [c for c in data.dex_classes if len(c.rsplit("/", 1)[-1].rstrip(";")) <= 2]
    data.has_obfuscation_hint = len(short) > max(50, len(data.dex_classes) * 0.3)

    return data

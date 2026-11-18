"""Consulta de hashes en VirusTotal (API v3).

Solo se envía el hash SHA-256 del archivo, nunca el APK.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from dataclasses import asdict, dataclass, field
from typing import Any

VT_URL = "https://www.virustotal.com/api/v3/files/{sha256}"
CACHE_FILE = os.path.join(os.path.expanduser("~"), ".apk_analyzer", "vt_cache.json")
CACHE_TTL = 24 * 3600
NOT_FOUND_TTL = 3600
MAX_CALLS = 4
PERIOD = 60.0
MAX_RETRIES = 2
TIMEOUT = 20.0
_SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")


@dataclass
class VTResult:
    queried: bool = False
    found: bool = False
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    total_engines: int = 0
    reputation: int = 0
    threat_names: list[str] = field(default_factory=list)
    permalink: str = ""
    error: str = ""

    @property
    def detection_ratio(self) -> str:
        if not self.total_engines:
            return "—"
        return f"{self.malicious}/{self.total_engines}"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["detection_ratio"] = self.detection_ratio
        return data


def _as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _cache_path() -> str:
    return os.environ.get("APK_ANALYZER_CACHE") or CACHE_FILE


def _load_cache() -> dict[str, Any]:
    try:
        with open(_cache_path(), encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_cache(cache: dict[str, Any]) -> None:
    path = _cache_path()
    now = time.time()
    pruned = {
        key: entry for key, entry in cache.items()
        if isinstance(entry, dict) and now - entry.get("ts", 0) < CACHE_TTL
    }
    tmp = path + ".tmp"
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(pruned, fh)
        os.replace(tmp, path)
    except Exception:
        try:
            os.remove(tmp)
        except OSError:
            pass


def _parse(payload: dict[str, Any], sha256: str) -> VTResult:
    attrs = payload.get("data", {}).get("attributes", {}) or {}
    stats = attrs.get("last_analysis_stats", {}) or {}
    results = attrs.get("last_analysis_results", {}) or {}
    names: set[str] = set()
    for engine in results.values():
        name = (engine or {}).get("result")
        if name:
            names.add(name)

    return VTResult(
        queried=True,
        found=True,
        malicious=_as_int(stats.get("malicious")),
        suspicious=_as_int(stats.get("suspicious")),
        harmless=_as_int(stats.get("harmless")),
        undetected=_as_int(stats.get("undetected")),
        total_engines=sum(_as_int(v) for v in stats.values() if isinstance(v, (int, float, str))),
        reputation=_as_int(attrs.get("reputation")),
        threat_names=sorted(names)[:15],
        permalink=f"https://www.virustotal.com/gui/file/{sha256}",
    )


def _request(sha256: str, api_key: str) -> VTResult:
    request = urllib.request.Request(
        VT_URL.format(sha256=sha256),
        headers={"x-apikey": api_key, "Accept": "application/json"},
    )

    for attempt in range(MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
                payload = json.loads(response.read().decode("utf-8"))
            return _parse(payload, sha256)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return VTResult(queried=True, found=False, error="Hash no conocido por VirusTotal")
            if exc.code == 401:
                return VTResult(queried=False, error="Clave de API inválida")
            if exc.code == 429 or 500 <= exc.code < 600:
                if attempt < MAX_RETRIES:
                    delay = 2.0 ** attempt
                    retry_after = exc.headers.get("Retry-After") if exc.headers else None
                    if retry_after and retry_after.isdigit():
                        delay = max(delay, float(retry_after))
                    time.sleep(delay)
                    continue
                if exc.code == 429:
                    return VTResult(queried=False, error="Límite de peticiones alcanzado")
            return VTResult(queried=False, error=f"HTTP {exc.code}")
        except Exception as exc:
            return VTResult(queried=False, error=f"Error de red: {exc}")

    return VTResult(queried=False, error="Error de red: reintentos agotados")


def lookup(sha256: str, api_key: str | None = None, use_cache: bool = True) -> VTResult:
    if not isinstance(sha256, str) or not _SHA256_RE.fullmatch(sha256):
        return VTResult(queried=False, error="Hash SHA-256 inválido")

    api_key = api_key or os.environ.get("VT_API_KEY", "")
    if not api_key:
        return VTResult(queried=False, error="Sin clave de API (VT_API_KEY)")

    sha256 = sha256.lower()
    cache = _load_cache() if use_cache else {}
    entry = cache.get(sha256)
    if entry and isinstance(entry, dict):
        ttl = NOT_FOUND_TTL if entry.get("result", {}).get("found") is False else CACHE_TTL
        if time.time() - entry.get("ts", 0) < ttl:
            try:
                return VTResult(**entry["result"])
            except (TypeError, KeyError):
                pass

    result = _request(sha256, api_key)
    if use_cache and (result.found or result.queried):
        cache[sha256] = {"ts": time.time(), "result": asdict(result)}
        _save_cache(cache)
    return result


class RateLimiter:
    def __init__(self, max_calls: int = MAX_CALLS, period: float = PERIOD) -> None:
        self.max_calls = max_calls
        self.period = period
        self._calls: deque[float] = deque()
        self._lock = threading.Lock()

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            while self._calls and now - self._calls[0] >= self.period:
                self._calls.popleft()
            if len(self._calls) >= self.max_calls:
                time.sleep(self.period - (now - self._calls[0]))
            self._calls.append(time.monotonic())

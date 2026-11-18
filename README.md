# Analizador Estático de APKs

Herramienta **defensiva** de análisis estático de aplicaciones Android.
Inspecciona un `.apk` **sin ejecutarlo ni instalarlo**: lee el manifiesto, los
DEX, los recursos y el certificado de firma, y produce un informe con
indicadores de riesgo.

> No es un antivirus ni sustituye a un sandbox. Es un triaje rápido para
> decidir si un APK merece una revisión más profunda.

## Instalación

```powershell
pip install -r requirements.txt
```

Requiere Python 3.10+ y Java 17 (opcional, solo si quieres usar `apktool` aparte).

## Uso

```powershell
# Análisis en consola
python -m apk_analyzer app.apk

# Varios APKs a la vez + reportes JSON y HTML
python -m apk_analyzer *.apk -o reports

# Mostrar también hallazgos informativos
python -m apk_analyzer app.apk --all

# Para CI: falla (exit 1) si el riesgo es alto o superior
python -m apk_analyzer app.apk --fail-on high
```

| Opción | Descripción |
|---|---|
| `-o, --output DIR` | Guarda `<nombre>.json` y `<nombre>.html` en el directorio |
| `--json FILE` | Ruta concreta para el JSON |
| `--html FILE` | Ruta concreta para el HTML |
| `--all` | Incluye hallazgos informativos en la consola |
| `--no-color` | Sin colores ANSI |
| `--fail-on {low,medium,high,critical}` | Código de salida 1 si se alcanza ese nivel |
| `--vt-key KEY` | Clave de API de VirusTotal (o variable `VT_API_KEY`) |
| `--no-vt` | No consultar VirusTotal aunque haya clave |
| `--summary FILE` | Resumen comparativo HTML de todos los APKs |

Códigos de salida: `0` correcto, `1` umbral de riesgo superado, `2` error.

## VirusTotal (opcional)

Si defines `VT_API_KEY`, se consulta el **hash SHA-256** del APK (nunca el
archivo) y el veredicto se añade como hallazgo puntuable:

| Detecciones | Severidad | Puntos |
|---|---|---|
| ≥ 10 motores | Crítico | 40 |
| 3–9 | Alto | 25 |
| 1–2 | Medio | 12 |
| Solo sospechosos | Bajo | 5 |
| 0 | Informativo | 0 |

```powershell
$env:VT_API_KEY = "tu_clave"
python -m apk_analyzer app.apk
```

Las respuestas se cachean en `~/.apk_analyzer/vt_cache.json` (24 h; 1 h si el
hash aún no se conoce en VirusTotal) y se respeta el límite de la API pública
de 4 peticiones/minuto con una ventana deslizante. Los errores transitorios
(429 y 5xx) se reintentan con backoff. La ruta de la caché se puede cambiar con
la variable `APK_ANALYZER_CACHE`. Sin clave, el análisis funciona igual y la
sección se omite.

## Modo lote

Al pasar varios APKs se muestra una tabla comparativa al final, y con
`--summary` se genera un HTML con KPIs y la tabla ordenada por riesgo:

```powershell
python -m apk_analyzer *.apk -o reports --summary reports\resumen.html
```

## Qué analiza

**Manifiesto**
- Permisos peligrosos y de alto impacto (accesibilidad, admin de dispositivo,
  overlay, SMS, instalación de paquetes, `QUERY_ALL_PACKAGES`…).
- Componentes exportados (`exported=true` o implícito por `intent-filter`).
- `debuggable`, `allowBackup`, `usesCleartextTraffic`, `networkSecurityConfig`.

**Código (DEX)**
- Carga dinámica de código: `DexClassLoader`, `InMemoryDexClassLoader`,
  `PathClassLoader`, `Class.forName`.
- Ejecución de comandos: `Runtime.exec`, `ProcessBuilder`.
- APIs de accesibilidad, admin de dispositivo, `MediaProjection`,
  `PackageInstaller`, `SmsManager`.
- Empaquetadores conocidos (Legu, Jiagu, Bangcle, SecNeo…).
- Heurística de ofuscación por nombres de clase.

**Strings y red**
- URLs, IPs literales, TLDs de bajo coste, `.onion`.
- Tokens de bot de Telegram (C2/exfiltración).
- Palabras clave de fraude y de evasión (`frida`, `xposed`, `isDebuggerConnected`,
  detección de emuladores…).

**Firma**
- Presencia de firma, certificado de debug, autofirmado, huella SHA-256.

## Puntuación de riesgo

Cada hallazgo aporta puntos según su severidad; el total se limita a 100.

| Puntos | Nivel | Veredicto |
|---|---|---|
| 0 | Informativo | Sin indicadores |
| 1–19 | Bajo | Probablemente legítimo |
| 20–44 | Medio | Requiere revisión |
| 45–69 | Alto | Sospechoso |
| 70–100 | Crítico | Muy sospechoso |

## Estructura

```
apk_analyzer/
  apk_reader.py   # parseo del APK: manifiesto, DEX, firma, entradas ZIP
  rules.py        # motor de reglas heurísticas (fácil de ampliar)
  models.py       # modelos de datos y cálculo de riesgo
  analyzer.py     # orquestador
  report.py       # reportes JSON y HTML
  cli.py          # interfaz de línea de comandos
tests/
  make_sample_apk.py   # genera un APK de prueba inofensivo
```

### Añadir una regla

En `rules.py`, escribe una función que reciba `RawApkData` y devuelva
`list[Finding]`, y añádela a `RULES`:

```python
def rule_mi_regla(data: RawApkData) -> list[Finding]:
    if "algo_sospechoso" not in data.dex_strings:
        return []
    return [_finding("MI-001", "Título", "medium", "Descripción",
                     "categoría", score=6, evidence=["algo_sospechoso"])]
```

## Prueba rápida

```powershell
python tests\make_sample_apk.py
python -m apk_analyzer tests\samples\sample_suspicious.apk -o reports
```

## Limitaciones

- Solo análisis estático: no detecta comportamiento en tiempo de ejecución.
- Los APKs empaquetados (packers) solo muestran el stub; el código real se
  carga dinámicamente y no es visible.
- Las heurísticas producen **falsos positivos**: un hallazgo es un indicador
  para revisar, no una prueba de que la app sea maliciosa.
- No sustituye a VirusTotal, un sandbox (Cuckoo/CAPE) ni a un análisis manual
  con `jadx`/`apktool`.

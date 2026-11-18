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
python -m apk_analyzer app.apk
python -m apk_analyzer *.apk -o reports
python -m apk_analyzer app.apk --all
python -m apk_analyzer app.apk --fail-on high
```

## VirusTotal (opcional)

Define `VT_API_KEY` para consultar únicamente el hash SHA-256 del archivo:

```powershell
$env:VT_API_KEY = "tu_clave"
python -m apk_analyzer app.apk
```

Las heurísticas producen falsos positivos: un hallazgo es un indicador para
revisar, no una prueba de que la aplicación sea maliciosa.

## Estructura

- `apk_analyzer/apk_reader.py`: extracción del manifiesto, DEX y firma.
- `apk_analyzer/rules.py`: motor de reglas heurísticas.
- `apk_analyzer/models.py`: modelos y cálculo de riesgo.
- `apk_analyzer/analyzer.py`: orquestador del análisis.
- `apk_analyzer/report.py`: reportes JSON y HTML.
- `apk_analyzer/cli.py`: interfaz de línea de comandos.

## Prueba rápida

```powershell
python tests\make_sample_apk.py
python -m apk_analyzer tests\samples\sample_suspicious.apk -o reports
```

## Limitaciones

- Solo realiza análisis estático.
- Las heurísticas pueden generar falsos positivos.
- No sustituye VirusTotal, un sandbox ni una revisión manual.

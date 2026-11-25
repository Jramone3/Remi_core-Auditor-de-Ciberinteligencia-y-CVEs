# REMI-Lite Audit Portable

Herramienta de auditoría de vulnerabilidades (CVEs) y revisión de paquetes del sistema para entornos Linux (Debian / Ubuntu / Linux Mint), enfocada en reportes estructurados y ejecución ligera.

## Arquitectura real del motor
- **`cve_monitor`**: lee los subsistemas configurados en `config/security_profiles.json`, consulta la API REST v2.0 del NVD (`https://services.nvd.nist.gov/rest/json/cves/2.0`) y almacena los resultados en `feeds/cve_feed_*.json`.
- **`system_checker`**: obtiene el inventario de paquetes instalados mediante `dpkg-query` y cruza los hallazgos contra el último *feed* JSON disponible.
- **`report_generator`**: consolida los hallazgos y genera reportes en `reports/` (JSON / Markdown / HTML) con severidad CVSS y recomendaciones de mitigación. El envío de telemetría externa es opcional y requiere configurar `REMI_TELEMETRY_TOKEN` y `REMI_TELEMETRY_URL` por entorno (nunca en código).

## Descarga e integridad del binario
Los ejecutables compilados (`remi-audit-linux`) y sus *checksums* (`remi-audit-linux.sha256`) se publican en **GitHub Releases** para mantener la rama principal limpia y auditable.

```bash
sha256sum -c remi-audit-linux.sha256
chmod +x remi-audit-linux
./remi-audit-linux
```

## Soporte y licenciamiento

Proyecto: REMI_CORE Ecosystem

Canales de contacto y soporte: consultar la documentación oficial o los canales habilitados del repositorio.

""",
encoding="utf-8"
)
print("README.md formateado correctamente")


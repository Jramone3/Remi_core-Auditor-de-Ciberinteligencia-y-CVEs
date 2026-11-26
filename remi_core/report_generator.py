"""
==============================================================================
Remi_core Auditor de Ciberinteligencia y CVEs
Modulo: report_generator.py (Generador de Informes, Filtrado y Telemetría API)
==============================================================================
"""

import glob
import json
import os
import urllib.error
import urllib.request

from datetime import datetime
from typing import Any

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FEEDS_DIR = os.path.join(BASE_DIR, "feeds")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")


def find_latest_feed() -> str | None:
    pattern = os.path.join(FEEDS_DIR, "cve_feed_*.json")
    files = glob.glob(pattern)
    if not files:
        return None
    return max(files, key=os.path.getmtime)


def send_telemetry_to_suite(report_data: dict[str, Any]) -> bool:
    """Envía el reporte de telemetría a la REMI Enterprise Suite en Render."""
    endpoint = os.environ.get(
        "REMI_TELEMETRY_URL",
        "https://remi-enterprise-suite.onrender.com/api/telemetry",
    )
    api_key = os.environ.get("REMI_TELEMETRY_KEY", "")
    print("[*] Despachando telemetría hacia la REMI Enterprise Suite...")

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    payload = json.dumps(report_data).encode("utf-8")
    req = urllib.request.Request(endpoint, data=payload, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            if response.status == 200:
                print("[+] ¡Telemetría entregada y procesada con éxito por la Suite!")
                return True
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
        print(f"[!] Nota de Red / Envío a Suite: {exc}")
        print("[*] (El reporte local se guardó correctamente de forma autónoma).")
    return False


def generate_summary_report(min_cvss: float = 8.0) -> tuple[str | None, str | None]:
    print("==================================================")
    print("📊 GENERANDO REPORTE EJECUTIVO DE CIBERINTELIGENCIA")
    print("==================================================")

    feed_file = find_latest_feed()
    if not feed_file:
        print("[!] No se encontró feed de vulnerabilidades.")
        return None, None

    with open(feed_file, "r", encoding="utf-8") as f:
        alerts = json.load(f)

    critical_alerts = [a for a in alerts if float(a.get("cvss", 0.0)) >= min_cvss]
    os.makedirs(REPORTS_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_json = os.path.join(REPORTS_DIR, f"audit_report_{timestamp}.json")
    report_md = os.path.join(REPORTS_DIR, f"audit_report_{timestamp}.md")

    report_data = {
        "source": "Remi_core Auditor",
        "node": "ramon-desktop",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_analyzed": len(alerts),
        "critical_high_priority": len(critical_alerts),
        "findings": critical_alerts[:15],
    }

    with open(report_json, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)

    md_lines = [
        "# 🛡️ Reporte de Auditoría de Ciberinteligencia - REMI_CORE\n",
        f"**Fecha:** {report_data['timestamp']}\n\n",
        "### 📈 Resumen General\n",
        f"- **Vulnerabilidades Totales Analizadas:** {report_data['total_analyzed']}\n",
        f"- **Alertas de Alta Prioridad (CVSS >= {min_cvss}):** {report_data['critical_high_priority']}\n\n",
        "### 🚨 Principales Hallazgos Prioritarios\n",
    ]

    for item in critical_alerts[:10]:
        md_lines.append(
            f"#### [{item.get('cve_id', 'UNKNOWN')}] - CVSS: {item.get('cvss', 0.0)} "
            f"({item.get('subsystem', 'general')})\n"
        )
        md_lines.append(f"{item.get('description', '')}\n\n")

    with open(report_md, "w", encoding="utf-8") as f:
        f.writelines(md_lines)

    print(f"[+] Reporte JSON generado: {report_json}")
    print(f"[+] Reporte Markdown generado: {report_md}")
    send_telemetry_to_suite(report_data)
    return report_json, report_md


if __name__ == "__main__":
    generate_summary_report()

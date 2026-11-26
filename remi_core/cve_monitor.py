"""
==============================================================================
Remi_core Auditor de Ciberinteligencia y CVEs
Modulo: cve_monitor.py
==============================================================================
"""

from datetime import datetime
import json
import os
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(BASE_DIR, "config", "security_profiles.json")
FEEDS_DIR = os.path.join(BASE_DIR, "feeds")


def load_profile() -> dict[str, Any]:
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
    return {"monitored_subsystems": ["kernel", "mptcp", "openssl"]}


def fetch_cve_alerts(keyword: str, cvss_min: float = 7.5) -> list[dict[str, Any]]:
    print(f"[*] Escaneando vulnerabilidades criticas para subsistema: {keyword}...")
    encoded_kw = urllib.parse.quote(keyword)
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encoded_kw}"
    req = urllib.request.Request(url, headers={"User-Agent": "RemiCoreAuditor/1.0"})
    alerts: list[dict[str, Any]] = []

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status == 200:
                data = json.loads(response.read().decode("utf-8"))
                vulnerabilities = data.get("vulnerabilities", [])
                for item in vulnerabilities:
                    cve_data = item.get("cve", {})
                    cve_id = cve_data.get("id", "UNKNOWN")
                    metrics = cve_data.get("metrics", {})
                    cvss_score = 0.0
                    if metrics.get("cvssMetricV31"):
                        cvss_score = float(metrics["cvssMetricV31"][0]["cvssData"]["baseScore"])
                    elif metrics.get("cvssMetricV30"):
                        cvss_score = float(metrics["cvssMetricV30"][0]["cvssData"]["baseScore"])

                    if cvss_score >= cvss_min:
                        descriptions = cve_data.get("descriptions", [])
                        desc_text = (
                            descriptions[0].get("value", "Sin descripcion disponible.")
                            if descriptions
                            else "Sin descripcion disponible."
                        )
                        alerts.append(
                            {
                                "cve_id": cve_id,
                                "cvss": cvss_score,
                                "subsystem": keyword,
                                "description": f"{desc_text[:200]}...",
                            }
                        )
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError, IndexError, OSError) as exc:
        print(f"[!] Error al consultar NVD para {keyword}: {exc}")

    return alerts


def run_cve_scan() -> str:
    profile = load_profile()
    subsystems = profile.get("monitored_subsystems", [])
    all_findings: list[dict[str, Any]] = []

    print("==================================================")
    print(f"🛡️  EJECUTANDO AUDITORIA DE CVEs: REMI_CORE ({datetime.now().strftime('%Y-%m-%d %H:%M')})")
    print("==================================================")

    for sub in subsystems:
        findings = fetch_cve_alerts(sub)
        all_findings.extend(findings)

    os.makedirs(FEEDS_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(FEEDS_DIR, f"cve_feed_{timestamp}.json")

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(all_findings, f, indent=2)

    print("==================================================")
    print(f"✅ Escaneo completado. Total de alertas criticas: {len(all_findings)}")
    print(f"📁 Reporte guardado en: {output_file}")
    print("==================================================")
    return output_file


if __name__ == "__main__":
    run_cve_scan()

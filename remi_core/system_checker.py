"""
==============================================================================
Remi_core Auditor de Ciberinteligencia y CVEs
Modulo: system_checker.py (Verificador Local de Paquetes y Versiones)
==============================================================================
"""

import glob
import json
import os
import subprocess
from typing import Any

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FEEDS_DIR = os.path.join(BASE_DIR, "feeds")


def get_installed_packages() -> dict[str, str]:
    """Obtiene la lista de paquetes instalados en el sistema Debian/Ubuntu/Mint."""
    print("[*] Leyendo inventario de paquetes instalados en el sistema local...")
    installed: dict[str, str] = {}
    cmd = ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"]
    try:
        output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
        for line in output.splitlines():
            parts = line.strip().split("\t", 1)
            if len(parts) == 2:
                installed[parts[0].lower()] = parts[1]
        print(f"[+] Total de paquetes locales indexados: {len(installed)}")
    except Exception as exc:
        print(f"[!] Error al consultar paquetes locales con dpkg: {exc}")
    return installed


def find_latest_feed() -> str | None:
    """Busca el archivo JSON de feed de CVEs más reciente en la carpeta feeds/."""
    pattern = os.path.join(FEEDS_DIR, "cve_feed_*.json")
    files = glob.glob(pattern)
    if not files:
        return None
    return max(files, key=os.path.getmtime)


def audit_local_system() -> list[dict[str, Any]]:
    print("==================================================")
    print("🛡️  INICIANDO CRUCE LOCAL DE VULNERABILIDADES (AUDIT)")
    print("==================================================")

    installed_pkgs = get_installed_packages()
    feed_file = find_latest_feed()
    if not feed_file:
        print("[!] No se encontró ningún archivo de feed de CVEs. Ejecute primero cve_monitor.py")
        return []

    print(f"[*] Analizando contra el feed: {feed_file}")
    with open(feed_file, "r", encoding="utf-8") as f:
        cve_alerts = json.load(f)

    matches: list[dict[str, Any]] = []
    for alert in cve_alerts:
        subsys = str(alert.get("subsystem", "")).lower()
        if not subsys:
            continue
        for pkg_name, pkg_version in installed_pkgs.items():
            if subsys == pkg_name or subsys in pkg_name:
                matches.append(
                    {
                        "package": pkg_name,
                        "installed_version": pkg_version,
                        "cve_id": alert.get("cve_id", "UNKNOWN"),
                        "cvss": alert.get("cvss", 0.0),
                        "description": alert.get("description", ""),
                    }
                )

    print("✅ Auditoría local finalizada.")
    print(f"🔍 Coincidencias encontradas con paquetes del sistema: {len(matches)}")
    if matches:
        print("\n[!] Alertas preliminares asociadas a componentes locales:")
        for m in matches[:5]:
            print(
                f" - Paquete: {m['package']} ({m['installed_version']}) "
                f"| CVE: {m['cve_id']} (CVSS: {m['cvss']})"
            )
    else:
        print("[+] Ninguna coincidencia directa crítica detectada en los paquetes analizados del sistema.")

    return matches


if __name__ == "__main__":
    audit_local_system()

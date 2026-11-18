#!/usr/bin/env python3
"""Detecta versiones de software instalado y las registra en el inventario.

El inventario tecnologico solo sirve para descartar avisos si tiene la version
instalada de cada producto. Rellenarlo a mano para 68 tecnologias es tedioso, y
este script automatiza la parte que se puede automatizar.

Modos de uso:

  1. En ESTE servidor, actualizando el inventario directamente:
       bin/detectar_versiones.py --aplicar

  2. En OTRO servidor de la organizacion, generando un CSV que luego se importa
     desde la interfaz (Inventario -> Importar CSV):
       bin/detectar_versiones.py --csv inventario_host2.csv

  3. Solo ver que detecta, sin escribir nada:
       bin/detectar_versiones.py

La deteccion es conservadora: si no puede determinar una version con certeza,
no la registra. Una version equivocada en el inventario es peor que ninguna,
porque haria que el sistema descartase avisos que si aplican.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import csv
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threatintel import db                                  # noqa: E402
from threatintel.logging_setup import get_logger, setup      # noqa: E402


def _ejecutar(orden: list[str], timeout: int = 8) -> str:
    """Ejecuta una orden y devuelve su salida combinada, o cadena vacia."""
    try:
        proceso = subprocess.run(orden, capture_output=True, timeout=timeout,
                                 text=True, check=False)
        return (proceso.stdout or "") + (proceso.stderr or "")
    except (OSError, subprocess.SubprocessError):
        return ""


def _primera(patron: str, texto: str) -> Optional[str]:
    coincidencia = re.search(patron, texto)
    return coincidencia.group(1) if coincidencia else None


def _dpkg(paquete: str) -> Optional[str]:
    """Version de un paquete Debian/Ubuntu, limpia de epoch y sufijo."""
    salida = _ejecutar(["dpkg-query", "-W", "-f=${Version}", paquete])
    if not salida or "no packages" in salida.lower():
        return None
    version = salida.strip()
    if not version:
        return None
    version = re.sub(r"^\d+:", "", version)          # epoch
    version = re.split(r"[-+~]", version)[0]          # sufijo de distribucion
    return version or None


def _rpm(paquete: str) -> Optional[str]:
    salida = _ejecutar(["rpm", "-q", "--qf", "%{VERSION}", paquete])
    return salida.strip() or None if salida and "not installed" not in salida else None


def _paquete(*nombres: str) -> Optional[str]:
    """Prueba varios nombres de paquete en dpkg y despues en rpm."""
    for nombre in nombres:
        version = _dpkg(nombre)
        if version:
            return version
    for nombre in nombres:
        version = _rpm(nombre)
        if version:
            return version
    return None


# --------------------------------------------------------------------------
# Detectores
# --------------------------------------------------------------------------
def _sistema_operativo() -> tuple[Optional[str], Optional[str]]:
    """Devuelve (slug, version) del sistema operativo."""
    try:
        datos = {}
        for linea in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" in linea:
                clave, _, valor = linea.partition("=")
                datos[clave] = valor.strip().strip('"')
        identificador = (datos.get("ID") or "").lower()
        version = datos.get("VERSION_ID")
        mapa = {"ubuntu": "ubuntu", "debian": "debian", "rhel": "redhat",
                "centos": "centos", "rocky": "rocky-linux",
                "almalinux": "almalinux", "sles": "suse", "opensuse": "suse",
                "fedora": "fedora"}
        if identificador in mapa and version:
            return mapa[identificador], version
    except OSError:
        pass

    if platform.system() == "Windows":
        return "windows", platform.release()
    return None, None


DETECTORES: dict[str, Callable[[], Optional[str]]] = {
    # --- servidores web y aplicaciones ---
    "apache-httpd": lambda: (
        _primera(r"Apache/(\d+\.\d+\.\d+)", _ejecutar(["apache2", "-v"]))
        or _primera(r"Apache/(\d+\.\d+\.\d+)", _ejecutar(["httpd", "-v"]))
        or _paquete("apache2", "httpd")),
    "nginx": lambda: (
        _primera(r"nginx/(\d+\.\d+\.\d+)", _ejecutar(["nginx", "-v"]))
        or _paquete("nginx", "nginx-core")),
    "tomcat": lambda: _paquete("tomcat9", "tomcat10", "tomcat8"),

    # --- bases de datos ---
    "postgresql": lambda: (
        _primera(r"psql \(PostgreSQL\) (\d+\.\d+)", _ejecutar(["psql", "--version"]))
        or _primera(r"(\d+\.\d+)", _ejecutar(["postgres", "--version"]))
        or _paquete("postgresql")),
    "mysql": lambda: (
        _primera(r"Ver (\d+\.\d+\.\d+)", _ejecutar(["mysql", "--version"]))
        or _paquete("mysql-server")),
    "mariadb": lambda: (
        _primera(r"(\d+\.\d+\.\d+)-MariaDB", _ejecutar(["mariadb", "--version"]))
        or _primera(r"(\d+\.\d+\.\d+)-MariaDB", _ejecutar(["mysql", "--version"]))
        or _paquete("mariadb-server")),
    "mongodb": lambda: _primera(
        r"db version v(\d+\.\d+\.\d+)", _ejecutar(["mongod", "--version"])),
    "sqlite": lambda: (
        _primera(r"^(\d+\.\d+\.\d+)", _ejecutar(["sqlite3", "--version"]))
        or _paquete("sqlite3")),
    "redis": lambda: _primera(
        r"v=(\d+\.\d+\.\d+)", _ejecutar(["redis-server", "--version"])),

    # --- lenguajes y plataformas ---
    "php": lambda: (
        _primera(r"PHP (\d+\.\d+\.\d+)", _ejecutar(["php", "-v"]))
        or _paquete("php", "php8.1", "php8.2", "php7.4")),
    "java": lambda: (
        _primera(r'version "?(\d+\.\d+\.\d+)', _ejecutar(["java", "-version"]))
        or _primera(r'version "?(\d+)', _ejecutar(["java", "-version"]))
        or _paquete("openjdk-17-jre-headless", "openjdk-11-jre-headless",
                    "default-jre")),
    "python": lambda: _primera(r"Python (\d+\.\d+\.\d+)",
                               _ejecutar(["python3", "--version"])),
    "nodejs": lambda: _primera(r"v(\d+\.\d+\.\d+)", _ejecutar(["node", "--version"])),

    # --- criptografia y acceso remoto ---
    "openssl": lambda: (
        _primera(r"OpenSSL (\d+\.\d+\.\d+)", _ejecutar(["openssl", "version"]))
        or _paquete("openssl", "libssl3")),
    "openssh": lambda: (
        _primera(r"OpenSSH_(\d+\.\d+)", _ejecutar(["ssh", "-V"]))
        or _paquete("openssh-server", "openssh-client")),

    # --- contenedores y virtualizacion ---
    "docker": lambda: (
        _primera(r"version (\d+\.\d+\.\d+)", _ejecutar(["docker", "--version"]))
        or _paquete("docker-ce", "docker.io")),
    "proxmox": lambda: _primera(r"pve-manager/(\d+\.\d+)",
                                _ejecutar(["pveversion"])),

    # --- desarrollo ---
    "git": lambda: (
        _primera(r"git version (\d+\.\d+\.\d+)", _ejecutar(["git", "--version"]))
        or _paquete("git")),
    "subversion": lambda: _primera(
        r"(\d+\.\d+\.\d+)", _ejecutar(["svn", "--version", "--quiet"])),

    # --- comunicaciones ---
    "asterisk": lambda: _primera(r"Asterisk (\d+\.\d+\.\d+)",
                                 _ejecutar(["asterisk", "-V"])),

    # --- monitorizacion y seguridad ---
    "wazuh": lambda: (
        _primera(r"v(\d+\.\d+\.\d+)",
                 _ejecutar(["/var/ossec/bin/wazuh-control", "info"]))
        or _paquete("wazuh-agent", "wazuh-manager")),
    "zabbix": lambda: _paquete("zabbix-agent", "zabbix-agent2", "zabbix-server-pgsql"),

    # --- escritorio (util en estaciones) ---
    "libreoffice": lambda: _primera(
        r"LibreOffice (\d+\.\d+\.\d+)", _ejecutar(["libreoffice", "--version"])),
    "firefox": lambda: _primera(
        r"Mozilla Firefox (\d+\.\d+)", _ejecutar(["firefox", "--version"])),
    "chrome": lambda: _primera(
        r"Google Chrome (\d+\.\d+\.\d+)",
        _ejecutar(["google-chrome", "--version"])),
    "7-zip": lambda: _paquete("p7zip-full", "p7zip"),
    "keepass": lambda: _paquete("keepassxc", "keepass2"),
}


def detectar() -> dict[str, str]:
    """Devuelve {slug: version} de lo que se ha podido determinar."""
    encontrado: dict[str, str] = {}

    slug_so, version_so = _sistema_operativo()
    if slug_so and version_so:
        encontrado[slug_so] = version_so
        if slug_so in ("ubuntu", "debian", "redhat", "centos", "rocky-linux",
                       "almalinux", "suse", "fedora"):
            nucleo = platform.release().split("-")[0]
            if re.match(r"^\d+\.\d+", nucleo):
                encontrado["linux"] = nucleo

    for slug, detector in DETECTORES.items():
        try:
            version = detector()
        except Exception:  # noqa: BLE001 - un detector roto no debe abortar
            version = None
        if version:
            limpia = re.sub(r"[^0-9.]", "", str(version).strip())
            if re.match(r"^\d+(\.\d+)*$", limpia):
                encontrado[slug] = limpia

    return encontrado


# --------------------------------------------------------------------------
# Aplicacion
# --------------------------------------------------------------------------
def aplicar(conn, detectado: dict[str, str], *,
            sobrescribir: bool = False) -> dict[str, list]:
    """Registra las versiones detectadas en el inventario.

    Solo actualiza tecnologias que YA existen: crear entradas nuevas desde una
    deteccion automatica llenaria el inventario de cosas irrelevantes.
    """
    resultado: dict[str, list] = {"actualizadas": [], "sin_cambio": [],
                                  "no_en_inventario": [], "ya_tenia": []}

    for slug, version in sorted(detectado.items()):
        fila = conn.execute(
            "SELECT id, name, version_installed FROM technologies WHERE slug=?",
            (slug,)).fetchone()

        if fila is None:
            resultado["no_en_inventario"].append((slug, version))
            continue

        actual = (fila["version_installed"] or "").strip()
        if actual == version:
            resultado["sin_cambio"].append((fila["name"], version))
            continue
        if actual and not sobrescribir:
            resultado["ya_tenia"].append((fila["name"], actual, version))
            continue

        conn.execute(
            "UPDATE technologies SET version_installed=?, updated_at=? WHERE id=?",
            (version, db.utcnow(), fila["id"]))
        resultado["actualizadas"].append((fila["name"], actual or "—", version))

    if resultado["actualizadas"]:
        db.audit(conn, "cli", "tecnologia.detectar_versiones", "technologies",
                 None, f"host={platform.node()} "
                       f"actualizadas={len(resultado['actualizadas'])}")
    return resultado


def exportar_csv(detectado: dict[str, str], ruta: Path) -> None:
    """CSV con el formato que espera Inventario -> Importar."""
    with ruta.open("w", encoding="utf-8-sig", newline="") as fichero:
        escritor = csv.writer(fichero, delimiter=";")
        escritor.writerow(["slug", "nombre", "version_instalada", "num_sistemas",
                           "criticidad", "exposicion", "responsable"])
        for slug, version in sorted(detectado.items()):
            escritor.writerow([slug, "", version, "", "", "", platform.node()])


def exportar_paquetes(destino: Path) -> int:
    """Lista de paquetes instalados (dpkg-query en Debian/Ubuntu, rpm en RHEL/SUSE),
    un nombre por linea y ordenada, para `debian_packages_file`. Con varios
    servidores, guarde un fichero por servidor en un mismo directorio y apunte el
    ajuste a ese directorio."""
    salida = _ejecutar(["dpkg-query", "-W", "-f=${Package}\n"])
    if not salida:
        salida = _ejecutar(["rpm", "-qa", "--qf", "%{NAME}\n"])
    nombres = sorted({l.strip().split(":", 1)[0] for l in (salida or "").splitlines() if l.strip()})
    if not nombres:
        print("  No se pudo obtener la lista de paquetes (ni dpkg-query ni rpm respondieron).")
        return 1
    destino.parent.mkdir(parents=True, exist_ok=True)
    import socket
    destino.write_text(f"# paquetes instalados en {socket.gethostname()} · {datetime.now():%Y-%m-%d %H:%M}\n"
                       + "\n".join(nombres) + "\n", encoding="utf-8")
    print(f"  {len(nombres)} paquetes escritos en {destino}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--aplicar", action="store_true",
                        help="registra las versiones en el inventario local")
    parser.add_argument("--sobrescribir", action="store_true",
                        help="sustituye versiones ya registradas")
    parser.add_argument("--csv", metavar="RUTA",
                        help="exporta a CSV para importar desde la interfaz")
    parser.add_argument("--db", default=None)
    parser.add_argument("--paquetes", metavar="RUTA",
                        help="escribe en RUTA la lista de paquetes instalados (dpkg-query o "
                             "rpm), una por línea, para debian_packages_file; no toca la base")
    args = parser.parse_args()

    if args.paquetes:
        return exportar_paquetes(Path(args.paquetes))

    if args.aplicar:
        setup(level="INFO", log_file="deteccion.jsonl", console=False)

    print(f"\n  Equipo: {platform.node()}")
    print(f"  Sistema: {platform.system()} {platform.release()}")
    print("\n  Detectando software instalado...\n")

    detectado = detectar()

    if not detectado:
        print("  No se ha detectado ningun producto con version determinable.\n")
        return 0

    print(f"  {'SLUG':22} VERSION")
    print(f"  {'-' * 40}")
    for slug, version in sorted(detectado.items()):
        print(f"  {slug:22} {version}")
    print(f"\n  Total detectado: {len(detectado)}")

    if args.csv:
        ruta = Path(args.csv)
        exportar_csv(detectado, ruta)
        print(f"\n  CSV escrito: {ruta}")
        print("  Impórtelo en la interfaz: Inventario -> Importar CSV")
        print("  Revise antes las columnas num_sistemas, criticidad y exposicion.\n")
        return 0

    if not args.aplicar:
        print("\n  (solo lectura: use --aplicar para registrarlo en el inventario,")
        print("   o --csv RUTA para generar el fichero de importacion)\n")
        return 0

    db.init_db(args.db)
    with db.session(args.db) as conn:
        resultado = aplicar(conn, detectado, sobrescribir=args.sobrescribir)

    if resultado["actualizadas"]:
        print(f"\n  ACTUALIZADAS ({len(resultado['actualizadas'])}):")
        for nombre, antes, ahora in resultado["actualizadas"]:
            print(f"    {nombre:28} {antes:>12} -> {ahora}")

    if resultado["sin_cambio"]:
        print(f"\n  Ya correctas ({len(resultado['sin_cambio'])}): "
              f"{', '.join(n for n, _ in resultado['sin_cambio'])}")

    if resultado["ya_tenia"]:
        print(f"\n  Con version distinta ya registrada "
              f"({len(resultado['ya_tenia'])}) — use --sobrescribir para cambiarlas:")
        for nombre, actual, detectada in resultado["ya_tenia"]:
            print(f"    {nombre:28} inventario={actual}  detectado={detectada}")

    if resultado["no_en_inventario"]:
        print(f"\n  Detectadas pero NO en el inventario "
              f"({len(resultado['no_en_inventario'])}):")
        for slug, version in resultado["no_en_inventario"]:
            print(f"    {slug:22} {version}")
        print("    Añádalas desde la interfaz si interesa seguirlas.")

    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

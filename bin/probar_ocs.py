#!/usr/bin/env python3
"""Comprueba el acceso de solo lectura a los servidores de OCS Inventory.

Lee las variables OCS_SERVIDORES_* y OCS_EQUIPOS_* de config/credentials.env,
conecta a cada base (MySQL/MariaDB) y muestra: version del servidor, tablas de
inventario detectadas (hardware, softwares o software/software_name/...),
recuento de equipos y una muestra de programas instalados. Sirve para validar
credenciales y para conocer el esquema exacto antes de programar la sincronizacion.

Solo ejecuta consultas SELECT; con --sql permite lanzar una consulta de lectura
concreta (se rechaza cualquier otra sentencia).

Uso:
    bin/probar_ocs.py                       # ambos servidores
    bin/probar_ocs.py --solo servidores     # o --solo equipos
    bin/probar_ocs.py --sql "SELECT NAME, OSNAME, OSVERSION FROM hardware LIMIT 5"
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threatintel import config, db   # noqa: E402

SERVIDORES = {
    "servidores": "OCS_SERVIDORES",
    "equipos": "OCS_EQUIPOS",
}
TABLAS_INTERES = ("hardware", "softwares", "software", "software_name", "software_version",
                  "software_publisher", "accountinfo", "networks", "bios")
_SOLO_LECTURA = re.compile(r"^\s*(SELECT|SHOW|DESCRIBE|EXPLAIN)\b", re.IGNORECASE)


def _conexion(secretos: dict, prefijo: str):
    """Misma conexion de solo lectura que usa la sincronizacion (threatintel.ocs)."""
    from threatintel import ocs
    return ocs.conectar(secretos, prefijo)


def _consulta(conn, sql: str, params=None):
    # Sin parametros se pasa None: con una tupla vacia pymysql interpreta los
    # '%' de un LIKE como marcadores de formato y falla.
    with conn.cursor() as cur:
        cur.execute(sql, params or None)
        return cur.fetchall()


def inspeccionar(conn) -> None:
    version = _consulta(conn, "SELECT VERSION() AS v")[0]["v"]
    print(f"    motor: {version}")
    tablas = {r[list(r)[0]] for r in _consulta(conn, "SHOW TABLES")}
    presentes = [t for t in TABLAS_INTERES if t in tablas]
    print(f"    tablas: {len(tablas)} en total; de interés: {', '.join(presentes) or 'ninguna reconocida'}")

    if "hardware" in tablas:
        n = _consulta(conn, "SELECT COUNT(*) AS n FROM hardware")[0]["n"]
        print(f"    equipos en hardware: {n}")
        for fila in _consulta(conn, "SELECT NAME, OSNAME, OSVERSION, OSCOMMENTS, IPADDR, LASTDATE "
                                    "FROM hardware ORDER BY LASTDATE DESC LIMIT 5"):
            print(f"      {fila['NAME']:<28} {str(fila['OSNAME'])[:34]:<34} {str(fila['OSVERSION'])[:18]:<18} "
                  f"{str(fila['IPADDR'])[:15]:<15} {fila['LASTDATE']}")

    # OCS <= 2.3: tabla plana 'softwares'; OCS >= 2.4: 'software' normalizada
    if "softwares" in tablas:
        n = _consulta(conn, "SELECT COUNT(*) AS n FROM softwares")[0]["n"]
        print(f"    programas (tabla softwares, esquema clásico): {n}")
        for fila in _consulta(conn, "SELECT NAME, VERSION, PUBLISHER, COUNT(*) AS equipos FROM softwares "
                                    "GROUP BY NAME, VERSION, PUBLISHER ORDER BY equipos DESC LIMIT 8"):
            print(f"      {str(fila['NAME'])[:40]:<40} {str(fila['VERSION'])[:20]:<20} "
                  f"{str(fila['PUBLISHER'])[:22]:<22} en {fila['equipos']} equipos")
    if "software" in tablas and "software_name" in tablas:
        n = _consulta(conn, "SELECT COUNT(*) AS n FROM software")[0]["n"]
        print(f"    programas (tabla software, esquema normalizado 2.4+): {n}")
        for fila in _consulta(conn, """
                SELECT sn.NAME AS nombre, sv.VERSION AS version, sp.PUBLISHER AS fabricante,
                       COUNT(DISTINCT s.HARDWARE_ID) AS equipos
                  FROM software s
                  JOIN software_name sn ON sn.ID = s.NAME_ID
             LEFT JOIN software_version sv ON sv.ID = s.VERSION_ID
             LEFT JOIN software_publisher sp ON sp.ID = s.PUBLISHER_ID
              GROUP BY sn.NAME, sv.VERSION, sp.PUBLISHER ORDER BY equipos DESC LIMIT 8"""):
            print(f"      {str(fila['nombre'])[:40]:<40} {str(fila['version'])[:20]:<20} "
                  f"{str(fila['fabricante'])[:22]:<22} en {fila['equipos']} equipos")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--solo", choices=sorted(SERVIDORES), help="probar solo un servidor")
    parser.add_argument("--sql", help="consulta SELECT a ejecutar en lugar de la inspección")
    args = parser.parse_args()

    if args.sql and not _SOLO_LECTURA.match(args.sql):
        print("  Solo se admiten consultas de lectura (SELECT, SHOW, DESCRIBE, EXPLAIN).")
        return 2

    secretos = config.read_secrets()
    fallos = 0
    for nombre, prefijo in SERVIDORES.items():
        if args.solo and args.solo != nombre:
            continue
        print(f"\n  OCS de {nombre} ({secretos.get(f'{prefijo}_HOST') or 'sin host'})")
        conn, detalle = _conexion(secretos, prefijo)
        if conn is None:
            print(f"    NO CONECTA: {detalle}")
            fallos += 1
            continue
        print(f"    conectado como {detalle}")
        try:
            if args.sql:
                filas = _consulta(conn, args.sql)
                print(f"    {len(filas)} fila(s)")
                for fila in filas[:50]:
                    print("      " + " | ".join(f"{k}={str(v)[:40]}" for k, v in fila.items()))
            else:
                inspeccionar(conn)
        except Exception as exc:  # noqa: BLE001
            print(f"    ERROR en la consulta: {type(exc).__name__}: {exc}")
            fallos += 1
        finally:
            conn.close()
    print()
    return 1 if fallos else 0


if __name__ == "__main__":
    raise SystemExit(main())

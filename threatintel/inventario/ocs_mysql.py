"""Lector de inventario desde OCS Inventory (MariaDB/MySQL, solo lectura).

Movido tal cual desde ``threatintel/ocs.py`` (2026-11-15), cuando ese modulo dejo de ser
el unico lector de inventario posible: ``conectar()`` y ``LectorOCS`` no cambiaron de
logica, solo de fichero. ``threatintel/ocs.py`` los reexporta para que el codigo que ya
hacia ``from threatintel import ocs`` y usaba ``ocs.conectar``/``ocs.LectorOCS`` siga
funcionando exactamente igual.

Dos bases de OCS (MariaDB): la de servidores y la de equipos de computo. Las
credenciales viven en ``config/credentials.env`` (``OCS_SERVIDORES_*``/``OCS_EQUIPOS_*``
por defecto, u otro prefijo si ``config/inventarios.yml`` declara mas fuentes
``ocs_mysql``); aqui solo se ejecutan SELECT.
"""
from __future__ import annotations

from typing import Iterator, Optional

from ..logging_setup import get_logger

log = get_logger("inventario.ocs_mysql")


def conectar(secretos: dict, prefijo: str, *, timeout: int = 8):
    """Conexion pymysql de solo lectura. Devuelve (conexion|None, detalle)."""
    import pymysql
    host = (secretos.get(f"{prefijo}_HOST") or "").strip()
    usuario = (secretos.get(f"{prefijo}_USER") or "").strip()
    clave = secretos.get(f"{prefijo}_PASSWORD") or ""
    base = (secretos.get(f"{prefijo}_DB") or "ocsweb").strip()
    puerto = int((secretos.get(f"{prefijo}_PORT") or "3306").strip() or 3306)
    if not host or not usuario or not clave:
        return None, (f"faltan {prefijo}_HOST / {prefijo}_USER / {prefijo}_PASSWORD "
                      f"en config/credentials.env")
    try:
        conn = pymysql.connect(host=host, port=puerto, user=usuario, password=clave, database=base,
                               connect_timeout=timeout, read_timeout=600, charset="utf8mb4",
                               cursorclass=pymysql.cursors.DictCursor)
        return conn, f"{usuario}@{host}:{puerto}/{base}"
    except Exception as exc:  # noqa: BLE001
        return None, f"{type(exc).__name__}: {exc}"


class LectorOCS:
    """Lee hardware y software de una base OCS 2.4+ (tablas normalizadas)."""

    SQL_HARDWARE = ("SELECT ID, DEVICEID, NAME, OSNAME, OSVERSION, OSCOMMENTS, IPADDR, LASTCOME, "
                    "LASTDATE, USERID, ARCH, WORKGROUP, DESCRIPTION FROM hardware")
    SQL_SOFTWARE = ("SELECT s.HARDWARE_ID, n.NAME, v.VERSION, p.PUBLISHER "
                    "FROM software s JOIN software_name n ON n.ID = s.NAME_ID "
                    "LEFT JOIN software_version v ON v.ID = s.VERSION_ID "
                    "LEFT JOIN software_publisher p ON p.ID = s.PUBLISHER_ID "
                    "ORDER BY s.HARDWARE_ID")
    SQL_SOFTWARE_CLASICO = ("SELECT HARDWARE_ID, NAME, VERSION, PUBLISHER FROM softwares "
                            "ORDER BY HARDWARE_ID")

    def __init__(self, conexion):
        self.conexion = conexion

    def hardware(self) -> list[dict]:
        with self.conexion.cursor() as cur:
            cur.execute(self.SQL_HARDWARE)
            return [dict(f) for f in cur.fetchall()]

    def accountinfo(self) -> dict[int, dict]:
        """Campos administrativos de OCS por equipo (TAG = proceso; el resto, entorno)."""
        try:
            with self.conexion.cursor() as cur:
                cur.execute("SELECT * FROM accountinfo")
                return {int(f["HARDWARE_ID"]): dict(f) for f in cur.fetchall() if f.get("HARDWARE_ID") is not None}
        except Exception as exc:  # noqa: BLE001 - la tabla puede no existir en OCS antiguos
            log.warning("no se pudo leer accountinfo", extra={"error": str(exc)})
            return {}

    def software(self) -> Iterator[tuple[int, str, Optional[str], Optional[str]]]:
        import pymysql
        sql = self.SQL_SOFTWARE
        try:
            with self.conexion.cursor() as cur:
                cur.execute("SELECT 1 FROM software LIMIT 1")
        except pymysql.err.ProgrammingError:
            sql = self.SQL_SOFTWARE_CLASICO
        cur = self.conexion.cursor(pymysql.cursors.SSCursor)
        try:
            cur.execute(sql)
            for fila in cur:
                yield int(fila[0]), fila[1], fila[2], fila[3]
        finally:
            cur.close()

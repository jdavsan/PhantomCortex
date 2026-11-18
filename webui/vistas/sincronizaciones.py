"""Consultas a las bases de OCS Inventory: cuándo se ejecutaron y qué leyeron.

El usuario pidió el 2026-09-07 «un módulo en administración que me deje ver las fechas y
horas en las que se ejecutó la consulta a las 2 bases de datos». Todo sale de la tabla
`sync_ocs`, que `threatintel.ocs.sincronizar_origen` rellena en cada ejecución: una fila
por base y por intento, con la hora de inicio, la de fin, el estado, cuántos activos y
programas leyó, cuántos eran nuevos o cambiaron, cuántos ya no aparecen, la duración y el
error si falló.

La página no lanza nada: es de consulta. La sincronización a demanda sigue estando en
Activos, donde ya estaba, y solo para administradores.

El horario programado se lee del crontab del usuario del servicio (`si`), no de una
constante en el código: si alguien cambia la hora en cron, la página lo refleja sin que
haya que tocar nada. Del crontab se extraen únicamente las horas de las órdenes de la
plataforma; el resto del fichero no se muestra.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from flask import Blueprint, g, render_template, request

from threatintel import ocs, programacion
from webui import auth

bp = Blueprint("sincronizaciones", __name__, url_prefix="/sincronizaciones")

#: Filas por página, como en el resto de los listados (el usuario pidió 20).
POR_PAGINA = 20

#: Horas por encima de las cuales el inventario se considera viejo para alertar. La
#: alerta de las 08:00 se apoya en la consulta de las 07:30: media hora de margen.
HORAS_INVENTARIO_VIEJO = 6

ESTADO_ES = {"success": "Correcta", "failed": "Fallida", "running": "En curso"}
ESTADO_INSIGNIA = {"success": "ok", "failed": "critical", "running": "medium"}

def _ahora() -> datetime:
    return datetime.now(timezone.utc)


def _momento(texto: Optional[str]) -> Optional[datetime]:
    if not texto:
        return None
    try:
        return datetime.fromisoformat(str(texto).replace("Z", "+00:00"))
    except ValueError:
        return None


def _fila(cruda: Any) -> dict:
    """Una fila de sync_ocs con lo que la plantilla necesita ya calculado."""
    f = dict(cruda)
    inicio, fin = _momento(f.get("started_at")), _momento(f.get("finished_at"))
    f["origen_es"] = ocs.ORIGEN_PLURAL_ES.get(f["origen"], f["origen"])
    f["estado_es"] = ESTADO_ES.get(f["status"], f["status"])
    f["estado_insignia"] = ESTADO_INSIGNIA.get(f["status"], "neutra")
    f["segundos"] = round((f.get("duracion_ms") or 0) / 1000, 1)
    if f["status"] == "running" and inicio:
        # Una fila «en curso» de hace horas es una ejecución que murió a medias.
        f["segundos"] = round((_ahora() - inicio).total_seconds(), 1)
        f["colgada"] = (_ahora() - inicio) > timedelta(minutes=30)
    else:
        f["colgada"] = False
    f["fin"] = f.get("finished_at")
    return f


def _resumen_por_base(conn) -> list[dict]:
    """La última consulta de cada base, con su antigüedad y su tendencia."""
    salida = []
    for origen in ocs.ORIGENES:
        ultima = conn.execute(
            """SELECT * FROM sync_ocs WHERE origen=? ORDER BY id DESC LIMIT 1""",
            (origen,)).fetchone()
        ultima_ok = conn.execute(
            """SELECT * FROM sync_ocs WHERE origen=? AND status='success'
                ORDER BY id DESC LIMIT 1""", (origen,)).fetchone()
        medias = conn.execute(
            """SELECT AVG(duracion_ms) AS media, COUNT(*) AS n,
                      SUM(status='failed') AS fallidas
                 FROM sync_ocs WHERE origen=? AND started_at > ?""",
            (origen, (_ahora() - timedelta(days=30)).isoformat().replace("+00:00", "Z"))
        ).fetchone()
        datos: dict[str, Any] = {
            "origen": origen,
            "origen_es": ocs.ORIGEN_PLURAL_ES.get(origen, origen),
            "ultima": _fila(ultima) if ultima else None,
            "ultima_ok": _fila(ultima_ok) if ultima_ok else None,
            "media_segundos": round((medias["media"] or 0) / 1000, 1) if medias else 0.0,
            "intentos_30d": int(medias["n"] or 0) if medias else 0,
            "fallidas_30d": int(medias["fallidas"] or 0) if medias else 0,
        }
        momento_ok = _momento(ultima_ok["started_at"]) if ultima_ok else None
        datos["horas"] = (round((_ahora() - momento_ok).total_seconds() / 3600, 1)
                          if momento_ok else None)
        datos["vieja"] = datos["horas"] is None or datos["horas"] > HORAS_INVENTARIO_VIEJO
        salida.append(datos)
    return salida


def _pagina_valida(pagina: Any, total: int) -> tuple[int, int]:
    paginas = max(1, -(-int(total or 0) // POR_PAGINA))
    try:
        pagina = int(pagina)
    except (TypeError, ValueError):
        pagina = 1
    return min(max(pagina, 1), paginas), paginas


@bp.route("/")
@auth.requiere_admin
def lista():
    """Histórico de las consultas a las dos bases de OCS, paginado."""
    origen = request.args.get("origen", "")
    estado = request.args.get("estado", "")
    where, params = [], []
    if origen in ocs.ORIGENES:
        where.append("origen = ?")
        params.append(origen)
    if estado in ESTADO_ES:
        where.append("status = ?")
        params.append(estado)
    clausula = (" WHERE " + " AND ".join(where)) if where else ""

    total = g.db.execute(f"SELECT COUNT(*) FROM sync_ocs{clausula}", params).fetchone()[0]
    pagina, paginas = _pagina_valida(request.args.get("pagina", 1, type=int), total)
    filas = [_fila(r) for r in g.db.execute(
        f"""SELECT * FROM sync_ocs{clausula} ORDER BY started_at DESC, id DESC
             LIMIT ? OFFSET ?""", params + [POR_PAGINA, (pagina - 1) * POR_PAGINA])]

    args = {k: v for k, v in request.args.items()
            if k in ("origen", "estado")}
    return render_template(
        "sincronizaciones.html",
        resumen=_resumen_por_base(g.db), filas=filas, total=total,
        pagina=pagina, paginas=paginas, por_pagina=POR_PAGINA, args=args,
        origen=origen, estado=estado, origenes=ocs.ORIGENES, estados=ESTADO_ES,
        origen_es=ocs.ORIGEN_PLURAL_ES, programado=programacion.guardado(g.db),
        horas_viejo=HORAS_INVENTARIO_VIEJO,
        conexiones=_conexiones(),
        fallidas_total=g.db.execute(
            "SELECT COUNT(*) FROM sync_ocs WHERE status='failed'").fetchone()[0])


def _conexiones() -> list[dict[str, str]]:
    """A qué servidor y base apunta cada origen, SIN la contraseña.

    Se leen los mismos secretos que usa la sincronización, pero solo el servidor, el
    puerto, la base y el usuario: la contraseña no sale nunca de credentials.env."""
    salida = []
    for origen, prefijo in ocs.ORIGENES.items():
        secretos = g.cfg.secrets
        salida.append({
            "origen": origen,
            "origen_es": ocs.ORIGEN_PLURAL_ES.get(origen, origen),
            "servidor": (secretos.get(f"{prefijo}_HOST") or "").strip() or "sin configurar",
            "puerto": (secretos.get(f"{prefijo}_PORT") or "3306").strip(),
            "base": (secretos.get(f"{prefijo}_DB") or "ocsweb").strip(),
            "usuario": (secretos.get(f"{prefijo}_USER") or "").strip() or "sin configurar",
        })
    return salida

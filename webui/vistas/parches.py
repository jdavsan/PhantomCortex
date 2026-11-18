"""Pagina de correcciones pendientes (v7): que vulnerabilidades confirmadas no tienen todavia
version que las corrija, por que, y cuales aparecieron ya.

Solo lectura: el seguimiento lo abren y lo cierran solos ``threatintel.parches.sincronizar`` y
``threatintel.parches.buscar`` en la ejecucion diaria, asi que aqui no hay formularios de
escritura. El filtro va por GET con busqueda en vivo (``data-filtro-vivo``), que vuelve a pedir
la pagina y sustituye el panel del listado. Sin ``style=`` ni ``on*=``: CSP estricta.
"""
from __future__ import annotations

import inspect

from flask import Blueprint, g, render_template, request

from threatintel import parches
from .. import auth

bp = Blueprint("parches", __name__, url_prefix="/parches-pendientes")

# --------------------------------------------------------------------------
# Alcance por tipo de maquina (2026-09-08)
#
# Cada fila de ``parches_pendientes`` es una correccion que falta para (CVE, paquete,
# ecosistema) y sus recuentos de activos son del parque entero. El perfil de Redes solo
# ve servidores y el de Mantenimiento solo equipos de computo, asi que para ellos la
# lista, el total y el resumen se calculan aqui con una condicion mas: que exista al
# menos un activo de su tipo con esa vulnerabilidad confirmada, y los activos se cuentan
# solo de su tipo. ``threatintel.parches`` no acepta todavia un ``origen`` (no pertenece
# a esta vista); estas consultas repiten las suyas con sus mismas constantes y deben
# desaparecer en cuanto lo acepte.
# --------------------------------------------------------------------------
#: Activos del tipo del perfil con la vulnerabilidad de la fila ``p`` confirmada.
#: La severidad baja tampoco cuenta aqui (2026-09-10): sin ese filtro un equipo de computo
#: cuya unica vulnerabilidad de la fila fuera baja sumaba a «activos afectados» de esta
#: pagina y no al mismo indicador del Panel.
_ACTIVOS_DEL_TIPO = ("SELECT ap.activo_id, a.entorno FROM aplicabilidad ap JOIN activos a ON a.id=ap.activo_id "
                     "WHERE ap.cve=p.cve AND ap.paquete=p.paquete "
                     "AND COALESCE(a.ecosistema, a.so_familia, '')=p.ecosistema "
                     "AND ap.veredicto='afectado' AND a.presente=1 AND a.origen=?")
_EXISTE_DEL_TIPO = f"EXISTS ({_ACTIVOS_DEL_TIPO})"
_N_ACTIVOS_TIPO = f"(SELECT COUNT(DISTINCT activo_id) FROM ({_ACTIVOS_DEL_TIPO}))"
_N_EXPUESTOS_TIPO = (f"(SELECT COUNT(DISTINCT activo_id) FROM ({_ACTIVOS_DEL_TIPO}) "
                     f"WHERE entorno IN {parches._ENTORNOS_SQL})")
_CAMPOS_TIPO = f"""p.id, p.cve, p.paquete, p.ecosistema, p.threat_id, p.motivo, p.motivo_detalle,
       p.version_corregida, p.aviso, p.detectado_at, p.encontrado_at,
       {_N_ACTIVOS_TIPO} AS n_activos, {_N_EXPUESTOS_TIPO} AS n_activos_expuestos,
       t.title_es, t.title_en, t.severity, t.in_kev,
       (julianday(COALESCE(p.encontrado_at, 'now')) - julianday(p.detectado_at)) AS dias_crudos"""


def _contar_acotado(conn, origen: str, *, estado: str, q: str) -> int:
    _, condicion, params = parches._condicion(conn, estado, q)
    total = conn.execute(
        f"""SELECT COUNT(*) FROM parches_pendientes p LEFT JOIN threats t ON t.id = p.threat_id
             WHERE {condicion} AND {_EXISTE_DEL_TIPO}""", params + [origen]).fetchone()[0]
    return int(total or 0)


def _listar_acotado(conn, origen: str, *, estado: str, q: str, limite: int,
                    desplazamiento: int) -> list[dict]:
    estado, condicion, params = parches._condicion(conn, estado, q)
    orden = ("n_activos_expuestos DESC, n_activos DESC, p.detectado_at ASC, p.id"
             if estado == "seguimiento" else "p.encontrado_at DESC, n_activos DESC, p.id")
    filas = conn.execute(
        f"""SELECT {_CAMPOS_TIPO}, p.buscado_at, p.intentos, p.avisado_at
              FROM parches_pendientes p LEFT JOIN threats t ON t.id = p.threat_id
             WHERE {condicion} AND {_EXISTE_DEL_TIPO}
             ORDER BY {orden}
             LIMIT ? OFFSET ?""",
        [origen, origen] + params + [origen, int(limite), max(0, int(desplazamiento))]).fetchall()
    # El activo más expuesto de cada espera, igual que en ``parches.listar``: una sola
    # consulta para toda la página (2026-09-10).
    return parches.anotar_activo_mas_expuesto(conn, [parches._fila_es(f) for f in filas])


def _resumen_acotado(conn, origen: str) -> dict:
    """Las mismas claves que ``parches.resumen``, para un tipo de maquina.

    Sin la severidad baja (2026-09-10, ajuste ``ignore_low_severity``), igual que
    ``parches.resumen``: si una de las dos la contara y la otra no, el perfil de Redes y
    el de administracion verian dos cifras distintas de lo mismo."""
    viva = parches._VIVA_SQL + parches._y_sin_bajas(conn)
    viva_ap = parches._y_sin_bajas(conn, aplicabilidad=True)
    base = f"FROM parches_pendientes p WHERE {viva} AND {_EXISTE_DEL_TIPO}"
    # Las mismas tres cifras que ``parches.resumen`` para explicar que es cada fila
    # (2026-09-15): identificadores CVE, paquetes y versiones de sistema distintos.
    catalogo = conn.execute(
        f"""SELECT COUNT(*) AS filas, COUNT(DISTINCT p.cve) AS cve_distintos,
                   COUNT(DISTINCT p.paquete) AS paquetes,
                   COUNT(DISTINCT p.ecosistema) AS ecosistemas
            {base} AND p.encontrado_at IS NULL""", (origen,)).fetchone()
    en_seguimiento = catalogo["filas"]
    por_motivo = {m: 0 for m in parches.MOTIVOS}
    for fila in conn.execute(f"""SELECT p.motivo AS motivo, COUNT(*) AS n {base}
                                    AND p.encontrado_at IS NULL GROUP BY p.motivo""", (origen,)):
        por_motivo[fila["motivo"] if fila["motivo"] in por_motivo else "desconocido"] += int(fila["n"] or 0)
    encontradas_hoy = conn.execute(
        f"""SELECT COUNT(*) {base} AND p.encontrado_at IS NOT NULL
               AND substr(p.encontrado_at,1,10) = substr(?,1,10)""",
        (origen, parches.db.utcnow())).fetchone()[0]
    encontradas_semana = conn.execute(
        f"""SELECT COUNT(*) {base} AND p.encontrado_at IS NOT NULL
               AND julianday('now') - julianday(p.encontrado_at) <= 7""", (origen,)).fetchone()[0]
    encontradas = conn.execute(
        f"SELECT COUNT(*) {base} AND p.encontrado_at IS NOT NULL", (origen,)).fetchone()[0]
    activos = conn.execute(
        f"""SELECT COUNT(DISTINCT ap.activo_id) FROM aplicabilidad ap
              JOIN activos a ON a.id=ap.activo_id
              LEFT JOIN threats t ON t.id=ap.threat_id
             WHERE ap.veredicto=? AND ap.version_corregida IS NULL AND a.presente=1 AND a.origen=?
               AND (t.id IS NULL OR t.estado NOT IN {parches._ESTADOS_CERRADOS_SQL}){viva_ap}""",
        (parches.AFECTADO, origen)).fetchone()[0]
    expuestos = conn.execute(
        f"""SELECT COUNT(DISTINCT ap.activo_id) FROM aplicabilidad ap
              JOIN activos a ON a.id=ap.activo_id
              LEFT JOIN threats t ON t.id=ap.threat_id
             WHERE ap.veredicto=? AND ap.version_corregida IS NULL AND a.presente=1 AND a.origen=?
               AND (t.id IS NULL OR t.estado NOT IN {parches._ESTADOS_CERRADOS_SQL}){viva_ap}
               AND a.entorno IN {parches._ENTORNOS_SQL}""", (parches.AFECTADO, origen)).fetchone()[0]
    antigua = conn.execute(
        f"""SELECT julianday('now') - julianday(MIN(p.detectado_at)) {base}
               AND p.encontrado_at IS NULL""", (origen,)).fetchone()[0]
    espera = conn.execute(
        f"""SELECT AVG(julianday(p.encontrado_at) - julianday(p.detectado_at)) {base}
               AND p.encontrado_at IS NOT NULL""", (origen,)).fetchone()[0]
    ultima = conn.execute(f"SELECT MAX(p.buscado_at) {base}", (origen,)).fetchone()[0]
    return {"en_seguimiento": int(en_seguimiento or 0), "por_motivo": por_motivo,
            "cve_distintos": int(catalogo["cve_distintos"] or 0),
            "paquetes": int(catalogo["paquetes"] or 0),
            "ecosistemas": int(catalogo["ecosistemas"] or 0),
            "encontradas_hoy": int(encontradas_hoy or 0),
            "encontradas_semana": int(encontradas_semana or 0),
            "encontradas": int(encontradas or 0),
            "activos_afectados": int(activos or 0), "activos_expuestos": int(expuestos or 0),
            "mas_antigua_dias": parches._dias(antigua) if antigua is not None else None,
            "espera_media_dias": round(float(espera), 1) if espera is not None else None,
            "espera_media_es": parches._decimal_es(espera) if espera is not None else None,
            "ultima_busqueda_at": ultima, "acotado": origen}

#: Filas por pagina en pantalla (2026-09-07). Antes eran las 500 primeras con un aviso
#: de recorte; ahora es el tamano de la pagina y la lista se recorre con la paginacion.
#: Filas por pagina en los listados largos. El usuario pidio 20 el 2026-09-07
#: («que en cada uno solo muestre de a 20»): una pantalla se recorre de un vistazo.
LIMITE_PAGINA = 20
#: Tope de filas que esta vista lee de una vez MIENTRAS ``parches.listar`` no acepte
#: ``desplazamiento`` (2026-09-07, hallazgo del revisor sobre la pagina de
#: remediacion): sin ese parametro llegar a una pagina profunda obliga a pedir las
#: filas hasta el final de la pagina y recortar en Python, y eso crece con el numero
#: de filas. Hoy el seguimiento tiene 183 filas y el tope no se alcanza nunca; queda
#: como red de seguridad si la lista crece. En cuanto el parametro exista deja de
#: aplicarse solo.
TOPE_SIN_DESPLAZAMIENTO = 5000


def _pagina_valida(pagina, total: int, por_pagina: int) -> tuple[int, int]:
    """(pagina, paginas) con la pagina acotada al rango real (2026-09-07).

    Una pagina fuera de rango no es un error: se atiende con la primera o con la
    ultima, para que un enlace antiguo o un filtro que reduce el total sigan
    devolviendo una pagina util.
    """
    por_pagina = max(1, int(por_pagina or 1))
    paginas = max(1, -(-int(total or 0) // por_pagina))
    try:
        pagina = int(pagina)
    except (TypeError, ValueError):
        pagina = 1
    return min(max(pagina, 1), paginas), paginas


#: Argumentos reservados de ``url_for`` (2026-09-07). Un parametro de la direccion
#: llamado como uno de ellos («?_anchor=x», «?endpoint=x», «?_method=POST») no es un
#: filtro de la pagina: si se reenviara a ``url_for(..., **args)`` la llamada
#: recibiria el mismo argumento dos veces y la pagina responderia con un error 500.
_ARGS_RESERVADOS = ("endpoint", "values")


def _args_a_conservar(*excluir: str) -> dict:
    """Los argumentos de la direccion que se conservan al cambiar de pagina (los
    filtros), sin los ``excluir`` ni los reservados de ``url_for``."""
    return {k: v for k, v in request.args.items()
            if k not in excluir and k not in _ARGS_RESERVADOS and not k.startswith("_")}


def _admite_desplazamiento() -> bool:
    """Si ``parches.listar`` ya acepta ``desplazamiento`` (LIMIT/OFFSET en SQL)."""
    try:
        return "desplazamiento" in inspect.signature(parches.listar).parameters
    except (TypeError, ValueError):
        return False


def _filas_alcanzables(total: int) -> int:
    """Cuantas filas del total se pueden recorrer en pantalla sin leer de una vez mas
    de ``TOPE_SIN_DESPLAZAMIENTO`` (2026-09-07)."""
    if _admite_desplazamiento():
        return total
    return min(total, max(int(TOPE_SIN_DESPLAZAMIENTO), LIMITE_PAGINA))


def _filas_de_la_pagina(*, estado: str, q: str, desplazamiento: int, limite: int) -> list[dict]:
    """Las filas de una pagina del seguimiento, con el filtro ya aplicado.

    ``threatintel.parches.listar`` solo admite ``limite``. Mientras no acepte tambien
    ``desplazamiento`` (una linea en ese modulo, que no pertenece a esta vista), se le
    piden las filas hasta el final de la pagina y se recorta aqui: el resultado es el
    mismo, pero nunca se leen mas de ``TOPE_SIN_DESPLAZAMIENTO`` filas de una vez
    (2026-09-07), para que una pagina profunda no pueda cargar la lista entera en
    memoria. En cuanto el parametro exista se usa sin tocar esta vista ni la plantilla.
    """
    if _admite_desplazamiento():
        return parches.listar(g.db, estado=estado, q=q, limite=limite,
                              desplazamiento=desplazamiento)
    hasta = min(desplazamiento + limite,
                max(int(TOPE_SIN_DESPLAZAMIENTO), LIMITE_PAGINA))
    if hasta <= desplazamiento:
        return []
    return parches.listar(g.db, estado=estado, q=q, limite=hasta)[desplazamiento:]


def _actualizaciones_sin_version(origen: str | None) -> int | None:
    """Cuantas actualizaciones de la pagina de Remediacion no tienen todavia version que
    instalar, o None si esa cifra no se puede obtener.

    Conciliacion pedida en la auditoria de tableros del 2026-09-15: esta pagina dice «191
    correcciones en seguimiento» y Remediacion «1.748 actualizaciones sin version que
    instalar», y las dos cifras convivian sin que nadie dijera que son unidades distintas.
    Son el mismo hecho contado de dos maneras: aqui, una fila por identificador CVE,
    paquete y version del sistema (el catalogo del problema, sea cual sea el numero de
    maquinas); alli, una tarea por activo y origen de paquete (el trabajo que quedaria
    pendiente en cada maquina el dia que la version exista).

    Se pide con ``resumen_memorizado``, que guarda el resultado en ``g`` durante la
    peticion: si la pagina de Remediacion o la de Activos ya lo calcularon, no se repite.
    El alcance por tipo de maquina del perfil se respeta (``origen``). Si el modulo de
    remediacion no esta disponible o cambia de forma, se devuelve None y la pagina escribe
    la conciliacion sin cifra en lugar de caerse.
    """
    try:
        from webui.vistas import remediaciones as vista_remediaciones
        res = vista_remediaciones.resumen_memorizado(
            vista_remediaciones._dias_resumen(), origen or None, solo_cifras=True)
        valor = res.get("actualizaciones_sin_version")
    except Exception:  # noqa: BLE001 - una conciliación nunca puede tumbar la página
        return None
    try:
        return max(0, int(valor))
    except (TypeError, ValueError):
        return None


@bp.route("/")
@auth.requiere_login
def lista():
    """Correcciones pendientes, paginadas en el servidor (2026-09-07).

    El total sale de ``parches.contar`` (un ``COUNT(*)``, no las filas) y la lista se
    recorre por paginas de ``LIMITE_PAGINA`` conservando la lista elegida y el texto
    buscado.
    """
    estado = (request.args.get("estado") or "seguimiento").strip()[:20]
    if estado not in parches.ESTADOS:
        estado = "seguimiento"
    q = (request.args.get("q") or "").strip()[:120]
    origen = auth.alcance_origen()
    if origen:
        # Perfil acotado a un tipo de maquina: lista, total y resumen de su tipo.
        total = _contar_acotado(g.db, origen, estado=estado, q=q)
        pagina, paginas = _pagina_valida(request.args.get("pagina", 1, type=int), total,
                                         LIMITE_PAGINA)
        alcanzables = total
        filas = _listar_acotado(g.db, origen, estado=estado, q=q, limite=LIMITE_PAGINA,
                                desplazamiento=(pagina - 1) * LIMITE_PAGINA)
        resumen = _resumen_acotado(g.db, origen)
    else:
        total = parches.contar(g.db, estado=estado, q=q)
        alcanzables = _filas_alcanzables(total)
        pagina, paginas = _pagina_valida(request.args.get("pagina", 1, type=int), alcanzables,
                                         LIMITE_PAGINA)
        filas = _filas_de_la_pagina(estado=estado, q=q, limite=LIMITE_PAGINA,
                                    desplazamiento=(pagina - 1) * LIMITE_PAGINA)
        resumen = parches.resumen(g.db)
    return render_template("parches_pendientes.html", filas=filas, total=total,
                           limite=LIMITE_PAGINA, por_pagina=LIMITE_PAGINA,
                           pagina=pagina, paginas=paginas, alcanzables=alcanzables,
                           args=_args_a_conservar("pagina"),
                           resumen=resumen, estado=estado,
                           # Conciliación con Remediación (2026-09-15): son unidades distintas
                           # y la página lo dice con las dos cifras delante.
                           actualizaciones_sin_version=_actualizaciones_sin_version(origen),
                           q=q, motivo_es=parches.MOTIVO_ES, motivo_clave=parches.MOTIVO_CLAVE,
                           estado_es=parches.ESTADO_ES)

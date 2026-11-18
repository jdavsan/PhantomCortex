"""Activos de la organizacion (inventario real de OCS Inventory) y aplicabilidad
por activo.

Tres paginas (docs/INVENTARIO_OCS_2026-09-04.md, apartado 3.3):

* **Activos** — lista con busqueda por nombre, IP o sistema, filtros por tipo
  (servidores / equipos), familia de sistema y vista rapida (con vulnerabilidades
  confirmadas, KEV, fuera de soporte, sin reportar, sin agente, software de
  riesgo), metricas, reparto por sistema y tabla paginada.
* **Ficha de activo** — datos de OCS, fin de soporte, hallazgos de politica,
  amenazas que le aplican con veredicto y evidencia, software instalado con su
  tecnologia, y la pregunta «¿Le aplica este CVE?» (POST, responde al momento
  con OSV.dev, VuXML o comparacion de version).
* **Software** — nombres de programa de OCS, cobertura del mapa de nombres,
  reglas OCS -> tecnologia (alta y baja para administradores), propuestas
  automaticas y software sin clasificar por numero de equipos.

Sin ``style=`` ni ``on*=``: CSP estricta; los graficos son SVG del servidor.
"""
from __future__ import annotations

import csv
import io
import json
import re
import subprocess
import sys
from datetime import date, datetime, timedelta, timezone
from typing import Any, Optional

from flask import (abort, Blueprint, Response, current_app, flash, g, jsonify, redirect,
                   render_template, request, url_for)

from threatintel import aplicabilidad, db, excepciones, ocs, openscap, queries, sbom
from threatintel import msrc as _msrc, remediacion as _remediacion  # v6
from threatintel.paths import BASE_DIR, LOGS_DIR
from webui import auth
from webui.filtros import celda_csv, fecha_es
# El resumen de remediacion se pide por el ayudante de la vista de remediaciones, que lo
# memoriza durante la peticion: esta pagina lo pedia otra vez en cada carga y costaba
# 590 ms de los 1.667 medidos (hallazgo MEDIO de la revision del 2026-09-09).
from webui.vistas.remediaciones import (indice_riesgo_aceptado, marcar_riesgo_aceptado,
                                        resumen_memorizado)

bp = Blueprint("activos", __name__, url_prefix="/activos")

#: Filas por pagina en los listados largos. El usuario pidio 20 el 2026-09-07
#: («que en cada uno solo muestre de a 20»): una pantalla se recorre de un vistazo.
POR_PAGINA = 20
VISTAS = ("todos", "afectados", "kev", "fuera_soporte", "sin_reportar", "sin_edr",
          "software_riesgo", "sin_datos_windows", "ausentes")
VISTA_ES = {
    "todos": "Todos", "afectados": "Con vulnerabilidades confirmadas", "kev": "Con explotación activa (KEV)",
    "fuera_soporte": "Fuera de soporte", "sin_reportar": "Sin reportar", "sin_edr": "Sin agente de protección",
    "software_riesgo": "Con software de riesgo",
    # v14 (2026-09-10): la CAUSA de las remediaciones «esperando datos del inventario».
    # Se ofrece como atajo para que Redes llegue a la lista de máquinas
    # que hay que arreglar sin tener que buscarlas una a una.
    # 2026-09-15 (revision de claridad, punto 6): decia «Sin datos suficientes de
    # Windows» y contaba ACTIVOS con el agente de OCS Inventory incompleto (3), mientras
    # la pagina de Remediacion decia «794 vulnerabilidades ... en 1 activo» y contaba
    # FILAS DE REMEDIACION en espera. Eran dos cifras distintas bajo la misma idea; cada
    # rotulo dice ahora que cuenta.
    "sin_datos_windows": "Sin datos de actualizaciones de Windows",
    "ausentes": "Retirados de OCS Inventory",
}
#: Ordenes de la lista. Todos terminan en «a.id» a proposito (2026-09-07): un ORDER BY
#: con empates no define un orden total y SQLite no garantiza el mismo reparto entre dos
#: consultas, asi que con LIMIT/OFFSET una fila podria salir en dos paginas y otra en
#: ninguna. Desempatar por identificador lo cierra sin coste.
ORDENES = {"riesgo": "kev DESC, afectados DESC, a.nombre, a.id", "nombre": "a.nombre, a.id",
           "sistema": "a.so_familia, a.so_ciclo, a.nombre, a.id",
           "conexion": "a.ultimo_inventario DESC, a.id"}
ORDEN_ES = {"riesgo": "Riesgo", "nombre": "Nombre", "sistema": "Sistema", "conexion": "Último inventario"}
#: Regla de color de la sección: los estados (riesgo, soporte) usan los colores semánticos;
#: los repartos por categoría usan la paleta categórica cat-1..cat-8 de la hoja de estilos
#: (colores vivos, un color claramente distinto por categoría y fijo entre visitas);
#: «sin datos» en gris. Familias: Ubuntu naranja, Debian magenta, FreeBSD violeta,
#: Windows cian, CentOS lima, otros dorado.
FAMILIA_CLAVE = {"ubuntu": "cat-3", "debian": "cat-6", "freebsd": "cat-4", "windows": "cat-2",
                 "centos": "cat-5", "otro": "cat-7", "desconocido": "neutro"}
#: Entornos, de más a menos expuesto (orden fijo de la dona): producción azul, contingencia
#: naranja, desarrollo esmeralda, pruebas violeta, soporte magenta; sin entorno, gris. Las
#: insignias .insignia.entorno-* solo distinguen expuesto de no expuesto.
ORDEN_ENTORNOS = ["produccion", "contingencia", "desarrollo", "pruebas", "soporte", "desconocido"]
CLAVE_ENTORNO = {"produccion": "cat-1", "contingencia": "cat-3", "desarrollo": "cat-8",
                 "pruebas": "cat-4", "soporte": "cat-6", "desconocido": "neutro"}
#: Gráfica «Versiones de sistema con más activos»: cada barra (versión) lleva un color
#: categórico distinto y sin repetir, por lo que el tope de barras es el número de colores de
#: la paleta (cat-1..cat-12). El estado de soporte ya no se codifica en color: va escrito en la
#: nota de cada barra. Petición del usuario (2026-09-08): «que se diferencien y no se repitan
#: los colores de solamente esta gráfica».
MAX_VERSIONES_GRAFICA = 12
_RE_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
ESTADOS_ABIERTOS_SQL = "('descartada','falso_positivo','mitigada')"
SOFTWARE_POR_PAGINA = 20


def _escapar_like(texto: str) -> str:
    """El texto buscado con los comodines de ``LIKE`` neutralizados (2026-09-07).

    Hallazgo del revisor: sin ``ESCAPE`` el «%» y el «_» que escribe el operador son
    comodines, asi que buscar «%» devolvia el inventario completo. Se escapan como en
    ``threatintel/remediacion.py`` y ``threatintel/parches.py``: quien escribe «%»
    espera que se busque ese caracter, no la lista entera.
    """
    return str(texto or "").replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _patron_like(texto: str) -> str:
    """El texto buscado convertido en patron «%texto%» ya escapado."""
    return f"%{_escapar_like(texto)}%"


#: Argumentos reservados de ``url_for`` (2026-09-07). Un parametro de la direccion
#: llamado como uno de ellos («?_anchor=x», «?endpoint=x», «?_method=POST») no es un
#: filtro de la pagina: si se reenviara a ``url_for(..., **args)`` la llamada
#: recibiria el mismo argumento dos veces y la pagina responderia con un error 500.
_ARGS_RESERVADOS = ("endpoint", "values")


def _args_a_conservar(*excluir: str) -> dict[str, str]:
    """Los argumentos de la direccion que se conservan en los enlaces de la pagina
    (los filtros y el orden), sin los ``excluir`` ni los reservados de ``url_for``."""
    return {k: v for k, v in request.args.items()
            if k not in excluir and k not in _ARGS_RESERVADOS and not k.startswith("_")}


def _umbral(cfg: Any) -> str:
    return ocs._umbral_sin_reportar(cfg)


def _etiquetar(activo: dict, tabla_eol: dict, umbral: str) -> dict:
    activo["origen_es"] = ocs.ORIGEN_ES.get(activo.get("origen"), activo.get("origen") or "—")
    activo["familia_es"] = ocs.FAMILIA_ES.get(activo.get("so_familia"), activo.get("so_familia") or "—")
    activo["zona_es"] = ocs.ZONA_ES.get(activo.get("zona"), activo.get("zona") or "—")
    activo["entorno_es"] = ocs.ENTORNO_ES.get(activo.get("entorno"), "Sin entorno") if activo.get("entorno") else "Sin entorno"
    activo["expuesto"] = activo.get("entorno") in ocs.ENTORNOS_EXPUESTOS
    activo["soporte"] = aplicabilidad.estado_soporte(tabla_eol, activo)
    ult = activo.get("ultimo_inventario")
    activo["sin_reportar"] = (ult is None) or (ult < umbral)
    # Activo RETIRADO de OCS Inventory (2026-09-15, revision de claridad, punto 1). La
    # ficha decia cuatro cosas incompatibles sobre el mismo activo: «22 vulnerabilidades
    # entran en la cola en la proxima sincronizacion» (no entraran nunca), una tabla con
    # 155 remediaciones ya abiertas en estado «Activo retirado», «0 actualizaciones por
    # aplicar» y «No hay activos con la version vulnerable». Aqui se resuelve de una vez:
    # «retirado» y la FECHA en que se le vio por ultima vez («visto_at» es la ultima
    # sincronizacion que lo encontro en OCS Inventory).
    activo["retirado"] = not activo.get("presente")
    activo["retirado_desde"] = activo.get("visto_at") if activo["retirado"] else None
    # El campo DESCRIPTION del agente UNIX de OCS no es una descripcion: es la
    # arquitectura y el tiempo encendido («x86_64/00-00-17 09:36:09»). Se separa en datos
    # con nombre y deja de leerse como ruido; la arquitectura, que la columna propia trae
    # vacia en los 881 activos, sale de ahi (punto 12 de la misma revision).
    agente = ocs.interpretar_descripcion(activo.get("descripcion"))
    activo["descripcion_es"] = agente["descripcion"]
    activo["encendido_es"] = agente["encendido_es"]
    if not activo.get("arquitectura") and agente["arquitectura"]:
        activo["arquitectura"] = agente["arquitectura"]
        activo["arquitectura_del_agente"] = True
    # Una sola etiqueta de sistema operativo: la ficha escribia «Ubuntu 24.04 24.04.4 LTS
    # Ubuntu 24.04.4 LTS», el mismo sistema tres veces.
    activo["sistema_es"], activo["sistema_detalle_es"] = ocs.etiqueta_sistema(activo)
    # Etiqueta de proceso de negocio mal escrita en OCS Inventory (punto 10): el proceso
    # ya sale normalizado, pero conviene corregirlo en el origen.
    activo["proceso_mal_escrito"] = ocs.etiqueta_mal_escrita(
        activo.get("etiqueta_ocs"), activo.get("proceso"))
    hall = activo.get("hallazgos")
    activo["hallazgos_lista"] = sorted((hall or "").split(",")) if hall else []
    activo["hallazgos_es"] = [ocs.TIPO_HALLAZGO_ES.get(h, h) for h in activo["hallazgos_lista"]]
    return activo


def _hallazgos_detallados(conn, activo_ids: Optional[list[int]] = None) -> dict[int, list[dict]]:
    """{activo_id: [{"tipo", "tipo_es", "detalle", "resumen", "explicacion"}]} de los hallazgos abiertos.

    Con ``activo_ids`` se leen solo los de esos activos (los de la pagina que se pinta,
    2026-09-07): con la paginacion no hay motivo para traerse los hallazgos de los 881.
    """
    salida: dict[int, list[dict]] = {}
    sql = ("SELECT activo_id, tipo, clave, detalle FROM hallazgos_activos "
           "WHERE resuelto_at IS NULL")
    params: list[Any] = []
    if activo_ids is not None:
        if not activo_ids:
            return salida
        sql += f" AND activo_id IN ({','.join('?' * len(activo_ids))})"
        params = [int(i) for i in activo_ids]
    for r in conn.execute(sql + " ORDER BY tipo, clave", params):
        detalle = r["detalle"] or ""
        resumen = detalle.split(":")[0].strip() if r["tipo"] == "software_riesgo" else ""
        salida.setdefault(r["activo_id"], []).append({
            "tipo": r["tipo"], "tipo_es": ocs.TIPO_HALLAZGO_ES.get(r["tipo"], r["tipo"]), "detalle": detalle,
            "resumen": resumen, "explicacion": ocs.TIPO_HALLAZGO_EXPLICACION.get(r["tipo"], "")})
    return salida


def _pagina_valida(pagina: Any, total: int, por_pagina: int) -> tuple[int, int]:
    """(pagina, paginas) con la pagina acotada al rango real (2026-09-07).

    Un numero de pagina fuera de rango no es un error: se atiende con la primera
    o con la ultima pagina, para que un enlace antiguo o un filtro que reduce el
    total sigan devolviendo una pagina util.
    """
    por_pagina = max(1, int(por_pagina or 1))
    paginas = max(1, -(-int(total or 0) // por_pagina))
    try:
        pagina = int(pagina)
    except (TypeError, ValueError):
        pagina = 1
    return min(max(pagina, 1), paginas), paginas


#: La severidad Baja no se reporta (regla interna, ajuste ``ignore_low_severity``). Sin
#: esta condicion la pagina de Activos decia «747 con vulnerabilidades confirmadas»
#: mientras Amenazas, el Panel y el resumen semanal decian 746 sobre el mismo parque, y
#: la tarjeta de Amenazas enlazaba de una cifra a la otra: dos numeros de lo mismo
#: (revision de precision del 2026-09-09). La diferencia eran activos cuyos unicos CVE
#: son de severidad Baja.
_SIN_BAJAS_SQL = "(t.severity IS NULL OR t.severity <> 'Low')"


def _sin_bajas() -> bool:
    """Si la severidad Baja se deja fuera de las cifras de esta pagina."""
    return bool((getattr(g, "cfg", None) or {}).get("ignore_low_severity", True))


def _sin_excepcion() -> str:
    """« AND <condición>» que deja fuera el riesgo aceptado, o cadena vacia (2026-09-10).

    La tarjeta grande «Con vulnerabilidades confirmadas» de esta pagina sale de
    ``ocs.resumen``, que desde el 2026-09-10 (tarde) descuenta las vulnerabilidades
    cubiertas por una excepcion vigente. La columna «Afectados» de la tabla, el atajo
    «Con vulnerabilidades confirmadas» y el orden por riesgo se calculan aqui, asi que
    tienen que descontarlas TAMBIEN: si solo lo hiciera una de las dos mitades, la misma
    pantalla ensenaria dos cifras distintas de lo mismo, que es el defecto que este
    proyecto no admite. Por eso los tres sitios se aplicaron juntos.

    Con cero excepciones vigentes devuelve cadena vacia y las subconsultas quedan
    EXACTAMENTE como estaban (``excepciones.y_sin_excepcion``). La condicion se escribe
    con ``NOT IN`` sobre subconsultas no correlacionadas, que SQLite materializa una sola
    vez por consulta, de modo que no se paga una vez por cada uno de los 918 activos.
    """
    conn = getattr(g, "db", None)
    if conn is None:
        return ""
    return excepciones.y_sin_excepcion(conn, activo="ap.activo_id", cve="ap.cve",
                                       paquete="ap.paquete")


def _subconsultas(sin_bajas: bool = True, sin_excepcion: str = "") -> str:
    """Cifras por activo de la lista y de la ficha: CVE distintos, no filas por paquete.

    ``afectados`` y ``kev`` cuentan CVE distintos porque la unidad es un CVE en un
    activo: un mismo CVE que toca cuatro paquetes del nucleo es UNA vulnerabilidad
    (``queries.VULNERABILIDAD_DISTINTA``, 2026-09-09).

    ``sin_excepcion`` es lo que devuelve :func:`_sin_excepcion`: el riesgo aceptado no
    cuenta, igual que la severidad baja.
    """
    baja = f" AND {_SIN_BAJAS_SQL}" if sin_bajas else ""
    return f"""
    (SELECT COUNT(DISTINCT ap.cve) FROM aplicabilidad ap LEFT JOIN threats t ON t.id=ap.threat_id
      WHERE ap.activo_id=a.id AND ap.veredicto='afectado'
        AND (t.id IS NULL OR t.estado NOT IN {ESTADOS_ABIERTOS_SQL}){baja}{sin_excepcion}) AS afectados,
    (SELECT COUNT(DISTINCT ap.cve) FROM aplicabilidad ap JOIN threats t ON t.id=ap.threat_id
      WHERE ap.activo_id=a.id AND ap.veredicto='afectado' AND t.in_kev=1
        AND t.estado NOT IN {ESTADOS_ABIERTOS_SQL}{baja}{sin_excepcion}) AS kev,
    (SELECT COUNT(*) FROM activo_software s WHERE s.activo_id=a.id AND s.technology_id IS NOT NULL) AS n_mapeado,
    (SELECT GROUP_CONCAT(DISTINCT h.tipo) FROM hallazgos_activos h
      WHERE h.activo_id=a.id AND h.resuelto_at IS NULL) AS hallazgos
"""


#: Condiciones de una sola fila, compartidas por el filtro de la lista (`_condiciones`)
#: y por los recuentos de las vistas rapidas (`_conteos_vista`), para que el numero del
#: atajo y las filas que se ven al pulsarlo salgan de la misma condicion.
def _existe_afectado(sin_bajas: bool = True, sin_excepcion: str = "") -> str:
    """Activo con al menos una vulnerabilidad viva de las que si se reportan."""
    baja = f" AND {_SIN_BAJAS_SQL}" if sin_bajas else ""
    return f"""EXISTS (SELECT 1 FROM aplicabilidad ap LEFT JOIN threats t ON t.id=ap.threat_id
                          WHERE ap.activo_id=a.id AND ap.veredicto='afectado'
                            AND (t.id IS NULL OR t.estado NOT IN {ESTADOS_ABIERTOS_SQL}){baja}{sin_excepcion})"""


def _existe_kev(sin_bajas: bool = True, sin_excepcion: str = "") -> str:
    """Activo con al menos una vulnerabilidad de explotacion confirmada."""
    baja = f" AND {_SIN_BAJAS_SQL}" if sin_bajas else ""
    return f"""EXISTS (SELECT 1 FROM aplicabilidad ap JOIN threats t ON t.id=ap.threat_id
                     WHERE ap.activo_id=a.id AND ap.veredicto='afectado' AND t.in_kev=1
                       AND t.estado NOT IN {ESTADOS_ABIERTOS_SQL}{baja}{sin_excepcion})"""
#: Lleva un «?» con el tipo de hallazgo (fin_soporte, sin_edr, software_riesgo).
_EXISTE_HALLAZGO = ("EXISTS (SELECT 1 FROM hallazgos_activos h WHERE h.activo_id=a.id AND h.tipo=? "
                    "AND h.resuelto_at IS NULL)")
#: Lleva un «?» con la fecha umbral por debajo de la cual el activo no reporta.
_SIN_REPORTAR = "(a.ultimo_inventario IS NULL OR a.ultimo_inventario < ?)"


def _condiciones(filtros: dict, umbral: str, sin_bajas: bool = True,
                 sin_excepcion: str = "") -> tuple[list[str], list[Any]]:
    where: list[str] = []
    params: list[Any] = []
    if filtros["vista"] != "ausentes":
        where.append("a.presente=1")
    if filtros["q"]:
        like = _patron_like(filtros["q"])
        # Los mismos campos que anuncia la etiqueta del buscador («Nombre, IP, sistema
        # o usuario») mas el proceso de negocio. La columna «descripcion» de OCS se
        # dejo fuera al pasar el filtrado al servidor (2026-09-07): guarda la
        # arquitectura y el tiempo de encendido («x86_64/00-02-13 08:06:05»), asi que
        # buscar en ella solo producia coincidencias que el operador no entiende.
        where.append("(a.nombre LIKE ? ESCAPE '\\' OR a.ip LIKE ? ESCAPE '\\' "
                     "OR a.so_nombre LIKE ? ESCAPE '\\' OR a.so_version LIKE ? ESCAPE '\\' "
                     "OR a.usuario LIKE ? ESCAPE '\\' OR a.proceso LIKE ? ESCAPE '\\')")
        params += [like] * 6
    if filtros["origen"] in ocs.ORIGENES:
        where.append("a.origen=?")
        params.append(filtros["origen"])
    if filtros["familia"] in ocs.FAMILIAS:
        where.append("a.so_familia=?")
        params.append(filtros["familia"])
    if filtros.get("tec"):
        where.append("EXISTS (SELECT 1 FROM activo_software s WHERE s.activo_id=a.id AND s.technology_id=?)")
        params.append(filtros["tec"])
    if filtros.get("cve"):
        # Mismo patron EXISTS que _existe_afectado/_existe_kev: un activo entra si tiene
        # al menos una fila de aplicabilidad con veredicto «afectado» para ese CVE exacto
        # (normalizado a mayusculas en _leer_filtros, igual que en /aplica). Si el CVE no
        # existe en ``aplicabilidad`` la subconsulta no devuelve nada y la lista queda
        # vacia, sin error (pedido del usuario: filtrar Activos por CVE para ver a quien
        # afecta, cerrando el ciclo con la ficha de Amenazas que ya hace lo contrario).
        where.append("EXISTS (SELECT 1 FROM aplicabilidad ap WHERE ap.activo_id=a.id "
                     "AND ap.cve=? AND ap.veredicto='afectado')")
        params.append(filtros["cve"])
    if filtros.get("entorno"):
        if filtros["entorno"] == "desconocido":
            where.append("a.entorno IS NULL")
        else:
            where.append("a.entorno=?")
            params.append(filtros["entorno"])
    if filtros.get("proceso"):
        # Mismo recorte que la pagina de Amenazas (queries.filtro_parque), que incluye
        # los dos grupos sinteticos «Servidores sin proceso asignado» y «Equipos de
        # cómputo (Mantenimiento)»: con «a.proceso=?» literal, la tarjeta de Amenazas
        # decia «33 activos afectados» y su enlace aterrizaba en una lista vacia
        # (revision de seguridad del 2026-09-08).
        extra, extra_params = queries.filtro_parque(filtros["proceso"], None)
        where.append(extra[len(" AND "):])
        params.extend(extra_params)
    vista = filtros["vista"]
    if vista == "afectados":
        where.append(_existe_afectado(sin_bajas, sin_excepcion))
    elif vista == "kev":
        where.append(_existe_kev(sin_bajas, sin_excepcion))
    elif vista in ("fuera_soporte", "sin_edr", "software_riesgo", "sin_datos_windows"):
        where.append(_EXISTE_HALLAZGO)
        params.append("fin_soporte" if vista == "fuera_soporte" else vista)
    elif vista == "sin_reportar":
        where.append(_SIN_REPORTAR)
        params.append(umbral)
    elif vista == "ausentes":
        where.append("a.presente=0")
    return where, params


def _conteos_vista(conn, filtros: dict, umbral: str, sin_bajas: bool = True,
                   sin_excepcion: str = "") -> dict[str, int]:
    """Cuantos activos caen en cada vista rapida, en dos consultas de recuento.

    Se cuentan con los mismos filtros de la pagina SALVO la propia vista, para que
    los numeros de los atajos digan cuantos activos veria el operador al pulsarlos
    sin perder la busqueda que ya escribio. Antes se contaban en Python sobre las
    881 filas que la pagina traia enteras; con la paginacion en el servidor
    (2026-09-07) las filas ya no estan todas, asi que el recuento es SQL.
    """
    base = dict(filtros, vista="todos")
    where, params = _condiciones(base, umbral, sin_bajas, sin_excepcion)
    sql_where = (" WHERE " + " AND ".join(where)) if where else ""
    fila = conn.execute(
        f"""SELECT SUM(CASE WHEN {_existe_afectado(sin_bajas, sin_excepcion)} THEN 1 ELSE 0 END)  AS afectados,
                   SUM(CASE WHEN {_existe_kev(sin_bajas, sin_excepcion)} THEN 1 ELSE 0 END)       AS kev,
                   SUM(CASE WHEN {_EXISTE_HALLAZGO} THEN 1 ELSE 0 END)  AS fuera_soporte,
                   SUM(CASE WHEN {_SIN_REPORTAR} THEN 1 ELSE 0 END)     AS sin_reportar,
                   SUM(CASE WHEN {_EXISTE_HALLAZGO} THEN 1 ELSE 0 END)  AS sin_edr,
                   SUM(CASE WHEN {_EXISTE_HALLAZGO} THEN 1 ELSE 0 END)  AS software_riesgo,
                   SUM(CASE WHEN {_EXISTE_HALLAZGO} THEN 1 ELSE 0 END)  AS sin_datos_windows
              FROM activos a{sql_where}""",
        ["fin_soporte", umbral, "sin_edr", "software_riesgo", "sin_datos_windows"] + params).fetchone()
    conteos = {clave: int(fila[clave] or 0) for clave in
               ("afectados", "kev", "fuera_soporte", "sin_reportar", "sin_edr", "software_riesgo",
                "sin_datos_windows")}
    where_aus, params_aus = _condiciones(dict(filtros, vista="ausentes"), umbral)
    conteos["ausentes"] = int(conn.execute(
        "SELECT COUNT(*) FROM activos a WHERE " + " AND ".join(where_aus), params_aus).fetchone()[0] or 0)
    return conteos


def _leer_filtros() -> dict[str, Any]:
    vista = (request.args.get("vista") or "todos").strip()
    orden = (request.args.get("orden") or "riesgo").strip()
    return {
        "q": (request.args.get("q") or "").strip()[:120],
        # Alcance por tipo de maquina (2026-09-08): para Redes y Mantenimiento el tipo lo
        # fija el perfil y «?origen=» no lo cambia; el filtro SQL siempre lo lleva, asi
        # que tampoco un proceso del otro tipo puede ensenar nada.
        "origen": auth.origen_efectivo((request.args.get("origen") or "").strip()) or "",
        "familia": (request.args.get("familia") or "").strip(),
        "vista": vista if vista in VISTAS else "todos",
        "orden": orden if orden in ORDENES else "riesgo",
        "tec": request.args.get("tec", 0, type=int) or 0,
        "entorno": (request.args.get("entorno") or "").strip()[:40],
        "proceso": (request.args.get("proceso") or "").strip()[:120],
        # CVE exacto (2026-11-15): mismo recorte y normalizacion que el campo «cve» de
        # «¿Le aplica este CVE?» (ver «aplica»), para que buscar «cve-2024-11053» con
        # espacios o en minusculas encuentre lo mismo que CVE-2024-11053.
        "cve": (request.args.get("cve") or "").strip().upper()[:40],
    }


def _porciones_familias(familias: list[dict]) -> list[dict]:
    """Porciones de la dona de familias, de mayor a menor, cada una con su color fijo;
    «sin datos» en gris al final."""
    conocidas = sorted((f for f in familias if f.get("n") and f.get("so_familia") not in (None, "", "desconocido")),
                       key=lambda f: (-int(f["n"] or 0), str(f["so_familia"])))
    porciones = [{"clave": FAMILIA_CLAVE.get(f["so_familia"], "cat-8"),
                  "nombre": ocs.FAMILIA_ES.get(f["so_familia"], f["so_familia"]),
                  "valor": int(f["n"] or 0)} for f in conocidas]
    sin_datos = sum(int(f["n"] or 0) for f in familias if f.get("n") and f.get("so_familia") in (None, "", "desconocido"))
    if sin_datos:
        porciones.append({"clave": "neutro", "nombre": ocs.FAMILIA_ES.get("desconocido", "Sin datos de sistema"),
                          "valor": sin_datos})
    return porciones


def _sistemas(conn, tabla_eol: dict, *, limite: Optional[int] = None) -> list[dict]:
    """Sistemas (nombre y ciclo) con más activos, de mayor a menor, y su estado de soporte.
    Sin ``limite`` devuelve todos: la vista necesita el total para decir cuántas versiones
    quedan fuera de la gráfica."""
    filas = []
    hoy = date.today()
    # Alcance por tipo de maquina (2026-09-08): el reparto por sistema es el del perfil.
    extra, params = auth.filtro_alcance_sql("a")
    for r in conn.execute(
            f"""SELECT a.so_nombre, a.so_familia, a.so_ciclo, COUNT(*) AS n, MIN(a.so_version) AS version_min,
                      MAX(a.so_version) AS version_max
                 FROM activos a WHERE a.presente=1{extra}
                GROUP BY a.so_nombre, a.so_familia, a.so_ciclo ORDER BY n DESC, a.so_nombre""", params):
        fila = dict(r)
        fila["soporte"] = aplicabilidad.estado_soporte(
            tabla_eol, {"so_familia": fila["so_familia"], "so_ciclo": fila["so_ciclo"],
                        "so_nombre": fila["so_nombre"]}, hoy=hoy)
        fila["familia_es"] = ocs.FAMILIA_ES.get(fila["so_familia"], fila["so_familia"] or "—")
        filas.append(fila)
    return filas[:limite] if limite else filas


def _nota_soporte(soporte: Optional[dict]) -> str:
    """Estado de soporte escrito, con la fecha en español: el color de la barra ya no lo
    dice (cada versión tiene el suyo), así que el texto es la única forma de leerlo."""
    from webui.filtros import mes_es
    sop = soporte or {}
    eol = str(sop.get("eol") or "")
    # Mes y año, no el dia: con la fecha completa la nota se comia el ancho de la barra
    # (la menor medía 4,6 px; revisión del 2026-09-08). El día exacto está en la tabla
    # «Fin de soporte» y en la ficha de cada activo.
    cuando = mes_es(eol[:7]) if re.match(r"^\d{4}-\d{2}", eol) else ""
    if sop.get("fuera") and cuando:
        return f"sin soporte desde {cuando}"
    if sop.get("proximo") and cuando:
        return f"fin de soporte en {cuando}"
    if cuando:
        return f"soporte hasta {cuando}"
    # Sin ciclo reconocido, sin dato en endoflife.date o con una fecha ilegible: se dice.
    return "sin dato de soporte"


def _versiones_reales(sistemas: list[dict]) -> list[dict]:
    """Las filas que SÍ son una versión de sistema operativo, en el orden recibido.

    Deja fuera los activos cuyo agente nunca envió el sistema, que la sincronización
    guarda con el literal «Sin datos de sistema» y familia «desconocido».
    """
    return [s for s in sistemas or [] if not _sistema_desconocido(s)]


def _items_sistemas(sistemas: list[dict], *, limite: int = MAX_VERSIONES_GRAFICA) -> list[dict]:
    """Barras de la gráfica: una por versión, con un color categórico distinto cada una
    (cat-1, cat-2… en orden de activos) y el estado de soporte en la nota. Como hay tantos
    colores como barras admitidas, ningún color se repite; la leyenda lista las versiones.

    Solo versiones (auditoría de tableros del 2026-09-15). Hasta ahora, «Sin datos de
    sistema» entraba en el mismo orden que las versiones y salía como la quinta barra de un
    top de versiones (42 activos sobre la base real), compitiendo con Debian 12 y Windows 11
    Pro sin ser una versión de nada; además robaba un puesto al top, así que el pie decía
    «se muestran las 12 versiones con más activos» cuando solo había 11. Esos activos salen
    de la gráfica y se cuentan aparte, en su propia línea, con enlace a su lista.
    """
    items = []
    for color, s in enumerate(_versiones_reales(sistemas)[:limite], start=1):
        nombre = s["so_nombre"]
        items.append({"etiqueta": nombre,
                      "valores": [(f"cat-{color}", int(s["n"] or 0), nombre)],
                      "href": (url_for("activos.lista", familia=s["so_familia"])
                               if s.get("so_familia") else ""),
                      "nota": _nota_soporte(s.get("soporte"))})
    return items


def _activos_sin_datos_de_sistema(sistemas: list[dict]) -> int:
    """Activos presentes cuyo agente nunca envió el sistema operativo: no son una versión
    y por eso no entran en la gráfica «Versiones de sistema con más activos», pero tampoco
    se callan (se dicen debajo, con enlace a su lista)."""
    return sum(int(s.get("n") or 0) for s in sistemas or [] if _sistema_desconocido(s))


def _sistema_desconocido(s: dict) -> bool:
    """True si la fila no tiene un sistema reconocible (nombre vacio, familia desconocida o
    el literal «Sin datos de sistema» que escribe la sincronizacion)."""
    nombre = (s.get("so_nombre") or "").strip()
    familia = (s.get("so_familia") or "desconocido")
    return not nombre or familia == "desconocido" or nombre == ocs.FAMILIA_ES["desconocido"]


def _versiones_fuera_grafica(sistemas: list[dict], *, limite: int = MAX_VERSIONES_GRAFICA) -> dict[str, int]:
    """Cuántas versiones (y cuántos activos) no caben en la gráfica por el tope de colores,
    para decirlo debajo en lugar de callarlo.

    Se recorta sobre las versiones REALES (2026-09-15): antes «Sin datos de sistema»
    ocupaba sitio en la gráfica y a la vez se descontaba de este recuento, así que el pie
    prometía una versión más de las que se dibujaban."""
    fuera = _versiones_reales(sistemas)[limite:]
    return {"versiones": len(fuera), "activos": sum(int(s["n"] or 0) for s in fuera)}


def _fin_soporte_resumen(conn, tabla_eol: dict) -> dict[str, list[dict]]:
    fuera: dict[str, dict] = {}
    proximos: dict[str, dict] = {}
    hoy = date.today()
    extra, params = auth.filtro_alcance_sql("a")
    for a in conn.execute("SELECT a.nombre, a.so_nombre, a.so_version, a.so_familia, a.so_ciclo FROM activos a "
                          f"WHERE a.presente=1 AND a.so_ciclo IS NOT NULL{extra}", params):
        est = aplicabilidad.estado_soporte(tabla_eol, dict(a), hoy=hoy)
        if not est or est.get("sin_datos"):
            continue
        destino = fuera if est["fuera"] else (proximos if est["proximo"] else None)
        if destino is None:
            continue
        clave = f"{a['so_nombre']}|{est['ciclo']}"
        e = destino.setdefault(clave, {"sistema": a["so_nombre"], "etiqueta": est["etiqueta"], "eol": est["eol"],
                                       "dias": est["dias"], "familia": a["so_familia"], "activos": 0})
        e["activos"] += 1
    return {"fuera": sorted(fuera.values(), key=lambda x: -x["activos"]),
            "proximos": sorted(proximos.values(), key=lambda x: x["dias"] or 0)}


# --------------------------------------------------------------------------
# Lista
# --------------------------------------------------------------------------
@bp.route("/")
@auth.requiere_login
def lista():
    """Lista de activos paginada en el servidor (2026-09-07).

    Hasta ahora la pagina enviaba al navegador las 881 filas del inventario y
    ``webui/static/app.js`` filtraba y ordenaba alli. Con ese volumen el HTML pesaba
    1,5 MB y la pagina tardaba mas de un segundo en construirse, asi que el filtrado
    (texto, tipo, sistema, entorno, proceso y vista rapida), el orden y la paginacion
    pasan al servidor: la consulta lleva ``LIMIT``/``OFFSET``, el total sale de un
    ``COUNT(*)`` y los numeros de las vistas rapidas de dos consultas de recuento.

    La busqueda sigue aplicandose mientras se escribe: el formulario lleva
    ``data-filtro-vivo`` y solo se sustituye la zona ``#lista-activos``. Sin
    JavaScript el mismo formulario funciona con el envio clasico.
    """
    filtros = _leer_filtros()
    umbral = _umbral(g.cfg)
    tabla_eol = aplicabilidad.tabla_fin_soporte(g.db)

    sin_bajas = _sin_bajas()
    # Una sola llamada por peticion: la condicion del riesgo aceptado se resuelve aqui y
    # se pasa a las tres consultas de la pagina (filtro, columna «Afectados» y recuentos
    # de los atajos), para que las tres cuenten lo mismo y para no repetir la consulta a
    # ``excepciones`` tres veces.
    sin_excepcion = _sin_excepcion()
    where, params = _condiciones(filtros, umbral, sin_bajas, sin_excepcion)
    sql_where = (" WHERE " + " AND ".join(where)) if where else ""
    total = int(g.db.execute(f"SELECT COUNT(*) FROM activos a{sql_where}", params).fetchone()[0] or 0)
    pagina, paginas = _pagina_valida(request.args.get("pagina", 1, type=int), total, POR_PAGINA)

    crudas = [dict(r) for r in g.db.execute(
        f"""SELECT a.*, {_subconsultas(sin_bajas, sin_excepcion)} FROM activos a{sql_where}
             ORDER BY {ORDENES[filtros['orden']]} LIMIT ? OFFSET ?""",
        params + [POR_PAGINA, (pagina - 1) * POR_PAGINA])]
    # Los hallazgos, solo los de los activos de esta pagina.
    hallazgos = _hallazgos_detallados(g.db, [f["id"] for f in crudas])
    filas = []
    for f in crudas:
        f["afectados"] = int(f.get("afectados") or 0)
        f["kev"] = int(f.get("kev") or 0)
        f["n_mapeado"] = int(f.get("n_mapeado") or 0)
        f["hallazgos_detalle"] = hallazgos.get(f["id"], [])
        _etiquetar(f, tabla_eol, umbral)
        flags = []
        if f["afectados"]:
            flags.append("afectados")
        if f["kev"]:
            flags.append("kev")
        if f["sin_reportar"]:
            flags.append("sin_reportar")
        flags += [h for h in ("fin_soporte", "sin_edr", "software_riesgo", "sin_datos_windows")
                  if h in f["hallazgos_lista"]]
        if "fin_soporte" in flags:
            flags.append("fuera_soporte")
        if not f["presente"]:
            flags.append("ausentes")
        f["vistas"] = " ".join(flags)
        filas.append(f)

    resumen = _resumen_en_alcance(g.db, ocs.resumen(g.db, cfg=g.cfg), umbral)
    sistemas = _sistemas(g.db, tabla_eol)
    soporte = _fin_soporte_resumen(g.db, tabla_eol)
    conteos_vista = _conteos_vista(g.db, filtros, umbral, sin_bajas, sin_excepcion)
    graf = {"familias": _porciones_familias(resumen["familias"]),
            "sistemas": _items_sistemas(sistemas),
            "sistemas_total": len(_versiones_reales(sistemas)),
            "sistemas_fuera": _versiones_fuera_grafica(sistemas),
            "sistemas_tope": MAX_VERSIONES_GRAFICA,
            # Los activos sin sistema conocido NO son una versión: salen de la gráfica y
            # se dicen aparte, debajo (auditoría de tableros del 2026-09-15).
            "sistemas_sin_datos": _activos_sin_datos_de_sistema(sistemas),
            # Orden fijo de más a menos expuesto, cada entorno con su color.
            "entornos": [{"clave": CLAVE_ENTORNO[e], "nombre": ocs.ENTORNO_ES.get(e, "Sin entorno"),
                          "valor": resumen["entornos"].get(e, 0)}
                         for e in ORDEN_ENTORNOS if resumen["entornos"].get(e)]}
    # Solo las bases de OCS del alcance del perfil: para Redes no existe la de equipos de
    # computo, ni su recuento (revisión del 2026-09-08).
    sincro = {k: v for k, v in resumen["sincronizacion"].items() if auth.dentro_del_alcance(k)}
    en_curso = any(s_ and s_.get("status") == "running" for s_ in sincro.values())
    args = _args_a_conservar("pagina")
    tecnologia_filtro = None
    if filtros["tec"]:
        fila_tec = g.db.execute("SELECT name FROM technologies WHERE id=?", (filtros["tec"],)).fetchone()
        tecnologia_filtro = fila_tec["name"] if fila_tec else None
    # Procesos de negocio del selector: consulta propia, porque con la paginacion las
    # filas de la pagina ya no son todo el inventario.
    extra_alcance, params_alcance = auth.filtro_alcance_sql("a")
    procesos_lista = [r[0] for r in g.db.execute(
        "SELECT DISTINCT a.proceso FROM activos a WHERE a.presente=1 AND a.proceso IS NOT NULL "
        f"AND a.proceso <> ''{extra_alcance} ORDER BY a.proceso COLLATE NOCASE", params_alcance)]
    # Tecnologias del selector «Tecnología» (2026-11-15): antes el filtro «tec» solo
    # llegaba con el id ya resuelto desde otra pantalla (la ficha de Tecnología); para
    # escribirlo a mano desde Activos hace falta la lista de opciones. Son como mucho
    # las tecnologias con algun activo (``activos_ocs``, ~200 filas, columna que
    # mantiene la sincronizacion), no las 881 filas de activos ni las 922.000
    # instalaciones: una sola consulta pequena, no una por activo.
    tecnologias_lista = [dict(r) for r in g.db.execute(
        "SELECT id, name FROM technologies WHERE COALESCE(activos_ocs, 0) > 0 "
        "ORDER BY name COLLATE NOCASE")]
    return render_template(
        "activos.html", filas=filas, total=total, pagina=pagina, paginas=paginas,
        por_pagina=POR_PAGINA, args=args, filtros=filtros, vistas=VISTAS,
        # Solo las cifras: el panel «Remediación» de esta página pinta cinco métricas y
        # no el reparto por proceso ni la serie semanal, que es lo que cuesta.
        remediacion_resumen=resumen_memorizado(
            int(float(g.cfg.get("remediacion_dias_resumen", 30) or 30)),
            auth.alcance_origen(), solo_cifras=True),
        vista_es=VISTA_ES, ordenes=ORDENES, orden_es=ORDEN_ES, conteos_vista=conteos_vista,
        resumen=resumen, sistemas=sistemas, soporte=soporte, graf=graf, sincro=sincro,
        en_curso=en_curso, origen_es=ocs.ORIGEN_ES,
        # El selector «Tipo» solo ofrece lo que el perfil puede ver.
        origen_plural={k: v for k, v in ocs.ORIGEN_PLURAL_ES.items() if auth.dentro_del_alcance(k)},
        familia_es=ocs.FAMILIA_ES, familias=ocs.FAMILIAS, tipo_hallazgo_es=ocs.TIPO_HALLAZGO_ES,
        explicacion_hallazgo=ocs.TIPO_HALLAZGO_EXPLICACION, entornos=ocs.ENTORNOS, entorno_es=ocs.ENTORNO_ES,
        procesos_lista=procesos_lista, tecnologia_filtro=tecnologia_filtro,
        tecnologias_lista=tecnologias_lista,
        # Si las cifras de esta pagina dejan fuera la severidad Baja (regla interna,
        # ajuste ``ignore_low_severity``): la plantilla lo necesita para explicar por que
        # «Con vulnerabilidades confirmadas» y «Activos con pendientes» de Remediacion no
        # dan el mismo numero (revision visual del 2026-09-09).
        sin_bajas=sin_bajas,
        dias_sin_reportar=int(float(g.cfg.get("ocs_stale_days", 30) or 30)))


@bp.route("/<int:activo_id>/vulnerabilidades.json")
@auth.requiere_login
def vulnerabilidades_json(activo_id: int):
    """Vulnerabilidades confirmadas de un activo, para el desplegable de la lista."""
    activo = g.db.execute("SELECT id, nombre, ip, so_nombre, origen FROM activos WHERE id=?", (activo_id,)).fetchone()
    # Un activo del otro tipo de maquina responde igual que uno inexistente (2026-09-08).
    if activo is None or not auth.dentro_del_alcance(activo["origen"]):
        return jsonify({"error": "no existe"}), 404
    activo = {k: activo[k] for k in ("id", "nombre", "ip", "so_nombre")}
    lista = aplicabilidad.vulnerabilidades_activo(g.db, activo_id, limite=100)
    for v in lista:
        v["url"] = url_for("amenazas.detalle", threat_id=v["threat_id"]) if v.get("threat_id") else None
        v["severidad_es"] = {"Critical": "Crítica", "High": "Alta", "Medium": "Media", "Low": "Baja"}.get(v.get("severidad"), v.get("severidad") or "—")
    resp = jsonify({"activo": dict(activo), "url_activo": url_for("activos.detalle", activo_id=activo_id),
                    "url_remediacion": url_for("activos.remediacion", activo_id=activo_id),
                    "vulnerabilidades": lista, "total": len(lista)})
    resp.headers["Cache-Control"] = "no-store, private"
    return resp


# --------------------------------------------------------------------------
# Ficha
# --------------------------------------------------------------------------
def _cargar_activo(activo_id: int) -> Optional[dict]:
    """La ficha del activo, o None si no existe.

    Alcance por tipo de maquina (2026-09-08): si el activo existe pero es del otro tipo
    (un equipo de computo para el perfil de Redes, un servidor para el de Mantenimiento)
    la peticion termina con 404, la misma respuesta que un identificador inventado, para
    no revelar que existe. Pasan por aqui la ficha, el plan de remediacion, el CSV del
    activo y las acciones de escritura sobre el (aplica, SBOM, OpenSCAP).
    """
    # La ficha NO descuenta el riesgo aceptado, a proposito y como el resto de la ficha
    # (``aplicabilidad.conteo_activo``, el historial de remediacion): aqui la fila tiene
    # que seguir viendose con su insignia «Riesgo aceptado». De estas subconsultas la
    # ficha solo pinta ``hallazgos`` y ``n_mapeado``; su contador de vulnerabilidades
    # confirmadas sale de ``aplicabilidad.conteo_activo``, que es un hecho tecnico.
    fila = g.db.execute(f"SELECT a.*, {_subconsultas(_sin_bajas())} FROM activos a WHERE a.id=?",
                        (activo_id,)).fetchone()
    if fila is None:
        # Misma respuesta que un activo fuera del alcance (revisión del 2026-09-08): si el
        # inexistente redirigiera y el ajeno diera 404, un perfil acotado podria enumerar
        # que identificadores existen del otro tipo.
        abort(404)
    auth.exigir_alcance(fila["origen"])
    return _etiquetar(dict(fila), aplicabilidad.tabla_fin_soporte(g.db), _umbral(g.cfg))


def _resumen_en_alcance(conn, resumen: dict, umbral: str) -> dict:
    """Las cifras de cabecera de la pagina de Activos acotadas al tipo de maquina del
    perfil (2026-09-08).

    ``ocs.resumen`` cuenta el parque entero (es lo que usan el correo y el panel). Para
    Redes y Mantenimiento se recalculan aqui, con las mismas condiciones y ``a.origen``,
    las cifras que la pagina ensena: total, tipos, sin reportar, sin sistema, con
    vulnerabilidades, fuera de soporte, familias, entornos y hallazgos. Las de software
    clasificado (porcentaje del inventario) y tecnologias no son por maquina y se dejan.
    Sin alcance se devuelve tal cual.
    """
    origen = auth.alcance_origen()
    if not origen or not resumen:
        return resumen
    fila = conn.execute(
        """SELECT COUNT(*) AS total,
                  SUM(a.origen='servidores') AS servidores, SUM(a.origen='equipos') AS equipos,
                  SUM(a.ultimo_inventario IS NULL OR a.ultimo_inventario < ?) AS sin_reportar,
                  SUM(a.so_familia='desconocido') AS sin_so
             FROM activos a WHERE a.presente=1 AND a.origen=?""", (umbral, origen)).fetchone()
    familias = [dict(r) for r in conn.execute(
        "SELECT a.so_familia, COUNT(*) AS n FROM activos a WHERE a.presente=1 AND a.origen=? "
        "GROUP BY a.so_familia ORDER BY n DESC", (origen,))]
    hallazgos = {r["tipo"]: int(r["n"]) for r in conn.execute(
        """SELECT h.tipo, COUNT(DISTINCT h.activo_id) AS n FROM hallazgos_activos h
             JOIN activos a ON a.id=h.activo_id
            WHERE h.resuelto_at IS NULL AND a.presente=1 AND a.origen=? GROUP BY h.tipo""", (origen,))}
    # Las MISMAS dos condiciones que ``ocs.resumen``, del que esta funcion es la version
    # acotada por tipo de maquina: sin ellas, Redes y Mantenimiento veian una cifra
    # calculada con otro criterio que el SOC (contaba la severidad baja y el riesgo
    # aceptado) sobre los mismos servidores (2026-09-10, tarde).
    baja = f" AND {_SIN_BAJAS_SQL}" if _sin_bajas() else ""
    # El mismo reparto por frescura del inventario que ``ocs.resumen`` (2026-09-10): la
    # cifra entera y la de los activos que reportan al día, para que Redes y
    # Mantenimiento vean el mismo desglose que el SOC.
    fresco = "(a.ultimo_inventario IS NOT NULL AND a.ultimo_inventario >= ?)"
    fila_af = conn.execute(
        f"""SELECT COUNT(DISTINCT ap.activo_id) AS total,
                   COUNT(DISTINCT CASE WHEN {fresco} THEN ap.activo_id END) AS con_dato,
                   COUNT(DISTINCT CASE WHEN NOT {fresco} THEN ap.activo_id END) AS sin_reportar
              FROM aplicabilidad ap
              JOIN activos a ON a.id=ap.activo_id
              LEFT JOIN threats t ON t.id=ap.threat_id
             WHERE ap.veredicto='afectado' AND a.presente=1 AND a.origen=?
               AND (t.id IS NULL OR t.estado NOT IN ('descartada','falso_positivo','mitigada'))
               {baja}{_sin_excepcion()}""",
        (umbral, umbral, origen)).fetchone()
    afectados = int(fila_af["total"] or 0)
    entornos = {r["entorno"] or "desconocido": int(r["n"]) for r in conn.execute(
        "SELECT a.entorno, COUNT(*) AS n FROM activos a WHERE a.presente=1 AND a.origen=? "
        "GROUP BY a.entorno", (origen,))}
    acotado = dict(resumen)
    acotado.update({
        "total": int(fila["total"] or 0), "servidores": int(fila["servidores"] or 0),
        "equipos": int(fila["equipos"] or 0), "sin_reportar": int(fila["sin_reportar"] or 0),
        "sin_so": int(fila["sin_so"] or 0), "familias": familias, "hallazgos": hallazgos,
        "con_vulnerabilidades": int(afectados or 0),
        "con_vulnerabilidades_con_dato": int(fila_af["con_dato"] or 0),
        "sin_reportar_afectados": int(fila_af["sin_reportar"] or 0),
        "presentes_con_dato": max(0, int(fila["total"] or 0) - int(fila["sin_reportar"] or 0)),
        "fuera_soporte": hallazgos.get("fin_soporte", 0), "entornos": entornos,
        "acotado": origen})
    if origen != "servidores":
        # Los procesos de negocio (TAG de OCS) son de los servidores: Mantenimiento no
        # los ve, y «servidores sin proceso» tampoco es una cifra de su alcance.
        acotado["procesos"] = []
        acotado["sin_proceso"] = 0
    return acotado


def _sql_software(activo_id: int, q: str, todo: bool) -> tuple[str, list]:
    """WHERE y parametros comunes al recuento y a la pagina del software de un activo."""
    sql = " WHERE s.activo_id=?"
    params: list[Any] = [activo_id]
    if q:
        sql += (" AND (s.nombre_norm LIKE ? ESCAPE '\\' OR s.version LIKE ? ESCAPE '\\' "
                "OR t.name LIKE ? ESCAPE '\\')")
        params += [_patron_like(q.lower()), _patron_like(q), _patron_like(q)]
    elif not todo:
        sql += " AND s.technology_id IS NOT NULL"
    return sql, params


def _contar_software_de(activo_id: int, *, q: str = "", todo: bool = False) -> int:
    """Programas del activo que cumplen el filtro; es lo que cuenta la paginacion."""
    donde, params = _sql_software(activo_id, q, todo)
    return int(g.db.execute(
        "SELECT COUNT(*) FROM activo_software s LEFT JOIN technologies t ON t.id=s.technology_id"
        + donde, params).fetchone()[0] or 0)


def _software_de(activo_id: int, *, q: str = "", todo: bool = False,
                 desplazamiento: int = 0) -> tuple[list[dict], int, int, int]:
    """Una pagina del software del activo: primero lo mapeado a tecnologias; con ``todo``
    o con ``q``, tambien el resto.

    Devuelve (filas, total_instalado, mapeado, total_del_filtro). «total_instalado» son
    todos los programas del equipo y no cambia con la busqueda; «total_del_filtro» es lo
    que cuenta la paginacion (2026-09-07). El WHERE lo construye ``_sql_software``, el
    mismo que usa el recuento, para que la pagina y el total no puedan discrepar."""
    donde, params = _sql_software(activo_id, q, todo)
    total = g.db.execute("SELECT COUNT(*) FROM activo_software WHERE activo_id=?",
                         (activo_id,)).fetchone()[0]
    # El orden termina en «s.rowid», que es unico: sin el, dos programas con el mismo
    # nombre podian salir en dos paginas y dejar a otro sin salir.
    filas = [dict(r) for r in g.db.execute(
        """SELECT s.nombre, s.nombre_norm, s.version, s.fabricante, s.technology_id,
                  t.name AS tecnologia, t.slug, t.criticality
             FROM activo_software s LEFT JOIN technologies t ON t.id=s.technology_id"""
        + donde
        + " ORDER BY (s.technology_id IS NULL), t.name, s.nombre_norm, s.rowid LIMIT ? OFFSET ?",
        params + [SOFTWARE_POR_PAGINA, max(0, int(desplazamiento or 0))])]
    mapeado = g.db.execute(
        "SELECT COUNT(*) FROM activo_software WHERE activo_id=? AND technology_id IS NOT NULL",
        (activo_id,)).fetchone()[0]
    return filas, int(total or 0), int(mapeado or 0), _contar_software_de(activo_id, q=q, todo=todo)



def _render_detalle(activo: dict, *, respuesta: Optional[dict] = None, cve_consultado: str = ""):
    q = (request.values.get("soft") or "").strip()[:80]
    todo = request.values.get("todo") == "1"
    # Tres listados largos, cada uno con su propio parametro de pagina para poder avanzar
    # en uno sin perder el sitio en los demas (peticion del 2026-09-07). Eran cuatro: la
    # tabla «Amenazas evaluadas para este activo» se retiro el 2026-09-09 (ver abajo).
    #
    # SOLO LO QUE AFECTA (2026-09-09, peticion repetida del usuario): «recuerda eliminar
    # lo que no me afecta, no necesito que me muestre informacion de vulnerabilidades que
    # no me afecten como por ejemplo: … CVE-2023-42366 · Media · No afectado ·
    # busybox-initramfs 1:1.36.1-6ubuntu3.1 → 1:1.36.1-6ubuntu3.1 · ya incluye la
    # correccion». Esa tabla listaba los tres veredictos (en el activo 511 de produccion,
    # 182 filas: 155 afectadas, 22 no afectadas y 5 sin dato) y una fila por CVE y paquete,
    # asi que las 69 vulnerabilidades del activo se leian como 155 tareas. La ficha pinta
    # ahora UNA ENTRADA POR COSA QUE HAY QUE ACTUALIZAR (28 actualizaciones en ese activo),
    # con la version objetivo y la cola de versiones; de los veredictos que no afectan
    # queda una sola linea al pie, que es la prueba de que la comprobacion se hizo, y la
    # exportacion en CSV sigue trayendo TODOS los veredictos sin recorte.
    conteo = aplicabilidad.conteo_activo(g.db, activo["id"])
    # Paquetes con alguna evaluacion, para la columna «Aplicabilidad» de la tabla de
    # software. Antes salia de la pagina de veredictos que se estuviera mirando, asi que
    # un paquete evaluado dejaba de marcarse al pasar de pagina; ahora es una consulta
    # propia con el indice por activo (idx_aplic_activo).
    paquetes_evaluados = {r[0] for r in g.db.execute(
        "SELECT DISTINCT paquete FROM aplicabilidad WHERE activo_id=? AND paquete IS NOT NULL",
        (activo["id"],))}
    hallazgos = [dict(r) for r in g.db.execute(
        "SELECT * FROM hallazgos_activos WHERE activo_id=? AND resuelto_at IS NULL ORDER BY tipo, clave",
        (activo["id"],))]
    for h in hallazgos:
        h["tipo_es"] = ocs.TIPO_HALLAZGO_ES.get(h["tipo"], h["tipo"])
        h["explicacion"] = ocs.TIPO_HALLAZGO_EXPLICACION.get(h["tipo"], "")
    if respuesta:
        for f in respuesta.get("filas") or []:
            f["veredicto_es"] = aplicabilidad.VEREDICTO_ES.get(f["veredicto"], f["veredicto"])
            f["motor_es"] = aplicabilidad.MOTOR_ES.get(f["motor"], f["motor"])
        respuesta["veredicto_es"] = aplicabilidad.VEREDICTO_ES.get(respuesta["veredicto"], respuesta["veredicto"])
    resumen_sbom = sbom.resumen_activo(g.db, activo["id"])
    resumen_scap = openscap.resumen_activo(g.db, activo["id"])
    total_scap = openscap.contar_fallos_activo(g.db, activo["id"]) if resumen_scap["perfiles"] else 0
    pagina_scap, paginas_scap = _pagina_valida(
        request.values.get("pagina_scap", 1, type=int), total_scap, POR_PAGINA)
    fallos_scap = (openscap.fallos_activo(g.db, activo["id"], limite=POR_PAGINA,
                                          desplazamiento=(pagina_scap - 1) * POR_PAGINA)
                   if total_scap else [])
    total_rem = _remediacion.contar_historial_activo(g.db, activo["id"])
    pagina_rem, paginas_rem = _pagina_valida(
        request.values.get("pagina_rem", 1, type=int), total_rem, POR_PAGINA)
    remediaciones = _remediacion.historial_activo(
        g.db, activo["id"], limite=POR_PAGINA, desplazamiento=(pagina_rem - 1) * POR_PAGINA)
    # Riesgo aceptado (excepciones con vencimiento, 2026-09-10). La ficha del activo es el
    # sitio donde una vulnerabilidad cubierta por una excepcion vigente TIENE que seguir
    # viendose: el historial la trae y aqui se le pone la insignia «Riesgo aceptado», con
    # el responsable, la fecha de vencimiento y el enlace a la excepcion. Las excepciones
    # del activo se resuelven de UNA VEZ (una consulta con ``excepciones.por_activo``, que
    # incluye tambien las de un CVE en toda la organizacion que tapan alguna de sus
    # vulnerabilidades) y se cruzan en Python: nunca una consulta por fila.
    excepciones_activo = excepciones.por_activo(g.db, activo["id"], solo_vigentes=True)
    marcar_riesgo_aceptado(remediaciones, indice_riesgo_aceptado(excepciones_activo))
    total_soft_filtro = _contar_software_de(activo["id"], q=q, todo=todo)
    pagina_soft, paginas_soft = _pagina_valida(
        request.values.get("pagina_soft", 1, type=int), total_soft_filtro, SOFTWARE_POR_PAGINA)
    software, total_soft, mapeado, _ = _software_de(
        activo["id"], q=q, todo=todo,
        desplazamiento=(pagina_soft - 1) * SOFTWARE_POR_PAGINA)
    # Lo que hay que conservar al cambiar de pagina en cualquiera de los cuatro
    # listados: el filtro del software, la consulta de un CVE y la pagina EN LA QUE
    # ESTAN LOS OTROS TRES, para poder avanzar en uno sin perder el sitio en los demas.
    # El parcial sobrescribe su propia clave, asi que no hay conflicto. Solo se llevan
    # las paginas distintas de la primera, para no ensuciar la direccion.
    # Un activo RETIRADO de OCS Inventory no tiene cola de trabajo ni la va a tener
    # (2026-09-15, punto 1 de la revision de claridad): sus vulnerabilidades y sus
    # remediaciones quedaron congeladas con el ultimo dato conocido. La ficha lo dice UNA
    # vez, con la fecha y las dos cifras, en vez de prometer que «entran en la cola en la
    # proxima sincronizacion» al lado de una tabla de remediaciones ya abiertas en estado
    # «Activo retirado». Las cifras se calculan aqui para que el aviso, la tarjeta y la
    # tabla no puedan decir numeros distintos.
    congeladas = (_remediacion.contar_congeladas_activo(g.db, activo["id"])
                  if activo.get("retirado") else 0)
    retirado = ({"desde": activo.get("retirado_desde"),
                 "vulnerabilidades": int(conteo.get("afectado") or 0),
                 "remediaciones": total_rem,
                 "congeladas": congeladas}
                if activo.get("retirado") else None)
    args_ficha = {k: v for k, v in request.values.items() if k in ("soft", "todo", "cve")}
    for clave, valor in (("pagina_rem", pagina_rem),
                         ("pagina_scap", pagina_scap), ("pagina_soft", pagina_soft)):
        if valor > 1:
            args_ficha[clave] = valor
    return render_template(
        "activo_detalle.html", a=activo, software=software, total_software=total_soft, mapeado=mapeado,
        windows=_msrc.resumen_activo(g.db, activo), remediaciones=remediaciones,
        resumen_sbom=resumen_sbom, resumen_scap=resumen_scap, fallos_scap=fallos_scap,
        args_ficha=args_ficha, por_pagina=POR_PAGINA, por_pagina_soft=SOFTWARE_POR_PAGINA,
        # Acciones de remediación: solo administradores y Redes
        puede_remediar=auth.puede_remediar(),
        comprobacion_es=_remediacion.VEREDICTO_ES,
        # La insignia lleva la version CORTA y la frase entera va en su «title» y debajo
        # en texto: una frase dentro de una insignia con «nowrap» estiraba la tabla hasta
        # sacarla de la pantalla (revision del 2026-09-08, igual que en Remediación).
        comprobacion_corto=_remediacion.VEREDICTO_CORTO,
        comprobacion_clave=_remediacion.VEREDICTO_CLAVE,
        total_rem=total_rem, pagina_rem=pagina_rem, paginas_rem=paginas_rem,
        # Las excepciones vigentes que afectan a este activo, para el aviso de la ficha.
        excepciones_activo=excepciones_activo,
        total_scap=total_scap, pagina_scap=pagina_scap, paginas_scap=paginas_scap,
        total_soft_filtro=total_soft_filtro, pagina_soft=pagina_soft, paginas_soft=paginas_soft,
        resultado_es=openscap.RESULTADO_ES,
        soft_q=q, soft_todo=todo, limite_software=SOFTWARE_POR_PAGINA,
        conteo=conteo, hallazgos=hallazgos, respuesta=respuesta, cve_consultado=cve_consultado,
        retirado=retirado,
        # El motivo de cierre «de siempre» de un activo retirado: la tabla no lo repite
        # en cada fila cuando es ese (2026-09-15).
        motivo_ausente=_remediacion.MOTIVO_AUSENTE,
        veredicto_es=aplicabilidad.VEREDICTO_ES, veredicto_clave=aplicabilidad.VEREDICTO_CLAVE,
        motor_es=aplicabilidad.MOTOR_ES, paquetes_evaluados=paquetes_evaluados,
        dias_sin_reportar=int(float(g.cfg.get("ocs_stale_days", 30) or 30)))


@bp.route("/<int:activo_id>")
@auth.requiere_login
def detalle(activo_id: int):
    activo = _cargar_activo(activo_id)
    if activo is None:
        flash("El activo no existe.", "error")
        return redirect(url_for("activos.lista"))
    return _render_detalle(activo)


@bp.route("/<int:activo_id>/aplica", methods=["POST"])
@auth.requiere_operacion
@auth.requiere_csrf
def aplica(activo_id: int):
    """«¿Le aplica este CVE?»: responde al momento y GUARDA el veredicto.

    Administradores y operador SOC (2026-09-07; operador SOC desde el 2026-09-08): parece
    una consulta, pero por debajo llama a ``aplicabilidad.responder_cve``, que evalua la
    amenaza y escribe la fila de ``aplicabilidad`` del activo. Los perfiles de remediacion
    y el de «Solo lectura» no modifican nada."""
    activo = _cargar_activo(activo_id)
    if activo is None:
        flash("El activo no existe.", "error")
        return redirect(url_for("activos.lista"))
    cve = (request.form.get("cve") or "").strip().upper()
    if not _RE_CVE.match(cve):
        flash("Escriba un identificador con el formato CVE-AAAA-NNNN.", "error")
        return _render_detalle(activo, cve_consultado=cve)
    try:
        with db.session(current_app.config.get("DB_PATH")) as conn:
            respuesta = aplicabilidad.responder_cve(conn, activo_id, cve, cfg=g.cfg)
            db.audit(conn, g.usuario, "activo.consulta_cve", "activos", activo_id,
                     f"{cve} -> {respuesta['veredicto']}", request.remote_addr)
    except Exception as exc:  # noqa: BLE001
        flash(f"No se pudo evaluar {cve}: {exc}", "error")
        return _render_detalle(activo, cve_consultado=cve)
    activo = _cargar_activo(activo_id) or activo
    return _render_detalle(activo, respuesta=respuesta, cve_consultado=cve)


MAX_FICHERO_IMPORTACION = 40 * 1024 * 1024


def _leer_fichero_subido(campo: str = "archivo") -> tuple[Optional[bytes], str, Optional[str]]:
    """(contenido, nombre, error). Limita el tamano y rechaza nombres raros."""
    archivo = request.files.get(campo)
    if not archivo or not archivo.filename:
        return None, "", "Seleccione un fichero."
    nombre = re.sub(r"[^A-Za-z0-9_.\-]+", "_", archivo.filename)[:120]
    contenido = archivo.read(MAX_FICHERO_IMPORTACION + 1)
    if len(contenido) > MAX_FICHERO_IMPORTACION:
        return None, nombre, "El fichero supera los 40 MB."
    if not contenido.strip():
        return None, nombre, "El fichero está vacío."
    return contenido, nombre, None


@bp.route("/<int:activo_id>/sbom", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def importar_sbom(activo_id: int):
    """Sube un SBOM (CycloneDX o SPDX en JSON) y evalua sus componentes con OSV.dev."""
    if g.db.execute("SELECT 1 FROM activos WHERE id=?", (activo_id,)).fetchone() is None:
        flash("El activo no existe.", "error")
        return redirect(url_for("activos.lista"))
    contenido, nombre, error = _leer_fichero_subido()
    if error:
        flash(error, "error")
        return redirect(url_for("activos.detalle", activo_id=activo_id) + "#sbom")
    try:
        with db.session(current_app.config.get("DB_PATH")) as conn:
            r = sbom.importar(conn, activo_id, contenido, fichero=nombre)
            ev = sbom.evaluar(conn, activo_id, cfg=g.cfg)
            db.audit(conn, g.usuario, "activo.sbom", "activos", activo_id,
                     f"{nombre}: {r['componentes']} componentes, {ev['vulnerabilidades']} vulnerabilidades", request.remote_addr)
    except sbom.ErrorSBOM as exc:
        flash(f"No se pudo importar el SBOM: {exc}", "error")
        return redirect(url_for("activos.detalle", activo_id=activo_id) + "#sbom")
    except Exception as exc:  # noqa: BLE001
        flash(f"Error al procesar el SBOM: {exc}", "error")
        return redirect(url_for("activos.detalle", activo_id=activo_id) + "#sbom")
    flash(f"SBOM {r['formato']} importado: {r['componentes']} componentes ({r['evaluables']} evaluables), "
          f"{ev['vulnerabilidades']} vulnerabilidad{'es' if ev['vulnerabilidades'] != 1 else ''} confirmada{'s' if ev['vulnerabilidades'] != 1 else ''} "
          f"en OSV.dev" + (f"; avisos: {'; '.join(ev['errores'][:2])}" if ev["errores"] else ""), "exito" if not ev["errores"] else "aviso")
    return redirect(url_for("activos.detalle", activo_id=activo_id) + "#sbom")


@bp.route("/<int:activo_id>/openscap", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def importar_openscap(activo_id: int):
    """Sube resultados de OpenSCAP (XCCDF o ARF) y guarda el cumplimiento por regla."""
    if g.db.execute("SELECT 1 FROM activos WHERE id=?", (activo_id,)).fetchone() is None:
        flash("El activo no existe.", "error")
        return redirect(url_for("activos.lista"))
    contenido, nombre, error = _leer_fichero_subido()
    if error:
        flash(error, "error")
        return redirect(url_for("activos.detalle", activo_id=activo_id) + "#openscap")
    try:
        with db.session(current_app.config.get("DB_PATH")) as conn:
            r = openscap.importar(conn, activo_id, contenido, fichero=nombre)
            db.audit(conn, g.usuario, "activo.openscap", "activos", activo_id,
                     f"{nombre}: {r['reglas']} reglas, {r['conteo'].get('fail', 0)} incumplidas", request.remote_addr)
    except openscap.ErrorOpenSCAP as exc:
        flash(f"No se pudo importar el resultado de OpenSCAP: {exc}", "error")
        return redirect(url_for("activos.detalle", activo_id=activo_id) + "#openscap")
    flash(f"OpenSCAP importado ({r['perfil']}): {r['reglas']} reglas, {r['conteo'].get('pass', 0)} cumplen y "
          f"{r['conteo'].get('fail', 0)} no cumplen.", "exito")
    return redirect(url_for("activos.detalle", activo_id=activo_id) + "#openscap")


@bp.route("/<int:activo_id>/remediacion")
@auth.requiere_login
def remediacion(activo_id: int):
    """Plan de remediacion de todas las vulnerabilidades confirmadas de un activo."""
    activo = _cargar_activo(activo_id)
    if activo is None:
        flash("El activo no existe.", "error")
        return redirect(url_for("activos.lista"))
    plan = aplicabilidad.plan_remediacion(g.db, activo_id=activo_id)
    if request.args.get("formato") == "txt":
        texto = aplicabilidad.plan_remediacion_texto(plan, titulo=f"Plan de remediación · {activo['nombre']}")
        nombre = re.sub(r"[^A-Za-z0-9_.-]+", "_", activo["nombre"])[:60] or "activo"
        return Response(texto, mimetype="text/plain; charset=utf-8",
                        headers={"Content-Disposition": f"attachment; filename=remediacion_{nombre}.txt"})
    # Un activo retirado de OCS Inventory no tiene plan: la pagina decia «0
    # actualizaciones por aplicar · No hay activos con la version vulnerable: nada que
    # remediar» mientras su ficha ensenaba 155 remediaciones congeladas (revision de
    # claridad del 2026-09-15). Se le pasa a la plantilla el mismo dato que a la ficha
    # para que las dos digan lo mismo.
    congeladas = (_remediacion.contar_congeladas_activo(g.db, activo_id)
                  if activo.get("retirado") else 0)
    retirado = ({"desde": activo.get("retirado_desde"),
                 "vulnerabilidades": int(aplicabilidad.conteo_activo(g.db, activo_id).get("afectado") or 0),
                 "remediaciones": _remediacion.contar_historial_activo(g.db, activo_id),
                 "congeladas": congeladas}
                if activo.get("retirado") else None)
    return render_template("remediacion.html", plan=plan, activo=activo, amenaza=None,
                           retirado=retirado,
                           titulo=f"Plan de remediación de {activo['nombre']}", entorno_es=ocs.ENTORNO_ES)


# --------------------------------------------------------------------------
# Software y mapa de nombres
# --------------------------------------------------------------------------
def _tecnologias_con_activos(*, limite: int, desplazamiento: int = 0) -> list[dict]:
    """Tecnologias del inventario realmente instaladas, una pagina cada vez (2026-09-07)."""
    filas = []
    for r in g.db.execute(
            """SELECT id, name, slug, criticality, activos_ocs, versiones_ocs, version_installed, systems_count
                 FROM technologies WHERE COALESCE(activos_ocs, 0) > 0
                ORDER BY activos_ocs DESC, name, id
                LIMIT ? OFFSET ?""", (int(limite), int(desplazamiento))):
        fila = dict(r)
        try:
            versiones = json.loads(fila.get("versiones_ocs") or "[]")
        except ValueError:
            versiones = []
        fila["versiones"] = versiones
        fila["n_versiones"] = len(versiones)
        fila["dispersion"] = len(versiones) >= 4
        filas.append(fila)
    return filas


@bp.route("/software")
@auth.requiere_login
def software():
    """Software instalado y mapa de nombres, con los tres listados largos paginados
    en el servidor (2026-09-07).

    Las tres tablas de esta pagina crecen sin techo: 10.542 nombres de programa
    distintos, 9.372 reglas del mapa (192 manuales o del mapa base y el resto
    automaticas) y 166 tecnologias con activos. Cada una tiene su propio numero de
    pagina en la direccion, para poder avanzar en una sin perder el sitio en las
    otras: ``pagina`` (software sin clasificar), ``pagina_reglas`` y
    ``pagina_tecnologias``. El total de cada tabla sale de una consulta de recuento,
    no de traerse las filas.
    """
    q = (request.args.get("q") or "").strip()[:80]
    resumen = ocs.resumen(g.db, cfg=g.cfg)

    # --- 1. software sin clasificar: paginado, con el buscador del propio panel ----
    condiciones_sc = ["s.technology_id IS NULL", "a.presente=1"]
    params_sc: list[Any] = []
    if q:
        condiciones_sc.append("s.nombre_norm LIKE ? ESCAPE '\\'")
        params_sc.append(_patron_like(q.lower()))
    where_sc = " AND ".join(condiciones_sc)
    total_sin_clasificar = int(g.db.execute(
        f"""SELECT COUNT(*) FROM (SELECT 1 FROM activo_software s JOIN activos a ON a.id=s.activo_id
              WHERE {where_sc} GROUP BY s.nombre_norm)""", params_sc).fetchone()[0] or 0)
    pagina_sc, paginas_sc = _pagina_valida(
        request.args.get("pagina", 1, type=int), total_sin_clasificar, POR_PAGINA)
    sin_clasificar = [dict(r) for r in g.db.execute(
        f"""SELECT s.nombre_norm, MIN(s.nombre) AS nombre, COUNT(DISTINCT s.activo_id) AS activos,
                   COUNT(DISTINCT s.version) AS versiones
              FROM activo_software s JOIN activos a ON a.id=s.activo_id
             WHERE {where_sc}
             GROUP BY s.nombre_norm ORDER BY activos DESC, s.nombre_norm
             LIMIT ? OFFSET ?""", params_sc + [POR_PAGINA, (pagina_sc - 1) * POR_PAGINA])]
    for f in sin_clasificar:
        f["tecnologia_id"] = f["tecnologia"] = None

    # Las propuestas automaticas son un panel aparte y no dependen del buscador: son
    # los nombres sin clasificar que se parecen a una tecnologia o a un alias.
    propuestas = [p for p in ocs.proponer_mapa(g.db, limite=60, minimo_activos=2)
                  if p.get("tecnologia_id")]

    # --- 2. reglas del mapa de nombres: paginadas ---------------------------------
    condicion = ("" if not q else
                 " AND (m.patron LIKE ? ESCAPE '\\' OR t.name LIKE ? ESCAPE '\\')")
    params_reglas: list[Any] = [] if not q else [_patron_like(q.lower()), _patron_like(q)]
    # Las automaticas (una por nombre de programa) solo se listan si se buscan: son
    # miles y no aportan al operador mientras no pregunte por un nombre concreto.
    where_reglas = (f"""FROM tecnologia_ocs m JOIN technologies t ON t.id=m.technology_id
             WHERE (m.origen <> 'automatico'{' OR 1=1' if q else ''}){condicion}""")
    total_reglas = int(g.db.execute(
        f"SELECT COUNT(*) {where_reglas}", params_reglas).fetchone()[0] or 0)
    pagina_reglas, paginas_reglas = _pagina_valida(
        request.args.get("pagina_reglas", 1, type=int), total_reglas, POR_PAGINA)
    reglas = [dict(r) for r in g.db.execute(
        f"""SELECT m.*, t.name AS tecnologia, t.slug {where_reglas}
             ORDER BY CASE m.origen WHEN 'manual' THEN 0 WHEN 'semilla' THEN 1 ELSE 2 END,
                      t.name, m.patron, m.id
             LIMIT ? OFFSET ?""", params_reglas + [POR_PAGINA, (pagina_reglas - 1) * POR_PAGINA])]
    n_automaticas = g.db.execute("SELECT COUNT(*) FROM tecnologia_ocs WHERE origen='automatico'").fetchone()[0]
    if reglas:
        # Activos por nombre de programa, una sola consulta; a cuantos activos afecta
        # cada regla se cuenta en memoria, solo para las reglas de ESTA pagina.
        activos_por_nombre = {r["nombre_norm"]: int(r["n"]) for r in g.db.execute(
            """SELECT s.nombre_norm, COUNT(DISTINCT s.activo_id) AS n FROM activo_software s
                 JOIN activos a ON a.id=s.activo_id WHERE a.presente=1 GROUP BY s.nombre_norm""")}
        for r in reglas:
            r["modo_es"] = ocs.MODO_MAPA_ES.get(r["modo"], r["modo"])
            patron = (r["patron"] or "").lower()
            if r["modo"] == "exacto":
                r["activos"] = activos_por_nombre.get(patron, 0)
            elif r["modo"] == "prefijo":
                r["activos"] = sum(n for nombre, n in activos_por_nombre.items() if nombre.startswith(patron))
            else:
                try:
                    rx = re.compile(r["patron"] or "", re.IGNORECASE)
                    r["activos"] = sum(n for nombre, n in activos_por_nombre.items() if rx.search(nombre))
                except re.error:
                    r["activos"] = 0

    # --- 3. tecnologias con activos: paginadas ------------------------------------
    total_con_activos = int(g.db.execute(
        "SELECT COUNT(*) FROM technologies WHERE COALESCE(activos_ocs, 0) > 0").fetchone()[0] or 0)
    pagina_tec, paginas_tec = _pagina_valida(
        request.args.get("pagina_tecnologias", 1, type=int), total_con_activos, POR_PAGINA)
    con_activos = _tecnologias_con_activos(limite=POR_PAGINA, desplazamiento=(pagina_tec - 1) * POR_PAGINA)

    tecnologias = [dict(r) for r in g.db.execute("SELECT id, name FROM technologies ORDER BY name")]
    # Cada paginacion conserva los argumentos de las otras dos y el buscador.
    args = _args_a_conservar("pagina", "pagina_reglas", "pagina_tecnologias")
    return render_template(
        "software.html", resumen=resumen, reglas=reglas, n_automaticas=n_automaticas,
        sin_clasificar=sin_clasificar, propuestas=propuestas, tecnologias=tecnologias,
        con_activos=con_activos, q=q, por_pagina=POR_PAGINA, args=args,
        total_sin_clasificar=total_sin_clasificar, pagina_sc=pagina_sc, paginas_sc=paginas_sc,
        args_sin_clasificar=_args_a_conservar("pagina"),
        total_reglas=total_reglas, pagina_reglas=pagina_reglas, paginas_reglas=paginas_reglas,
        args_reglas=_args_a_conservar("pagina_reglas"),
        total_con_activos=total_con_activos, pagina_tec=pagina_tec, paginas_tec=paginas_tec,
        args_tecnologias=_args_a_conservar("pagina_tecnologias"),
        modos=ocs.MODOS_MAPA, modo_es=ocs.MODO_MAPA_ES,
        graf={"mapa": [{"clave": "exito", "nombre": "Clasificado", "valor": resumen["instalaciones_mapeadas"]},
                       {"clave": "neutro", "nombre": "Sin clasificar",
                        "valor": max(resumen["instalaciones"] - resumen["instalaciones_mapeadas"], 0)}]})


def _reaplicar_mapa(conn) -> None:
    ocs.aplicar_mapa(conn)
    ocs.actualizar_inventario_desde_ocs(conn, cfg=g.cfg)


@bp.route("/software/regla", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def regla_nueva():
    patron = (request.form.get("patron") or "").strip().lower()[:200]
    modo = (request.form.get("modo") or "exacto").strip()
    fuente = (request.form.get("paquete_fuente") or "").strip().lower()[:120] or None
    try:
        tec_id = int(request.form.get("technology_id") or 0)
    except ValueError:
        tec_id = 0
    if not patron or modo not in ocs.MODOS_MAPA or not tec_id:
        flash("Indique el nombre del programa, el modo y la tecnología.", "error")
        return redirect(url_for("activos.software"))
    if modo == "regex":
        try:
            re.compile(patron)
        except re.error as exc:
            flash(f"La expresión regular no es válida: {exc}", "error")
            return redirect(url_for("activos.software"))
    try:
        with db.session(current_app.config.get("DB_PATH")) as conn:
            if conn.execute("SELECT 1 FROM technologies WHERE id=?", (tec_id,)).fetchone() is None:
                flash("La tecnología no existe.", "error")
                return redirect(url_for("activos.software"))
            conn.execute(
                """INSERT INTO tecnologia_ocs(patron, modo, technology_id, paquete_fuente, origen, created_at, created_by)
                   VALUES(?,?,?,?,'manual',?,?)
                   ON CONFLICT(patron, modo) DO UPDATE SET technology_id=excluded.technology_id,
                       paquete_fuente=excluded.paquete_fuente, origen='manual', created_by=excluded.created_by""",
                (patron, modo, tec_id, fuente, db.utcnow(), g.usuario))
            ocs.retirar_automaticas(conn, patron, modo)
            _reaplicar_mapa(conn)
            db.audit(conn, g.usuario, "activos.mapa_crear", "tecnologia_ocs", None,
                     f"{modo}:{patron} -> {tec_id}", request.remote_addr)
        flash(f"Regla guardada: «{patron}» ({ocs.MODO_MAPA_ES.get(modo, modo).lower()}). "
              f"El software ya aparece clasificado.", "exito")
    except Exception as exc:  # noqa: BLE001
        flash(f"No se pudo guardar la regla: {exc}", "error")
    return redirect(url_for("activos.software"))


@bp.route("/software/regla/<int:regla_id>/borrar", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def regla_borrar(regla_id: int):
    with db.session(current_app.config.get("DB_PATH")) as conn:
        fila = conn.execute("SELECT patron, modo FROM tecnologia_ocs WHERE id=?", (regla_id,)).fetchone()
        conn.execute("DELETE FROM tecnologia_ocs WHERE id=?", (regla_id,))
        _reaplicar_mapa(conn)
        db.audit(conn, g.usuario, "activos.mapa_borrar", "tecnologia_ocs", regla_id,
                 f"{fila['modo']}:{fila['patron']}" if fila else None, request.remote_addr)
    flash("Regla eliminada; el software afectado vuelve a estar sin clasificar.", "info")
    return redirect(url_for("activos.software"))


@bp.route("/software/sembrar", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def sembrar_mapa():
    with db.session(current_app.config.get("DB_PATH")) as conn:
        creadas = ocs.sembrar_mapa(conn, actor=g.usuario or "web")
        _reaplicar_mapa(conn)
        db.audit(conn, g.usuario, "activos.mapa_sembrar", "tecnologia_ocs", None, f"creadas={creadas}",
                 request.remote_addr)
    flash(f"Mapa base cargado: {creadas} regla{'s' if creadas != 1 else ''} nueva{'s' if creadas != 1 else ''}.",
          "exito" if creadas else "info")
    return redirect(url_for("activos.software"))


# --------------------------------------------------------------------------
# Sincronizacion y exportacion
# --------------------------------------------------------------------------
@bp.route("/sincronizar", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def sincronizar():
    """Lanza bin/sincronizar_ocs.py en segundo plano: tarda varios minutos y no
    debe bloquear la peticion web."""
    en_curso = g.db.execute(
        "SELECT 1 FROM sync_ocs WHERE status='running' AND started_at > ? LIMIT 1",
        ((datetime.now(timezone.utc) - timedelta(minutes=30)).replace(microsecond=0)
         .isoformat().replace("+00:00", "Z"),)).fetchone()
    if en_curso:
        flash("Ya hay una sincronización en curso. Espere a que termine.", "aviso")
        return redirect(url_for("activos.lista"))
    guion = BASE_DIR / "bin" / "sincronizar_ocs.py"
    try:
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        salida = open(LOGS_DIR / "sincronizar_ocs_web.log", "ab")
        argumentos = [sys.executable, str(guion)]
        if current_app.config.get("DB_PATH"):
            argumentos += ["--db", str(current_app.config["DB_PATH"])]
        subprocess.Popen(argumentos, cwd=str(BASE_DIR), stdout=salida, stderr=subprocess.STDOUT,
                         stdin=subprocess.DEVNULL, start_new_session=True, close_fds=True)
        salida.close()
        with db.session(current_app.config.get("DB_PATH")) as conn:
            db.audit(conn, g.usuario, "activos.sincronizar", "activos", None, "lanzada desde la interfaz",
                     request.remote_addr)
        flash("Sincronización con OCS iniciada en segundo plano. Suele tardar entre dos y cinco minutos; "
              "recargue la página para ver el resultado.", "exito")
    except Exception as exc:  # noqa: BLE001
        flash(f"No se pudo lanzar la sincronización: {exc}", "error")
    return redirect(url_for("activos.lista"))


@bp.route("/exportar.csv")
@auth.requiere_login
def exportar():
    filtros = _leer_filtros()
    umbral = _umbral(g.cfg)
    tabla_eol = aplicabilidad.tabla_fin_soporte(g.db)
    sin_bajas = _sin_bajas()
    # El CSV es la misma lista que la pagina: mismas condiciones, mismas cifras.
    sin_excepcion = _sin_excepcion()
    where, params = _condiciones(filtros, umbral, sin_bajas, sin_excepcion)
    sql_where = (" WHERE " + " AND ".join(where)) if where else ""
    salida = io.StringIO()
    escritor = csv.writer(salida, delimiter=";")
    # El usuario pidio el 2026-09-07 que «entorno» y «proceso» salieran en el CSV:
    # faltaban los dos y son justo lo que se usa para repartir el trabajo. «zona» es
    # otra cosa (la zona de red) y se conserva.
    escritor.writerow(["activo", "tipo", "entorno", "proceso", "ip", "sistema", "version_sistema",
                       "zona", "ultimo_inventario", "sin_reportar", "fin_de_soporte",
                       "software_total", "software_clasificado", "vulnerabilidades_confirmadas",
                       "con_explotacion_activa", "hallazgos", "presente"])
    for r in g.db.execute(f"SELECT a.*, {_subconsultas(sin_bajas, sin_excepcion)} FROM activos a{sql_where} "
                          f"ORDER BY a.origen, a.nombre", params):
        a = _etiquetar(dict(r), tabla_eol, umbral)
        sop = a.get("soporte") or {}
        escritor.writerow([celda_csv(v) for v in [
            a["nombre"], a["origen_es"], a.get("entorno_es") or "Sin entorno",
            a.get("proceso") or "Sin proceso",
            a.get("ip") or "", a.get("so_nombre") or "", a.get("so_version") or "",
            a["zona_es"], (a.get("ultimo_inventario") or "")[:19], "sí" if a["sin_reportar"] else "no",
            sop.get("eol") or "", a.get("n_software") or 0, a.get("n_mapeado") or 0, a.get("afectados") or 0,
            a.get("kev") or 0, ", ".join(a["hallazgos_es"]), "sí" if a.get("presente") else "no"]])
    return Response("﻿" + salida.getvalue(), mimetype="text/csv; charset=utf-8",
                    headers={"Content-Disposition": "attachment; filename=activos.csv"})


@bp.route("/<int:activo_id>/exportar.csv")
@auth.requiere_login
def exportar_activo(activo_id: int):
    activo = _cargar_activo(activo_id)
    if activo is None:
        flash("El activo no existe.", "error")
        return redirect(url_for("activos.lista"))
    salida = io.StringIO()
    escritor = csv.writer(salida, delimiter=";")
    escritor.writerow(["cve", "veredicto", "paquete", "version_instalada", "version_corregida", "motor",
                       "aviso", "evidencia", "amenaza", "severidad", "kev", "evaluado"])
    for v in aplicabilidad.veredictos_de_activo(g.db, activo_id, limite=5000):
        escritor.writerow([celda_csv(x) for x in [
            v["cve"], aplicabilidad.VEREDICTO_ES.get(v["veredicto"], v["veredicto"]), v["paquete"],
            v.get("version_instalada") or "", v.get("version_corregida") or "",
            aplicabilidad.MOTOR_ES.get(v["motor"], v["motor"]), v.get("aviso") or "", v.get("evidencia") or "",
            v.get("title_es") or v.get("title_en") or "", v.get("severity") or "", "sí" if v.get("in_kev") else "no",
            (v.get("evaluado_at") or "")[:19]]])
    nombre = re.sub(r"[^A-Za-z0-9_.-]+", "_", activo["nombre"])[:60] or "activo"
    return Response("﻿" + salida.getvalue(), mimetype="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f"attachment; filename=activo_{nombre}.csv"})

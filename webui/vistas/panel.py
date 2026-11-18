"""Panel de estado y endpoint de salud para monitorizacion.

Rediseño del 2026-09-03 (sección 6 «Panel» de docs/DISENO_INTERFAZ_2026-09-03.md).
La vista prepara los datos de los gráficos como listas y diccionarios simples
y la plantilla los pinta con ``graficos.<función>(...)``. Las consultas que no
existen en ``threatintel.queries`` (procedencia por ``severity_source``,
cobertura del inventario, última ejecución por tipo, última alerta, total de
pendientes) viven aquí como SQL local en funciones pequeñas: ``queries.py`` no
se edita desde el panel (lo edita Tendencias).

Orden de lectura de la página: qué pasa ahora (avisos y diagrama de flujo),
cuánto y cómo evoluciona (métricas con chispa, barras apiladas, donas), detalle
en tablas y glosario.
"""
from __future__ import annotations

import calendar
import sqlite3
from datetime import date, datetime, timedelta, timezone
from typing import Any, Iterable, Optional

from flask import Blueprint, abort, g, jsonify, render_template, request, url_for

from threatintel import excepciones, ocs, queries
from threatintel.collector import TIPOS_RECOLECTABLES as _TIPOS_RECOLECTABLES
from webui import auth
from webui.filtros import MESES, _parse, hace, mes_es

bp = Blueprint("panel", __name__)

# Etiquetas visibles en español (regla 7 de la especificación: sin abreviaturas).
TIPO_EJECUCION = {
    "daily": "Recolección diaria", "monthly": "Informe mensual",
    "health": "Comprobación de salud", "smtp_verify": "Verificación del correo",
    "enrich": "Enriquecimiento",
}
ESTADO_EJECUCION = {  # estado -> (texto, clase de insignia)
    "success": ("Correcta", "ok"), "partial": ("Parcial", "medium"),
    "failed": ("Fallida", "critical"), "running": ("En curso", "neutra"),
}
CRITICIDAD_ES = {"critical": "Crítica", "high": "Alta", "medium": "Media", "low": "Baja"}

#: Procedencia de la severidad: (valor en BD, nombre visible, clave de color).
#: El dato oficial va en éxito; el vector CVSS (calculado, pero exacto) en el
#: secundario; KEV con su color propio; la heurística en «medio» porque es una
#: estimación que conviene vigilar.
PROCEDENCIA = (
    ("nvd", "CVSS oficial (NVD)", "exito"),
    ("vector", "CVSS calculado del vector", "secundario"),
    ("kev", "Severidad tomada del catálogo KEV", "kev"),
    ("heuristic", "Severidad estimada", "medio"),
)

#: Bloque «Estado de los activos (OCS Inventory)»: las cuatro cifras con las que abre
#: el correo de alerta diario, en su mismo orden y con su misma etiqueta
#: (threatintel/emails/alerta.html, bucle sobre ``resumen_activos``). Cada tupla es
#: (etiqueta visible, clave del resumen, clase de color, filtro de /activos/ al que
#: enlaza la cifra). El usuario no encontraba estas cifras en la plataforma porque el
#: panel las llamaba de otra manera (petición del 2026-09-06): ahora se llaman igual,
#: salen del mismo cálculo y cada una abre la lista de activos ya filtrada.
#: Las cuatro filas del bloque «Estado de los activos», en el mismo orden y con las
#: mismas etiquetas que el resumen semanal, que es donde vive ahora ese bloque del correo.
#:
#: Cada fila lleva DOS cifras y las dos dicen lo que cuentan (2026-09-07): un ACTIVO
#: afectado es un equipo con al menos una vulnerabilidad; una VULNERABILIDAD es un CVE en
#: un activo (2026-09-09: si toca varios paquetes de la misma maquina cuenta una sola
#: vez), asi que el mismo fallo en cien activos son cien vulnerabilidades y un solo CVE.
#: Antes ponia «772 con vulnerabilidades confirmadas» y no se sabia si eran activos o
#: vulnerabilidades.
#:
#: «Sin reportar» ya no esta aqui: es mantenimiento del inventario, no seguridad, y tiene
#: su propio informe (bin/informe_inventario.py). Sigue accesible desde Activos.
CIFRAS_ACTIVOS = (
    ("Con al menos una vulnerabilidad confirmada", "activos_afectados",
     "vulnerabilidades", "critico", {"vista": "afectados"}),
    ("En producción o contingencia", "expuestos_activos",
     "expuestos_vulnerabilidades", "critico",
     {"vista": "afectados", "entorno": "produccion"}),
    ("Fuera de soporte y con vulnerabilidades", "fuera_soporte_con_vulnerabilidades",
     "fuera_soporte_vulnerabilidades", "alto", {"vista": "fuera_soporte"}),
    ("Fuera de soporte, sin vulnerabilidades conocidas hoy",
     "fuera_soporte_sin_vulnerabilidades", None, "medio", {"vista": "fuera_soporte"}),
    # 2026-09-10: la quinta fila. Hasta hoy el bloque decía «las máquinas que no reportan
    # no están aquí», y era falso: sí estaban, contadas en las cuatro cifras de arriba
    # con un dato de hace más de un mes. Ahora se dicen con su nombre, con cuántas
    # vulnerabilidades arrastran y con enlace a su lista, y las cuatro cifras de arriba
    # llevan escrito cuántos de sus activos son de este grupo.
    ("Sin reportar: su dato es de hace más de {dias} días", "sin_reportar_activos",
     "sin_reportar_vulnerabilidades", "medio", {"vista": "sin_reportar"}),
)

#: Las dos filas del bloque que son cifras de RIESGO: son las que tienen que declarar
#: cuántos de sus activos llevan más de ``ocs_stale_days`` días sin reportar.
CIFRAS_CON_DATO = {
    "activos_afectados": ("activos_afectados_con_dato", "vulnerabilidades_con_dato"),
    "expuestos_activos": ("expuestos_activos_con_dato", "expuestos_vulnerabilidades_con_dato"),
}

#: Entornos expuestos con los que se calcula «En producción o contingencia». La lista
#: de activos filtra por un entorno a la vez (``webui/vistas/activos.py``, filtro
#: ``entorno``), así que la cifra ofrece los dos enlaces por separado.
ENTORNOS_EXPUESTOS_ES = (("producción", "produccion"), ("contingencia", "contingencia"))

#: Umbrales del diagrama de flujo (sección 6, punto 2: «umbrales razonables»).
UMBRAL_CAIDAS_ATENCION = 0.20      # < 20 % de fuentes caídas → atención; más → crítico
UMBRAL_PENDIENTES_ENRIQUECER = 500  # CVE sin enriquecer por encima → atención
DIAS_INFORME_VIGENTE = 35           # un informe mensual más antiguo → atención


def _cargar(modulo: str, funcion: str, *args, **kwargs):
    """Carga perezosa de los modulos de dominio.

    Permite que la interfaz arranque aunque un modulo aun no este disponible,
    en lugar de caerse por completo con un ImportError.
    """
    try:
        mod = __import__(f"threatintel.{modulo}", fromlist=[funcion])
        return getattr(mod, funcion)(*args, **kwargs), None
    except Exception as exc:  # noqa: BLE001 - se muestra al operador
        return None, f"{type(exc).__name__}: {exc}"


# --------------------------------------------------------------------------
# Consultas locales (SQL pequeño y documentado; no se toca queries.py)
# --------------------------------------------------------------------------
def _procedencia_severidad(conn: sqlite3.Connection, mes: str, *,
                           excluir_bajas: bool = True) -> dict[str, int]:
    """Recuento del mes por ``severity_source`` (nvd | vector | kev | heuristic).

    Cualquier valor no previsto se acumula en ``otros`` para que la barra de
    procedencia siempre sume el total del mes.

    ``excluir_bajas`` (regla interna, ajuste ``ignore_low_severity``, activo) deja fuera
    la severidad Baja, EXACTAMENTE como ``queries.estadisticas_mes``. Hasta el
    2026-09-15 no lo hacia y el mismo Panel daba dos totales del mismo mes: la tarjeta
    «Amenazas del periodo» decia 1.532 (sin bajas) y la barra «Procedencia de la
    severidad» sumaba 1.622 (con las 90 bajas dentro). De paso, el porcentaje de CVSS
    oficial salia con dos denominadores: 77 % en la barra (1.250 de 1.622) y 80 % en el
    paso de enriquecimiento del flujo (1.228 de 1.532). Con la baja fuera de los dos, el
    unico denominador posible es el del resto de la plataforma.
    """
    conteo = {origen: 0 for origen, _, _ in PROCEDENCIA}
    conteo["otros"] = 0
    filtro = " AND (severity IS NULL OR severity <> 'Low')" if excluir_bajas else ""
    for fila in conn.execute(
            "SELECT severity_source AS origen, COUNT(*) AS n FROM threats "
            f"WHERE month=?{filtro} GROUP BY severity_source", (mes,)):
        clave = fila["origen"] if fila["origen"] in conteo else "otros"
        conteo[clave] += fila["n"] or 0
    return conteo


def _enriquecimiento(conn: sqlite3.Connection, *, excluir_bajas: bool = True) -> dict[str, int]:
    """Progreso del enriquecimiento sobre las AMENAZAS CON CVE que la plataforma reporta.

    Tres partes excluyentes que suman ``con_cve``: con CVSS oficial de NVD,
    consultadas a NVD pero sin puntuación publicada, y pendientes de consultar
    (``enriched_at`` nulo, el mismo criterio que ``health.resumen_sistema``).

    ``con_cve`` cuenta AMENAZAS, no CVE distintos: una misma vulnerabilidad publicada por
    tres avisos son tres amenazas y un solo CVE. El rótulo de la página lo dice desde el
    2026-09-15 (auditoría de tableros, punto 11): decía «0 de 4.515 CVE siguen sin
    consultar» y los CVE distintos eran 4.308.

    ``excluir_bajas`` (regla interna, ajuste ``ignore_low_severity``, activo) deja fuera
    la severidad Baja y las amenazas ya cerradas por el equipo, que es el criterio del
    resto de la plataforma: con él la cifra pasa de 4.515 a 4.402, que es exactamente
    «4.402 de las 7.284 tienen identificador CVE» de la página de Amenazas.
    """
    filtro = ""
    if excluir_bajas:
        filtro = (" AND (severity IS NULL OR severity <> 'Low')"
                  f" AND (estado IS NULL OR estado NOT IN {queries._ESTADOS_CERRADOS_SQL})")
    fila = conn.execute(
        f"""SELECT COUNT(*) AS con_cve,
                  SUM(enriched_at IS NOT NULL AND severity_source='nvd')  AS con_cvss_oficial,
                  SUM(enriched_at IS NOT NULL AND severity_source<>'nvd') AS consultadas_sin_cvss,
                  SUM(enriched_at IS NULL)                                AS pendientes
             FROM threats WHERE cve IS NOT NULL{filtro}""").fetchone()
    return {k: int(fila[k] or 0) for k in fila.keys()}


def _cobertura_inventario(conn: sqlite3.Connection) -> dict[str, int]:
    """Tecnologías con y sin versión registrada (mismo criterio que health)."""
    fila = conn.execute(
        """SELECT COUNT(*) AS total,
                  SUM(CASE WHEN version_installed IS NOT NULL
                            AND version_installed <> '' THEN 1 ELSE 0 END) AS con_version
             FROM technologies""").fetchone()
    total = int(fila["total"] or 0)
    con_version = int(fila["con_version"] or 0)
    return {"total": total, "con_version": con_version,
            "sin_version": max(total - con_version, 0)}


def _expuestos_afectados(conn: sqlite3.Connection, *, cfg: Any = None) -> int:
    """Activos de producción o contingencia con una vulnerabilidad confirmada.

    Desde el 2026-09-10 (tarde) la calcula ``ocs.resumen`` y esta función solo la lee de
    ahí: es la única fuente del número y la comparten el Panel, el correo de alerta
    (``bin/ejecucion_diaria.py``) y el envío de prueba (``bin/enviar_prueba.py``). Antes
    la escribían a mano los tres, con la consulta copiada palabra por palabra, y ninguna
    de las tres copias dejaba fuera la severidad baja ni el riesgo aceptado de una
    excepción vigente, así que la misma pantalla mezclaba dos criterios: «con
    vulnerabilidades confirmadas» con uno y «en producción o contingencia» con otro.

    Una cifra que no se puede calcular (base sin la tabla, esquema anterior) devuelve 0 y
    no deja el panel entero sin bloque de activos, igual que hacía antes.
    """
    try:
        return int((ocs.resumen(conn, cfg=cfg) or {}).get("expuestos_afectados") or 0)
    except sqlite3.Error:
        return 0


def resumen_activos_correo(conn: sqlite3.Connection, *, cfg: Any = None) -> tuple[Optional[dict], Optional[str]]:
    """``ocs.resumen`` más ``expuestos_afectados``: las cifras generales del inventario.

    Alimenta el resto del panel (totales, familias de sistema, procesos). Las cuatro
    filas del bloque «Estado de los activos» salen de :func:`estado_activos_semanal`,
    que es la misma fuente que el resumen semanal.
    """
    resumen, error = _cargar("ocs", "resumen", conn, cfg=cfg)
    if resumen is not None:
        # ``ocs.resumen`` ya la trae (2026-09-10, tarde). El respaldo cubre una base con
        # un esquema anterior, donde la clave no existe.
        resumen.setdefault("expuestos_afectados", 0)
    return resumen, error


def estado_activos_semanal(conn: sqlite3.Connection, *, cfg: Any = None) -> tuple[Optional[dict], Optional[str]]:
    """Las mismas cifras del bloque que lleva el resumen semanal por correo.

    Una sola fuente para el correo y para el panel: si el panel las calculase por su
    cuenta podrían discrepar y el operador no sabría a cuál creer. Separan equipos de
    vulnerabilidades y no incluyen los activos que no reportan (2026-09-07).
    """
    return _cargar("ocs", "estado_activos", conn, cfg=cfg)


def _estado_activos_en_alcance(conn: sqlite3.Connection, origen: str, *, cfg: Any = None) -> Optional[dict]:
    """Las cifras de ``ocs.estado_activos`` para UN tipo de maquina (2026-09-08).

    El perfil de Redes solo ve servidores y el de Mantenimiento solo equipos de computo,
    y el Panel no puede ensenarles las cifras del parque entero. ``ocs.estado_activos``
    no acepta todavia un ``origen`` (no pertenece a esta vista), asi que se repiten aqui
    sus consultas, con sus mismas constantes (``_AMENAZA_VIVA``, ``_EXPUESTOS``) y una
    condicion mas: ``a.origen = ?``. En cuanto la funcion lo acepte, esta copia debe
    desaparecer y llamarse a la original.
    """
    excluir_bajas = bool((cfg or {}).get("ignore_low_severity", True)) if hasattr(cfg or {}, "get") else True
    viva = ocs._AMENAZA_VIVA + (" AND (t.severity IS NULL OR t.severity <> 'Low')" if excluir_bajas else "")
    # El riesgo aceptado tampoco cuenta (2026-09-10, tarde): la misma condición y en el
    # mismo sitio que en ``ocs.estado_activos``, del que esta función es la copia acotada
    # por tipo de máquina. Si solo la llevara una de las dos, el Panel de Redes y el del
    # SOC dirían cifras distintas del mismo servidor.
    viva += excepciones.y_sin_excepcion(conn, activo="ap.activo_id", cve="ap.cve",
                                        paquete="ap.paquete")
    marcadores = ",".join("?" * len(ocs._EXPUESTOS))
    try:
        presentes = conn.execute(
            """SELECT COUNT(*) AS total, SUM(origen='servidores') AS servidores,
                      SUM(origen='equipos') AS equipos
                 FROM activos WHERE presente=1 AND origen=?""", (origen,)).fetchone()
        confirmadas = conn.execute(
            f"""SELECT {queries.sql_vulnerabilidades()} AS vulnerabilidades,
                       COUNT(DISTINCT ap.activo_id) AS activos,
                       COUNT(DISTINCT ap.cve) AS cve,
                       {queries.sql_vulnerabilidades(condicion=f"a.entorno IN ({marcadores})")}
                           AS vulnerabilidades_expuestas
                  FROM aplicabilidad ap JOIN activos a ON a.id=ap.activo_id
                  LEFT JOIN threats t ON t.id=ap.threat_id
                 WHERE ap.veredicto='afectado' AND a.presente=1 AND a.origen=? AND {viva}""",
            (*ocs._EXPUESTOS, origen)).fetchone()
        activos_expuestos = conn.execute(
            f"""SELECT COUNT(DISTINCT ap.activo_id) FROM aplicabilidad ap
                  JOIN activos a ON a.id=ap.activo_id
                  LEFT JOIN threats t ON t.id=ap.threat_id
                 WHERE ap.veredicto='afectado' AND a.presente=1 AND a.origen=?
                   AND a.entorno IN ({marcadores}) AND {viva}""",
            (origen, *ocs._EXPUESTOS)).fetchone()[0]
        sin_soporte = conn.execute(
            f"""SELECT COUNT(DISTINCT h.activo_id) AS activos,
                       COUNT(DISTINCT CASE WHEN EXISTS (
                            SELECT 1 FROM aplicabilidad ap
                              LEFT JOIN threats t ON t.id=ap.threat_id
                             WHERE ap.activo_id=h.activo_id AND ap.veredicto='afectado'
                               AND {viva})
                         THEN h.activo_id END) AS con_vulnerabilidades
                  FROM hallazgos_activos h JOIN activos a ON a.id=h.activo_id
                 WHERE h.tipo='fin_soporte' AND h.resuelto_at IS NULL AND a.presente=1
                   AND a.origen=?""", (origen,)).fetchone()
        vulns_sin_soporte = conn.execute(
            f"""SELECT {queries.sql_vulnerabilidades()}
                  FROM aplicabilidad ap JOIN activos a ON a.id=ap.activo_id
                  LEFT JOIN threats t ON t.id=ap.threat_id
                 WHERE ap.veredicto='afectado' AND a.presente=1 AND a.origen=? AND {viva}
                   AND EXISTS (SELECT 1 FROM hallazgos_activos h
                                WHERE h.activo_id=ap.activo_id AND h.tipo='fin_soporte'
                                  AND h.resuelto_at IS NULL)""", (origen,)).fetchone()[0]
    except sqlite3.Error:
        return None
    total = int(presentes["total"] or 0)
    fuera_activos = int(sin_soporte["activos"] or 0)
    fuera_con = int(sin_soporte["con_vulnerabilidades"] or 0)
    return {
        "activos_presentes": total,
        "servidores": int(presentes["servidores"] or 0),
        "equipos": int(presentes["equipos"] or 0),
        "activos_afectados": int(confirmadas["activos"] or 0),
        "activos_sin_vulnerabilidades": total - int(confirmadas["activos"] or 0),
        "vulnerabilidades": int(confirmadas["vulnerabilidades"] or 0),
        "cve_distintos": int(confirmadas["cve"] or 0),
        "expuestos_activos": int(activos_expuestos or 0),
        "expuestos_vulnerabilidades": int(confirmadas["vulnerabilidades_expuestas"] or 0),
        "fuera_soporte_activos": fuera_activos,
        "fuera_soporte_con_vulnerabilidades": fuera_con,
        "fuera_soporte_sin_vulnerabilidades": max(0, fuera_activos - fuera_con),
        "fuera_soporte_vulnerabilidades": int(vulns_sin_soporte or 0),
        "acotado": origen,
    }


def _resumen_activos_en_alcance(conn: sqlite3.Connection, resumen: Optional[dict],
                                origen: str) -> Optional[dict]:
    """El resumen general del inventario (``ocs.resumen``) con los totales de UN tipo de
    maquina (2026-09-08): total y reparto por tipo. El porcentaje de software clasificado
    es del inventario entero y se conserva."""
    if not resumen:
        return resumen
    acotado = dict(resumen)
    propios = int(resumen.get(origen) or 0)
    acotado.update({"total": propios,
                    "servidores": propios if origen == "servidores" else 0,
                    "equipos": propios if origen == "equipos" else 0,
                    "acotado": origen})
    return acotado


def _cifras_activos(estado: Optional[dict]) -> list[dict]:
    """Las cuatro filas del bloque, en el orden del resumen semanal, con su enlace.

    ``estado`` es lo que devuelve ``ocs.estado_activos``. Cada fila trae el numero de
    equipos y, cuando tiene sentido, el de vulnerabilidades, para que se lea sin
    ambiguedad (2026-09-07). Cada cifra enlaza a la vista rapida o al filtro de entorno
    equivalente de ``/activos/``; el cero se pinta en gris, que no es un riesgo.
    """
    if not estado or not estado.get("activos_presentes"):
        return []
    cifras = []
    dias = int(estado.get("dias_sin_reportar") or 30)
    for etiqueta, clave_activos, clave_vulns, color, filtro in CIFRAS_ACTIVOS:
        activos = int(estado.get(clave_activos) or 0)
        vulns = int(estado.get(clave_vulns) or 0) if clave_vulns else None
        cifra = {"etiqueta": etiqueta.format(dias=dias), "clave": clave_activos,
                 "valor": activos,
                 "vulnerabilidades": vulns,
                 "color": color if activos else "neutro",
                 "href": url_for("activos.lista", **filtro)}
        # Las dos cifras de riesgo declaran su parte de dato viejo (2026-09-10): la
        # misma magnitud calculada solo sobre los activos que reportan al día, y cuántos
        # quedan fuera de esa cuenta. Sin esto, una de las dos cifras del bloque los
        # contaría y otra no, sin decirlo.
        if clave_activos in CIFRAS_CON_DATO:
            clave_a, clave_v = CIFRAS_CON_DATO[clave_activos]
            con_dato = int(estado.get(clave_a) or 0)
            cifra["con_dato"] = con_dato
            cifra["vulnerabilidades_con_dato"] = int(estado.get(clave_v) or 0)
            cifra["dato_viejo"] = max(0, activos - con_dato)
            cifra["dias_sin_reportar"] = dias
            cifra["href_sin_reportar"] = url_for("activos.lista", vista="sin_reportar")
        if clave_activos == "sin_reportar_activos":
            cifra["mantenimiento"] = True
            cifra["dias_sin_reportar"] = dias
        if clave_activos == "expuestos_activos":
            cifra["entornos"] = [
                {"nombre": nombre,
                 "href": url_for("activos.lista", vista="afectados", entorno=entorno)}
                for nombre, entorno in ENTORNOS_EXPUESTOS_ES]
        cifras.append(cifra)
    return cifras


def _ultima_ejecucion(conn: sqlite3.Connection, kind: str) -> Optional[dict]:
    """Última fila de ``executions`` de un tipo (daily, monthly…), o None."""
    fila = conn.execute(
        "SELECT * FROM executions WHERE kind=? ORDER BY started_at DESC LIMIT 1",
        (kind,)).fetchone()
    return dict(fila) if fila else None


def _ultima_recoleccion(conn: sqlite3.Connection) -> Optional[dict]:
    """Última corrida diaria que DE VERDAD recolectó de las fuentes.

    Por qué (auditoría de tableros del 2026-09-15, punto 1): el cron lanza dos corridas
    de tipo ``daily`` cada día, la recolección de las 12:30 (consulta las fuentes y
    escribe ``threats_new``) y el envío de la alerta de las 13:00 (no consulta ninguna
    fuente y escribe ``threats_alerted``). El paso «Correlación» del flujo tomaba
    simplemente la última fila y por eso decía «0 amenazas nuevas en la última
    recolección» el mismo día en que la tabla «Últimas ejecuciones» de la misma página
    enseñaba 261. Aquí se pide la última que consultó fuentes (``sources_ok > 0``); la
    corrida más reciente se sigue usando para el paso «Alerta».

    Si ninguna corrida trae ese dato (base antigua) se devuelve la última diaria, que es
    exactamente lo que se hacía antes: nunca se queda el paso sin cifra.
    """
    fila = conn.execute(
        "SELECT * FROM executions WHERE kind='daily' AND COALESCE(sources_ok,0) > 0 "
        "ORDER BY started_at DESC LIMIT 1").fetchone()
    return dict(fila) if fila else _ultima_ejecucion(conn, "daily")


def _ultima_alerta(conn: sqlite3.Connection, ahora: datetime) -> dict[str, Any]:
    """Fecha de la última amenaza alertada y cuántas se alertaron en 24 horas."""
    limite = (ahora - timedelta(hours=24)).replace(microsecond=0)
    limite_iso = limite.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    fila = conn.execute(
        """SELECT MAX(alerted_at) AS ultima,
                  SUM(alerted_at >= ?) AS en_24h
             FROM threats WHERE alerted_at IS NOT NULL""", (limite_iso,)).fetchone()
    return {"ultima": fila["ultima"], "en_24h": int(fila["en_24h"] or 0)}


def _total_pendientes(conn: sqlite3.Connection, min_severidad: str) -> int:
    """Amenazas nunca alertadas que alcanzan la severidad mínima configurada.

    ``queries.pendientes_de_alerta`` devuelve las filas (limitadas a 5 en el
    panel); aquí solo hace falta el total para la tarjeta de métrica.
    """
    umbral = queries.SEVERIDAD_ORDEN.get(min_severidad, 1)
    sevs = [s for s, o in queries.SEVERIDAD_ORDEN.items() if o <= umbral]
    fila = conn.execute(
        f"SELECT COUNT(*) FROM threats WHERE alerted_at IS NULL "
        f"AND severity IN ({','.join('?' * len(sevs))})", sevs).fetchone()
    return int(fila[0] or 0)


# --------------------------------------------------------------------------
# Preparación de datos para los gráficos (funciones puras, fáciles de probar)
# --------------------------------------------------------------------------
def _mes_corto(month: Optional[str]) -> str:
    """'2026-09' -> 'septiembre\\n2026': etiqueta de eje X en dos lineas.

    Sin abreviaturas: la regla del proyecto y el contrato de ``webui/graficos`` piden el
    nombre completo, y el grafico de los doce meses del ano ya demuestra que caben
    (revision de interfaz del 2026-09-09; antes se recortaba a tres letras).
    """
    if not month or "-" not in str(month):
        return str(month or "—")
    anio, mes = str(month).split("-")[:2]
    try:
        return f"{MESES[int(mes) - 1]}\n{anio}"
    except (ValueError, IndexError):
        return str(month)


def _fecha_corta(valor: Any) -> str:
    """'2026-08-31T22:05:00Z' -> '31 de agosto' (sin hora ni año, para el flujo).

    Escrita en español y sin abreviaturas, como el resto de la plataforma: hasta el
    2026-09-15 esta cifra y la nota de al lado se pintaban como «31/08/2026», el único
    sitio del Panel con fecha en formato numérico (revisión de claridad). El año va en
    la nota, que sí tiene sitio: la cifra grande de una tarjeta de 150 píxeles no lo
    admite sin partirse.
    """
    dt = _parse(valor)
    if dt is None:
        return "—"
    if dt.tzinfo is not None:
        dt = dt.astimezone()
    try:
        return f"{dt.day} de {MESES[dt.month - 1]}"
    except IndexError:
        return "—"


def _fecha_larga(valor: Any) -> str:
    """date o marca ISO -> '30 de septiembre de 2026'."""
    dt = valor if isinstance(valor, date) else _parse(valor)
    if dt is None:
        return "—"
    if isinstance(dt, datetime) and dt.tzinfo is not None:
        dt = dt.astimezone()
    try:
        return f"{dt.day} de {MESES[dt.month - 1]} de {dt.year}"
    except IndexError:
        return "—"


def _dias_desde(valor: Any, ahora: datetime) -> Optional[int]:
    """Días de calendario transcurridos desde una marca ISO; None si no hay."""
    dt = _parse(valor)
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (ahora.date() - dt.astimezone(ahora.tzinfo or timezone.utc).date()).days


def _ultimo_dia_mes(hoy: date) -> date:
    """El informe mensual se genera el último día del mes (crontab)."""
    return hoy.replace(day=calendar.monthrange(hoy.year, hoy.month)[1])


def _resumen_fuentes_activas(fuentes: Iterable[dict]) -> dict[str, Any]:
    """Agrega el estado de las fuentes ACTIVAS a partir de ``health.resumen_fuentes``.

    Las desactivadas no se consultan y por tanto no se cuentan como «no
    operativas» (el panel anterior decía «14 de 78» mezclándolas). Devuelve
    también la lista de las no operativas, ya ordenada por gravedad porque
    health la entrega así (caídas, degradadas, sin comprobar).
    """
    resumen = {"activas": 0, "operativas": 0, "degradadas": 0, "caidas": 0,
               "sin_comprobar": 0, "desactivadas": 0, "total": 0,
               "feeds": 0, "apis": 0, "no_operativas": []}
    for f in fuentes or []:
        resumen["total"] += 1
        if not f.get("enabled"):
            resumen["desactivadas"] += 1
            continue
        resumen["activas"] += 1
        if f.get("kind") in _TIPOS_RECOLECTABLES:   # RSS y pagina HTML de ColCERT (v6)
            resumen["feeds"] += 1
        else:
            resumen["apis"] += 1
        estado = f.get("estado")
        if estado == "ok":
            resumen["operativas"] += 1
        else:
            clave = {"degradada": "degradadas", "caida": "caidas"}.get(estado, "sin_comprobar")
            resumen[clave] += 1
            resumen["no_operativas"].append(f)
    return resumen


def _estado_recoleccion(caidas: int, activas: int) -> str:
    """ok sin caídas; atención si caen menos del 20 %; crítico si más."""
    if activas <= 0:
        return "inactivo"
    if caidas <= 0:
        return "ok"
    return "atencion" if caidas < UMBRAL_CAIDAS_ATENCION * activas else "critico"


def _estado_correlacion(ejecucion: Optional[dict]) -> str:
    """Según el resultado de la última recolección diaria."""
    if not ejecucion:
        return "inactivo"
    estado = ejecucion.get("status")
    if estado == "failed":
        return "critico"
    if estado == "partial":
        return "atencion"
    return "ok"


def _estado_enriquecimiento(pendientes: int, con_cve: int) -> str:
    """Atención cuando la cola de CVE sin enriquecer supera el umbral."""
    if con_cve <= 0:
        return "inactivo"
    return "atencion" if pendientes > UMBRAL_PENDIENTES_ENRIQUECER else "ok"


def _estado_alerta(dias_desde_diaria: Optional[int]) -> str:
    """ok si la última ejecución diaria fue hoy o ayer; crítico pasados 2 días."""
    if dias_desde_diaria is None:
        return "inactivo"
    if dias_desde_diaria <= 1:
        return "ok"
    return "atencion" if dias_desde_diaria == 2 else "critico"


def _estado_informe(dias_desde_informe: Optional[int]) -> str:
    """inactivo si nunca se generó; atención si el último es de hace > 35 días."""
    if dias_desde_informe is None:
        return "inactivo"
    return "ok" if dias_desde_informe <= DIAS_INFORME_VIGENTE else "atencion"


def _pasos_flujo(*, fuentes: dict, ultima_diaria: Optional[dict], enriquecimiento: dict,
                 pct_cvss_oficial: float, alerta: dict, ultimo_informe: Optional[dict],
                 ahora: datetime, hrefs: dict,
                 ultima_recoleccion: Optional[dict] = None) -> list[dict]:
    """Los cinco pasos del proceso con valores reales y estado por umbrales.

    ``ultima_recoleccion`` es la última corrida que consultó las fuentes y
    ``ultima_diaria`` la más reciente de las dos que hay cada día (la del correo de
    alerta). El paso «Correlación» habla de la primera y el paso «Alerta» de la segunda:
    hasta el 2026-09-15 los dos leían la misma fila y «Correlación» decía «0 amenazas
    nuevas» el día en que se recolectaron 261. Sin ``ultima_recoleccion`` se comporta
    como antes.
    """
    activas, operativas, caidas = fuentes["activas"], fuentes["operativas"], fuentes["caidas"]
    nota_rec = "fuentes activas operativas"
    if caidas:
        nota_rec += f" · {caidas} caída{'s' if caidas != 1 else ''}"
    elif fuentes["degradadas"]:
        nota_rec += f" · {fuentes['degradadas']} degradada{'s' if fuentes['degradadas'] != 1 else ''}"

    recoleccion = ultima_recoleccion or ultima_diaria
    nuevas = int((recoleccion or {}).get("threats_new") or 0)
    nota_cor = ("amenazas nuevas en la última recolección, "
                f"{hace(recoleccion.get('started_at'))}" if recoleccion
                else "sin recolecciones registradas")

    pendientes = int(enriquecimiento.get("pendientes") or 0)
    nota_enr = (f"amenazas con CVE pendientes · {_fmt_pct(pct_cvss_oficial)} del mes con CVSS oficial"
                if enriquecimiento.get("con_cve") else "sin CVE que enriquecer")

    dias_diaria = _dias_desde((ultima_diaria or {}).get("started_at"), ahora)
    nota_ale = (f"alertadas en 24 horas · última {hace(alerta['ultima'])}"
                if alerta.get("ultima") else "todavía no se ha alertado nada")

    proximo = _fecha_larga(_ultimo_dia_mes(ahora.date()))
    if ultimo_informe:
        marca = ultimo_informe.get("finished_at") or ultimo_informe.get("started_at")
        valor_inf = _fecha_corta(marca)
        nota_inf = (f"último informe generado el {_fecha_larga(marca)} · "
                    f"próximo el {proximo}")
    else:
        valor_inf = "—"
        nota_inf = f"nunca generado · previsto el {proximo}"
    dias_informe = _dias_desde((ultimo_informe or {}).get("started_at"), ahora)

    return [
        {"titulo": "Recolección", "valor": f"{operativas} / {activas}", "nota": nota_rec,
         "estado": _estado_recoleccion(caidas, activas), "href": hrefs.get("fuentes")},
        {"titulo": "Correlación", "valor": nuevas, "nota": nota_cor,
         "estado": _estado_correlacion(recoleccion), "href": hrefs.get("amenazas")},
        {"titulo": "Enriquecimiento", "valor": pendientes, "nota": nota_enr,
         "estado": _estado_enriquecimiento(pendientes, int(enriquecimiento.get("con_cve") or 0)),
         "href": hrefs.get("credenciales")},
        {"titulo": "Alerta", "valor": int(alerta.get("en_24h") or 0), "nota": nota_ale,
         "estado": _estado_alerta(dias_diaria)},
        {"titulo": "Informe mensual", "valor": valor_inf, "nota": nota_inf,
         "estado": _estado_informe(dias_informe)},
    ]


def _fmt_pct(valor: float) -> str:
    """Porcentaje entero para las notas: 14.5 -> '15 %'.

    Se redondea a entero porque las leyendas de ``barra_progreso`` del mismo
    panel muestran porcentajes enteros; una misma cifra con dos redondeos en la
    misma pantalla (14,5 % frente a 15 %) parecia una contradiccion."""
    from webui.graficos import fmt
    return f"{fmt(int(round(valor or 0)))} %"


#: Dias de cada una de las dos ventanas que compara la flecha de tendencia.
VENTANA_TENDENCIA_DIAS = 30


def _dias_del_mes(mes: Optional[str], hoy: date) -> dict[str, int]:
    """{transcurridos, totales} del mes «YYYY-MM» respecto a ``hoy``.

    La tarjeta «Amenazas del periodo» ensena el acumulado del mes EN CURSO, que casi
    siempre esta a medias: sin decir cuantos dias lleva, 1.532 parece comparable con los
    2.501 de los ultimos 30 dias y no lo es (revision de claridad del 2026-09-15). Un
    mes pasado devuelve transcurridos = totales.
    """
    if not mes or "-" not in str(mes):
        return {"transcurridos": 0, "totales": 0}
    try:
        anio, numero = (int(x) for x in str(mes).split("-")[:2])
        totales = calendar.monthrange(anio, numero)[1]
    except (ValueError, IndexError, calendar.IllegalMonthError):
        return {"transcurridos": 0, "totales": 0}
    if (anio, numero) == (hoy.year, hoy.month):
        transcurridos = min(hoy.day, totales)
    elif (anio, numero) > (hoy.year, hoy.month):
        transcurridos = 0
    else:
        transcurridos = totales
    return {"transcurridos": transcurridos, "totales": totales}


def _variaciones_30_dias(conn, *, ahora: Optional[datetime] = None,
                         excluir_bajas: bool = True) -> dict[str, dict[str, Any]]:
    """Recuento de los últimos 30 días frente a los 30 anteriores, por indicador.

    Se compara por ventanas de 30 días y no por mes natural: el mes en curso
    está incompleto y una comparación con el mes anterior completo mentiría
    («−90 %» el día 4). Devuelve {indicador: {actual, anterior, delta, pct, sentido,
    dias}}.

    ``ahora`` se acepta para las pruebas (una ventana de 30 días se prueba fijando una
    referencia de tiempo, no esperando 30 días); si no se proporciona, usa el instante
    actual del servidor.

    ``excluir_bajas`` (regla interna, ajuste ``ignore_low_severity``, activo) deja fuera
    la severidad Baja, como todas las demás cifras del Panel: hasta el 2026-09-15 la
    flecha las contaba y la tarjeta de al lado no.

    Las DOS ventanas son de 30 días: la flecha nunca compara el mes en curso a medias
    con un mes completo. Quien lee necesita ver las dos cifras para juzgarlo, así que se
    devuelven ``actual`` y ``anterior`` y la plantilla las escribe al lado del
    porcentaje; el gráfico pequeño de la misma tarjeta es de MESES NATURALES y el último
    está a medias, que es por lo que puede bajar mientras la flecha sube.
    """
    ahora = ahora or datetime.now(timezone.utc)
    hace_30_iso = (ahora - timedelta(days=30)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    hace_60_iso = (ahora - timedelta(days=60)).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    sin_bajas = " AND (severity IS NULL OR severity <> 'Low')" if excluir_bajas else ""
    consulta = f"""SELECT
        SUM(first_seen_at >= ?) AS total_a,
        SUM(first_seen_at <  ? AND first_seen_at >= ?) AS total_b,
        SUM(severity='Critical' AND first_seen_at >= ?) AS crit_a,
        SUM(severity='Critical' AND first_seen_at <  ? AND first_seen_at >= ?) AS crit_b,
        SUM(severity='High' AND first_seen_at >= ?) AS alta_a,
        SUM(severity='High' AND first_seen_at <  ? AND first_seen_at >= ?) AS alta_b,
        SUM(in_kev=1 AND first_seen_at >= ?) AS kev_a,
        SUM(in_kev=1 AND first_seen_at <  ? AND first_seen_at >= ?) AS kev_b
        FROM threats WHERE first_seen_at >= ?{sin_bajas}"""

    parametros = (
        hace_30_iso,  # total_a >= -30
        hace_30_iso, hace_60_iso,  # total_b < -30 AND >= -60
        hace_30_iso,  # crit_a >= -30
        hace_30_iso, hace_60_iso,  # crit_b < -30 AND >= -60
        hace_30_iso,  # alta_a >= -30
        hace_30_iso, hace_60_iso,  # alta_b < -30 AND >= -60
        hace_30_iso,  # kev_a >= -30
        hace_30_iso, hace_60_iso,  # kev_b < -30 AND >= -60
        hace_60_iso,  # WHERE >= -60
    )
    fila = conn.execute(consulta, parametros).fetchone()
    salida: dict[str, dict[str, Any]] = {}
    for clave, a, b in (("total", "total_a", "total_b"), ("criticas", "crit_a", "crit_b"),
                        ("altas", "alta_a", "alta_b"), ("en_kev", "kev_a", "kev_b")):
        actual = int((fila[a] if fila else 0) or 0)
        anterior = int((fila[b] if fila else 0) or 0)
        delta = actual - anterior
        pct = round(delta * 100.0 / anterior) if anterior else None
        salida[clave] = {"actual": actual, "anterior": anterior, "delta": delta, "pct": pct,
                         "dias": VENTANA_TENDENCIA_DIAS,
                         "sentido": "sube" if delta > 0 else ("baja" if delta < 0 else "igual")}
    return salida


def _series_evolucion(evolucion: list[dict], *, sin_bajas: bool = True) -> dict[str, Any]:
    """Categorías, series apiladas, línea KEV y chispas a partir de la serie
    mensual en orden cronológico ASCENDENTE.

    ``queries.evolucion_mensual`` no devuelve «bajas»: se derivan del total
    (todo lo que no es crítica, alta ni media) salvo que la consulta ya las
    traiga, para no depender de una ampliación ajena a este fichero.
    """
    def col(clave: str) -> list[int]:
        return [int(e.get(clave) or 0) for e in evolucion]

    criticas, altas, medias, totales = col("criticas"), col("altas"), col("medias"), col("total")
    bajas = [int(e["bajas"]) if e.get("bajas") is not None
             else max(t - c - a - m, 0)
             for e, t, c, a, m in zip(evolucion, totales, criticas, altas, medias)]
    en_kev = col("en_kev")
    # Regla interna (2026-09-08): con ``sin_bajas`` la serie tiene exactamente TRES
    # segmentos, criticas, altas y medias. Las bajas no se reportan.
    series = [
        {"clave": "critico", "nombre": "Críticas", "valores": criticas},
        {"clave": "alto", "nombre": "Altas", "valores": altas},
        {"clave": "medio", "nombre": "Medias", "valores": medias},
    ]
    if not sin_bajas:
        series.append({"clave": "bajo", "nombre": "Bajas", "valores": bajas})
    return {
        "categorias": [_mes_corto(e.get("month")) for e in evolucion],
        "series": series,
        # El nombre dice que NO es un cuarto grupo que se suma a los tres anteriores
        # (auditoría de tableros del 2026-09-15, punto 12): la leyenda ponía «En KEV 71»
        # al lado de «Críticas 905», «Altas 2.493» y «Medias 2.999», y quien leía sumaba
        # los cuatro. Las del catálogo KEV ya están contadas en su severidad.
        "linea": {"clave": "kev", "nombre": "Con explotación confirmada (ya contadas arriba)",
                  "valores": en_kev},
        "chispas": {"total": totales, "criticas": criticas, "altas": altas, "en_kev": en_kev},
        "bajas": bajas,
    }


def _porciones_severidad(stats: Optional[dict], *, sin_bajas: bool = True) -> list[dict]:
    if not stats:
        return []
    porciones = [
        {"clave": "critico", "nombre": "Críticas", "valor": stats.get("criticas", 0)},
        {"clave": "alto", "nombre": "Altas", "valor": stats.get("altas", 0)},
        {"clave": "medio", "nombre": "Medias", "valor": stats.get("medias", 0)},
    ]
    if not sin_bajas:
        porciones.append({"clave": "bajo", "nombre": "Bajas", "valor": stats.get("bajas", 0)})
    return porciones


def _items_tecnologias(top: list[dict], mes: Optional[str], *, sin_bajas: bool = True) -> list[dict]:
    """Filas de ``barras_horizontales``: Críticas, Altas y Medias (y Bajas solo si la regla
    interna de no reportarlas esta desactivada), con enlace a la consulta filtrada por
    tecnología y mes, y nota «sin versión»."""
    items = []
    for t in top or []:
        criticas = int(t.get("criticas") or 0)
        altas = int(t.get("altas") or 0)
        medias = int(t.get("medias") or 0)
        bajas = max(int(t.get("amenazas") or 0) - criticas - altas - medias, 0)
        valores = [("critico", criticas), ("alto", altas), ("medio", medias)]
        if not sin_bajas:
            valores.append(("bajo", bajas))
        items.append({
            "etiqueta": t.get("name") or "—",
            "valores": valores,
            "href": url_for("amenazas.lista", tec=t.get("slug"), mes=mes) if t.get("slug") else "",
            "nota": "" if t.get("version_installed") else "sin versión",
        })
    return items


def _porciones_fuentes(resumen: dict) -> list[dict]:
    return [
        {"clave": "exito", "nombre": "Operativas", "valor": resumen["operativas"]},
        {"clave": "medio", "nombre": "Degradadas", "valor": resumen["degradadas"]},
        {"clave": "critico", "nombre": "Caídas", "valor": resumen["caidas"]},
        {"clave": "neutro", "nombre": "Sin comprobar", "valor": resumen["sin_comprobar"]},
    ]


def _partes_procedencia(procedencia: dict) -> list[dict]:
    partes = [{"clave": clave, "nombre": nombre, "valor": procedencia.get(origen, 0)}
              for origen, nombre, clave in PROCEDENCIA]
    if procedencia.get("otros"):
        partes.append({"clave": "neutro", "nombre": "Otra procedencia", "valor": procedencia["otros"]})
    return partes


def _partes_enriquecimiento(enr: dict) -> list[dict]:
    partes = [{"clave": "exito", "nombre": "Con CVSS oficial", "valor": enr.get("con_cvss_oficial", 0)}]
    if enr.get("consultadas_sin_cvss"):
        partes.append({"clave": "neutro", "nombre": "Consultadas sin puntuación en NVD",
                       "valor": enr["consultadas_sin_cvss"]})
    partes.append({"clave": "medio", "nombre": "Pendientes de consultar", "valor": enr.get("pendientes", 0)})
    return partes


def _partes_inventario(inv: dict) -> list[dict]:
    return [
        {"clave": "exito", "nombre": "Con versión registrada", "valor": inv.get("con_version", 0)},
        {"clave": "neutro", "nombre": "Sin versión", "valor": inv.get("sin_version", 0)},
    ]


def _partes_disco(disco: Optional[dict]) -> list[dict]:
    """Usado / libre en GB; el color del uso sube con la ocupación."""
    if not disco or not disco.get("total_gb"):
        return []
    total = float(disco.get("total_gb") or 0)
    libre = float(disco.get("libre_gb") or 0)
    usado = max(total - libre, 0.0)
    pct = float(disco.get("usado_pct") or (usado * 100.0 / total if total else 0))
    clave = "critico" if pct >= 90 or libre < 2 else "medio" if pct >= 75 else "acento"
    return [
        {"clave": clave, "nombre": "Usado (GB)", "valor": round(usado, 1)},
        {"clave": "neutro", "nombre": "Libre (GB)", "valor": round(libre, 1)},
    ]


def motivos_sin_repetir(salud: Optional[dict], cred: Optional[dict]) -> list[str]:
    """Los motivos del estado global SIN los que ya tienen su propio aviso en la página.

    Por qué (revisión de claridad del 2026-09-15): el Panel abría con «El sistema
    funciona con incidencias · 44 de 44 fuentes activas operativas · Motivos: Caduca en
    5 días. Conviene renovarla antes de que las alertas dejen de enviarse.» y, justo
    debajo, con «La contraseña del correo caduca en 5 días. Renovarla.». Dos avisos
    seguidos de lo mismo, y el primero sin sujeto: no decía QUÉ caduca. El aviso propio
    de la credencial lo dice con su nombre y con el enlace para renovarla, así que el
    motivo se quita de la lista de arriba en lugar de repetirse.

    La comparación es por identidad de texto con ``cred["mensaje"]``, que es justo lo
    que ``health.resumen_sistema`` mete en ``motivos`` para este caso: si mañana el
    mensaje cambia, cambian los dos a la vez y esto sigue funcionando.
    """
    motivos = [str(m).strip() for m in ((salud or {}).get("motivos") or []) if str(m).strip()]
    if (cred or {}).get("estado") not in ("caducada", "fallando", "por_caducar"):
        return motivos
    propio = str((cred or {}).get("mensaje") or "").strip()
    return [m for m in motivos if m != propio]


#: Nombre de la corrida diaria que NO consulta fuentes: la de las 13:00, que solo envía
#: el correo con lo que recolectó la de las 12:30 (auditoría de tableros del 2026-09-15,
#: punto 12). Las dos son de tipo ``daily`` y la tabla las llamaba igual, así que la de
#: la alerta salía con «Fuentes 0» y se leía como un fallo de recolección.
TIPO_EJECUCION_ALERTA = "Envío de la alerta diaria"


def _es_envio_de_alerta(e: dict) -> bool:
    """¿Esta fila de ``executions`` es el envío de la alerta y no una recolección?

    Lo es cuando es diaria y no consultó NINGUNA fuente, ni con éxito ni con fallo. Se
    exige que la fila traiga de verdad esas dos columnas: una fila sin el dato (base
    antigua o llamada de prueba con un diccionario suelto) se sigue llamando
    «Recolección diaria», como siempre.
    """
    if e.get("kind") != "daily" or ("sources_ok" not in e and "sources_failed" not in e):
        return False
    return (int(e.get("sources_ok") or 0) + int(e.get("sources_failed") or 0)) == 0


def _etiquetar_ejecuciones(filas: Iterable[dict]) -> list[dict]:
    """Añade tipo y estado en español a cada fila de ``executions``.

    ``consulta_fuentes`` dice si la corrida consultaba fuentes: la tabla escribe «—» en
    lugar de un cero en la columna «Fuentes» de las que no lo hacen, porque ese cero se
    leía como «no respondió ninguna fuente».
    """
    salida = []
    for e in filas:
        e = dict(e)
        es_alerta = _es_envio_de_alerta(e)
        e["tipo_es"] = (TIPO_EJECUCION_ALERTA if es_alerta
                        else TIPO_EJECUCION.get(e.get("kind"), str(e.get("kind") or "—")))
        e["consulta_fuentes"] = not es_alerta
        texto, clase = ESTADO_EJECUCION.get(e.get("status"), (str(e.get("status") or "—"), "neutra"))
        e["estado_es"], e["estado_clase"] = texto, clase
        salida.append(e)
    return salida


#: Enlaces que puede llevar una incidencia de ``health.resumen_sistema`` y que van a
#: una pantalla de Administración (``@auth.requiere_admin``): a quien no es
#: administrador no se le ofrece el enlace, el mismo criterio que ya aplica ``hrefs``
#: en :func:`inicio`, porque la ruta le respondería 403.
ENLACES_INCIDENCIA_SOLO_ADMIN = frozenset(
    {"credenciales.panel", "fuentes.lista", "sincronizaciones.lista"})


def _incidencias_para_el_rol(incidencias: Iterable[dict], *, es_admin: bool) -> list[dict]:
    """Quita el ENLACE (no el texto) de las incidencias que llevan a Administración.

    Revisión de permisos del 2026-11-15: el perfil de solo lectura veía en el Panel
    un enlace «Ver el estado del certificado» que apuntaba a Credenciales, una pantalla
    de administración a la que no puede entrar (403). El título, la consecuencia y la
    acción de la incidencia siguen viéndose igual para todos los perfiles: solo se
    quita el enlace que ese perfil no puede usar.
    """
    if es_admin:
        return list(incidencias)
    salida = []
    for inc in incidencias:
        if inc.get("enlace") in ENLACES_INCIDENCIA_SOLO_ADMIN:
            inc = dict(inc, enlace=None, enlace_es=None)
        salida.append(inc)
    return salida


# --------------------------------------------------------------------------
# Vistas
# --------------------------------------------------------------------------
@bp.route("/")
@auth.requiere_login
def inicio():
    ahora = datetime.now(timezone.utc)
    salud, err_salud = _cargar("health", "resumen_sistema", g.db, cfg=g.cfg)
    # resumen_sistema ya trae el detalle por fuente; solo se recalcula si falló.
    fuentes = (salud or {}).get("fuentes_detalle")
    err_fuentes = None
    if fuentes is None:
        fuentes, err_fuentes = _cargar("health", "resumen_fuentes", g.db, ventana=10, cfg=g.cfg)
    cred, err_cred = _cargar("credentials", "estado", g.db, cfg=g.cfg)

    meses = queries.meses_disponibles(g.db)
    mes = meses[0] if meses else None
    # Regla interna: las bajas no se reportan (ajuste ignore_low_severity, activo).
    sin_bajas = bool(g.cfg.get("ignore_low_severity", True))
    stats = queries.estadisticas_mes(g.db, mes, excluir_bajas=sin_bajas) if mes else None
    # evolucion_mensual devuelve DESC; los gráficos van en orden cronológico.
    evolucion = list(reversed(queries.evolucion_mensual(g.db, 6, excluir_bajas=sin_bajas)))
    variaciones = _variaciones_30_dias(g.db, ahora=ahora, excluir_bajas=sin_bajas)
    top = queries.top_tecnologias(g.db, mes, 8, excluir_bajas=sin_bajas) if mes else []
    for t in top:
        t["criticidad_es"] = CRITICIDAD_ES.get(t.get("criticality"), str(t.get("criticality") or "—"))

    ejecuciones = _etiquetar_ejecuciones(
        g.db.execute("SELECT * FROM executions ORDER BY started_at DESC LIMIT 8"))

    min_severidad = g.cfg.get("alert_min_severity", "High") or "High"
    # Criterio real de la alerta diaria (relevancia o KEV, con activos afectados cuando se
    # ha podido comprobar): lo que saldra en el proximo correo, no el criterio antiguo.
    try:
        clasificacion = queries.clasificar_pendientes(g.db, cfg=g.cfg, persistir=False)
        pendientes = clasificacion["alertar"][:5]
        total_pendientes = len(clasificacion["alertar"])
        # Las descartadas por su severidad NO se cuentan aquí con la regla interna activa
        # (auditoría de tableros del 2026-09-15, punto 12): el Panel decía «1.409
        # excluidas por el filtro» y 150 de ellas lo estaban por una severidad que la
        # plataforma no reporta en ninguna otra cifra, así que el número no se podía
        # cuadrar con nada. Con la regla desactivada se siguen contando todas.
        excluidas_pendientes = sum(
            n for motivo, n in clasificacion["conteo"].items()
            if not (sin_bajas and motivo == "severidad_baja"))
    except Exception:  # noqa: BLE001
        pendientes = queries.pendientes_de_alerta(g.db, min_severidad=min_severidad, limite=5)
        total_pendientes = _total_pendientes(g.db, min_severidad)
        excluidas_pendientes = None

    procedencia = _procedencia_severidad(g.db, mes, excluir_bajas=sin_bajas) if mes else {}
    enriquecimiento = _enriquecimiento(g.db, excluir_bajas=sin_bajas)
    inventario = _cobertura_inventario(g.db)
    # Misma fuente que el correo de alerta: ocs.resumen + expuestos_afectados.
    activos, err_activos = resumen_activos_correo(g.db, cfg=g.cfg)
    estado_activos, _err_estado = estado_activos_semanal(g.db, cfg=g.cfg)
    # Alcance por tipo de maquina (2026-09-08): Redes y Mantenimiento ven las cifras de
    # activos de su tipo, calculadas en el servidor, no las del parque entero.
    alcance = auth.alcance_origen()
    if alcance:
        estado_activos = _estado_activos_en_alcance(g.db, alcance, cfg=g.cfg)
        activos = _resumen_activos_en_alcance(g.db, activos, alcance)
    resumen_fuentes = _resumen_fuentes_activas(fuentes or [])
    ultima_diaria = _ultima_ejecucion(g.db, "daily")
    # La última corrida que de verdad recolectó (12:30), distinta de la más reciente
    # (13:00, el correo de alerta): el paso «Correlación» habla de la primera.
    ultima_recoleccion = _ultima_recoleccion(g.db)
    ultimo_informe = _ultima_ejecucion(g.db, "monthly")
    alerta = _ultima_alerta(g.db, ahora)

    # Fuentes y Credenciales son de administracion (Fuentes desde el 2026-09-08): a los
    # demas perfiles no se les ofrece un enlace que respondería 403.
    es_admin = auth.es_admin()
    hrefs = {"fuentes": url_for("fuentes.lista") if es_admin else "",
             "amenazas": url_for("amenazas.lista", mes=mes) if mes else url_for("amenazas.lista"),
             "credenciales": url_for("credenciales.panel") if es_admin else ""}
    flujo = _pasos_flujo(
        fuentes=resumen_fuentes, ultima_diaria=ultima_diaria,
        ultima_recoleccion=ultima_recoleccion, enriquecimiento=enriquecimiento,
        pct_cvss_oficial=float((stats or {}).get("pct_con_cvss_real") or 0.0),
        alerta=alerta, ultimo_informe=ultimo_informe, ahora=ahora, hrefs=hrefs)

    evo = _series_evolucion(evolucion, sin_bajas=sin_bajas)
    graf = {
        "categorias": evo["categorias"], "series": evo["series"], "linea": evo["linea"],
        "chispas": evo["chispas"],
        "porciones_mes": _porciones_severidad(stats, sin_bajas=sin_bajas),
        "tecnologias": _items_tecnologias(top, mes, sin_bajas=sin_bajas),
        "porciones_fuentes": _porciones_fuentes(resumen_fuentes),
        "procedencia": _partes_procedencia(procedencia),
        "enriquecimiento": _partes_enriquecimiento(enriquecimiento),
        "inventario": _partes_inventario(inventario),
        "disco": _partes_disco((salud or {}).get("disco")),
    }
    # Filas de la tabla de evolución con «bajas» (misma fuente que el gráfico).
    evolucion_tabla = [dict(e, bajas=b) for e, b in zip(evolucion, evo["bajas"])]

    # Conciliación con la página de Remediación (2026-09-15): «pendientes» es
    # «confirmadas» más las vulnerabilidades que siguen en la cola porque su fila de
    # evaluación desapareció sin que OCS Inventory confirme ningún cambio. Sin decirlo,
    # las dos pantallas daban dos cifras distintas de lo mismo.
    pendientes_sin_confirmar = queries.vulnerabilidades_pendientes_sin_confirmar(
        g.db, origen=alcance or None, incluir_bajas=not sin_bajas)
    # Cuántos días del mes en curso llevan contados: la tarjeta del periodo enseña un
    # acumulado a medias y la flecha de al lado compara dos ventanas de 30 días.
    dias_mes = _dias_del_mes(mes, ahora.date())

    return render_template(
        "panel.html", salud=salud, cred=cred, mes=mes, stats=stats, sin_bajas=sin_bajas,
        motivos_salud=motivos_sin_repetir(salud, cred), dias_mes=dias_mes,
        # Incidencias con sujeto, consecuencia y accion (2026-09-15): el aviso decia
        # «funciona con incidencias» y a continuacion que las 44 fuentes estaban bien,
        # que es justo lo que NO fallaba, y no decia que hacer. Sin el enlace a
        # Administracion para quien no es administrador (2026-11-15): vease
        # ``_incidencias_para_el_rol``.
        incidencias=_incidencias_para_el_rol(
            (salud or {}).get('incidencias') or [], es_admin=es_admin),
        ventana_tendencia=VENTANA_TENDENCIA_DIAS,
        pendientes_sin_confirmar=pendientes_sin_confirmar,
        evolucion=evolucion_tabla, top=top, ejecuciones=ejecuciones, variaciones=variaciones,
        pendientes=pendientes, total_pendientes=total_pendientes, excluidas_pendientes=excluidas_pendientes,
        min_severidad=min_severidad, flujo=flujo, graf=graf,
        fuentes_resumen=resumen_fuentes, procedencia=procedencia,
        enriquecimiento=enriquecimiento, inventario=inventario, activos=activos,
        cifras_activos=_cifras_activos(estado_activos),
        errores=[e for e in (err_salud, err_fuentes, err_cred, err_activos) if e],
    )


@bp.route("/salud.json")
def salud_json():
    """Metricas para Zabbix. Protegido por token, no por sesion.

    Esta maquina ya tiene agente Zabbix y un cron zbx_salud, asi que exponer
    las metricas aqui evita tener que escribir un colector aparte.
    """
    token_esperado = g.cfg.secrets.get("HEALTH_TOKEN")
    token = request.args.get("token") or request.headers.get("X-Health-Token")

    if token_esperado:
        if not token or token != token_esperado:
            return jsonify({"error": "token invalido"}), 403
    # Sin HEALTH_TOKEN basta una sesion, pero no una sesion a medio abrir: quien
    # todavia debe cambiar la contrasena inicial o tiene la cuenta deshabilitada no
    # puede leer las metricas (hallazgo ALTO de la revision del 2026-09-07).
    elif (not auth.usuario_actual() or auth.cambio_password_obligatorio()
          or auth.cuenta_deshabilitada()):
        return jsonify({"error": "requiere sesión o HEALTH_TOKEN configurado"}), 403

    metricas, err = _cargar("health", "exportar_metricas", g.db, cfg=g.cfg)
    if err:
        return jsonify({"error": err}), 500
    return jsonify(metricas)


@bp.route("/auditoria")
@auth.requiere_admin
def auditoria():
    pagina = max(1, request.args.get("pagina", 1, type=int))
    por_pagina = 20          # el usuario pidio 20 filas por pagina (2026-09-07)
    total = g.db.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    filas = [dict(r) for r in g.db.execute(
        "SELECT * FROM audit_log ORDER BY at DESC LIMIT ? OFFSET ?",
        (por_pagina, (pagina - 1) * por_pagina))]
    return render_template("auditoria.html", filas=filas, pagina=pagina,
                           total=total, por_pagina=por_pagina)


# --------------------------------------------------------------------------
# Recorrido guiado completo (v6): la respuesta del usuario a la invitacion se
# guarda en su ficha para no volver a preguntar en cada acceso ni por navegador.
# --------------------------------------------------------------------------
ESTADOS_TOUR = ("empezado", "rechazado", "completado", "pendiente")


@bp.route("/tour/respuesta", methods=["POST"])
@auth.requiere_login
@auth.requiere_csrf
def tour_estado():
    """Guarda si el usuario empezo, rechazo o completo el recorrido («pendiente» lo reinicia)."""
    estado = (request.form.get("estado") or "").strip().lower()[:20]
    if estado not in ESTADOS_TOUR:
        abort(400, "Estado del recorrido no válido.")
    from threatintel import db as _db
    valor = None if estado == "pendiente" else estado
    g.db.execute("UPDATE users SET tour_estado=?, tour_at=? WHERE username=?",
                 (valor, _db.utcnow() if valor else None, g.usuario))
    g.db.commit()
    return ("", 204)

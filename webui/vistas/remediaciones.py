"""Pagina de seguimiento de remediacion (v11): por actualizacion y por vulnerabilidad.

Dos vistas de lo mismo, con un selector:

- «Por actualizacion» (la de omision, 2026-09-08): una fila por activo y ORIGEN de paquete
  con la version objetivo, que es la MAYOR de las solicitadas por los avisos. Es la unidad
  de trabajo real: un kernel con veintinueve avisos es UNA actualizacion, no veintinueve,
  y desde el 2026-09-09 sus binarios (linux-image, linux-headers, linux-modules,
  linux-tools… con la misma version y los mismos CVE) tambien son UNA fila, «Núcleo Linux
  6.8.0-60-generic», con la lista de paquetes desplegable (threatintel.remediacion, seccion
  «Una actualizacion por ORIGEN DE PAQUETE»). Al desplegar la fila se ve la trazabilidad, la
  version que pedia cada CVE. El usuario lo pidio el 2026-09-08 y lo reclamo de nuevo el
  2026-09-09: «si hay una vulnerabilidad de kernel que se repite que se cuente como una y se
  vea como la trazabilidad de las versiones a las que se solicita actualizar».
- «Por vulnerabilidad»: el listado por (activo, CVE, paquete) de siempre, que sigue siendo
  necesario para investigar un CVE concreto.

Escritura: las remediaciones se abren y cierran solas en cada sincronizacion con OCS
(threatintel.remediacion.sincronizar). Lo unico que se puede enviar desde aqui son las dos
acciones del perfil «Redes», que antes solo estaban en la ficha del activo
y el usuario no encontraba (2026-09-08: «No veo tampoco la opcion de que servicios
tecnologicos pueda documentar sobre una vulnerabilidad en un activo»): pedir la
comprobacion y documentar. Ninguna de las dos cierra nada por si misma.

Sin ``style=`` ni ``on*=``: CSP estricta; el grafico es SVG del servidor y el despliegue de
la trazabilidad es ``<details>``, HTML puro sin una linea de JavaScript.
"""
from __future__ import annotations

import csv
import inspect
import io

from flask import (abort, Blueprint, Response, current_app, flash, g, redirect,
                   render_template, request, url_for)

from threatintel import aplicabilidad, db, excepciones, remediacion
from .. import auth, graficos
from ..filtros import celda_csv

bp = Blueprint("remediaciones", __name__, url_prefix="/remediaciones")

#: «esperando_datos» (2026-09-10, esquema v14) se ofrece en el filtro para poder verlas
#: una a una desde la propia página; NO es el valor de omisión (siguen fuera de la cola)
#: y su sitio natural es el panel «Esperando datos del inventario», que las agrupa por
#: activo, que es la unidad del trabajo que hay que hacer con ellas.
ESTADOS_FILTRO = ("abierta", "todas", "esperando_datos", "corregida", "activo_ausente")
#: Las dos vistas del listado. La primera es la de omision porque es la que evita el
#: reproceso: agrupa las vulnerabilidades que una sola actualizacion resuelve.
VISTAS = ("actualizacion", "vulnerabilidad")
VISTA_ES = {"actualizacion": "Por actualización", "vulnerabilidad": "Por vulnerabilidad"}
#: Filas por pagina en pantalla (2026-09-07). Antes eran las 500 primeras de las
#: 42.902 remediaciones con un aviso de recorte y ningun modo de ver el resto sin
#: exportar; ahora es el tamano de la pagina y la lista se recorre con la paginacion.
#: Filas por pagina en los listados largos. El usuario pidio 20 el 2026-09-07
#: («que en cada uno solo muestre de a 20»): una pantalla se recorre de un vistazo.
LIMITE_PAGINA = 20
#: Filas que lleva el CSV: la exportacion sigue siendo completa, no se pagina.
LIMITE_CSV = 20000
#: Tope de filas que esta vista lee de una vez MIENTRAS ``remediacion.listar`` no
#: acepte ``desplazamiento`` (2026-09-07, hallazgo del revisor). Sin ese parametro la
#: unica forma de llegar a una pagina profunda es pedir las filas hasta el final de
#: la pagina y recortar en Python, y con 42.902 remediaciones la ultima pagina
#: materializaba las 42.902 en memoria (medido: +118 MB de RSS y 1.184 ms frente a
#: 334 ms de la primera). Con el tope, en pantalla se recorren las primeras
#: TOPE_SIN_DESPLAZAMIENTO filas (100 paginas de 50) y la pagina lo dice; el resto se
#: alcanza acotando los filtros o con el CSV, que sigue completo. En cuanto el
#: parametro exista el tope deja de aplicarse solo, sin tocar nada.
TOPE_SIN_DESPLAZAMIENTO = 5000

#: Activos que lista de una vez el panel «Esperando datos del inventario» (2026-09-10).
#: Cada fila es UN ACTIVO cuyo agente de OCS Inventory hay que revisar, no una
#: remediación: en producción son cuatro equipos de cómputo con 2.480 remediaciones entre
#: los cuatro. Con más de este tope el panel lo dice y la lista completa se obtiene en la
#: página de Activos con la vista «Sin datos suficientes de Windows».
LIMITE_ESPERANDO = 25


#: Actualizaciones que la ficha del activo lista de una vez. El activo con mas
#: actualizaciones de produccion tiene 36 (2026-09-09); si hay mas, la ficha lo dice y
#: enlaza a la pagina de Remediacion acotada al activo, que si pagina.
LIMITE_FICHA_ACTIVO = 60


def resumen_memorizado(dias: int, origen=None, *, solo_cifras: bool = False) -> dict:
    """``remediacion.resumen`` calculado UNA VEZ por peticion para cada (origen, dias).

    Hallazgo MEDIO de la revision del 2026-09-09: el resumen cuesta cientos de
    milisegundos (590 ms medidos sobre la base real) y la pagina de Remediacion lo pedia
    tres veces —una para las cifras de arriba y otra por cada tipo de maquina del bloque
    «Avance»—, mas otra vez la pagina de Activos en cada carga: 2,0 s y 1,7 s. Aqui se
    memoriza en ``g`` (vive lo que vive la peticion, nunca entre peticiones: los datos
    cambian con cada sincronizacion y una cache larga mostraria cifras viejas) y se pide
    con ``solo_cifras`` cuando el bloque que lo consume no pinta ni el reparto por proceso
    ni la serie semanal, que es lo caro. Un resumen completo ya calculado sirve tambien
    para quien pide solo las cifras: es un superconjunto.
    """
    dias = max(1, int(dias or 30))
    cache = getattr(g, "cache_resumen_remediacion", None)
    if cache is None:
        cache = {}
        g.cache_resumen_remediacion = cache
    if (origen, dias, False) in cache:
        return cache[(origen, dias, False)]
    clave = (origen, dias, bool(solo_cifras))
    if clave not in cache:
        cache[clave] = remediacion.resumen(g.db, dias=dias, origen=origen,
                                           solo_cifras=bool(solo_cifras))
    return cache[clave]


#: Lo que se devuelve cuando no hay nada que contar: las mismas claves, a cero, para que
#: la plantilla no tenga que comprobar si el diccionario esta completo.
_SIN_ACTUALIZACIONES = {"grupos": [], "total": 0, "recortado": False,
                        "vulnerabilidades": 0, "paquetes": 0, "filas": 0}


def _cifras_pendientes_del_activo(activo_id: int) -> dict:
    """Las tres magnitudes pendientes de UN activo, en una consulta.

    ``vulnerabilidades`` son CVE distintos (uno por activo y CVE, la unidad de riesgo),
    ``paquetes`` los paquetes distintos que hay que actualizar y ``filas`` las filas de
    remediacion (una por activo, amenaza y paquete). La tarjeta principal de la ficha
    pinta el numero de ACTUALIZACIONES y estas tres van debajo como trazabilidad: la
    cifra grande y la tabla no pueden decir numeros distintos (peticion del usuario del
    2026-09-09). Con ``idx_remed_activo`` cuesta milisegundos.

    Sin la severidad baja (2026-09-10, ajuste ``ignore_low_severity``) y sin el riesgo
    aceptado con una excepcion vigente (2026-09-10): las dos condiciones salen de
    ``threatintel.remediacion``, las mismas que usan las actualizaciones que se pintan
    encima, para que la tarjeta y la tabla no puedan discrepar. Lo aceptado se dice
    aparte, en ``aceptadas``, para que la bajada no parezca trabajo hecho.
    """
    fila = g.db.execute(
        f"""SELECT COUNT(*) AS filas,
                  COUNT(DISTINCT CASE WHEN r.cve IS NOT NULL AND r.cve <> '' THEN r.cve END) AS cves,
                  COUNT(DISTINCT r.paquete) AS paquetes
             FROM remediaciones r
            WHERE r.activo_id = ? AND r.estado = 'abierta'
                  {remediacion._y_sin_bajas(g.db)}
                  {remediacion._y_sin_excepcion(g.db)}""", (activo_id,)).fetchone()
    return {"vulnerabilidades": int((fila["cves"] if fila else 0) or 0),
            "paquetes": int((fila["paquetes"] if fila else 0) or 0),
            "filas": int((fila["filas"] if fila else 0) or 0),
            "aceptadas": _cifras_riesgo_aceptado(activo_id=activo_id)["vulnerabilidades"]}


# --------------------------------------------------------------------------
# Riesgo aceptado (excepciones con vencimiento, 2026-09-10)
#
# Una excepcion vigente saca la vulnerabilidad de la cola y de las cifras (la condicion
# la ponen ``threatintel.remediacion`` y ``threatintel.queries``), pero NO la borra ni la
# oculta: donde la fila se sigue viendo —la ficha del activo y su historial— lleva la
# insignia «Riesgo aceptado», con el responsable, la fecha de vencimiento y el enlace a
# la excepcion. Y donde la cifra baja por esa causa, la pagina lo dice con su nombre: una
# cifra que baja por aceptacion de riesgo y no por correccion tiene que verse.
#
# Las excepciones vigentes se resuelven de UNA VEZ (una consulta por pagina, decenas de
# filas) y se cruzan en Python: nunca una consulta por fila.
# --------------------------------------------------------------------------
def _cifras_riesgo_aceptado(*, origen=None, activo_id=None) -> dict:
    """Cuanto trabajo pendiente esta fuera de la cola por una aceptacion de riesgo.

    ``vulnerabilidades`` son pares (activo, CVE) y ``filas`` filas de remediacion, y las
    dos se calculan como la DIFERENCIA exacta entre lo que habria y lo que hay: un par
    cuyo paquete cubierto convive con otro paquete que sigue pendiente NO desaparece de
    la cola, asi que no se puede contar como aceptado. Una sola consulta, y solo cuando
    hay alguna excepcion vigente (si no, ceros y ni una consulta de mas).
    """
    vacio = {"vulnerabilidades": 0, "filas": 0, "hay": False}
    if not excepciones.hay_excepciones(g.db):
        return vacio
    condicion = excepciones.SQL_SIN_EXCEPCION_REMEDIACION
    par = "r.activo_id || char(31) || r.cve"
    where = ["r.estado = 'abierta'"]
    params: list = []
    if activo_id:
        where.append("r.activo_id = ?")
        params.append(int(activo_id))
    union = ""
    if origen in remediacion.ORIGENES:
        union = " JOIN activos a ON a.id = r.activo_id"
        where.append("a.origen = ?")
        params.append(origen)
    fila = g.db.execute(
        f"""SELECT COUNT(DISTINCT CASE WHEN r.cve IS NOT NULL AND r.cve <> ''
                                       THEN {par} END) AS pares,
                   COUNT(DISTINCT CASE WHEN r.cve IS NOT NULL AND r.cve <> ''
                                        AND {condicion} THEN {par} END) AS pares_libres,
                   COUNT(*) AS filas,
                   SUM(CASE WHEN {condicion} THEN 1 ELSE 0 END) AS filas_libres
              FROM remediaciones r{union}
             WHERE {" AND ".join(where)}{remediacion._y_sin_bajas(g.db)}""",
        params).fetchone()
    if fila is None:
        return vacio
    return {"vulnerabilidades": max(0, int(fila["pares"] or 0) - int(fila["pares_libres"] or 0)),
            "filas": max(0, int(fila["filas"] or 0) - int(fila["filas_libres"] or 0)),
            "hay": True}


def indice_riesgo_aceptado(filas_excepciones) -> dict:
    """Indexa unas excepciones vigentes por lo que cubren, para cruzarlas en Python.

    Devuelve tres diccionarios, uno por alcance: ``(activo, CVE)``, ``CVE`` (toda la
    organizacion) y ``(activo, paquete)``. La forma es la misma que la de la condicion
    SQL de ``threatintel.excepciones``, asi que la insignia marca EXACTAMENTE las filas
    que esa condicion saca de la cola.
    """
    indice: dict = {"activo_cve": {}, "cve": {}, "activo_paquete": {}}
    for e in filas_excepciones or []:
        if e.get("estado") != "vigente":
            continue
        alcance = e.get("alcance")
        if alcance == "activo_cve" and e.get("activo_id") and e.get("cve"):
            indice["activo_cve"][(int(e["activo_id"]), str(e["cve"]))] = e
        elif alcance == "cve" and e.get("cve"):
            indice["cve"][str(e["cve"])] = e
        elif alcance == "activo_paquete" and e.get("activo_id") and e.get("paquete"):
            indice["activo_paquete"][(int(e["activo_id"]), str(e["paquete"]))] = e
    return indice


def excepciones_vigentes(conn, *, activo_id=None) -> list[dict]:
    """Las excepciones vigentes, en UNA consulta (decenas de filas como maximo).

    Con ``activo_id`` se pide solo lo que afecta a ese activo con la funcion del propio
    modulo (``excepciones.por_activo``, que incluye las de un CVE en toda la
    organizacion). Sin el, se leen todas las vigentes: es lo que necesita un listado con
    filas de veinte activos distintos, y hacerlo activo por activo seria una consulta por
    fila.
    """
    if not excepciones.hay_excepciones(conn):
        return []
    if activo_id:
        return excepciones.por_activo(conn, int(activo_id), solo_vigentes=True)
    filas = conn.execute(
        f"""SELECT e.id, e.alcance, e.activo_id, e.cve, e.paquete, e.vence_at, e.kev,
                   e.permanente, e.responsable_nombre, e.responsable_correo, e.justificacion,
                   {excepciones.SQL_DIAS_RESTANTES} AS dias_restantes
              FROM excepciones e WHERE {excepciones.SQL_VIGENTE}""").fetchall()
    # `permanente` viaja con la fila (2026-09-10): la insignia «Riesgo aceptado» de las
    # fichas tiene que poder decir «(permanente)» en lugar de una fecha que no existe, y
    # `dias_restantes` vale None en ese caso, nunca cero.
    return [dict(f, estado="vigente", permanente=bool(f["permanente"])) for f in filas]


def marcar_riesgo_aceptado(filas, indice: dict) -> int:
    """Pone ``riesgo_aceptado`` (la excepcion que la cubre) en cada fila cubierta.

    Cruce en Python contra el indice ya resuelto: ni una consulta por fila. Devuelve
    cuantas filas quedaron marcadas, para que quien llame pueda decirlo en pantalla.
    """
    if not indice or not (indice["activo_cve"] or indice["cve"] or indice["activo_paquete"]):
        return 0
    marcadas = 0
    for fila in filas or []:
        try:
            activo_id = int(fila.get("activo_id") or 0)
        except (TypeError, ValueError):
            continue
        cve = str(fila.get("cve") or "")
        paquete = str(fila.get("paquete") or "")
        excepcion = (indice["activo_cve"].get((activo_id, cve))
                     or indice["cve"].get(cve)
                     or indice["activo_paquete"].get((activo_id, paquete)))
        if excepcion is not None:
            fila["riesgo_aceptado"] = excepcion
            marcadas += 1
    return marcadas


#: Tope de vulnerabilidades a las que se les trae la evidencia de la evaluacion en la
#: ficha de un activo. Es el mismo presupuesto que pinta la ficha, asi que no puede
#: quedarse corto ni traer nada que no se vaya a leer.
LIMITE_EVIDENCIA_FICHA = 800


def _evidencia_de_los_pintados(activo_id: int, grupos: list) -> None:
    """Anade a cada vulnerabilidad PINTADA la evidencia de su evaluacion.

    La ficha del activo tenia una tabla «Amenazas evaluadas» con la comparacion de
    versiones, la orden reproducible que la verifica, el motivo por el que un aviso todavia
    no publica correccion y la referencia oficial con su nombre en espanol. Esa tabla se
    retiro el 2026-09-09 porque listaba tambien lo que NO afecta, pero esas cuatro cosas
    son de las vulnerabilidades que SI afectan y no se pueden perder (las exigio la
    revision de precision del 2026-09-06): ahora viajan dentro de la trazabilidad de cada
    actualizacion, junto al CVE que las pidio.

    Solo se piden los pares (CVE, paquete) que la pagina va a pintar y solo con veredicto
    ``afectado``. El enriquecimiento es el mismo que hace
    ``aplicabilidad.veredictos_de_activo`` —se llaman sus propias funciones, no una copia
    de sus reglas— para que las dos pantallas digan lo mismo.
    """
    pares = {(c.get("cve"), c.get("paquete")) for g in grupos
             for v in (g.get("versiones") or []) for c in (v.get("cves") or [])
             if c.get("cve") and c.get("paquete")}
    if not pares:
        return
    pares = sorted(pares)[:LIMITE_EVIDENCIA_FICHA]
    cves = sorted({c for c, _ in pares})
    paquetes = sorted({p for _, p in pares})
    filas = g.db.execute(
        f"""SELECT ap.*, ap.referencia AS referencia_guardada,
                   a.ecosistema, a.so_familia, a.so_nombre, a.so_ciclo
              FROM aplicabilidad ap JOIN activos a ON a.id = ap.activo_id
             WHERE ap.activo_id = ? AND ap.veredicto = 'afectado'
               AND ap.cve IN ({','.join('?' * len(cves))})
               AND ap.paquete IN ({','.join('?' * len(paquetes))})""",
        (activo_id, *cves, *paquetes)).fetchall()
    pedidos = set(pares)
    indice: dict = {}
    for cruda in filas:
        f = dict(cruda)
        if (f.get("cve"), f.get("paquete")) not in pedidos:
            continue
        guardada = aplicabilidad.referencia_de_fila(f)
        f["evidencia"] = aplicabilidad.partir_evidencia(f.get("evidencia"))[0]
        f["avisos"] = aplicabilidad.avisos_con_url(f.get("aviso"))
        f["comparacion"] = aplicabilidad.explicar_fila(f)
        f["sin_parche_texto"] = (None if f.get("version_corregida")
                                 else aplicabilidad.texto_sin_correccion(f.get("sin_parche_motivo")))
        f["sin_parche_motivo_es"] = (None if f.get("version_corregida")
                                     else aplicabilidad.motivo_sin_parche_es(f.get("sin_parche_motivo")))
        f["referencia"] = aplicabilidad.referencia_segura(
            guardada or next((av["url"] for av in f["avisos"] if av["url"]), ""),
            cve=f.get("cve"), ecosistema=f.get("ecosistema"), familia=f.get("so_familia"),
            motor=f.get("motor"))
        f["referencia_es"] = aplicabilidad.etiqueta_referencia(f["referencia"])
        f["motor_es"] = aplicabilidad.MOTOR_ES.get(f.get("motor"), f.get("motor"))
        indice[(f["cve"], f["paquete"])] = f
    for grupo in grupos:
        for v in grupo.get("versiones") or []:
            for c in v.get("cves") or []:
                f = indice.get((c.get("cve"), c.get("paquete")))
                if f is None:
                    continue
                for campo in ("evidencia", "avisos", "comparacion", "sin_parche_texto",
                              "sin_parche_motivo_es", "referencia", "referencia_es",
                              "motor_es", "version_instalada"):
                    c[campo] = f.get(campo)


def _actualizaciones_del_activo(activo_id, limite: int = LIMITE_FICHA_ACTIVO) -> dict:
    """Las actualizaciones pendientes de UN activo, fusionadas por origen de paquete.

    La usa el parcial ``_remediaciones_activo.html`` (ficha del activo) a traves del
    procesador de contexto de abajo: la ficha la pinta ``activos.detalle``, que recibe el
    historial plano por CVE y paquete, y este blueprint no puede tocar esa vista. El
    alcance ya lo comprobo la ficha antes de llegar aqui; se repite el ``origen`` del
    perfil por si acaso, y solo se consulta ese activo (milisegundos con el indice).

    Desde el 2026-09-09 es la tabla PRINCIPAL de la ficha —una entrada por cosa que hay
    que actualizar, no una fila por vulnerabilidad— y trae la cola de versiones COMPLETA:
    ``limite_cves_por_version`` acota los CVE de cada version en vez de recortar la cola,
    porque la cola es la trazabilidad que el usuario pidio ver. Devuelve tambien las tres
    magnitudes pendientes del activo, para que la tarjeta de arriba y la tabla no puedan
    decir cifras distintas.
    """
    try:
        activo_id = int(activo_id)
    except (TypeError, ValueError):
        return dict(_SIN_ACTUALIZACIONES)
    if activo_id <= 0:
        return dict(_SIN_ACTUALIZACIONES)
    pagina = remediacion.pagina_actualizaciones(
        g.db, estado="abierta", activo_id=activo_id, limite=max(1, int(limite)),
        origen=auth.alcance_origen(),
        limite_cves=remediacion.LIMITE_CVES_FICHA,
        limite_cves_por_version=remediacion.LIMITE_CVES_POR_VERSION_FICHA)
    total = int(pagina["total"] or 0)
    _evidencia_de_los_pintados(activo_id, pagina["grupos"])
    salida = {"grupos": pagina["grupos"], "total": total,
              "recortado": total > len(pagina["grupos"])}
    salida.update(_cifras_pendientes_del_activo(activo_id))
    return salida


@bp.app_context_processor
def _ayudas_de_remediacion() -> dict:
    """Ayudas para las plantillas que muestran actualizaciones fuera de esta vista.

    ``actualizaciones_del_activo`` (ficha del activo), ``fusionar_plan`` (plan de
    remediacion de ``remediacion.html``, que junta los grupos con la misma orden) y
    ``nombre_actualizacion``. Son funciones perezosas: solo consultan si la plantilla las
    llama, y ninguna escribe nada.

    ``limite_accion_grupo`` es el tope de filas de remediacion de UNA accion de grupo
    (``remediacion.LIMITE_ACCION_GRUPO``): las plantillas no pintan el boton de grupo
    cuando la actualizacion lo supera, porque la peticion responderia siempre con el
    aviso del tope (hallazgo MEDIO de la revision del 2026-09-09: el boton «Ya se
    actualizó: comprobar las 1.358» nunca funcionaba)."""
    return {"actualizaciones_del_activo": _actualizaciones_del_activo,
            "fusionar_plan": remediacion.fusionar_plan,
            "nombre_actualizacion": remediacion.nombre_actualizacion,
            "limite_accion_grupo": remediacion.LIMITE_ACCION_GRUPO}


def _filtros() -> dict:
    estado = (request.args.get("estado") or "abierta").strip()[:20]
    if estado not in ESTADOS_FILTRO:
        estado = "abierta"
    vista = (request.args.get("vista") or VISTAS[0]).strip()[:20]
    if vista not in VISTAS:
        vista = VISTAS[0]
    # Filtro de severidad (2026-09-09). Desde el 2026-09-10 «todas» significa las tres
    # que se reportan —critica, alta y media—: la severidad baja no se ofrece porque no
    # cuenta en nada (``threatintel.remediacion.SEVERIDADES_FILTRO``). Un valor
    # desconocido, incluido un «low» guardado en un enlace antiguo, vuelve a «todas» y
    # nunca vacia la lista en silencio.
    severidad = (request.args.get("severidad") or "todas").strip()[:20].lower()
    if severidad not in remediacion.SEVERIDADES_FILTRO:
        severidad = "todas"
    return {"estado": estado, "vista": vista, "severidad": severidad,
            "proceso": (request.args.get("proceso") or "").strip()[:120],
            "q": (request.args.get("q") or "").strip()[:120],
            # Acota a UN activo: lo usa el enlace a los paquetes hermanos de una
            # actualizacion (revision del 2026-09-08). Solo enteros positivos.
            "activo": max(0, request.args.get("activo", 0, type=int) or 0) or None,
            # Alcance por tipo de maquina (2026-09-08): lo fija el perfil (Redes solo
            # servidores, Mantenimiento solo equipos de computo) y ningun parametro de la
            # direccion lo amplia; None para quien ve los dos tipos.
            "origen": auth.alcance_origen()}


def _activo_acotado(activo_id) -> dict | None:
    """Nombre del activo al que se acota la lista, o None si no se acota o no existe.
    Un activo del otro tipo de maquina responde 404, como uno inexistente (2026-09-08)."""
    if not activo_id:
        return None
    fila = g.db.execute("SELECT id, nombre, origen FROM activos WHERE id=?", (activo_id,)).fetchone()
    if fila is None:
        # Igual que un activo fuera de alcance: 404, para que un perfil acotado no pueda
        # distinguir «no existe» de «existe pero no es tuyo» (revisión del 2026-09-08).
        abort(404)
    auth.exigir_alcance(fila["origen"])
    return {"id": fila["id"], "nombre": fila["nombre"]}


def _exigir_alcance_remediacion(remediacion_id: int) -> None:
    """Corta con 404 si la remediacion es de un activo fuera del alcance del perfil.

    Es la comprobacion en el servidor que pidio el diseno del 2026-09-08: el perfil de
    Redes no puede comprobar ni documentar una remediacion de un equipo de computo aunque
    conozca su identificador, y la respuesta no revela que existe. Una remediacion
    inexistente responde tambien 404 (revisión del 2026-09-08): con dos respuestas
    distintas un perfil acotado podia enumerar que identificadores existen.
    """
    fila = g.db.execute(
        "SELECT a.origen FROM remediaciones r JOIN activos a ON a.id=r.activo_id WHERE r.id=?",
        (remediacion_id,)).fetchone()
    if fila is None:
        # Inexistente y fuera de alcance responden igual (404): sin diferencia que enumerar.
        abort(404)
    auth.exigir_alcance(fila["origen"])


def _dias_resumen() -> int:
    try:
        return max(1, int(float(g.cfg.get("remediacion_dias_resumen", 30) or 30)))
    except (TypeError, ValueError):
        return 30


#: Los dos tipos de maquina del bloque «Avance por tipo de maquina», con su nombre en
#: texto corrido (nunca «equipos» a secas) y su singular.
TIPOS_AVANCE = (("servidores", "Servidores", "servidor", "servidores"),
                ("equipos", "Equipos de cómputo", "equipo de cómputo", "equipos de cómputo"))


def _cola_al_empezar(dias: int) -> dict[str, dict]:
    """Por tipo de maquina, la cola que YA estaba pendiente al empezar el periodo y cuanta
    de ella se ha cerrado desde entonces.

    Por que existe (auditoria de tableros del 2026-09-15). El bloque «Avance por tipo de
    maquina» decia «0,6 % corregido: 140 de 22.731», y ese 22.731 era 140 corregidas en 30
    dias (un FLUJO) mas 22.591 pendientes hoy (un STOCK): dos magnitudes de periodos
    distintos sumadas en un denominador que no existe en ninguna parte. Es el mismo error
    que ya se corrigio en la grafica semanal. El unico porcentaje honesto con estos datos
    es de cohorte: de las filas que estaban pendientes cuando empezo el periodo, cuantas
    se han cerrado dentro del periodo. Numerador y denominador, la misma unidad (filas de
    remediacion), el mismo conjunto de filas y el mismo periodo.

    Devuelve ``{"desde": ..., "servidores": {"cohorte": n, "corregidas": n}, "equipos": …}``.
    Si un tipo no tiene cola anterior (``cohorte`` = 0) NO se inventa ningun porcentaje: la
    pantalla escribe por que no lo hay. Es lo que ocurre hoy sobre la base real, donde la
    remediacion mas antigua se detecto el 2026-09-04 y el periodo son 30 dias: todo lo
    pendiente nacio dentro del periodo.

    Una sola consulta agrupada por tipo de maquina, con los mismos filtros de severidad y
    de riesgo aceptado que ``remediacion.resumen``, para que no puedan discrepar.
    """
    conn = g.db
    desde = conn.execute("SELECT strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?)",
                         (f"-{max(1, int(dias or 30))} days",)).fetchone()[0]
    # Fragmentos « AND …» sin parametros, calculados por el propio modulo de remediacion.
    filtros = remediacion._y_sin_bajas(conn) + remediacion._y_sin_excepcion(conn)
    salida: dict[str, dict] = {"desde": desde}
    for clave, _nombre, _singular, _plural in TIPOS_AVANCE:
        salida[clave] = {"cohorte": 0, "corregidas": 0}
    for fila in conn.execute(
            f"""SELECT a.origen AS origen,
                       SUM(CASE WHEN r.detectado_at < :desde
                                 AND (r.corregido_at IS NULL OR r.corregido_at >= :desde)
                                THEN 1 ELSE 0 END) AS cohorte,
                       SUM(CASE WHEN r.detectado_at < :desde AND r.estado = 'corregida'
                                 AND r.corregido_at >= :desde THEN 1 ELSE 0 END) AS corregidas
                  FROM remediaciones r JOIN activos a ON a.id = r.activo_id
                 WHERE a.origen IS NOT NULL{filtros}
                 GROUP BY a.origen""", {"desde": desde}):
        if fila["origen"] in salida:
            salida[fila["origen"]] = {"cohorte": int(fila["cohorte"] or 0),
                                      "corregidas": int(fila["corregidas"] or 0)}
    return salida


def _avances_por_tipo(dias: int) -> list[dict] | None:
    """El avance de remediacion de servidores y de equipos de computo por separado.

    Peticion del usuario del 2026-09-08: el perfil de Redes (los jefes
    del proceso) tiene que ver «vulnerabilidades de servidores y de equipos al mismo
    tiempo y los avances de cada uno». Lo ven tambien la administracion y el operador SOC
    (auth.ROLES_AVANCES); para los perfiles acotados a un tipo no tiene sentido y para el
    de solo lectura no se pidio, asi que devuelve None y la plantilla no pinta el bloque.

    Por tipo: actualizaciones pendientes (una por activo y origen de paquete),
    vulnerabilidades pendientes (pares distintos de activo y CVE, 2026-09-09; las filas
    de remediacion van aparte en ``filas``), corregidas en el periodo, dias de media
    hasta corregir y el avance DEL PERIODO. Sale de ``remediacion.resumen`` con
    ``origen``, la misma funcion que las cifras de arriba, para que no puedan discrepar.

    El «porcentaje corregido» que habia aqui hasta el 2026-09-15 era corregidas del
    periodo sobre corregidas del periodo mas filas pendientes HOY: un flujo de 30 dias
    sumado a un stock de hoy, es decir, el mismo error de la grafica semanal. Se ha
    sustituido por el avance de cohorte que calcula :func:`_cola_al_empezar` (de lo que
    ya estaba pendiente al empezar el periodo, cuanto se ha cerrado dentro del periodo) y,
    cuando esa cola anterior no existe, por las DOS cifras separadas —lo corregido en el
    periodo y lo pendiente hoy— sin ningun porcentaje: ``avance_pct`` vale None y la
    plantilla escribe por que.
    """
    if not auth.ve_avances():
        return None
    cola = _cola_al_empezar(dias)
    avances = []
    for clave, nombre, singular, plural in TIPOS_AVANCE:
        # Solo las cifras: este bloque no pinta el reparto por proceso ni la serie
        # semanal, que es lo que cuesta (ver ``resumen_memorizado``).
        res = resumen_memorizado(dias, clave, solo_cifras=True)
        filas = int(res.get("abiertas") or 0)
        pendientes = int(res.get("vulnerabilidades_unicas") or 0)
        corregidas = int(res.get("corregidas_periodo") or 0)
        anterior = cola.get(clave) or {}
        cohorte = int(anterior.get("cohorte") or 0)
        cohorte_corregidas = int(anterior.get("corregidas") or 0)
        avance_pct = round(cohorte_corregidas * 100.0 / cohorte, 1) if cohorte else None
        avances.append({
            "clave": clave, "nombre": nombre, "singular": singular, "plural": plural,
            "actualizaciones": int(res.get("actualizaciones") or 0),
            "pendientes": pendientes, "filas": filas, "corregidas": corregidas,
            "activos_con_abiertas": int(res.get("activos_con_abiertas") or 0),
            "tiempo_medio_dias": res.get("tiempo_medio_dias"),
            # Avance del periodo sobre la cola que ya existia al empezarlo: misma unidad
            # (filas de remediacion), mismo conjunto de filas y mismo periodo.
            "cohorte": cohorte,
            "cohorte_corregidas": cohorte_corregidas,
            "cohorte_pendientes": max(cohorte - cohorte_corregidas, 0),
            "avance_pct": avance_pct,
            # Texto ya formateado en español («12,5 %»): el filtro «numero» solo sabe de
            # enteros y el porcentaje lleva un decimal.
            "avance_es": (graficos.fmt(avance_pct, 1) + " %") if avance_pct is not None else None,
            "desde": cola.get("desde"),
            "dias": int(res.get("dias") or dias),
        })
    return avances


def _barras_agrupadas(categorias, series, *, extras=None, ancho: float = 760,
                      alto: float = 200, aria: str = ""):
    """Barras verticales AGRUPADAS: una barra por serie y categoría, con su valor encima.

    Por qué existe aquí y no en ``webui/graficos.py``: la hoja de gráficos del proyecto
    solo ofrece barras APILADAS, y apilar dos flujos opuestos —vulnerabilidades detectadas
    y vulnerabilidades corregidas— es engañoso: la suma que se escribía encima de cada
    semana (28.019) no significa nada, y quien la leía entendía que esa semana se habían
    detectado 28.019 (revisión de claridad del 2026-09-15, punto 4). Con barras agrupadas
    cada flujo tiene su barra y su número.

    Se apoya en las mismas piezas internas de ``webui.graficos`` que usa
    ``barras_apiladas`` (escala, rejilla, ejes, envoltorio y leyenda) para que el gráfico
    salga idéntico al resto de la consola en tipografía, colores y modo oscuro, y para no
    duplicar la lógica de escalado. **Pendiente para el coordinador**: subir esta función
    a ``webui/graficos.py`` como ``barras_agrupadas`` y dejar aquí solo la llamada; el
    fichero de gráficos es compartido y no se toca desde esta vista.

    Sin ``style=``: la geometría va en atributos SVG y el color, por clase.
    """
    cats = [graficos._texto(c) for c in list(categorias or [])]
    n = len(cats)
    series_n = graficos._normalizar_series(series, n)
    if n == 0 or not series_n:
        return graficos.VACIO
    maximo = max((v for s in series_n for v in s["valores"]), default=0)
    if maximo <= 0:
        return graficos.VACIO

    ancho, alto = graficos._dim(ancho, 760), graficos._dim(alto, 200)
    tope, paso = graficos._escala(maximo)
    ticks = graficos._ticks(tope, paso)
    izq = max(graficos._ancho_texto(graficos.fmt(t)) for t in ticks) + 14
    ranura_aprox = (ancho - izq - 12) / n
    ancho_etq_x = max((graficos._ancho_texto(l)
                       for lineas, _ in graficos._lineas_eje_x(cats, ranura_aprox, False)
                       for l in lineas), default=0)
    der = max(12.0, ancho_etq_x / 2 - ranura_aprox / 2 + 6)
    arriba = 22.0
    pw = max(ancho - izq - der, 40.0)
    abajo = graficos._ALTO_LINEA * graficos._n_lineas_eje_x(cats, pw / n, False) + 12.0
    ph = max(alto - arriba - abajo, 40.0)
    ancho, alto = izq + pw + der, arriba + ph + abajo
    px0, py0 = izq, arriba

    def y_de(v: float) -> float:
        return py0 + ph - ph * v / tope

    ranura = pw / n
    # Las barras del grupo ocupan como mucho el 70 % de la ranura, con 2 px entre ellas.
    hueco = 2.0 if len(series_n) > 1 else 0.0
    ancho_barra = min(max((ranura * 0.70 - hueco * (len(series_n) - 1)) / len(series_n), 2.0), 40.0)
    ancho_grupo = ancho_barra * len(series_n) + hueco * (len(series_n) - 1)

    def x_centro(i: int) -> float:
        return px0 + ranura * i + ranura / 2

    cuerpo = [graficos._eje_y(px0, pw, y_de, ticks)]
    # Un rótulo por barra, pero solo cada «paso» posiciones si no caben todos: con 5
    # semanas caben los diez; con 30 se espaciarían y el valor seguiría en el <title>.
    anchos_valor = [graficos._ancho_texto(graficos.fmt(v), negrita=True)
                    for s in series_n for v in s["valores"]]
    paso_t = graficos._paso_etiquetas(n, max(anchos_valor) * len(series_n) + 4, ranura)
    for i, cat in enumerate(cats):
        x0 = x_centro(i) - ancho_grupo / 2
        for k, s in enumerate(series_n):
            v = s["valores"][i]
            x = x0 + k * (ancho_barra + hueco)
            titulo = f"{graficos._plano(cat)} · {s['nombre']}: {graficos.fmt(v)}"
            if v > 0:
                h = ph * v / tope
                cuerpo.append(
                    f'<rect class="serie-{s["clave"]}" x="{graficos._num(x)}" '
                    f'y="{graficos._num(y_de(v))}" width="{graficos._num(ancho_barra)}" '
                    f'height="{graficos._num(h)}">{graficos._titulo(titulo)}</rect>')
            if v > 0 and (n - 1 - i) % paso_t == 0:
                cuerpo.append(
                    f'<text class="etiqueta-valor" x="{graficos._num(x + ancho_barra / 2)}" '
                    f'y="{graficos._num(y_de(v) - 5)}" text-anchor="middle">'
                    f'{graficos._e(graficos.fmt(v))}</text>')
    cuerpo.append(graficos._eje_x(cats, x_centro, py0 + ph + graficos._ALTO_LINEA + 4,
                                  ranura, categorico=False))
    if not aria:
        nombres = ", ".join(s["nombre"] for s in series_n)
        aria = (f"Gráfico de barras agrupadas ({nombres}) en {graficos.fmt(n)} periodos, "
                f"de {graficos._plano(cats[0])} a {graficos._plano(cats[-1])}; "
                f"máximo {graficos.fmt(maximo)}")
    # ``_normalizar_series`` se queda con clave, nombre y valores, así que la nota de
    # cada serie («= 7.638 filas de remediación») viaja aparte, en ``extras``.
    extras = list(extras or [])
    filas = [(s["clave"], s["nombre"], graficos.fmt(sum(s["valores"])),
              extras[i] if i < len(extras) else "")
             for i, s in enumerate(series_n)]
    return graficos._figura("barras-agrupadas",
                            graficos._svg(ancho, alto, aria, "".join(cuerpo)),
                            graficos._leyenda(filas))


def _grafico_semanal(res: dict):
    """Barras AGRUPADAS por semana: vulnerabilidades detectadas y corregidas. None si no hay datos.

    Unidad: la VULNERABILIDAD (un CVE en un activo), la misma que encabeza la pagina.

    Barras agrupadas y no apiladas desde el 2026-09-15 (revision de claridad, punto 4):
    apiladas, el numero que se escribia encima de cada semana era la SUMA de detectadas y
    corregidas —dos flujos opuestos—, asi que la semana del 24 de agosto decia «28.019» y
    se leia como «esa semana se detectaron 28.019». Ahora cada flujo lleva su barra y su
    numero, y ninguna cifra es una suma sin significado.

    Tres correcciones de la revision visual del 2026-09-09 que siguen en pie:

    * La leyenda dice la UNIDAD («Vulnerabilidades corregidas», no «Corregidas»), porque sin
      la palabra no se sabe que se esta contando. Desde el 2026-09-15 dice ademas la
      equivalencia en FILAS de remediacion, que es la unidad de la tarjeta «Corregidas en
      30 dias» de la misma pantalla: eran 7.638 filas y 7.483 vulnerabilidades, dos cifras
      parecidas sin ninguna relacion escrita.
    * Una serie cuyo total es CERO se pinta en NEUTRO, no en su color: la leyenda decia
      «Corregidas 0» con el cuadrado verde, que se lee como si algo hubiera ido bien.
    * Las etiquetas del eje van sin ``categorico``, que es lo que permite a
      ``webui.graficos`` poner el dia y el mes arriba y el ano debajo («10 de agosto» /
      «2026»): antes decia «10 ago», sin ano y con el mes abreviado.
    """
    semanas = res.get("semanas") or []
    if not semanas:
        return None
    corregidas = [s["corregidas"] for s in semanas]
    detectadas = [s["detectadas"] for s in semanas]
    filas_corregidas = int(res.get("corregidas_periodo") or 0)
    extra_corregidas = (f"= {graficos.fmt(filas_corregidas)} filas de remediación, "
                        "que es la cifra de la tarjeta «Corregidas en "
                        f"{graficos.fmt(res.get('dias') or 0)} días»"
                        if filas_corregidas else "")
    return _barras_agrupadas(
        [s["etiqueta"] for s in semanas],
        [{"clave": "critico" if sum(detectadas) else "neutro",
          "nombre": "Vulnerabilidades detectadas", "valores": detectadas},
         {"clave": "exito" if sum(corregidas) else "neutro",
          "nombre": "Vulnerabilidades corregidas", "valores": corregidas}],
        extras=["", extra_corregidas],
        alto=200,
        aria=("Vulnerabilidades detectadas y corregidas por semana en los últimos "
              f"{res['dias']} días, dos barras por semana; una vulnerabilidad es un CVE en "
              "un activo, y no cuentan las de activos retirados de OCS Inventory"))


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
    """Si ``remediacion.listar`` ya acepta ``desplazamiento`` (LIMIT/OFFSET en SQL)."""
    try:
        return "desplazamiento" in inspect.signature(remediacion.listar).parameters
    except (TypeError, ValueError):
        return False


def _filas_alcanzables(total: int) -> int:
    """Cuantas filas del total se pueden recorrer en pantalla sin leer de una vez mas
    de ``TOPE_SIN_DESPLAZAMIENTO`` (2026-09-07)."""
    if _admite_desplazamiento():
        return total
    return min(total, max(int(TOPE_SIN_DESPLAZAMIENTO), LIMITE_PAGINA))


def _filas_de_la_pagina(*, estado, proceso, q: str, desplazamiento: int, limite: int,
                        activo_id=None, severidad=None) -> list[dict]:
    """Las remediaciones de una pagina, con los filtros ya aplicados.

    ``threatintel.remediacion.listar`` solo admite ``limite``. Mientras no acepte
    tambien ``desplazamiento`` (una linea en ese modulo, que no pertenece a esta
    vista), se le piden las filas hasta el final de la pagina y se recorta aqui: el
    resultado es el mismo y las primeras paginas, las que se usan, cuestan lo mismo.
    Lo que NO se hace (hallazgo del revisor, 2026-09-07) es leer sin tope: nunca se
    piden mas de ``TOPE_SIN_DESPLAZAMIENTO`` filas de una vez, asi que una pagina
    profunda de las 42.902 remediaciones no puede cargar la lista entera en memoria.
    En cuanto el parametro exista se usa sin tocar esta vista ni la plantilla.
    """
    comunes = {"estado": estado, "proceso": proceso, "q": q, "activo_id": activo_id,
               "origen": auth.alcance_origen(), "severidad": severidad}
    if _admite_desplazamiento():
        return remediacion.listar(g.db, limite=limite, desplazamiento=desplazamiento, **comunes)
    # Sin ``desplazamiento``, el numero de filas leidas se acota al tope para no
    # materializar en memoria toda la lista (ver TOPE_SIN_DESPLAZAMIENTO).
    hasta = min(desplazamiento + limite,
                max(int(TOPE_SIN_DESPLAZAMIENTO), LIMITE_PAGINA))
    if hasta <= desplazamiento:
        return []
    return remediacion.listar(g.db, limite=hasta, **comunes)[desplazamiento:]


def _grupos_de_la_pagina(*, estado, proceso, q: str, desplazamiento: int,
                         limite: int, activo_id=None,
                         severidad=None) -> tuple[list[dict], int]:
    """(actualizaciones de una pagina, total que cumple los filtros).

    ``remediacion.pagina_actualizaciones`` pagina en el servidor (LIMIT/OFFSET en la
    consulta agrupada) y devuelve el total en la misma consulta (2026-09-09): pedirlo
    aparte repetia el calculo de las firmas de fusion, unos 110 ms en produccion. Si la
    pagina pedida queda mas alla del final (enlace antiguo), el total no viene y se pide
    con ``contar_actualizaciones``; la vista recoloca la pagina y vuelve a pedirla.
    """
    comunes = {"estado": estado, "proceso": proceso, "q": q, "activo_id": activo_id,
               "origen": auth.alcance_origen(), "severidad": severidad}
    pagina = remediacion.pagina_actualizaciones(
        g.db, limite=limite, desplazamiento=desplazamiento, **comunes)
    total = pagina["total"]
    if total is None:
        total = remediacion.contar_actualizaciones(g.db, **comunes)
    return pagina["grupos"], int(total or 0)


def _volver_aqui() -> str:
    """La direccion de esta misma pagina, con sus filtros, para regresar tras actuar.

    Se manda en un campo oculto ``volver`` de los formularios: quien pide una
    comprobacion desde la pagina 7 filtrada por un proceso tiene que volver a la pagina 7
    filtrada por ese proceso, no al principio. ``remediaciones.comprobar`` valida el
    destino antes de redirigir (solo rutas locales), asi que no es un salto abierto.
    """
    return request.full_path + "#tabla-remediaciones"


@bp.route("/")
@auth.requiere_login
def lista():
    """Listado de remediaciones paginado en el servidor, agrupado o por vulnerabilidad.

    Por omision agrupa por actualizacion (activo y paquete): esa es la deduplicacion que
    pidio el usuario. El total de la paginacion es entonces el de GRUPOS, y la cabecera
    dice las dos magnitudes para no confundirlas: cuantas actualizaciones y cuantas
    vulnerabilidades cubren.
    """
    f = _filtros()
    dias = _dias_resumen()
    estado = None if f["estado"] == "todas" else f["estado"]
    comunes = {"estado": estado, "proceso": f["proceso"] or None, "q": f["q"],
               "activo_id": f["activo"], "severidad": f["severidad"]}
    # Las dos cifras del listado, siempre las dos: filas de remediacion que cumplen los
    # filtros y actualizaciones en que se agrupan. Con el alcance del perfil por delante.
    total_vulnerabilidades = remediacion.contar(g.db, origen=f["origen"], **comunes)
    agrupada = f["vista"] == "actualizacion"

    grupos: list[dict] = []
    filas: list[dict] = []
    if agrupada:
        # El total viene con la pagina (una sola consulta agrupada). Si la pagina pedida
        # queda fuera de rango se recoloca al final y se vuelve a pedir: una vez.
        pagina_pedida = request.args.get("pagina", 1, type=int)
        pagina, _ = _pagina_valida(pagina_pedida, TOPE_SIN_DESPLAZAMIENTO * LIMITE_PAGINA,
                                   LIMITE_PAGINA)
        grupos, total_actualizaciones = _grupos_de_la_pagina(
            desplazamiento=(pagina - 1) * LIMITE_PAGINA, limite=LIMITE_PAGINA, **comunes)
        total = total_actualizaciones
        alcanzables = _filas_alcanzables(total)
        pagina, paginas = _pagina_valida(pagina_pedida, alcanzables, LIMITE_PAGINA)
        if not grupos and total:
            grupos, _ = _grupos_de_la_pagina(desplazamiento=(pagina - 1) * LIMITE_PAGINA,
                                             limite=LIMITE_PAGINA, **comunes)
    else:
        total_actualizaciones = remediacion.contar_actualizaciones(g.db, origen=f["origen"],
                                                                  **comunes)
        total = total_vulnerabilidades
        alcanzables = _filas_alcanzables(total)
        pagina, paginas = _pagina_valida(request.args.get("pagina", 1, type=int),
                                         alcanzables, LIMITE_PAGINA)
        filas = _filas_de_la_pagina(desplazamiento=(pagina - 1) * LIMITE_PAGINA,
                                    limite=LIMITE_PAGINA, **comunes)
    # El resumen completo (con reparto por proceso y serie semanal) una sola vez.
    res = resumen_memorizado(dias, f["origen"])
    # Riesgo aceptado (2026-09-10). Las filas cubiertas por una excepcion vigente ya no
    # estan en la lista —salieron de la cola—, asi que aqui lo que se hace es DECIR
    # cuantas son y marcar con la insignia cualquiera que se siga viendo (por ejemplo si
    # el ajuste de severidad cambia el conjunto, o si alguna vez se ofrece verlas): la
    # insignia se resuelve con UNA consulta por pagina y se cruza en Python.
    aceptadas = _cifras_riesgo_aceptado(origen=f["origen"])
    indice_aceptado = indice_riesgo_aceptado(
        excepciones_vigentes(g.db, activo_id=f["activo"]) if aceptadas["hay"] else [])
    marcar_riesgo_aceptado(filas, indice_aceptado)
    # Esperando datos del inventario (2026-09-10, esquema v14): trabajo que nadie puede
    # hacer porque la evaluación no puede decidir. No está en la lista (salió de la cola),
    # así que se enseña en su propio panel, con el activo señalado y acotado al tipo de
    # máquina del perfil. Una sola consulta agrupada por activo.
    espera = remediacion.esperando_datos(g.db, origen=f["origen"], limite=LIMITE_ESPERANDO)
    # Cuantos ACTIVOS tienen el hallazgo «Sin datos de actualizaciones de Windows» de la
    # pagina de Activos (2026-09-15, punto 6 de la revision de claridad). Esta pagina
    # contaba filas de remediacion en espera («794 vulnerabilidades ... en 1 activo») y
    # aquella contaba maquinas («Sin datos suficientes de Windows (3)»): se leian como dos
    # cifras de lo mismo. Con las dos juntas se ve que cuentan cosas distintas y que una
    # es subconjunto de la otra: hay maquinas con el agente incompleto que todavia no
    # tienen ninguna remediacion en espera. Es un COUNT sobre un indice, milisegundos.
    origen_sql, params_origen = ("", [])
    if f["origen"]:
        origen_sql, params_origen = (" AND a.origen=?", [f["origen"]])
    espera["activos_con_hallazgo"] = int(g.db.execute(
        "SELECT COUNT(DISTINCT h.activo_id) FROM hallazgos_activos h "
        "JOIN activos a ON a.id=h.activo_id "
        "WHERE h.tipo='sin_datos_windows' AND h.resuelto_at IS NULL AND a.presente=1"
        + origen_sql, params_origen).fetchone()[0] or 0)
    return render_template("remediaciones.html", filas=filas, grupos=grupos, agrupada=agrupada,
                           riesgo_aceptado=aceptadas, esperando=espera,
                           avances=_avances_por_tipo(dias),
                           total=total, total_vulnerabilidades=total_vulnerabilidades,
                           total_actualizaciones=total_actualizaciones,
                           limite=LIMITE_PAGINA, limite_csv=LIMITE_CSV,
                           pagina=pagina, paginas=paginas,
                           por_pagina=LIMITE_PAGINA, alcanzables=alcanzables,
                           args=_args_a_conservar("pagina"),
                           resumen=res, filtros=f, estado=f["estado"], vistas=VISTAS,
                           vista_es=VISTA_ES,
                           severidades=remediacion.SEVERIDADES_FILTRO,
                           severidad_filtro_es=remediacion.SEVERIDAD_FILTRO_ES,
                           estado_es=remediacion.ESTADO_ES, estado_clave=remediacion.ESTADO_CLAVE,
                           procesos=remediacion.procesos(g.db, origen=f["origen"]),
                           grafico_semanal=_grafico_semanal(res),
                           # La vista elegida no es un filtro: «Quitar filtros» no debe
                           # devolver a nadie a la vista agrupada sin haberlo pedido.
                           hay_filtros=bool(f["proceso"] or f["q"] or f["activo"]
                                            or f["estado"] != "abierta"
                                            or f["severidad"] != "todas"),
                           motivo_desinstalado=remediacion.MOTIVO_DESINSTALADO,
                           # Acciones de remediación: solo administradores y Redes
                           activo_acotado=_activo_acotado(f["activo"]),
                           puede_remediar=auth.puede_remediar(),
                           comprobacion_es=remediacion.VEREDICTO_ES,
                           comprobacion_corto=remediacion.VEREDICTO_CORTO,
                           comprobacion_clave=remediacion.VEREDICTO_CLAVE,
                           volver=_volver_aqui())


@bp.route("/exportar.csv")
@auth.requiere_login
def exportar():
    """CSV (separador «;», UTF-8 con BOM para Excel) con los mismos filtros que la pagina.

    Va por vulnerabilidad (una fila por activo, CVE y paquete) tambien cuando la pantalla
    esta agrupada: la exportacion es el detalle completo, e incluye la columna
    ``version_corregida`` de cada aviso, que es de donde sale la version objetivo del grupo.
    """
    f = _filtros()
    filas = remediacion.listar(g.db, estado=None if f["estado"] == "todas" else f["estado"],
                               activo_id=f["activo"], origen=f["origen"],
                               proceso=f["proceso"] or None, q=f["q"],
                               severidad=f["severidad"], limite=LIMITE_CSV)
    salida = io.StringIO()
    escritor = csv.writer(salida, delimiter=";")
    escritor.writerow(["estado", "activo", "ip", "entorno", "proceso", "cve", "amenaza", "severidad", "kev",
                       "estado_amenaza", "paquete", "version_vulnerable", "version_corregida", "version_final",
                       "detectado", "comprobado", "corregido", "dias", "motivo_cierre"])
    for r in filas:
        escritor.writerow([celda_csv(v) for v in [
            r["estado_es"], r["activo_nombre"], r.get("ip") or "", r["entorno_es"], r.get("proceso") or "",
            r["cve"], r["titulo"], r.get("severity") or "", "sí" if r["in_kev"] else "no", r.get("estado_amenaza_es") or "",
            r["paquete"], r.get("version_vulnerable") or "", r.get("version_corregida") or "", r.get("version_final") or "",
            (r.get("detectado_at") or "")[:19], (r.get("comprobado_at") or "")[:19], (r.get("corregido_at") or "")[:19],
            r["dias"], r.get("cerrado_motivo") or ""]])
    return Response("﻿" + salida.getvalue(), mimetype="text/csv; charset=utf-8",
                    headers={"Content-Disposition": "attachment; filename=remediaciones.csv"})


# --------------------------------------------------------------------------
# «Ya lo remedie, compruebalo» y documentar (v10, 2026-09-07; alcance de grupo 2026-09-08)
#
# Las dos unicas acciones que puede hacer el perfil «Redes». La marca de
# la persona NO cierra nada: pide la comprobacion y la plataforma decide comparando la
# version que OCS reporta con la que corrige el fallo (threatintel.remediacion.comprobar).
#
# Desde el 2026-09-08 las dos aceptan un campo ``alcance=grupo``: la accion se aplica a
# TODAS las vulnerabilidades pendientes del mismo (activo, paquete), porque una sola
# actualizacion las resuelve todas y pedirlas de una en una serian cientos de clics para
# una unica tarea. No hay ruta nueva a proposito: el mapa de rutas es lo que fija el
# alcance del perfil, y una ruta mas lo ampliaria sin que nadie lo revisara.
# --------------------------------------------------------------------------
def _ip() -> str | None:
    return request.remote_addr


def _es_grupo() -> bool:
    """Si la accion se pidio para la actualizacion entera y no para una vulnerabilidad."""
    return (request.form.get("alcance") or "").strip() == "grupo"


def _volver(remediacion_id: int) -> str:
    """A donde regresar: al activo si se sabe, y si no a la lista de remediacion."""
    destino = (request.form.get("volver") or "").strip()
    if destino.startswith("/") and "//" not in destino and "\\" not in destino:
        return destino
    fila = g.db.execute("SELECT activo_id FROM remediaciones WHERE id=?",
                        (remediacion_id,)).fetchone()
    if fila:
        return url_for("activos.detalle", activo_id=fila["activo_id"]) + "#remediaciones-lista"
    return url_for("remediaciones.lista")


def _desglose(conteo: dict) -> str:
    """«3 corregidas, 26 siguen vulnerables»: solo lo que no es cero, en español."""
    textos = []
    for clave, singular, plural in (
            ("corregida", "1 corregida", "{n} corregidas"),
            ("desinstalado", "1 con el paquete ya desinstalado", "{n} con el paquete ya desinstalado"),
            ("sigue_vulnerable", "1 sigue vulnerable", "{n} siguen vulnerables"),
            ("sin_datos", "1 sin datos para comprobar", "{n} sin datos para comprobar")):
        n = int(conteo.get(clave) or 0)
        if n == 1:
            textos.append(singular)
        elif n > 1:
            textos.append(plural.format(n=n))
    if not textos:
        return "sin resultados"
    if len(textos) == 1:
        return textos[0]
    return ", ".join(textos[:-1]) + " y " + textos[-1]


def _mensaje_grupo(resultado: dict) -> tuple[str, str]:
    """(mensaje, nivel) de una comprobacion de toda una actualizacion."""
    objetivo = (f" a la versión {resultado['version_objetivo']}"
                if resultado.get("version_objetivo") else "")
    total = resultado["total"]
    # En la vista agrupada el formulario manda siempre «alcance=grupo», tambien cuando el
    # grupo tiene una sola vulnerabilidad pendiente (14.818 de 19.284 grupos en
    # produccion), asi que la frase del caso singular es la mas frecuente y tiene que
    # estar bien escrita: «se comprobaron las 1 vulnerabilidad» era agramatical
    # (revision del 2026-09-08).
    # Con varios paquetes del mismo origen (2026-09-09) «total» son filas de remediacion
    # (una por CVE y paquete) y «cves» las vulnerabilidades distintas: se dicen las dos.
    paquetes = len(resultado.get("paquetes") or [resultado.get("paquete")])
    cves = int(resultado.get("cves") or total)
    if paquetes > 1:
        cubre = (f"se comprobaron las {cves} vulnerabilidad{'es' if cves != 1 else ''} que "
                 f"cubre en sus {paquetes} paquetes ({total} filas de remediación)")
    elif total == 1:
        cubre = "se comprobó la única vulnerabilidad que cubre"
    else:
        cubre = f"se comprobaron las {total} vulnerabilidades que cubre"
    mensaje = (f"Actualización de «{resultado.get('nombre') or resultado['paquete']}»{objetivo} en "
               f"{resultado['activo_nombre']}: {cubre}. "
               f"{_desglose(resultado['conteo']).capitalize()}.")
    if resultado["cerradas"]:
        mensaje += (f" Quedan cerradas {resultado['cerradas']} "
                    f"remediaci{'ones' if resultado['cerradas'] != 1 else 'ón'}.")
    if resultado["conteo"].get("sigue_vulnerable"):
        mensaje += (" Las que siguen vulnerables no se cierran: la comprobación se "
                    "repetirá sola en la próxima sincronización con OCS Inventory.")
    nivel = {"corregida": "exito", "sigue_vulnerable": "error",
             "sin_datos": "aviso"}.get(resultado["veredicto"], "info")
    return mensaje, nivel


@bp.route("/<int:remediacion_id>/comprobar", methods=["POST"])
@auth.requiere_remediacion
@auth.requiere_csrf
def comprobar(remediacion_id: int):
    """Pide a la plataforma que compruebe si esa vulnerabilidad ya está corregida.

    Con ``alcance=grupo`` comprueba todas las pendientes del mismo activo y paquete: una
    sola actualización las resuelve todas, y el mensaje dice cuántas se comprobaron y qué
    respondió cada una.
    """
    _exigir_alcance_remediacion(remediacion_id)
    destino = _volver(remediacion_id)
    grupo = _es_grupo()
    try:
        with db.session(current_app.config.get("DB_PATH")) as conn:
            if grupo:
                resultado = remediacion.comprobar_grupo(conn, remediacion_id,
                                                        solicitante=g.usuario, ip=_ip())
            else:
                resultado = remediacion.comprobar(conn, remediacion_id, solicitante=g.usuario,
                                                  ip=_ip())
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(destino)
    except Exception as exc:  # noqa: BLE001
        current_app.logger.error("fallo la comprobación de la remediación %s", remediacion_id,
                                 exc_info=exc)
        flash("No se pudo comprobar la remediación por un error interno; quedó anotado en el "
              "registro del servicio.", "error")
        return redirect(destino)

    if grupo:
        mensaje, nivel = _mensaje_grupo(resultado)
        flash(mensaje, nivel)
        return redirect(destino)

    nivel = {"corregida": "exito", "desinstalado": "exito",
             "sigue_vulnerable": "error", "sin_datos": "aviso"}.get(resultado["veredicto"], "info")
    mensaje = (f"{resultado['cve']} · {resultado['paquete']} en "
               f"{resultado['activo_nombre']}: {resultado['veredicto_es']}. "
               f"{resultado['detalle']}")
    if resultado["cerrada"]:
        mensaje += " La remediación queda cerrada."
    elif resultado["veredicto"] == "sigue_vulnerable":
        mensaje += (" No se cierra: la comprobación se repetirá sola en la próxima "
                    "sincronización con OCS Inventory.")
    flash(mensaje, nivel)
    return redirect(destino)


@bp.route("/<int:remediacion_id>/nota", methods=["POST"])
@auth.requiere_remediacion
@auth.requiere_csrf
def nota(remediacion_id: int):
    """Documenta qué se hizo con esa vulnerabilidad en ese equipo.

    Con ``alcance=grupo`` la misma nota se guarda en todas las pendientes del activo y el
    paquete: lo que se documenta («programado para la ventana del sábado») vale para la
    actualización completa, no para uno de sus CVE.
    """
    _exigir_alcance_remediacion(remediacion_id)
    destino = _volver(remediacion_id)
    grupo = _es_grupo()
    try:
        with db.session(current_app.config.get("DB_PATH")) as conn:
            if grupo:
                resultado = remediacion.anotar_grupo(conn, remediacion_id, autor=g.usuario,
                                                     texto=request.form.get("texto") or "",
                                                     ip=_ip())
            else:
                remediacion.anotar(conn, remediacion_id, autor=g.usuario,
                                   texto=request.form.get("texto") or "", ip=_ip())
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(destino)
    except Exception as exc:  # noqa: BLE001
        # Igual que la ruta hermana ``comprobar`` (revisión del 2026-09-09): un error de
        # base de datos —base bloqueada, disco lleno— no puede convertirse en un 500 con
        # rastro de pila; queda en el registro del servicio y la persona vuelve a su
        # página con un mensaje neutro que no revela nada del error interno.
        current_app.logger.error("falló la nota de la remediación %s", remediacion_id,
                                 exc_info=exc)
        flash("No se pudo guardar la nota por un error interno; quedó anotado en el "
              "registro del servicio.", "error")
        return redirect(destino)
    if grupo:
        total = resultado["total"]
        paquetes = len(resultado.get("paquetes") or [resultado.get("paquete")])
        cves = int(resultado.get("cves") or total)
        if paquetes > 1:
            donde = (f"las {cves} vulnerabilidad{'es' if cves != 1 else ''} que cubre, en sus "
                     f"{paquetes} paquetes ({total} filas de remediación),")
        elif total == 1:
            donde = "la única vulnerabilidad que cubre"
        else:
            donde = f"las {total} vulnerabilidades que cubre"
        flash(f"Nota guardada en {donde} la actualización de "
              f"«{resultado.get('nombre') or resultado['paquete']}» "
              f"en {resultado['activo_nombre']}.", "exito")
    else:
        flash("Nota guardada.", "exito")
    return redirect(destino)

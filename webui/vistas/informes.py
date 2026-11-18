"""Módulo de informes: generador de informes a medida y descarga del mensual.

Historia y por qué está así:

* **2026-09-08.** El usuario pidió «un módulo para crear informes donde solo tenga acceso
  el rol de operador SOC» y, en Tendencias, «una opción para poder descargar informes del
  mes que desee». Nació esta página con una fila por mes y un botón que generaba el mismo
  documento que la ejecución programada.
* **2026-09-10.** El usuario pidió lo que faltaba: «el apartado de /informes/ es para que
  se puedan crear informes con lo que uno desee, es decir que uno pueda agregar lo que
  desea y no descargar los informes de cada mes; la idea es poder crear informes
  personalizados y tener plantillas de informes preconfiguradas». La página es ahora un
  **generador**: se elige el periodo, el alcance, las severidades y los apartados, se ve
  antes de descargar cuántas vulnerabilidades y cuántos activos entran, y se descarga. El
  informe mensual completo sigue estando, como una plantilla más y con su descarga rápida
  por mes, y el documento que produce es EXACTAMENTE el de siempre.

Reglas que se cumplen aquí:

* **Sin correo.** Se genera y se devuelve al navegador como descarga. El envío mensual
  sigue siendo cosa exclusiva de la ejecución programada.
* **Sin ficheros en el árbol del proyecto.** El documento se construye en memoria
  (:func:`threatintel.report.generar_en_memoria`) y viaja en la respuesta: no queda copia
  en ``reports/`` ni en ``data/``, así que no hay nada que limpiar ni que pueda leer otro
  usuario del servidor. El nombre del fichero se compone solo con claves internas y
  fechas, nunca con el título que escriba la persona.
* **Permiso.** Solo administradores y el perfil «operador SOC»
  (:data:`webui.auth.ROLES_INFORMES`). Cualquier otro perfil recibe 403 sin que se le diga
  qué perfil haría falta.
* **Alcance del perfil.** Un perfil acotado a un tipo de máquina (Redes: servidores;
  Mantenimiento: equipos de cómputo) solo puede informar de su parte: el recorte lo aplica
  el servidor con ``auth.alcance_origen`` y pedir otro tipo o un activo ajeno responde 404,
  igual que en el resto de la plataforma.
* **Auditoría.** Cada generación queda en ``audit_log``: la descarga mensual con la acción
  ``informe.generado`` y el mes, y el informe a medida con ``informe.medida``, la plantilla,
  el periodo, el alcance, las severidades y los apartados.
* **La severidad baja no se reporta.** No se ofrece en el formulario y el módulo de
  selección la descarta aunque se escriba en la dirección web.
* **Sin modelo de lenguaje.** El resumen ejecutivo se redacta con la plantilla determinista
  de la plataforma, no con Ollama (:func:`_cfg_para_interfaz`). Medido el 2026-09-08: con
  el modelo tardaba 200 segundos y nginx corta la respuesta a los 120
  (``proxy_read_timeout``); la descarga no llegaría nunca. Tiempos medidos el 2026-09-10
  sobre la base real (7.121 amenazas, 717 activos): informe mensual completo 16 segundos,
  resumen para dirección 0,4, informe técnico de remediación 1,0, informe por proceso 0,7,
  explotación activa 3,2 y informe de un activo 3,3.
* **2026-09-15.** El usuario pidió «que a final de mes también se genere un informe
  ejecutivo sobre las amenazas del mes que no exceda las 10 páginas». Es una plantilla más
  de esta pantalla (``ejecutivo``), pero con estructura FIJA: ni periodo libre, ni alcance
  libre, ni apartados a elegir. La construye ``report.construir_documento_ejecutivo`` y la
  ejecución mensual programada la genera y la envía junto al informe completo.
* **Nada se guarda en la base.** Una selección se comparte por su dirección web (botón
  «Copiar el enlace de este informe»): es el paso previo a las plantillas propias
  guardadas, que necesitan una tabla nueva.
"""
from __future__ import annotations

import functools
import re
from typing import Any, Callable, Optional

from flask import (Blueprint, Response, abort, current_app, flash, g, redirect,
                   render_template, request, url_for)

from threatintel import config as ti_config
from threatintel import db, informe_seleccion as seleccion_informe, queries, report
from threatintel.logging_setup import get_logger
from threatintel.paths import report_file
from webui import auth
from webui.filtros import mes_es, numero

log = get_logger("webui.informes")

bp = Blueprint("informes", __name__, url_prefix="/informes")

#: Acción que queda en audit_log por cada informe mensual descargado desde la interfaz.
ACCION_AUDITORIA = "informe.generado"
#: Acción de un informe a medida (2026-09-10): en ``entity_id`` va la plantilla usada y en
#: el detalle el periodo, el alcance, las severidades y los apartados.
ACCION_AUDITORIA_MEDIDA = "informe.medida"
#: Tipo MIME oficial de un documento Word (.docx).
MIME_DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
#: Un mes válido tiene la forma «AAAA-MM» con MM entre 01 y 12; nada más entra al
#: nombre del fichero ni a la consulta.
_RE_MES = re.compile(r"^\d{4}-(0[1-9]|1[0-2])$")
#: Límite de meses que se piden a ``evolucion_mensual`` para las cifras de la lista:
#: cien años de histórico, que en la práctica es «todos».
_MESES_TODOS = 1200
#: A partir de estas amenazas en el periodo, un informe con apartados pesados (fichas,
#: anexo o cola de remediación) tarda lo suficiente para avisarlo en pantalla. Medido el
#: 2026-09-10: 1.330 amenazas con todos los apartados, 16 segundos; nginx corta a los 120.
UMBRAL_AVISO_LENTO = 700


def _puede_generar_informes() -> bool:
    """True si el perfil de la sesión puede generar y descargar informes.

    Administradores y el perfil «operador SOC». La regla vive en
    ``webui.auth.ROLES_INFORMES``: una sola lista para el menú, el decorador y aquí.
    """
    return auth.puede_informes()


def requiere_informes(vista: Callable) -> Callable:
    """Decorador de permiso del módulo: sesión válida y perfil autorizado."""
    @functools.wraps(vista)
    @auth.requiere_login
    def envoltorio(*args: Any, **kwargs: Any):
        if not _puede_generar_informes():
            # Sin nombrar el perfil que haría falta (petición del usuario del 2026-09-08:
            # «que solamente diga acceso inválido»): decirlo le indicaría a quien prueba
            # qué cuenta tendría que robar.
            abort(403, "No tiene permiso para realizar esta acción.")
        return vista(*args, **kwargs)
    return envoltorio


class _CfgSinModelo:
    """Configuración envuelta que apaga el motor de redacción para el informe.

    Delega todo en la configuración real salvo ``translate_engine``, que responde
    «none»: así :func:`threatintel.translate.resumen_ejecutivo` compone el párrafo
    determinista en milisegundos en vez de pedírselo al modelo de lenguaje local. Se
    envuelve en lugar de copiar y editar ``Config.settings`` para no tocar el objeto que
    comparte toda la petición (``g.cfg``).
    """

    def __init__(self, cfg: Any):
        self._cfg = cfg

    def get(self, key: str, default: Any = None) -> Any:
        if key == "translate_engine":
            return "none"
        return self._cfg.get(key, default)

    def __getattr__(self, nombre: str) -> Any:
        return getattr(self._cfg, nombre)


def _cfg_para_interfaz(cfg: Any) -> _CfgSinModelo:
    """La configuración con la que se genera el informe desde la interfaz."""
    return _CfgSinModelo(cfg)


def nombre_fichero(mes: str) -> str:
    """«informe_amenazas_2026-08.docx»: el nombre de la descarga rápida del mes."""
    return f"informe_amenazas_{mes}.docx"


def mes_valido(mes: Any) -> bool:
    """True si ``mes`` tiene la forma «AAAA-MM» con un mes real."""
    return bool(mes) and bool(_RE_MES.match(str(mes)))


def generaciones_previas(conn) -> dict[str, dict]:
    """Última descarga de cada mes desde la interfaz, según ``audit_log``.

    Devuelve ``{"2026-08": {"at": ..., "username": ..., "veces": n}}``. Se recorren
    las filas en orden cronológico para que la última pise a las anteriores: son
    pocas (una por descarga) y así no hace falta una subconsulta correlacionada.
    """
    salida: dict[str, dict] = {}
    filas = conn.execute(
        "SELECT entity_id, at, username FROM audit_log WHERE action=? ORDER BY at ASC, id ASC",
        (ACCION_AUDITORIA,)).fetchall()
    for fila in filas:
        mes = fila["entity_id"]
        if not mes:
            continue
        anterior = salida.get(mes)
        salida[mes] = {"at": fila["at"], "username": fila["username"],
                       "veces": (anterior["veces"] if anterior else 0) + 1}
    return salida


def meses_para_informe(conn, *, excluir_bajas: bool) -> list[dict]:
    """Los meses con amenazas registradas, del más reciente al más antiguo, con lo que
    la lista necesita: nombre en español, cifras por severidad, si ya se generó desde
    la interfaz (y por quién) y si la ejecución mensual programada dejó su fichero.

    La lista de meses sale de ``queries.meses_disponibles`` (todo mes con alguna
    amenaza) y las cifras de ``queries.evolucion_mensual`` con el mismo criterio de
    severidades que el informe: un mes cuyas amenazas fueran todas bajas aparece con
    0 amenazas reportables, que es exactamente lo que el informe diría.
    """
    cifras = {e["month"]: e for e in
              queries.evolucion_mensual(conn, _MESES_TODOS, excluir_bajas=excluir_bajas)}
    previas = generaciones_previas(conn)
    filas = []
    for mes in queries.meses_disponibles(conn):
        e = cifras.get(mes) or {}
        filas.append({
            "mes": mes,
            "nombre": mes_es(mes),
            "total": int(e.get("total") or 0),
            "criticas": int(e.get("criticas") or 0),
            "altas": int(e.get("altas") or 0),
            "medias": int(e.get("medias") or 0),
            "en_kev": int(e.get("en_kev") or 0),
            "generado": previas.get(mes),
            "programado": report_file(mes).exists(),
            "fichero": nombre_fichero(mes),
        })
    return filas


# --------------------------------------------------------------------------
# Informe a medida (2026-09-10)
# --------------------------------------------------------------------------
def _meses_disponibles() -> list[str]:
    """Los meses con amenazas, calculados UNA vez por petición.

    La vista previa viva (2026-09-10) pide esta pantalla en cada cambio del formulario y
    la lista de meses se necesitaba dos veces por petición (al validar la selección y al
    pintar el selector). Se guarda en ``g`` porque ``g`` dura exactamente lo que la
    petición: ni se comparte entre usuarios ni se queda obsoleta.
    """
    cache = getattr(g, "_meses_informe", None)
    if cache is None:
        cache = list(queries.meses_disponibles(g.db))
        g._meses_informe = cache
    return cache


def _seleccion(params) -> seleccion_informe.Seleccion:
    """La selección validada que piden los parámetros de la petición.

    El alcance del perfil (``auth.alcance_origen``) entra como ``origen_perfil`` y el
    módulo de selección lo aplica por encima de cualquier parámetro: es la única forma de
    que un perfil de Redes no pueda pedir un informe de equipos de cómputo.
    """
    return seleccion_informe.Seleccion.desde_parametros(
        params,
        meses_disponibles=_meses_disponibles(),
        origen_perfil=auth.alcance_origen())


def _exigir_alcance(sel: seleccion_informe.Seleccion, params) -> Optional[dict]:
    """Corta con 404 si lo pedido cae fuera del alcance del perfil.

    404 y no 403 a propósito, igual que en Activos: un identificador del otro tipo de
    máquina no debe revelar que existe. Devuelve el activo elegido cuando el alcance es
    «un activo concreto», para que la pantalla pueda decir su nombre.
    """
    pedido = str(params.get("tipo") or "").strip()
    if pedido in seleccion_informe.TIPOS_MAQUINA:
        auth.exigir_alcance(pedido)
    if sel.alcance != "activo" or not sel.activo_id:
        return None
    elegido = seleccion_informe.activo(g.db, sel.activo_id)
    if elegido is None:
        return None
    auth.exigir_alcance(elegido.get("origen"))
    return elegido


def _avisos(sel: seleccion_informe.Seleccion, previa: dict, *, cfg,
            actualizaciones: Optional[int],
            estimacion: Optional[dict] = None) -> list[str]:
    """Lo que hay que decir antes de descargar: recortes y tiempos de espera."""
    avisos: list[str] = []
    max_fichas = int(cfg.get("report_max_detail_items", 120) or 120)
    max_anexo = int(cfg.get("report_max_anexo_items", 250) or 250)
    pesados = [c for c in sel.apartados
               if seleccion_informe.APARTADO_POR_CLAVE[c].pesado]
    if "prioritarias" in sel.apartados and previa["amenazas"] > max_fichas:
        avisos.append(
            f"El documento detallará como máximo {numero(max_fichas)} fichas, las de mayor "
            f"prioridad de las {numero(previa['amenazas'])} amenazas del periodo; "
            f"el resto queda en el anexo o en la interfaz.")
    if "anexo" in sel.apartados and previa["amenazas"] > max_anexo:
        avisos.append(
            f"El anexo listará como máximo {numero(max_anexo)} amenazas de las "
            f"{numero(previa['amenazas'])} del periodo, ordenadas por prioridad.")
    if actualizaciones is not None and actualizaciones > 2 * max_fichas:
        avisos.append(
            f"La cola de remediación tiene {numero(actualizaciones)} actualizaciones "
            f"pendientes en este alcance y el documento incluirá las "
            f"{numero(2 * max_fichas)} de mayor prioridad; la cola completa está en la "
            f"página de Remediación.")
    # UNA sola estimación de tiempo en el panel (2026-09-15, punto 16 de la revisión de
    # claridad): este aviso decía «entre quince y cuarenta segundos» mientras la línea de
    # la estimación, tres renglones más arriba, decía «unos 7 segundos». La que vale es la
    # calculada con el modelo de ``informe_seleccion.estimacion`` (calibrado sobre los
    # informes generados con la base real), que es la que ya se escribe arriba; aquí solo
    # se advierte de que hay que esperar sin cerrar la página.
    if pesados and previa["amenazas"] >= UMBRAL_AVISO_LENTO:
        cuanto = (estimacion or {}).get("tiempo_es") or "varios segundos"
        avisos.append(
            f"Con {numero(previa['amenazas'])} amenazas y "
            f"{numero(len(pesados))} apartados detallados la generación tarda {cuanto}, "
            f"la misma estimación que se lee arriba. No cierre la página: la descarga "
            f"empieza sola cuando el documento está listo.")
    return avisos


def _campos_ocultos(sel: seleccion_informe.Seleccion) -> list[tuple[str, str]]:
    """La selección como pares nombre/valor para el formulario que la genera.

    El botón «Generar y descargar» es un POST (deja rastro en la auditoría y cuesta
    segundos), así que la selección viaja en campos ocultos con el mismo nombre que en la
    dirección web: una sola forma de expresarla y ninguna posibilidad de que la vista
    previa y el documento no coincidan.
    """
    pares: list[tuple[str, str]] = []
    for clave, valor in sel.a_parametros().items():
        if isinstance(valor, (list, tuple)):
            pares.extend((clave, str(v)) for v in valor)
        else:
            pares.append((clave, str(valor)))
    return pares


def _datos_de_pantalla(sel: seleccion_informe.Seleccion, *,
                       activo_elegido: Optional[dict]) -> dict[str, Any]:
    """Todo lo que la plantilla necesita para pintar el formulario y la vista previa."""
    conn = g.db
    cfg = g.cfg
    completa, falta = sel.completa()
    # Las cifras se cuentan en cuanto se sabe DE QUÉ habla el informe, aunque todavía no
    # haya ningún apartado marcado (2026-09-10): así quien empieza de cero ve desde el
    # primer momento cuántas amenazas entran mientras arma el documento. Lo único
    # que impide contar es un alcance a medias (un proceso o un activo sin elegir),
    # porque entonces la cifra sería la de toda la organización y engañaría.
    pendiente = sel.alcance_pendiente()
    previa = seleccion_informe.vista_previa(conn, sel) if not pendiente else None
    actualizaciones = (seleccion_informe.actualizaciones_pendientes(conn, sel)
                       if previa is not None and "remediacion" in sel.apartados else None)
    vacio = bool(previa) and previa["amenazas"] == 0 and not actualizaciones
    max_fichas = int(cfg.get("report_max_detail_items", 120) or 120)
    max_anexo = int(cfg.get("report_max_anexo_items", 250) or 250)
    # La estimación se calcula UNA vez y la comparten la línea de «Estimación: …» y el
    # aviso de que la generación tarda: eran dos cifras contradictorias en el mismo panel
    # («unos 7 segundos» y «entre quince y cuarenta segundos», 2026-09-15).
    estimacion = (seleccion_informe.estimacion(
        sel, previa or {}, actualizaciones=actualizaciones or 0,
        max_fichas=max_fichas, max_anexo=max_anexo) if previa is not None else None)
    # Por qué NO se puede generar todavía, escrito para leerlo antes de pulsar nada.
    if pendiente:
        razon = pendiente
    elif not completa:
        razon = falta
    elif vacio:
        razon = ("Esa selección no devuelve ninguna amenaza ni ninguna "
                 "actualización pendiente, así que el documento saldría vacío. Amplíe el "
                 "periodo, cambie el alcance o marque más severidades.")
    else:
        razon = ""
    return {
        "sel": sel,
        "plantillas": seleccion_informe.PLANTILLAS,
        "plantilla_actual": seleccion_informe.PLANTILLA_POR_CLAVE[sel.plantilla],
        "plantilla_libre": seleccion_informe.PERSONALIZADA,
        "modo": sel.modo(),
        "modo_es": sel.etiqueta_modo(),
        "apartados_catalogo": seleccion_informe.APARTADOS,
        # Los del informe ejecutivo van aparte: no son apartados que se puedan marcar, son
        # la estructura fija de ese documento (2026-09-15).
        "apartados_ejecutivo": seleccion_informe.APARTADOS_EJECUTIVO_DETALLE,
        "clases_periodo": seleccion_informe.CLASES_PERIODO,
        "alcances": seleccion_informe.ALCANCES,
        "tipos_maquina": seleccion_informe.TIPOS_MAQUINA,
        "severidades": seleccion_informe.SEVERIDADES,
        "severidad_es_plural": seleccion_informe.SEVERIDAD_ES_PLURAL,
        "meses": _meses_disponibles(),
        # Los mismos meses con amenazas, pero solo el año: alimenta los selectores de
        # año, trimestre y semestre sin otra consulta (2026-11-17).
        "anios_disponibles": (anios := sorted(
            {m[:4] for m in _meses_disponibles()} | {str(seleccion_informe.hoy().year)},
            reverse=True)),
        "opciones_trimestre": [(f"{a}-T{t}", seleccion_informe.etiqueta_trimestre(int(a), t))
                               for a in anios for t in (4, 3, 2, 1)],
        "opciones_semestre": [(f"{a}-S{s}", seleccion_informe.etiqueta_semestre(int(a), s))
                              for a in anios for s in (2, 1)],
        # Los selectores largos solo se calculan cuando la pantalla los va a pintar: la
        # lista de activos elegibles son 598 máquinas en producción y no tiene sentido
        # consultarla ni enviarla al navegador si el alcance no es «un activo concreto».
        "procesos": (seleccion_informe.procesos(conn, origen=auth.alcance_origen())
                     if sel.alcance == "proceso" else []),
        "activos_elegibles": (seleccion_informe.activos_elegibles(
            conn, origen=auth.alcance_origen()) if sel.alcance == "activo" else []),
        "tecnologias_elegibles": (seleccion_informe.tecnologias_elegibles(conn)
                                  if sel.alcance == "tecnologia" else []),
        "activo_elegido": activo_elegido,
        "alcance_es": seleccion_informe.etiqueta_alcance(conn, sel),
        "periodo_es": sel.etiqueta_periodo(),
        "completa": completa,
        "falta": falta,
        "pendiente": pendiente,
        "razon_no_generar": razon,
        "puede_generar": not razon,
        "previa": previa,
        "actualizaciones": actualizaciones,
        "vacio": vacio,
        "esquema": seleccion_informe.esquema(sel),
        "estimacion": estimacion,
        "avisos_informe": (_avisos(sel, previa, cfg=cfg, actualizaciones=actualizaciones,
                                   estimacion=estimacion)
                           if previa else []),
        "campos_ocultos": _campos_ocultos(sel),
        # Dirección absoluta a propósito: el botón «Copiar el enlace de este informe» sirve
        # para guardarlo o pasárselo a un compañero.
        #
        # Se construye con el NOMBRE PÚBLICO configurado (ajuste ``webui_url``, el mismo
        # que usan los correos a través de ``threatintel.config.url_publica``) y no con el
        # servidor por el que haya llegado la petición: con ``_external=True`` el enlace
        # salía «http://127.0.0.1:9090/informes/…» para quien entrara directamente al
        # servicio, y la pantalla decía a la vez «páselo a un compañero» (revisión de
        # claridad del 2026-09-15, punto 16). De paso deja de depender del Host de la
        # petición, así que ni siquiera hace falta confiar en que nginx lo filtre.
        # Si no hay nombre público configurado, ``url_publica`` cae a host y puerto.
        "enlace_informe": ti_config.url_publica(
            cfg, url_for("informes.lista", **sel.a_parametros())),
        "alcance_perfil": auth.alcance_origen(),
        "alcance_perfil_es": auth.alcance_es(),
        "max_fichas": int(cfg.get("report_max_detail_items", 120) or 120),
    }


def _seleccion_de_la_peticion() -> dict[str, Any]:
    """La selección de ``request.args`` ya validada, avisando de lo que no cuadre.

    Lo comparten la página completa y el fragmento de la vista previa, para que los dos
    apliquen exactamente las mismas comprobaciones de alcance y los mismos avisos: si el
    fragmento fuera más permisivo que la página, la vista previa viva sería un agujero.
    """
    sel = _seleccion(request.args)
    activo_elegido = _exigir_alcance(sel, request.args)
    if sel.alcance == "proceso" and sel.proceso:
        permitidos = seleccion_informe.procesos(g.db, origen=auth.alcance_origen())
        if sel.proceso not in permitidos:
            flash(f"El proceso de negocio «{sel.proceso}» no tiene vulnerabilidades "
                  "confirmadas que informar. Elija uno de la lista.", "aviso")
            sel = sel.con(proceso="")
    if sel.alcance == "activo" and sel.activo_id and activo_elegido is None:
        flash("El activo indicado ya no figura en el inventario. Elija uno de la lista.",
              "aviso")
        sel = sel.con(activo_id=0)
    return _datos_de_pantalla(sel, activo_elegido=activo_elegido)


@bp.route("/")
@requiere_informes
def lista():
    """El generador de informes: plantillas, formulario, vista previa y meses.

    Es una única dirección con parámetros para que una selección se pueda guardar o
    compartir como enlace (el botón «Copiar el enlace de este informe»). Sin parámetros
    llega la plantilla «Informe mensual completo» con el último mes con datos, que es lo
    que se pedía antes de este cambio.
    """
    sin_bajas = bool(g.cfg.get("ignore_low_severity", True))
    datos = _seleccion_de_la_peticion()
    filas = meses_para_informe(g.db, excluir_bajas=sin_bajas)
    return render_template("informes.html", filas=filas, sin_bajas=sin_bajas,
                           total_meses=len(filas), **datos)


@bp.route("/vista-previa")
@requiere_informes
def vista_previa():
    """Solo los dos trozos que cambian al tocar el formulario, sin la página entera.

    Por qué existe (2026-09-10): el usuario pidió «poder previsualizarlo según vaya
    eligiendo opciones», así que la vista previa se recalcula en CADA cambio del
    formulario. Devolver la página completa costaba entre 200 y 450 milisegundos, y la
    mayor parte era la tabla de «Meses disponibles»
    (:func:`meses_para_informe` recorre la evolución mensual entera y todo el registro de
    auditoría) y el catálogo de apartados, que no dependen de la selección. Este fragmento
    devuelve únicamente los campos del formulario y la vista previa, que es lo que el
    motor de actualización parcial sustituye (``webui/static/app.js``).

    No es una interfaz de datos nueva: es el MISMO HTML que pinta la página completa, con
    los mismos permisos, el mismo alcance por perfil (404 fuera de alcance) y la misma
    validación. Sin JavaScript nadie llega aquí: el formulario sigue enviándose a
    ``/informes/`` y recargando la página.
    """
    return render_template("_informe_fragmento.html", **_seleccion_de_la_peticion())


@bp.route("/generar", methods=["POST"])
@requiere_informes
@auth.requiere_csrf
def generar():
    """Construye el informe a medida en memoria y lo devuelve como descarga.

    POST a propósito: generar un documento cuesta segundos, deja rastro en la auditoría y
    no debe dispararlo un rastreador ni la previsualización de un enlace.
    """
    sel = _seleccion(request.form)
    _exigir_alcance(sel, request.form)
    volver = url_for("informes.lista", **sel.a_parametros())

    completa, falta = sel.completa()
    if not completa:
        flash(falta, "error")
        return redirect(volver)

    previa = seleccion_informe.vista_previa(g.db, sel)
    actualizaciones = (seleccion_informe.actualizaciones_pendientes(g.db, sel)
                       if "remediacion" in sel.apartados else 0)
    if not previa["amenazas"] and not actualizaciones:
        flash("Esa selección no devuelve ninguna vulnerabilidad ni ninguna actualización "
              "pendiente, así que el documento saldría vacío. Amplíe el periodo, el "
              "alcance o las severidades.", "aviso")
        return redirect(volver)

    cfg = _cfg_para_interfaz(g.cfg)
    try:
        if sel.es_ejecutivo():
            # Informe ejecutivo mensual (2026-09-15): otro documento y otro generador. Va
            # antes que las demás ramas porque su selección no es «un informe a medida con
            # otros apartados», sino una plantilla de estructura fija de diez páginas.
            datos = report.generar_ejecutivo_en_memoria(
                g.db, sel.mes, cfg=cfg, filtros=sel)
        elif sel.es_mensual_clasico():
            # Es el informe mensual de siempre: se genera por el mismo camino que la
            # ejecución programada, sin filtros ni selección de apartados, para que el
            # documento no pueda diferir del que se envía por correo.
            datos = report.generar_en_memoria(g.db, sel.mes, cfg=cfg)
        else:
            datos = report.generar_en_memoria(
                g.db, sel.mes_representativo(), cfg=cfg,
                secciones=sel.apartados, filtros=sel)
    except Exception:  # noqa: BLE001 - se informa en español y queda en el log
        log.error("no se pudo generar el informe a medida",
                  extra={"plantilla": sel.plantilla, "usuario": g.usuario}, exc_info=True)
        flash("No se pudo generar el informe con esa selección. Inténtelo de nuevo en unos "
              "minutos o avise a un administrador; el detalle técnico ha quedado en el "
              "registro de la plataforma.", "error")
        return redirect(volver)

    kb = round(len(datos) / 1024, 1)
    fichero = sel.nombre_fichero()
    with db.session(current_app.config.get("DB_PATH")) as conn:
        if sel.es_mensual_clasico():
            db.audit(conn, g.usuario, ACCION_AUDITORIA, "informes", sel.mes,
                     f"informe mensual de {mes_es(sel.mes)} generado y descargado desde el "
                     f"generador de informes ({fichero}, {numero(kb)} KB)",
                     request.remote_addr)
        elif sel.es_ejecutivo():
            db.audit(conn, g.usuario, ACCION_AUDITORIA_MEDIDA, "informes", sel.plantilla,
                     f"informe ejecutivo de {mes_es(sel.mes)} generado y descargado "
                     f"({fichero}, {numero(kb)} KB); alcance: "
                     f"{sel.clave_alcance_texto()}", request.remote_addr)
        else:
            db.audit(conn, g.usuario, ACCION_AUDITORIA_MEDIDA, "informes", sel.plantilla,
                     f"informe a medida generado y descargado ({fichero}, {numero(kb)} KB); "
                     f"{sel.resumen_auditoria()}", request.remote_addr)
    log.info("informe a medida generado", extra={
        "plantilla": sel.plantilla, "usuario": g.usuario, "kb": kb,
        "apartados": ",".join(sel.apartados), "amenazas": previa["amenazas"]})

    return Response(
        datos, mimetype=MIME_DOCX,
        headers={"Content-Disposition": f'attachment; filename="{fichero}"',
                 "Content-Length": str(len(datos))})


@bp.route("/<mes>/descargar", methods=["POST"])
@requiere_informes
@auth.requiere_csrf
def descargar(mes: str):
    """Genera el informe mensual completo de ``mes`` y lo devuelve como descarga.

    Es la descarga rápida de la tabla de meses: el mismo documento que la ejecución
    programada, sin pasar por el formulario. POST a propósito: generar un documento de
    varias páginas cuesta segundos y no debe dispararlo un rastreador ni una
    previsualización de enlace; además así el botón lleva token CSRF como toda acción que
    deja rastro en la auditoría.
    """
    mes = (mes or "").strip()
    if not mes_valido(mes):
        flash("El mes indicado no es válido. Elija uno de la lista.", "error")
        return redirect(url_for("informes.lista"))
    if mes not in queries.meses_disponibles(g.db):
        flash(f"No hay amenazas registradas en {mes_es(mes)}: no hay nada que informar.", "error")
        return redirect(url_for("informes.lista"))

    try:
        datos = report.generar_en_memoria(g.db, mes, cfg=_cfg_para_interfaz(g.cfg))
    except Exception:  # noqa: BLE001 - se informa en español y queda en el log
        log.error("no se pudo generar el informe desde la interfaz",
                  extra={"mes": mes, "usuario": g.usuario}, exc_info=True)
        flash(f"No se pudo generar el informe de {mes_es(mes)}. Inténtelo de nuevo en unos "
              "minutos o avise a un administrador; el detalle técnico ha quedado en el registro "
              "de la plataforma.", "error")
        return redirect(url_for("informes.lista"))

    kb = round(len(datos) / 1024, 1)
    with db.session(current_app.config.get("DB_PATH")) as conn:
        db.audit(conn, g.usuario, ACCION_AUDITORIA, "informes", mes,
                 f"informe mensual de {mes_es(mes)} generado y descargado desde la "
                 f"interfaz ({nombre_fichero(mes)}, {numero(kb)} KB)", request.remote_addr)
    log.info("informe generado desde la interfaz",
             extra={"mes": mes, "usuario": g.usuario, "kb": kb})

    return Response(
        datos, mimetype=MIME_DOCX,
        headers={"Content-Disposition": f'attachment; filename="{nombre_fichero(mes)}"',
                 "Content-Length": str(len(datos))})

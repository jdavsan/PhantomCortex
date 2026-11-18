"""Excepciones con vencimiento: aceptación de riesgo con responsable y caducidad (2026-09-10).

Página ``/excepciones/``: lista filtrable (las que vencen pronto arriba), formulario de
alta con validación EN EL SERVIDOR, y prórroga y revocación por POST con CSRF. Toda
escritura queda en el registro de auditoría (``threatintel.excepciones`` lo hace con
``db.audit``, en la misma transacción que el cambio).

Quién puede qué (criterio del usuario del 2026-09-10, con los conjuntos de ``webui.auth``
para no inventar un sistema de permisos paralelo):

* **crear, prorrogar y revocar**: administración y ciberseguridad
  (:data:`webui.auth.ROLES_OPERACION`, el mismo conjunto que ya decide el estado de una
  amenaza; aceptar un riesgo es exactamente esa clase de decisión operativa).
* **solicitar y ver**: los jefes de proceso, es decir ``redes`` y ``mantenimiento``. La
  solicitud NO crea la excepción: deja constancia en la auditoría y aparece en esta
  página para que administración o ciberseguridad la registre o la descarte. Así el que
  pide el riesgo y el que lo acepta no son la misma persona.
* **ver, acotado a sus máquinas**: ``redes`` (servidores) y ``mantenimiento`` (equipos de
  cómputo), con ``auth.alcance_origen``. Las excepciones de un CVE en toda la organización
  también les afectan, así que también las ven.
* **ver**: ``viewer``, sin ninguna acción.

Excepciones PERMANENTES (2026-09-10, tarde). Petición del usuario: «en excepciones se
debe agregar la opción de fecha permanente, ya que no va a tener una fecha de
vencimiento». Lo que cambia en los permisos, con su porqué:

* **conceder lo permanente, confirmar su revisión y quitarle la fecha a una temporal**:
  solo ``admin`` (:data:`ROLES_PERMANENTE`). Una excepción con fecha se corrige sola el
  día que vence, así que equivocarse cuesta como mucho el plazo; una permanente no se
  corrige nunca sola, y eso ya no es una decisión operativa del turno, es una decisión
  de la organización. Por la misma razón, reiniciar el plazo de revisión —decir «sigue
  siendo válida» y callar el recordatorio otros ciento ochenta días— es la misma
  decisión que concederla, y lo hace el mismo perfil.
* **ponerle fecha a una permanente** (``/temporal``): administración y operador SOC, como
  el resto de la gestión. Va en la dirección que REDUCE el riesgo (la excepción vuelve a
  caducar sola), así que no tiene sentido pedir más permisos para eso que para revocarla.
* **solicitar una permanente**: un jefe de proceso puede pedirla, como cualquier otra;
  la solicitud no registra nada y la decisión sigue siendo de administración.

Sin ``style=`` ni ``on*=`` (CSP estricta): los formularios de prórroga y revocación se
despliegan con ``<details>``, que es HTML puro, y la confirmación de revocar usa
``data-confirm`` de ``app.js``.
"""
from __future__ import annotations

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for

from threatintel import excepciones
from .. import auth

bp = Blueprint("excepciones", __name__, url_prefix="/excepciones")

#: Filas por página, como en el resto de los listados largos.
LIMITE_PAGINA = 20

#: Cuántos activos se ofrecen en el selector del formulario de alta. Solo los que tienen
#: alguna vulnerabilidad confirmada (en los demás no hay ningún riesgo que aceptar) y con
#: un tope, para que la página no crezca con el inventario.
MAX_ACTIVOS_SELECTOR = 1000

#: Perfiles que pueden crear, prorrogar y revocar.
ROLES_GESTION = auth.ROLES_OPERACION
#: Perfiles que además pueden SOLICITAR una excepción (los jefes de proceso: quienes
#: administran el día a día de servidores o equipos de cómputo, aunque la decisión de
#: aceptar el riesgo sea de administración o ciberseguridad).
ROLES_SOLICITUD = tuple(dict.fromkeys(ROLES_GESTION + ("redes", "mantenimiento")))
#: Perfiles que pueden aceptar un riesgo SIN fecha de vencimiento, quitarle la fecha a
#: una temporal y confirmar la revisión de una permanente. Solo administración: ver el
#: porqué en la cabecera del módulo. No se lee de ``auth.ROLES_OPERACION`` a propósito,
#: porque es un conjunto más estrecho y tiene que poder divergir de él.
ROLES_PERMANENTE = ("admin",)

#: Argumentos reservados de ``url_for``: un parámetro de la dirección con uno de esos
#: nombres no es un filtro de la página y no se reenvía (mismo criterio que en
#: ``webui.vistas.parches``).
_ARGS_RESERVADOS = ("endpoint", "values")


def puede_gestionar() -> bool:
    """Si el perfil de la sesión puede crear, prorrogar y revocar."""
    return auth.rol_actual() in ROLES_GESTION


def puede_solicitar() -> bool:
    """Si el perfil de la sesión puede pedir una excepción."""
    return auth.rol_actual() in ROLES_SOLICITUD


def puede_permanente() -> bool:
    """Si el perfil de la sesión puede aceptar un riesgo sin fecha de vencimiento."""
    return auth.rol_actual() in ROLES_PERMANENTE


def _exigir_gestion() -> None:
    if not puede_gestionar():
        abort(403, auth.MENSAJE_403)


def _exigir_permanente() -> None:
    if not puede_permanente():
        abort(403, auth.MENSAJE_403)


def _exigir_solicitud() -> None:
    if not puede_solicitar():
        abort(403, auth.MENSAJE_403)


def _pagina_valida(pagina, total: int, por_pagina: int) -> tuple[int, int]:
    """(página, páginas) con la página acotada al rango real: una página fuera de rango se
    atiende con la primera o con la última, no con un error."""
    por_pagina = max(1, int(por_pagina or 1))
    paginas = max(1, -(-int(total or 0) // por_pagina))
    try:
        pagina = int(pagina)
    except (TypeError, ValueError):
        pagina = 1
    return min(max(pagina, 1), paginas), paginas


def _args_a_conservar(*excluir: str) -> dict:
    return {k: v for k, v in request.args.items()
            if k not in excluir and k not in _ARGS_RESERVADOS and not k.startswith("_")}


def _activo_del_alcance(activo_id):
    """El activo pedido en la dirección, o 404 si no existe o está fuera del alcance.

    404 y no 403 a propósito: el identificador de una máquina del otro tipo no debe
    revelar que existe (``auth.exigir_alcance``).
    """
    if not activo_id:
        return None
    fila = g.db.execute("SELECT id, nombre, origen FROM activos WHERE id = ?",
                        (int(activo_id),)).fetchone()
    if fila is None:
        abort(404)
    auth.exigir_alcance(fila["origen"])
    return dict(fila)


#: Amenazas que NO cuentan en las cifras del selector: las cerradas por el equipo y las
#: ya mitigadas. Es la misma lista que usan la ficha del activo
#: (``webui/vistas/activos.py``, ``ESTADOS_ABIERTOS_SQL``), ``ocs.estado_activos`` y
#: ``queries.resumen_amenazas``: si el selector usara otra, el mismo servidor tendría dos
#: números de vulnerabilidades en dos pantallas.
_ESTADOS_CERRADOS_SQL = "('descartada','falso_positivo','mitigada')"
#: La severidad que la organización no reporta tampoco cuenta aquí.
_SIN_BAJAS_SQL = "(t.severity IS NULL OR t.severity <> 'Low')"


def _activos_del_selector(origen, *, excluir_bajas: bool = True):
    """Activos con alguna vulnerabilidad confirmada, para el selector del formulario.

    La cifra que acompaña a cada nombre («48 vulnerabilidades confirmadas») es la MISMA
    que enseña la ficha de ese activo: CVE distintos con veredicto «afectado», sin las
    amenazas cerradas o mitigadas y sin la severidad que no se reporta.

    Por qué (auditoría de tableros del 2026-09-15, punto 7): sin esos dos filtros, 348 de
    los 652 activos del selector enseñaban un número distinto del de su propia ficha (el
    primero de la lista, 30 aquí y 27 allí), y quien pide una excepción la justifica con
    una cifra que después no encuentra.

    El riesgo YA aceptado con una excepción vigente tampoco cuenta, por la misma razón:
    la ficha del activo no lo cuenta y aquí ya no hay nada que volver a exceptuar. Con
    cero excepciones vigentes la condición es cadena vacía y la consulta queda igual
    (``excepciones.y_sin_excepcion``).

    Un activo cuyas vulnerabilidades queden todas fuera por los filtros ya no aparece en
    el selector: no hay nada que exceptuar en él.
    """
    condicion = " AND a.origen = ?" if origen else ""
    filtro = f" AND {_SIN_BAJAS_SQL}" if excluir_bajas else ""
    filtro += excepciones.y_sin_excepcion(g.db, activo="ap.activo_id", cve="ap.cve",
                                          paquete="ap.paquete")
    params = [excepciones.AFECTADO] + ([origen] if origen else []) + [MAX_ACTIVOS_SELECTOR]
    filas = g.db.execute(
        f"""SELECT a.id, a.nombre, a.origen, a.proceso, COUNT(DISTINCT ap.cve) AS cves
              FROM activos a JOIN aplicabilidad ap ON ap.activo_id = a.id
              LEFT JOIN threats t ON t.id = ap.threat_id
             WHERE ap.veredicto = ? AND a.presente = 1{condicion}
               AND (t.id IS NULL OR t.estado NOT IN {_ESTADOS_CERRADOS_SQL}){filtro}
             GROUP BY a.id HAVING cves > 0 ORDER BY a.nombre LIMIT ?""", params).fetchall()
    return [dict(f) for f in filas]


def _contexto(*, formulario=None, aviso_kev=None):
    """Todo lo que necesita la plantilla. Se reutiliza al reenviar el formulario con un
    error de validación, para no perder lo que la persona ya había escrito."""
    origen = auth.alcance_origen()
    aviso_dias = excepciones.ajuste_aviso_dias(g.db, cfg=g.cfg)
    revision_dias = excepciones.ajuste_revision_dias(g.db, cfg=g.cfg)
    estado = (request.args.get("estado") or "").strip()[:20]
    if estado not in ("",) + excepciones.FILTROS_SITUACION:
        estado = ""
    alcance = (request.args.get("alcance") or "").strip()[:20]
    if alcance not in excepciones.ALCANCES:
        alcance = ""
    proceso = (request.args.get("proceso") or "").strip()[:120]
    q = (request.args.get("q") or "").strip()[:120]
    activo = _activo_del_alcance(request.args.get("activo", type=int))
    filtros = {"estado": estado, "alcance": alcance, "proceso": proceso, "q": q,
               "origen": origen, "activo_id": activo["id"] if activo else None,
               "aviso_dias": aviso_dias, "revision_dias": revision_dias}
    total = excepciones.contar(g.db, **filtros)
    pagina, paginas = _pagina_valida(request.args.get("pagina", 1, type=int), total,
                                     LIMITE_PAGINA)
    filas = excepciones.listar(g.db, limite=LIMITE_PAGINA,
                               desplazamiento=(pagina - 1) * LIMITE_PAGINA, **filtros)
    return {
        "filas": filas, "total": total, "pagina": pagina, "paginas": paginas,
        "por_pagina": LIMITE_PAGINA, "args": _args_a_conservar("pagina"),
        "estado": estado, "alcance": alcance, "proceso": proceso, "q": q,
        "activo": activo,
        "resumen": excepciones.resumen(g.db, origen=origen, aviso_dias=aviso_dias,
                                       revision_dias=revision_dias),
        "procesos": excepciones.procesos(g.db, origen=origen),
        # Regla interna: las bajas no se reportan (ajuste ignore_low_severity, activo).
        "activos": (_activos_del_selector(
            origen, excluir_bajas=bool(g.cfg.get("ignore_low_severity", True)))
            if puede_solicitar() else []),
        "activos_tope": MAX_ACTIVOS_SELECTOR,
        "solicitudes": excepciones.solicitudes(g.db) if puede_solicitar() else [],
        "aviso_dias": aviso_dias,
        "revision_dias": revision_dias,
        "alcances": excepciones.ALCANCES,
        "alcance_es": excepciones.ALCANCE_ES,
        "alcance_ayuda": excepciones.ALCANCE_AYUDA,
        "estado_es": excepciones.ESTADO_ES,
        "estado_explicacion": excepciones.ESTADO_EXPLICACION,
        "max_dias": excepciones.MAX_DIAS,
        "max_dias_kev": excepciones.MAX_DIAS_KEV,
        "min_justificacion": excepciones.MIN_JUSTIFICACION,
        "min_justificacion_permanente": excepciones.MIN_JUSTIFICACION_PERMANENTE,
        "texto_permanente": excepciones.TEXTO_PERMANENTE,
        "texto_permanente_corto": excepciones.TEXTO_PERMANENTE_CORTO,
        "permanente_explicacion": excepciones.PERMANENTE_EXPLICACION,
        "revision_explicacion": excepciones.REVISION_EXPLICACION,
        "fecha_minima": excepciones.hoy(),
        "fecha_maxima": excepciones.fecha_maxima(),
        "puede_gestionar": puede_gestionar(),
        "puede_solicitar": puede_solicitar(),
        "puede_permanente": puede_permanente(),
        "formulario": formulario or {},
        "aviso_kev": aviso_kev,
    }


@bp.route("/")
@auth.requiere_login
def lista():
    """Lista de excepciones con las que vencen pronto arriba, y formulario de alta."""
    return render_template("excepciones.html", **_contexto())


def _datos_del_formulario() -> dict:
    """Los campos del formulario, tal como llegaron (para reenviarlos si hay un error)."""
    campos = ("alcance", "activo_id", "cve", "paquete", "justificacion",
              "responsable_nombre", "responsable_correo", "compensacion", "vence_at")
    datos = {campo: (request.form.get(campo) or "").strip() for campo in campos}
    datos["confirmar_kev"] = (request.form.get("confirmar_kev") or "").strip() in (
        "1", "on", "true", "si", "sí")
    # «vigencia» es el grupo de opciones «Con fecha de vencimiento» / «Permanente». Se
    # lee como un valor cerrado y no como una casilla suelta para que el formulario
    # obligue a elegir una de las dos cosas: no hay estado intermedio.
    datos["vigencia"] = ("permanente"
                         if (request.form.get("vigencia") or "").strip() == "permanente"
                         else "temporal")
    datos["permanente"] = datos["vigencia"] == "permanente"
    return datos


@bp.route("/crear", methods=["POST"])
@auth.requiere_login
@auth.requiere_csrf
def crear():
    """Registra la excepción. Solo administración y operador SOC.

    Una excepción PERMANENTE (sin fecha de vencimiento) además exige el perfil de
    administración: ver el porqué en la cabecera del módulo.
    """
    _exigir_gestion()
    datos = _datos_del_formulario()
    if datos["permanente"]:
        _exigir_permanente()
    if datos["alcance"] in ("activo_cve", "activo_paquete") and datos["activo_id"]:
        # Defensa en profundidad: los perfiles que gestionan ven las dos clases de
        # máquina, pero si eso cambiara el alcance seguiría aplicándose aquí.
        _activo_del_alcance(int(datos["activo_id"]) if datos["activo_id"].isdigit() else 0)
    try:
        fila = excepciones.crear(g.db, actor=g.usuario, ip=request.remote_addr,
                                 alcance=datos["alcance"], activo_id=datos["activo_id"] or None,
                                 cve=datos["cve"], paquete=datos["paquete"],
                                 justificacion=datos["justificacion"],
                                 responsable_nombre=datos["responsable_nombre"],
                                 responsable_correo=datos["responsable_correo"],
                                 compensacion=datos["compensacion"],
                                 vence_at=datos["vence_at"],
                                 permanente=datos["permanente"],
                                 confirmar_kev=datos["confirmar_kev"])
    except excepciones.AvisoKev as aviso:
        flash(str(aviso), "error")
        return render_template("excepciones.html",
                               **_contexto(formulario=datos, aviso_kev=aviso.cves)), 200
    except excepciones.ErrorExcepcion as error:
        flash(str(error), "error")
        return render_template("excepciones.html", **_contexto(formulario=datos)), 200
    except Exception as error:  # noqa: BLE001 - nunca una página de error por un dato raro
        flash(f"No se pudo registrar la excepción: {error}", "error")
        return render_template("excepciones.html", **_contexto(formulario=datos)), 200
    if fila["permanente"]:
        flash(f"Riesgo aceptado de forma permanente, sin fecha de vencimiento: "
              f"{fila['descripcion']}. Responsable: {fila['responsable_nombre']}. La "
              f"vulnerabilidad sale de la cola y de las cifras y NO volverá sola: no hay "
              f"ninguna fecha que la devuelva. La plataforma pedirá revisarla cada "
              f"{fila['revision_dias']} días; mientras tanto sigue vigente.", "exito")
    else:
        flash(f"Riesgo aceptado hasta el {fila['vence_at']}: {fila['descripcion']}. "
              f"Responsable: {fila['responsable_nombre']}. La vulnerabilidad sale de la cola y "
              f"de las cifras, sigue consultable aquí y volverá sola al vencer.", "exito")
    return redirect(url_for("excepciones.lista"))


@bp.route("/solicitar", methods=["POST"])
@auth.requiere_login
@auth.requiere_csrf
def solicitar():
    """Deja constancia de una solicitud de excepción sin registrarla.

    Es lo que puede hacer un jefe de proceso: pedirla. La decisión sigue siendo del SOC.
    """
    _exigir_solicitud()
    datos = _datos_del_formulario()
    try:
        validados = excepciones.validar(
            g.db, alcance=datos["alcance"], activo_id=datos["activo_id"] or None,
            cve=datos["cve"], paquete=datos["paquete"],
            justificacion=datos["justificacion"],
            responsable_nombre=datos["responsable_nombre"],
            responsable_correo=datos["responsable_correo"],
            compensacion=datos["compensacion"], vence_at=datos["vence_at"],
            permanente=datos["permanente"], confirmar_kev=True)
    except excepciones.ErrorExcepcion as error:
        flash(str(error), "error")
        return render_template("excepciones.html", **_contexto(formulario=datos)), 200
    plazo = ("de forma PERMANENTE, sin fecha de vencimiento" if validados["permanente"]
             else f"hasta {validados['vence_at']}")
    texto = (f"solicita {excepciones.descripcion(validados)} {plazo}; "
             f"responsable {validados['responsable_nombre']} "
             f"<{validados['responsable_correo']}>; "
             f"justificación: {validados['justificacion']}")
    excepciones.registrar_solicitud(g.db, actor=g.usuario, texto=texto,
                                    ip=request.remote_addr)
    flash("Solicitud registrada. Queda en el registro de auditoría y en esta página; "
          "el operador del SOC o un administrador decide si acepta el riesgo. "
          "Mientras no la registren, la vulnerabilidad sigue en la cola de trabajo.",
          "exito")
    return redirect(url_for("excepciones.lista"))


@bp.route("/<int:excepcion_id>/prorrogar", methods=["POST"])
@auth.requiere_login
@auth.requiere_csrf
def prorrogar(excepcion_id: int):
    """Amplía la fecha de vencimiento, con motivo. Solo administración y operador SOC."""
    _exigir_gestion()
    if excepciones.obtener(g.db, excepcion_id) is None:
        abort(404)
    try:
        fila = excepciones.prorrogar(g.db, excepcion_id,
                                     vence_at=(request.form.get("vence_at") or "").strip(),
                                     motivo=(request.form.get("motivo") or "").strip(),
                                     actor=g.usuario, ip=request.remote_addr)
    except excepciones.ErrorExcepcion as error:
        flash(str(error), "error")
        return redirect(url_for("excepciones.lista"))
    flash(f"Excepción prorrogada hasta el {fila['vence_at']}: {fila['descripcion']}. "
          f"Es la prórroga número {fila['prorrogas']} y queda en el registro de auditoría.",
          "exito")
    return redirect(url_for("excepciones.lista"))


@bp.route("/<int:excepcion_id>/revocar", methods=["POST"])
@auth.requiere_login
@auth.requiere_csrf
def revocar(excepcion_id: int):
    """Retira la aceptación del riesgo: la vulnerabilidad vuelve a la cola en el acto."""
    _exigir_gestion()
    if excepciones.obtener(g.db, excepcion_id) is None:
        abort(404)
    try:
        fila = excepciones.revocar(g.db, excepcion_id,
                                   motivo=(request.form.get("motivo") or "").strip(),
                                   actor=g.usuario, ip=request.remote_addr)
    except excepciones.ErrorExcepcion as error:
        flash(str(error), "error")
        return redirect(url_for("excepciones.lista"))
    flash(f"Excepción revocada: {fila['descripcion']}. La vulnerabilidad vuelve ahora mismo "
          f"a la cola de trabajo y a las cifras de riesgo.", "exito")
    return redirect(url_for("excepciones.lista"))


# --------------------------------------------------------------------------
# Excepciones permanentes: revisión periódica y conversiones (2026-09-10)
# --------------------------------------------------------------------------
@bp.route("/<int:excepcion_id>/revisar", methods=["POST"])
@auth.requiere_login
@auth.requiere_csrf
def revisar(excepcion_id: int):
    """Confirma que una excepción permanente sigue siendo válida. Solo administración.

    Reinicia el plazo del recordatorio y deja constancia de quién y cuándo. No cambia
    nada más: la excepción ya estaba vigente y sigue estándolo.
    """
    _exigir_permanente()
    if excepciones.obtener(g.db, excepcion_id) is None:
        abort(404)
    try:
        fila = excepciones.confirmar_revision(
            g.db, excepcion_id, nota=(request.form.get("nota") or "").strip(),
            actor=g.usuario, ip=request.remote_addr)
    except excepciones.ErrorExcepcion as error:
        flash(str(error), "error")
        return redirect(url_for("excepciones.lista"))
    flash(f"Revisión confirmada: {fila['descripcion']} sigue con el riesgo aceptado de "
          f"forma permanente. Queda registrado que la revisó {g.usuario} y el recordatorio "
          f"no volverá hasta dentro de {fila['revision_dias']} días. Si el riesgo dejara de "
          f"aceptarse, hay que revocarla: una permanente no caduca sola.", "exito")
    return redirect(url_for("excepciones.lista"))


@bp.route("/<int:excepcion_id>/permanente", methods=["POST"])
@auth.requiere_login
@auth.requiere_csrf
def convertir_permanente(excepcion_id: int):
    """Le quita la fecha de vencimiento a una excepción. Solo administración."""
    _exigir_permanente()
    if excepciones.obtener(g.db, excepcion_id) is None:
        abort(404)
    try:
        fila = excepciones.convertir_en_permanente(
            g.db, excepcion_id, motivo=(request.form.get("motivo") or "").strip(),
            actor=g.usuario, ip=request.remote_addr)
    except excepciones.ErrorExcepcion as error:
        flash(str(error), "error")
        return redirect(url_for("excepciones.lista"))
    flash(f"Excepción convertida en permanente: {fila['descripcion']} queda con el riesgo "
          f"aceptado sin fecha de vencimiento. Ya no volverá sola a la cola de trabajo: la "
          f"plataforma pedirá revisarla cada {fila['revision_dias']} días y solo se sale de "
          f"aquí revocándola o poniéndole fecha otra vez.", "exito")
    return redirect(url_for("excepciones.lista"))


@bp.route("/<int:excepcion_id>/temporal", methods=["POST"])
@auth.requiere_login
@auth.requiere_csrf
def convertir_temporal(excepcion_id: int):
    """Le pone fecha de vencimiento a una permanente: vuelve a caducar sola.

    Administración y operador SOC: va en la dirección que reduce el riesgo.
    """
    _exigir_gestion()
    if excepciones.obtener(g.db, excepcion_id) is None:
        abort(404)
    try:
        fila = excepciones.convertir_en_temporal(
            g.db, excepcion_id, vence_at=(request.form.get("vence_at") or "").strip(),
            motivo=(request.form.get("motivo") or "").strip(),
            actor=g.usuario, ip=request.remote_addr)
    except excepciones.ErrorExcepcion as error:
        flash(str(error), "error")
        return redirect(url_for("excepciones.lista"))
    flash(f"Excepción con fecha de vencimiento otra vez: {fila['descripcion']} vence el "
          f"{fila['vence_at']}. Ese día la vulnerabilidad volverá sola a la cola de trabajo "
          f"y a las cifras de riesgo, sin que nadie tenga que acordarse.", "exito")
    return redirect(url_for("excepciones.lista"))

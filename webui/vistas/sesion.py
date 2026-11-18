"""Inicio y cierre de sesion, cambio de contrasena propia y segundo factor.

Segundo factor (2026-09-05): si el usuario tiene TOTP activado, la contrasena
correcta crea una sesion «pendiente» (web_sessions.mfa_pendiente=1) que solo
sirve para /login/segundo-factor y /logout; el codigo de la aplicacion o un
codigo de recuperacion la completa, y al completarla la sesion recibe un
identificador y un token CSRF nuevos. La activacion, la regeneracion de codigos
y la desactivacion viven bajo /mi-password/segundo-factor/...

Revision de seguridad del 2026-09-06:
  * el secreto que aun no se ha confirmado se guarda en el SERVIDOR
    (users.totp_secret con users.totp_activado_at NULL, que no cuenta como
    segundo factor en ninguna comprobacion); en la cookie firmada de Flask solo
    queda la marca de tiempo del inicio, para respetar los diez minutos de
    caducidad. Antes viajaba el secreto entero en una cookie firmada pero NO
    cifrada, legible con un Base64;
  * desactivar el segundo factor y regenerar los codigos de recuperacion exigen
    contrasena Y codigo, y sus fallos cuentan para el bloqueo de la cuenta igual
    que en el acceso.

Peticiones del usuario del 2026-09-07:
  * cambio de contrasena obligatorio y BLOQUEANTE (/cambiar-contrasena): con
    users.must_change=1 el usuario solo ve una pantalla propia, sin menu, sin barra
    superior y sin buscador, con la contrasena nueva, su repeticion y guardar. El
    fallo grave que se corrige: antes se le redirigia ahi con un aviso, pero nada
    impedia escribir otra direccion y entrar con la contrasena inicial;
  * apartado de perfil (/perfil) que sustituye al boton «Contrasena» de la barra
    superior: quien soy (nombre de la persona, correo de acceso, perfil y antiguedad
    de la cuenta), acceso (ultimo inicio de sesion, sesiones abiertas, intentos
    fallidos, bloqueo y el registro de los ultimos accesos leido de audit_log),
    contrasena y segundo factor;
  * /mi-password se conserva como direccion historica: el GET muestra el mismo
    perfil y el POST sigue aceptando el formulario de tres campos.

Peticiones del usuario del 2026-09-08:
  * sesion opaca en servidor (webui/sesion_servidor.py): la cookie lleva solo un
    token; lo que aqui se guarda en ``session`` (destino tras el segundo factor,
    marca de la activacion) vive en web_sessions.datos, no en el navegador;
  * la sesion caduca a los 30 minutos sin actividad y la pantalla de acceso lo dice;
  * rotacion de credenciales: contrasena con mas de «password_max_dias» dias ->
    cambio obligatorio con su propio aviso; cinco dias antes se avisa al entrar; el
    perfil muestra la fecha del ultimo cambio y los dias que quedan; no se puede
    repetir ninguna de las ultimas «password_historial» contrasenas.
"""
from __future__ import annotations

import re
import time
from datetime import datetime, timedelta, timezone

from flask import (Blueprint, current_app, flash, g, make_response, redirect,
                   render_template, request, session, url_for)

from threatintel import db
from webui import auth, totp

bp = Blueprint("auth", __name__)

#: Clave de la sesion con la marca de tiempo en que se inicio la activacion del
#: segundo factor. El secreto NO va aqui: vive en users.totp_secret sin confirmar.
#: Desde el 2026-09-08 la sesion entera esta en el servidor (web_sessions.datos), asi
#: que ni esta marca pasa por el navegador.
CLAVE_ACTIVACION_INICIADA = "totp_activacion_at"
#: Clave de la sesion con el destino solicitado antes del segundo factor.
CLAVE_DESTINO = "destino_2fa"
CADUCIDAD_ACTIVACION_S = 10 * 60

#: Nombre del perfil tal como se ensena a las personas (nunca «admin»/«viewer»).
ROL_ES = auth.ROL_ES  # una sola lista de perfiles, la de webui/auth.py (2026-09-08)
#: Acciones de audit_log que son un acceso (o un intento) a la plataforma, con el
#: texto que ve la persona en su perfil. El usuario pidio «contar con el registro
#: de ultimo inicio de sesion de cada usuario» (2026-09-07).
ACCIONES_ACCESO = {
    "login.ok": ("Acceso completado", "ok"),
    "login.2fa.ok": ("Segundo factor verificado", "ok"),
    "login.password_ok": ("Contraseña correcta, pendiente el segundo factor", "info"),
    "login.fallo": ("Intento fallido", "medium"),
}
#: Cuantos accesos se muestran en el perfil (los mas recientes primero).
ACCESOS_EN_PERFIL = 10


def _destino_seguro(siguiente: str | None) -> str:
    """Valida el destino de la redireccion tras iniciar sesion.

    Comprobar solo `startswith("/")` NO basta: "//evil.com/" empieza por barra
    y el navegador lo interpreta como URL con esquema relativo, es decir un
    dominio externo. Verificado el 2026-09-03: ese valor pasaba el filtro.

    Aqui se exige que el destino sea una ruta local de una sola barra, sin
    barra invertida ni esquema, y que coincida con una ruta registrada en la
    aplicacion.
    """
    respaldo = url_for("panel.inicio")
    if not siguiente:
        return respaldo

    destino = str(siguiente).strip()
    if (not destino.startswith("/")
            or destino.startswith("//")
            or destino.startswith("/\\")
            or "\\" in destino
            or "://" in destino
            or any(c in destino for c in "\r\n\t\x00")):
        return respaldo

    # Debe corresponder a una ruta real de la aplicacion
    try:
        adaptador = current_app.url_map.bind("localhost")
        adaptador.match(destino.split("?")[0], method="GET")
    except Exception:  # noqa: BLE001 - cualquier fallo de emparejamiento
        return respaldo
    return destino


def _ip() -> str | None:
    return request.remote_addr


def _tras_acceso(fila: dict, siguiente: str | None):
    """Redireccion comun tras completar el acceso (con o sin segundo factor).

    El orden importa: primero la contrasena propia (must_change) y despues el
    segundo factor obligatorio de los administradores.

    Aqui pasan los dos caminos de acceso (con y sin segundo factor) una vez
    completado, asi que es el sitio donde se aplica la politica de UNA SOLA sesion
    por usuario (2026-09-07): entrar cierra la sesion que hubiera abierta en otro
    navegador o en otro equipo, y se le avisa por si no ha sido el."""
    with db.session(current_app.config.get("DB_PATH")) as conn:
        cerradas = auth.dejar_solo_esta_sesion(conn, fila["username"])
    if cerradas:
        flash("Se ha cerrado la sesión que tenía abierta en otro navegador o equipo: "
              "esta plataforma admite una sola sesión por usuario. Si no ha sido usted, "
              "cambie su contraseña y avise a administración.", "aviso")
    if fila.get("must_change"):
        flash(auth.AVISO_CAMBIO_OBLIGATORIO, "aviso")
        # Se conserva /mi-password como primer destino (direccion historica del
        # acceso, con enlaces y pruebas que la esperan); su vista reenvia acto
        # seguido a /cambiar-contrasena, que es la pantalla bloqueante. Quien
        # cambie esta linea a auth.cambiar_contrasena debe ajustar tambien
        # tests/test_segundo_factor.py (test_must_change_sigue_funcionando...).
        return redirect(url_for("auth.mi_password"))
    # Rotacion de credenciales (2026-09-08): contrasena con mas de «password_max_dias»
    # dias -> cambio obligatorio, con un aviso que dice por que; a cinco dias o menos
    # de caducar se avisa cuantos quedan y se deja pasar.
    contrasena = auth.estado_password(fila, cfg=g.cfg)
    if contrasena["caducada"]:
        flash(auth.aviso_password_caducada(contrasena["max_dias"]), "aviso")
        return redirect(url_for("auth.cambiar_contrasena"))
    if contrasena["avisar"]:
        flash(auth.aviso_password_por_caducar(contrasena["restantes"]), "aviso")
    if (fila.get("role") == "admin" and not fila.get("totp_activado_at")
            and bool(g.cfg.get("mfa_obligatorio_admin", False))):
        flash("Los administradores deben activar el segundo factor de autenticación. "
              "Escanee el código con su aplicación para continuar.", "aviso")
        return redirect(url_for("auth.segundo_factor_activar"))
    return redirect(_destino_seguro(siguiente))


@bp.route("/login", methods=["GET", "POST"])
def login():
    if auth.usuario_actual():
        return redirect(url_for("panel.inicio"))
    if auth.sesion_pendiente_2fa():
        return redirect(url_for("auth.segundo_factor"))

    hay_usuarios = g.db.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0
    # La sesion anterior murio por inactividad o por el tope absoluto: se explica aqui,
    # tambien cuando la persona llega directamente a /login (2026-09-08).
    auth.avisar_caducidad()

    if request.method == "POST":
        usuario = request.form.get("usuario", "")
        password = request.form.get("password", "")

        with db.session(current_app.config.get("DB_PATH")) as conn:
            ok, mensaje, fila = auth.autenticar(conn, usuario, password,
                                                cfg=g.cfg, ip=_ip())
        if ok and fila:
            pendiente = bool(fila.get("totp_activado_at"))
            auth.iniciar_sesion(fila, mfa_pendiente=pendiente)
            if pendiente:
                siguiente = request.args.get("siguiente")
                if siguiente:
                    session[CLAVE_DESTINO] = str(siguiente)[:500]
                return redirect(url_for("auth.segundo_factor"))
            return _tras_acceso(fila, request.args.get("siguiente"))
        flash(mensaje, "error")

    return render_template("login.html", hay_usuarios=hay_usuarios)


@bp.route("/login/segundo-factor", methods=["GET", "POST"])
@auth.requiere_csrf
def segundo_factor():
    """Segundo paso del acceso: codigo de la aplicacion o de recuperacion.

    Sin sesion pendiente (anonimo o ya dentro) redirige: la pagina no revela nada."""
    pendiente = auth.sesion_pendiente_2fa()
    if pendiente is None:
        if auth.usuario_actual():
            return redirect(url_for("panel.inicio"))
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        codigo = (request.form.get("codigo") or "")[:totp.LONGITUD_MAXIMA_ENTRADA]
        with db.session(current_app.config.get("DB_PATH")) as conn:
            ok, mensaje, bloqueado = auth.completar_segundo_factor(conn, codigo, cfg=g.cfg, ip=_ip())
        if ok:
            if mensaje != "Acceso concedido.":
                flash(mensaje, "aviso")
            with db.session(current_app.config.get("DB_PATH")) as conn:
                fila = conn.execute("SELECT * FROM users WHERE username=?",
                                    (pendiente["username"],)).fetchone()
            return _tras_acceso(dict(fila) if fila else pendiente, session.pop(CLAVE_DESTINO, None))
        flash(mensaje, "error")
        if bloqueado:
            session.pop(CLAVE_DESTINO, None)
            return redirect(url_for("auth.login"))

    respuesta = make_response(render_template("segundo_factor.html", csrf=auth.token_csrf()))
    respuesta.headers["Cache-Control"] = "no-store, private"
    respuesta.headers["Pragma"] = "no-cache"
    return respuesta


@bp.route("/logout", methods=["POST"])
@auth.requiere_csrf
def logout():
    auth.cerrar_sesion()
    flash("Sesión cerrada.", "info")
    return redirect(url_for("auth.login"))


def _fila_propia(conn=None):
    conexion = conn if conn is not None else g.db
    fila = conexion.execute("SELECT * FROM users WHERE username=?", (g.usuario,)).fetchone()
    return dict(fila) if fila else None


# --------------------------------------------------------------------------
# Cambio de contrasena obligatorio (bloqueante) del primer acceso
# --------------------------------------------------------------------------
# Fallo grave corregido el 2026-09-07, senalado por el usuario: «cuando un usuario
# ingresa por primera vez y lo lleva a cambiar de clave, veo que le da acceso
# directamente a la plataforma y eso no deberia ser asi». _tras_acceso redirigia al
# formulario con un aviso, pero webui.auth.requiere_login no comprobaba
# users.must_change, de modo que bastaba escribir «/», «/activos/» o «/amenazas/»
# para entrar con la contrasena inicial, que conoce quien creo la cuenta.
#
# Ahora la comprobacion vive en el decorador (auth.cambio_password_obligatorio) y
# esta pantalla es una pagina aparte, con la misma estructura que segundo_factor.html:
# ni menu lateral, ni barra superior, ni buscador, ni recorrido guiado. Solo la
# marca, el formulario de dos campos y el boton de salir.

@bp.route("/cambiar-contrasena", methods=["GET", "POST"])
@auth.requiere_login
@auth.requiere_csrf
def cambiar_contrasena():
    """Pantalla aislada y bloqueante mientras users.must_change vale 1.

    No pide la contrasena actual: la sesion ya se abrio con ella hace un instante
    y pedirla otra vez solo empuja a escribirla en un sitio donde no hace falta.
    Si que rechaza repetir la actual, porque una contrasena que conoce el
    administrador que creo la cuenta no puede seguir siendo la de la persona."""
    motivo = auth.motivo_cambio_obligatorio()
    if motivo is None:
        # Nada que forzar: el formulario normal esta en el perfil.
        return redirect(url_for("auth.perfil"))

    fila = _fila_propia()
    if fila is None:
        auth.cerrar_sesion()
        return redirect(url_for("auth.login"))
    contrasena = auth.estado_password(fila, cfg=g.cfg)

    if request.method == "POST":
        nueva = request.form.get("nueva", "")
        repetir = request.form.get("repetir", "")
        if nueva != repetir:
            flash("Las contraseñas nuevas no coinciden.", "error")
        elif auth.verificar_password(nueva, fila["password_hash"]):
            if motivo == "caducada":
                flash("La contraseña nueva es la misma que la actual. La política de "
                      "seguridad exige una distinta cada "
                      f"{contrasena['max_dias']} días.", "error")
            else:
                flash("La contraseña nueva es la misma que la actual. Escriba una "
                      "distinta: la que tiene ahora la conoce quien creó la cuenta.", "error")
        else:
            try:
                # Se conserva ESTA sesion (excepto_sid) y mueren las demas: el
                # usuario acaba de escribir su contrasena nueva y entra, mientras
                # cualquier otra sesion abierta con la contrasena inicial se cierra.
                with db.session(current_app.config.get("DB_PATH")) as conn:
                    auth.cambiar_password(conn, g.usuario, nueva, actor=g.usuario,
                                          excepto_sid=auth.sid_actual())
                    # Identificador de sesion y token CSRF nuevos (revision del
                    # 2026-09-07): esta sesion pasa de «solo ve una pantalla» a
                    # «acceso completo», asi que no debe conservar el identificador
                    # con el que entro usando la contrasena que escribio el
                    # administrador. Es la misma defensa que el segundo factor
                    # (fijacion de sesion, A07:2025).
                    auth.renovar_identificador_sesion(conn)
                    db.audit(conn, g.usuario, "password.cambio_obligatorio", "users",
                             fila["id"],
                             ("contraseña caducada renovada por su dueño; "
                              if motivo == "caducada" else
                              "contraseña inicial sustituida por su dueño; ")
                             + "las demás sesiones quedan revocadas y el identificador "
                             "de sesión se renueva", _ip())
                auth.olvidar_estado_cuenta()
                flash("Contraseña actualizada. Ya puede usar la plataforma.", "exito")
                # El siguiente paso lo decide requiere_login: si el ajuste obliga al
                # segundo factor a los administradores, «/» lleva a la activacion.
                return redirect(url_for("panel.inicio"))
            except ValueError as exc:
                flash(str(exc), "error")

    respuesta = make_response(render_template(
        "cambiar_password_obligatorio.html", csrf=auth.token_csrf(),
        correo=g.usuario, nombre=(fila.get("nombre") or "").strip(),
        motivo=motivo, contrasena=contrasena,
        historial=auth.ajuste_entero("password_historial", auth.PASSWORD_HISTORIAL_DEFECTO)))
    respuesta.headers["Cache-Control"] = "no-store, private"
    respuesta.headers["Pragma"] = "no-cache"
    return respuesta


# --------------------------------------------------------------------------
# Perfil de la persona
# --------------------------------------------------------------------------
def _cambiar_password_propia():
    """Cambio de contrasena con la contrasena actual (perfil y ruta historica).

    Devuelve la redireccion cuando se ha cambiado; None cuando hay que volver a
    mostrar la pagina con el aviso del error.

    Revision del 2026-09-07 (hallazgo medio del revisor): la contrasena actual se
    comprobaba sin contador, sin bloqueo y sin dejar rastro, asi que desde una
    sesion robada se podia adivinarla indefinidamente en /perfil y en /mi-password
    (A07:2025 y A09:2025). Ahora usa el MISMO contador, el mismo bloqueo y la misma
    auditoria que las rutas del segundo factor (_comprobar_password_propia), de modo
    que los tres formularios que piden la contrasena propia se comportan igual."""
    actual = request.form.get("actual", "")[:200]
    nueva = request.form.get("nueva", "")
    repetir = request.form.get("repetir", "")

    fila = _fila_propia()
    if not fila:
        auth.cerrar_sesion()
        return redirect(url_for("auth.login"))
    bloqueada = _rechazar_si_bloqueada(fila)
    if bloqueada is not None:
        return bloqueada
    with db.session(current_app.config.get("DB_PATH")) as conn:
        correcta, agotada, minutos = _comprobar_password_propia(
            conn, fila, actual, accion="usuario.password.fallo")
    if not correcta:
        if agotada:
            return _aviso_bloqueo(minutos)
        flash("La contraseña actual no es correcta.", "error")
        return None
    if nueva != repetir:
        flash("Las contraseñas nuevas no coinciden.", "error")
        return None
    if auth.verificar_password(nueva, fila["password_hash"]):
        flash("La contraseña nueva es la misma que la actual. Escriba una distinta.", "error")
        return None
    try:
        with db.session(current_app.config.get("DB_PATH")) as conn:
            auth.cambiar_password(conn, g.usuario, nueva, actor=g.usuario)
            # La contrasena era correcta: el contador de intentos vuelve a cero,
            # igual que al acertar un codigo del segundo factor.
            auth.reiniciar_fallos_2fa(conn, fila["id"])
        flash("Contraseña actualizada.", "exito")
        return redirect(url_for("panel.inicio"))
    except ValueError as exc:
        flash(str(exc), "error")
        return None


#: Detalles de audit_log con un texto propio para el perfil. La cadena vacia
#: significa «no lo repitas»: la columna «Qué ocurrió» ya lo dice.
#:
#: Revision del 2026-09-07 (hallazgo medio del revisor): la columna «Detalle»
#: volcaba audit_log.detail tal cual, y los detalles historicos se escribieron sin
#: tildes («contrasena incorrecta (intento 1/5)»), asi que la interfaz mostraba a
#: cada persona un texto que incumple la regla del proyecto. Los detalles nuevos ya
#: llevan tildes (webui/auth.py), pero la base real conserva las filas antiguas y
#: hay que traducirlas al mostrarlas.
DETALLES_ACCESO_ES = {
    "contrasena correcta; pendiente el segundo factor": "",
    "contraseña correcta; pendiente el segundo factor": "",
    "usuario inexistente": "El correo escrito no corresponde a ninguna cuenta.",
    "usuario deshabilitado": "La cuenta estaba deshabilitada en ese momento.",
    "la cuenta estaba deshabilitada": "La cuenta estaba deshabilitada en ese momento.",
}
#: «contrasena incorrecta (intento 1/5)» y «contraseña incorrecta (intento 1 de 5)».
_RE_INTENTO = re.compile(r"^contrase(?:n|ñ)a incorrecta \(intento (\d+)\s*(?:/|de)\s*(\d+)\)$",
                         re.IGNORECASE)
#: Palabras que en los detalles antiguos se escribieron sin tilde.
_TILDES_DETALLE = (("contrasena", "contraseña"), ("codigo", "código"),
                   ("sesion", "sesión"), ("direccion", "dirección"),
                   ("invalido", "inválido"), ("caduco", "caducó"))


def detalle_en_espanol(detalle: str | None) -> str:
    """Detalle de auditoria listo para mostrarlo a la persona en su perfil.

    Devuelve cadena vacia cuando el detalle no anade nada a la columna «Qué
    ocurrió». Nunca inventa: si el texto no es conocido, se limita a reponer las
    tildes de las palabras que el proyecto escribe con tilde."""
    texto = (detalle or "").strip()
    if not texto:
        return ""
    if texto in DETALLES_ACCESO_ES:
        return DETALLES_ACCESO_ES[texto]
    intento = _RE_INTENTO.match(texto)
    if intento:
        return ("Contraseña incorrecta (intento "
                f"{intento.group(1)} de {intento.group(2)}: al llegar al último "
                "la cuenta se bloquea un rato).")
    for sin_tilde, con_tilde in _TILDES_DETALLE:
        texto = texto.replace(sin_tilde, con_tilde)
        texto = texto.replace(sin_tilde.capitalize(), con_tilde.capitalize())
    return texto


def _accesos_recientes(conn, usuario: str, limite: int = ACCESOS_EN_PERFIL) -> list[dict]:
    """Ultimos accesos e intentos de ESE usuario, leidos de audit_log.

    Los aciertos se auditan con username=<usuario>; los fallos con username NULL
    (no hay sesion) y el usuario en entity_id, asi que se buscan por las dos
    columnas. Solo se leen las acciones de acceso: el perfil no es la auditoria
    general, que es cosa de administradores."""
    marcas = tuple(ACCIONES_ACCESO)
    filas = conn.execute(
        f"""SELECT at, action, ip, detail FROM audit_log
             WHERE action IN ({','.join('?' * len(marcas))})
               AND (username = ? OR (entity = 'users' AND entity_id = ?))
             ORDER BY id DESC LIMIT ?""",
        (*marcas, usuario, usuario, int(limite))).fetchall()
    accesos = []
    for f in filas:
        texto, insignia = ACCIONES_ACCESO[f["action"]]
        accesos.append({"at": f["at"], "que": texto, "insignia": insignia,
                        "ip": f["ip"], "detalle": detalle_en_espanol(f["detail"])})
    return accesos


def _datos_perfil(fila: dict) -> dict:
    """Todo lo que muestra el perfil, en una sola consulta por dato."""
    usuario = fila["username"]
    minutos = auth.ajuste_entero("webui_session_minutos", auth.MINUTOS_SESION_DEFECTO)
    # Una sesion sin actividad durante «webui_session_minutos» ya no cuenta como abierta
    # aunque su fila siga en la tabla hasta la siguiente limpieza (2026-09-08).
    limite_inactividad = (datetime.now(timezone.utc) - timedelta(minutes=minutos)).replace(
        microsecond=0).isoformat().replace("+00:00", "Z")
    sesiones = g.db.execute(
        """SELECT COUNT(*) FROM web_sessions
            WHERE username=? AND mfa_pendiente=0 AND expires_at > ? AND last_seen_at > ?""",
        (usuario, db.utcnow(), limite_inactividad)).fetchone()[0]
    bloqueada = auth.cuenta_bloqueada(fila)
    contrasena = auth.estado_password(fila, cfg=g.cfg)
    return {
        # Politica de sesion y de contrasena, para explicarlas en la pagina
        "sesion_minutos": minutos,
        "sesion_maximo_horas": auth.ajuste_entero("webui_session_maximo_horas",
                                                  auth.HORAS_SESION_MAXIMO_DEFECTO),
        "password_cambiada": fila.get("password_changed_at"),
        "password": contrasena,
        "password_historial": auth.ajuste_entero("password_historial",
                                                 auth.PASSWORD_HISTORIAL_DEFECTO),
        "nombre": (fila.get("nombre") or "").strip(),
        "correo": usuario,
        "rol": fila.get("role"),
        "rol_es": ROL_ES.get(fila.get("role"), fila.get("role")),
        "creada": fila.get("created_at"),
        "ultimo_acceso": fila.get("last_login_at"),
        "sesiones": int(sesiones or 0),
        "fallos": int(fila.get("failed_logins") or 0),
        "bloqueada_minutos": bloqueada,
        # «1 minuto» / «15 minutos»: la concordancia importa en un texto visible
        # (hallazgo bajo del revisor del 2026-09-07: decia «quedan 1 minutos»).
        "bloqueada_texto": auth.texto_minutos(bloqueada) if bloqueada else "",
        "accesos": _accesos_recientes(g.db, usuario),
    }


def _pagina_perfil(plantilla: str):
    fila = _fila_propia()
    if fila is None:
        auth.cerrar_sesion()
        return redirect(url_for("auth.login"))
    return render_template(plantilla, persona=_datos_perfil(fila),
                           accesos_maximo=ACCESOS_EN_PERFIL,
                           segundo_factor=auth.estado_2fa(fila),
                           obligatorio=auth.activacion_2fa_obligatoria())


@bp.route("/perfil", methods=["GET", "POST"])
@auth.requiere_login
@auth.requiere_csrf
def perfil():
    """Apartado de perfil: quien soy, accesos, contrasena y segundo factor.

    Sustituye al boton «Contrasena» de la barra superior (peticion del 2026-09-07:
    «se debe crear un apartado para consultar el usuario de cada persona, es decir
    como ir al perfil para cada usuario»). Solo muestra los datos del usuario de la
    sesion: no recibe ningun identificador, asi que no hay forma de pedir el perfil
    de otra persona."""
    if request.method == "POST":
        destino = _cambiar_password_propia()
        if destino is not None:
            return destino
    return _pagina_perfil("perfil.html")


@bp.route("/mi-password", methods=["GET", "POST"])
@auth.requiere_login
@auth.requiere_csrf
def mi_password():
    """Direccion historica del formulario de contrasena, hoy dentro del perfil.

    Se conserva porque hay enlaces, marcadores y avisos que apuntan aqui: muestra
    el mismo perfil y acepta el mismo POST de tres campos.

    Con users.must_change=1 reenvia a la pantalla del cambio obligatorio. Esta ruta
    esta exenta de la comprobacion general (auth.ENDPOINTS_SIN_CAMBIO_OBLIGATORIO)
    solo para que el POST del formulario antiguo siga funcionando; ninguna vista de
    la plataforma se muestra a quien todavia no ha cambiado la contrasena inicial."""
    if request.method == "POST":
        destino = _cambiar_password_propia()
        if destino is not None:
            return destino
    if auth.cambio_password_obligatorio():
        return redirect(url_for("auth.cambiar_contrasena"))
    return _pagina_perfil("mi_password.html")


# --------------------------------------------------------------------------
# Segundo factor: activacion, codigos de recuperacion y desactivacion
# --------------------------------------------------------------------------
def _inicio_activacion() -> float | None:
    """Marca de tiempo en que empezo la activacion, o None si caduco o no existe."""
    creado = session.get(CLAVE_ACTIVACION_INICIADA)
    if not isinstance(creado, (int, float)) or isinstance(creado, bool) \
            or time.time() - creado > CADUCIDAD_ACTIVACION_S:
        session.pop(CLAVE_ACTIVACION_INICIADA, None)
        return None
    return float(creado)


def _secreto_pendiente() -> str | None:
    """Secreto escaneado y aun sin confirmar.

    Vive en el servidor (users.totp_secret con users.totp_activado_at NULL); de la
    cookie solo se lee la marca de tiempo, para respetar los diez minutos."""
    if _inicio_activacion() is None:
        return None
    return auth.secreto_pendiente_2fa(g.db, g.usuario)


def _olvidar_activacion() -> None:
    """Cancela la activacion en curso: borra el secreto sin confirmar y la marca."""
    session.pop(CLAVE_ACTIVACION_INICIADA, None)
    with db.session(current_app.config.get("DB_PATH")) as conn:
        auth.cancelar_activacion_2fa(conn, g.usuario)


def _pagina_activacion(secreto: str | None, estado: int = 200):
    """Pagina de activacion. Con ``secreto`` None todavia no hay activacion en curso:
    se muestra la explicacion y un boton que la empieza por POST, porque un GET nunca
    debe cambiar el estado del servidor (revision de seguridad del 2026-09-06)."""
    respuesta = make_response(render_template(
        "segundo_factor_activar.html",
        secreto=totp.agrupar_secreto(secreto) if secreto else None,
        qr=totp.qr_svg(totp.uri(secreto, g.usuario)) if secreto else None,
        minutos=CADUCIDAD_ACTIVACION_S // 60,
        codigos=None), estado)
    respuesta.headers["Cache-Control"] = "no-store, private"
    return respuesta


def _pagina_codigos(codigos: list[str], titulo: str):
    respuesta = make_response(render_template(
        "segundo_factor_activar.html", secreto=None, qr=None, minutos=0,
        codigos=codigos, titulo_codigos=titulo))
    respuesta.headers["Cache-Control"] = "no-store, private"
    return respuesta


def _comprobar_codigo_propio(conn, fila: dict, codigo: str, *, accion: str
                             ) -> tuple[bool, bool, int]:
    """Comprueba un codigo del segundo factor del propio usuario CONTANDO los fallos.

    Revision del 2026-09-06 (hallazgos 3 y 4): «Desactivar» y «Regenerar los
    codigos» comprobaban el codigo sin contador ni bloqueo, asi que desde una
    sesion robada se podian probar codigos sin limite. Ahora comparten el mismo
    contador (users.totp_fallos) y el mismo bloqueo que el acceso: al alcanzar
    «webui_max_failed_logins» la cuenta queda bloqueada «webui_lockout_minutes»
    minutos y se cierran sus sesiones.

    Devuelve (correcto, bloqueada, minutos_de_bloqueo)."""
    ok, _modo = auth.verificar_codigo_2fa(conn, fila, codigo)
    if ok:
        auth.reiniciar_fallos_2fa(conn, fila["id"])
        return True, False, 0
    fallos, maximo, bloqueada, minutos = auth.anotar_fallo_2fa(conn, fila, cfg=g.cfg)
    db.audit(conn, g.usuario, accion, "users", fila["id"],
             f"codigo incorrecto (intento {fallos}/{maximo})", _ip())
    if bloqueada:
        auth.revocar_sesiones(conn, g.usuario)
        auth.cerrar_sesion(conn)
    return False, bool(bloqueada), minutos


def _comprobar_password_propia(conn, fila: dict, password: str, *, accion: str
                               ) -> tuple[bool, bool, int]:
    """Comprueba la contrasena del propio usuario CONTANDO los fallos.

    Revision del 2026-09-06: «Desactivar el segundo factor» y «Regenerar los
    codigos» contaban los codigos incorrectos pero no las contrasenas, asi que
    desde una sesion robada se podian probar contrasenas sin limite y sin dejar
    rastro. Ahora comparten el contador y el bloqueo del segundo factor y queda
    auditado. Devuelve (correcta, bloqueada, minutos_de_bloqueo)."""
    if auth.verificar_password(password, fila["password_hash"]):
        return True, False, 0
    fallos, maximo, bloqueada, minutos = auth.anotar_fallo_2fa(conn, fila, cfg=g.cfg)
    db.audit(conn, g.usuario, accion, "users", fila["id"],
             f"contrasena incorrecta (intento {fallos}/{maximo})", _ip())
    if bloqueada:
        auth.revocar_sesiones(conn, g.usuario)
        auth.cerrar_sesion(conn)
    return False, bool(bloqueada), minutos


def _aviso_bloqueo(minutos: int):
    flash("Demasiados intentos incorrectos: la cuenta queda bloqueada "
          f"{auth.texto_minutos(minutos)} y se han cerrado sus sesiones. "
          "Vuelva a identificarse cuando pase ese tiempo.", "error")
    return redirect(url_for("auth.login"))


def _rechazar_si_bloqueada(fila: dict):
    """Con la cuenta bloqueada no se toca el segundo factor: la sesion se cierra."""
    restante = auth.cuenta_bloqueada(fila)
    if not restante:
        return None
    with db.session(current_app.config.get("DB_PATH")) as conn:
        auth.revocar_sesiones(conn, g.usuario)
        auth.cerrar_sesion(conn)
    flash("Cuenta bloqueada temporalmente. Vuelva a intentarlo en "
          f"{auth.texto_minutos(restante)}.", "error")
    return redirect(url_for("auth.login"))


@bp.route("/mi-password/segundo-factor/activar", methods=["GET", "POST"])
@auth.requiere_login
@auth.requiere_csrf
def segundo_factor_activar():
    fila = _fila_propia()
    if fila is None:
        auth.cerrar_sesion()
        return redirect(url_for("auth.login"))
    if fila.get("totp_activado_at"):
        flash("El segundo factor ya está activado. Para cambiar de dispositivo, desactívelo y vuelva a activarlo.", "info")
        return redirect(url_for("auth.mi_password"))

    if request.method == "POST" and request.form.get("empezar"):
        # Empezar una activacion nueva sustituye cualquier secreto sin confirmar.
        with db.session(current_app.config.get("DB_PATH")) as conn:
            secreto = auth.iniciar_activacion_2fa(conn, g.usuario, actor=g.usuario, ip=_ip())
        session[CLAVE_ACTIVACION_INICIADA] = time.time()
        return _pagina_activacion(secreto)

    if request.method == "POST":
        secreto = _secreto_pendiente()
        if secreto is None:
            _olvidar_activacion()
            flash("La activación caducó (diez minutos). Escanee el código nuevo e inténtelo otra vez.", "aviso")
            return redirect(url_for("auth.segundo_factor_activar"))
        codigo = (request.form.get("codigo") or "")[:totp.LONGITUD_MAXIMA_ENTRADA]
        paso = totp.paso_valido(secreto, codigo, ventana=1)
        if paso is None:
            flash("El código no coincide. Compruebe que la aplicación tiene la hora correcta y escriba el código actual.", "error")
            return _pagina_activacion(secreto, 400)
        with db.session(current_app.config.get("DB_PATH")) as conn:
            codigos = auth.activar_2fa(conn, g.usuario, secreto, paso, actor=g.usuario, ip=_ip(),
                                       excepto_sid=auth.sid_actual())
        session.pop(CLAVE_ACTIVACION_INICIADA, None)
        g._2fa_obligatoria = None
        flash("Segundo factor activado. A partir de ahora se pedirá el código de la aplicación al entrar. "
              "Sus otras sesiones abiertas se han cerrado.", "exito")
        return _pagina_codigos(codigos, "Códigos de recuperación")

    # Un GET nunca cambia el estado del servidor (revision 2026-09-06): solo muestra el
    # secreto de una activacion en curso. El secreto se crea en el POST «empezar», que
    # si pasa por la comprobacion de CSRF.
    secreto = _secreto_pendiente()
    if secreto is None:
        _olvidar_activacion()
    return _pagina_activacion(secreto)


@bp.route("/mi-password/segundo-factor/codigos", methods=["POST"])
@auth.requiere_login
@auth.requiere_csrf
def segundo_factor_codigos():
    """Regenera los ocho codigos de recuperacion.

    Exige contrasena Y codigo del segundo factor (hallazgo 4 del 2026-09-06): con
    solo la contrasena, quien robara una sesion se llevaba ocho codigos nuevos con
    los que entrar mas tarde sin el telefono."""
    fila = _fila_propia()
    if not fila or not fila.get("totp_activado_at"):
        flash("El segundo factor no está activado.", "error")
        return redirect(url_for("auth.mi_password"))
    bloqueada = _rechazar_si_bloqueada(fila)
    if bloqueada is not None:
        return bloqueada
    password = request.form.get("password", "")[:200]
    codigo = (request.form.get("codigo") or "")[:totp.LONGITUD_MAXIMA_ENTRADA]
    fallo_password = False
    with db.session(current_app.config.get("DB_PATH")) as conn:
        ok, bloqueada, minutos = _comprobar_password_propia(
            conn, fila, password, accion="2fa.codigos.fallo")
        if ok:
            ok, bloqueada, minutos = _comprobar_codigo_propio(
                conn, fila, codigo, accion="2fa.codigos.fallo")
        elif not bloqueada:
            fallo_password = True
        if ok:
            codigos = auth.regenerar_codigos_2fa(conn, g.usuario, actor=g.usuario, ip=_ip())
    if bloqueada:
        return _aviso_bloqueo(minutos)
    if not ok:
        flash("La contraseña actual no es correcta." if fallo_password
              else "El código no es válido; los códigos de recuperación siguen siendo los mismos.", "error")
        return redirect(url_for("auth.mi_password"))
    flash("Códigos de recuperación regenerados: los anteriores ya no sirven.", "exito")
    return _pagina_codigos(codigos, "Códigos de recuperación nuevos")


@bp.route("/mi-password/segundo-factor/desactivar", methods=["POST"])
@auth.requiere_login
@auth.requiere_csrf
def segundo_factor_desactivar():
    fila = _fila_propia()
    if not fila or not fila.get("totp_activado_at"):
        flash("El segundo factor no está activado.", "error")
        return redirect(url_for("auth.mi_password"))
    bloqueada = _rechazar_si_bloqueada(fila)
    if bloqueada is not None:
        return bloqueada
    password = request.form.get("password", "")[:200]
    codigo = (request.form.get("codigo") or "")[:totp.LONGITUD_MAXIMA_ENTRADA]
    fallo_password = False
    with db.session(current_app.config.get("DB_PATH")) as conn:
        ok, bloqueada, minutos = _comprobar_password_propia(
            conn, fila, password, accion="2fa.desactivar.fallo")
        if ok:
            ok, bloqueada, minutos = _comprobar_codigo_propio(
                conn, fila, codigo, accion="2fa.desactivar.fallo")
        elif not bloqueada:
            fallo_password = True
        if ok:
            auth.desactivar_2fa(conn, g.usuario, actor=g.usuario, ip=_ip(),
                                excepto_sid=auth.sid_actual())
    if bloqueada:
        return _aviso_bloqueo(minutos)
    if not ok:
        flash("La contraseña actual no es correcta." if fallo_password
              else "El código no es válido; el segundo factor sigue activo.", "error")
        return redirect(url_for("auth.mi_password"))
    g._2fa_obligatoria = None
    flash("Segundo factor desactivado. Sus otras sesiones abiertas se han cerrado.", "exito")
    return redirect(url_for("auth.mi_password"))

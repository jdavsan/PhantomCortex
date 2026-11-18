"""Gestion de usuarios de la interfaz (solo administradores).

Peticion del 2026-09-05: crear, editar y eliminar usuarios desde la interfaz, con
el correo electronico como nombre de usuario y una politica de contrasenas
verificable (webui.auth.fuerza_password: 12 caracteres y tres clases). Reglas:

* el nombre de usuario nuevo debe ser un correo electronico valido, en minusculas;
* un administrador no puede eliminarse ni degradarse a si mismo, ni dejar el
  sistema sin ningun administrador habilitado;
* la contrasena inicial la escribe el administrador (cumpliendo la politica) o
  se genera; en ambos casos el usuario debe cambiarla en su primer acceso;
* al deshabilitar, eliminar o restablecer la contrasena se revocan las sesiones
  abiertas de ese usuario; todo queda en la auditoria;
* segundo factor (2026-09-05): la lista muestra si cada usuario lo tiene activado y
  un administrador puede restablecerlo (borrar secreto y codigos de recuperacion)
  cuando el usuario ha perdido el telefono; tambien revoca sus sesiones. El
  PROPIO segundo factor no se restablece desde aqui (solo con sesion y CSRF seria
  saltarse la contrasena y el codigo que exige «Cambiar mi contrasena» → Desactivar);
* revision del 2026-09-05: «Desbloquear» reinicia tambien totp_fallos; las sesiones
  pendientes de segundo factor (mfa_pendiente=1) no cuentan como abiertas; rol y
  estado se aplican al cambiar el selector y el aviso dice exactamente que cambio.

Peticion del 2026-09-07 (nombre de la persona y edicion completa):

* la persona tiene NOMBRE (users.nombre, esquema v9) y es lo que se muestra en la
  interfaz; el correo queda debajo, en pequeno y atenuado, porque sigue siendo el
  nombre de usuario con el que se entra. Donde el nombre falta, la fila lo dice y
  ofrece el enlace para completarlo;
* alta: el nombre es obligatorio en el formulario (campo `required` con etiqueta
  visible) y se valida en el servidor con `_normalizar_nombre` (3 a 80 caracteres,
  letras con tilde, espacios, guiones, apostrofos y puntos; sin cifras ni signos
  de marcado). Es obligatorio SIEMPRE desde el 2026-09-07: una cuenta sin nombre
  obliga a volver a editarla, porque la barra superior y el perfil muestran el
  nombre de la persona y no su correo. Las altas desde el servidor lo pasan con
  `bin/gestionar_usuario.py crear <correo> --nombre "Nombre Apellidos"`; si se
  omite ahi, la cuenta queda sin nombre y la lista invita a completarlo;
* edicion completa en `actualizar()`: nombre, perfil, estado y, si se desea,
  contrasena nueva con repeticion. El formulario NO es en linea (se abre con
  `/usuarios/?editar=<id>` y se ve como un panel propio con etiquetas visibles),
  para que un cambio de contrasena nunca dependa de un selector que se envia solo;
* la contrasena nueva aplica la politica del proyecto, revoca todas las sesiones
  del usuario (webui.auth.cambiar_password) y deja must_change=1 para que la
  cambie el propio interesado en su primer acceso. En la auditoria se escribe que
  cambio y con que valor anterior y nuevo, NUNCA la contrasena;
* nadie cambia su propia contrasena desde aqui: se hace en «Cambiar mi contrasena»,
  que exige la contrasena actual (con solo una sesion robada bastaria si no).
"""
from __future__ import annotations

import time

import re
import secrets
import string

from flask import (Blueprint, current_app, flash, g, redirect, render_template,
                   request, url_for)
from flask import session  # la contraseña generada viaja una sola vez en la sesión

from threatintel import db
from webui import auth

bp = Blueprint("usuarios", __name__, url_prefix="/usuarios")

#: Los perfiles y su nombre visible los define webui.auth, que es donde vive el alcance
#: de cada uno: asi la lista de la interfaz y lo que permite el servidor no pueden
#: discrepar (2026-09-07, al añadir el perfil de Redes).
ROLES = auth.ROLES
ROL_ES = auth.ROL_ES
ROL_ALCANCE_ES = auth.ROL_ALCANCE_ES
_RE_CORREO = re.compile(r"^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$")
# Sin &, <, >, comillas ni espacios: la contrasena se muestra en HTML y se copia a mano.
_ALFABETO = string.ascii_letters + string.digits + "!#$%*+-=?@_"

#: Nombre de la persona: letras (con tilde y enie), espacios, guiones, apostrofos y
#: puntos. Sin cifras ni caracteres de marcado (<, >, &, comillas): asi el nombre nunca
#: puede confundirse con etiquetas al pintarlo, ademas del escapado de Jinja.
LONGITUD_NOMBRE = (3, 80)
_LETRAS = "A-Za-zÁÉÍÓÚÜÑáéíóúüñÇçÀÈÌÒÙàèìòùÂÊÎÔÛâêîôû"
_RE_NOMBRE = re.compile(rf"^[{_LETRAS}][{_LETRAS} .'’\-]*$")
AYUDA_NOMBRE = ("Entre 3 y 80 caracteres: letras, espacios, guiones, apóstrofos y puntos "
                "(por ejemplo «Ana María Pérez Gómez»). Sin cifras ni signos.")


def generar_password(longitud: int = 16) -> str:
    """Contrasena aleatoria que cumple la politica (tres clases como minimo)."""
    while True:
        p = "".join(secrets.choice(_ALFABETO) for _ in range(longitud))
        if auth.fuerza_password(p)[0]:
            return p


def _normalizar_correo(texto: str) -> str | None:
    correo = (texto or "").strip().lower()
    return correo if _RE_CORREO.match(correo) and len(correo) <= 120 else None


def _normalizar_nombre(texto: str) -> str | None:
    """Nombre de la persona listo para guardar, o None si no es aceptable.

    Colapsa los espacios repetidos (nadie escribe dos espacios a proposito) y
    comprueba longitud y caracteres."""
    nombre = " ".join((texto or "").split())
    minimo, maximo = LONGITUD_NOMBRE
    if not (minimo <= len(nombre) <= maximo):
        return None
    return nombre if _RE_NOMBRE.match(nombre) else None


def _nombre_de(fila) -> str:
    """Nombre guardado de la persona, o cadena vacia si todavia no se ha puesto."""
    try:
        valor = fila["nombre"]
    except (KeyError, IndexError):
        valor = None
    return (valor or "").strip()


def _identidad(fila) -> str:
    """Como se llama a esa persona en los avisos: su nombre o, si falta, su correo."""
    return _nombre_de(fila) or fila["username"]


def _usuarios(conn) -> list[dict]:
    filas = [dict(r) for r in conn.execute(
        """SELECT u.*, (SELECT COUNT(*) FROM web_sessions s WHERE s.username=u.username
                          AND s.mfa_pendiente=0
                          AND s.expires_at > strftime('%Y-%m-%dT%H:%M:%SZ','now')) AS sesiones
             FROM users u ORDER BY u.role, u.username""")]
    for f in filas:
        f["rol_es"] = ROL_ES.get(f["role"], f["role"])
        f["es_correo"] = _normalizar_correo(f["username"]) is not None
        f["bloqueado"] = bool(f.get("locked_until") and f["locked_until"] > db.utcnow())
        f["nombre_persona"] = _nombre_de(f)
        f["identidad"] = f["nombre_persona"] or f["username"]
        f["falta_nombre"] = not f["nombre_persona"]
    return filas


def _admins_habilitados(conn, excepto: str | None = None) -> int:
    fila = conn.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND enabled=1 AND username<>?",
                        (excepto or "",)).fetchone()
    return int(fila[0] or 0)


def _error_de_rol_y_estado(conn, fila, rol: str, habilitado: int) -> str | None:
    """Salvaguardas comunes al selector de la fila y al formulario de edicion."""
    if rol not in ROLES:
        return "Rol no válido."
    if fila["username"] == g.usuario and (rol != "admin" or not habilitado):
        return ("No puede quitarse a sí mismo el rol de administrador ni deshabilitar su propia cuenta.")
    if fila["role"] == "admin" and fila["enabled"] and (rol != "admin" or not habilitado) \
            and _admins_habilitados(conn, excepto=fila["username"]) == 0:
        return "Debe quedar al menos un administrador habilitado."
    return None


def _sesiones_abiertas(conn, username: str) -> int:
    fila = conn.execute("SELECT COUNT(*) FROM web_sessions WHERE username=?", (username,)).fetchone()
    return int(fila[0] or 0)


CLAVE_UNA_VEZ = "credencial_una_vez"
#: Segundos que la contrasena generada espera en memoria a que el navegador cargue la pagina
#: de Usuarios tras la redireccion. Pasado el plazo se descarta.
SEGUNDOS_CREDENCIAL_UNA_VEZ = 120
#: La contrasena generada NUNCA se escribe en la base: con la sesion en servidor, guardarla en
#: la sesion la dejaba en claro en web_sessions.datos (revision de seguridad del 2026-09-08).
#: Vive en la memoria del proceso, bajo un identificador aleatorio de un solo uso que es lo
#: unico que viaja en la sesion. Un reinicio del servicio la pierde: se muestra una vez o nunca.
_CREDENCIALES_UNA_VEZ: dict[str, tuple[float, dict]] = {}


def _mostrar_una_vez(usuario: str, password: str, motivo: str, nombre) -> None:
    """Deja la contrasena en memoria y su identificador en la sesion del administrador para
    que la proxima carga de la pagina de Usuarios la muestre una sola vez y la borre."""
    import secrets
    ahora = time.monotonic()
    for clave, (marca, _) in list(_CREDENCIALES_UNA_VEZ.items()):
        if ahora - marca > SEGUNDOS_CREDENCIAL_UNA_VEZ:
            _CREDENCIALES_UNA_VEZ.pop(clave, None)
    identificador = secrets.token_urlsafe(24)
    _CREDENCIALES_UNA_VEZ[identificador] = (ahora, {"usuario": usuario, "password": password,
                                                    "motivo": motivo, "nombre": nombre or ""})
    session[CLAVE_UNA_VEZ] = identificador


def _recoger_una_vez(identificador) -> dict | None:
    """Saca de la memoria la contrasena asociada al identificador (una sola vez)."""
    if not isinstance(identificador, str):
        return None
    marca, datos = _CREDENCIALES_UNA_VEZ.pop(identificador, (None, None))
    if marca is None or time.monotonic() - marca > SEGUNDOS_CREDENCIAL_UNA_VEZ:
        return None
    return datos


@bp.route("/")
@auth.requiere_admin
def lista():
    usuarios = _usuarios(g.db)
    # La contrasena generada en el alta o el restablecimiento: se saca de la sesion (pop) y
    # por tanto solo se ve en esta carga; al recargar ya no esta.
    credencial = _recoger_una_vez(session.pop(CLAVE_UNA_VEZ, None))
    # El formulario de edicion se abre con ?editar=<id>: asi es una pagina normal
    # (funciona sin JavaScript, se puede enlazar y no se pierde al recargar).
    editar_id = request.args.get("editar", type=int)
    editando = next((u for u in usuarios if u["id"] == editar_id), None) if editar_id else None
    return render_template("usuarios.html", usuarios=usuarios, roles=ROLES, rol_es=ROL_ES,
                           rol_alcance_es=ROL_ALCANCE_ES,
                           admins=sum(1 for u in usuarios if u["role"] == "admin" and u["enabled"]),
                           sin_nombre=sum(1 for u in usuarios if u["falta_nombre"]),
                           editando=editando,
                           editar_no_existe=bool(editar_id and editando is None),
                           ayuda_nombre=AYUDA_NOMBRE,
                           credencial=credencial)


@bp.route("/crear", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def crear():
    correo = _normalizar_correo(request.form.get("correo"))
    # El nombre es obligatorio en el alta desde el 2026-09-07: la barra superior y el
    # perfil muestran el nombre de la persona, no su correo, y una cuenta sin nombre
    # obliga a volver a editarla. Las altas desde el servidor lo piden con --nombre.
    nombre = _normalizar_nombre(request.form.get("nombre"))
    if nombre is None:
        flash(f"Escriba el nombre y apellidos de la persona. {AYUDA_NOMBRE}", "error")
        return redirect(url_for("usuarios.lista"))
    rol = (request.form.get("rol") or "viewer").strip()
    password = request.form.get("password") or ""
    generar = request.form.get("generar") == "1"
    if correo is None:
        flash("El usuario debe ser un correo electrónico válido (nombre@dominio).", "error")
        return redirect(url_for("usuarios.lista"))
    if rol not in ROLES:
        flash("Rol no válido.", "error")
        return redirect(url_for("usuarios.lista"))
    if generar:
        password = generar_password()
    else:
        ok, motivo = auth.fuerza_password(password)
        if not ok:
            flash(f"Contraseña rechazada: {motivo}", "error")
            return redirect(url_for("usuarios.lista"))
        if password != (request.form.get("repetir") or ""):
            flash("Las contraseñas no coinciden.", "error")
            return redirect(url_for("usuarios.lista"))
    try:
        with db.session(current_app.config.get("DB_PATH")) as conn:
            nuevo_id = auth.crear_usuario(conn, correo, password, rol=rol, must_change=True,
                                          actor=g.usuario)
            if nombre:
                # auth.crear_usuario no conoce la columna nombre: se guarda aqui, en la
                # misma transaccion, y queda en la auditoria del alta.
                conn.execute("UPDATE users SET nombre=? WHERE id=?", (nombre, nuevo_id))
                db.audit(conn, g.usuario, "usuario.nombre", "users", nuevo_id,
                         f"usuario={correo} nombre=«{nombre}»", request.remote_addr)
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("usuarios.lista"))
    de_quien = f" a nombre de {nombre}" if nombre else ""
    if generar:
        # La contrasena generada se muestra UNA sola vez, en un panel propio de la pagina de
        # Usuarios (no en el aviso de arriba, donde el usuario no la veia: 2026-09-08). Viaja
        # en la sesion del administrador hasta la siguiente carga de la pagina, que la
        # consume; no se guarda ni se registra en ningun sitio.
        _mostrar_una_vez(correo, password, "alta", nombre)
        flash(f"Usuario {correo} creado con rol {ROL_ES[rol].lower()}{de_quien}. Su contraseña "
              f"inicial se muestra a continuación una sola vez.", "exito")
    else:
        flash(f"Usuario {correo} creado con rol {ROL_ES[rol].lower()}{de_quien}. "
              f"Deberá cambiar la contraseña en el primer acceso.", "exito")
    return redirect(url_for("usuarios.lista"))


@bp.route("/<int:usuario_id>/editar", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def editar(usuario_id: int):
    """Cambio rapido de perfil y estado desde el selector de la fila.

    La edicion completa (nombre y contrasena incluidos) esta en `actualizar()`."""
    rol = (request.form.get("rol") or "").strip()
    habilitado = 1 if request.form.get("enabled") == "1" else 0
    with db.session(current_app.config.get("DB_PATH")) as conn:
        fila = conn.execute("SELECT * FROM users WHERE id=?", (usuario_id,)).fetchone()
        if fila is None:
            flash("El usuario no existe.", "error")
            return redirect(url_for("usuarios.lista"))
        error = _error_de_rol_y_estado(conn, fila, rol, habilitado)
        if error:
            flash(error, "error")
            return redirect(url_for("usuarios.lista"))
        quien = _identidad(fila)
        cambios: list[str] = []
        if rol != fila["role"]:
            cambios.append(f"rol de {quien} cambiado a {ROL_ES[rol]}")
        if habilitado != int(fila["enabled"] or 0):
            cambios.append(f"usuario {quien} {'habilitado' if habilitado else 'deshabilitado'}")
        if not cambios:
            flash(f"Sin cambios: {quien} ya tenía ese rol y ese estado.", "info")
            return redirect(url_for("usuarios.lista"))
        conn.execute("UPDATE users SET role=?, enabled=? WHERE id=?", (rol, habilitado, usuario_id))
        revocadas = 0
        if not habilitado or rol != fila["role"]:
            revocadas = auth.revocar_sesiones(conn, fila["username"])
        db.audit(conn, g.usuario, "usuario.editar", "users", usuario_id,
                 f"usuario={fila['username']} rol={rol} habilitado={habilitado} sesiones_revocadas={revocadas}",
                 request.remote_addr)
    # El aviso dice exactamente que cambio (la fila se guarda al cambiar el selector,
    # sin boton «Guardar», asi que es la unica confirmacion que ve el administrador).
    mensaje = "; ".join(cambios)
    mensaje = mensaje[0].upper() + mensaje[1:] + "."
    if revocadas:
        mensaje += f" Se han cerrado {revocadas} sesión(es) abierta(s) de ese usuario."
    flash(mensaje, "exito")
    return redirect(url_for("usuarios.lista"))


@bp.route("/<int:usuario_id>/actualizar", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def actualizar(usuario_id: int):
    """Edicion completa de un usuario: nombre, perfil, estado y contrasena nueva.

    Peticion del 2026-09-07. El correo (nombre de usuario) no se cambia: es la
    referencia de las sesiones, la auditoria y el historial, asi que si cambia la
    persona se crea otro usuario y se elimina el anterior."""
    nombre = _normalizar_nombre(request.form.get("nombre"))
    rol = (request.form.get("rol") or "").strip()
    habilitado = 1 if request.form.get("enabled") == "1" else 0
    nueva = request.form.get("password_nueva") or ""
    repetir = request.form.get("password_repetir") or ""
    volver = url_for("usuarios.lista", editar=usuario_id)
    with db.session(current_app.config.get("DB_PATH")) as conn:
        fila = conn.execute("SELECT * FROM users WHERE id=?", (usuario_id,)).fetchone()
        if fila is None:
            flash("El usuario no existe.", "error")
            return redirect(url_for("usuarios.lista"))
        if nombre is None:
            flash(f"Escriba el nombre y apellidos de la persona. {AYUDA_NOMBRE}", "error")
            return redirect(volver)
        error = _error_de_rol_y_estado(conn, fila, rol, habilitado)
        if error:
            flash(error, "error")
            return redirect(volver)
        if (nueva or repetir) and fila["username"] == g.usuario:
            # Con solo una sesion robada se podria cambiar la contrasena sin conocer la
            # actual. La propia se cambia en «Cambiar mi contrasena», que la exige.
            flash("No puede cambiar su propia contraseña desde aquí. Use «Cambiar mi contraseña», "
                  "que exige la contraseña actual.", "error")
            return redirect(volver)
        if nueva or repetir:
            ok, motivo = auth.fuerza_password(nueva)
            if not ok:
                flash(f"Contraseña rechazada: {motivo}", "error")
                return redirect(volver)
            if nueva != repetir:
                flash("Las contraseñas nuevas no coinciden.", "error")
                return redirect(volver)

        nombre_anterior = _nombre_de(fila)
        quien = nombre
        cambios: list[str] = []
        detalles: list[str] = [f"usuario={fila['username']}"]
        if nombre != nombre_anterior:
            cambios.append(f"nombre de {fila['username']}"
                           + (f" cambiado de «{nombre_anterior}» a «{nombre}»" if nombre_anterior
                              else f" establecido como «{nombre}»"))
            detalles.append(f"nombre=«{nombre_anterior}»→«{nombre}»")
        if rol != fila["role"]:
            cambios.append(f"perfil de {quien} cambiado a {ROL_ES[rol]}")
            detalles.append(f"rol={fila['role']}→{rol}")
        if habilitado != int(fila["enabled"] or 0):
            cambios.append(f"usuario {quien} {'habilitado' if habilitado else 'deshabilitado'}")
            detalles.append(f"habilitado={int(fila['enabled'] or 0)}→{habilitado}")
        if not cambios and not nueva:
            flash(f"Sin cambios: {quien} ya tenía ese nombre, ese perfil y ese estado, "
                  f"y no se escribió ninguna contraseña nueva.", "info")
            return redirect(volver)

        conn.execute("UPDATE users SET nombre=?, role=?, enabled=? WHERE id=?",
                     (nombre, rol, habilitado, usuario_id))
        revocadas = 0
        if nueva:
            # Se cuentan antes de revocar: cambiar_password borra todas las sesiones.
            revocadas = _sesiones_abiertas(conn, fila["username"])
            try:
                auth.cambiar_password(conn, fila["username"], nueva, actor=g.usuario)
            except ValueError as exc:
                # Historial de contrasenas (2026-09-08): la repetida no se guarda y se
                # explica; antes era un error 500 sin mensaje.
                flash(str(exc), "error")
                return redirect(volver)
            # cambiar_password deja must_change=0 (es el cambio que hace el propio
            # usuario); aqui la escribe un administrador, asi que debe cambiarla el.
            conn.execute("UPDATE users SET must_change=1 WHERE id=?", (usuario_id,))
            detalles.append("contraseña=cambiada por el administrador")
        elif not habilitado or rol != fila["role"]:
            revocadas = auth.revocar_sesiones(conn, fila["username"])
        detalles.append(f"sesiones_revocadas={revocadas}")
        # Nunca la contrasena: solo que se cambio, con el valor anterior y nuevo del resto.
        db.audit(conn, g.usuario, "usuario.actualizar", "users", usuario_id,
                 " ".join(detalles), request.remote_addr)

    mensaje = "; ".join(cambios) if cambios else f"Datos de {quien} guardados"
    mensaje = mensaje[0].upper() + mensaje[1:] + "."
    if nueva:
        mensaje += (f" Contraseña nueva guardada: comuníquela por un canal seguro; "
                    f"{quien} deberá cambiarla en su próximo acceso.")
    if revocadas:
        mensaje += f" Se han cerrado {revocadas} sesión(es) abierta(s) de ese usuario."
    flash(mensaje, "exito")
    return redirect(url_for("usuarios.lista"))


@bp.route("/<int:usuario_id>/password", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def restablecer(usuario_id: int):
    with db.session(current_app.config.get("DB_PATH")) as conn:
        fila = conn.execute("SELECT username FROM users WHERE id=?", (usuario_id,)).fetchone()
        if fila is None:
            flash("El usuario no existe.", "error")
            return redirect(url_for("usuarios.lista"))
        nueva = generar_password()
        auth.cambiar_password(conn, fila["username"], nueva, actor=g.usuario)
        conn.execute("UPDATE users SET must_change=1 WHERE id=?", (usuario_id,))
        db.audit(conn, g.usuario, "usuario.restablecer", "users", usuario_id,
                 f"usuario={fila['username']} contraseña restablecida por el administrador", request.remote_addr)
    _mostrar_una_vez(fila["username"], nueva, "restablecida", None)
    flash(f"Contraseña de {fila['username']} restablecida: se muestra a continuación una sola vez. "
          f"Sus sesiones abiertas se han cerrado.", "exito")
    return redirect(url_for("usuarios.lista"))


@bp.route("/<int:usuario_id>/segundo-factor/restablecer", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def restablecer_segundo_factor(usuario_id: int):
    """Borra el segundo factor de un usuario que perdio el telefono y los codigos.

    Deja la cuenta protegida solo por la contrasena hasta que el usuario lo
    vuelva a activar (o hasta el siguiente acceso si es administrador y el
    segundo factor es obligatorio). Revoca sus sesiones y queda en auditoria."""
    with db.session(current_app.config.get("DB_PATH")) as conn:
        fila = conn.execute("SELECT username FROM users WHERE id=?", (usuario_id,)).fetchone()
        if fila is None:
            flash("El usuario no existe.", "error")
            return redirect(url_for("usuarios.lista"))
        if fila["username"] == g.usuario:
            # Revision de seguridad del 2026-09-05: restablecer el propio segundo factor
            # solo con sesion y CSRF permitiria a quien robe una sesion quitarlo sin
            # conocer la contrasena ni un codigo. El propio se desactiva desde
            # «Cambiar mi contrasena», que exige ambos.
            db.audit(conn, g.usuario, "2fa.restablecer.rechazado", "users", usuario_id,
                     f"usuario={fila['username']} intento de restablecer su propio segundo factor",
                     request.remote_addr)
            flash("No puede restablecer su propio segundo factor desde aquí. Use «Cambiar mi contraseña» → "
                  "Desactivar, que exige su contraseña y un código.", "error")
            return redirect(url_for("usuarios.lista"))
        try:
            revocadas = auth.restablecer_2fa(conn, fila["username"], actor=g.usuario, ip=request.remote_addr)
        except ValueError:
            flash(f"El usuario {fila['username']} no tiene el segundo factor activado.", "info")
            return redirect(url_for("usuarios.lista"))
    flash(f"Segundo factor de {fila['username']} restablecido: podrá entrar solo con la contraseña y deberá "
          f"activarlo de nuevo desde «Cambiar mi contraseña». Se han cerrado {revocadas} sesión(es) abierta(s).", "exito")
    return redirect(url_for("usuarios.lista"))


@bp.route("/<int:usuario_id>/desbloquear", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def desbloquear(usuario_id: int):
    with db.session(current_app.config.get("DB_PATH")) as conn:
        fila = conn.execute("SELECT username FROM users WHERE id=?", (usuario_id,)).fetchone()
        if fila is None:
            flash("El usuario no existe.", "error")
            return redirect(url_for("usuarios.lista"))
        # Tambien los fallos del segundo factor: comparten el bloqueo (revision 2026-09-05).
        conn.execute("UPDATE users SET failed_logins=0, locked_until=NULL, totp_fallos=0 WHERE id=?",
                     (usuario_id,))
        db.audit(conn, g.usuario, "usuario.desbloquear", "users", usuario_id, f"usuario={fila['username']}",
                 request.remote_addr)
    flash(f"Cuenta {fila['username']} desbloqueada.", "exito")
    return redirect(url_for("usuarios.lista"))


@bp.route("/<int:usuario_id>/eliminar", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def eliminar(usuario_id: int):
    with db.session(current_app.config.get("DB_PATH")) as conn:
        fila = conn.execute("SELECT * FROM users WHERE id=?", (usuario_id,)).fetchone()
        if fila is None:
            flash("El usuario no existe.", "error")
            return redirect(url_for("usuarios.lista"))
        if fila["username"] == g.usuario:
            flash("No puede eliminar su propia cuenta.", "error")
            return redirect(url_for("usuarios.lista"))
        if fila["role"] == "admin" and fila["enabled"] and _admins_habilitados(conn, excepto=fila["username"]) == 0:
            flash("Debe quedar al menos un administrador habilitado.", "error")
            return redirect(url_for("usuarios.lista"))
        revocadas = auth.revocar_sesiones(conn, fila["username"])
        conn.execute("DELETE FROM users WHERE id=?", (usuario_id,))
        # El historial de contrasenas se va con la cuenta: son hashes de una persona que ya
        # no esta, y si se recrea el mismo correo no debe heredarlos (revision 2026-09-08).
        conn.execute("DELETE FROM password_historial WHERE username=?", (fila["username"],))
        db.audit(conn, g.usuario, "usuario.eliminar", "users", usuario_id,
                 f"usuario={fila['username']} rol={fila['role']} sesiones_revocadas={revocadas}", request.remote_addr)
    flash(f"Usuario {_identidad(fila)} eliminado.", "info")
    return redirect(url_for("usuarios.lista"))

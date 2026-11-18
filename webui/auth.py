"""Autenticacion y sesiones de la interfaz de administracion.

La interfaz gestiona la contrasena SMTP, asi que no puede quedar abierta en la
LAN. Controles implementados:
  * contrasenas con bcrypt (nunca en claro, nunca reversibles)
  * bloqueo temporal tras N intentos fallidos
  * sesiones firmadas con caducidad
  * token CSRF en todos los formularios de escritura
  * registro en audit_log de quien cambia que
  * segundo factor opcional por aplicacion de codigos (TOTP, RFC 6238) con codigos
    de recuperacion de un solo uso; la sesion queda «pendiente» (web_sessions.
    mfa_pendiente=1) hasta que se verifica el codigo y, mientras, usuario_actual()
    devuelve None para toda la interfaz
  * al superar el segundo factor la sesion recibe un identificador y un token CSRF
    nuevos (renovar_identificador_sesion): la contrasena y el codigo nunca comparten
    identificador, de modo que un identificador fijado antes no hereda el acceso
  * el secreto TOTP pendiente de confirmar vive en el servidor (users.totp_secret
    con users.totp_activado_at NULL), nunca en la cookie
  * cambio de contrasena obligatorio y BLOQUEANTE: con users.must_change=1
    (contrasena inicial o restablecida) requiere_login redirige cualquier ruta a
    /cambiar-contrasena, de modo que la contrasena que escribio el administrador
    no da acceso a nada hasta que su dueno la sustituye
  * la misma comprobacion por peticion lee users.enabled: una cuenta deshabilitada
    mientras estaba dentro pierde la sesion en la peticion siguiente
  * sesion OPACA en servidor (2026-09-08, webui/sesion_servidor.py): la cookie lleva
    solo un token aleatorio; caduca a los «webui_session_minutos» sin actividad (cada
    peticion la renueva), nunca dura mas de «webui_session_maximo_horas» y cada
    «webui_session_rotacion_minutos» de actividad se emite un token nuevo y el
    anterior deja de valer en el acto
  * rotacion de credenciales (2026-09-08): users.password_changed_at y la tabla
    password_historial. Pasados «password_max_dias» dias la cuenta entra en el cambio
    obligatorio; al cambiar se rechaza cualquiera de las ultimas «password_historial»
    contrasenas (y la actual); cinco dias antes de caducar se avisa al entrar
  * las respuestas 403 no dicen que perfil haria falta: «Acceso invalido» a secas
"""
from __future__ import annotations

import functools
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

import bcrypt
from flask import (abort, current_app, flash, g, has_app_context, redirect,
                   request, session, url_for)

from threatintel import db
from webui import sesion_servidor, totp


#: Coste de bcrypt de las contrasenas. Es un nombre de modulo (y no un literal) para
#: que las pruebas que encadenan muchos cambios de contrasena puedan bajarlo; en
#: produccion es siempre 12.
BCRYPT_RONDAS = 12

# Hash bcrypt valido de una contrasena aleatoria, usado SOLO para que el login
# de un usuario inexistente tarde lo mismo que el de uno real (coste 12).
_HASH_FICTICIO = bcrypt.hashpw(b"relleno-para-igualar-tiempos", bcrypt.gensalt(rounds=12)).decode()

#: Valores por defecto de los ajustes de sesion y contrasena (coinciden con
#: threatintel/config.py; aqui se repiten para funcionar sin contexto de aplicacion).
MINUTOS_SESION_DEFECTO = 30
HORAS_SESION_MAXIMO_DEFECTO = 12
MINUTOS_ROTACION_DEFECTO = 15
#: Segundos en que el token anterior a una rotacion periodica sigue sirviendo para LEER la
#: sesion (nunca para escribir). Cubre las peticiones que ya estaban en vuelo al rotar.
SEGUNDOS_GRACIA_ROTACION = 60
PASSWORD_MAX_DIAS_DEFECTO = 30
PASSWORD_HISTORIAL_DEFECTO = 12
#: Desde cuantos dias antes de caducar la contrasena se avisa al entrar.
DIAS_AVISO_PASSWORD = 5

#: Detalle unico de toda respuesta 403 (peticion del usuario del 2026-09-08): no se
#: nombra ningun perfil, para no decirle a quien prueba que perfil necesitaria.
MENSAJE_403 = "No tiene permiso para realizar esta acción."


def ajuste_entero(clave: str, defecto: int, *, cfg=None, conn=None) -> int:
    """Lee un ajuste entero de donde este disponible: la configuracion indicada, la
    de la peticion en curso (g.cfg) o la tabla settings por la conexion dada."""
    valor = None
    if cfg is not None:
        valor = cfg.get(clave)
    elif has_app_context() and getattr(g, "cfg", None) is not None:
        valor = g.cfg.get(clave)
    elif conn is not None:
        valor = db.get_setting(conn, clave, None)
    if valor is None or valor == "":
        return int(defecto)
    try:
        return int(valor)
    except (TypeError, ValueError):
        return int(defecto)


# --------------------------------------------------------------------------
# Contrasenas
# --------------------------------------------------------------------------
def hash_password(password: str) -> str:
    if not password or len(password) < 8:
        raise ValueError("La contraseña debe tener al menos 8 caracteres.")
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_RONDAS)).decode()


def verificar_password(password: str, hash_guardado: str) -> bool:
    if not password or not hash_guardado:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hash_guardado.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def fuerza_password(password: str) -> tuple[bool, str]:
    """Comprueba una politica minima razonable, sin ser hostil."""
    if len(password) < 12:
        return False, "Debe tener al menos 12 caracteres."
    clases = sum([
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    ])
    if clases < 3:
        return False, "Debe combinar al menos tres de: minúsculas, mayúsculas, dígitos y símbolos."
    if password.lower() in {"contrasena123", "password1234", "administrador"}:
        return False, "Es una contraseña demasiado común."
    return True, "Correcta."


# --------------------------------------------------------------------------
# Usuarios
# --------------------------------------------------------------------------
def crear_usuario(conn, username: str, password: str, *, rol: str = "admin",
                  must_change: bool = False, actor: Optional[str] = None,
                  nombre: Optional[str] = None) -> int:
    """Crea la cuenta. ``nombre`` es el de la persona, que la barra superior y el
    perfil muestran en lugar del correo; si no se indica queda vacio y la lista de
    Usuarios invita a completarlo."""
    username = (username or "").strip().lower()
    if not username or len(username) < 3:
        raise ValueError("El nombre de usuario debe tener al menos 3 caracteres.")
    if rol not in ROLES:
        raise ValueError("El rol indicado no es válido.")

    existe = conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone()
    if existe:
        raise ValueError(f"El usuario «{username}» ya existe.")

    ahora = db.utcnow()
    cur = conn.execute(
        """INSERT INTO users(username, password_hash, role, enabled, created_at,
                             failed_logins, must_change, nombre, password_changed_at)
           VALUES(?,?,?,1,?,0,?,?,?)""",
        (username, hash_password(password), rol, ahora, 1 if must_change else 0,
         (nombre or "").strip() or None, ahora),
    )
    db.audit(conn, actor, "usuario.crear", "users", cur.lastrowid,
             f"usuario={username} rol={rol}"
             + (f" nombre={nombre.strip()}" if (nombre or "").strip() else ""))
    return cur.lastrowid


def cambiar_password(conn, username: str, password_nueva: str, *,
                     actor: Optional[str] = None,
                     excepto_sid: Optional[str] = None) -> None:
    """Cambia la contrasena, quita ``must_change`` y revoca las sesiones abiertas.

    ``excepto_sid`` conserva UNA sesion (la del navegador que esta cambiando la
    contrasena). Se usa en el cambio obligatorio del primer acceso: el usuario
    acaba de escribir su contrasena nueva y debe entrar a la plataforma, mientras
    las demas sesiones que hubiera abiertas con la contrasena antigua mueren.
    Sin el parametro se cierran TODAS, que es el comportamiento historico.

    Rotacion de credenciales (2026-09-08): se rechaza una contrasena igual a la
    actual o a cualquiera de las ultimas «password_historial» (12) de la cuenta,
    por TODAS las vias (perfil, cambio obligatorio, administrador, restablecimiento
    y bin/gestionar_usuario.py, que llaman aqui). El hash que se sustituye pasa a
    password_historial (solo bcrypt, nunca la contrasena) y se anota
    users.password_changed_at, que es lo que mide la caducidad de 30 dias."""
    ok, motivo = fuerza_password(password_nueva)
    if not ok:
        raise ValueError(motivo)
    username = username.strip().lower()
    fila = conn.execute("SELECT id, password_hash FROM users WHERE username=?",
                        (username,)).fetchone()
    if fila is None:
        raise ValueError(f"No existe el usuario «{username}».")
    historial = ajuste_entero("password_historial", PASSWORD_HISTORIAL_DEFECTO, conn=conn)
    if password_reutilizada(conn, username, password_nueva, fila["password_hash"], historial):
        if historial > 0:
            raise ValueError(f"No puede reutilizar ninguna de sus últimas {historial} contraseñas.")
        raise ValueError("La contraseña nueva no puede ser igual a la actual.")
    ahora = db.utcnow()
    conn.execute("INSERT INTO password_historial(username, password_hash, cambiado_at) "
                 "VALUES(?,?,?)", (username, fila["password_hash"], ahora))
    # Solo se conservan las ultimas «historial»: lo mas antiguo se borra.
    conn.execute(
        "DELETE FROM password_historial WHERE username=? AND id NOT IN "
        "(SELECT id FROM password_historial WHERE username=? ORDER BY id DESC LIMIT ?)",
        (username, username, max(0, historial)))
    conn.execute(
        "UPDATE users SET password_hash=?, must_change=0, failed_logins=0, "
        "locked_until=NULL, password_changed_at=? WHERE id=?",
        (hash_password(password_nueva), ahora, fila["id"]),
    )
    # Revocar las sesiones abiertas del usuario: si la contrasena se cambia
    # porque se sospecha un compromiso, las sesiones robadas deben morir ya.
    cerradas = revocar_sesiones(conn, username, excepto_sid=excepto_sid)
    db.audit(conn, actor or username, "usuario.password", "users", username,
             f"contrasena actualizada; {cerradas} sesion(es) revocada(s)")


def password_reutilizada(conn, username: str, password_nueva: str,
                         hash_actual: Optional[str], historial: int) -> bool:
    """True si la contrasena coincide con la actual o con alguna de las ultimas
    ``historial`` guardadas. Se comparan TODAS las filas (sin cortar en la primera
    coincidencia) para que el tiempo de respuesta no diga cual coincidio."""
    coincide = verificar_password(password_nueva, hash_actual or "")
    if historial > 0:
        filas = conn.execute(
            "SELECT password_hash FROM password_historial WHERE username=? "
            "ORDER BY id DESC LIMIT ?", ((username or "").strip().lower(), int(historial))).fetchall()
        for fila in filas:
            if verificar_password(password_nueva, fila["password_hash"]):
                coincide = True
    return coincide


def completar_fecha_password(conn) -> int:
    """Migracion suave (2026-09-08): a las cuentas creadas antes de la columna
    users.password_changed_at se les anota la fecha de hoy, para que la caducidad de
    30 dias empiece a contar desde la puesta en marcha y no expulse a todo el mundo
    el primer dia. Devuelve cuantas cuentas se completaron."""
    cur = conn.execute("UPDATE users SET password_changed_at=? WHERE password_changed_at IS NULL",
                       (db.utcnow(),))
    return cur.rowcount or 0


def estado_password(fila_usuario: Optional[dict], *, cfg=None, conn=None,
                    ahora: Optional[datetime] = None) -> dict:
    """Situacion de la contrasena respecto a la politica de caducidad.

    Devuelve ``{"cambiada_at", "max_dias", "dias", "restantes", "caducada", "avisar"}``:
    ``dias`` transcurridos desde el ultimo cambio, ``restantes`` hasta caducar (puede
    ser 0 o negativo), ``caducada`` cuando ya toca cambiarla y ``avisar`` cuando quedan
    DIAS_AVISO_PASSWORD o menos. Con «password_max_dias» a 0 o sin fecha registrada no
    caduca nunca (``restantes`` es None)."""
    max_dias = ajuste_entero("password_max_dias", PASSWORD_MAX_DIAS_DEFECTO, cfg=cfg, conn=conn)
    cambiada = _parse((fila_usuario or {}).get("password_changed_at")) if fila_usuario else None
    estado = {"cambiada_at": (fila_usuario or {}).get("password_changed_at") if fila_usuario else None,
              "max_dias": max_dias, "dias": None, "restantes": None,
              "caducada": False, "avisar": False}
    if max_dias <= 0 or cambiada is None:
        return estado
    ahora = ahora or _ahora()
    dias = max(0, (ahora - cambiada).days)
    restantes = max_dias - dias
    estado.update(dias=dias, restantes=restantes, caducada=restantes <= 0,
                  avisar=0 < restantes <= DIAS_AVISO_PASSWORD)
    return estado


def aviso_password_caducada(max_dias: int) -> str:
    return (f"Su contraseña tiene más de {int(max_dias)} días: por política de seguridad "
            "debe cambiarla ahora.")


def aviso_password_por_caducar(restantes: int) -> str:
    n = int(restantes)
    dias = "1 día" if n == 1 else f"{n} días"
    return (f"Su contraseña caduca en {dias}. Cámbiela desde Mi perfil para no quedarse "
            "sin acceso.")


def _ahora() -> datetime:
    return datetime.now(timezone.utc)


def _parse(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None


def autenticar(conn, username: str, password: str, *, cfg=None,
               ip: Optional[str] = None) -> tuple[bool, str, Optional[dict]]:
    """Devuelve (ok, mensaje, fila_usuario)."""
    username = (username or "").strip().lower()
    max_fallos = int((cfg.get("webui_max_failed_logins") if cfg else 5) or 5)
    minutos = int((cfg.get("webui_lockout_minutes") if cfg else 15) or 15)

    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

    if row is None:
        # Mismo mensaje que con contrasena mala: no revelar si el usuario existe.
        #
        # Y mismo COSTE: sin esto, un usuario inexistente respondia en 0,1 ms y
        # uno existente en 188 ms (bcrypt), un oraculo de 1.700x que permitia
        # enumerar cuentas por tiempo (A07:2025). Verificado el 2026-09-03.
        # Se ejecuta bcrypt contra un hash ficticio para igualar el tiempo.
        verificar_password(password, _HASH_FICTICIO)
        db.audit(conn, None, "login.fallo", "users", username,
                 "usuario inexistente", ip)
        return False, "Usuario o contraseña incorrectos.", None

    if not row["enabled"]:
        db.audit(conn, None, "login.fallo", "users", username,
                 "la cuenta estaba deshabilitada", ip)
        # Mismo mensaje que para una cuenta inexistente: el detalle queda en la auditoria y
        # en el perfil de la propia persona (revision de seguridad del 2026-09-08, A07:2025).
        return False, "Usuario o contraseña incorrectos.", None

    bloqueado_hasta = _parse(row["locked_until"])
    if bloqueado_hasta and bloqueado_hasta > _ahora():
        db.audit(conn, None, "login.fallo", "users", username,
                 "la cuenta estaba bloqueada temporalmente", ip)
        return False, "Usuario o contraseña incorrectos.", None

    if not verificar_password(password, row["password_hash"]):
        fallos = (row["failed_logins"] or 0) + 1
        bloqueo = None
        if fallos >= max_fallos:
            bloqueo = (_ahora() + timedelta(minutes=minutos)).replace(
                microsecond=0).isoformat().replace("+00:00", "Z")
        conn.execute("UPDATE users SET failed_logins=?, locked_until=? WHERE id=?",
                     (fallos, bloqueo, row["id"]))
        # Revision del 2026-09-07: este detalle se muestra ahora a la propia
        # persona en su perfil («Registro de mis accesos»), asi que va en espanol
        # con tildes y sin abreviaturas, como cualquier texto visible.
        db.audit(conn, None, "login.fallo", "users", username,
                 f"contraseña incorrecta (intento {fallos} de {max_fallos})", ip)
        # Tambien al bloquear: decirlo revelaria que la cuenta existe (un correo inexistente
        # nunca se bloquea). El bloqueo consta en la auditoria y en el perfil.
        return False, "Usuario o contraseña incorrectos.", None

    if row["totp_activado_at"]:
        # Revision del 2026-09-05: con segundo factor la contrasena correcta NO es
        # un acceso. last_login_at y «login.ok» se registran en
        # completar_segundo_factor; aqui solo queda constancia del primer paso.
        conn.execute("UPDATE users SET failed_logins=0, locked_until=NULL WHERE id=?",
                     (row["id"],))
        db.audit(conn, username, "login.password_ok", "users", username,
                 "contraseña correcta; pendiente el segundo factor", ip)
        return True, "Falta el segundo factor.", dict(row)

    conn.execute(
        "UPDATE users SET last_login_at=?, failed_logins=0, locked_until=NULL WHERE id=?",
        (db.utcnow(), row["id"]),
    )
    db.audit(conn, username, "login.ok", "users", username, None, ip)
    return True, "Acceso concedido.", dict(row)


# --------------------------------------------------------------------------
# Sesion en servidor
# --------------------------------------------------------------------------
# La cookie de Flask llevaba usuario, rol, token CSRF y hora de inicio, solo
# FIRMADOS (itsdangerous/HMAC): cualquiera que capturase la cookie podia LEER
# todo eso aunque no pudiera modificarlo. Verificado el 2026-09-03.
#
# Desde entonces el estado vive en la tabla web_sessions y, desde el 2026-09-08
# (webui/sesion_servidor.py), la cookie contiene UNICAMENTE un token aleatorio
# opaco de 256 bits: ni siquiera los avisos flash o la contrasena generada que se
# muestra una vez pasan por el navegador (van en web_sessions.datos). Consecuencias:
#   * no hay nada legible en el cliente;
#   * las sesiones se pueden revocar: al cambiar la contrasena se cierran todas;
#   * la caducidad se controla en servidor, no en el propio token:
#       - inactividad: «webui_session_minutos» (30) sin peticiones; cada peticion
#         autenticada la renueva («siempre se pueda renovar»);
#       - tope absoluto: «webui_session_maximo_horas» (12) desde el acceso, para que
#         la renovacion no sea infinita;
#       - rotacion: cada «webui_session_rotacion_minutos» (15) de actividad se emite un
#         token nuevo y el anterior deja de existir en la tabla en ese instante.
# No se usa criptografia asimetrica a proposito: el mismo proceso emite y
# verifica la sesion, de modo que una clave privada estaria en la misma maquina
# que la publica y no anadiria seguridad, solo complejidad.

#: Nombre historico de la clave del identificador. Ya no se guarda en el diccionario
#: de sesion (el token vive en ``session.sid``); se conserva por compatibilidad.
SESION_SID = "sid"
#: Minutos de vida de una sesion con la contrasena correcta pero el segundo factor
#: pendiente (revision del 2026-09-05). Al completar el codigo se amplia al tope
#: absoluto; si no, muere sola y no cuenta como sesion abierta.
MINUTOS_SESION_PENDIENTE_2FA = 10


def caducidad_en(*, horas: int = 0, minutos: int = 0) -> str:
    return ((_ahora() + timedelta(hours=horas, minutes=minutos)).replace(microsecond=0)
            .isoformat().replace("+00:00", "Z"))


_caducidad = caducidad_en


def _hash_sid(sid: str) -> str:
    return sesion_servidor.hash_token(sid)


def _hash_agente() -> str:
    return sesion_servidor.hash_agente()


def _conn():
    """Conexion de la peticion en curso (g.db) o una nueva si no la hay."""
    conexion = getattr(g, "db", None)
    if conexion is not None:
        return conexion, False
    return db.connect(current_app.config.get("DB_PATH")), True


def sid_actual() -> Optional[str]:
    """Token de sesion de la peticion en curso (None sin cookie valida)."""
    return getattr(session, "sid", None) if has_app_context() else None


def motivo_caducidad(fila: dict, *, minutos: Optional[int] = None,
                     ahora: Optional[datetime] = None) -> Optional[str]:
    """Por que una fila de web_sessions ya no vale: «maximo» (paso expires_at, el
    tope absoluto, o los diez minutos de una sesion pendiente del segundo factor),
    «inactividad» (mas de ``minutos`` sin peticiones) o None si sigue viva."""
    ahora = ahora or _ahora()
    expira = _parse(fila.get("expires_at"))
    if expira is None or expira <= ahora:
        return "maximo"
    if fila.get("mfa_pendiente"):
        return None                      # su unico limite son los diez minutos
    if minutos is None:
        minutos = ajuste_entero("webui_session_minutos", MINUTOS_SESION_DEFECTO)
    visto = _parse(fila.get("last_seen_at")) or _parse(fila.get("created_at"))
    if visto is None or visto + timedelta(minutes=int(minutos)) <= ahora:
        return "inactividad"
    return None


def _fila_sesion() -> Optional[dict]:
    """Devuelve la fila de web_sessions de la cookie actual, o None.

    La interfaz de sesion ya la cargo y comprobo al abrir la peticion
    (``session.fila``); se vuelve a la base solo cuando en esta misma peticion se
    cambio el token (acceso, segundo factor, rotacion). Una fila sin usuario es una
    sesion anonima (solo avisos flash) y aqui cuenta como «sin sesion»."""
    cache = getattr(g, "_sesion_fila", None)
    if cache is not None:
        return cache or None
    sid = sid_actual()
    if not sid:
        g._sesion_fila = False
        return None
    fila = getattr(session, "fila", None)
    if fila is None:
        conexion, propia = _conn()
        try:
            fila = conexion.execute(
                "SELECT * FROM web_sessions WHERE sid_hash=?", (_hash_sid(sid),)).fetchone()
        finally:
            if propia:
                conexion.close()
        if fila is None:
            g._sesion_fila = False
            return None
        fila = dict(fila)
        session.fila = fila
    datos = dict(fila)
    if not datos.get("username"):
        g._sesion_fila = False
        return None
    if motivo_caducidad(datos):
        g._sesion_fila = False
        return None
    g._sesion_fila = datos
    return datos


def iniciar_sesion(fila_usuario: dict, *, mfa_pendiente: bool = False) -> None:
    """Crea la sesion en servidor y deja en la cookie solo el token nuevo.

    Con ``mfa_pendiente=True`` la sesion existe (para el token CSRF del formulario
    del segundo factor y para poder cancelarla) pero no da acceso a nada hasta
    que ``completar_segundo_factor`` la confirme, y caduca a los
    MINUTOS_SESION_PENDIENTE_2FA minutos en vez de al tope absoluto."""
    sid = sesion_servidor.nuevo_token()
    if mfa_pendiente:
        expira = caducidad_en(minutos=MINUTOS_SESION_PENDIENTE_2FA)
    else:
        expira = caducidad_en(horas=ajuste_entero("webui_session_maximo_horas",
                                                  HORAS_SESION_MAXIMO_DEFECTO))
    # La direccion real la resuelve ProxyFix cuando la aplicacion esta detras de nginx
    # (ajuste webui_tras_proxy). Leer X-Forwarded-For a mano, como se hacia hasta el
    # 2026-09-08, permitia a cualquier cliente falsear la direccion de la auditoria.
    ip = request.remote_addr if request else None
    ahora = db.utcnow()

    conexion, propia = _conn()
    try:
        # Revision del 2026-09-06 (hallazgo 6): la tabla web_sessions no se limpiaba
        # nunca. Al crear una sesion se borran las ya caducadas: es una sola
        # sentencia sobre una tabla pequena y sucede una vez por acceso.
        limpiar_sesiones_caducadas(conexion)
        # La fila que traia la cookie (anonima con avisos, o muerta) se sustituye:
        # el acceso empieza siempre con un token nuevo (evita fijacion de sesion).
        antiguo = sid_actual()
        if antiguo:
            conexion.execute("DELETE FROM web_sessions WHERE sid_hash=?", (_hash_sid(antiguo),))
        conexion.execute(
            """INSERT INTO web_sessions(sid_hash, username, role, csrf, created_at,
                                        last_seen_at, expires_at, ip, agente_hash,
                                        mfa_pendiente, datos, rotado_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (_hash_sid(sid), fila_usuario["username"], fila_usuario["role"],
             secrets.token_urlsafe(32), ahora, ahora, expira,
             ip, _hash_agente(), 1 if mfa_pendiente else 0, "{}", ahora))
        if propia:
            conexion.commit()
    finally:
        if propia:
            conexion.close()

    session.clear()                     # los datos anonimos no pasan a la sesion nueva
    session.cambiar_token(sid)          # cookie nueva: evita fijacion
    g._sesion_fila = None
    g._sesion_tocada = False


def renovar_identificador_sesion(conn, *, mfa_pendiente: bool = False,
                                 expira: Optional[str] = None,
                                 rotar_csrf: bool = True) -> Optional[str]:
    """Cambia el token de sesion (y, salvo que se pida lo contrario, el token CSRF)
    conservando la fila.

    Revision de seguridad del 2026-09-06 (hallazgo 1): al superar el segundo
    factor se reutilizaba la misma fila de web_sessions, es decir el MISMO
    identificador de sesion y el MISMO token CSRF que se emitieron cuando solo
    se habia comprobado la contrasena. Quien conociera o hubiera fijado ese
    identificador (fijacion de sesion, A07:2025) heredaba la sesion ya completa.

    Aqui se emite un token nuevo, se actualiza la fila con el nuevo ``sid_hash``
    (misma sentencia, misma transaccion: nunca hay dos filas ni un instante sin
    sesion) y se deja el token nuevo en la cookie. El anterior deja de existir en
    la tabla, asi que ya no da acceso.

    ``expira`` sustituye el tope absoluto (el segundo factor lo fija al completarse);
    sin el, se conserva el que tenia: la rotacion periodica NO alarga la sesion.
    ``rotar_csrf=False`` es para la rotacion periodica de cada 15 minutos: cambiar
    tambien el token CSRF invalidaria los formularios abiertos en otra pestana.
    Devuelve el token nuevo, o None si no habia sesion que renovar."""
    antiguo = sid_actual()
    if not antiguo:
        return None
    nuevo = sesion_servidor.nuevo_token()
    ahora = db.utcnow()
    if rotar_csrf:
        # Acceso, segundo factor y cambio obligatorio: el token anterior deja de valer en el
        # acto (fijacion de sesion) y no se conserva ningun periodo de gracia.
        cur = conn.execute(
            "UPDATE web_sessions SET sid_hash=?, csrf=?, mfa_pendiente=?, sid_hash_anterior=NULL, "
            "expires_at=COALESCE(?, expires_at), last_seen_at=?, rotado_at=? WHERE sid_hash=?",
            (_hash_sid(nuevo), secrets.token_urlsafe(32), 1 if mfa_pendiente else 0,
             expira, ahora, ahora, _hash_sid(antiguo)))
    else:
        # Rotacion periodica: el hash anterior se conserva SEGUNDOS_GRACIA_ROTACION para que
        # una peticion concurrente con el token viejo (filtro en vivo, segunda pestana) no
        # expulse al usuario (revision adversaria del 2026-09-08). Con el se puede leer la
        # sesion, no escribir ni renovar (sesion_servidor.open_session, «gracia»).
        cur = conn.execute(
            "UPDATE web_sessions SET sid_hash=?, sid_hash_anterior=?, mfa_pendiente=?, "
            "expires_at=COALESCE(?, expires_at), last_seen_at=?, rotado_at=? WHERE sid_hash=?",
            (_hash_sid(nuevo), _hash_sid(antiguo), 1 if mfa_pendiente else 0, expira, ahora, ahora,
             _hash_sid(antiguo)))
    if not cur.rowcount:
        return None
    session.cambiar_token(nuevo)
    # La fila cacheada de la peticion corresponde al token viejo.
    g._sesion_fila = None
    g._sesion_tocada = False
    return nuevo


def cerrar_sesion(conn=None) -> None:
    """Borra la sesion en servidor y hace que el navegador olvide la cookie.

    ``conn`` permite hacerlo dentro de una transaccion ya abierta (si se usara
    otra conexion mientras esa transaccion escribe, SQLite esperaria el bloqueo)."""
    sid = sid_actual()
    if sid:
        if conn is not None:
            conexion, propia = conn, False
        else:
            conexion, propia = _conn()
        try:
            conexion.execute("DELETE FROM web_sessions WHERE sid_hash=?", (_hash_sid(sid),))
            if propia:
                conexion.commit()
        finally:
            if propia:
                conexion.close()
    if has_app_context() and hasattr(session, "olvidar"):
        session.olvidar()
    else:
        session.clear()
    g._sesion_fila = False


def revocar_sesiones(conn, username: str, *, excepto_sid: Optional[str] = None) -> int:
    """Cierra TODAS las sesiones de un usuario. Se invoca al cambiar la
    contrasena y al deshabilitar la cuenta. Devuelve cuantas se cerraron."""
    if excepto_sid:
        cur = conn.execute("DELETE FROM web_sessions WHERE username=? AND sid_hash<>?",
                           (username.strip().lower(), _hash_sid(excepto_sid)))
    else:
        cur = conn.execute("DELETE FROM web_sessions WHERE username=?",
                           (username.strip().lower(),))
    return cur.rowcount or 0


def dejar_solo_esta_sesion(conn, username: str) -> int:
    """Cierra las demas sesiones del usuario y deja abierta solo la de esta ventana.

    Politica de UNA SOLA sesion por usuario (peticion del usuario del 2026-09-07).
    Se llama cuando el acceso queda COMPLETO (contrasena, y el codigo del segundo
    factor si lo tiene activado), nunca con la contrasena a medias: si se revocara
    ahi, quien robase la contrasena sin tener el codigo podria echar de la plataforma
    al usuario legitimo cuantas veces quisiera, y ademas sabria por el efecto que la
    contrasena es correcta.

    Devuelve cuantas sesiones se cerraron (0 si no habia ninguna otra)."""
    sid = sid_actual()
    if not sid:
        return 0
    cerradas = revocar_sesiones(conn, username, excepto_sid=sid)
    if cerradas:
        detalle = ("acceso desde otro sitio: se cerró la sesión anterior" if cerradas == 1
                   else f"acceso desde otro sitio: se cerraron las {cerradas} sesiones anteriores")
        db.audit(conn, username, "sesion.unica", "users", username, detalle,
                 request.remote_addr if request else None)
    return cerradas


def limpiar_sesiones_caducadas(conn) -> int:
    """Borra las filas que ya no valen: pasado el tope absoluto (expires_at) o, en
    sesiones completas, con mas de «webui_session_minutos» sin actividad."""
    minutos = ajuste_entero("webui_session_minutos", MINUTOS_SESION_DEFECTO, conn=conn)
    limite_inactividad = ((_ahora() - timedelta(minutes=minutos)).replace(microsecond=0)
                          .isoformat().replace("+00:00", "Z"))
    cur = conn.execute(
        "DELETE FROM web_sessions WHERE expires_at <= ? "
        "OR (mfa_pendiente=0 AND last_seen_at <= ?)",
        (db.utcnow(), limite_inactividad))
    return cur.rowcount or 0


def _sesion_completa() -> Optional[dict]:
    """Fila de sesion SOLO si ya se ha superado el segundo factor (o no lo tiene)."""
    fila = _fila_sesion()
    if fila and not fila.get("mfa_pendiente"):
        return fila
    return None


def sesion_pendiente_2fa() -> Optional[dict]:
    """Fila de sesion con la contrasena verificada pero el segundo factor pendiente."""
    fila = _fila_sesion()
    if fila and fila.get("mfa_pendiente"):
        return fila
    return None


def usuario_actual() -> Optional[str]:
    fila = _sesion_completa()
    return fila["username"] if fila else None


def rol_actual() -> Optional[str]:
    fila = _sesion_completa()
    return fila["role"] if fila else None


#: Perfiles de la plataforma y lo que puede hacer cada uno. El alcance esta aqui, en un
#: solo sitio, para poder demostrarlo con una prueba en vez de suponerlo (2026-09-07;
#: segmentacion por tipo de maquina el 2026-09-08; reacoplamiento de roles el 2026-11-16).
#:
#:   admin                  todo: configuracion, fuentes, inventario, usuarios, estado de
#:                          las amenazas, informes, y tambien lo de remediacion.
#:   ciberseguridad         acceso completo a la operacion: consulta todo el parque
#:                          (servidores y equipos de computo), opera las amenazas (cambia su
#:                          estado, evalua un CVE contra un activo) y accede a todos los
#:                          datos de activos e inventario. No administra la plataforma (ni
#:                          fuentes, ni usuarios, ni ajustes, ni informes) y no remedia.
#:   redes                  SOLO servidores: ve sus vulnerabilidades, activos y
#:                          remediaciones y puede comprobar y documentar las suyas. Un
#:                          equipo de computo no existe para este perfil.
#:   mantenimiento          SOLO equipos de computo, simetrico al de redes.
#:
#: El recorte por tipo de maquina (ROL_ORIGEN) lo aplica cada vista EN EL SERVIDOR a
#: partir de alcance_origen(): ni el parametro «origen» de la direccion ni el «proceso»
#: pueden ampliarlo. El menu solo decide que enlaces se ven.
ROLES = ("admin", "ciberseguridad", "redes", "mantenimiento")

ROL_ES = {
    "admin": "Administrador",
    "ciberseguridad": "Ciberseguridad",
    "redes": "Redes",
    "mantenimiento": "Mantenimiento",
}

ROL_ALCANCE_ES = {
    "admin": ("Acceso total: puede consultar y cambiar la configuración, las fuentes, el "
              "inventario, los usuarios, el estado de las amenazas, generar informes y "
              "gestionar remediaciones."),
    "ciberseguridad": ("Acceso completo a la operación: consulta todo el parque (servidores "
                       "y equipos de cómputo), cambia el estado de las amenazas, evalúa un CVE "
                       "contra un activo y accede a todos los datos de activos e inventario. "
                       "No administra la plataforma ni remedia."),
    "redes": ("Solo servidores: consulta sus vulnerabilidades, activos y remediaciones, y "
              "puede pedir la comprobación de una remediación de un servidor y documentarla. "
              "No ve los equipos de cómputo."),
    "mantenimiento": ("Solo equipos de cómputo: consulta sus vulnerabilidades, activos y "
                      "remediaciones, y puede pedir la comprobación de una remediación de un "
                      "equipo de cómputo y documentarla. No ve los servidores."),
}

#: Perfiles que pueden pedir la comprobacion de una remediacion y documentarla (dentro
#: de su alcance por tipo de maquina, que es lo que aplica cada vista).
ROLES_REMEDIACION = ("admin", "redes", "mantenimiento")

#: Perfiles que generan y descargan los informes mensuales (/informes/).
ROLES_INFORMES = ("admin",)

#: Perfiles que operan las amenazas: cambian su estado y evaluan un CVE contra un activo.
ROLES_OPERACION = ("admin", "ciberseguridad")

#: Perfiles que ven el avance de remediacion por tipo de maquina (servidores y equipos de
#: computo por separado): la administracion.
ROLES_AVANCES = ("admin",)

#: Recorte por tipo de maquina de cada perfil: el valor de ``activos.origen`` que puede
#: ver. Los perfiles que no figuran ven los dos tipos.
ROL_ORIGEN = {"redes": "servidores", "mantenimiento": "equipos"}

#: Nombre de cada tipo de maquina en texto corrido; «equipos» a secas no se usa nunca.
ORIGEN_ES = {"servidores": "servidores", "equipos": "equipos de cómputo"}


def es_admin() -> bool:
    return rol_actual() == "admin"


def es_ciberseguridad() -> bool:
    """True si el perfil de la sesion es el de Ciberseguridad (2026-11-16)."""
    return rol_actual() == "ciberseguridad"


def es_redes() -> bool:
    """True si el perfil de la sesion es el de Redes (solo servidores)."""
    return rol_actual() == "redes"


def es_mantenimiento() -> bool:
    """True si el perfil de la sesion es el de Mantenimiento (solo equipos de computo)."""
    return rol_actual() == "mantenimiento"


def puede_remediar() -> bool:
    """True si el perfil puede pedir comprobaciones y documentar remediaciones."""
    return rol_actual() in ROLES_REMEDIACION


def puede_informes() -> bool:
    """True si el perfil puede generar y descargar los informes mensuales."""
    return rol_actual() in ROLES_INFORMES


def puede_operar_amenazas() -> bool:
    """True si el perfil cambia el estado de las amenazas y evalua CVE contra activos."""
    return rol_actual() in ROLES_OPERACION


def ve_avances() -> bool:
    """True si el perfil ve el avance de remediacion por tipo de maquina."""
    return rol_actual() in ROLES_AVANCES


def alcance_origen() -> Optional[str]:
    """Tipo de maquina al que esta acotado el perfil de la sesion.

    «servidores» para Redes, «equipos» para Mantenimiento y None para los demas (ven los
    dos tipos). Es la UNICA fuente del recorte: las vistas lo aplican en el servidor y
    fuerzan este valor por encima de cualquier parametro de la direccion.
    """
    return ROL_ORIGEN.get(rol_actual() or "")


def alcance_es() -> str:
    """El alcance en palabras: «servidores», «equipos de cómputo» o
    «servidores y equipos de cómputo»."""
    origen = alcance_origen()
    if origen:
        return ORIGEN_ES[origen]
    return "servidores y equipos de cómputo"


def origen_efectivo(pedido: Optional[str]) -> Optional[str]:
    """El tipo de maquina que se aplica de verdad a una consulta.

    Con un perfil acotado devuelve SIEMPRE su alcance, se pida lo que se pida en la
    direccion (asi «?origen=equipos» no amplia nada a Redes). Sin recorte devuelve el
    pedido si es un tipo valido, o None.
    """
    propio = alcance_origen()
    if propio:
        return propio
    return pedido if pedido in ORIGEN_ES else None


def dentro_del_alcance(origen_activo: Optional[str]) -> bool:
    """True si un activo de ese tipo es visible para el perfil de la sesion."""
    propio = alcance_origen()
    return propio is None or origen_activo == propio


def exigir_alcance(origen_activo: Optional[str]) -> None:
    """Corta con 404 si el activo esta fuera del alcance del perfil.

    404 y no 403 a proposito: un identificador del otro tipo de maquina no debe revelar
    que existe (la misma respuesta que un identificador inventado).
    """
    if not dentro_del_alcance(origen_activo):
        abort(404)


def filtro_alcance_sql(alias: str = "a") -> tuple[str, list]:
    """Condicion SQL (con « AND » inicial) y parametros que acotan ``activos`` al alcance
    del perfil; vacia si el perfil ve los dos tipos."""
    origen = alcance_origen()
    if not origen:
        return "", []
    return f" AND {alias}.origen = ?", [origen]


def sesion_caducada(horas: int = 0) -> bool:
    """La caducidad se comprueba en servidor en _fila_sesion(); aqui solo se
    informa. Se conserva la firma por compatibilidad."""
    return _fila_sesion() is None


def avisar_caducidad() -> Optional[str]:
    """Si la cookie traia una sesion completa que acaba de morir, encola el aviso
    que vera la pantalla de acceso y devuelve el motivo. Se llama desde
    requiere_login (antes de redirigir) y desde la propia vista de acceso."""
    motivo = getattr(session, "caducidad", None) if has_app_context() else None
    if not motivo:
        return None
    if motivo == "inactividad":
        _avisar_una_vez(
            f"Su sesión caducó por inactividad tras {texto_minutos(session.caducidad_minutos)}. "
            "Vuelva a identificarse.", "aviso")
    else:
        horas = int(getattr(session, "caducidad_horas", 0) or HORAS_SESION_MAXIMO_DEFECTO)
        _avisar_una_vez(
            f"Su sesión alcanzó la duración máxima de {texto_horas(horas)} y se cerró. "
            "Vuelva a identificarse.", "aviso")
    session.caducidad = None
    return motivo


def _tocar_sesion() -> None:
    """Renueva la sesion una vez por peticion autenticada.

    Actualiza last_seen_at (la inactividad se cuenta desde aqui: cada peticion
    «siempre puede renovar» la sesion, hasta el tope absoluto) y, si han pasado
    «webui_session_rotacion_minutos» desde la ultima rotacion, emite un token
    nuevo: el anterior deja de valer en este mismo instante. El token CSRF no
    cambia en la rotacion periodica, para no romper formularios abiertos."""
    sid = sid_actual()
    if not sid or getattr(g, "_sesion_tocada", False):
        return
    fila = _fila_sesion()
    conexion, propia = _conn()
    try:
        rotacion = ajuste_entero("webui_session_rotacion_minutos", MINUTOS_ROTACION_DEFECTO)
        ultima = _parse((fila or {}).get("rotado_at")) or _parse((fila or {}).get("created_at"))
        if (fila and rotacion > 0 and ultima is not None
                and ultima + timedelta(minutes=rotacion) <= _ahora()):
            renovar_identificador_sesion(conexion, mfa_pendiente=False, rotar_csrf=False)
        else:
            conexion.execute("UPDATE web_sessions SET last_seen_at=? WHERE sid_hash=?",
                             (db.utcnow(), _hash_sid(sid)))
        if propia:
            conexion.commit()
    finally:
        if propia:
            conexion.close()
    g._sesion_tocada = True


def texto_horas(horas: int) -> str:
    """«1 hora» / «12 horas»."""
    n = max(1, int(horas or 0))
    return f"{n} hora" if n == 1 else f"{n} horas"


# --------------------------------------------------------------------------
# CSRF
# --------------------------------------------------------------------------
def token_csrf() -> str:
    fila = _fila_sesion()
    return fila["csrf"] if fila else ""


def validar_csrf() -> None:
    enviado = request.form.get("csrf") or request.headers.get("X-CSRF-Token") or ""
    esperado = token_csrf()
    if not esperado or not secrets.compare_digest(enviado, esperado):
        abort(400, "Token CSRF inválido o ausente. Recargue la página.")


# --------------------------------------------------------------------------
# Decoradores
# --------------------------------------------------------------------------
#: Rutas permitidas a un administrador que aun no ha activado el segundo factor
#: obligatorio: la propia activacion, su perfil (donde esta el boton de activar),
#: su contrasena y salir.
ENDPOINTS_SIN_2FA_OBLIGATORIO = frozenset({
    "auth.segundo_factor_activar", "auth.mi_password", "auth.perfil",
    # El cambio de contrasena obligatorio va ANTES que el segundo factor: si esta
    # ruta no estuviera exenta, un administrador con must_change=1 y el segundo
    # factor obligatorio iria de una pantalla a la otra sin poder hacer ninguna.
    "auth.cambiar_contrasena", "auth.logout", "static",
})

#: Rutas permitidas mientras users.must_change vale 1 (contrasena inicial escrita
#: por un administrador, o restablecida): SOLO la pantalla del cambio obligatorio,
#: salir y los ficheros estaticos.
#:
#: «auth.mi_password» figura aqui por compatibilidad con la direccion historica del
#: formulario: su vista reenvia el GET a la pantalla del cambio obligatorio (no
#: muestra ni el menu ni ningun dato) y solo sigue aceptando el POST del formulario
#: antiguo, que exige la contrasena actual. No abre ninguna consulta de la plataforma.
ENDPOINTS_SIN_CAMBIO_OBLIGATORIO = frozenset({
    "auth.cambiar_contrasena", "auth.mi_password", "auth.logout", "static",
})


#: Texto del aviso del cambio obligatorio, compartido con la vista del acceso.
AVISO_CAMBIO_OBLIGATORIO = "Debe cambiar la contraseña antes de continuar."


def _avisar_una_vez(mensaje: str, categoria: str = "aviso") -> None:
    """Encola un aviso solo si no esta ya en la cola de la sesion.

    Revision del 2026-09-07: el navegador pide varias direcciones bloqueadas antes
    de dibujar la pantalla del cambio obligatorio (pestanas abiertas, recursos), y
    cada una encolaba el mismo aviso, asi que la pantalla lo mostraba tres o cuatro
    veces seguidas. Ahora se apila una sola vez."""
    if any(texto == mensaje for _cat, texto in (session.get("_flashes") or [])):
        return
    flash(mensaje, categoria)


def requiere_login(vista: Callable) -> Callable:
    @functools.wraps(vista)
    def envoltorio(*args: Any, **kwargs: Any):
        if sesion_pendiente_2fa():
            # Contrasena correcta pero falta el codigo: nada mas es accesible.
            return redirect(url_for("auth.segundo_factor"))
        if not usuario_actual():
            # Si la sesion acaba de morir por inactividad o por el tope absoluto, la
            # pantalla de acceso lo explica (peticion del usuario del 2026-09-08).
            avisar_caducidad()
            return redirect(url_for("auth.login", siguiente=request.path))
        g.usuario = usuario_actual()
        g.rol = rol_actual()
        # Cuenta deshabilitada mientras estaba dentro (revision del 2026-09-07):
        # las rutas de administracion que deshabilitan ya revocan las sesiones, pero
        # si la columna se cambia directamente en la base la sesion seguia sirviendo
        # para toda la plataforma (A01:2025). Se comprueba en la misma consulta que
        # el cambio obligatorio, asi que no anade ni una lectura.
        if cuenta_deshabilitada():
            cerrar_sesion()
            flash("La cuenta está deshabilitada. Hable con un administrador.", "error")
            return redirect(url_for("auth.login"))
        # Cambio de contrasena obligatorio (fallo grave corregido el 2026-09-07):
        # hasta hoy _tras_acceso redirigia al formulario de contrasena cuando
        # users.must_change valia 1, pero este decorador no lo comprobaba, asi que
        # bastaba escribir otra direccion («/», «/activos/», «/amenazas/») para
        # entrar con la contrasena inicial, que conoce quien creo la cuenta
        # (A07:2025). Mientras must_change valga 1 no se ve nada de la plataforma.
        #
        # Va ANTES del segundo factor obligatorio a proposito: primero la
        # contrasena propia y despues el codigo del segundo factor.
        if (request.endpoint not in ENDPOINTS_SIN_CAMBIO_OBLIGATORIO
                and cambio_password_obligatorio()):
            # Dos motivos: la contrasena inicial (must_change) o una contrasena con
            # mas de «password_max_dias» dias (rotacion de credenciales, 2026-09-08).
            if motivo_cambio_obligatorio() == "caducada":
                _avisar_una_vez(aviso_password_caducada(_estado_cuenta()["password"]["max_dias"]))
            else:
                _avisar_una_vez(AVISO_CAMBIO_OBLIGATORIO)
            return redirect(url_for("auth.cambiar_contrasena"))
        if (request.endpoint not in ENDPOINTS_SIN_2FA_OBLIGATORIO
                and activacion_2fa_obligatoria()):
            flash("Los administradores deben activar el segundo factor de autenticación "
                  "antes de continuar.", "aviso")
            return redirect(url_for("auth.segundo_factor_activar"))
        _tocar_sesion()
        return vista(*args, **kwargs)
    return envoltorio


def requiere_admin(vista: Callable) -> Callable:
    @functools.wraps(vista)
    @requiere_login
    def envoltorio(*args: Any, **kwargs: Any):
        if not es_admin():
            # Sin nombrar el perfil que haria falta (peticion del 2026-09-08).
            abort(403, MENSAJE_403)
        return vista(*args, **kwargs)
    return envoltorio


def requiere_remediacion(vista: Callable) -> Callable:
    """Solo los perfiles de ROLES_REMEDIACION (administración, redes y mantenimiento).

    Cubre exactamente dos acciones: pedir la comprobacion de una remediacion y
    documentarla. El recorte por tipo de maquina de Redes y Mantenimiento lo aplica la
    vista con exigir_alcance() sobre el activo de la remediacion: este decorador solo
    decide si el perfil puede enviar la accion. Cualquier otra ruta que escriba sigue
    exigiendo administrador u operador SOC.
    """
    @functools.wraps(vista)
    @requiere_login
    def envoltorio(*args: Any, **kwargs: Any):
        if not puede_remediar():
            abort(403, MENSAJE_403)
        return vista(*args, **kwargs)
    return envoltorio


def requiere_informes(vista: Callable) -> Callable:
    """Solo administracion y operador SOC: generar y descargar informes (2026-09-08)."""
    @functools.wraps(vista)
    @requiere_login
    def envoltorio(*args: Any, **kwargs: Any):
        if not puede_informes():
            abort(403, MENSAJE_403)
        return vista(*args, **kwargs)
    return envoltorio


def requiere_operacion(vista: Callable) -> Callable:
    """Solo administracion y operador SOC: cambiar el estado de una amenaza y evaluar un
    CVE contra un activo (2026-09-08). Todo lo demas que escribe sigue siendo de
    administrador."""
    @functools.wraps(vista)
    @requiere_login
    def envoltorio(*args: Any, **kwargs: Any):
        if not puede_operar_amenazas():
            abort(403, MENSAJE_403)
        return vista(*args, **kwargs)
    return envoltorio


def requiere_csrf(vista: Callable) -> Callable:
    @functools.wraps(vista)
    def envoltorio(*args: Any, **kwargs: Any):
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            validar_csrf()
        return vista(*args, **kwargs)
    return envoltorio


# --------------------------------------------------------------------------
# Segundo factor (TOTP + codigos de recuperacion)
# --------------------------------------------------------------------------
# Estado por usuario (esquema v6):
#   users.totp_secret        secreto Base32 (en claro: vease webui/totp.py)
#   users.totp_activado_at   fecha de activacion; NULL = sin segundo factor
#   users.totp_recuperacion  JSON {"codigos": [{"hash": bcrypt, "usado_at": ...}],
#                                  "ultimo_paso": int, "generados_at": ...}
#   users.totp_fallos        intentos fallidos del segundo factor (bloqueo)
#   web_sessions.mfa_pendiente  1 mientras falta el codigo
# "ultimo_paso" impide aceptar dos veces el mismo codigo TOTP (un codigo
# capturado por encima del hombro deja de valer en cuanto lo usa el dueno).

CODIGOS_RECUPERACION = 8


def _json_recuperacion(fila: Optional[dict]) -> dict:
    bruto = (fila or {}).get("totp_recuperacion") if fila else None
    if not bruto:
        return {"codigos": [], "ultimo_paso": 0}
    try:
        datos = json.loads(bruto)
    except (TypeError, ValueError):
        return {"codigos": [], "ultimo_paso": 0}
    if not isinstance(datos, dict):
        return {"codigos": [], "ultimo_paso": 0}
    # Revision del 2026-09-05: un JSON con la forma equivocada ({"codigos": 5},
    # {"ultimo_paso": "x"}) debe rechazar el codigo, nunca provocar un error 500.
    if not isinstance(datos.get("codigos"), list):
        datos["codigos"] = []
    datos["codigos"] = [c for c in datos["codigos"] if isinstance(c, dict)]
    try:
        datos["ultimo_paso"] = int(datos.get("ultimo_paso") or 0)
    except (TypeError, ValueError):
        datos["ultimo_paso"] = 0
    return datos


def _guardar_recuperacion(conn, usuario_id: int, datos: dict) -> None:
    conn.execute("UPDATE users SET totp_recuperacion=? WHERE id=?",
                 (json.dumps(datos, ensure_ascii=False), usuario_id))


def estado_2fa(fila: Optional[dict]) -> dict:
    """Resumen para las plantillas: activo, fecha y codigos de recuperacion restantes."""
    if not fila or not fila.get("totp_activado_at"):
        return {"activo": False, "desde": None, "restantes": 0}
    datos = _json_recuperacion(fila)
    restantes = sum(1 for c in datos.get("codigos", [])
                    if isinstance(c, dict) and not c.get("usado_at"))
    return {"activo": True, "desde": fila["totp_activado_at"], "restantes": restantes}


def _fila_usuario(conn, username: str) -> Optional[dict]:
    fila = conn.execute("SELECT * FROM users WHERE username=?",
                        ((username or "").strip().lower(),)).fetchone()
    return dict(fila) if fila else None


def activacion_2fa_obligatoria() -> bool:
    """True si el ajuste «mfa_obligatorio_admin» esta activo, el usuario de la
    sesion es administrador y aun no tiene segundo factor."""
    cache = getattr(g, "_2fa_obligatoria", None)
    if cache is not None:
        return cache
    resultado = False
    fila = _sesion_completa()
    cfg = getattr(g, "cfg", None)
    if fila and fila.get("role") == "admin" and cfg is not None \
            and bool(cfg.get("mfa_obligatorio_admin", False)):
        conexion, propia = _conn()
        try:
            usuario = conexion.execute(
                "SELECT totp_activado_at FROM users WHERE username=?",
                (fila["username"],)).fetchone()
        finally:
            if propia:
                conexion.close()
        resultado = bool(usuario) and not usuario["totp_activado_at"]
    g._2fa_obligatoria = resultado
    return resultado


def _estado_cuenta() -> dict:
    """``{"must_change": bool, "habilitada": bool}`` del usuario de la sesion.

    Se consulta la base en cada peticion (dos columnas, por clave unica) y se
    guarda en ``g`` para no repetirla: el valor tiene que ser el de AHORA, porque
    un administrador puede restablecer la contrasena o deshabilitar la cuenta de
    alguien que ya esta dentro, y esa sesion debe enterarse en la peticion
    siguiente, no en la proxima vez que se identifique.

    Revision del 2026-09-07 (hallazgo bajo del revisor): antes solo se leia
    ``must_change``. Leer tambien ``enabled`` en la MISMA consulta no cuesta nada
    y cierra el caso de una cuenta deshabilitada escribiendo directamente en la
    base (las rutas de administracion ya revocan las sesiones) que seguia
    navegando con la sesion abierta (A01:2025)."""
    cache = getattr(g, "_estado_cuenta", None)
    if cache is not None:
        return cache
    sin_password = estado_password(None)
    estado = {"must_change": False, "habilitada": True, "nombre": "", "password": sin_password}
    fila = _sesion_completa()
    if fila:
        conexion, propia = _conn()
        try:
            usuario = conexion.execute(
                "SELECT must_change, enabled, nombre, password_changed_at, role FROM users "
                "WHERE username=?", (fila["username"],)).fetchone()
            # El perfil de la sesion es una copia de users.role tomada al entrar. Si cambio
            # por fuera de la interfaz (bin/gestionar_usuario.py, sqlite3), la sesion no
            # puede seguir con el perfil viejo: se cierra y la persona vuelve a entrar con
            # el nuevo (revision de seguridad del 2026-09-08, A01:2025).
            if usuario is not None and usuario["role"] != fila.get("role"):
                conexion.execute("DELETE FROM web_sessions WHERE sid_hash=?", (fila["sid_hash"],))
                if propia:
                    conexion.commit()
                usuario = None
        finally:
            if propia:
                conexion.close()
        if usuario is not None:
            estado = {"must_change": bool(usuario["must_change"]),
                      "habilitada": bool(usuario["enabled"]),
                      # El nombre viaja en la MISMA consulta para que la barra superior
                      # pueda mostrarlo sin una segunda lectura por peticion.
                      "nombre": ((usuario["nombre"] or "") if "nombre" in usuario.keys() else "").strip(),
                      # Y la fecha del ultimo cambio de contrasena (caducidad a los 30 dias),
                      # tambien en la misma consulta.
                      "password": estado_password(dict(usuario))}
        else:
            # La cuenta ya no existe: la sesion no vale para nada.
            estado = {"must_change": False, "habilitada": False, "nombre": "",
                      "password": sin_password}
    g._estado_cuenta = estado
    return estado


def olvidar_estado_cuenta() -> None:
    """Descarta el estado cacheado tras cambiarlo (cambio de contrasena propio)."""
    g._estado_cuenta = None


def cambio_password_obligatorio() -> bool:
    """True si el usuario de la sesion tiene ``users.must_change`` a 1 o su contrasena
    ha superado los «password_max_dias» dias (rotacion de credenciales)."""
    return motivo_cambio_obligatorio() is not None


def motivo_cambio_obligatorio() -> Optional[str]:
    """«inicial» (users.must_change=1), «caducada» (mas de «password_max_dias» dias
    desde el ultimo cambio) o None si no hay que cambiar nada. La contrasena inicial
    va primero: es la que conoce quien creo la cuenta."""
    estado = _estado_cuenta()
    if estado["must_change"]:
        return "inicial"
    if estado["password"]["caducada"]:
        return "caducada"
    return None


def cuenta_deshabilitada() -> bool:
    """True si la cuenta del usuario de la sesion ya no esta habilitada."""
    return not _estado_cuenta()["habilitada"]


def nombre_actual() -> Optional[str]:
    """Nombre de la persona de la sesion; si esta vacio, su correo de acceso.

    La barra superior debe decir quien es la persona, no su direccion de correo
    (peticion del usuario del 2026-09-07). Mientras un administrador no rellene
    ``users.nombre`` desde Usuarios se sigue mostrando el correo, que es lo unico
    que se conoce."""
    usuario = usuario_actual()
    if not usuario:
        return None
    return _estado_cuenta().get("nombre") or usuario


def _generar_codigos_recuperacion(datos: dict) -> list[str]:
    codigos = totp.codigos_recuperacion(CODIGOS_RECUPERACION)
    datos["codigos"] = [{"hash": hash_password(c), "usado_at": None} for c in codigos]
    datos["generados_at"] = db.utcnow()
    return codigos


# --------------------------------------------------------------------------
# Activacion pendiente de confirmar (secreto en el servidor, no en la cookie)
# --------------------------------------------------------------------------
# Revision de seguridad del 2026-09-06 (hallazgo 2): el secreto TOTP que el
# usuario acaba de escanear y aun no ha confirmado viajaba en la cookie de
# sesion de Flask. Esa cookie va FIRMADA pero NO cifrada: cualquiera que la
# capture (o la lea del disco del navegador) decodifica el Base64 y obtiene un
# secreto con el que generar codigos validos.
#
# Ahora el secreto pendiente vive en users.totp_secret con users.totp_activado_at
# a NULL, que es el estado «escaneado pero sin confirmar»: no cuenta como segundo
# factor en ningun sitio (estado_2fa, autenticar, requiere_login y
# verificar_codigo_2fa exigen totp_activado_at). En la cookie solo queda la marca
# de tiempo del inicio, para conservar la caducidad de diez minutos.

def secreto_pendiente_2fa(conn, username: str) -> Optional[str]:
    """Secreto escaneado y aun sin confirmar del usuario, o None."""
    fila = conn.execute(
        "SELECT totp_secret FROM users WHERE username=? AND totp_activado_at IS NULL",
        ((username or "").strip().lower(),)).fetchone()
    return fila["totp_secret"] if fila and fila["totp_secret"] else None


def iniciar_activacion_2fa(conn, username: str, *, actor: Optional[str] = None,
                           ip: Optional[str] = None) -> str:
    """Genera un secreto nuevo, lo guarda SIN activar y lo devuelve.

    Sustituye cualquier secreto pendiente anterior (empezar una activacion nueva
    invalida la anterior). Se niega a tocar un segundo factor ya activo."""
    fila = _fila_usuario(conn, username)
    if fila is None:
        raise ValueError(f"No existe el usuario «{username}».")
    if fila.get("totp_activado_at"):
        raise ValueError("El segundo factor ya estaba activado.")
    secreto = totp.generar_secreto()
    conn.execute("UPDATE users SET totp_secret=? WHERE id=? AND totp_activado_at IS NULL",
                 (secreto, fila["id"]))
    db.audit(conn, actor or fila["username"], "2fa.activar.inicio", "users", fila["id"],
             f"usuario={fila['username']} secreto nuevo pendiente de confirmar", ip)
    return secreto


def cancelar_activacion_2fa(conn, username: str) -> bool:
    """Borra el secreto pendiente de confirmar (cancelacion o caducidad).

    Nunca toca un secreto ya confirmado: la condicion exige totp_activado_at NULL."""
    cur = conn.execute(
        "UPDATE users SET totp_secret=NULL WHERE username=? AND totp_activado_at IS NULL "
        "AND totp_secret IS NOT NULL", ((username or "").strip().lower(),))
    return bool(cur.rowcount)


# --------------------------------------------------------------------------
# Contador de fallos del segundo factor (comun al acceso y a /mi-password)
# --------------------------------------------------------------------------
# Revision del 2026-09-06 (hallazgo 3): desactivar el segundo factor y regenerar
# los codigos de recuperacion comprobaban el codigo sin contar los fallos, asi
# que desde una sesion robada se podian probar codigos sin limite. Ahora las tres
# rutas comparten este contador y el mismo bloqueo de cuenta.

def texto_minutos(minutos: int) -> str:
    """«1 minuto» / «15 minutos»: la concordancia importa en un texto visible."""
    n = max(1, int(minutos or 0))
    return f"{n} minuto" if n == 1 else f"{n} minutos"


def anotar_fallo_2fa(conn, fila: dict, *, cfg=None) -> tuple[int, int, bool, int]:
    """Suma un fallo de codigo a users.totp_fallos y bloquea la cuenta al llegar
    al maximo. Devuelve (fallos, maximo, bloqueada, minutos_de_bloqueo)."""
    max_fallos = int((cfg.get("webui_max_failed_logins") if cfg else 5) or 5)
    minutos = int((cfg.get("webui_lockout_minutes") if cfg else 15) or 15)
    fallos = int(fila.get("totp_fallos") or 0) + 1
    bloqueo = None
    if fallos >= max_fallos:
        bloqueo = (_ahora() + timedelta(minutes=minutos)).replace(
            microsecond=0).isoformat().replace("+00:00", "Z")
    conn.execute(
        "UPDATE users SET totp_fallos=?, locked_until=COALESCE(?, locked_until) WHERE id=?",
        (fallos, bloqueo, fila["id"]))
    return fallos, max_fallos, bool(bloqueo), minutos


def reiniciar_fallos_2fa(conn, usuario_id: int) -> None:
    """Un codigo correcto borra el contador de fallos del segundo factor."""
    conn.execute("UPDATE users SET totp_fallos=0 WHERE id=?", (usuario_id,))


def cuenta_bloqueada(fila: Optional[dict]) -> int:
    """Minutos que le quedan de bloqueo a la cuenta (0 si no esta bloqueada)."""
    bloqueado_hasta = _parse((fila or {}).get("locked_until"))
    if bloqueado_hasta and bloqueado_hasta > _ahora():
        return int((bloqueado_hasta - _ahora()).total_seconds() // 60) + 1
    return 0


def activar_2fa(conn, username: str, secreto: str, paso: int, *,
                actor: Optional[str] = None, ip: Optional[str] = None,
                excepto_sid: Optional[str] = None) -> list[str]:
    """Guarda el secreto ya comprobado, genera los codigos de recuperacion y los
    devuelve EN CLARO (se muestran una sola vez). Revoca las demas sesiones."""
    fila = _fila_usuario(conn, username)
    if fila is None:
        raise ValueError(f"No existe el usuario «{username}».")
    if fila.get("totp_activado_at"):
        raise ValueError("El segundo factor ya estaba activado.")
    datos = {"codigos": [], "ultimo_paso": int(paso)}
    codigos = _generar_codigos_recuperacion(datos)
    conn.execute(
        "UPDATE users SET totp_secret=?, totp_activado_at=?, totp_recuperacion=?, "
        "totp_fallos=0 WHERE id=?",
        (secreto, db.utcnow(), json.dumps(datos, ensure_ascii=False), fila["id"]))
    cerradas = revocar_sesiones(conn, username, excepto_sid=excepto_sid)
    db.audit(conn, actor or username, "2fa.activar", "users", fila["id"],
             f"usuario={fila['username']} segundo factor activado; "
             f"{len(codigos)} codigos de recuperacion; {cerradas} sesion(es) revocada(s)", ip)
    return codigos


def regenerar_codigos_2fa(conn, username: str, *, actor: Optional[str] = None,
                          ip: Optional[str] = None) -> list[str]:
    """Sustituye TODOS los codigos de recuperacion (los antiguos dejan de valer)."""
    fila = _fila_usuario(conn, username)
    if fila is None or not fila.get("totp_activado_at"):
        raise ValueError("El segundo factor no está activado.")
    datos = _json_recuperacion(fila)
    codigos = _generar_codigos_recuperacion(datos)
    _guardar_recuperacion(conn, fila["id"], datos)
    db.audit(conn, actor or username, "2fa.codigos", "users", fila["id"],
             f"usuario={fila['username']} codigos de recuperacion regenerados ({len(codigos)})", ip)
    return codigos


def _borrar_2fa(conn, fila: dict) -> None:
    conn.execute(
        "UPDATE users SET totp_secret=NULL, totp_activado_at=NULL, totp_recuperacion=NULL, "
        "totp_fallos=0 WHERE id=?", (fila["id"],))


def desactivar_2fa(conn, username: str, *, actor: Optional[str] = None,
                   ip: Optional[str] = None, excepto_sid: Optional[str] = None) -> int:
    """Quita el segundo factor del propio usuario (ya comprobados contrasena y
    codigo en la vista). Devuelve las sesiones revocadas."""
    fila = _fila_usuario(conn, username)
    if fila is None or not fila.get("totp_activado_at"):
        raise ValueError("El segundo factor no está activado.")
    _borrar_2fa(conn, fila)
    cerradas = revocar_sesiones(conn, username, excepto_sid=excepto_sid)
    db.audit(conn, actor or username, "2fa.desactivar", "users", fila["id"],
             f"usuario={fila['username']} segundo factor desactivado; {cerradas} sesion(es) revocada(s)", ip)
    return cerradas


def restablecer_2fa(conn, username: str, *, actor: Optional[str] = None,
                    ip: Optional[str] = None) -> int:
    """Un administrador (o la consola) borra el segundo factor de otro usuario que
    ha perdido el movil y los codigos. Revoca todas sus sesiones."""
    fila = _fila_usuario(conn, username)
    if fila is None:
        raise ValueError(f"No existe el usuario «{username}».")
    if not fila.get("totp_activado_at"):
        # Sin segundo factor activo pero con un secreto a medio activar: se limpia igual
        # (ese secreto no da acceso, pero no debe quedar colgado). Revision 2026-09-06.
        if not fila.get("totp_secret"):
            raise ValueError(f"El usuario «{fila['username']}» no tiene el segundo factor activado.")
    _borrar_2fa(conn, fila)
    cerradas = revocar_sesiones(conn, username)
    db.audit(conn, actor, "2fa.restablecer", "users", fila["id"],
             f"usuario={fila['username']} segundo factor restablecido por {actor or 'consola'}; "
             f"{cerradas} sesion(es) revocada(s)", ip)
    return cerradas


def verificar_codigo_2fa(conn, fila: dict, codigo: str) -> tuple[bool, str]:
    """Comprueba un codigo TOTP (sin repetir paso) o un codigo de recuperacion no
    usado; si acierta, actualiza el JSON (ultimo_paso o usado_at) y devuelve
    (True, "totp"|"recuperacion"). No audita ni toca contadores: eso lo hace el
    llamador segun el contexto (acceso, desactivacion).

    Revision del 2026-09-06 (hallazgo 2): un secreto con ``totp_activado_at``
    NULL es un secreto que el usuario todavia no ha confirmado; NO vale como
    segundo factor y aqui se rechaza expresamente."""
    if not fila or not fila.get("totp_secret") or not fila.get("totp_activado_at"):
        return False, ""
    datos = _json_recuperacion(fila)
    paso = totp.paso_valido(fila["totp_secret"], codigo, ventana=1)
    if paso is not None:
        if paso <= int(datos.get("ultimo_paso") or 0):
            return False, "repetido"
        datos["ultimo_paso"] = paso
        _guardar_recuperacion(conn, fila["id"], datos)
        return True, "totp"
    recuperacion = totp.normalizar_recuperacion(codigo)
    if recuperacion:
        acierto = None
        # Se comparan todos los codigos para no revelar por tiempo cual coincide.
        for indice, entrada in enumerate(datos.get("codigos", [])):
            if not isinstance(entrada, dict) or entrada.get("usado_at"):
                continue
            if verificar_password(recuperacion, entrada.get("hash", "")) and acierto is None:
                acierto = indice
        if acierto is not None:
            datos["codigos"][acierto]["usado_at"] = db.utcnow()
            _guardar_recuperacion(conn, fila["id"], datos)
            return True, "recuperacion"
    return False, ""


def completar_segundo_factor(conn, codigo: str, *, cfg=None,
                             ip: Optional[str] = None) -> tuple[bool, str, bool]:
    """Segundo paso del acceso. Devuelve (ok, mensaje, bloqueado).

    Con exito: la sesion recibe un identificador y un token CSRF nuevos (deja de
    estar pendiente, con la caducidad completa) y se reinicia totp_fallos. Con
    fallo: totp_fallos+1 y, al llegar al maximo, la cuenta se bloquea el mismo
    tiempo que por contrasena y la sesion pendiente se cierra."""
    sesion = sesion_pendiente_2fa()
    if sesion is None:
        return False, "No hay ningún acceso pendiente de segundo factor.", False
    fila = _fila_usuario(conn, sesion["username"])
    if fila is None or not fila.get("enabled"):
        cerrar_sesion(conn)
        return False, "La cuenta no está disponible.", True
    restante = cuenta_bloqueada(fila)
    if restante:
        cerrar_sesion(conn)
        return False, (f"Cuenta bloqueada temporalmente. Vuelva a intentarlo en "
                       f"{texto_minutos(restante)}."), True

    ok, modo = verificar_codigo_2fa(conn, fila, codigo)
    if ok:
        horas = ajuste_entero("webui_session_maximo_horas", HORAS_SESION_MAXIMO_DEFECTO)
        # Identificador de sesion y token CSRF NUEVOS (hallazgo 1 del 2026-09-06):
        # los que se emitieron con la contrasena dejan de existir en este momento.
        # El tope absoluto de la sesion empieza a contar aqui, con el acceso completo.
        renovar_identificador_sesion(conn, mfa_pendiente=False,
                                     expira=caducidad_en(horas=horas))
        # El acceso se completa AHORA: ultimo acceso y «login.ok» (revision 2026-09-05).
        conn.execute("UPDATE users SET totp_fallos=0, last_login_at=? WHERE id=?",
                     (db.utcnow(), fila["id"]))
        restantes = estado_2fa({**fila, "totp_recuperacion": conn.execute(
            "SELECT totp_recuperacion FROM users WHERE id=?", (fila["id"],)).fetchone()[0]})["restantes"]
        detalle = "código de la aplicación" if modo == "totp" else             f"código de recuperación (quedan {restantes})"
        db.audit(conn, fila["username"], "login.2fa.ok", "users", fila["username"], detalle, ip)
        db.audit(conn, fila["username"], "login.ok", "users", fila["username"],
                 "acceso completado con segundo factor", ip)
        g._sesion_fila = None
        mensaje = "Acceso concedido."
        if modo == "recuperacion":
            mensaje = (f"Acceso con un código de recuperación; le quedan {restantes}. "
                       "Si ya no tiene la aplicación, desactive y vuelva a activar el segundo factor.")
        return True, mensaje, False

    fallos, max_fallos, bloqueo, minutos = anotar_fallo_2fa(conn, fila, cfg=cfg)
    motivo = "código repetido" if modo == "repetido" else "código incorrecto"
    db.audit(conn, None, "login.2fa.fallo", "users", fila["username"],
             f"{motivo} (intento {fallos}/{max_fallos})", ip)
    if bloqueo:
        cerrar_sesion(conn)
        return False, f"Demasiados intentos. La cuenta queda bloqueada {texto_minutos(minutos)}.", True
    return False, "El código no es válido. Compruebe la hora del dispositivo e inténtelo de nuevo.", False


# --------------------------------------------------------------------------
# Clave de firma de sesion
# --------------------------------------------------------------------------
def obtener_secret_key(conn) -> str:
    """Persiste la clave de firma para que las sesiones sobrevivan a un reinicio."""
    clave = db.get_setting(conn, "webui_secret_key")
    if not clave:
        clave = secrets.token_hex(32)
        db.set_setting(conn, "webui_secret_key", clave)
    return clave

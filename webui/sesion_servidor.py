"""Sesion opaca en servidor: la cookie solo lleva un token aleatorio (2026-09-08).

Hasta hoy la interfaz usaba la cookie firmada de Flask como transporte: iba
FIRMADA (itsdangerous, HMAC) pero NO cifrada, asi que cualquiera que la capturase
podia decodificar el Base64 y leer su contenido ({"sid": ..., "_flashes": [...],
"credencial_una_vez": {...}}). El identificador de sesion ya era opaco y el estado
de la sesion ya vivia en web_sessions, pero los avisos flash, el destino tras el
segundo factor y la contrasena generada que se muestra una sola vez viajaban en
claro dentro de la cookie. Peticion del usuario: «El valor de las cookies debe
estar ofuscado y no exponer informacion».

Ahora la cookie «session» contiene UNICAMENTE un token de 32 bytes aleatorios
(secrets.token_urlsafe: 256 bits, 43 caracteres), sin firma porque no hay nada
que firmar: no codifica ningun dato. Todo lo demas se guarda en la fila de
web_sessions cuyo ``sid_hash`` es el SHA-256 del token (leer la tabla no da
tokens utilizables); los datos de la sesion (flash, destino, credencial de un solo
uso) van en la columna JSON ``web_sessions.datos``.

Atributos de la cookie:
  * ``Secure`` segun el ajuste «webui_https» (SESSION_COOKIE_SECURE);
  * ``HttpOnly`` siempre: el JavaScript de la pagina no puede leerla;
  * ``SameSite=Lax`` y no ``Strict``: los correos de alerta llevan enlaces a la
    plataforma y, con Strict, el navegador NO enviaria la cookie al llegar desde el
    cliente de correo, asi que cada enlace obligaria a identificarse otra vez. Lax
    envia la cookie en navegaciones de primer nivel (pulsar un enlace) pero no en
    peticiones POST ni en subrecursos desde otro sitio, que es lo que protege del
    CSRF; ademas todo formulario lleva su token CSRF propio;
  * ``Path=/`` y sin ``Domain``: la cookie es solo de este nombre de servidor;
  * sin ``Max-Age``: cookie de navegador (muere al cerrarlo). La duracion real la
    decide el servidor (inactividad, tope absoluto y rotacion: webui/auth.py).

Ciclo de vida (webui/auth.py decide, este modulo transporta):
  * al abrir la peticion se busca la fila del token; si no existe o caduco, la
    sesion empieza vacia y, si caduco por inactividad o por el tope absoluto, se
    deja anotado el motivo para que la pantalla de acceso lo explique;
  * una sesion anonima (sin usuario) solo se escribe en la base cuando tiene algo
    que guardar (un aviso flash pendiente); los intentos de acceso fallidos, que
    muestran el aviso en la misma respuesta, no crean ninguna fila;
  * ``iniciar_sesion`` y ``renovar_identificador_sesion`` cambian el token: la
    cookie se reemite y el token anterior deja de existir en la tabla.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
import re
import secrets
from typing import Any, Optional

from flask import g, has_app_context, request
from flask.json.tag import TaggedJSONSerializer
from flask.sessions import SessionInterface, SessionMixin
from werkzeug.datastructures import CallbackDict

from threatintel import db

#: Nombre de la cookie. Se conserva «session» (el historico) porque no revela nada
#: distinto de lo que ya dice la propia aplicacion y hay pruebas que lo esperan.
NOMBRE_COOKIE = "session"
#: Bytes aleatorios del token (256 bits). token_urlsafe(32) produce 43 caracteres.
BYTES_TOKEN = 32
_RE_TOKEN = re.compile(r"^[A-Za-z0-9_-]{43}$")

#: Serializador de Flask: conserva tuplas (los avisos flash son pares), fechas y
#: bytes al pasar por JSON, igual que hacia la cookie firmada.
_serializador = TaggedJSONSerializer()


def nuevo_token() -> str:
    return secrets.token_urlsafe(BYTES_TOKEN)


def hash_token(token: str) -> str:
    """SHA-256 en hexadecimal: es lo que se guarda en web_sessions.sid_hash."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def token_valido(token: Optional[str]) -> bool:
    """Forma exacta de un token emitido aqui; cualquier otra cosa (una cookie
    firmada antigua, basura) se descarta sin consultar la base."""
    return bool(token) and bool(_RE_TOKEN.match(token))


def hash_agente() -> str:
    agente = request.headers.get("User-Agent", "") if request else ""
    return hashlib.sha256(agente.encode("utf-8", "replace")).hexdigest()[:32]


class SesionServidor(CallbackDict, SessionMixin):
    """Diccionario de sesion cuyo contenido vive en web_sessions.datos.

    ``sid`` es el token en claro (solo en memoria, nunca en la base); ``fila`` la
    fila de web_sessions cargada al abrir la peticion, que webui.auth reutiliza
    para no repetir la consulta. Los atributos ``caducidad`` y
    ``caducidad_minutos`` explican por que murio la sesion que traia la cookie
    (para el aviso «Su sesion caduco por inactividad tras 30 minutos»)."""

    def __init__(self, datos: Optional[dict] = None, *, sid: Optional[str] = None,
                 fila: Optional[dict] = None):
        def al_cambiar(_self):
            self.modified = True
        super().__init__(datos or {}, al_cambiar)
        self.sid: Optional[str] = sid
        self.fila: Optional[dict] = fila
        self.modified = False
        self.sid_nuevo = False          # hay que reemitir la cookie
        self.borrar_cookie = False      # el navegador traia un token que ya no vale
        self.caducidad: Optional[str] = None       # "inactividad" | "maximo" | None
        self.caducidad_minutos = 0
        self.caducidad_horas = 0
        self.gracia = False             # token anterior a una rotacion, dentro del periodo
        #                                 de gracia: la sesion se lee, no se escribe

    # SessionMixin.permanent escribe «_permanent» en el diccionario; aqui la
    # duracion la decide el servidor y no se quiere ese dato en la base.
    @property
    def permanent(self) -> bool:  # type: ignore[override]
        return False

    @permanent.setter
    def permanent(self, value: bool) -> None:  # type: ignore[override]
        return None

    def cambiar_token(self, token: str) -> None:
        """Adopta un token nuevo (acceso, segundo factor, rotacion): la cookie se
        reemite y la fila cacheada deja de valer."""
        self.sid = token
        self.sid_nuevo = True
        self.fila = None
        self.borrar_cookie = False

    def olvidar(self) -> None:
        """Cierre de sesion: sin token, sin datos y cookie borrada en el navegador."""
        self.sid = None
        self.fila = None
        self.sid_nuevo = False
        self.borrar_cookie = True
        dict.clear(self)
        self.modified = True


class InterfazSesionServidor(SessionInterface):
    """SessionInterface de Flask con el estado en web_sessions."""

    def __init__(self, db_path=None):
        self.db_path = db_path

    # ------------------------------------------------------------------ util
    def _conexion(self):
        """Conexion de la peticion en curso (g.db) o una propia, que hay que cerrar."""
        conexion = getattr(g, "db", None) if has_app_context() else None
        if conexion is not None:
            return conexion, False
        return db.connect(self.db_path), True

    @staticmethod
    def _cargar_datos(bruto: Optional[str]) -> dict:
        if not bruto:
            return {}
        try:
            datos = _serializador.loads(bruto)
        except (ValueError, TypeError):
            return {}
        return datos if isinstance(datos, dict) else {}

    @staticmethod
    def _volcar_datos(sesion: dict) -> str:
        return _serializador.dumps(dict(sesion))

    # ------------------------------------------------------------- abrir
    def open_session(self, app, request_):  # noqa: D401 - firma de Flask
        from webui import auth  # aqui para evitar la importacion circular

        token = request_.cookies.get(NOMBRE_COOKIE)
        if not token:
            return SesionServidor()
        if not token_valido(token):
            sesion = SesionServidor()
            sesion.borrar_cookie = True
            return sesion

        conexion = db.connect(self.db_path)
        try:
            fila = conexion.execute("SELECT * FROM web_sessions WHERE sid_hash=?",
                                    (hash_token(token),)).fetchone()
            gracia = False
            if fila is None:
                # ¿Es el token anterior a una rotacion periodica reciente? Una peticion que
                # ya estaba en vuelo al rotar (filtro en vivo, segunda pestana) llega con
                # el viejo: se atiende con la misma fila, en solo lectura, durante
                # SEGUNDOS_GRACIA_ROTACION. Fuera de ese plazo, o para un token desconocido,
                # NO se pide borrar la cookie: la respuesta tardia de una peticion vieja no
                # puede pisar la cookie nueva que el navegador acaba de recibir (revision
                # adversaria del 2026-09-08).
                limite = (datetime.now(timezone.utc)
                          - timedelta(seconds=auth.SEGUNDOS_GRACIA_ROTACION)
                          ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
                fila = conexion.execute(
                    "SELECT * FROM web_sessions WHERE sid_hash_anterior=? AND rotado_at >= ?",
                    (hash_token(token), limite)).fetchone()
                if fila is None:
                    return SesionServidor()
                gracia = True
            fila = dict(fila)
            minutos = auth.ajuste_entero("webui_session_minutos", auth.MINUTOS_SESION_DEFECTO,
                                         conn=conexion)
            motivo = auth.motivo_caducidad(fila, minutos=minutos)
            if motivo:
                # La fila muerta se borra ya (no esperar a la limpieza del siguiente acceso)
                conexion.execute("DELETE FROM web_sessions WHERE sid_hash=?", (fila["sid_hash"],))
                sesion = SesionServidor()
                sesion.borrar_cookie = True
                if fila.get("username") and not fila.get("mfa_pendiente"):
                    # Solo una sesion completa merece explicacion; la anonima o la
                    # pendiente del segundo factor vuelven al acceso sin mas.
                    sesion.caducidad = motivo
                    sesion.caducidad_minutos = minutos
                    sesion.caducidad_horas = auth.ajuste_entero(
                        "webui_session_maximo_horas", auth.HORAS_SESION_MAXIMO_DEFECTO,
                        conn=conexion)
                return sesion
        finally:
            conexion.close()
        sesion = SesionServidor(self._cargar_datos(fila.get("datos")), sid=token, fila=fila)
        sesion.gracia = gracia
        return sesion

    # ----------------------------------------------------------- guardar
    def save_session(self, app, session, response):  # noqa: D401 - firma de Flask
        sesion: SesionServidor = session  # type: ignore[assignment]
        seguro = bool(app.config.get("SESSION_COOKIE_SECURE"))

        if getattr(sesion, "gracia", False):
            # Peticion atendida con el token anterior a una rotacion: no se escribe nada ni se
            # toca la cookie (la buena ya esta en el navegador). Los avisos que hubiera
            # encolado esta peticion se pierden; es el precio de no expulsar a nadie.
            return

        if sesion.sid is None:
            if not len(sesion):
                # Nada que guardar. Si el navegador traia un token muerto, se le
                # pide que lo olvide para no consultarlo en cada peticion.
                if sesion.borrar_cookie:
                    response.delete_cookie(NOMBRE_COOKIE, path="/", secure=seguro,
                                           httponly=True, samesite="Lax")
                return
            # Sesion anonima con datos (un aviso flash pendiente): fila sin usuario
            token = nuevo_token()
            self._insertar_anonima(token, sesion)
            sesion.sid = token
            sesion.sid_nuevo = True
            sesion.borrar_cookie = False

        elif sesion.modified:
            conexion, propia = self._conexion()
            try:
                cur = conexion.execute("UPDATE web_sessions SET datos=? WHERE sid_hash=?",
                                       (self._volcar_datos(sesion), hash_token(sesion.sid)))
                if propia:
                    conexion.commit()
            finally:
                if propia:
                    conexion.close()
            if not cur.rowcount:
                # La fila murio durante esta misma peticion (por ejemplo, cambiar la
                # contrasena revoca TODAS las sesiones, incluida esta, y despues encola
                # «Contraseña actualizada.»). Sin esto el aviso se perdia y el navegador
                # se quedaba con un token muerto: los datos pendientes pasan a una sesion
                # anonima nueva, con su cookie nueva, y la pantalla de acceso los muestra.
                if len(sesion):
                    token = nuevo_token()
                    self._insertar_anonima(token, sesion)
                    sesion.sid = token
                    sesion.sid_nuevo = True
                else:
                    sesion.sid = None
                    response.delete_cookie(NOMBRE_COOKIE, path="/", secure=seguro,
                                           httponly=True, samesite="Lax")
                    return

        if sesion.sid_nuevo:
            response.set_cookie(
                NOMBRE_COOKIE, sesion.sid,
                max_age=None, expires=None, path="/", domain=None,
                secure=seguro, httponly=True, samesite="Lax",
            )
            response.vary.add("Cookie")
            sesion.sid_nuevo = False

    def _insertar_anonima(self, token: str, sesion: SesionServidor) -> None:
        from webui import auth

        conexion, propia = self._conexion()
        try:
            minutos = auth.ajuste_entero("webui_session_minutos", auth.MINUTOS_SESION_DEFECTO,
                                         conn=conexion)
            ahora = db.utcnow()
            conexion.execute(
                """INSERT INTO web_sessions(sid_hash, username, role, csrf, created_at,
                                            last_seen_at, expires_at, ip, agente_hash,
                                            mfa_pendiente, datos, rotado_at)
                   VALUES(?,?,?,?,?,?,?,?,?,0,?,?)""",
                (hash_token(token), "", "", nuevo_token(), ahora, ahora,
                 auth.caducidad_en(minutos=minutos),
                 request.remote_addr if request else None, hash_agente(),
                 self._volcar_datos(sesion), ahora))
            if propia:
                conexion.commit()
        finally:
            if propia:
                conexion.close()


def datos_de_sesion(conn, token: str) -> dict:
    """Datos guardados en el servidor para un token (uso en pruebas y diagnostico)."""
    fila = conn.execute("SELECT datos FROM web_sessions WHERE sid_hash=?",
                        (hash_token(token),)).fetchone()
    if fila is None:
        return {}
    datos: Any = InterfazSesionServidor._cargar_datos(fila["datos"])
    return datos

"""Fabrica de la aplicacion Flask de administracion.

Interfaz interna de consulta y gestion. Cubre lo que el sistema anterior obligaba
a hacer editando codigo o ficheros a mano:
  * validar el estado de las fuentes de consulta y probarlas en vivo
  * rotar la contrasena SMTP (cambia cada mes) y verificarla
  * mantener el inventario tecnologico CON versiones, para afinar los hallazgos
  * consultar el historico de amenazas
  * revisar la salud del sistema y las ejecuciones
"""
from __future__ import annotations

from pathlib import Path

import os
from typing import Any, Optional

from flask import Flask, g, jsonify, render_template, request

from threatintel import config, db
from threatintel.logging_setup import get_logger, setup

from . import auth, sesion_servidor
from .filtros import registrar_filtros

log = get_logger("webui")


def crear_app(*, db_path: Optional[str] = None, testing: bool = False) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")

    db.init_db(db_path)

    with db.session(db_path) as conn:
        config.seed_settings(conn)
        secret = auth.obtener_secret_key(conn)
        # Rotacion de credenciales (2026-09-08): las cuentas anteriores a la columna
        # password_changed_at reciben la fecha de hoy, para que los 30 dias empiecen
        # a contar desde la puesta en marcha y no se expulse a nadie el primer dia.
        auth.completar_fecha_password(conn)
        cfg = config.load(conn)

    app.config.update(
        SECRET_KEY=secret,
        DB_PATH=db_path,
        # Sesion (2026-09-08): inactividad, tope absoluto y rotacion del token. Los valores
        # vigentes se leen de los ajustes en cada peticion (g.cfg); estos son los de
        # arranque, de referencia. «webui_session_hours» ya no se lee: si sigue en la
        # tabla settings, se ignora.
        SESSION_MINUTOS=auth.ajuste_entero("webui_session_minutos", auth.MINUTOS_SESION_DEFECTO, cfg=cfg),
        SESSION_MAXIMO_HORAS=auth.ajuste_entero("webui_session_maximo_horas",
                                                auth.HORAS_SESION_MAXIMO_DEFECTO, cfg=cfg),
        SESSION_ROTACION_MINUTOS=auth.ajuste_entero("webui_session_rotacion_minutos",
                                                    auth.MINUTOS_ROTACION_DEFECTO, cfg=cfg),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=bool(cfg.get("webui_https")),
        PREFERRED_URL_SCHEME="https" if cfg.get("webui_https") else "http",
        MAX_CONTENT_LENGTH=41 * 1024 * 1024,   # SBOM y resultados OpenSCAP (ARF) de hasta 40 MB
        TESTING=testing,
        JSON_SORT_KEYS=False,
    )

    # Detras de un proxy inverso (nginx en el 443, desde el 2026-09-08) la direccion del
    # cliente llega en X-Forwarded-For y el esquema en X-Forwarded-Proto. Se confia en UN
    # solo salto y solo si el ajuste lo dice: sin proxy, cualquiera podria enviar esas
    # cabeceras y falsear la direccion que queda en la auditoria. Con el ajuste puesto la
    # aplicacion debe escuchar SOLO en 127.0.0.1, para que nadie salvo nginx la alcance.
    if cfg.get("webui_tras_proxy"):
        from werkzeug.middleware.proxy_fix import ProxyFix
        # Solo direccion y esquema: el Host lo fija nginx en la propia cabecera Host (y solo
        # admite los dos nombres conocidos), asi que no hace falta confiar en
        # X-Forwarded-Host ni X-Forwarded-Port, que serian una via de inyeccion de Host si
        # alguna vista generara direcciones absolutas (revision adversaria del 2026-09-08).
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=0, x_port=0)  # type: ignore[method-assign]

    # La cookie «session» lleva solo un token aleatorio; todo el estado (incluidos los
    # avisos flash) vive en web_sessions. SameSite=Lax y no Strict porque los enlaces de
    # los correos de alerta deben abrir la plataforma con la sesion (webui/sesion_servidor.py).
    app.session_interface = sesion_servidor.InterfazSesionServidor(db_path)

    registrar_filtros(app)

    # ------------------------------------------------------------------
    # Contexto por peticion
    # ------------------------------------------------------------------
    @app.before_request
    def _abrir_conexion() -> None:
        g.db = db.connect(app.config.get("DB_PATH"))
        g.cfg = config.load(g.db)  # misma conexion: los ajustes salen de esta BD

    @app.teardown_request
    def _cerrar_conexion(exc: Optional[BaseException]) -> None:
        conexion = g.pop("db", None)
        if conexion is not None:
            try:
                if exc is None:
                    conexion.execute("COMMIT")
            except Exception:
                pass
            conexion.close()

    @app.url_defaults
    def _version_estaticos(endpoint: str, values: dict) -> None:
        """Añade ?v=<mtime> a los estáticos: al cambiar la hoja de estilos o el
        JavaScript, el navegador pide la versión nueva en vez de servir la
        antigua desde su caché."""
        if endpoint == "static" and "filename" in values:
            try:
                ruta = Path(app.static_folder) / values["filename"]
                values["v"] = int(ruta.stat().st_mtime)
            except OSError:
                pass

    def _estado_tour() -> str:
        usuario = auth.usuario_actual()
        if not usuario:
            return ""
        cache = getattr(g, "_tour_estado", None)
        if cache is not None:
            return cache
        estado = "pendiente"
        try:
            fila = g.db.execute("SELECT tour_estado FROM users WHERE username=?", (usuario,)).fetchone()
            if fila and fila["tour_estado"]:
                estado = str(fila["tour_estado"])
        except Exception:  # noqa: BLE001 - sin base o sin columna: no se invita
            estado = ""
        g._tour_estado = estado
        return estado

    @app.context_processor
    def _variables_plantilla() -> dict[str, Any]:
        cfg = getattr(g, "cfg", {})
        empresa = (cfg.get("empresa_nombre") or "").strip() or "Mi Organización"
        try:
            tiene_logo = g.db.execute("SELECT 1 FROM marca WHERE id=1").fetchone() is not None
        except Exception:  # noqa: BLE001 - base sin la tabla todavia (antes de migrar)
            tiene_logo = False
        return {
            "usuario": auth.usuario_actual(),
            # El nombre de la persona para la barra superior; si no esta relleno,
            # nombre_actual() devuelve el correo de acceso.
            "usuario_nombre": auth.nombre_actual(),
            "rol": auth.rol_actual(),
            "rol_es": auth.ROL_ES.get(auth.rol_actual() or "", ""),
            "rol_alcance_es": auth.ROL_ALCANCE_ES.get(auth.rol_actual() or "", ""),
            "es_admin": auth.es_admin(),
            # Perfiles segmentados (2026-11-16): el menu y las plantillas solo ensenan lo
            # que el perfil puede usar; el recorte real lo aplica cada vista en el servidor.
            "es_ciberseguridad": auth.es_ciberseguridad(),
            "puede_informes": auth.puede_informes(),
            "puede_remediar": auth.puede_remediar(),
            "puede_operar_amenazas": auth.puede_operar_amenazas(),
            "ve_avances": auth.ve_avances(),
            "alcance_origen": auth.alcance_origen(),
            "alcance_es": auth.alcance_es(),
            "csrf": auth.token_csrf() if auth.usuario_actual() else "",
            "nombre_app": "Inteligencia de Amenazas",
            "empresa": empresa,
            "tiene_logo": tiene_logo,
            # Recorrido guiado completo: «pendiente» solo si el usuario nunca respondio a la
            # invitacion (se guarda en la base, asi que no se repite en cada acceso ni por navegador).
            "tour_estado": _estado_tour(),
        }

    @app.after_request
    def _cabeceras_seguridad(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        # A02/A04:2025: las paginas autenticadas contienen datos internos y no
        # deben quedar en caches de navegador ni de proxy. Flask 3.1.3 ya anade
        # Vary: Cookie; esto lo hace explicito para toda respuesta con sesion.
        if auth.usuario_actual():
            resp.headers["Cache-Control"] = "no-store, private"
            resp.headers["Pragma"] = "no-cache"
        # CSP estricta, sin 'unsafe-inline' en ningun directorio (A02:2025).
        # Todo el JavaScript vive en static/app.js (comportamiento por atributos
        # data-*) y todo el estilo en static/estilo.css (clases de utilidad en
        # lugar de style=""). Un XSS que lograse inyectar <script>, onclick= o
        # style= queda bloqueado por el navegador, no solo por el autoescape.
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
            "form-action 'self'; frame-ancestors 'none'; base-uri 'self'; "
            "object-src 'none'",
        )
        resp.headers.setdefault("Permissions-Policy",
                                "camera=(), microphone=(), geolocation=()")
        resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        return resp

    # ------------------------------------------------------------------
    # Rutas
    # ------------------------------------------------------------------
    from .vistas import (activos, ajustes, alertas_proceso, amenazas, colores, credenciales, excepciones,
                         fuentes, informes, panel, parches, remediaciones, sesion,
                         sincronizaciones, tecnologias, usuarios)

    app.register_blueprint(sesion.bp)
    app.register_blueprint(panel.bp)
    app.register_blueprint(fuentes.bp)
    app.register_blueprint(tecnologias.bp)
    app.register_blueprint(activos.bp)
    app.register_blueprint(credenciales.bp)
    app.register_blueprint(amenazas.bp)
    app.register_blueprint(ajustes.bp)
    app.register_blueprint(usuarios.bp)
    app.register_blueprint(alertas_proceso.bp)   # v6
    app.register_blueprint(remediaciones.bp)     # v6
    app.register_blueprint(parches.bp)           # v7
    app.register_blueprint(sincronizaciones.bp)  # v9: consultas a las bases de OCS
    app.register_blueprint(informes.bp)         # 2026-09-08: informes mensuales a demanda (administrador y operador SOC)
    app.register_blueprint(excepciones.bp)      # v13 (2026-09-10): aceptacion de riesgo con vencimiento
    app.register_blueprint(colores.bp)          # Personalización de colores y temas

    # ------------------------------------------------------------------
    # Errores
    # ------------------------------------------------------------------
    # Paginas de error (revision de claridad del 2026-09-15): cada una dice QUE PASO y
    # COMO SEGUIR, en palabras y sin siglas. El numero del error ya no manda en la pagina;
    # queda al pie, en pequeno, para poder citarlo al avisar.
    @app.errorhandler(400)
    def _e400(e):
        # El detalle del abort() se conserva cuando lo hay (por ejemplo el aviso de que el
        # formulario caducó), porque dice exactamente qué hacer; si no lo hay, o si es el
        # texto genérico que pone Werkzeug, se escribe una frase que se entienda.
        detalle = str(getattr(e, "description", "") or "").strip()
        generico = ("Los datos enviados no tenían la forma esperada. Vuelva a la página "
                    "anterior, rellene el formulario de nuevo y envíelo otra vez.")
        if not detalle or detalle.startswith("The browser (or proxy) sent a request"):
            detalle = generico
        return render_template("error.html", codigo=400,
                               titulo="La plataforma no entendió la petición",
                               detalle=detalle), 400

    @app.errorhandler(403)
    def _e403(e):
        # Ninguna respuesta de este tipo dice que perfil haria falta ni sobre que recurso:
        # eso serviria para averiguar el mapa de la plataforma desde fuera. El texto es
        # siempre el mismo (peticion del usuario del 2026-09-08), pero ya no culpa a nadie.
        return render_template("error.html", codigo=403,
                               titulo="Esta página no está incluida en su perfil",
                               detalle=("Su cuenta es correcta; lo que pasa es que este apartado "
                                        "pertenece a otro perfil de acceso. Si necesita entrar, "
                                        "pídalo a administración. Mientras tanto, "
                                        "puede seguir trabajando desde el panel.")), 403

    @app.errorhandler(404)
    def _e404(e):
        return render_template("error.html", codigo=404,
                               titulo="Esa página no existe",
                               detalle=("La dirección que se ha abierto no corresponde a ninguna "
                                        "página de la plataforma: puede que el enlace sea antiguo "
                                        "o que el elemento se haya eliminado. Use el menú o vuelva "
                                        "al panel para seguir."), ), 404

    @app.errorhandler(405)
    def _e405(e):
        return render_template("error.html", codigo=405,
                               titulo="Esta dirección no se abre directamente",
                               detalle=("Corresponde a la acción de un formulario de la plataforma, "
                                        "no a una página que se pueda visitar. Vuelva a la página "
                                        "anterior y use el botón correspondiente."), ), 405

    @app.errorhandler(413)
    def _e413(e):
        # El servidor web corta los cuerpos grandes antes de llegar aqui; este es el caso
        # de un cuerpo troceado (chunked) que supera MAX_CONTENT_LENGTH.
        return render_template("error.html", codigo=413,
                               titulo="El fichero que ha enviado es demasiado grande",
                               detalle=("La plataforma admite como mucho 41 megabytes por envío. "
                                        "Reduzca el fichero, divídalo en partes o envíe solo la "
                                        "parte que haga falta."), ), 413

    @app.errorhandler(500)
    def _e500(e):
        log.error("error no controlado en la interfaz",
                  extra={"ruta": request.path}, exc_info=True)
        return render_template("error.html", codigo=500,
                               titulo="Se ha producido un fallo en la plataforma",
                               detalle=("No es culpa de lo que estaba haciendo. El fallo ha quedado "
                                        "registrado con todo el detalle; avise a Seguridad de la "
                                        "Información e inténtelo de nuevo en unos minutos.")), 500

    return app


def main() -> int:
    """Arranque en produccion con waitress."""
    from waitress import serve

    setup(level=os.getenv("LOG_LEVEL", "INFO"), log_file="webui.jsonl")
    db.init_db()
    cfg = config.load()
    host = str(cfg.get("webui_host") or "127.0.0.1")
    port = int(cfg.get("webui_port") or 9090)

    app = crear_app()
    log.info("interfaz de administracion iniciada",
             extra={"host": host, "port": port})
    print(f"  Interfaz escuchando en http://{host}:{port}"
          + (" (detrás de nginx)" if cfg.get("webui_tras_proxy") else ""))
    extra: dict = {}
    if cfg.get("webui_tras_proxy"):
        # waitress descarta por omision las cabeceras X-Forwarded-* de cualquier origen no
        # declarado de confianza (clear_untrusted_proxy_headers), asi que sin esto la
        # aplicacion registraba 127.0.0.1 en la auditoria aunque nginx enviara la direccion
        # real. Solo se confia en el propio equipo (nginx en 127.0.0.1) y en UN salto.
        extra = {"trusted_proxy": "127.0.0.1", "trusted_proxy_count": 1,
                 "trusted_proxy_headers": {"x-forwarded-for", "x-forwarded-proto"},
                 "clear_untrusted_proxy_headers": True}
    serve(app, host=host, port=port, threads=8, ident="ThreatIntel", **extra)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

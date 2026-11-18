"""Gestion de credenciales: contrasena SMTP, destinatarios y clave de API de NVD.

Peticion explicita del usuario: la contrasena SMTP cambia cada mes, y quiere
poder cambiarla sin editar ficheros y recibir un aviso especifico cuando toque
cambiarla o cuando falle.

La contrasena NUNCA se muestra en claro ni se devuelve al navegador: solo se
escribe, enmascarada en la interfaz y guardada en config/credentials.env con
permisos 600.
"""
from __future__ import annotations

import re

from flask import (Blueprint, current_app, flash, g, redirect, render_template,
                   request, url_for)

from threatintel import config, db
from webui import auth

bp = Blueprint("credenciales", __name__, url_prefix="/credenciales")


def _mod(nombre: str):
    return __import__(f"threatintel.{nombre}", fromlist=["x"])


@bp.route("/")
@auth.requiere_admin
def panel():
    try:
        estado = _mod("credentials").estado(g.db, cfg=g.cfg)
    except Exception as exc:  # noqa: BLE001
        estado = None
        flash(f"No se pudo leer el estado de las credenciales: {exc}", "aviso")
    # Certificado HTTPS (2026-09-08): misma pagina, misma logica de dias restantes.
    try:
        certificado = _mod("certificado").estado(cfg=g.cfg)
    except Exception:  # noqa: BLE001
        certificado = None

    historial = [dict(r) for r in g.db.execute(
        """SELECT * FROM audit_log
            WHERE action LIKE 'credencial%' OR action LIKE 'smtp%' OR action LIKE 'nvd%'
            ORDER BY at DESC LIMIT 25""")]

    avisos = [dict(r) for r in g.db.execute(
        """SELECT * FROM admin_notices WHERE kind LIKE 'smtp%'
            ORDER BY sent_at DESC LIMIT 15""")]

    try:
        nvd = _mod("enrich").estado_clave_nvd(g.db, g.cfg)
    except Exception as exc:  # noqa: BLE001
        nvd = None
        flash(f"No se pudo leer el estado de la clave NVD: {exc}", "aviso")

    smtp = g.cfg.smtp
    return render_template(
        "credenciales.html", certificado=certificado,
        estado=estado, historial=historial, avisos=avisos, nvd=nvd,
        smtp={
            "server": smtp.server, "port": smtp.port, "user": smtp.user,
            "password_mascara": config.mask(smtp.password),
            "use_ssl": smtp.use_ssl, "use_tls": smtp.use_tls,
            "from_addr": smtp.from_addr, "from_name": smtp.from_name,
        },
        destinatarios={
            "alertas": g.cfg.alert_to, "alertas_cc": g.cfg.alert_cc,
            "informes": g.cfg.report_to, "informes_cc": g.cfg.report_cc,
            "administrador": g.cfg.admin_to,
        },
        rotacion_dias=g.cfg.get("smtp_rotation_days", 30),
        avisos_dias=g.cfg.get("smtp_warn_days_before", [7, 3, 1]),
    )


@bp.route("/rotar", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def rotar():
    """Guarda la contrasena nueva, la verifica y reinicia el ciclo de avisos."""
    nueva = request.form.get("password_nueva") or ""
    repetir = request.form.get("password_repetir") or ""
    verificar_antes = request.form.get("verificar") == "1"

    if not nueva:
        flash("Debe indicar la contrasena nueva.", "error")
        return redirect(url_for("credenciales.panel"))
    if nueva != repetir:
        flash("Las dos contrasenas no coinciden.", "error")
        return redirect(url_for("credenciales.panel"))
    if len(nueva) < 6:
        flash("La contrasena parece demasiado corta.", "error")
        return redirect(url_for("credenciales.panel"))

    anterior = g.cfg.smtp.password

    # Verificar la credencial nueva ANTES de persistirla, para no dejar el
    # sistema sin capacidad de enviar correo si el operador se equivoca.
    if verificar_antes:
        import copy
        prueba = copy.copy(g.cfg)
        prueba.smtp = copy.copy(g.cfg.smtp)
        prueba.smtp.password = nueva
        try:
            mailer = _mod("notify").Mailer(prueba)
            ok, error = mailer.verify_connection()
        except Exception as exc:  # noqa: BLE001
            ok, error = False, f"{type(exc).__name__}: {exc}"
        if not ok:
            flash(f"La contrasena nueva no funciona, no se ha guardado. Error: {error}",
                  "error")
            with db.session(current_app.config.get("DB_PATH")) as conn:
                db.audit(conn, g.usuario, "credencial.rotar_rechazada",
                         "credentials_meta", "smtp_password",
                         f"verificacion fallida: {error}", request.remote_addr)
            return redirect(url_for("credenciales.panel"))

    try:
        config.update_secret("SMTP_PASSWORD", nueva)
    except Exception as exc:  # noqa: BLE001
        # El detalle (que puede llevar rutas del servidor) va al registro, no al navegador.
        current_app.logger.error("no se pudo escribir la credencial en el servidor", exc_info=exc)
        flash("No se pudo guardar la credencial en el servidor; quedó anotado en el registro del servicio.", "error")
        return redirect(url_for("credenciales.panel"))

    dias = request.form.get("rotacion_dias", type=int)
    with db.session(current_app.config.get("DB_PATH")) as conn:
        try:
            _mod("credentials").registrar_rotacion(
                conn, key="smtp_password", usuario=g.usuario, rotation_days=dias)
        except Exception as exc:  # noqa: BLE001
            flash(f"Contrasena guardada, pero no se pudo registrar la rotacion: {exc}",
                  "aviso")
        db.audit(conn, g.usuario, "credencial.rotar", "credentials_meta",
                 "smtp_password",
                 f"anterior={config.mask(anterior)} nueva={config.mask(nueva)}",
                 request.remote_addr)

    flash("Contrasena SMTP actualizada y ciclo de avisos reiniciado.", "exito")
    return redirect(url_for("credenciales.panel"))


_RE_SERVIDOR = re.compile(r"^[A-Za-z0-9.-]{1,255}$")
_RE_CORREO = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@bp.route("/servidor", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def servidor():
    """Cambia el servidor, el puerto, el usuario, el cifrado y el remitente SMTP.

    Separado de :func:`rotar` (petición del usuario, 2026-11-17: «la estoy viendo en el
    apartado de credenciales de la interfaz web así que eso se tiene que editar»): antes
    el servidor y el usuario solo se podían leer aquí, había que entrar a
    config/credentials.env a mano para moverse, por ejemplo, de un servidor SMTP propio a
    Gmail. La contraseña sigue teniendo su propio formulario, con verificación antes de
    guardar: aquí NO se toca, porque un servidor nuevo casi siempre necesita también una
    contraseña nueva, y las dos cosas a la vez no se pueden probar sin la contraseña.
    """
    servidor_ = (request.form.get("servidor") or "").strip()
    puerto = request.form.get("puerto", type=int)
    usuario_smtp = (request.form.get("usuario_smtp") or "").strip()
    cifrado = (request.form.get("cifrado") or "").strip()
    remitente = (request.form.get("remitente") or "").strip()
    remitente_nombre = (request.form.get("remitente_nombre") or "").strip()[:120]

    if not _RE_SERVIDOR.match(servidor_):
        flash("El servidor no tiene una forma válida (solo letras, números, puntos y "
              "guiones; por ejemplo smtp.gmail.com).", "error")
        return redirect(url_for("credenciales.panel"))
    if puerto is None or not 1 <= puerto <= 65535:
        flash("El puerto debe ser un número entre 1 y 65535.", "error")
        return redirect(url_for("credenciales.panel"))
    if not usuario_smtp:
        flash("Indique el usuario SMTP.", "error")
        return redirect(url_for("credenciales.panel"))
    if cifrado not in ("tls", "ssl", "ninguno"):
        flash("Elija un tipo de cifrado válido.", "error")
        return redirect(url_for("credenciales.panel"))
    if not _RE_CORREO.match(remitente):
        flash("El remitente debe ser una dirección de correo válida.", "error")
        return redirect(url_for("credenciales.panel"))

    anterior = f"{g.cfg.smtp.server}:{g.cfg.smtp.port} usuario={g.cfg.smtp.user}"
    try:
        config.update_secret("SMTP_SERVER", servidor_)
        config.update_secret("SMTP_PORT", str(puerto))
        config.update_secret("SMTP_USER", usuario_smtp)
        config.update_secret("SMTP_USE_TLS", "true" if cifrado == "tls" else "false")
        config.update_secret("SMTP_USE_SSL", "true" if cifrado == "ssl" else "false")
        config.update_secret("EMAIL_FROM", remitente)
        config.update_secret("EMAIL_FROM_NAME", remitente_nombre)
    except Exception as exc:  # noqa: BLE001
        current_app.logger.error("no se pudo escribir el servidor SMTP en el servidor", exc_info=exc)
        flash("No se pudo guardar el servidor en el archivo del servidor; quedó anotado "
              "en el registro del servicio.", "error")
        return redirect(url_for("credenciales.panel"))

    with db.session(current_app.config.get("DB_PATH")) as conn:
        db.audit(conn, g.usuario, "credencial.servidor", "credentials_meta", "smtp_server",
                 f"anterior=({anterior}) nuevo=({servidor_}:{puerto} usuario={usuario_smtp})",
                 request.remote_addr)

    flash("Servidor de correo actualizado. Si cambió de proveedor, es probable que "
          "también tenga que renovar la contraseña (abajo) para que vuelva a enviar.",
          "exito")
    return redirect(url_for("credenciales.panel"))


@bp.route("/verificar", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def verificar():
    """Prueba la conexion y el login SMTP actuales, sin enviar correo."""
    try:
        ok, error = _mod("credentials").verificar(g.db, cfg=g.cfg)
    except Exception as exc:  # noqa: BLE001
        ok, error = False, f"{type(exc).__name__}: {exc}"

    with db.session(current_app.config.get("DB_PATH")) as conn:
        db.audit(conn, g.usuario, "smtp.verificar", "credentials_meta",
                 "smtp_password", f"ok={ok} error={error}", request.remote_addr)

    if ok:
        flash("Conexion y autenticacion SMTP correctas.", "exito")
    elif error and error.startswith("AUTH"):
        flash(f"La credencial ya no es valida: {error}. Hay que cambiar la "
              f"contrasena.", "error")
    else:
        flash(f"No se pudo conectar con el servidor de correo: {error}. "
              f"Esto apunta a un problema de red, no de credencial.", "aviso")
    return redirect(url_for("credenciales.panel"))


@bp.route("/prueba-envio", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def prueba_envio():
    """Envia un correo de prueba real al administrador."""
    destino = (request.form.get("destino") or "").strip()
    destinos = config.split_emails(destino) or g.cfg.admin_to
    if not destinos:
        flash("No hay ningun destinatario valido.", "error")
        return redirect(url_for("credenciales.panel"))

    try:
        notify = _mod("notify")
        html = notify.render_admin_email(
            titulo="Prueba de configuracion de correo",
            intro=("Este mensaje confirma que el sistema de inteligencia de amenazas "
                   "puede enviar correo con la configuracion actual."),
            severidad="info",
            secciones=[{
                "titulo": "Configuracion utilizada",
                "filas": [
                    ("Servidor", f"{g.cfg.smtp.server}:{g.cfg.smtp.port}"),
                    ("Usuario", g.cfg.smtp.user),
                    ("Cifrado", "SSL" if g.cfg.smtp.use_ssl else
                                ("STARTTLS" if g.cfg.smtp.use_tls else "ninguno")),
                    ("Solicitado por", g.usuario),
                ],
            }],
            acciones=["No se requiere ninguna accion. Es una prueba manual."],
        )
        enviado = notify.Mailer(g.cfg).send(
            subject="[SOC] Prueba de configuracion de correo",
            html=html, to=destinos)
    except Exception as exc:  # noqa: BLE001
        enviado, exc_txt = False, f"{type(exc).__name__}: {exc}"
        flash(f"No se pudo enviar la prueba: {exc_txt}", "error")
        return redirect(url_for("credenciales.panel"))

    with db.session(current_app.config.get("DB_PATH")) as conn:
        db.audit(conn, g.usuario, "smtp.prueba_envio", None, None,
                 f"destinos={destinos} enviado={enviado}", request.remote_addr)

    if enviado:
        flash(f"Correo de prueba enviado a {', '.join(destinos)}.", "exito")
    else:
        flash("El envio no se completo. Revise el registro.", "error")
    return redirect(url_for("credenciales.panel"))


@bp.route("/destinatarios", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def destinatarios():
    """Edita los destinatarios de alertas, informes y avisos de administracion."""
    mapa = {
        "ALERT_EMAIL_TO": "alertas",
        "ALERT_EMAIL_CC": "alertas_cc",
        "REPORT_EMAIL_TO": "informes",
        "REPORT_EMAIL_CC": "informes_cc",
        "ADMIN_EMAIL": "administrador",
    }
    cambios = []
    for clave, campo in mapa.items():
        bruto = request.form.get(campo)
        if bruto is None:
            continue
        direcciones = config.split_emails(bruto)
        if bruto.strip() and not direcciones:
            flash(f"Ninguna direccion valida en '{campo}'. No se ha cambiado.", "error")
            continue
        if clave == "ALERT_EMAIL_TO" and not direcciones:
            flash("Los destinatarios de alertas no pueden quedar vacios.", "error")
            continue
        try:
            config.update_secret(clave, ", ".join(direcciones))
            cambios.append(f"{clave}={len(direcciones)} destinatario(s)")
        except Exception as exc:  # noqa: BLE001
            flash(f"No se pudo guardar {clave}: {exc}", "error")

    if cambios:
        with db.session(current_app.config.get("DB_PATH")) as conn:
            db.audit(conn, g.usuario, "credencial.destinatarios", None, None,
                     "; ".join(cambios), request.remote_addr)
        flash("Destinatarios actualizados: " + "; ".join(cambios), "exito")
    return redirect(url_for("credenciales.panel"))


# ----------------------------------------------------------- clave de API NVD

def _resultado_verificacion_nvd(ok: bool, mensaje: str) -> None:
    """Persiste el resultado y lo comunica al operador con el nivel adecuado."""
    with db.session(current_app.config.get("DB_PATH")) as conn:
        _mod("enrich").registrar_verificacion_nvd(conn, ok, mensaje)
        db.audit(conn, g.usuario, "nvd.verificar", "credentials", "NIST_NVD_API_KEY",
                 f"ok={ok} {mensaje}", request.remote_addr)
    flash(("Clave NVD verificada: " if ok else "Clave NVD no válida: ") + mensaje,
          "exito" if ok else "error")


@bp.route("/nvd/guardar", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def nvd_guardar():
    """Guarda una clave NVD nueva, verificandola antes contra la API si se pide."""
    nueva = (request.form.get("clave") or "").strip()
    verificar_antes = request.form.get("verificar") == "1"
    enrich = _mod("enrich")

    if not nueva:
        flash("Debe pegar la clave recibida del NIST.", "error")
        return redirect(url_for("credenciales.panel"))

    # El formato se comprueba siempre: una clave mal copiada no debe llegar al fichero
    if not enrich._FORMATO_CLAVE_NVD.match(nueva):
        flash(f"La clave no tiene el formato que emite el NIST ({len(nueva)} caracteres; "
              f"se esperan 36 con guiones). No se ha guardado.", "error")
        return redirect(url_for("credenciales.panel"))

    if verificar_antes:
        try:
            ok, mensaje = enrich.validar_clave_nvd(g.cfg, clave=nueva)
        except Exception as exc:  # noqa: BLE001
            ok, mensaje = False, f"{type(exc).__name__}: {exc}"
        if not ok:
            with db.session(current_app.config.get("DB_PATH")) as conn:
                db.audit(conn, g.usuario, "nvd.guardar_rechazada", "credentials",
                         "NIST_NVD_API_KEY", mensaje, request.remote_addr)
            flash(f"La clave no se ha guardado porque NVD no la acepta: {mensaje}", "error")
            return redirect(url_for("credenciales.panel"))

    anterior = g.cfg.nvd_api_key
    try:
        config.update_secret("NIST_NVD_API_KEY", nueva)
    except Exception as exc:  # noqa: BLE001
        # El detalle (que puede llevar rutas del servidor) va al registro, no al navegador.
        current_app.logger.error("no se pudo escribir la credencial en el servidor", exc_info=exc)
        flash("No se pudo guardar la credencial en el servidor; quedó anotado en el registro del servicio.", "error")
        return redirect(url_for("credenciales.panel"))

    with db.session(current_app.config.get("DB_PATH")) as conn:
        if verificar_antes:
            enrich.registrar_verificacion_nvd(conn, True, "clave válida: NVD la acepta")
        else:
            # Sin verificar: se borra el resultado anterior para no mostrar uno ajeno
            db.set_setting(conn, "nvd_key_last_check_ok", None)
            db.set_setting(conn, "nvd_key_last_check_msg", "guardada sin verificar")
            db.set_setting(conn, "nvd_key_last_check_at", db.utcnow())
        db.audit(conn, g.usuario, "nvd.guardar", "credentials", "NIST_NVD_API_KEY",
                 f"anterior={config.mask(anterior)} nueva={config.mask(nueva)} "
                 f"verificada={verificar_antes}", request.remote_addr)

    flash("Clave de API de NVD guardada. La próxima ejecución de enriquecimiento "
          "(13:00) ya la usará.", "exito")
    return redirect(url_for("credenciales.panel"))


@bp.route("/nvd/verificar", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def nvd_verificar():
    """Prueba la clave configurada contra la API real de NVD."""
    try:
        ok, mensaje = _mod("enrich").validar_clave_nvd(g.cfg)
    except Exception as exc:  # noqa: BLE001
        ok, mensaje = False, f"{type(exc).__name__}: {exc}"
    _resultado_verificacion_nvd(ok, mensaje)
    return redirect(url_for("credenciales.panel"))


@bp.route("/nvd/quitar", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def nvd_quitar():
    """Retira la clave: el sistema vuelve al límite público, sin romperse."""
    anterior = g.cfg.nvd_api_key
    if not anterior:
        flash("No hay ninguna clave NVD configurada.", "aviso")
        return redirect(url_for("credenciales.panel"))
    try:
        config.update_secret("NIST_NVD_API_KEY", "")
    except Exception as exc:  # noqa: BLE001
        # El detalle (que puede llevar rutas del servidor) va al registro, no al navegador.
        current_app.logger.error("no se pudo escribir la credencial en el servidor", exc_info=exc)
        flash("No se pudo guardar la credencial en el servidor; quedó anotado en el registro del servicio.", "error")
        return redirect(url_for("credenciales.panel"))
    with db.session(current_app.config.get("DB_PATH")) as conn:
        for k in ("nvd_key_last_check_ok", "nvd_key_last_check_at", "nvd_key_last_check_msg"):
            db.set_setting(conn, k, None)
        db.audit(conn, g.usuario, "nvd.quitar", "credentials", "NIST_NVD_API_KEY",
                 f"anterior={config.mask(anterior)}", request.remote_addr)
    flash("Clave NVD retirada. El enriquecimiento sigue funcionando con el límite público.",
          "exito")
    return redirect(url_for("credenciales.panel"))

"""Rotacion y verificacion de la credencial de correo.

La contrasena SMTP de esta organizacion se renueva cada mes. El sistema
anterior no lo sabia: cuando caducaba, las alertas simplemente dejaban de
enviarse y nadie se enteraba hasta echarlas de menos.

Aqui se registra cuando se cambio, se avisa con antelacion escalonada y, sobre
todo, se distingue el fallo de CREDENCIAL del fallo de RED. Son problemas
distintos: uno exige cambiar la contrasena y el otro no, y pedir una contrasena
nueva porque el servidor de correo esta caido solo genera desconfianza en el
aviso.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from . import db
from .logging_setup import get_logger

log = get_logger("credentials")

CLAVE_SMTP = "smtp_password"

ESTADO_OK = "ok"
ESTADO_POR_CADUCAR = "por_caducar"
ESTADO_CADUCADA = "caducada"
ESTADO_FALLANDO = "fallando"


def _ahora() -> datetime:
    return datetime.now(timezone.utc)


def _parse(valor: Optional[str]) -> Optional[datetime]:
    if not valor:
        return None
    texto = str(valor).strip().replace("Z", "+00:00")
    for intento in (texto, texto[:19] + "+00:00", texto[:10]):
        try:
            dt = datetime.fromisoformat(intento)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


# --------------------------------------------------------------------------
# Registro
# --------------------------------------------------------------------------
def asegurar_registro(conn: sqlite3.Connection, *, cfg,
                      key: str = CLAVE_SMTP) -> None:
    """Crea la fila de seguimiento si no existe.

    La fecha de rotacion inicial se registra como AHORA (2026-11-15), no como la fecha
    de modificacion del fichero de credenciales: ese ``mtime`` dice cuando se desplego la
    configuracion (por ejemplo al reconstruir el entorno), no cuando se cambio la
    contrasena realmente, y usarlo como estimacion generaba avisos de «caducada» falsos
    en una instalacion nueva sin ningun historico. Sin fila previa no hay ningun dato
    mejor que «ahora mismo», asi que se siembra con :func:`registrar_rotacion`, que ya
    sabe crear la fila cuando no existe.
    """
    fila = conn.execute(
        "SELECT 1 FROM credentials_meta WHERE key=?", (key,)).fetchone()
    if fila is not None:
        return

    registrar_rotacion(
        conn, key=key,
        rotation_days=int(cfg.get("smtp_rotation_days", 30) or 30))
    log.info("registro de credencial creado", extra={"key": key})


def estado(conn: sqlite3.Connection, *, cfg,
           key: str = CLAVE_SMTP) -> dict[str, Any]:
    """Devuelve el estado completo de la credencial."""
    asegurar_registro(conn, cfg=cfg, key=key)
    fila = conn.execute(
        "SELECT * FROM credentials_meta WHERE key=?", (key,)).fetchone()

    dias_validez = int(fila["rotation_days"] or cfg.get("smtp_rotation_days", 30))
    rotada = _parse(fila["rotated_at"])
    fallos = int(fila["consecutive_failures"] or 0)
    ultima_ok = fila["last_verify_ok"]
    ultimo_error = fila["last_verify_error"]

    if rotada is None:
        dias_desde = None
        dias_restantes = None
        caducada = False
    else:
        dias_desde = (_ahora() - rotada).days
        dias_restantes = dias_validez - dias_desde
        caducada = dias_restantes < 0

    # Un fallo de AUTENTICACION es el sintoma claro de credencial invalida.
    fallo_auth = bool(ultimo_error and str(ultimo_error).startswith("AUTH"))

    if fallo_auth:
        situacion = ESTADO_FALLANDO
        mensaje = ("La autenticación con el servidor de correo se rechaza: la "
                   "contraseña ya no es válida y debe cambiarse.")
    elif caducada:
        situacion = ESTADO_CADUCADA
        mensaje = (f"Superó su periodo de validez hace "
                   f"{abs(dias_restantes)} día{'s' if abs(dias_restantes) != 1 else ''}. Debe renovarse.")
    elif dias_restantes is not None and dias_restantes <= max(
            cfg.get("smtp_warn_days_before", [7, 3, 1]) or [7]):
        situacion = ESTADO_POR_CADUCAR
        mensaje = (f"Caduca en {dias_restantes} día{'s' if dias_restantes != 1 else ''}. Conviene renovarla "
                   f"antes de que las alertas dejen de enviarse.")
    elif fallos >= 2:
        situacion = ESTADO_FALLANDO
        mensaje = (f"El envío ha fallado {fallos} veces consecutivas por causas "
                   f"de red. La credencial parece correcta.")
    else:
        situacion = ESTADO_OK
        if dias_restantes is None:
            mensaje = "Vigente."
        else:
            mensaje = f"Caduca en {dias_restantes} día{'s' if dias_restantes != 1 else ''}."

    try:
        avisados = json.loads(fila["notified_stages"] or "[]")
    except (json.JSONDecodeError, TypeError):
        avisados = []

    return {
        "key": key,
        "rotated_at": fila["rotated_at"],
        "rotation_days": dias_validez,
        "dias_desde": dias_desde,
        "dias_restantes": dias_restantes,
        "caducada": caducada,
        "last_verified_at": fila["last_verified_at"],
        "last_verify_ok": None if ultima_ok is None else bool(ultima_ok),
        "last_verify_error": ultimo_error,
        "consecutive_failures": fallos,
        "fallo_autenticacion": fallo_auth,
        "avisos_enviados": avisados,
        "estado": situacion,
        "mensaje": mensaje,
    }


def registrar_rotacion(conn: sqlite3.Connection, *, key: str = CLAVE_SMTP,
                       usuario: Optional[str] = None,
                       rotation_days: Optional[int] = None) -> None:
    """Marca la credencial como recien cambiada y reinicia el ciclo de avisos."""
    campos = ["rotated_at=?", "consecutive_failures=0", "notified_stages='[]'",
              "last_verify_error=NULL", "updated_at=?"]
    valores: list[Any] = [db.utcnow(), db.utcnow()]

    if rotation_days:
        campos.insert(1, "rotation_days=?")
        valores.insert(1, int(rotation_days))

    valores.append(key)
    cur = conn.execute(
        f"UPDATE credentials_meta SET {', '.join(campos)} WHERE key=?", valores)

    if not cur.rowcount:
        conn.execute(
            """INSERT INTO credentials_meta(key, rotated_at, rotation_days,
                   consecutive_failures, notified_stages, updated_at)
               VALUES(?,?,?,0,'[]',?)""",
            (key, db.utcnow(), int(rotation_days or 30), db.utcnow()))

    db.audit(conn, usuario, "credencial.rotada", "credentials_meta", key,
             f"validez={rotation_days or 'sin cambio'} dias")
    log.info("rotacion de credencial registrada",
             extra={"key": key, "usuario": usuario})


# --------------------------------------------------------------------------
# Verificacion
# --------------------------------------------------------------------------
def verificar(conn: sqlite3.Connection, *, cfg, mailer=None,
              registrar: bool = True,
              key: str = CLAVE_SMTP) -> tuple[bool, Optional[str]]:
    """Comprueba conexion y autenticacion SMTP sin enviar correo."""
    if mailer is None:
        from .notify import Mailer
        mailer = Mailer(cfg)

    ok, error = mailer.verify_connection()

    if registrar:
        asegurar_registro(conn, cfg=cfg, key=key)
        if ok:
            conn.execute(
                """UPDATE credentials_meta
                      SET last_verified_at=?, last_verify_ok=1,
                          last_verify_error=NULL, consecutive_failures=0,
                          updated_at=?
                    WHERE key=?""",
                (db.utcnow(), db.utcnow(), key))
        else:
            # Solo los fallos de RED acumulan racha. Un fallo de autenticacion
            # no es transitorio: se marca de inmediato como credencial invalida.
            es_red = bool(error and error.startswith("RED"))
            conn.execute(
                f"""UPDATE credentials_meta
                       SET last_verified_at=?, last_verify_ok=0,
                           last_verify_error=?,
                           consecutive_failures={'consecutive_failures + 1' if es_red else '0'},
                           updated_at=?
                     WHERE key=?""",
                (db.utcnow(), error, db.utcnow(), key))

    nivel = log.info if ok else log.warning
    nivel("verificacion SMTP", extra={"ok": ok, "error": error})
    return ok, error


# --------------------------------------------------------------------------
# Avisos
# --------------------------------------------------------------------------
def _ya_avisado(conn: sqlite3.Connection, kind: str, subject_key: str,
                horas: int) -> bool:
    """True si se envio un aviso igual dentro del periodo de silencio."""
    limite = (_ahora() - timedelta(hours=max(1, horas))).replace(
        microsecond=0).isoformat().replace("+00:00", "Z")
    fila = conn.execute(
        """SELECT 1 FROM admin_notices
            WHERE kind=? AND subject_key=? AND sent_at >= ? LIMIT 1""",
        (kind, subject_key, limite)).fetchone()
    return fila is not None


def _registrar_aviso(conn: sqlite3.Connection, kind: str, subject_key: str,
                     detalle: str) -> None:
    conn.execute(
        """INSERT OR IGNORE INTO admin_notices(kind, subject_key, sent_at, detail)
           VALUES(?,?,?,?)""",
        (kind, subject_key, db.utcnow(), detalle[:600]))


def revisar_y_avisar(conn: sqlite3.Connection, *, cfg, mailer=None,
                     key: str = CLAVE_SMTP) -> list[dict[str, Any]]:
    """Envia los avisos que correspondan sobre la credencial.

    Cuatro situaciones, cada una con su propio mensaje:

      1. Fallo de AUTENTICACION -> aviso inmediato: hay que cambiarla ya.
      2. Ya caducada            -> aviso diario mientras siga asi.
      3. Proxima a caducar      -> un aviso por cada umbral, sin repetir.
      4. Fallos de RED seguidos -> aviso de conectividad, NO de credencial.
    """
    from .notify import Mailer, asunto_admin, render_admin_email

    if mailer is None:
        mailer = Mailer(cfg)

    est = estado(conn, cfg=cfg, key=key)
    destinatarios = cfg.admin_to
    if not destinatarios:
        log.warning("no hay destinatarios de administracion configurados; "
                    "no se puede avisar de la credencial")
        return []

    enfriamiento = int(cfg.get("health_notice_cooldown_h", 24) or 24)
    enviados: list[dict[str, Any]] = []
    smtp = cfg.smtp

    datos_servidor = [
        ("Servidor", f"{smtp.server}:{smtp.port}"),
        ("Usuario", smtp.user),
        ("Cifrado", "SSL" if smtp.use_ssl else ("STARTTLS" if smtp.use_tls else "ninguno")),
        ("Último cambio de contraseña", est["rotated_at"] or "sin registrar"),
        ("Periodo de validez", f"{est['rotation_days']} días"),
    ]

    def _enviar(kind: str, subject_key: str, titulo: str, severidad: str,
                intro: str, acciones: list[str], filas_extra=None,
                pie: Optional[str] = None) -> bool:
        if _ya_avisado(conn, kind, subject_key, enfriamiento):
            log.debug("aviso omitido por periodo de silencio",
                      extra={"kind": kind, "subject_key": subject_key})
            return False
        secciones = [{"titulo": "Configuración de correo",
                      "filas": datos_servidor + list(filas_extra or [])}]
        html = render_admin_email(titulo=titulo, intro=intro, severidad=severidad,
                                  secciones=secciones, acciones=acciones, pie=pie)
        if mailer.send(subject=asunto_admin(titulo, severidad), html=html,
                       to=destinatarios):
            _registrar_aviso(conn, kind, subject_key, titulo)
            enviados.append({"kind": kind, "titulo": titulo,
                             "severidad": severidad})
            log.info("aviso de credencial enviado",
                     extra={"kind": kind, "titulo": titulo})
            return True
        log.error("no se pudo enviar el aviso de credencial",
                  extra={"kind": kind})
        return False

    from .config import url_publica
    url_interfaz = url_publica(cfg, "/credenciales/")

    # ---------------------------------------------- 1. credencial rechazada
    if est["fallo_autenticacion"]:
        _enviar(
            kind="smtp_auth_fallida", subject_key=key,
            titulo="La contraseña de correo ya no es válida",
            severidad="critical",
            intro=("El servidor de correo está rechazando la autenticación del "
                   "sistema de inteligencia de amenazas. Mientras no se "
                   "actualice la contraseña, NO se enviarán las alertas diarias "
                   "ni el informe mensual."),
            acciones=[f"Acceder a {url_interfaz}",
                      "Introducir la contraseña nueva dejando activada la "
                      "verificación previa",
                      "Comprobar que el estado pasa a «vigente»"],
            filas_extra=[("Error devuelto", est["last_verify_error"] or "—"),
                         ("Última verificación", est["last_verified_at"] or "—")],
            pie=("Este aviso se distingue a propósito de un fallo de red: aquí el "
                 "servidor responde y rechaza las credenciales, de modo que la "
                 "causa es la contraseña."))
        return enviados

    # ------------------------------------------------------- 2. ya caducada
    if est["caducada"]:
        # Aviso diario: la clave del asunto incluye el dia para que el periodo
        # de silencio no lo suprima indefinidamente.
        hoy = _ahora().strftime("%Y-%m-%d")
        _enviar(
            kind="smtp_caducada", subject_key=f"{key}:{hoy}",
            titulo=f"La contraseña de correo caducó hace "
                   f"{abs(est['dias_restantes'])} día{'s' if abs(est['dias_restantes']) != 1 else ''}",
            severidad="critical",
            intro=("La contraseña de envío ha superado su periodo de validez de "
                   f"{est['rotation_days']} días. Aunque de momento siga "
                   "funcionando, debe renovarse: si el servidor la invalida, el "
                   "sistema dejará de enviar alertas sin previo aviso."),
            acciones=[f"Renovar la contraseña en {url_interfaz}",
                      "Registrar el cambio para reiniciar el ciclo de avisos"],
            filas_extra=[("Días desde el último cambio", est["dias_desde"])])
        return enviados

    # -------------------------------------------------- 3. proxima a caducar
    umbrales = sorted(
        {int(u) for u in (cfg.get("smtp_warn_days_before", [7, 3, 1]) or [])},
        reverse=True)
    restantes = est["dias_restantes"]

    if restantes is not None:
        for umbral in umbrales:
            if restantes <= umbral and umbral not in est["avisos_enviados"]:
                enviado = _enviar(
                    kind="smtp_rotacion", subject_key=f"{key}:umbral{umbral}",
                    titulo=f"La contraseña de correo caduca en {restantes} día{'s' if restantes != 1 else ''}",
                    severidad="warning" if restantes > 1 else "critical",
                    intro=("La contraseña de envío del sistema de inteligencia de "
                           f"amenazas caduca en {restantes} día{'s' if restantes != 1 else ''}. Conviene "
                           "renovarla antes de que las alertas dejen de "
                           "entregarse."),
                    acciones=[f"Renovar la contraseña en {url_interfaz}",
                              "Usar la verificación previa para confirmar que la "
                              "nueva funciona antes de guardarla"],
                    filas_extra=[("Días restantes", restantes)],
                    pie=("Se envía un único aviso por cada umbral configurado "
                         f"({', '.join(map(str, umbrales))} días). No se repetirá "
                         "para este umbral."))
                if enviado:
                    # Se marcan TODOS los umbrales ya superados, no solo este.
                    # Si el sistema estuvo parado y se cruzan varios de golpe
                    # (por ejemplo el de 7 y el de 3), debe salir un unico
                    # aviso con los dias reales restantes, no uno por umbral en
                    # dias consecutivos.
                    superados = {u for u in umbrales if restantes <= u}
                    marcados = sorted(set(est["avisos_enviados"]) | superados,
                                      reverse=True)
                    conn.execute(
                        "UPDATE credentials_meta SET notified_stages=?, "
                        "updated_at=? WHERE key=?",
                        (json.dumps(marcados), db.utcnow(), key))
                break

    # ------------------------------------------------ 4. problemas de red
    if est["consecutive_failures"] >= 2 and not est["fallo_autenticacion"]:
        _enviar(
            kind="smtp_red", subject_key=key,
            titulo="Problemas de conectividad con el servidor de correo",
            severidad="warning",
            intro=(f"El sistema no ha podido conectar con el servidor de correo "
                   f"en {est['consecutive_failures']} intentos consecutivos. La "
                   f"credencial parece correcta: el problema apunta a la red o "
                   f"al propio servidor."),
            acciones=["Comprobar la disponibilidad del servidor de correo",
                      "Revisar reglas de cortafuegos y resolución DNS",
                      "No es necesario cambiar la contraseña"],
            filas_extra=[("Fallos consecutivos", est["consecutive_failures"]),
                         ("Último error", est["last_verify_error"] or "—")])

    return enviados

"""Administracion de las alertas por proceso de negocio (v6). Solo administradores.

Cada proceso (campo TAG de OCS) puede recibir su propio correo con las amenazas que
afectan a SUS servidores. Aqui se fija el destinatario, el interruptor de activacion y
si se limitan a produccion y contingencia; se ve el historial de envios y se puede
mandar un correo de prueba al destino configurado.
"""
from __future__ import annotations

from flask import Blueprint, flash, g, redirect, render_template, request, url_for

from threatintel import alertas_proceso, db, notify
from .. import auth

bp = Blueprint("alertas_proceso", __name__, url_prefix="/alertas-proceso")


def _marcado(nombre: str) -> bool:
    return (request.form.get(nombre) or "").strip().lower() in {"1", "on", "true", "si", "sí"}


#: Estados de amenaza que no cuentan en ningun indicador de la plataforma (los mismos que
#: usa ``threatintel.alertas_proceso.procesos_disponibles``).
_ESTADOS_CERRADOS = ("descartada", "falso_positivo", "mitigada")


def _parque_de_servidores(conn) -> dict[str, int]:
    """Todos los servidores presentes de OCS Inventory, tengan proceso o no.

    Por que existe (auditoria de tableros del 2026-09-15): las tarjetas de esta pagina
    suman los procesos, asi que solo hablan de los servidores CON proceso asignado. Decian
    «356 servidores» y «334 con vulnerabilidades» cuando en todo el parque hay 391
    servidores presentes y 357 afectados: sin el alcance escrito, la cifra parecia la del
    parque entero y contradecia al Panel y a la pagina de Activos. Aqui se calculan las
    dos cifras del parque, con el MISMO criterio de severidad y de estado que
    ``alertas_proceso.procesos_disponibles``, para poder escribir el alcance en la propia
    cifra. Son dos recuentos por conjuntos sobre ``activos``, sin bucles ni consultas por
    fila.
    """
    sin_bajas = ("" if alertas_proceso.incluir_bajas(conn)
                 else " AND (t.severity IS NULL OR t.severity <> 'Low')")
    cerrados = ",".join("?" * len(_ESTADOS_CERRADOS))
    fila = conn.execute(
        f"""SELECT COUNT(*) AS total,
                   SUM(CASE WHEN a.proceso IS NOT NULL AND TRIM(a.proceso) <> ''
                            THEN 1 ELSE 0 END) AS con_proceso,
                   SUM(CASE WHEN EXISTS (SELECT 1 FROM aplicabilidad ap
                                          LEFT JOIN threats t ON t.id = ap.threat_id
                                          WHERE ap.activo_id = a.id AND ap.veredicto = 'afectado'
                                            AND (t.id IS NULL OR t.estado NOT IN ({cerrados}))
                                            {sin_bajas})
                            THEN 1 ELSE 0 END) AS con_vulnerabilidades
              FROM activos a
             WHERE a.presente = 1 AND a.origen = 'servidores'""",
        list(_ESTADOS_CERRADOS)).fetchone()
    return {"total": int(fila["total"] or 0),
            "con_proceso": int(fila["con_proceso"] or 0),
            "con_vulnerabilidades": int(fila["con_vulnerabilidades"] or 0)}


@bp.route("/")
@auth.requiere_admin
def lista():
    procesos = alertas_proceso.listar(g.db)
    parque = _parque_de_servidores(g.db)
    n_servidores = sum(p["servidores"] for p in procesos)
    return render_template(
        "alertas_proceso.html",
        procesos=procesos,
        habilitado=bool(g.cfg.get("alert_procesos_enabled", True)),
        envios=alertas_proceso.envios_recientes(g.db, limite=20),
        # Solo los procesos con servidores presentes en OCS; los configurados que ya no
        # tienen servidores se listan aparte y no cuentan como «procesos de negocio».
        n_procesos=sum(1 for p in procesos if p["disponible"]),
        n_activas=sum(1 for p in procesos if p["activa"]),
        n_con_correo=sum(1 for p in procesos if p["correos"]),
        n_servidores=n_servidores,
        n_vulnerables=sum(p["con_vulnerabilidades"] for p in procesos),
        # El parque completo, para escribir el alcance en la propia cifra (2026-09-15).
        parque=parque,
        n_sin_proceso=max(parque["total"] - n_servidores, 0),
    )


@bp.route("/guardar", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def guardar():
    proceso = (request.form.get("proceso") or "").strip()
    correo = (request.form.get("correo") or "").strip()
    activa = _marcado("activa")
    solo_expuestos = _marcado("solo_expuestos")
    try:
        fila = alertas_proceso.guardar(g.db, proceso, correo=correo, activa=activa,
                                       solo_expuestos=solo_expuestos, actor=g.usuario,
                                       ip=request.remote_addr)
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("alertas_proceso.lista"))
    except Exception as exc:  # noqa: BLE001 - nunca una pagina de error al administrador
        flash(f"No se pudo guardar la configuración del proceso «{proceso}»: {exc}", "error")
        return redirect(url_for("alertas_proceso.lista"))
    if fila["activa"]:
        ambito = " (solo producción y contingencia)" if fila["solo_expuestos"] else ""
        flash(f"Alerta del proceso «{fila['proceso']}» activada: se enviará a "
              f"{', '.join(fila['correos'])}{ambito}.", "exito")
    elif fila["correos"]:
        flash(f"Configuración del proceso «{fila['proceso']}» guardada. La alerta queda desactivada; "
              f"el destino {', '.join(fila['correos'])} se conserva.", "exito")
    else:
        flash(f"Configuración del proceso «{fila['proceso']}» guardada sin correo: la alerta queda desactivada.",
              "exito")
    # El SMTP interno rechaza destinatarios de otros dominios: se guarda igual (puede ser un
    # alias que el administrador de correo vaya a crear) pero se avisa, sin bloquear.
    aviso = alertas_proceso.aviso_dominio(fila["correos"], g.cfg)
    if aviso:
        flash(aviso, "aviso")
    return redirect(url_for("alertas_proceso.lista"))


@bp.route("/probar", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def probar():
    """Envia un correo corto al destino configurado del proceso para comprobar que llega."""
    proceso = (request.form.get("proceso") or "").strip()
    cfg = alertas_proceso.configuracion(g.db, proceso) if proceso else None
    if not cfg:
        flash(f"El proceso «{proceso}» no tiene configuración guardada. Guarde primero el correo de destino.",
              "error")
        return redirect(url_for("alertas_proceso.lista"))
    destinos = cfg["correos"]
    if not destinos:
        flash(f"El proceso «{proceso}» no tiene un correo de destino válido. Guarde primero la dirección.",
              "error")
        return redirect(url_for("alertas_proceso.lista"))
    try:
        html = notify.render_admin_email(
            titulo=f"Prueba de la alerta del proceso {proceso}",
            intro=(f"Este mensaje confirma que la dirección configurada para el proceso de negocio "
                   f"«{proceso}» recibe correctamente los correos del sistema de inteligencia de amenazas. "
                   "Cuando haya amenazas nuevas que afecten a servidores de este proceso, llegará a esta "
                   "misma dirección un correo con la lista de esos servidores."),
            severidad="info",
            secciones=[{
                "titulo": "Configuración del proceso",
                "filas": [
                    ("Proceso de negocio", proceso),
                    ("Destino", ", ".join(destinos)),
                    ("Alerta", "activada" if cfg["activa"] else "desactivada"),
                    ("Ámbito", "solo producción y contingencia" if cfg["solo_expuestos"] else "todos los entornos"),
                    ("Solicitado por", g.usuario),
                ],
            }],
            acciones=["No se requiere ninguna acción. Es una prueba manual solicitada desde la interfaz."],
        )
        enviado = notify.Mailer(g.cfg).send(
            subject=f"[Inteligencia de Amenazas] Prueba de la alerta del proceso {proceso}",
            html=html, to=destinos)
    except Exception as exc:  # noqa: BLE001
        flash(f"No se pudo enviar la prueba al proceso «{proceso}»: {type(exc).__name__}: {exc}", "error")
        return redirect(url_for("alertas_proceso.lista"))
    db.audit(g.db, g.usuario, "alertas_proceso.prueba", "alertas_proceso", cfg["id"],
             f"proceso={proceso} destinos={', '.join(destinos)} enviado={int(bool(enviado))}",
             request.remote_addr)
    if enviado:
        flash(f"Correo de prueba del proceso «{proceso}» enviado a {', '.join(destinos)}.", "exito")
    else:
        flash(f"El servidor de correo no aceptó el envío de prueba del proceso «{proceso}». "
              "Compruebe que el destino pertenece al dominio de la empresa y revise el registro.", "error")
    return redirect(url_for("alertas_proceso.lista"))

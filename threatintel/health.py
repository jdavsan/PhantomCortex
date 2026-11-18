"""Salud de las fuentes y del sistema.

Este modulo existe por el hallazgo principal de la auditoria: 10 de las 35
fuentes llevaban mas de 33 dias fallando al 100 % (las tres de CISA y la de NVD
entre ellas) y nadie lo sabia, porque el recolector envolvia cada fuente en
`except Exception: continue` y luego imprimia "35 fuentes (100 % funcionales)".

La causa raiz no era la URL rota: era la ausencia de cualquier mecanismo que
avisara al operador. Eso es lo que se arregla aqui.
"""
from __future__ import annotations

import shutil
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from . import db
from .logging_setup import get_logger
from .paths import DB_FILE, LOGS_DIR

log = get_logger("health")

ESTADO_OK = "ok"
ESTADO_DEGRADADA = "degradada"
ESTADO_CAIDA = "caida"
ESTADO_DESACTIVADA = "desactivada"
ESTADO_SIN_DATOS = "sin_datos"


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
# Salud por fuente
# --------------------------------------------------------------------------
def _es_fallo(registro: dict, cero_es_fallo: bool) -> bool:
    """Criterio UNICO de fallo, usado tanto por la racha como por la tasa.

    Una fuente que responde 200 pero no devuelve ninguna entrada tampoco esta
    aportando nada: contarla como exito daba resultados contradictorios
    ("caida con 100 % de exito"). El ajuste `health_zero_entries_is_failure`
    decide si se aplica este criterio.
    """
    if not registro.get("ok"):
        return True
    return cero_es_fallo and (registro.get("entries") or 0) == 0


def resumen_fuentes(conn: sqlite3.Connection, *, ventana: int = 10,
                    cfg=None) -> list[dict[str, Any]]:
    """Estado de cada fuente sobre sus ultimas `ventana` comprobaciones."""
    racha_alerta = int((cfg.get("health_fail_streak_alert") if cfg else 3) or 3)
    cero_es_fallo = bool(
        cfg.get("health_zero_entries_is_failure") if cfg else True)

    fuentes = [dict(r) for r in conn.execute(
        "SELECT id, slug, name, url, enabled, category, priority, kind, timeout_s "
        "FROM sources ORDER BY name")]
    if not fuentes:
        return []

    # Historial de todas las fuentes en una sola consulta, no una por fuente
    historial: dict[int, list[dict]] = {}
    for fila in conn.execute(
            """SELECT source_id, checked_at, ok, http_status, entries, accepted,
                      latency_ms, error
                 FROM source_health
                ORDER BY source_id, checked_at DESC"""):
        historial.setdefault(fila["source_id"], []).append(dict(fila))

    resultado: list[dict[str, Any]] = []
    for fuente in fuentes:
        registros = historial.get(fuente["id"], [])[:ventana]

        if not fuente["enabled"]:
            situacion = ESTADO_DESACTIVADA
        elif not registros:
            situacion = ESTADO_SIN_DATOS
        else:
            situacion = None      # se decide mas abajo

        total = len(registros)
        exitos = sum(1 for r in registros if not _es_fallo(r, cero_es_fallo))
        # Sin comprobaciones no hay tasa que informar: None, no 0 %
        tasa = (exitos * 100.0 / total) if total else None

        # Racha de fallos consecutivos desde la comprobacion mas reciente
        racha = 0
        for r in registros:
            if _es_fallo(r, cero_es_fallo):
                racha += 1
            else:
                break

        ultimo_ok = next((r["checked_at"] for r in registros
                          if not _es_fallo(r, cero_es_fallo)), None)
        ultimo = registros[0] if registros else {}

        if situacion is None:
            if racha >= racha_alerta:
                situacion = ESTADO_CAIDA
            elif racha > 0 or (tasa is not None and tasa < 60.0):
                situacion = ESTADO_DEGRADADA
            else:
                situacion = ESTADO_OK

        resultado.append({
            **fuente,
            "estado": situacion,
            "comprobaciones": total,
            "exitos": exitos,
            "tasa_exito": None if tasa is None else round(tasa, 1),
            "racha_fallos": racha,
            "ultimo_ok": ultimo_ok,
            "ultima_comprobacion": ultimo.get("checked_at"),
            "ultimo_error": ultimo.get("error"),
            "ultimo_status": ultimo.get("http_status"),
            "ultimas_entradas": ultimo.get("entries"),
            "ultimas_aceptadas": ultimo.get("accepted"),
            "ultima_latencia_ms": ultimo.get("latency_ms"),
        })

    orden = {ESTADO_CAIDA: 0, ESTADO_DEGRADADA: 1, ESTADO_SIN_DATOS: 2,
             ESTADO_OK: 3, ESTADO_DESACTIVADA: 4}
    resultado.sort(key=lambda f: (orden.get(f["estado"], 9), f["name"].lower()))
    return resultado


# --------------------------------------------------------------------------
# Salud del sistema
# --------------------------------------------------------------------------
def resumen_sistema(conn: sqlite3.Connection, *, cfg) -> dict[str, Any]:
    """Panorama completo para el panel de la interfaz y para monitorizacion."""
    fuentes = resumen_fuentes(conn, ventana=10, cfg=cfg)
    conteo = {"total": len(fuentes), "ok": 0, "degradadas": 0, "caidas": 0,
              "desactivadas": 0, "sin_datos": 0}
    for f in fuentes:
        clave = {ESTADO_OK: "ok", ESTADO_DEGRADADA: "degradadas",
                 ESTADO_CAIDA: "caidas", ESTADO_DESACTIVADA: "desactivadas",
                 ESTADO_SIN_DATOS: "sin_datos"}.get(f["estado"])
        if clave:
            conteo[clave] += 1
    conteo["activas"] = conteo["total"] - conteo["desactivadas"]
    # Los feeds y las API se cuentan aparte: la recoleccion diaria solo consulta
    # feeds, asi que mezclarlas hacia que el panel dijera "52 de 80 operativas"
    # comparando lo comprobado contra el total incluidas las desactivadas.
    activas = [f for f in fuentes if f["enabled"]]
    # «Feed» es cualquier fuente que se recolecta como avisos (RSS y la pagina HTML de
    # ColCERT, v6); el resto son APIs de enriquecimiento. Importacion diferida para no
    # crear un ciclo con collector.
    from .collector import TIPOS_RECOLECTABLES
    conteo["feeds"] = sum(1 for f in activas if f.get("kind") in TIPOS_RECOLECTABLES)
    conteo["apis"] = sum(1 for f in activas if f.get("kind") not in TIPOS_RECOLECTABLES)
    conteo["feeds_ok"] = sum(1 for f in activas
                             if f.get("kind") in TIPOS_RECOLECTABLES and f["estado"] == ESTADO_OK)
    conteo["apis_ok"] = sum(1 for f in activas
                            if f.get("kind") not in TIPOS_RECOLECTABLES and f["estado"] == ESTADO_OK)

    # --- credenciales ---
    try:
        from . import credentials
        cred = credentials.estado(conn, cfg=cfg)
    except Exception as exc:  # noqa: BLE001
        cred = {"estado": "desconocido", "mensaje": f"no disponible: {exc}"}

    # --- certificado TLS (2026-09-08) ---
    try:
        from . import certificado
        cert = certificado.estado(cfg=cfg)
    except Exception as exc:  # noqa: BLE001
        cert = {"estado": "error", "estado_es": "No se pudo leer", "ruta": None,
                "mensaje": f"no disponible: {exc}", "dias_restantes": None}

    # --- ultima ejecucion ---
    ultima = conn.execute(
        "SELECT * FROM executions ORDER BY started_at DESC LIMIT 1").fetchone()
    ejecucion = dict(ultima) if ultima else {}

    # --- amenazas ---
    mes = _ahora().strftime("%Y-%m")
    amenazas_mes = conn.execute(
        "SELECT COUNT(*) FROM threats WHERE month=?", (mes,)).fetchone()[0]
    sin_enriquecer = conn.execute(
        "SELECT COUNT(*) FROM threats WHERE cve IS NOT NULL "
        "AND enriched_at IS NULL").fetchone()[0]
    sin_alertar = conn.execute(
        "SELECT COUNT(*) FROM threats WHERE alerted_at IS NULL "
        "AND severity IN ('Critical','High')").fetchone()[0]

    # --- inventario ---
    inventario = conn.execute(
        """SELECT COUNT(*) AS total,
                  SUM(CASE WHEN version_installed IS NOT NULL
                            AND version_installed <> '' THEN 1 ELSE 0 END) AS con_version,
                  SUM(enabled) AS activas
             FROM technologies""").fetchone()

    # --- traductor ---
    try:
        from .translate import argos_disponible, ollama_disponible
        ollama_ok, ollama_info = ollama_disponible(cfg)
        traductor = {
            "ok": bool(ollama_ok or argos_disponible()),
            "ollama": bool(ollama_ok),
            "modelo": ollama_info if ollama_ok else None,
            "argos": argos_disponible(),
            "detalle": ollama_info,
        }
    except Exception as exc:  # noqa: BLE001
        traductor = {"ok": False, "detalle": str(exc)}

    # --- disco y base de datos ---
    try:
        uso = shutil.disk_usage(str(DB_FILE.parent))
        disco = {
            "total_gb": round(uso.total / 2**30, 1),
            "libre_gb": round(uso.free / 2**30, 1),
            "usado_pct": round((uso.total - uso.free) * 100.0 / uso.total, 1),
        }
    except OSError:
        disco = {}

    try:
        tamano_db = round(DB_FILE.stat().st_size / 2**20, 1)
    except OSError:
        tamano_db = 0.0

    # --- estado global ---
    # Cada incidencia se guarda con SUJETO, CONSECUENCIA y QUE HACER, no como una frase
    # suelta. El aviso de la portada decia «El sistema funciona con incidencias · 44 de 44
    # fuentes activas operativas · Motivos: Caduca en 4 dias», que junta tres defectos: no
    # dice que caduca, pone al lado lo unico que SI funciona, y no dice que hacer. El
    # usuario lo señalo asi: «no se que debo hacer para que todas funcionen y tampoco es
    # detallado» (2026-09-15). `motivos` se conserva como lista de frases para quien ya la
    # consumia (metricas y correos); `incidencias` es la version con la que se pinta.
    global_estado = ESTADO_OK
    motivos: list[str] = []
    incidencias: list[dict[str, Any]] = []

    def incidencia(clave: str, gravedad: str, titulo: str, consecuencia: str,
                   accion: str, enlace: Optional[str] = None,
                   enlace_es: Optional[str] = None) -> None:
        incidencias.append({"clave": clave, "gravedad": gravedad, "titulo": titulo,
                            "consecuencia": consecuencia, "accion": accion,
                            "enlace": enlace, "enlace_es": enlace_es})
        motivos.append(titulo)

    dias_cred = cred.get("dias_restantes")
    if cred.get("estado") in ("caducada", "fallando"):
        global_estado = "critico"
        incidencia(
            "correo", "critico",
            "La contraseña del buzón desde el que la plataforma envía los correos ya no sirve",
            "Ni la alerta diaria, ni el resumen semanal, ni el informe mensual salen de aquí "
            "hasta que se renueve.",
            "Pida la contraseña nueva a Redes y guárdela en Administración "
            "→ Credenciales. La plataforma la comprueba al guardarla.",
            "credenciales.panel", "Ir a Credenciales")
    elif cred.get("estado") == "por_caducar":
        if global_estado == ESTADO_OK:
            global_estado = "atencion"
        plazo = (f"caduca en {dias_cred} día{'s' if dias_cred != 1 else ''}"
                 if isinstance(dias_cred, int) else "está a punto de caducar")
        incidencia(
            "correo", "atencion",
            f"La contraseña del buzón desde el que la plataforma envía los correos {plazo}",
            "Cuando caduque dejarán de salir la alerta diaria, el resumen semanal y el "
            "informe mensual, sin más aviso que este.",
            "Pida la contraseña nueva a Redes y guárdela en Administración "
            "→ Credenciales antes de esa fecha.",
            "credenciales.panel", "Ir a Credenciales")

    if conteo["caidas"] >= 3:
        global_estado = "critico"
        incidencia(
            "fuentes", "critico",
            f"{conteo['caidas']} fuentes de información llevan varios intentos sin responder",
            "Lo que publiquen esas fuentes no llega a la plataforma, así que puede faltar "
            "alguna amenaza en la alerta.",
            "Abra Administración → Fuentes, mire el motivo de cada una y su última respuesta. "
            "Si es un fallo de la fuente, se recupera sola; si cambió de dirección, hay que "
            "corregirla ahí mismo.",
            "fuentes.lista", "Ir a Fuentes")
    elif conteo["caidas"] or conteo["degradadas"] >= 3:
        if global_estado != "critico":
            global_estado = "atencion"
        partes = []
        if conteo["caidas"]:
            partes.append(f"{conteo['caidas']} sin responder")
        if conteo["degradadas"]:
            partes.append(f"{conteo['degradadas']} respondiendo con fallos")
        incidencia(
            "fuentes", "atencion",
            "Hay fuentes de información con problemas: " + " y ".join(partes),
            "Puede faltar alguna amenaza de esas fuentes mientras no se recuperen.",
            "Abra Administración → Fuentes y revise el motivo de cada una. La mayoría se "
            "recupera sola en la siguiente recolección.",
            "fuentes.lista", "Ir a Fuentes")

    dias_cert = cert.get("dias_restantes")
    # TLS configurado (2026-11-15): servir por HTTP sin cifrar en la red interna es una
    # decision aceptada de este proyecto (riesgo aceptado conocido, vease
    # .claude/skills/auditoria-seguridad/SKILL.md), asi que una instalacion que nunca
    # activo el ajuste «La plataforma se sirve cifrada» (``webui_https``) ni señalo una
    # ruta de certificado propia no tiene nada que vigilar: no encontrar el certificado
    # de fabrica (``certificado.RUTA_POR_OMISION``, que no existe salvo que alguien lo
    # instale ahi) no es una incidencia, porque nunca se configuro HTTPS. Si se activo
    # «webui_https» o se señalo una ruta distinta de la de fabrica, el certificado SI
    # importa aunque «webui_https» siguiera sin marcar (por ejemplo, nginx hace la
    # terminacion TLS con un certificado propio y el ajuste del coleccionista todavia no
    # se marco). Antes de este cambio, una instalacion recien creada sin nada configurado
    # abria con «El sistema funciona, pero hay algo que atender» por un certificado que
    # nadie habia pedido vigilar (hallazgo de 2026-11-15, tests/test_claridad_operacion.py
    # TestAvisoDeSaludConAccion.test_sin_incidencias_no_se_habla_de_incidencias).
    from . import certificado as _certificado
    tls_configurado = bool(cfg.get("webui_https")) or (
        cert.get("ruta") != _certificado.RUTA_POR_OMISION)
    if cert.get("estado") == "caducado":
        global_estado = "critico"
        incidencia(
            "certificado", "critico",
            "El certificado de seguridad de esta plataforma ha caducado",
            "Los navegadores avisarán de que el sitio no es de fiar y algunos bloquearán el "
            "acceso.",
            "Pida el certificado renovado a Redes: ellos lo instalan en el "
            "servidor y recargan el servidor web.",
            "credenciales.panel", "Ver el estado del certificado")
    elif cert.get("estado") == "por_caducar":
        if global_estado == ESTADO_OK:
            global_estado = "atencion"
        plazo = (f"caduca en {dias_cert} día{'s' if dias_cert != 1 else ''}"
                 if isinstance(dias_cert, int) else "está a punto de caducar")
        incidencia(
            "certificado", "atencion",
            f"El certificado de seguridad de esta plataforma {plazo}",
            "Cuando caduque, los navegadores avisarán de que el sitio no es de fiar.",
            "Avise a Redes para que pidan la renovación con tiempo.",
            "credenciales.panel", "Ver el estado del certificado")
    elif cert.get("estado") in ("sin_certificado", "error") and tls_configurado:
        # Sin certificado legible la vigilancia no vigila nada: tambien es «atencion».
        # (si TLS no esta configurado -ver «tls_configurado» arriba- no encontrar el
        # certificado de fabrica no es una incidencia: nunca se pidio vigilarlo).
        if global_estado == ESTADO_OK:
            global_estado = "atencion"
        incidencia(
            "certificado", "atencion",
            "No se puede leer el certificado de seguridad de esta plataforma",
            "Nadie va a avisar de que caduca, porque la comprobación automática no puede "
            "hacerse.",
            "Avise a Redes para que comprueben el certificado instalado en "
            "el servidor.",
            "credenciales.panel", "Ver el estado del certificado")

    if ejecucion.get("status") == "failed":
        global_estado = "critico"
        incidencia(
            "ejecucion", "critico",
            "La última recolección diaria terminó con error",
            "Las amenazas publicadas desde entonces pueden no estar en la plataforma.",
            "Abra Administración → Consultas a OCS para ver qué paso dio error. La siguiente "
            "recolección se ejecuta sola a la hora prevista y suele recuperarse.",
            "sincronizaciones.lista", "Ver las ejecuciones")

    # La comprobación anterior solo mira si la ÚLTIMA fila de `executions` falló; si el
    # cron deja de llamar al script (se borró la tarea, el servidor se reinició y no
    # volvió a programarse, credenciales venció, etc.) nunca se escribe una fila nueva y
    # este chequeo no detecta nada: la última ejecución registrada puede seguir diciendo
    # "success" aunque lleve semanas sin volver a correr. Se compara contra la hora, no
    # contra el estado.
    # Un sistema recien instalado tambien tiene `ejecucion` vacio y no por eso esta
    # averiado: solo se avisa cuando SI hubo una ejecucion antes y el reloj se alejo
    # demasiado de ella.
    inicio_ultima = _parse(ejecucion.get("started_at"))
    if inicio_ultima is not None and _ahora() - inicio_ultima > timedelta(hours=36):
        dias = (_ahora() - inicio_ultima).days
        global_estado = "critico"
        incidencia(
            "ejecucion_ausente", "critico",
            f"La recolección diaria lleva {dias} día{'s' if dias != 1 else ''} sin ejecutarse",
            "Ninguna vulnerabilidad nueva se está detectando ni alertando desde entonces.",
            "Compruebe la tarea programada con «sudo -n -u si crontab -l»: puede haberse "
            "perdido al mover o reinstalar el servidor. Vuelva a programarla y relance "
            "bin/ejecucion_diaria.py para ponerse al día.",
            "sincronizaciones.lista", "Ver las ejecuciones")

    if disco.get("libre_gb") is not None and disco["libre_gb"] < 2:
        global_estado = "critico"
        incidencia(
            "disco", "critico",
            f"Al servidor le quedan {disco['libre_gb']} gigabytes libres de disco",
            "Si se llena, la plataforma dejará de guardar amenazas y de generar informes.",
            "Avise a Redes para que liberen espacio en el servidor.",
            None, None)

    return {
        "generado": db.utcnow(),
        "estado_global": global_estado,
        "motivos": [m for m in motivos if m],
        "incidencias": incidencias,
        "fuentes": conteo,
        "fuentes_detalle": fuentes,
        "credenciales": cred,
        "certificado": cert,
        "ultima_ejecucion": ejecucion,
        "amenazas_mes": amenazas_mes,
        "sin_enriquecer": sin_enriquecer,
        "sin_alertar": sin_alertar,
        "inventario": dict(inventario) if inventario else {},
        "ollama": traductor,
        "disco": disco,
        "db": {"tamano_mb": tamano_db},
        "config": {
            "alert_min_severity": cfg.get("alert_min_severity"),
            "translate_engine": cfg.get("translate_engine"),
            "collect_lookback_days": cfg.get("collect_lookback_days"),
        },
    }


# --------------------------------------------------------------------------
# Avisos
# --------------------------------------------------------------------------
def _ya_avisado(conn: sqlite3.Connection, kind: str, subject_key: str,
                horas: int) -> bool:
    limite = (_ahora() - timedelta(hours=max(1, horas))).replace(
        microsecond=0).isoformat().replace("+00:00", "Z")
    return conn.execute(
        """SELECT 1 FROM admin_notices
            WHERE kind=? AND subject_key=? AND sent_at >= ? LIMIT 1""",
        (kind, subject_key, limite)).fetchone() is not None


def revisar_y_avisar(conn: sqlite3.Connection, *, cfg,
                     mailer=None) -> list[dict[str, Any]]:
    """Avisa de las fuentes caidas agrupandolas en UN solo correo.

    Un correo por fuente convertiria diez fuentes caidas en diez mensajes, y el
    operador dejaria de leerlos. Aqui va uno con la tabla completa.
    """
    from .notify import Mailer, asunto_admin, render_admin_email

    if mailer is None:
        mailer = Mailer(cfg)

    destinatarios = cfg.admin_to
    if not destinatarios:
        log.warning("no hay destinatarios de administracion; no se avisa de "
                    "las fuentes caidas")
        return []

    fuentes = resumen_fuentes(conn, ventana=10, cfg=cfg)
    caidas = [f for f in fuentes if f["estado"] == ESTADO_CAIDA]
    degradadas = [f for f in fuentes if f["estado"] == ESTADO_DEGRADADA]

    if not caidas and len(degradadas) < 3:
        return []

    enfriamiento = int(cfg.get("health_notice_cooldown_h", 24) or 24)
    # La clave del asunto incluye las fuentes implicadas: si cae una nueva, el
    # aviso sale de inmediato aunque otro reciente lo hubiera silenciado.
    clave = "|".join(sorted(f["slug"] for f in caidas)) or "solo_degradadas"
    if _ya_avisado(conn, "source_down", clave, enfriamiento):
        log.debug("aviso de fuentes omitido por periodo de silencio",
                  extra={"caidas": len(caidas)})
        return []

    from .http import describir_error

    def _tabla(lista: list[dict]) -> dict:
        return {
            "cabeceras": ["Fuente", "Fallos seguidos", "Éxito", "Último error",
                          "Última vez correcta"],
            "filas": [[
                f["name"],
                str(f["racha_fallos"]),
                f"{f['tasa_exito']:.0f} %",
                describir_error(f["ultimo_error"]) if f["ultimo_error"] else "—",
                (f["ultimo_ok"] or "nunca")[:10],
            ] for f in lista],
        }

    secciones: list[dict] = []
    if caidas:
        secciones.append({"titulo": f"Fuentes caídas ({len(caidas)})",
                          "tabla": _tabla(caidas)})
    if degradadas:
        secciones.append({"titulo": f"Fuentes degradadas ({len(degradadas)})",
                          "tabla": _tabla(degradadas)})

    total_activas = sum(1 for f in fuentes if f["enabled"])
    operativas = sum(1 for f in fuentes if f["estado"] == ESTADO_OK)
    secciones.append({
        "titulo": "Situación general",
        "filas": [
            ("Fuentes activas", total_activas),
            ("Operativas", operativas),
            ("Caídas", len(caidas)),
            ("Degradadas", len(degradadas)),
            ("Umbral de aviso",
             f"{cfg.get('health_fail_streak_alert', 3)} fallos consecutivos"),
        ]})

    if caidas:
        titulo = (f"{len(caidas)} fuente{'s' if len(caidas) != 1 else ''} de "
                  f"inteligencia sin funcionar")
        severidad = "critical" if len(caidas) >= 3 else "warning"
        intro = (f"{len(caidas)} de las {total_activas} fuentes activas llevan al "
                 f"menos {cfg.get('health_fail_streak_alert', 3)} ejecuciones "
                 f"consecutivas sin aportar datos. Mientras sigan así, la "
                 f"recolección diaria continúa funcionando pero con cobertura "
                 f"reducida, sin generar ningún error visible.")
    else:
        titulo = f"{len(degradadas)} fuentes de inteligencia degradadas"
        severidad = "warning"
        intro = (f"{len(degradadas)} fuentes presentan una tasa de éxito baja o "
                 f"no devuelven entradas de forma persistente.")

    from .config import url_publica
    url = url_publica(cfg, "/fuentes/")

    html = render_admin_email(
        titulo=titulo, intro=intro, severidad=severidad, secciones=secciones,
        acciones=[f"Revisar el estado en {url}",
                  "Usar el botón «Probar» de cada fuente para ver el error exacto",
                  "Corregir la URL o desactivar la fuente si ya no existe"],
        pie=("Este aviso se agrupa en un único mensaje y no se repite durante "
             f"{enfriamiento} horas, salvo que caiga una fuente nueva."))

    if not mailer.send(subject=asunto_admin(titulo, severidad), html=html,
                       to=destinatarios):
        log.error("no se pudo enviar el aviso de fuentes caidas")
        return []

    conn.execute(
        """INSERT OR IGNORE INTO admin_notices(kind, subject_key, sent_at, detail)
           VALUES(?,?,?,?)""",
        ("source_down", clave, db.utcnow(),
         f"caidas={len(caidas)} degradadas={len(degradadas)}"))

    log.info("aviso de fuentes enviado",
             extra={"caidas": len(caidas), "degradadas": len(degradadas)})
    return [{"kind": "source_down", "titulo": titulo, "severidad": severidad,
             "caidas": [f["slug"] for f in caidas]}]


def avisar_ejecucion_fallida(conn: sqlite3.Connection, *, cfg, execution_id: int,
                             error: str, mailer=None) -> bool:
    """Avisa de que una ejecucion programada ha fallado por completo."""
    from .notify import Mailer, asunto_admin, render_admin_email

    if not cfg.admin_to:
        return False
    if mailer is None:
        mailer = Mailer(cfg)

    fila = conn.execute("SELECT * FROM executions WHERE id=?",
                        (execution_id,)).fetchone()
    ejecucion = dict(fila) if fila else {}
    clave = f"exec:{ejecucion.get('kind', 'desconocida')}"

    if _ya_avisado(conn, "run_failed", clave,
                   int(cfg.get("health_notice_cooldown_h", 24) or 24)):
        return False

    titulo = f"La ejecución {ejecucion.get('kind', '')} ha fallado"
    html = render_admin_email(
        titulo=titulo, severidad="critical",
        intro=("Una ejecución programada del sistema de inteligencia de amenazas "
               "ha terminado con error. Hasta que se resuelva, no se están "
               "recolectando ni distribuyendo hallazgos."),
        secciones=[{"titulo": "Detalle de la ejecución", "filas": [
            ("Tipo", ejecucion.get("kind", "—")),
            ("Inicio", ejecucion.get("started_at", "—")),
            ("Estado", ejecucion.get("status", "—")),
            ("Fuentes correctas", ejecucion.get("sources_ok", 0)),
            ("Fuentes con fallo", ejecucion.get("sources_failed", 0)),
            ("Registro", ejecucion.get("log_path") or str(LOGS_DIR)),
            ("Error", (error or "")[:500]),
        ]}],
        acciones=["Consultar logs/threatintel.jsonl para ver la traza completa",
                  "Comprobar el estado del sistema en la interfaz de administración"])

    if not mailer.send(subject=asunto_admin(titulo, "critical"), html=html,
                       to=cfg.admin_to):
        return False

    conn.execute(
        """INSERT OR IGNORE INTO admin_notices(kind, subject_key, sent_at, detail)
           VALUES(?,?,?,?)""",
        ("run_failed", clave, db.utcnow(), (error or "")[:400]))
    return True


# --------------------------------------------------------------------------
# Metricas planas para monitorizacion
# --------------------------------------------------------------------------
def exportar_metricas(conn: sqlite3.Connection, *, cfg) -> dict[str, Any]:
    """Diccionario plano apto para Zabbix.

    Este servidor ya tiene agente Zabbix en el puerto 10050 y un cron
    `zbx_salud`, asi que exponer las metricas aqui evita escribir un colector
    aparte: basta con consultar /salud.json.
    """
    resumen = resumen_sistema(conn, cfg=cfg)
    fuentes = resumen["fuentes"]
    cred = resumen["credenciales"]
    inventario = resumen.get("inventario") or {}

    mapa_estado = {"ok": 0, "atencion": 1, "critico": 2}
    mapa_cred = {"ok": 0, "por_caducar": 1, "caducada": 2, "fallando": 2}

    metricas: dict[str, Any] = {
        "ti.estado": mapa_estado.get(resumen["estado_global"], 3),
        "ti.estado_texto": resumen["estado_global"],
        "ti.fuentes.total": fuentes["total"],
        "ti.fuentes.activas": fuentes["activas"],
        "ti.fuentes.ok": fuentes["ok"],
        "ti.fuentes.degradadas": fuentes["degradadas"],
        "ti.fuentes.caidas": fuentes["caidas"],
        "ti.credencial.estado": mapa_cred.get(cred.get("estado"), 3),
        "ti.credencial.dias_restantes": cred.get("dias_restantes"),
        "ti.credencial.fallos": cred.get("consecutive_failures", 0),
        "ti.certificado.estado": {"ok": 0, "por_caducar": 1, "caducado": 2}.get(
            (resumen.get("certificado") or {}).get("estado"), 3),
        "ti.certificado.dias_restantes": (resumen.get("certificado") or {}).get("dias_restantes"),
        "ti.amenazas.mes": resumen["amenazas_mes"],
        "ti.amenazas.sin_enriquecer": resumen["sin_enriquecer"],
        "ti.amenazas.sin_alertar": resumen["sin_alertar"],
        "ti.inventario.total": inventario.get("total", 0),
        "ti.inventario.con_version": inventario.get("con_version", 0),
        "ti.db.tamano_mb": resumen["db"]["tamano_mb"],
        "ti.disco.libre_gb": (resumen.get("disco") or {}).get("libre_gb"),
        "ti.traductor.ok": 1 if resumen["ollama"].get("ok") else 0,
    }

    # Excepciones con vencimiento (2026-09-10): una aceptacion de riesgo vencida sin
    # decision es un fallo de gestion que Zabbix tiene que poder vigilar sin entrar en la
    # interfaz (la vulnerabilidad ya volvio sola a la cola, pero nadie decidio nada), y
    # las que vencen pronto son el trabajo de la semana. Se leen del propio modulo, con la
    # MISMA definicion de vencimiento que la pagina y el correo. Si la base es anterior a
    # la version 13 del esquema no existe la tabla: las metricas valen None y /salud.json
    # sigue respondiendo.
    try:
        from . import excepciones as _excepciones
        # ``con_cubiertas=False``: el resumen sin la cifra que recorre ``aplicabilidad``.
        # Medido el 2026-09-10 sobre una copia de la base real, esa sola cifra costaba 78
        # de los 89 milisegundos de /salud.json, que Zabbix consulta cada minuto; sin
        # ella la respuesta vuelve a los 11 milisegundos de antes.
        exc = _excepciones.resumen(conn, con_cubiertas=False)
        metricas["ti.excepciones.vencidas"] = int(exc.get("vencidas") or 0)
        metricas["ti.excepciones.por_vencer"] = int(exc.get("por_vencer") or 0)
        # Cuanto riesgo hay aceptado ahora mismo (vulnerabilidades que desaparecen de las
        # cifras por una excepcion vigente): si esta serie crece, la organizacion esta
        # aplazando trabajo, no reduciendolo. Solo se calcula si HAY alguna excepcion
        # vigente; sin ninguna vale cero sin tocar ``aplicabilidad``, que es el caso
        # normal y el que tiene que ser barato.
        metricas["ti.excepciones.vulnerabilidades_cubiertas"] = int(
            _excepciones.vulnerabilidades_cubiertas(conn) or 0)
    except sqlite3.OperationalError:
        metricas["ti.excepciones.vencidas"] = None
        metricas["ti.excepciones.por_vencer"] = None
        metricas["ti.excepciones.vulnerabilidades_cubiertas"] = None

    ejecucion = resumen.get("ultima_ejecucion") or {}
    metricas["ti.ejecucion.estado"] = {
        "success": 0, "partial": 1, "running": 0, "failed": 2,
    }.get(ejecucion.get("status"), 3)

    inicio = _parse(ejecucion.get("started_at"))
    metricas["ti.ejecucion.horas_desde"] = (
        round((_ahora() - inicio).total_seconds() / 3600, 1) if inicio else None)

    return metricas


# --------------------------------------------------------------------------
# Limpieza
# --------------------------------------------------------------------------
def limpiar_logs(cfg) -> dict[str, Any]:
    """Borra los ficheros de log mas antiguos que `log_retention_days`.

    Antes este ajuste se mostraba en la interfaz pero NADIE lo leia: el cron
    borraba con un `find -mtime +30` fijo, asi que cambiarlo no tenia efecto.
    Es el mismo defecto que la auditoria reprocho al sistema anterior, y no
    tiene sentido repetirlo.
    """
    dias = int(cfg.get("log_retention_days", 30) or 30)
    limite = _ahora() - timedelta(days=dias)
    resultado = {"borrados": 0, "bytes_liberados": 0, "dias": dias}

    for fichero in LOGS_DIR.glob("*"):
        if not fichero.is_file():
            continue
        # Los .jsonl los rota RotatingFileHandler: no se tocan los activos
        if fichero.suffix == ".jsonl" and not fichero.name[-1].isdigit():
            continue
        try:
            marca = datetime.fromtimestamp(fichero.stat().st_mtime, timezone.utc)
            if marca < limite:
                tamano = fichero.stat().st_size
                fichero.unlink()
                resultado["borrados"] += 1
                resultado["bytes_liberados"] += tamano
        except OSError as exc:
            log.warning("no se pudo borrar un log antiguo",
                        extra={"fichero": fichero.name, "error": str(exc)})

    if resultado["borrados"]:
        log.info("logs antiguos eliminados", extra=resultado)
    return resultado


def limpiar_historico(conn: sqlite3.Connection, *, cfg) -> dict[str, int]:
    """Aplica la retencion configurada a los datos y a los logs."""
    dias_datos = int(cfg.get("data_retention_days", 400) or 400)
    limite_datos = (_ahora() - timedelta(days=dias_datos)).replace(
        microsecond=0).isoformat().replace("+00:00", "Z")

    # El historial de salud crece rapido y solo interesa el pasado reciente
    limite_salud = (_ahora() - timedelta(days=90)).replace(
        microsecond=0).isoformat().replace("+00:00", "Z")

    borrados = {
        "amenazas": conn.execute(
            "DELETE FROM threats WHERE first_seen_at < ?",
            (limite_datos,)).rowcount or 0,
        "salud_fuentes": conn.execute(
            "DELETE FROM source_health WHERE checked_at < ?",
            (limite_salud,)).rowcount or 0,
        "ejecuciones": conn.execute(
            "DELETE FROM executions WHERE started_at < ?",
            (limite_salud,)).rowcount or 0,
        "avisos": conn.execute(
            "DELETE FROM admin_notices WHERE sent_at < ?",
            (limite_salud,)).rowcount or 0,
        "auditoria": conn.execute(
            "DELETE FROM audit_log WHERE at < ?",
            (limite_datos,)).rowcount or 0,
        "cache_traduccion": conn.execute(
            "DELETE FROM translation_cache WHERE created_at < ?",
            (limite_datos,)).rowcount or 0,
        # Sesiones web caducadas: la caducidad se comprueba al usarlas, pero las
        # filas de sesiones abandonadas sin cerrar quedarian para siempre.
        "sesiones_web": conn.execute(
            "DELETE FROM web_sessions WHERE expires_at <= ?",
            (db.utcnow(),)).rowcount or 0,
    }

    logs = limpiar_logs(cfg)
    borrados["logs"] = logs["borrados"]

    log.info("limpieza de historico", extra={**borrados,
                                             "retencion_dias": dias_datos,
                                             "retencion_logs": logs["dias"]})
    return borrados

"""Alertas por proceso de negocio (tabla ``alertas_proceso``, esquema v6).

Cada servidor pertenece a un proceso (campo TAG de OCS, columna ``activos.proceso``).
Ademas del correo general de alerta al equipo de seguridad, cada proceso puede tener su
propio destinatario y recibir SOLO las amenazas que afectan a SUS servidores, con la
lista de esos servidores (nombre, IP, entorno, paquete y versiones). Se activa y
desactiva por proceso; el ajuste ``alert_procesos_enabled`` apaga todas. Se envia justo
despues del correo general, con las mismas amenazas «pendientes» de la ejecucion diaria
(``bin/ejecucion_diaria.py``, marca «v6»).

Un servidor cuenta como afectado cuando ``aplicabilidad`` tiene una fila con veredicto
``afectado`` para esa amenaza y el activo sigue presente en OCS. Con ``solo_expuestos``
solo se tienen en cuenta los entornos de produccion y contingencia
(``ocs.ENTORNOS_EXPUESTOS``).
"""
from __future__ import annotations

import json
import re
import sqlite3
from typing import Any, Optional, Sequence

from . import config, db, notify
from .logging_setup import get_logger
from .ocs import ENTORNO_ES, ENTORNOS_EXPUESTOS

log = get_logger("alertas_proceso")

_EXPUESTO_SQL = "(" + ",".join("'" + e + "'" for e in ENTORNOS_EXPUESTOS) + ")"
_SEPARADOR_CORREOS = re.compile(r"[,;\s]+")


# --------------------------------------------------------------------------
# Consulta
# --------------------------------------------------------------------------
def incluir_bajas(conn: sqlite3.Connection) -> bool:
    """Si la severidad Baja cuenta, segun el ajuste ``ignore_low_severity`` de la base.

    Se lee de la tabla ``settings`` con la MISMA conexion que la consulta (igual que hace
    ``config.load``), no de un valor recibido: asi cualquiera que llame a
    :func:`procesos_disponibles` (la pagina de Alertas por proceso, ``listar``,
    ``guardar`` o la ejecucion diaria) cuenta lo mismo que Amenazas y que el Panel sin
    tener que acordarse de pasar el ajuste. Si el ajuste no esta guardado, se aplica la
    regla interna: las bajas no se reportan.
    """
    return not bool(db.get_setting(conn, "ignore_low_severity", True))


def procesos_disponibles(conn: sqlite3.Connection, *,
                         incluir_severidad_baja: Optional[bool] = None) -> list[dict]:
    """Procesos presentes en OCS con sus recuentos.

    Devuelve [{"proceso", "servidores", "expuestos", "con_vulnerabilidades"}] ordenados por
    nombre: ``servidores`` son los activos presentes del proceso, ``expuestos`` los que estan
    en produccion o contingencia y ``con_vulnerabilidades`` los que tienen alguna
    vulnerabilidad viva de las que si se reportan.

    Las amenazas descartadas, falsas y mitigadas quedan siempre fuera, como en Amenazas y en
    el Panel: sin ese filtro este apartado decia «Pila 171» y Amenazas «170» del mismo
    proceso (revision de precision del 2026-09-09).

    La severidad Baja queda fuera cuando el ajuste ``ignore_low_severity`` esta activo, que
    es lo normal. Hasta el 2026-09-09 la condicion ``t.severity <> 'Low'`` estaba fija en
    esta consulta y NO miraba el ajuste: al desactivarlo, «Procesos disponibles» seguia sin
    contar las bajas mientras Amenazas y el Panel si las contaban, y los dos numeros del
    mismo proceso discrepaban sin explicacion (revision de seguridad del 2026-09-09).
    ``incluir_severidad_baja`` fuerza el criterio (las pruebas lo usan para fijar los dos
    estados); con ``None`` se lee el ajuste de la propia base con :func:`incluir_bajas`.
    """
    con_bajas = incluir_bajas(conn) if incluir_severidad_baja is None else bool(incluir_severidad_baja)
    sin_bajas = "" if con_bajas else " AND (t.severity IS NULL OR t.severity <> 'Low')"
    filas = conn.execute(
        f"""SELECT a.proceso AS proceso,
                   COUNT(*) AS servidores,
                   SUM(CASE WHEN a.entorno IN {_EXPUESTO_SQL} THEN 1 ELSE 0 END) AS expuestos,
                   SUM(CASE WHEN EXISTS (SELECT 1 FROM aplicabilidad ap
                                          LEFT JOIN threats t ON t.id = ap.threat_id
                                          WHERE ap.activo_id = a.id AND ap.veredicto = 'afectado'
                                            AND (t.id IS NULL OR t.estado NOT IN
                                                 ('descartada','falso_positivo','mitigada')){sin_bajas})
                            THEN 1 ELSE 0 END) AS con_vulnerabilidades
              FROM activos a
             WHERE a.presente = 1 AND a.proceso IS NOT NULL AND TRIM(a.proceso) <> ''
             GROUP BY a.proceso
             ORDER BY a.proceso COLLATE NOCASE""").fetchall()
    return [{"proceso": r["proceso"], "servidores": int(r["servidores"] or 0),
             "expuestos": int(r["expuestos"] or 0),
             "con_vulnerabilidades": int(r["con_vulnerabilidades"] or 0)} for r in filas]


def _fila_config(fila: sqlite3.Row) -> dict:
    d = dict(fila)
    d["activa"] = bool(d.get("activa"))
    d["solo_expuestos"] = bool(d.get("solo_expuestos"))
    d["correos"] = config.split_emails(d.get("correo"))
    return d


def configuracion(conn: sqlite3.Connection, proceso: str) -> Optional[dict]:
    """Configuracion guardada de un proceso, o None si nunca se ha configurado."""
    fila = conn.execute("SELECT * FROM alertas_proceso WHERE proceso=?", (proceso,)).fetchone()
    return _fila_config(fila) if fila else None


def listar(conn: sqlite3.Connection, *,
           incluir_severidad_baja: Optional[bool] = None) -> list[dict]:
    """Configuracion actual por proceso: todos los procesos disponibles en OCS fusionados
    con su fila de ``alertas_proceso``. Los no configurados aparecen inactivos y sin correo.
    Un proceso configurado que ya no tiene servidores en OCS se conserva al final con
    ``disponible=False`` para que el administrador pueda verlo y desactivarlo.

    ``incluir_severidad_baja`` se pasa tal cual a :func:`procesos_disponibles`; con ``None``
    (lo normal) manda el ajuste ``ignore_low_severity`` guardado en la base."""
    guardadas = {r["proceso"]: _fila_config(r)
                 for r in conn.execute("SELECT * FROM alertas_proceso ORDER BY proceso COLLATE NOCASE")}
    salida: list[dict] = []
    vistos: set[str] = set()
    for p in procesos_disponibles(conn, incluir_severidad_baja=incluir_severidad_baja):
        cfg = guardadas.get(p["proceso"]) or {}
        vistos.add(p["proceso"])
        salida.append({
            **p,
            "id": cfg.get("id"),
            "correo": cfg.get("correo") or "",
            "correos": cfg.get("correos") or [],
            "activa": bool(cfg.get("activa")),
            "solo_expuestos": bool(cfg.get("solo_expuestos")),
            "configurado": bool(cfg),
            "disponible": True,
            "creado_at": cfg.get("creado_at"),
            "actualizado_at": cfg.get("actualizado_at"),
            "ultimo_envio_at": cfg.get("ultimo_envio_at"),
            "ultimo_envio_n": cfg.get("ultimo_envio_n"),
        })
    for nombre, cfg in guardadas.items():
        if nombre in vistos:
            continue
        salida.append({
            "proceso": nombre, "servidores": 0, "expuestos": 0, "con_vulnerabilidades": 0,
            "id": cfg.get("id"), "correo": cfg.get("correo") or "", "correos": cfg.get("correos") or [],
            "activa": bool(cfg.get("activa")), "solo_expuestos": bool(cfg.get("solo_expuestos")),
            "configurado": True, "disponible": False,
            "creado_at": cfg.get("creado_at"), "actualizado_at": cfg.get("actualizado_at"),
            "ultimo_envio_at": cfg.get("ultimo_envio_at"), "ultimo_envio_n": cfg.get("ultimo_envio_n"),
        })
    return salida


def envios_recientes(conn: sqlite3.Connection, *, limite: int = 20,
                     proceso: Optional[str] = None) -> list[dict]:
    """Ultimos envios registrados en ``alertas_proceso_envios`` (mas recientes primero)."""
    condicion, parametros = "", []
    if proceso:
        condicion, parametros = " WHERE proceso=?", [proceso]
    filas = conn.execute(
        f"SELECT * FROM alertas_proceso_envios{condicion} ORDER BY enviado_at DESC, id DESC LIMIT ?",
        parametros + [int(limite)]).fetchall()
    salida = []
    for r in filas:
        d = dict(r)
        try:
            d["threat_ids"] = [int(x) for x in json.loads(d.get("threat_ids") or "[]")]
        except (ValueError, TypeError):
            d["threat_ids"] = []
        salida.append(d)
    return salida


# --------------------------------------------------------------------------
# Configuracion
# --------------------------------------------------------------------------
def normalizar_correos(correo: Optional[str]) -> list[str]:
    """Valida uno o varios correos separados por coma, punto y coma o espacio.

    A diferencia de ``config.split_emails`` (que descarta en silencio lo que no parece un
    correo), aqui una direccion mal escrita es un error: el administrador debe enterarse
    de que el destino no se guardo tal como lo escribio."""
    texto = (correo or "").strip()
    if not texto:
        return []
    validos = config.split_emails(texto)
    minusculas = {v.lower() for v in validos}
    for parte in _SEPARADOR_CORREOS.split(texto):
        limpio = parte.strip().strip("<>").strip()
        if limpio and limpio.lower() not in minusculas:
            raise ValueError(f"La dirección «{limpio}» no es un correo válido (nombre@dominio).")
    return validos


def dominio_empresa(cfg: Any) -> Optional[str]:
    """Dominio de correo de la empresa, tomado del primer destinatario de ``alert_to``
    (``ALERT_EMAIL_TO`` en credentials.env). El SMTP interno solo acepta destinatarios de
    ese dominio; con una configuracion sin destinatarios devuelve None (sin aviso)."""
    if cfg is None:
        return None
    destinos = getattr(cfg, "alert_to", None)
    if destinos is None and hasattr(cfg, "get"):
        destinos = cfg.get("alert_to")
    if isinstance(destinos, str):
        destinos = config.split_emails(destinos)
    for destino in destinos or []:
        texto = str(destino or "").strip()
        if "@" in texto:
            dominio = texto.rsplit("@", 1)[1].strip().lower().strip(".")
            if dominio:
                return dominio
    return None


def correos_fuera_de_dominio(correos: Sequence[str], cfg: Any) -> list[str]:
    """Correos de ``correos`` cuyo dominio no es el de la empresa (ni un subdominio suyo).
    Lista vacia si no se conoce el dominio de la empresa."""
    dominio = dominio_empresa(cfg)
    if not dominio:
        return []
    fuera: list[str] = []
    for correo in correos or []:
        texto = str(correo or "").strip()
        if "@" not in texto:
            continue
        propio = texto.rsplit("@", 1)[1].lower().strip(".")
        if propio != dominio and not propio.endswith("." + dominio):
            fuera.append(texto)
    return fuera


def aviso_dominio(correos: Sequence[str], cfg: Any) -> Optional[str]:
    """Texto del aviso (no error) para la interfaz cuando algun correo es de otro dominio."""
    fuera = correos_fuera_de_dominio(correos, cfg)
    if not fuera:
        return None
    dominio = dominio_empresa(cfg)
    plural = len(fuera) != 1
    return (f"El servidor de correo interno solo acepta destinatarios del dominio {dominio}; "
            f"compruebe {'las direcciones' if plural else 'la dirección'} {', '.join(fuera)}: "
            f"{'podrían' if plural else 'podría'} no recibir la alerta.")


def guardar(conn: sqlite3.Connection, proceso: str, *, correo: Optional[str], activa: bool,
            solo_expuestos: bool = False, actor: str = "sistema", ip: Optional[str] = None) -> dict:
    """Crea o actualiza la configuracion de un proceso. Valida el correo. Audita.

    Lanza ``ValueError`` con un mensaje en español si el proceso no existe en el
    inventario, si alguna direccion no es valida o si se intenta activar sin correo."""
    nombre = (proceso or "").strip()
    if not nombre:
        raise ValueError("Debe indicar el proceso de negocio.")
    # Aqui solo interesan los NOMBRES de los procesos con servidores presentes: la lista
    # es la misma con las bajas dentro o fuera, asi que se deja el criterio por omision.
    disponibles = {p["proceso"] for p in procesos_disponibles(conn)}
    ya_configurado = conn.execute("SELECT 1 FROM alertas_proceso WHERE proceso=?", (nombre,)).fetchone()
    if nombre not in disponibles:
        if not ya_configurado:
            raise ValueError(f"El proceso «{nombre}» no existe en el inventario de OCS.")
        if activa:
            # Configurado en su dia pero sin servidores presentes hoy: se puede desactivar o
            # borrar su correo, nunca volver a activar (no habria nada que avisar y el
            # administrador creeria que la alerta funciona).
            raise ValueError(f"El proceso «{nombre}» ya no tiene servidores en OCS Inventory: no se puede "
                             "activar su alerta. Puede desactivarla o borrar su correo de destino.")
    correos = normalizar_correos(correo)
    if activa and not correos:
        raise ValueError(f"Para activar la alerta del proceso «{nombre}» debe indicar al menos un correo de destino.")
    correo_txt = ", ".join(correos) if correos else None
    ahora = db.utcnow()
    conn.execute(
        """INSERT INTO alertas_proceso(proceso, correo, activa, solo_expuestos, creado_at, actualizado_at)
           VALUES(?,?,?,?,?,?)
           ON CONFLICT(proceso) DO UPDATE SET correo=excluded.correo, activa=excluded.activa,
                solo_expuestos=excluded.solo_expuestos, actualizado_at=excluded.actualizado_at""",
        (nombre, correo_txt, 1 if activa else 0, 1 if solo_expuestos else 0, ahora, ahora))
    fila = conn.execute("SELECT * FROM alertas_proceso WHERE proceso=?", (nombre,)).fetchone()
    db.audit(conn, actor, "alertas_proceso.guardar", "alertas_proceso", fila["id"],
             f"proceso={nombre} correo={correo_txt or '-'} activa={int(bool(activa))} "
             f"solo_expuestos={int(bool(solo_expuestos))}", ip)
    return _fila_config(fila)


# --------------------------------------------------------------------------
# Envio
# --------------------------------------------------------------------------
def asunto(proceso: str, n_amenazas: int, n_activos: int, fecha: Any = None) -> str:
    """«[Inteligencia de Amenazas] Proceso X: N amenazas afectan a M servidores · 5 de septiembre de 2026»."""
    amenazas = f"{notify.numero(n_amenazas)} amenaza{'s' if n_amenazas != 1 else ''}"
    verbo = "afectan" if n_amenazas != 1 else "afecta"
    servidores = f"{notify.numero(n_activos)} servidor{'es' if n_activos != 1 else ''}"
    return (f"[Inteligencia de Amenazas] Proceso {proceso}: {amenazas} {verbo} a {servidores} · "
            f"{notify.fecha_larga(fecha)}")


def servidores_afectados(conn: sqlite3.Connection, threat_ids: Sequence[int]) -> dict[str, dict[int, list[dict]]]:
    """{proceso: {threat_id: [servidor, ...]}} con los servidores presentes que tienen la version
    vulnerable de cada amenaza. Una fila por servidor y paquete, ordenadas por nombre."""
    ids = [int(i) for i in threat_ids if i is not None]
    salida: dict[str, dict[int, list[dict]]] = {}
    for lote in range(0, len(ids), 800):
        trozo = ids[lote:lote + 800]
        for r in conn.execute(
                f"""SELECT ap.threat_id, a.id AS activo_id, a.nombre, a.ip, a.entorno, a.proceso, a.so_nombre,
                           a.origen, ap.paquete, ap.version_instalada, ap.version_corregida, ap.aviso
                      FROM aplicabilidad ap JOIN activos a ON a.id = ap.activo_id
                     WHERE ap.veredicto = 'afectado' AND a.presente = 1
                       AND a.proceso IS NOT NULL AND TRIM(a.proceso) <> ''
                       AND ap.threat_id IN ({','.join('?' * len(trozo))})
                     ORDER BY a.nombre COLLATE NOCASE, ap.paquete""", trozo):
            entorno = r["entorno"] or ""
            salida.setdefault(r["proceso"], {}).setdefault(int(r["threat_id"]), []).append({
                "activo_id": r["activo_id"], "nombre": r["nombre"], "ip": r["ip"],
                "entorno": entorno, "entorno_es": ENTORNO_ES.get(entorno, "Sin entorno"),
                "expuesto": entorno in ENTORNOS_EXPUESTOS, "so_nombre": r["so_nombre"],
                "origen": r["origen"], "paquete": r["paquete"] or "",
                "version_instalada": r["version_instalada"], "version_corregida": r["version_corregida"],
                "aviso": r["aviso"],
            })
    return salida


def amenazas_de_proceso(pendientes: Sequence[dict], por_amenaza: dict[int, list[dict]], *,
                        solo_expuestos: bool = False) -> tuple[list[dict], int]:
    """Filtra ``pendientes`` a las amenazas con servidores del proceso (respetando el orden
    de entrada) y adjunta a cada una ``servidores`` y ``n_servidores``. Devuelve
    (amenazas, numero de servidores distintos)."""
    seleccion: list[dict] = []
    distintos: set[int] = set()
    for amenaza in pendientes:
        tid = amenaza.get("id")
        if tid is None:
            continue
        servidores = por_amenaza.get(int(tid)) or []
        if solo_expuestos:
            servidores = [s for s in servidores if s["expuesto"]]
        if not servidores:
            continue
        copia = dict(amenaza)
        copia["servidores"] = servidores
        copia["n_servidores"] = len({s["activo_id"] for s in servidores})
        seleccion.append(copia)
        distintos.update(s["activo_id"] for s in servidores)
    return seleccion, len(distintos)


def enviar(conn: sqlite3.Connection, cfg: Any, mailer: Any, pendientes: Sequence[dict], *,
           url_base: str = "", dry_run: bool = False, ahora: Optional[str] = None) -> list[dict]:
    """Envia a cada proceso activo con correo su alerta con las amenazas de ``pendientes`` que
    afectan a sus servidores. Devuelve una lista de {"proceso", "correo", "enviado", "n_amenazas",
    "n_activos", "error"}; los procesos sin amenazas propias figuran con ``enviado=False`` y
    sin error (no se les envia nada). Con ``dry_run`` no se registra nada en la base: el envio
    lo simula el propio ``Mailer`` construido en modo dry-run por la ejecucion diaria.
    Nunca lanza una excepcion por un proceso: la captura y la devuelve en ``error``."""
    resultados: list[dict] = []
    if cfg is not None and not cfg.get("alert_procesos_enabled", True):
        return resultados
    configuradas = [_fila_config(r) for r in conn.execute(
        "SELECT * FROM alertas_proceso WHERE activa=1 AND correo IS NOT NULL AND TRIM(correo) <> '' "
        "ORDER BY proceso COLLATE NOCASE")]
    if not configuradas or not pendientes:
        return resultados
    momento = ahora or db.utcnow()
    try:
        # Se admiten diccionarios y filas sqlite3.Row (no tienen .get): todo a dict, en
        # copia, para no alterar las amenazas del llamador al normalizar el identificador.
        pendientes = [dict(a) for a in pendientes]
        ids: list[int] = []
        for a in pendientes:
            if a.get("id") is None:
                continue
            ids.append(int(a["id"]))
            a["id"] = ids[-1]
        por_proceso = servidores_afectados(conn, ids)
    except Exception as exc:  # noqa: BLE001 - la ejecucion diaria no debe caer por esto
        log.error("no se pudieron leer los servidores afectados por proceso", extra={"error": str(exc)},
                  exc_info=True)
        detalle = ("base de datos" if isinstance(exc, sqlite3.Error) else "amenazas pendientes no legibles")
        return [{"proceso": c["proceso"], "correo": c["correo"], "enviado": False, "n_amenazas": 0,
                 "n_activos": 0, "error": f"{detalle}: {type(exc).__name__}: {exc}"} for c in configuradas]
    base = str(url_base or "").rstrip("/")
    try:
        maximo = int((cfg.get("alert_max_items", 25) if cfg is not None else 25) or 25)
    except (TypeError, ValueError):
        maximo = 25
    for c in configuradas:
        proceso = c["proceso"]
        resultado = {"proceso": proceso, "correo": c["correo"], "enviado": False,
                     "n_amenazas": 0, "n_activos": 0, "error": None}
        try:
            correos = c["correos"]
            if not correos:
                resultado["error"] = "el correo de destino guardado no es válido"
                resultados.append(resultado)
                continue
            amenazas, n_activos = amenazas_de_proceso(pendientes, por_proceso.get(proceso) or {},
                                                      solo_expuestos=c["solo_expuestos"])
            resultado["n_amenazas"], resultado["n_activos"] = len(amenazas), n_activos
            if not amenazas:
                resultados.append(resultado)
                continue
            asunto_txt = asunto(proceso, len(amenazas), n_activos, momento)
            html = notify.render_alert_email_proceso(proceso, ", ".join(correos), amenazas, {
                "url_base": base, "n_activos": n_activos, "solo_expuestos": c["solo_expuestos"],
                "fecha": momento, "max_detalle": maximo})
            enviado = bool(mailer.send(subject=asunto_txt, html=html, to=correos))
            resultado["enviado"] = enviado
            if not enviado:
                resultado["error"] = "el servidor de correo no aceptó el envío"
            elif not dry_run:
                ids = [int(a["id"]) for a in amenazas]
                conn.execute(
                    """INSERT INTO alertas_proceso_envios(proceso, correo, enviado_at, n_amenazas, n_activos,
                                                          asunto, threat_ids) VALUES(?,?,?,?,?,?,?)""",
                    (proceso, ", ".join(correos), momento, len(amenazas), n_activos, asunto_txt,
                     json.dumps(ids)))
                conn.execute("UPDATE alertas_proceso SET ultimo_envio_at=?, ultimo_envio_n=? WHERE id=?",
                             (momento, len(amenazas), c["id"]))
                db.audit(conn, "sistema", "alertas_proceso.envio", "alertas_proceso", c["id"],
                         f"proceso={proceso} correo={', '.join(correos)} amenazas={len(amenazas)} "
                         f"servidores={n_activos}", None)
        except Exception as exc:  # noqa: BLE001 - un proceso no debe tumbar a los demas
            log.error("fallo la alerta por proceso", extra={"proceso": proceso, "error": str(exc)},
                      exc_info=True)
            resultado["error"] = f"{type(exc).__name__}: {exc}"
        resultados.append(resultado)
    return resultados


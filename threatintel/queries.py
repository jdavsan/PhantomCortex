"""Consultas de lectura. Produce el diccionario canonico `ThreatView`.

Todo lo que consume amenazas (correos, informe, GUI) pasa por aqui, para que la
forma del dato sea la misma en todas partes. Las tecnologias y fuentes se cargan
en lote (no una consulta por amenaza) porque con 2000 amenazas al mes el patron
N+1 se nota.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

from . import db, excepciones, identity

_THREAT_COLS = """
    id, fingerprint, cve, title_en, title_es, summary_en, summary_es,
    severity, severity_source, cvss_score, cvss_vector, cvss_version,
    epss_score, in_kev, kev_due_date, published_at, first_seen_at,
    last_seen_at, times_seen, impact_es, remediation_es,
    translation_engine, enriched_at, month, alerted_at, relevance,
    estado, estado_at, estado_por, estado_motivo, digest_at, alert_skip_reason,
    descripcion_origen, descripcion_buscada_at
"""

SEVERIDAD_ORDEN = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

# Estados operativos de una amenaza (gestion desde la interfaz). Los dos ultimos
# la excluyen de alertas, resumenes e informes como hallazgo vivo.
ESTADOS = ("nueva", "en_analisis", "mitigada", "aceptada", "descartada", "falso_positivo")
ESTADOS_CERRADOS = ("descartada", "falso_positivo")
#: Los mismos estados cerrados, listos para incrustar en un SQL («IN (...)»).
_ESTADOS_CERRADOS_SQL = "(" + ", ".join(f"'{e}'" for e in ESTADOS_CERRADOS) + ")"
ESTADO_ES = {"nueva": "Nueva", "en_analisis": "En análisis", "mitigada": "Mitigada",
             "aceptada": "Riesgo aceptado", "descartada": "Descartada",
             "falso_positivo": "Falso positivo"}


def cambiar_estado(conn: sqlite3.Connection, threat_id: int, estado: str, *,
                   usuario: Optional[str], motivo: Optional[str] = None) -> bool:
    """Cambia el estado operativo. Devuelve False si el estado no es valido o
    la amenaza no existe. No toca alerted_at: lo alertado, alertado queda."""
    if estado not in ESTADOS:
        return False
    cur = conn.execute(
        "UPDATE threats SET estado=?, estado_at=?, estado_por=?, estado_motivo=? WHERE id=?",
        (estado, db.utcnow(), usuario, (motivo or "").strip() or None, threat_id))
    return cur.rowcount > 0


def _fila_a_view(row: sqlite3.Row) -> dict[str, Any]:
    view = dict(row)
    view["in_kev"] = bool(view.get("in_kev"))
    view["technologies"] = []
    view["sources"] = []
    return view


def _adjuntar_relaciones(conn: sqlite3.Connection, vistas: list[dict]) -> list[dict]:
    """Carga tecnologias y fuentes de todas las amenazas en dos consultas."""
    if not vistas:
        return vistas

    por_id = {v["id"]: v for v in vistas}
    ids = list(por_id)

    # SQLite limita los parametros de una consulta; trocear por seguridad.
    for lote in _trocear(ids, 800):
        marcas = ",".join("?" * len(lote))

        for row in conn.execute(
            f"""SELECT tt.threat_id, t.name, t.slug, t.version_installed, t.criticality,
                       t.systems_count, t.exposure, t.owner,
                       tt.matched_alias, tt.confidence,
                       tt.version_verdict, tt.version_evidence
                  FROM threat_technologies tt
                  JOIN technologies t ON t.id = tt.technology_id
                 WHERE tt.threat_id IN ({marcas})
                 ORDER BY tt.confidence DESC, t.name""",
            lote,
        ):
            por_id[row["threat_id"]]["technologies"].append({
                "name": row["name"],
                "slug": row["slug"],
                "version_installed": row["version_installed"],
                "criticality": row["criticality"],
                "systems_count": row["systems_count"] or 0,
                "exposure": row["exposure"],
                "owner": row["owner"],
                "matched_alias": row["matched_alias"],
                "confidence": row["confidence"],
                "version_verdict": row["version_verdict"] or "unknown",
                "version_evidence": row["version_evidence"],
            })

        for row in conn.execute(
            f"""SELECT ts.threat_id, s.name, s.slug, ts.url
                  FROM threat_sources ts
                  JOIN sources s ON s.id = ts.source_id
                 WHERE ts.threat_id IN ({marcas})
                 ORDER BY s.priority, s.name""",
            lote,
        ):
            por_id[row["threat_id"]]["sources"].append({
                "name": row["name"], "slug": row["slug"], "url": row["url"],
            })

    return vistas


def _trocear(items: list, tamano: int) -> Iterable[list]:
    for i in range(0, len(items), tamano):
        yield items[i:i + tamano]


# --------------------------------------------------------------------------
# Consultas publicas
# --------------------------------------------------------------------------
def obtener_amenaza(conn: sqlite3.Connection, threat_id: int) -> Optional[dict]:
    row = conn.execute(
        f"SELECT {_THREAT_COLS} FROM threats WHERE id=?", (threat_id,)
    ).fetchone()
    if row is None:
        return None
    return _adjuntar_relaciones(conn, [_fila_a_view(row)])[0]


def por_fingerprint(conn: sqlite3.Connection, fingerprint: str) -> Optional[dict]:
    row = conn.execute(
        f"SELECT {_THREAT_COLS} FROM threats WHERE fingerprint=?", (fingerprint,)
    ).fetchone()
    return _fila_a_view(row) if row else None


def por_cve(conn: sqlite3.Connection, cve: str) -> list[dict]:
    rows = conn.execute(
        f"SELECT {_THREAT_COLS} FROM threats WHERE cve=? ORDER BY first_seen_at", (cve,)
    ).fetchall()
    return _adjuntar_relaciones(conn, [_fila_a_view(r) for r in rows])


def del_mes(conn: sqlite3.Connection, month: str, *,
            severidades: Optional[Iterable[str]] = None,
            limite: Optional[int] = None,
            orden: str = "relevancia", excluir_bajas: bool = False) -> list[dict]:
    """Amenazas de un mes ('YYYY-MM'), ordenadas por relevancia o severidad.
    ``excluir_bajas`` deja fuera la severidad Baja (ajuste ignore_low_severity)."""
    sql = f"SELECT {_THREAT_COLS} FROM threats WHERE month=?"
    params: list[Any] = [month]
    if excluir_bajas:
        sql += " AND severity != 'Low'"

    if severidades:
        sevs = list(severidades)
        sql += f" AND severity IN ({','.join('?' * len(sevs))})"
        params.extend(sevs)

    if orden == "relevancia":
        sql += (" ORDER BY relevance DESC, "
                "CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 "
                "WHEN 'Medium' THEN 2 ELSE 3 END, "
                "COALESCE(cvss_score, 0) DESC, first_seen_at DESC")
    elif orden == "fecha":
        sql += " ORDER BY first_seen_at DESC"
    else:
        sql += (" ORDER BY CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 "
                "WHEN 'Medium' THEN 2 ELSE 3 END, COALESCE(cvss_score,0) DESC")

    if limite:
        sql += " LIMIT ?"
        params.append(limite)

    rows = conn.execute(sql, params).fetchall()
    return _adjuntar_relaciones(conn, [_fila_a_view(r) for r in rows])


# --------------------------------------------------------------------------
# Criterio de alerta (2026-09-04)
# --------------------------------------------------------------------------
# Motivos por los que una amenaza pendiente NO se alerta, en el orden en que se
# evaluan: el primero que aplica es el que se persiste en alert_skip_reason.
MOTIVOS_EXCLUSION = ("estado_cerrado", "severidad_baja", "sin_identificador",
                     "heuristica_en_espera", "no_afectada", "sin_activos_afectados",
                     "riesgo_aceptado", "sin_evaluar_todavia", "sin_activos_confirmados",
                     "relevancia_baja")

# Explicacion breve de cada motivo, en lenguaje llano, para la ficha, el
# resumen semanal y el informe. Se completa con la cifra concreta en cada sitio.
MOTIVO_EXCLUSION_ES = {
    "estado_cerrado": "descartada o marcada como falso positivo por el equipo",
    # Sin nombrar la severidad que no se reporta (orden del usuario del 2026-09-10): este
    # texto lo pinta la ficha de la amenaza y lo escribe el informe mensual, y ninguno de
    # los dos puede nombrarla.
    "severidad_baja": "por su severidad: por decisión del equipo no se reporta",
    "sin_identificador": ("sin CVE ni identificador de aviso: es una noticia o un "
                          "artículo, no una vulnerabilidad concreta"),
    "heuristica_en_espera": ("severidad estimada por el texto; se espera la "
                             "puntuación oficial de NVD antes de decidir"),
    "no_afectada": "la versión instalada no es vulnerable",
    "sin_activos_afectados": ("ningún activo tiene instalada la versión vulnerable según "
                              "OCS Inventory: los activos ya llevan la corrección o la "
                              "distribución no está afectada"),
    # Riesgo aceptado con una excepcion vigente (2026-09-10). Va ANTES de
    # «sin_activos_confirmados» porque la afectacion SI esta confirmada: lo que hay es una
    # decision de riesgo con responsable y fecha de caducidad, y el correo tiene que
    # decirlo con su nombre en lugar de dar a entender que no nos afecta.
    "riesgo_aceptado": ("riesgo aceptado con una excepción vigente: la afectación está "
                        "confirmada, pero la organización decidió asumirla por escrito, "
                        "con responsable y con fecha de vencimiento (página Excepciones)"),
    # Sin evaluar todavia (2026-09-10). Hasta hoy, una amenaza que el motor no habia
    # llegado a evaluar SE ALERTABA (el filtro se abstenia) con el aviso «afectacion
    # todavia sin evaluar». El usuario lo rechazo: «me debe alertar lo que realmente me
    # este afectando, de lo contrario no». Ahora se evalua dirigida ANTES de decidir
    # (aplicabilidad.evaluar_dirigido) y, si aun asi no hay evaluacion, no se alerta y
    # queda con este motivo, que dice la verdad: no se sabe todavia.
    "sin_evaluar_todavia": ("a la espera de la evaluación contra el inventario: no se ha "
                            "podido comprobar si alguna máquina tiene la versión "
                            "vulnerable, así que no se alerta; se vuelve a intentar en la "
                            "siguiente ejecución"),
    "sin_activos_confirmados": ("sin afectación confirmada: ningún servidor ni equipo de "
                                "cómputo presente en el inventario tiene confirmada la "
                                "versión vulnerable (OCS Inventory)"),
    "relevancia_baja": ("relevancia por debajo del umbral: no afecta a tecnologías "
                        "críticas o expuestas del inventario"),
}

_ORDEN_ALERTA = (" ORDER BY relevance DESC, "
                 "CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 "
                 "WHEN 'Medium' THEN 2 ELSE 3 END, COALESCE(cvss_score,0) DESC")


def _a_datetime_utc(valor: Any) -> Optional[datetime]:
    """'2026-09-04T13:04:30Z' -> datetime consciente en UTC; None si no se puede."""
    if isinstance(valor, datetime):
        return valor if valor.tzinfo else valor.replace(tzinfo=timezone.utc)
    if not valor:
        return None
    texto = str(valor).strip().replace("Z", "+00:00")
    for intento in (texto, texto[:19]):
        try:
            dt = datetime.fromisoformat(intento)
        except ValueError:
            continue
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return None


def _ajuste_num(cfg: Any, clave: str, defecto: float) -> float:
    try:
        valor = cfg.get(clave, defecto) if cfg is not None else defecto
        return float(defecto if valor is None else valor)
    except (TypeError, ValueError):
        return float(defecto)


def _ajuste_bool(cfg: Any, clave: str, defecto: bool) -> bool:
    valor = cfg.get(clave, defecto) if cfg is not None else defecto
    return defecto if valor is None else bool(valor)


def motivo_exclusion(view: dict, *, cfg: Any, ahora: Optional[datetime] = None,
                     solo_afectadas: Optional[bool] = None,
                     solo_con_activos: Optional[bool] = None) -> Optional[str]:
    """Primer motivo (de MOTIVOS_EXCLUSION) por el que la amenaza NO se alerta,
    o None si debe alertarse. Evalua en el orden de la especificacion del
    2026-09-04, con el criterio de afectacion real anadido el 2026-09-08.

    Por que el criterio del 2026-09-08: el correo del 8 de septiembre alerto de
    CVE-2026-75650 (Critica, relevancia 63,1) sin un solo activo afectado. La
    relevancia mide lo grave que SERIA el problema si lo tuvieramos, no si lo
    tenemos; alertar por relevancia sola convierte el buzon en ruido y el
    operador deja de leerlo. Desde hoy una amenaza solo se alerta si al menos un
    activo con presente=1 tiene veredicto 'afectado' en `aplicabilidad`. La
    exclusion no es definitiva: alerted_at sigue a NULL, la clasificacion se
    repite cada dia y, en cuanto la evaluacion confirme un activo, se alerta;
    mientras tanto la amenaza va en el resumen semanal.

    Explotacion activa confirmada (KEV, ajuste ``alert_kev_sin_activos``): desde el
    2026-09-10 el ajuste vale **False** por omision, asi que una KEV sin afectacion
    confirmada TAMPOCO se alerta. Orden del usuario ese dia: «me debe alertar lo que
    realmente me este afectando, de lo contrario no». El ajuste se conserva porque la
    decision es reversible: con el activado se vuelve al criterio anterior y el correo
    dice que no se ha confirmado en ninguna maquina (`kev_sin_activos_confirmados`).

    SIN CONFIRMACION NO SE ALERTA (2026-09-10). Hasta hoy el filtro se ABSTENIA —y por
    tanto alertaba— cuando no podia afirmar nada: sin evaluacion de esa amenaza, con la
    evaluacion incompleta o con la amenaza sin CVE. El correo del 2026-09-10 alerto asi de
    cuatro criticas (CVE-2025-53521, CVE-2025-25249, CVE-2026-85102 y CVE-2026-12087) que
    NUNCA se habian evaluado, con el aviso «Afectacion todavia sin evaluar», y el usuario
    lo rechazo. Ahora esas amenazas se evaluan DIRIGIDAS justo antes de decidir
    (``aplicabilidad.evaluar_dirigido``, sin el cupo de reparto) y, si despues de eso
    siguen sin evaluacion o con la evaluacion incompleta, el motivo es
    ``sin_evaluar_todavia`` y NO entran en el correo.

    Que no se pierde nada: ``alerted_at`` sigue a NULL, la clasificacion se repite cada
    dia, la amenaza sigue consultable con su motivo, entra en el resumen semanal y se
    alerta en cuanto la evaluacion confirme un activo. Y para que un fallo tecnico no
    pueda callar algo en silencio, la ejecucion diaria emite un aviso de administracion
    con las candidatas que se quedaron sin evaluar (``aplicabilidad.avisar_sin_evaluar``):
    el fallo se ve, pero no llena el correo de amenazas que no afectan.

    Con ``applicability_enabled`` apagado el filtro NO se aplica (no hay motor que pueda
    confirmar nada, asi que se alerta como antes de que existiera): es la valvula de
    escape del criterio entero.

    ``solo_afectadas``: si se pasa, manda sobre ``alert_only_affected_versions``.
    ``solo_con_activos``: si se pasa, manda sobre
    ``alert_solo_con_activos_afectados``.
    """
    ahora = ahora or datetime.now(timezone.utc)
    if ahora.tzinfo is None:
        ahora = ahora.replace(tzinfo=timezone.utc)

    # 1. Cerrada por el equipo: nunca se alerta, aunque sea KEV.
    if view.get("estado") in ESTADOS_CERRADOS:
        return "estado_cerrado"

    kev = bool(view.get("in_kev"))
    id_aviso = identity.extraer_id_aviso(view.get("title_en"), view.get("summary_en"))
    tiene_identificador = bool(view.get("cve")) or id_aviso is not None

    # 1b. Severidad baja: por decision del equipo (2026-09-04) no se tiene en
    #     cuenta. Una KEV alerta igual: la explotacion confirmada pesa mas que
    #     la puntuacion.
    if (view.get("severity") == "Low" and not kev
            and _ajuste_bool(cfg, "ignore_low_severity", True)):
        return "severidad_baja"

    # 2. Sin CVE ni identificador de aviso: noticia, no vulnerabilidad concreta.
    if (not tiene_identificador and not kev
            and _ajuste_bool(cfg, "alert_require_identifier", True)):
        return "sin_identificador"

    # 3. Severidad estimada y reciente: se espera el dato oficial. Un aviso de
    #    proveedor (DSA, USN...) ya es la fuente oficial y no espera.
    horas = _ajuste_num(cfg, "alert_defer_heuristic_hours", 24)
    if (view.get("severity_source") == "heuristic" and id_aviso is None
            and not kev and horas > 0):
        visto = _a_datetime_utc(view.get("first_seen_at"))
        if visto is not None and (ahora - visto) < timedelta(hours=horas):
            return "heuristica_en_espera"

    # 4. Todas sus tecnologias con version confirmada no afectada.
    aplica_afectadas = (_ajuste_bool(cfg, "alert_only_affected_versions", False)
                        if solo_afectadas is None else bool(solo_afectadas))
    tecs = view.get("technologies") or []
    if aplica_afectadas and tecs and all(
            (t.get("version_verdict") or "unknown") == "not_affected" for t in tecs):
        return "no_afectada"

    # 4b. Evaluada contra el inventario real (OCS Inventory) y ningun activo tiene la
    #     version vulnerable. Hace falta evidencia positiva: activos que ya llevan la
    #     correccion, o que las bases de la distribucion no listan nuestras versiones y
    #     el aviso solo apunta al sistema operativo. Vale tambien para KEV: si consta que
    #     ningun activo esta afectado, no hay nada que corregir hoy (queda en el semanal).
    res = view.get("activos_resumen")
    if (res and _ajuste_bool(cfg, "alert_skip_without_assets", True) and not res.get("incompleta")
            and int(res.get("afectados") or 0) == 0 and int(res.get("sin_dato") or 0) == 0
            and (int(res.get("no_afectados") or 0) > 0
                 or (res.get("distro_no_afectada") and res.get("tecnologias_solo_so")))):
        return "sin_activos_afectados"

    # 4c. Afectacion real (2026-09-08, peticion expresa del usuario): sin ningun
    #     activo presente con veredicto 'afectado' no hay nada que corregir hoy,
    #     asi que no se alerta. Va despues de 4b para que, cuando haya evidencia
    #     positiva de que los activos ya estan corregidos, el motivo que se
    #     guarde siga siendo el mas informativo ('sin_activos_afectados').
    #     La cuenta la pone `_adjuntar_activos_afectados`.
    aplica_activos = (
        (_ajuste_bool(cfg, "alert_solo_con_activos_afectados", True)
         and _ajuste_bool(cfg, "applicability_enabled", True))
        if solo_con_activos is None else bool(solo_con_activos))
    confirmados = view.get("activos_afectados_presentes")
    # Dato de evaluacion: `evaluado_at` de `aplicabilidad_amenaza`. Sin fila no hay un
    # cero, hay un «todavia no lo sabemos».
    evaluada = bool((res or {}).get("evaluado_at"))
    # El motor solo evalua amenazas con CVE (aplicabilidad.evaluar_pendientes), asi que un
    # aviso de proveedor sin CVE (DSA, USN, RHSA, SUSE-SU) no se puede confirmar contra el
    # inventario. Hasta el 2026-09-09 eso bastaba para alertarlo; desde el 2026-09-10 no:
    # sin confirmacion no se alerta, y esa clase de aviso queda con su motivo, en la
    # interfaz y en el resumen semanal, hasta que llegue con CVE o alguien lo revise.
    evaluable = bool(view.get("cve"))
    # Activos cuya afectacion SI esta confirmada pero cuyo riesgo se acepto por escrito
    # con una excepcion vigente (2026-09-10). `_adjuntar_activos_afectados` los cuenta
    # aparte: sin esta cifra, una vulnerabilidad con el riesgo aceptado se habria callado
    # con el motivo «sin afectación confirmada», que es falso y ademas borra de la
    # trazabilidad la decision que se tomo.
    aceptados = int(view.get("activos_afectados_aceptados") or 0)
    # Relevancia (el motivo 5, que se resuelve aqui arriba porque hace falta para saber si
    # esta amenaza era de verdad CANDIDATA a alertar): sin llegar al umbral no se alertaria
    # ni confirmada, asi que su falta de evaluacion no es un problema que reportar.
    umbral = _ajuste_num(cfg, "alert_min_relevance", 50)
    try:
        relevancia = float(view.get("relevance") or 0.0)
    except (TypeError, ValueError):
        relevancia = 0.0
    candidata = bool(kev or relevancia >= umbral)
    # ``confirmados is None`` (nadie calculo la cifra, o no hay ni un activo con
    # presente=1) es la UNICA abstencion que queda: sin inventario ninguna amenaza se
    # podria confirmar nunca y el criterio entero no significa nada, igual que con
    # ``applicability_enabled`` apagado. Es la valvula de escape para que un fallo de la
    # sincronizacion con OCS Inventory no deje el correo vacio en silencio; lo que ya no
    # se abstiene es el caso real que denuncio el usuario: inventario al dia y ESTA
    # amenaza sin evaluar (confirmados == 0 sin dato de evaluacion).
    if aplica_activos and confirmados is not None and int(confirmados) == 0:
        sin_dato = not (evaluada and evaluable) or bool((res or {}).get("incompleta"))
        if sin_dato:
            # SIN CONFIRMACION NO SE ALERTA (2026-09-10). Sin evaluacion, con la
            # evaluacion incompleta, sin CVE que evaluar o sin la cuenta de activos, no se
            # sabe si nos afecta: no entra en el correo y queda con este motivo. La
            # ejecucion diaria ya intento evaluarla dirigida antes de llegar aqui
            # (aplicabilidad.evaluar_dirigido) y avisa a administracion de lo que no pudo
            # evaluar, para que un fallo tecnico no calle nada en silencio.
            view["afectacion_sin_evaluar"] = True
            # Solo cuenta como «a la espera de la evaluacion» lo que de verdad iba a
            # alertarse. Si su relevancia no llega al umbral y no hay explotacion activa,
            # el motivo honesto sigue siendo `relevancia_baja`: medido sobre la base real
            # el 2026-09-10, sin esta condicion el motivo nuevo se llevaba 241 amenazas
            # irrelevantes y el resumen semanal habria dicho «241 a la espera de la
            # evaluacion» cuando ninguna de ellas se habria alertado nunca. Con ella son
            # las 4 candidatas reales de ese dia.
            if candidata:
                return "sin_evaluar_todavia"
        else:
            # Con el dato delante: la afectacion esta descartada o esta aceptada por escrito.
            if kev and _ajuste_bool(cfg, "alert_kev_sin_activos", False):
                # Excepcion reversible, apagada por omision desde el 2026-09-10: con ella
                # encendida una KEV se alerta aunque no se confirme en ninguna maquina.
                # Pesa mas que una aceptacion de riesgo, igual que pesa mas que la
                # severidad baja; pero se distingue el caso, porque decir «no se ha
                # confirmado en ninguna maquina» cuando lo que hay es un riesgo aceptado
                # seria mentir.
                if aceptados > 0:
                    view["riesgo_aceptado_vigente"] = aceptados
                else:
                    view["kev_sin_activos_confirmados"] = True
            elif aceptados > 0:
                # Todos los activos confirmados estan cubiertos por una excepcion
                # vigente: no hay nada que hacer hoy y la decision ya tiene dueno, fecha
                # y auditoria. Al vencer la excepcion, la amenaza vuelve a alertarse sin
                # que nadie ejecute nada (alerted_at sigue a NULL).
                return "riesgo_aceptado"
            else:
                return "sin_activos_confirmados"

    # 5. Relevancia para la organizacion por debajo del umbral (ya calculada arriba).
    #    KEV alerta siempre.
    if not kev and relevancia < umbral:
        return "relevancia_baja"

    return None


def _adjuntar_activos_afectados(conn: sqlite3.Connection, vistas: list[dict]) -> bool:
    """Pone en cada vista ``activos_afectados_presentes`` (activos con presente=1
    y veredicto 'afectado' para esa amenaza) y devuelve si se pudo calcular.

    Los activos cuyo riesgo se acepto por escrito con una excepcion vigente NO cuentan
    en esa cifra (2026-09-10) y se devuelven aparte en
    ``activos_afectados_aceptados``: si contaran, la alerta diaria seguiria disparando
    por una afectacion confirmada que la organizacion decidio asumir hasta una fecha,
    con responsable y con auditoria, que es justo lo que la excepcion promete evitar. Con
    la cifra aparte, ``motivo_exclusion`` puede callar la alerta diciendo «riesgo
    aceptado» —su nombre— en vez de «sin afectación confirmada», que seria falso. Sin
    ninguna excepcion vigente la consulta es EXACTAMENTE la de siempre.

    Se cuenta aqui contra `aplicabilidad` + `activos` en vez de reutilizar el
    contador de `aplicabilidad_amenaza` porque ese solo se pone al dia al
    reevaluar o al sincronizar OCS: entre medias puede seguir contando un activo
    que ya se dio de baja. Callar una alerta es una decision demasiado seria
    para tomarla con una cifra en cache.

    Se cuenta por `threat_id` y tambien por `cve`, y se toma el mayor de los
    dos, porque la fila de `aplicabilidad` es unica por (activo_id, cve,
    paquete) y su `threat_id` lo sobrescribe la ultima amenaza evaluada
    (aplicabilidad.py, ON CONFLICT ... DO UPDATE SET threat_id). El mismo CVE
    llega por dos fuentes en 139 casos (297 amenazas), asi que sin el conteo por
    CVE una de las hermanas se queda con cero activos propios y se callaria una
    vulnerabilidad que si esta confirmada en el parque (revision del
    2026-09-08: CVE-2026-50508, amenazas 5668 y 2607).

    No se pone la clave (y se devuelve False) cuando no hay inventario
    sincronizado o la base es antigua y no tiene las tablas: sin inventario la
    frase «no afecta a ninguna maquina» no significa nada y el filtro tiene que
    abstenerse en vez de dejar el correo vacio.
    """
    ids = [v["id"] for v in vistas if v.get("id") is not None]
    if not ids:
        return False
    conteo: dict[int, int] = {}
    por_cve: dict[str, int] = {}
    # Los mismos dos conteos SIN los activos cuyo riesgo esta aceptado. Con cero
    # excepciones vigentes la columna no se pide y las consultas quedan como estaban.
    libres: dict[int, int] = {}
    libres_cve: dict[str, int] = {}
    cond_aceptado = (excepciones.SQL_SIN_EXCEPCION_APLICABILIDAD
                     if excepciones.hay_excepciones(conn) else "")
    columna_libres = (f", COUNT(DISTINCT CASE WHEN {cond_aceptado} THEN ap.activo_id END)"
                      if cond_aceptado else "")
    cves = sorted({str(v.get("cve")).strip() for v in vistas if v.get("cve")})
    try:
        if not conn.execute("SELECT 1 FROM activos WHERE presente=1 LIMIT 1").fetchone():
            return False
        for lote in _trocear(ids, 800):
            marcas = ",".join("?" * len(lote))
            for fila in conn.execute(
                    f"""SELECT ap.threat_id, COUNT(DISTINCT ap.activo_id){columna_libres}
                          FROM aplicabilidad ap JOIN activos a ON a.id = ap.activo_id
                         WHERE ap.veredicto = 'afectado' AND a.presente = 1
                           AND ap.threat_id IN ({marcas})
                         GROUP BY ap.threat_id""", lote):
                conteo[int(fila[0])] = int(fila[1] or 0)
                libres[int(fila[0])] = int((fila[2] if columna_libres else fila[1]) or 0)
        for lote in _trocear(cves, 800):
            marcas = ",".join("?" * len(lote))
            for fila in conn.execute(
                    f"""SELECT ap.cve, COUNT(DISTINCT ap.activo_id){columna_libres}
                          FROM aplicabilidad ap JOIN activos a ON a.id = ap.activo_id
                         WHERE ap.veredicto = 'afectado' AND a.presente = 1
                           AND ap.cve IN ({marcas})
                         GROUP BY ap.cve""", lote):
                por_cve[str(fila[0])] = int(fila[1] or 0)
                libres_cve[str(fila[0])] = int((fila[2] if columna_libres else fila[1]) or 0)
    except sqlite3.OperationalError:
        return False
    for vista in vistas:
        cve = str(vista.get("cve")).strip() if vista.get("cve") else ""
        # El mayor de los dos conteos, igual que siempre (ver el docstring): la fila de
        # `aplicabilidad` es unica por (activo, CVE, paquete) y su `threat_id` lo
        # sobrescribe la ultima amenaza evaluada del mismo CVE.
        total = max(conteo.get(vista.get("id"), 0), por_cve.get(cve, 0))
        sin_aceptados = max(libres.get(vista.get("id"), 0), libres_cve.get(cve, 0))
        vista["activos_afectados_presentes"] = sin_aceptados
        vista["activos_afectados_aceptados"] = max(0, total - sin_aceptados)
    return True


#: Tope de candidatas que se piden para la evaluacion dirigida previa a la alerta. Es
#: una cota de la consulta, no del trabajo: el tope real lo pone
#: ``aplicabilidad.LIMITE_EVALUACION_DIRIGIDA``.
MAX_CANDIDATAS_SIN_EVALUAR = 500


def candidatas_sin_evaluacion(conn: sqlite3.Connection, *, cfg: Any = None,
                              limite: int = MAX_CANDIDATAS_SIN_EVALUAR) -> list[dict[str, Any]]:
    """Amenazas que HOY se alertarian si se confirmara su afectacion y que NO tienen
    evaluacion utilizable contra el inventario.

    Es la lista que la ejecucion diaria evalua DIRIGIDA antes de decidir la alerta
    (2026-09-10), para que la decision se tome con datos y no por abstencion. El criterio
    es el mismo que el del filtro, pero solo con lo que se puede resolver en SQL y sin
    depender del orden en que ``motivo_exclusion`` evalua sus motivos:

    * nunca alertada y no cerrada por el equipo (descartada o falso positivo);
    * relevancia por encima del umbral (``alert_min_relevance``) O explotacion activa
      confirmada: si no llega al umbral, no se alertaria aunque se confirmara, y evaluar
      cientos de amenazas irrelevantes cada dia costaria el cupo de OSV.dev entero;
    * severidad que se reporta (la baja no cuenta, salvo con explotacion activa);
    * CON CVE: el motor solo sabe evaluar CVE, asi que un aviso sin CVE no se puede
      evaluar y no tiene sentido pedirlo (queda con su motivo en el filtro);
    * sin fila en ``aplicabilidad_amenaza`` o con la evaluacion marcada como incompleta.

    Cada elemento trae ``id``, ``cve``, ``severity``, ``in_kev``, ``relevance``,
    ``title_es``/``title_en`` y ``evaluada``, ordenados por explotacion activa y
    relevancia: si hubiera que recortar, se evalua primero lo que mas importa.
    """
    umbral = _ajuste_num(cfg, "alert_min_relevance", 50)
    incluir_bajas = not _ajuste_bool(cfg, "ignore_low_severity", True)
    cerrados = ",".join("?" * len(ESTADOS_CERRADOS))
    sin_bajas = "" if incluir_bajas else \
        " AND (t.severity IS NULL OR t.severity <> 'Low' OR t.in_kev = 1)"
    filas = conn.execute(
        f"""SELECT t.id, t.cve, t.severity, t.in_kev, t.relevance, t.title_es, t.title_en,
                   (aa.threat_id IS NOT NULL) AS evaluada,
                   COALESCE(json_extract(aa.detalle, '$.incompleta'), 0) AS incompleta
              FROM threats t LEFT JOIN aplicabilidad_amenaza aa ON aa.threat_id = t.id
             WHERE t.alerted_at IS NULL AND t.estado NOT IN ({cerrados})
               AND t.cve IS NOT NULL AND TRIM(t.cve) <> ''
               AND (COALESCE(t.relevance, 0) >= ? OR t.in_kev = 1){sin_bajas}
               AND (aa.threat_id IS NULL
                    OR aa.evaluado_at IS NULL
                    OR json_extract(aa.detalle, '$.incompleta') = 1)
             ORDER BY t.in_kev DESC, COALESCE(t.relevance, 0) DESC, t.id
             LIMIT ?""",
        (*ESTADOS_CERRADOS, umbral, max(1, int(limite)))).fetchall()
    return [dict(f, evaluada=bool(f["evaluada"]), incompleta=bool(f["incompleta"]))
            for f in filas]


def _candidatas_alerta(conn: sqlite3.Connection, *, incluir_cerradas: bool,
                       min_severidad: Optional[str] = None,
                       limite: Optional[int] = None) -> list[dict]:
    """Amenazas nunca alertadas, con tecnologias y fuentes cargadas, ordenadas
    por relevancia, severidad y CVSS."""
    sql = f"SELECT {_THREAT_COLS} FROM threats WHERE alerted_at IS NULL"
    params: list[Any] = []
    if not incluir_cerradas:
        sql += f" AND estado NOT IN ({','.join('?' * len(ESTADOS_CERRADOS))})"
        params.extend(ESTADOS_CERRADOS)
    if min_severidad:
        umbral = SEVERIDAD_ORDEN.get(min_severidad, 1)
        sevs = [s for s, o in SEVERIDAD_ORDEN.items() if o <= umbral]
        sql += f" AND severity IN ({','.join('?' * len(sevs))})"
        params.extend(sevs)
    sql += _ORDEN_ALERTA
    if limite:
        sql += " LIMIT ?"
        params.append(limite)
    return _adjuntar_relaciones(
        conn, [_fila_a_view(r) for r in conn.execute(sql, params).fetchall()])


def pendientes_de_alerta(conn: sqlite3.Connection, *, cfg: Any = None,
                         min_severidad: Optional[str] = None,
                         solo_afectadas: Optional[bool] = None,
                         solo_con_activos: Optional[bool] = None,
                         limite: Optional[int] = None) -> list[dict]:
    """Amenazas nunca alertadas que deben ir en la alerta de hoy.

    Con ``cfg`` aplica el criterio del 2026-09-04 (ver `clasificar_pendientes`):
    relevancia minima o KEV, identificador obligatorio, espera de la severidad
    estimada, version afectada y estado no cerrado. Si ademas se pasan
    ``min_severidad`` o ``solo_afectadas``, se respetan.

    Sin ``cfg`` conserva el criterio anterior (severidad >= ``min_severidad``,
    'High' por defecto; ``solo_afectadas`` descarta las de version no afectada),
    que siguen usando el panel y la comparacion ``--comparar``. En ambos casos
    las amenazas descartadas o marcadas como falso positivo quedan fuera.

    El estado de "ya alertada" vive en la columna alerted_at, asi que no se
    puede perder por un `rm -f` del cron (sustituye a analyzed_threats.json).
    """
    if cfg is None:
        vistas = _candidatas_alerta(conn, incluir_cerradas=False,
                                    min_severidad=min_severidad or "High",
                                    limite=limite)
        if solo_afectadas:
            vistas = [
                v for v in vistas
                if not v["technologies"]
                or any(t["version_verdict"] != "not_affected" for t in v["technologies"])
            ]
        return vistas

    resultado = clasificar_pendientes(conn, cfg=cfg, persistir=False,
                                      min_severidad=min_severidad,
                                      solo_afectadas=solo_afectadas,
                                      solo_con_activos=solo_con_activos)
    vistas = resultado["alertar"]
    return vistas[:limite] if limite else vistas


def clasificar_pendientes(conn: sqlite3.Connection, *, cfg: Any,
                          persistir: bool = True,
                          ahora: Optional[datetime] = None,
                          min_severidad: Optional[str] = None,
                          solo_afectadas: Optional[bool] = None,
                          solo_con_activos: Optional[bool] = None) -> dict[str, Any]:
    """Separa las amenazas nunca alertadas en las que se alertan y las excluidas.

    Devuelve ``{"alertar": [ThreatView], "excluidas": {motivo: [ids]},
    "conteo": {motivo: n}}``; ``excluidas`` y ``conteo`` traen siempre todos los
    motivos de MOTIVOS_EXCLUSION (con listas vacias o 0 si no aplican). Las que
    se alertan van por relevancia desc, severidad y CVSS.

    Antes de clasificar adjunta a cada candidata las cifras de la evaluacion
    contra el inventario (`aplicabilidad.adjuntar_resumen`) y el numero de
    activos presentes confirmados como afectados, porque desde el 2026-09-08 la
    alerta se decide por afectacion real y no solo por relevancia (ver
    `motivo_exclusion`).

    Con ``persistir`` escribe alert_skip_reason / alert_skip_at en las
    excluidas, solo si el motivo cambia, y borra el motivo de las que hoy si
    pasan (por ejemplo una `heuristica_en_espera` cuyo plazo vencio). Cada dia
    se reevalua todo: pasadas las horas de espera, la amenaza vuelve a competir
    con las demas reglas.

    ``min_severidad`` / ``solo_afectadas`` son para compatibilidad con la firma
    anterior de `pendientes_de_alerta`: si se pasan, se respetan.
    ``solo_con_activos`` manda sobre el ajuste
    ``alert_solo_con_activos_afectados`` (lo usan las pruebas y la comparacion
    de criterios para ver el efecto del filtro sin tocar los ajustes).
    """
    ahora = ahora or datetime.now(timezone.utc)
    candidatas = _candidatas_alerta(conn, incluir_cerradas=True,
                                    min_severidad=min_severidad)
    try:
        from . import aplicabilidad
        aplicabilidad.adjuntar_resumen(conn, candidatas)
    except Exception:  # noqa: BLE001 - sin aplicabilidad (base antigua) el filtro sigue igual
        pass
    _adjuntar_activos_afectados(conn, candidatas)

    alertar: list[dict] = []
    excluidas: dict[str, list[int]] = {m: [] for m in MOTIVOS_EXCLUSION}
    for vista in candidatas:
        motivo = motivo_exclusion(vista, cfg=cfg, ahora=ahora,
                                  solo_afectadas=solo_afectadas,
                                  solo_con_activos=solo_con_activos)
        if motivo is None:
            alertar.append(vista)
        else:
            excluidas[motivo].append(vista["id"])

    if persistir:
        marca = db.utcnow()
        for motivo, ids in excluidas.items():
            for lote in _trocear(ids, 800):
                marcas = ",".join("?" * len(lote))
                conn.execute(
                    f"UPDATE threats SET alert_skip_reason=?, alert_skip_at=? "
                    f"WHERE id IN ({marcas}) "
                    f"AND COALESCE(alert_skip_reason, '') != ?",
                    [motivo, marca, *lote, motivo])
        a_limpiar = [v["id"] for v in alertar if v.get("alert_skip_reason")]
        for lote in _trocear(a_limpiar, 800):
            marcas = ",".join("?" * len(lote))
            conn.execute(
                f"UPDATE threats SET alert_skip_reason=NULL, alert_skip_at=NULL "
                f"WHERE id IN ({marcas})", lote)
        for vista in alertar:
            vista["alert_skip_reason"] = None

    return {
        "alertar": alertar,
        "excluidas": excluidas,
        "conteo": {m: len(ids) for m, ids in excluidas.items()},
    }


# --------------------------------------------------------------------------
# Resumen semanal
# --------------------------------------------------------------------------
def no_alertadas_desde(conn: sqlite3.Connection, desde: str, *,
                       sin_digest: bool = True, excluir_bajas: bool = False) -> list[dict]:
    """Amenazas vistas por primera vez desde ``desde`` (ISO UTC), nunca
    alertadas y no cerradas; con ``sin_digest`` solo las que aun no han ido en
    ningun resumen semanal. Ordenadas por relevancia, severidad y CVSS."""
    sql = (f"SELECT {_THREAT_COLS} FROM threats "
           f"WHERE first_seen_at >= ? AND alerted_at IS NULL "
           f"AND estado NOT IN ({','.join('?' * len(ESTADOS_CERRADOS))})")
    params: list[Any] = [desde, *ESTADOS_CERRADOS]
    if sin_digest:
        sql += " AND digest_at IS NULL"
    if excluir_bajas:
        sql += " AND severity != 'Low'"
    sql += _ORDEN_ALERTA
    return _adjuntar_relaciones(
        conn, [_fila_a_view(r) for r in conn.execute(sql, params).fetchall()])


def alertadas_desde(conn: sqlite3.Connection, desde: str) -> list[dict]:
    """Amenazas alertadas a partir de ``desde`` (ISO UTC), las mas relevantes primero."""
    rows = conn.execute(
        f"SELECT {_THREAT_COLS} FROM threats WHERE alerted_at >= ?{_ORDEN_ALERTA}",
        (desde,)).fetchall()
    return _adjuntar_relaciones(conn, [_fila_a_view(r) for r in rows])


def conteo_exclusiones(conn: sqlite3.Connection, desde: str) -> dict[str, int]:
    """Cuantas amenazas vistas desde ``desde`` tiene cada alert_skip_reason.
    Siempre devuelve TODOS los motivos de MOTIVOS_EXCLUSION (0 si no hay)."""
    conteo = {m: 0 for m in MOTIVOS_EXCLUSION}
    for row in conn.execute(
            "SELECT alert_skip_reason AS motivo, COUNT(*) AS n FROM threats "
            "WHERE first_seen_at >= ? AND alert_skip_reason IS NOT NULL "
            "GROUP BY alert_skip_reason", (desde,)):
        conteo[row["motivo"]] = int(row["n"] or 0)
    return conteo


def marcar_en_digest(conn: sqlite3.Connection, threat_ids: Iterable[int]) -> int:
    """Anota digest_at en las amenazas incluidas en un resumen semanal."""
    ids = list(threat_ids)
    if not ids:
        return 0
    ahora = db.utcnow()
    total = 0
    for lote in _trocear(ids, 800):
        marcas = ",".join("?" * len(lote))
        cur = conn.execute(
            f"UPDATE threats SET digest_at=? WHERE id IN ({marcas}) AND digest_at IS NULL",
            [ahora, *lote])
        total += cur.rowcount or 0
    return total


def marcar_alertadas(conn: sqlite3.Connection, threat_ids: Iterable[int]) -> int:
    ids = list(threat_ids)
    if not ids:
        return 0
    ahora = db.utcnow()
    total = 0
    for lote in _trocear(ids, 800):
        marcas = ",".join("?" * len(lote))
        cur = conn.execute(
            f"UPDATE threats SET alerted_at=? WHERE id IN ({marcas}) AND alerted_at IS NULL",
            [ahora, *lote],
        )
        total += cur.rowcount or 0
    return total


def buscar(conn: sqlite3.Connection, *, texto: str = "", severidades=None,
           meses=None, tecnologia_slug: Optional[str] = None,
           solo_kev: bool = False, solo_con_cve: bool = False,
           orden: str = "relevancia", limite: int = 100,
           desplazamiento: int = 0, estados=None,
           excluir_bajas: bool = False) -> tuple[list[dict], int]:
    """Busqueda paginada para la GUI. Devuelve (resultados, total_sin_paginar).
    ``estados``: lista de estados operativos a incluir (None = todos).

    ``excluir_bajas`` (regla interna, ajuste ``ignore_low_severity``, activo en
    produccion) deja fuera la severidad Baja del RECUENTO y de las filas devueltas.
    Hasta el 2026-09-15 la lista no lo hacia cuando nadie elegia severidad en el filtro:
    la cabecera decia «7.514 amenazas coinciden con el filtro actual» y la tarjeta de la
    MISMA pagina «7.293 amenazas registradas» (``resumen_amenazas``, que si la deja
    fuera); las 221 de diferencia eran de severidad baja y salian con su insignia en la
    ultima pagina, justo lo que la regla del equipo prohibe. La condicion es la misma
    de :data:`_SIN_BAJAS`: una severidad DESCONOCIDA (NULL) no es una baja y sigue
    contando, para que las dos cifras cuadren tambien el dia que aparezca una.
    """
    where: list[str] = []
    params: list[Any] = []

    if excluir_bajas:
        # `_SIN_BAJAS` esta escrito con el alias `t`, que es el de esta consulta.
        where.append(_SIN_BAJAS)

    if estados:
        ests = [e for e in estados if e in ESTADOS]
        if ests:
            where.append(f"t.estado IN ({','.join('?' * len(ests))})")
            params.extend(ests)

    if texto:
        where.append("(t.title_en LIKE ? OR t.title_es LIKE ? OR t.cve LIKE ? "
                     "OR t.summary_es LIKE ?)")
        patron = f"%{texto}%"
        params.extend([patron] * 4)
    if severidades:
        sevs = list(severidades)
        where.append(f"t.severity IN ({','.join('?' * len(sevs))})")
        params.extend(sevs)
    if meses:
        ms = list(meses)
        where.append(f"t.month IN ({','.join('?' * len(ms))})")
        params.extend(ms)
    if solo_kev:
        where.append("t.in_kev = 1")
    if solo_con_cve:
        where.append("t.cve IS NOT NULL")
    if tecnologia_slug:
        where.append(
            "EXISTS (SELECT 1 FROM threat_technologies tt "
            "JOIN technologies tc ON tc.id = tt.technology_id "
            "WHERE tt.threat_id = t.id AND tc.slug = ?)"
        )
        params.append(tecnologia_slug)

    clausula = (" WHERE " + " AND ".join(where)) if where else ""

    total = conn.execute(
        f"SELECT COUNT(*) FROM threats t{clausula}", params
    ).fetchone()[0]

    if orden == "fecha":
        order_sql = " ORDER BY t.first_seen_at DESC"
    elif orden == "severidad":
        order_sql = (" ORDER BY CASE t.severity WHEN 'Critical' THEN 0 "
                     "WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END, "
                     "COALESCE(t.cvss_score,0) DESC")
    else:
        order_sql = " ORDER BY t.relevance DESC, t.first_seen_at DESC"

    rows = conn.execute(
        f"SELECT {_THREAT_COLS.replace('id,', 't.id,')} FROM threats t{clausula}"
        f"{order_sql} LIMIT ? OFFSET ?",
        [*params, limite, desplazamiento],
    ).fetchall()

    return _adjuntar_relaciones(conn, [_fila_a_view(r) for r in rows]), total


# --------------------------------------------------------------------------
# Agregados
# --------------------------------------------------------------------------
def _media_1_decimal(valor: Any) -> Optional[float]:
    """Redondea una media CVSS a 1 decimal de forma estable (mitad hacia arriba).

    AVG() de SQLite suma en coma flotante en el orden en que recorre las filas,
    asi que la misma media sale como 7.5500000001 con un indice y 7.5499999999
    con otro; round() daba entonces 7,6 en estadisticas_mes y 7,5 en
    evolucion_mensual para el mismo mes (visto el 2026-09-03 con datos
    reales). Se cuantiza antes a 6 decimales para que ambas coincidan.
    None y 0 devuelven None: no hay dato, no se inventa.
    """
    if not valor:
        return None
    from decimal import ROUND_HALF_UP, Decimal
    try:
        cuantizado = Decimal(str(round(float(valor), 6)))
    except (TypeError, ValueError, ArithmeticError):
        return None
    return float(cuantizado.quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))


def estadisticas_mes(conn: sqlite3.Connection, month: str, *,
                     excluir_bajas: bool = False) -> dict[str, Any]:
    """Cifras del periodo. Protegido frente a total=0 (el sistema viejo dividia
    por cero al calcular el porcentaje de criticas). Con ``excluir_bajas`` la
    severidad Baja no cuenta (y ``bajas`` sale 0)."""
    filtro_bajas = " AND severity != 'Low'" if excluir_bajas else ""
    fila = conn.execute(
        """SELECT COUNT(*) AS total,
                  SUM(severity='Critical') AS criticas,
                  SUM(severity='High')     AS altas,
                  SUM(severity='Medium')   AS medias,
                  SUM(severity='Low')      AS bajas,
                  SUM(in_kev=1)            AS en_kev,
                  SUM(cve IS NOT NULL)     AS con_cve,
                  SUM(severity_source='nvd')       AS sev_nvd,
                  SUM(severity_source='heuristic') AS sev_heuristica,
                  AVG(NULLIF(cvss_score,0))        AS cvss_medio,
                  MAX(cvss_score)                  AS cvss_max
             FROM threats WHERE month=?""" + filtro_bajas,
        (month,),
    ).fetchone()

    total = fila["total"] or 0
    stats = {k: (fila[k] or 0) for k in fila.keys()}
    stats["total"] = total
    stats["cvss_medio"] = _media_1_decimal(fila["cvss_medio"])
    stats["cvss_max"] = fila["cvss_max"]
    stats["pct_criticas"] = round(stats["criticas"] * 100.0 / total, 1) if total else 0.0
    stats["pct_altas"] = round(stats["altas"] * 100.0 / total, 1) if total else 0.0
    stats["pct_con_cvss_real"] = (
        round(stats["sev_nvd"] * 100.0 / total, 1) if total else 0.0
    )
    stats["month"] = month
    return stats


# Ordenes admitidos por top_tecnologias. Las columnas son los alias del SELECT.
_ORDENES_TOP_TECNOLOGIAS = {
    "criticidad": "criticas DESC, altas DESC, amenazas DESC",
    "amenazas": "amenazas DESC, criticas DESC, altas DESC, tc.name",
}


def top_tecnologias(conn: sqlite3.Connection, month: Optional[str] = None,
                    limite: int = 15, *, orden: str = "criticidad",
                    excluir_bajas: bool = False) -> list[dict]:
    """Tecnologias del inventario con amenazas en el mes (o en todo el historico).

    ``orden`` decide tanto la secuencia como que ``limite`` filas se devuelven:

    * ``"criticidad"`` (por defecto): criticas DESC, altas DESC, amenazas DESC.
      Es el orden historico del informe mensual, los correos y el panel, que
      muestran la severidad y donde lo primero debe ser lo mas grave.
    * ``"amenazas"``: amenazas DESC, criticas DESC, altas DESC, nombre. Para
      Tendencias, cuyo grafico apila por veredicto de version y no por
      severidad: el criterio de orden tiene que leerse en la longitud de la
      barra (con el orden por criticidad la secuencia parecia aleatoria en la
      revision visual del 2026-09-03). Las 20 devueltas son asi las 20 con mas
      amenazas, no las 20 con mas criticas reordenadas.

    Un valor desconocido usa el orden por defecto.

    ``excluir_bajas`` (regla interna, ajuste ``ignore_low_severity``) deja fuera la
    severidad Baja. Sin el, la grafica de Tendencias apilaba criticas mas altas mas medias
    (129 en Microsoft Office) mientras la tabla de debajo mostraba ``amenazas``, que las
    incluia (136): dos cifras de lo mismo en la misma pantalla, y 33 amenazas de diferencia
    en el top 20 del mes (revision del 2026-09-09).
    """
    sin_bajas = " AND (t.severity IS NULL OR t.severity <> 'Low')" if excluir_bajas else ""
    sql = """SELECT tc.name, tc.slug, tc.version_installed, tc.criticality,
                    tc.systems_count, tc.exposure,
                    COUNT(DISTINCT tt.threat_id) AS amenazas,
                    SUM(t.severity='Critical') AS criticas,
                    SUM(t.severity='High')     AS altas,
                    SUM(t.severity='Medium')   AS medias,
                    SUM(tt.version_verdict='affected')     AS confirmadas,
                    SUM(tt.version_verdict='not_affected') AS no_aplicables,
                    SUM(tt.version_verdict='unknown')      AS sin_determinar
               FROM threat_technologies tt
               JOIN technologies tc ON tc.id = tt.technology_id
               JOIN threats t       ON t.id  = tt.threat_id"""
    params: list[Any] = []
    condiciones = []
    if month:
        condiciones.append("t.month=?")
        params.append(month)
    if sin_bajas:
        condiciones.append(sin_bajas[len(" AND "):])
    if condiciones:
        sql += " WHERE " + " AND ".join(condiciones)
    order_by = _ORDENES_TOP_TECNOLOGIAS.get(orden, _ORDENES_TOP_TECNOLOGIAS["criticidad"])
    sql += f" GROUP BY tc.id ORDER BY {order_by} LIMIT ?"
    params.append(limite)
    return db.rows_to_dicts(conn.execute(sql, params).fetchall())


def evolucion_mensual(conn: sqlite3.Connection, meses: int = 12, *,
                      excluir_bajas: bool = False) -> list[dict]:
    """Serie historica, del mes mas reciente al mas antiguo (DESC).

    Solo es posible desde que los datos estan en SQLite. Ademas de las claves
    historicas (month, total, criticas, altas, medias, en_kev) devuelve
    `bajas`, `sev_nvd` (severidad con CVSS oficial de NVD), `con_cve` y
    `cvss_medio` (media de los CVSS reales, sin ceros, a 1 decimal; None si el
    mes no tiene ninguno: nunca se inventa un numero). Ampliada el 2026-09-03
    para los graficos de Tendencias; el informe y el panel siguen usando las
    claves antiguas.
    """
    # ``excluir_bajas`` (regla interna, ajuste ignore_low_severity): la severidad Baja no
    # cuenta en el total ni en la media de CVSS, y «bajas» sale 0. Asi la serie mensual del
    # Panel y de Tendencias habla de las mismas tres severidades que el resto (2026-09-08).
    filtro = " WHERE (severity IS NULL OR severity <> 'Low')" if excluir_bajas else ""
    filas = db.rows_to_dicts(conn.execute(
        f"""SELECT month,
                   COUNT(*) AS total,
                   SUM(severity='Critical') AS criticas,
                   SUM(severity='High')     AS altas,
                   SUM(severity='Medium')   AS medias,
                   SUM(severity='Low')      AS bajas,
                   SUM(in_kev=1)            AS en_kev,
                   SUM(severity_source='nvd') AS sev_nvd,
                   SUM(cve IS NOT NULL)     AS con_cve,
                   AVG(NULLIF(cvss_score,0)) AS cvss_medio
              FROM threats{filtro}
             GROUP BY month ORDER BY month DESC LIMIT ?""",
        (meses,),
    ).fetchall())
    for fila in filas:
        for clave in ("total", "criticas", "altas", "medias", "bajas", "en_kev",
                      "sev_nvd", "con_cve"):
            fila[clave] = fila[clave] or 0
        fila["cvss_medio"] = _media_1_decimal(fila.get("cvss_medio"))
    return filas


def meses_disponibles(conn: sqlite3.Connection) -> list[str]:
    return [r[0] for r in conn.execute(
        "SELECT DISTINCT month FROM threats ORDER BY month DESC"
    )]


def cve_recurrentes(conn: sqlite3.Connection, limite: int = 20, *,
                    excluir_bajas: bool = True) -> list[dict]:
    """CVE vistos en mas de un mes: candidatos a deuda de parcheo.

    ``excluir_bajas`` (regla interna, ajuste ``ignore_low_severity``) deja fuera la
    severidad Baja Y las amenazas ya cerradas por el equipo (descartada o falso
    positivo), que es el mismo criterio con el que cuentan la pagina de Amenazas y la de
    Tendencias. Viene ACTIVO por omision, al reves que el resto de funciones de este
    modulo, a proposito (auditoria de tableros del 2026-09-15, punto 6): la tabla de CVE
    recurrentes de Tendencias era la UNICA fila de toda la plataforma que escribia el
    nombre de esa severidad, y quien llama a esta funcion no tiene que acordarse de
    pedirlo. Quien necesite el historico completo pasa ``excluir_bajas=False``.

    Medido sobre la copia de produccion del 2026-09-15: de los 185 CVE recurrentes, 6
    tenian esa severidad como maxima y salen de la tabla (1 de ellos estaba entre los 20
    que se ensenan).
    """
    filtro = ""
    if excluir_bajas:
        filtro = (" AND (severity IS NULL OR severity <> 'Low')"
                  f" AND (estado IS NULL OR estado NOT IN {_ESTADOS_CERRADOS_SQL})")
    return db.rows_to_dicts(conn.execute(
        f"""SELECT cve, COUNT(DISTINCT month) AS meses, SUM(times_seen) AS veces,
                  CASE MAX(CASE severity WHEN 'Critical' THEN 4 WHEN 'High' THEN 3
                                         WHEN 'Medium' THEN 2 WHEN 'Low' THEN 1 ELSE 0 END)
                       WHEN 4 THEN 'Critical' WHEN 3 THEN 'High' WHEN 2 THEN 'Medium'
                       WHEN 1 THEN 'Low' END AS severidad,
                  MAX(COALESCE(in_kev, 0)) AS en_kev, MIN(first_seen_at) AS primera_vez
             FROM threats WHERE cve IS NOT NULL{filtro}
            GROUP BY cve HAVING meses > 1
            ORDER BY meses DESC, veces DESC LIMIT ?""",
        (limite,),
    ).fetchall())


def exportar_json_mes(conn: sqlite3.Connection, month: str) -> dict[str, Any]:
    """Estructura compatible con los data/monthly_threats_*.json anteriores."""
    vistas = del_mes(conn, month)
    return {
        "mes": month,
        "generado": db.utcnow(),
        "total_mes": len(vistas),
        "estadisticas": estadisticas_mes(conn, month),
        "amenazas_acumuladas": [
            {
                "id": v["fingerprint"],
                "cve": v["cve"],
                "nombre": v["title_es"] or v["title_en"],
                "titulo_es": v["title_es"],
                "titulo_en": v["title_en"],
                "severidad": v["severity"],
                "cvss_score": v["cvss_score"],
                "origen_severidad": v["severity_source"],
                "descripcion_es": v["summary_es"],
                "descripcion_en": v["summary_en"],
                "tecnologias_afectadas": [t["name"] for t in v["technologies"]],
                "fecha_publicacion": v["published_at"],
                "fecha_deteccion": v["first_seen_at"],
                "en_kev": v["in_kev"],
                "epss": v["epss_score"],
                "impacto_es": v["impact_es"],
                "mitigacion_es": v["remediation_es"],
                "referencias": [s["url"] for s in v["sources"]],
                "relevancia": v["relevance"],
            }
            for v in vistas
        ],
    }


# --------------------------------------------------------------------------
# Cuantas amenazas hay, y que cuenta cada cifra (2026-09-07)
#
# El usuario pidio «cifras o graficas en el apartado de amenazas, cuantas amenazas
# en total, si son amenazas por activo o en total o como se determina este numero».
# Hay tres magnitudes distintas y confundirlas lleva a conclusiones falsas:
#
#   1. AMENAZAS REGISTRADAS: filas de `threats`, el catalogo de avisos recolectados.
#      Incluye las que no afectan a ningun equipo de la organizacion.
#   2. AMENAZAS CONFIRMADAS: de las anteriores, las que se han confirmado en al menos
#      un activo comparando la version instalada con la que corrige el fallo.
#   3. VULNERABILIDADES: UN CVE en UN activo (2026-09-09). El mismo CVE en cien
#      activos son cien vulnerabilidades y una sola amenaza; el mismo CVE en cinco
#      paquetes del mismo servidor (linux-image, linux-headers, linux-modules...) es
#      UNA vulnerabilidad. Hasta el 2026-09-08 se contaban filas de `aplicabilidad`
#      (una por paquete binario) y el usuario lo leyo, con razon, como duplicidad:
#      «si hay una vulnerabilidad de kernel que se repite que se cuente como una».
#      Los paquetes son la trazabilidad (que actualizar), no la unidad de conteo.
# --------------------------------------------------------------------------

#: Expresion que identifica una vulnerabilidad: el par (activo, CVE). El separador es
#: el caracter de control 31 (separador de unidad), que no puede aparecer ni en un
#: identificador numerico ni en un CVE, asi que dos pares distintos nunca colisionan.
VULNERABILIDAD_DISTINTA = "ap.activo_id || char(31) || ap.cve"


def sql_vulnerabilidades(alias: str = "ap", condicion: Optional[str] = None) -> str:
    """``COUNT(DISTINCT ...)`` de vulnerabilidades, el UNICO punto de verdad del conteo.

    Devuelve ``COUNT(DISTINCT <alias>.activo_id || char(31) || <alias>.cve)`` y, con
    ``condicion``, la version condicionada ``COUNT(DISTINCT CASE WHEN <condicion> THEN
    ... END)``, que sustituye a los ``SUM(t.severity = 'Critical')`` que contaban filas
    de paquete. ``alias`` es el de la tabla ``aplicabilidad`` en la consulta que lo usa
    y ``condicion`` es SQL fijo del propio codigo (nunca una entrada del usuario).
    """
    par = f"{alias}.activo_id || char(31) || {alias}.cve"
    if condicion:
        return f"COUNT(DISTINCT CASE WHEN {condicion} THEN {par} END)"
    return f"COUNT(DISTINCT {par})"


#: Severidades de mayor a menor. Es el orden de desempate de una vulnerabilidad
#: (2026-09-09).
SEVERIDADES_DESCENDENTES = ("Critical", "High", "Medium", "Low")


def sql_vulnerabilidades_severidad(severidad: str, alias: str = "ap",
                                   columna: str = "t.severity") -> str:
    """Vulnerabilidades de UNA severidad, con la severidad MAXIMA del par (activo, CVE).

    Por que hace falta el desempate (revision de precision del 2026-09-09): el catalogo
    tiene 28 CVE con amenazas de severidad distinta (por ejemplo CVE-2026-15409, una
    Critical y una Low), y `UNIQUE(activo_id, cve, paquete)` permite que el MISMO par
    (activo, CVE) tenga dos filas de `aplicabilidad` con severidades distintas (dos
    paquetes, dos amenazas). Con `sql_vulnerabilidades(condicion="t.severity='High'")`
    ese par se contaba en dos segmentos a la vez y `criticas + altas + medias` superaba
    el total de vulnerabilidades: la misma vulnerabilidad, dos veces. Hoy no hay ningun
    par asi en produccion, pero nada lo impide, y una cifra que puede dejar de cuadrar
    manana no sirve para reportar.

    Regla: UNA vulnerabilidad tiene UNA severidad, la mas alta de las amenazas que la
    declaran (Critical > High > Medium > Low). Se calcula sin subconsulta correlacionada
    (178.007 filas en `aplicabilidad`: una por fila seria inaceptable) como diferencia de
    dos conteos de pares distintos: los pares con severidad igual o superior a la pedida
    menos los pares con severidad estrictamente superior. El resultado es exacto y los
    segmentos son excluyentes, asi que su suma nunca pasa del total.

    ``severidad`` es una de :data:`SEVERIDADES_DESCENDENTES` (SQL fijo del propio codigo,
    nunca una entrada del usuario; cualquier otro valor es un error de programacion).
    ``columna`` permite usar otro alias de ``threats`` en la consulta que lo llame.
    Una severidad desconocida (NULL) no entra en ningun segmento: la cuenta
    :func:`sql_vulnerabilidades_sin_severidad`, para que ninguna vulnerabilidad se
    quede fuera de todos los segmentos.
    """
    if severidad not in SEVERIDADES_DESCENDENTES:
        raise ValueError(f"severidad no valida: {severidad!r}")
    corte = SEVERIDADES_DESCENDENTES.index(severidad)
    hasta = SEVERIDADES_DESCENDENTES[:corte + 1]
    encima = SEVERIDADES_DESCENDENTES[:corte]
    lista = ",".join(f"'{s}'" for s in hasta)
    igual_o_superior = sql_vulnerabilidades(alias, f"{columna} IN ({lista})")
    if not encima:
        return igual_o_superior
    superior = sql_vulnerabilidades(alias, f"{columna} IN ({','.join(chr(39) + s + chr(39) for s in encima)})")
    return f"({igual_o_superior} - {superior})"


def sql_vulnerabilidades_sin_severidad(alias: str = "ap",
                                       columna: str = "t.severity") -> str:
    """Vulnerabilidades cuya severidad NO se conoce en ninguna de sus amenazas.

    Por que existe (revision de seguridad del 2026-09-09): los segmentos por severidad
    solo cuentan los pares (activo, CVE) con una severidad conocida, asi que un par cuyas
    amenazas tengan ``severity`` NULL (o un valor que no sea ninguna de las cuatro
    severidades) contaba en el total de vulnerabilidades y en ningun segmento; la barra
    perdia ese trozo y la suma de segmentos no cuadraba con el total sin que nada lo
    dijera. Con esta cifra, los cinco segmentos (criticas, altas, medias, bajas y sin
    severidad conocida) son EXCLUYENTES y COMPLETOS: suman exactamente el total.

    Es la definicion declarativa de esa cifra: todos los pares menos los que tienen alguna
    severidad conocida, sin subconsulta correlacionada. ``resumen_amenazas`` NO la usa en
    sus consultas: la obtiene restando los cuatro segmentos del total, que da el mismo
    numero (los segmentos son excluyentes y las severidades conocidas son solo cuatro) y
    cuesta cero, mientras que anadirla al SELECT costaba dos ``COUNT(DISTINCT)`` mas por
    consulta (medido en la base real: el resumen pasaba de 700 ms a 900 ms).
    ``tests/test_cifras_amenazas.py`` comprueba que los dos caminos coinciden.
    """
    lista = ",".join(f"'{s}'" for s in SEVERIDADES_DESCENDENTES)
    todos = sql_vulnerabilidades(alias)
    conocidos = sql_vulnerabilidades(alias, f"{columna} IN ({lista})")
    return f"({todos} - {conocidos})"


def _anotar_sin_severidad(fila: dict) -> dict:
    """Anade a una fila del reparto el segmento ``sin_severidad`` que le falta.

    ``sin_severidad = vulnerabilidades - criticas - altas - medias - bajas``. La resta es
    exacta porque los cuatro segmentos son excluyentes y su suma es, por construccion, el
    numero de pares (activo, CVE) con alguna severidad conocida. Se acota a 0 por si un
    cambio futuro rompiera la exclusion: una cifra negativa en una barra seria peor que
    una diferencia, y las pruebas vigilan la igualdad.
    """
    conocidas = sum(int(fila.get(c) or 0) for c in ("criticas", "altas", "medias", "bajas"))
    fila["sin_severidad"] = max(int(fila.get("vulnerabilidades") or 0) - conocidas, 0)
    return fila


#: Amenazas que siguen contando: descartada, falso positivo y mitigada no suman.
_VIVA_AMENAZA = ("(t.id IS NULL OR t.estado NOT IN "
                 "('descartada','falso_positivo','mitigada'))")

#: Etiquetas de los grupos cuando el activo no tiene proceso de negocio. Coinciden con
#: las de ``threatintel.remediacion`` para que la plataforma hable de lo mismo.
GRUPO_EQUIPOS_SIN_PROCESO = "Equipos de cómputo (Mantenimiento)"
GRUPO_SERVIDORES_SIN_PROCESO = "Servidores sin proceso asignado"

_GRUPO_SQL = (f"CASE WHEN COALESCE(NULLIF(a.proceso, ''), '') <> '' THEN a.proceso "
              f"WHEN a.origen = 'equipos' THEN '{GRUPO_EQUIPOS_SIN_PROCESO}' "
              f"ELSE '{GRUPO_SERVIDORES_SIN_PROCESO}' END")

ORIGEN_AMENAZAS_ES = {"servidores": "Servidores", "equipos": "Equipos de cómputo"}


def _filtro_parque(proceso: Optional[str] = None,
                   origen: Optional[str] = None) -> tuple[str, list]:
    """Condiciones extra sobre ``activos a`` para acotar por proceso o por tipo."""
    condiciones, params = [], []
    if origen in ("servidores", "equipos"):
        condiciones.append("a.origen = ?")
        params.append(origen)
    if proceso:
        if proceso == GRUPO_EQUIPOS_SIN_PROCESO:
            condiciones.append("(COALESCE(NULLIF(a.proceso,''),'')='' AND a.origen='equipos')")
        elif proceso == GRUPO_SERVIDORES_SIN_PROCESO:
            condiciones.append("(COALESCE(NULLIF(a.proceso,''),'')='' AND a.origen='servidores')")
        else:
            condiciones.append("a.proceso = ?")
            params.append(proceso)
    return ("".join(f" AND {c}" for c in condiciones), params)


def filtro_parque(proceso: Optional[str] = None,
                  origen: Optional[str] = None) -> tuple[str, list]:
    """Igual que ``_filtro_parque``, publica para las vistas.

    La vista de Amenazas necesita acotar el denominador exactamente igual que el
    numerador: escrito otra vez alli, al filtrar por un proceso saldria «171 de
    511», que compara el proceso con todo el parque. Se publica para que no
    dependa de un nombre privado (revision del 2026-09-08).
    """
    return _filtro_parque(proceso, origen)


#: Condicion que deja fuera la severidad Baja. Regla interna del equipo (2026-09-04,
#: reiterada el 2026-09-08): «las amenazas o vulnerabilidades bajas no se reportan», asi
#: que con el ajuste activo (lo normal) solo existen TRES segmentos: criticas, altas y
#: medias. Una severidad desconocida (NULL: un veredicto cuya amenaza ya no esta en el
#: catalogo) no es «baja» y sigue contando; desde el 2026-09-09 cuenta en su propio
#: segmento, `sin_severidad`, para que la suma de segmentos sea siempre el total.
_SIN_BAJAS = "(t.severity IS NULL OR t.severity <> 'Low')"


def _umbral_sin_reportar(conn: sqlite3.Connection) -> str:
    """Fecha ISO por debajo de la cual un activo «no reporta» (ajuste ``ocs_stale_days``).

    Se calcula aqui y no se importa de ``threatintel.ocs`` porque ese modulo importa
    este: seria una importacion circular. El ajuste se lee de la propia base con la misma
    conexion de la consulta, igual que ``remediacion.excluir_bajas``, de modo que la
    pagina de Amenazas y la de Activos usan el mismo plazo sin tener que pasarselo.
    """
    try:
        dias = int(float(db.get_setting(conn, "ocs_stale_days", 30) or 30))
    except (TypeError, ValueError):
        dias = 30
    return conn.execute("SELECT strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?)",
                        (f"-{max(1, dias)} days",)).fetchone()[0]


def resumen_amenazas(conn: sqlite3.Connection, *, proceso: Optional[str] = None,
                     origen: Optional[str] = None,
                     incluir_bajas: bool = False) -> dict[str, Any]:
    """Las tres magnitudes de arriba, mas el reparto por tipo de equipo y por proceso.

    ``proceso`` y ``origen`` acotan lo que se cuenta del parque; el catalogo
    (``registradas``, ``con_cve``) no depende del parque y no se filtra.

    ``incluir_bajas`` (False por omision) deja fuera de TODAS las cifras las amenazas de
    severidad Baja, catalogo incluido: por regla interna no se reportan, y entonces cada
    barra se parte en exactamente tres segmentos, criticas, altas y medias (``medias`` es
    Medium; ``bajas`` sale 0 por construccion). Con ``incluir_bajas`` las bajas cuentan y
    aparece el cuarto segmento, ``bajas``. La vista pasa ``not ignore_low_severity``.

    Los segmentos son EXCLUYENTES y COMPLETOS: si el mismo par (activo, CVE) llega con dos
    severidades distintas (dos paquetes, dos amenazas) cuenta una sola vez, en la mas
    alta (:func:`sql_vulnerabilidades_severidad`, 2026-09-09), y un par cuyas amenazas no
    declaran severidad cuenta en ``sin_severidad``
    (:func:`sql_vulnerabilidades_sin_severidad`, revision de seguridad del 2026-09-09).
    Asi, en cada fila del reparto y en el total del ambito se cumple siempre
    ``criticas + altas + medias + bajas + sin_severidad == vulnerabilidades``: antes, con
    las bajas dentro, 1.233 vulnerabilidades de la base real contaban en el total y en
    ningun segmento, la barra perdia ese trozo y nada lo advertia.

    El RIESGO ACEPTADO tampoco cuenta (2026-09-10): lo que cubre una excepcion vigente
    (``threatintel.excepciones``) sale de TODAS estas cifras, igual que la severidad
    baja, porque las dos condiciones significan lo mismo, «esta fila no cuenta». Y como
    una cifra que baja por aceptacion de riesgo y no por correccion tiene que verse, se
    devuelven dos claves mas: ``con_excepciones`` (si la exclusion se esta aplicando) y
    ``vulnerabilidades_aceptadas`` (cuantas vulnerabilidades han salido de las cifras por
    esa causa, contadas como la diferencia exacta entre lo que habria y lo que hay).
    """
    extra, params = _filtro_parque(proceso, origen)
    sin_bajas = "" if incluir_bajas else f" AND {_SIN_BAJAS}"
    # « AND <no cubierta por una excepcion vigente>», o cadena vacia si no hay ninguna:
    # sin excepciones registradas las consultas quedan EXACTAMENTE como estaban.
    sin_excepcion = excepciones.y_sin_excepcion(conn)
    sin_bajas_catalogo = "" if incluir_bajas else " AND (severity IS NULL OR severity <> 'Low')"
    # Con las bajas fuera, el segmento de bajas es 0 por construccion (sus filas ya no
    # estan en `base`): se escribe la constante en vez de dos COUNT(DISTINCT) mas por
    # consulta. Medido el 2026-09-09 en la base real: calcularlo cuando no hace falta
    # subia el resumen de 690 ms a 915 ms, un 33 % de mas por una cifra que solo puede
    # valer 0. El segmento «sin severidad conocida» SI se calcula siempre, porque una
    # severidad NULL no es una baja y sobrevive al filtro.
    sql_bajas = sql_vulnerabilidades_severidad("Low") if incluir_bajas else "0"
    # El catalogo cuenta con el MISMO criterio de cierre que el listado de la
    # pagina (ESTADOS_CERRADOS: descartada y falso positivo). Antes excluia
    # tambien las mitigadas, asi que en cuanto alguien marcaba una amenaza como
    # mitigada la misma pantalla mostraba dos totales distintos sin explicacion
    # (revision del 2026-09-08). Las mitigadas siguen fuera del recuento de
    # confirmadas, porque `_VIVA_AMENAZA` no las cuenta: eso es correcto, una
    # amenaza mitigada ya no pide trabajo.
    cerrados = ",".join("?" * len(ESTADOS_CERRADOS))
    catalogo = conn.execute(
        f"""SELECT COUNT(*) AS registradas,
                   SUM(cve IS NOT NULL) AS con_cve,
                   SUM(in_kev = 1) AS en_kev
              FROM threats
             WHERE estado NOT IN ({cerrados}){sin_bajas_catalogo}""", ESTADOS_CERRADOS).fetchone()
    # ``base_con_aceptadas`` es el ambito TAL CUAL, con el riesgo aceptado dentro: solo
    # se usa para poder decir cuantas vulnerabilidades desaparecen por esa causa.
    base_con_aceptadas = (f"""FROM aplicabilidad ap JOIN activos a ON a.id = ap.activo_id
                LEFT JOIN threats t ON t.id = ap.threat_id
               WHERE ap.veredicto = 'afectado' AND a.presente = 1
                 AND {_VIVA_AMENAZA}{sin_bajas}{extra}""")
    base = base_con_aceptadas + sin_excepcion
    # El total del ambito trae tambien sus cinco segmentos: la pagina necesita decir
    # cuantas vulnerabilidades hay de cada severidad sin volver a consultar, y la prueba
    # comprueba con ellos que la suma cuadra con el total (2026-09-09).
    # Activos que NO REPORTAN (2026-09-10, tarde). Los que llevan mas de
    # ``ocs_stale_days`` dias sin enviar inventario tienen sus vulnerabilidades
    # calculadas sobre datos viejos: ni afirmarlas ni negarlas es honesto. Se cuentan
    # aparte, en la MISMA pasada, para que la pagina pueda decir «24.489 con dato al dia
    # y 4.023 mas sobre datos de hace mas de 30 dias» en lugar de un 28.512 que no
    # distingue. Los cuatro marcadores «?» de la condicion van en el SELECT, es decir
    # ANTES de los de ``extra`` en el WHERE, asi que encabezan la lista de parametros.
    umbral = _umbral_sin_reportar(conn)
    fresco = "(a.ultimo_inventario IS NOT NULL AND a.ultimo_inventario >= ?)"
    parque = conn.execute(
        f"""SELECT {sql_vulnerabilidades()} AS vulnerabilidades,
                   COUNT(DISTINCT ap.threat_id) AS amenazas,
                   COUNT(DISTINCT ap.activo_id) AS activos,
                   COUNT(DISTINCT ap.cve) AS cve,
                   {sql_vulnerabilidades(condicion="t.in_kev = 1")} AS vulnerabilidades_kev,
                   {sql_vulnerabilidades_severidad('Critical')} AS criticas,
                   {sql_vulnerabilidades_severidad('High')} AS altas,
                   {sql_vulnerabilidades_severidad('Medium')} AS medias,
                   {sql_bajas} AS bajas,
                   {sql_vulnerabilidades(condicion=fresco)} AS vulnerabilidades_con_dato,
                   COUNT(DISTINCT CASE WHEN {fresco} THEN ap.activo_id END) AS activos_con_dato,
                   {sql_vulnerabilidades(condicion=f"NOT {fresco}")} AS vulnerabilidades_sin_reportar,
                   COUNT(DISTINCT CASE WHEN NOT {fresco} THEN ap.activo_id END) AS activos_sin_reportar
              {base}""", [umbral] * 4 + list(params)).fetchone()
    total_sin_severidad = _anotar_sin_severidad(dict(parque))["sin_severidad"]
    # Cuantas vulnerabilidades del ambito han salido de las cifras por una aceptacion de
    # riesgo: la DIFERENCIA exacta entre lo que habria y lo que hay, no un conteo
    # aproximado de filas cubiertas (un mismo par activo-CVE puede tener un paquete
    # cubierto por una excepcion de paquete y otro que sigue contando, y entonces no
    # desaparece). Solo se consulta cuando hay alguna excepcion vigente.
    if sin_excepcion:
        con_aceptadas = int(conn.execute(
            f"SELECT {sql_vulnerabilidades()} AS vulnerabilidades {base_con_aceptadas}",
            params).fetchone()[0] or 0)
        vulnerabilidades_aceptadas = max(0, con_aceptadas - int(parque["vulnerabilidades"] or 0))
    else:
        vulnerabilidades_aceptadas = 0

    # Denominadores: los activos presentes del ambito, con el mismo recorte. Viven
    # aqui, en la misma funcion que el numerador, para que no puedan divergir
    # (peticion de la revision del 2026-09-08).
    fila_p = conn.execute(
        f"""SELECT COUNT(*) AS total,
                   SUM(a.origen = 'servidores') AS servidores,
                   SUM(a.origen = 'equipos') AS equipos,
                   SUM(NOT {fresco}) AS sin_reportar
              FROM activos a
             WHERE a.presente = 1{extra}""", [umbral] + list(params)).fetchone()
    presentes = {"total": int(fila_p["total"] or 0),
                 "servidores": int(fila_p["servidores"] or 0),
                 "equipos": int(fila_p["equipos"] or 0),
                 # Denominador honesto: los activos del ambito cuyo inventario esta al
                 # dia. Un porcentaje calculado sobre el total contaria como «limpios»
                 # a los que llevan un mes sin decir nada.
                 "sin_reportar": int(fila_p["sin_reportar"] or 0),
                 "con_dato": max(0, int(fila_p["total"] or 0) - int(fila_p["sin_reportar"] or 0))}

    por_origen = []
    for fila in conn.execute(
            f"""SELECT a.origen AS origen, {sql_vulnerabilidades()} AS vulnerabilidades,
                       COUNT(DISTINCT ap.threat_id) AS amenazas,
                       COUNT(DISTINCT ap.activo_id) AS activos,
                       {sql_vulnerabilidades_severidad('Critical')} AS criticas,
                       {sql_vulnerabilidades_severidad('High')} AS altas,
                       {sql_vulnerabilidades_severidad('Medium')} AS medias,
                       {sql_bajas} AS bajas
                  {base}
                 GROUP BY a.origen ORDER BY vulnerabilidades DESC""", params):
        d = _anotar_sin_severidad(dict(fila))
        d["origen_es"] = ORIGEN_AMENAZAS_ES.get(d["origen"], d["origen"])
        d["presentes"] = int(presentes.get(d["origen"]) or 0)
        por_origen.append(d)

    por_proceso = []
    for fila in conn.execute(
            f"""SELECT {_GRUPO_SQL} AS proceso, {sql_vulnerabilidades()} AS vulnerabilidades,
                       COUNT(DISTINCT ap.threat_id) AS amenazas,
                       COUNT(DISTINCT ap.activo_id) AS activos,
                       {sql_vulnerabilidades_severidad('Critical')} AS criticas,
                       {sql_vulnerabilidades_severidad('High')} AS altas,
                       {sql_vulnerabilidades_severidad('Medium')} AS medias,
                       {sql_bajas} AS bajas,
                       {sql_vulnerabilidades(condicion="a.origen = 'equipos'")} AS de_equipos,
                       {sql_vulnerabilidades(condicion="a.origen = 'servidores'")} AS de_servidores,
                       COUNT(DISTINCT CASE WHEN a.origen='servidores' THEN ap.activo_id END)
                           AS activos_de_servidores,
                       COUNT(DISTINCT CASE WHEN a.origen='equipos' THEN ap.activo_id END)
                           AS activos_de_equipos
                  {base}
                 GROUP BY 1 ORDER BY vulnerabilidades DESC""", params):
        por_proceso.append(_anotar_sin_severidad(dict(fila)))

    # Presentes de cada grupo de proceso: sin este denominador la nota de la barra
    # decia «171 servidores afectados» y no se podia comparar con «33 servidores
    # afectados» de otro grupo, que es justo lo que se pidio poder hacer.
    presentes_grupo: dict[str, dict[str, int]] = {}
    for fila in conn.execute(
            f"""SELECT {_GRUPO_SQL} AS proceso, COUNT(*) AS total,
                       SUM(a.origen = 'servidores') AS servidores,
                       SUM(a.origen = 'equipos') AS equipos
                  FROM activos a
                 WHERE a.presente = 1{extra}
                 GROUP BY 1""", params):
        presentes_grupo[fila["proceso"]] = {
            "total": int(fila["total"] or 0),
            "servidores": int(fila["servidores"] or 0),
            "equipos": int(fila["equipos"] or 0)}
    for fila in por_proceso:
        p_g = presentes_grupo.get(fila["proceso"], {"total": 0, "servidores": 0, "equipos": 0})
        fila["presentes"] = p_g["total"]
        fila["presentes_servidores"] = p_g["servidores"]
        fila["presentes_equipos"] = p_g["equipos"]

    registradas = int(catalogo["registradas"] or 0)
    confirmadas = int(parque["amenazas"] or 0)
    # Con filtro puesto, «confirmadas» son las del ambito, asi que
    # registradas - confirmadas NO son «las que no estan confirmadas en ningun
    # activo»: son las que no lo estan DENTRO del ambito. Se devuelven las dos
    # cifras para que la pantalla pueda decir cada una por su nombre (revision
    # del 2026-09-08).
    if proceso or origen:
        confirmadas_global = int(conn.execute(
            f"""SELECT COUNT(DISTINCT ap.threat_id)
                  FROM aplicabilidad ap JOIN activos a ON a.id = ap.activo_id
                  LEFT JOIN threats t ON t.id = ap.threat_id
                 WHERE ap.veredicto = 'afectado' AND a.presente = 1
                   AND {_VIVA_AMENAZA}{sin_bajas}{sin_excepcion}""").fetchone()[0] or 0)
    else:
        confirmadas_global = confirmadas
    # «Sin confirmar» por diferencia de CONJUNTOS, no de totales: el catalogo cuenta con
    # ESTADOS_CERRADOS (dos estados) y las confirmadas con `_VIVA_AMENAZA` (que excluye
    # ademas las mitigadas), asi que «registradas - confirmadas» habria contado como «no
    # confirmada en ningun activo» a una amenaza mitigada que si lo esta (revision de
    # seguridad del 2026-09-08). Aqui se cuentan las registradas cuyo identificador no
    # aparece confirmado en ningun activo presente, del ambito y de todo el parque.
    # Una amenaza cuya afectacion esta confirmada SOLO en activos con el riesgo
    # aceptado cuenta como «sin confirmar en el parque»: es la misma regla que en el
    # resto de las cifras y evita que la pagina diga «confirmada» de algo que no aparece
    # en ninguna de ellas.
    confirmadas_en = (f"""SELECT DISTINCT ap.threat_id FROM aplicabilidad ap
                            JOIN activos a ON a.id = ap.activo_id
                           WHERE ap.veredicto = 'afectado' AND a.presente = 1
                                 {sin_excepcion}""")
    sin_confirmar = int(conn.execute(
        f"""SELECT COUNT(*) FROM threats
             WHERE estado NOT IN ({cerrados}){sin_bajas_catalogo}
               AND id NOT IN ({confirmadas_en}{extra})""",
        [*ESTADOS_CERRADOS, *params]).fetchone()[0] or 0)
    sin_confirmar_global = (sin_confirmar if not (proceso or origen) else int(conn.execute(
        f"""SELECT COUNT(*) FROM threats
             WHERE estado NOT IN ({cerrados}){sin_bajas_catalogo}
               AND id NOT IN ({confirmadas_en})""",
        ESTADOS_CERRADOS).fetchone()[0] or 0))
    return {
        "registradas": registradas,
        "presentes": presentes,
        "confirmadas_global": confirmadas_global,
        "sin_confirmar_global": sin_confirmar_global,
        "con_cve": int(catalogo["con_cve"] or 0),
        "en_kev": int(catalogo["en_kev"] or 0),
        "confirmadas": confirmadas,
        "sin_confirmar": sin_confirmar,
        "vulnerabilidades": int(parque["vulnerabilidades"] or 0),
        "vulnerabilidades_kev": int(parque["vulnerabilidades_kev"] or 0),
        # Los cinco segmentos del ambito completo, excluyentes y con suma igual al total.
        "criticas": int(parque["criticas"] or 0),
        "altas": int(parque["altas"] or 0),
        "medias": int(parque["medias"] or 0),
        "bajas": int(parque["bajas"] or 0),
        "sin_severidad": total_sin_severidad,
        "activos_afectados": int(parque["activos"] or 0),
        "cve_confirmados": int(parque["cve"] or 0),
        "por_origen": por_origen,
        "por_proceso": por_proceso,
        "proceso": proceso or "",
        "origen": origen or "",
        "incluye_bajas": bool(incluir_bajas),
        #: Si hay alguna excepcion vigente sacando vulnerabilidades de estas cifras, y
        #: cuantas son (2026-09-10). La pagina tiene que poder decir que una parte de la
        #: bajada es riesgo aceptado y no trabajo hecho.
        "con_excepciones": bool(sin_excepcion),
        "vulnerabilidades_aceptadas": vulnerabilidades_aceptadas,
        # ------------------------------------------------------------------
        # Activos que NO REPORTAN (2026-09-10). Ni se ocultan ni se afirman: se
        # dicen aparte, con su cifra, y la pagina enlaza a su lista. Las cifras
        # «_con_dato» son las mismas magnitudes calculadas SOLO sobre los activos
        # cuyo inventario esta al dia, excluidos del numerador Y del denominador.
        # ------------------------------------------------------------------
        "dias_sin_reportar": int(float(db.get_setting(conn, "ocs_stale_days", 30) or 30)),
        "sin_reportar_activos": int(presentes["sin_reportar"] or 0),
        "sin_reportar_afectados": int(parque["activos_sin_reportar"] or 0),
        "sin_reportar_vulnerabilidades": int(parque["vulnerabilidades_sin_reportar"] or 0),
        "vulnerabilidades_con_dato": int(parque["vulnerabilidades_con_dato"] or 0),
        "activos_afectados_con_dato": int(parque["activos_con_dato"] or 0),
        "presentes_con_dato": int(presentes["con_dato"] or 0),
    }


def vulnerabilidades_pendientes_sin_confirmar(conn: sqlite3.Connection, *,
                                              proceso: Optional[str] = None,
                                              origen: Optional[str] = None,
                                              incluir_bajas: bool = False) -> int:
    """Vulnerabilidades PENDIENTES en Remediacion que hoy no estan confirmadas aqui.

    Por que existe (revision de claridad del 2026-09-15). El Panel y la pagina de
    Amenazas decian «32.701 vulnerabilidades confirmadas» y la pagina de Remediacion
    «32.823 pendientes», y lo pendiente tiene que ser un subconjunto de lo confirmado:
    una de las dos pantallas mentia. Medido sobre una copia de la base real, la
    diferencia eran 122 pares (activo, CVE) —todos del mismo CVE— cuya fila de
    `aplicabilidad` DESAPARECIO mientras el paquete sigue instalado con la misma version
    vulnerable. `remediacion.sincronizar` (paso 4) deja esas remediaciones abiertas a
    proposito: cerrarlas seria afirmar una correccion que nadie ha comprobado. El
    conjunto de confirmadas es por tanto un subconjunto ESTRICTO del de pendientes, y
    la diferencia es exactamente lo que cuenta esta funcion:

        pendientes en Remediacion = vulnerabilidades confirmadas + este numero

    (comprobado sobre la copia: 32.701 + 122 = 32.823, y no hay ninguna confirmada que
    no este pendiente). Las dos pantallas pueden asi decir la misma verdad sin que una
    desmienta a la otra, en lugar de callar la diferencia.

    Se cuenta con EXACTAMENTE los mismos criterios que las dos cifras que concilia: el
    filtro de severidad baja de ``remediacion._SIN_BAJAS_SQL`` (por ``threat_id`` de la
    remediacion), el de excepciones vigentes de ``excepciones``, solo activos presentes
    y solo remediaciones abiertas. ``proceso`` y ``origen`` acotan igual que en
    :func:`resumen_amenazas`.

    Coste medido sobre la copia de produccion (48.291 remediaciones abiertas y 178.007
    filas de `aplicabilidad`): 130 a 185 ms. Se llama UNA vez por pagina y solo para
    escribir la nota; ninguna cifra depende de ella.
    """
    extra, params = _filtro_parque(proceso, origen)
    sin_bajas = "" if incluir_bajas else (
        " AND NOT EXISTS (SELECT 1 FROM threats tb WHERE tb.id = r.threat_id"
        " AND tb.severity = 'Low')")
    sin_excepcion_rem = excepciones.y_sin_excepcion(
        conn, activo="r.activo_id", cve="r.cve", paquete="r.paquete")
    sin_excepcion_ap = excepciones.y_sin_excepcion(conn)
    try:
        fila = conn.execute(
            f"""SELECT COUNT(*) FROM (
                    SELECT DISTINCT r.activo_id, r.cve
                      FROM remediaciones r JOIN activos a ON a.id = r.activo_id
                     WHERE r.estado = 'abierta' AND r.cve IS NOT NULL AND r.cve <> ''
                       AND a.presente = 1{sin_bajas}{sin_excepcion_rem}{extra}
                       AND NOT EXISTS (
                            SELECT 1 FROM aplicabilidad ap
                              LEFT JOIN threats t ON t.id = ap.threat_id
                             WHERE ap.activo_id = r.activo_id AND ap.cve = r.cve
                               AND ap.veredicto = 'afectado' AND {_VIVA_AMENAZA}
                               AND {_SIN_BAJAS}{sin_excepcion_ap}))""",
            list(params) * 1).fetchone()
    except sqlite3.Error:
        # Una base sin la tabla `remediaciones` (esquema anterior) no rompe la pagina:
        # sin cola de remediacion no hay nada que conciliar.
        return 0
    return int((fila[0] if fila else 0) or 0)


def procesos_del_parque(conn: sqlite3.Connection, *, incluir_bajas: bool = False,
                        origen: Optional[str] = None) -> list[str]:
    """Grupos de proceso con alguna vulnerabilidad confirmada, para el selector.
    Con el mismo criterio de severidad que ``resumen_amenazas``, para que no aparezca en
    el selector un proceso cuyas cifras salgan todas a cero. ``origen`` (2026-09-08)
    acota al tipo de maquina: el perfil de Redes no debe ver en el selector el grupo
    «Equipos de cómputo (Mantenimiento)». Un proceso cuyas unicas vulnerabilidades
    tienen el riesgo aceptado con una excepcion vigente tampoco aparece (2026-09-10):
    sus cifras saldrian todas a cero, que es el mismo motivo de siempre."""
    sin_bajas = "" if incluir_bajas else f" AND {_SIN_BAJAS}"
    sin_excepcion = excepciones.y_sin_excepcion(conn)
    extra, params = _filtro_parque(None, origen)
    return [r[0] for r in conn.execute(
        f"""SELECT DISTINCT {_GRUPO_SQL}
              FROM aplicabilidad ap JOIN activos a ON a.id = ap.activo_id
              LEFT JOIN threats t ON t.id = ap.threat_id
             WHERE ap.veredicto = 'afectado' AND a.presente = 1
                   AND {_VIVA_AMENAZA}{sin_bajas}{sin_excepcion}{extra}
             ORDER BY 1""", params)]


# --------------------------------------------------------------------------
# Serie anual (Tendencias, 2026-09-08)
# --------------------------------------------------------------------------
def serie_anual(conn: sqlite3.Connection, *, excluir_bajas: bool = False) -> list[dict]:
    """Amenazas registradas por año natural, del más reciente al más antiguo (DESC).

    El usuario pidió el 2026-09-08 «un apartado para poder ver una serie anual de
    vulnerabilidades» en Tendencias. Cada fila trae ``anio`` («2026»), ``total``,
    ``criticas``, ``altas``, ``medias``, ``bajas``, ``en_kev`` y ``meses`` (cuántos
    meses distintos del año tienen datos: un año con tres meses no se puede comparar
    a ciegas con uno de doce, así que la cifra acompaña a la barra).

    Con ``excluir_bajas`` (regla interna, ajuste ``ignore_low_severity``) la severidad
    Baja no cuenta en ninguna cifra y ``bajas`` sale 0, igual que en
    :func:`evolucion_mensual`: el total anual es la suma exacta de los doce meses que
    la página muestra debajo. El año se toma de ``threats.month`` («AAAA-MM»), que es
    el mismo campo que agrupa la serie mensual, para que ambas series cuadren.
    """
    condiciones = ["month IS NOT NULL"]
    if excluir_bajas:
        condiciones.append("(severity IS NULL OR severity <> 'Low')")
    filas = db.rows_to_dicts(conn.execute(
        f"""SELECT substr(month, 1, 4) AS anio,
                   COUNT(*)                 AS total,
                   SUM(severity='Critical') AS criticas,
                   SUM(severity='High')     AS altas,
                   SUM(severity='Medium')   AS medias,
                   SUM(severity='Low')      AS bajas,
                   SUM(in_kev=1)            AS en_kev,
                   COUNT(DISTINCT month)    AS meses
              FROM threats
             WHERE {' AND '.join(condiciones)}
             GROUP BY anio ORDER BY anio DESC""").fetchall())
    for fila in filas:
        fila["anio"] = str(fila["anio"])
        for clave in ("total", "criticas", "altas", "medias", "bajas", "en_kev", "meses"):
            fila[clave] = int(fila[clave] or 0)
    return filas

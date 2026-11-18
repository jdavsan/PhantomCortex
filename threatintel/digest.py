"""Resumen semanal: lo que la alerta diaria NO envio, con su porque.

Desde el 2026-09-04 la alerta diaria solo lleva lo que realmente impacta a la
organizacion (relevancia >= umbral o KEV, con identificador, sin severidades
estimadas recien llegadas). Todo lo demas no desaparece: una vez por semana se
envia este resumen, que agrupa las amenazas correlacionadas con el inventario
por tecnologia (seguimiento), lista el resto de severidad media o superior
(informativo), explica en lenguaje llano por que el filtro descarto cada grupo
y recuerda lo que si se alerto en la semana.

El correo usa la misma plantilla base que la alerta (`emails/base.html`) y el
mismo `notify.Mailer`. Las amenazas incluidas quedan marcadas con `digest_at`
para que no se repitan la semana siguiente.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

from . import notify, queries
from .logging_setup import get_logger

log = get_logger("digest")

#: Relevancia a partir de la cual una amenaza correlacionada entra en
#: «Seguimiento» aunque no llegue al umbral de alerta.
RELEVANCIA_SEGUIMIENTO = 25.0

#: Tope del recordatorio de alertadas (las mas relevantes primero).
MAX_ALERTADAS_RECORDATORIO = 40

#: Severidades que entran en «Informativo» (el resto no aporta nada semanal).
SEVERIDADES_INFORMATIVO = ("Critical", "High", "Medium")

#: Frase por motivo de exclusion; ``{n}`` es la cifra y ``{umbral}`` y
#: ``{horas}`` los ajustes vigentes. Redactadas para quien no conoce el filtro.
FRASES_MOTIVO = {
    "relevancia_baja": (
        "{n} {tenian} una relevancia inferior a {umbral} para la organización: "
        "no {afectan} a tecnologías críticas o expuestas del inventario, o la "
        "coincidencia era una simple mención."),
    "sin_identificador": (
        "{n} no {traian} CVE ni identificador de aviso (DSA, USN, RHSA…): "
        "{son} noticias, campañas o artículos, no vulnerabilidades concretas."),
    "heuristica_en_espera": (
        "{n} {tenian} la severidad estimada a partir del texto, sin CVSS oficial, y "
        "se {dejaron} {horas} horas a la espera de la puntuación de NVD antes de "
        "decidir; las que la superaron ya se alertaron."),
    "sin_activos_afectados": (
        "{n} no {tenian} ningún activo con la versión vulnerable instalada según OCS "
        "Inventory: los activos ya {llevaban} la corrección o la distribución no estaba afectada."),
    "sin_activos_confirmados": (
        "{n} no {tenian} la afectación confirmada en ninguna máquina: ningún servidor ni "
        "equipo de cómputo del inventario tiene la versión vulnerable confirmada según OCS "
        "Inventory. No es lo mismo que «no nos afecta»: es que todavía no se ha podido "
        "confirmar que nos afecte."),
    "no_afectada": (
        "{n} {afectan} a versiones distintas de las instaladas en la organización."),
    # Sin confirmacion no se alerta (2026-09-10): la frase dice que NO SE SABE, que no
    # es lo mismo que «no nos afecta».
    "sin_evaluar_todavia": (
        "{n} {quedaron} a la espera de la evaluación contra el inventario: no se pudo "
        "comprobar si alguna máquina tiene la versión vulnerable, así que no se alertó. "
        "La evaluación se repite cada día y se alerta en cuanto se confirme."),
    # Riesgo aceptado con una excepcion vigente (2026-09-10): la afectacion SI esta
    # confirmada, asi que la frase no puede parecerse a «no nos afecta».
    "riesgo_aceptado": (
        "{n} {tenian} el riesgo aceptado con una excepción vigente: la organización "
        "asumió por escrito esa afectación, con responsable y con fecha de vencimiento, "
        "así que no se alertó. Al vencer o revocarse la excepción, se vuelve a alertar."),
    "estado_cerrado": (
        "{n} {fueron} descartadas o marcadas como falso positivo por el equipo."),
    # Sin nombrar la severidad que no se reporta (orden del usuario del 2026-09-10): el
    # correo dice cuántas quedaron fuera por su severidad, no cuál es.
    "severidad_baja": (
        "{n} {son} de una severidad que, por decisión del equipo, no se reporta."),
}

_PLURAL = {
    "llevaban": ("llevaba", "llevaban"),
    "tenian": ("tenía", "tenían"), "afectan": ("afecta", "afectan"),
    "traian": ("traía", "traían"), "son": ("es", "son"),
    "dejaron": ("dejó", "dejaron"), "fueron": ("fue", "fueron"),
    "quedaron": ("quedó", "quedaron"),
}


def _iso(dt: datetime) -> str:
    """Mismo formato que db.utcnow(): ISO-8601 en UTC con sufijo Z."""
    return (dt.astimezone(timezone.utc).replace(microsecond=0)
            .isoformat().replace("+00:00", "Z"))


def ventana(ahora: Optional[datetime] = None, dias: int = 7) -> tuple[datetime, datetime]:
    """(desde, hasta) del periodo cubierto: los ultimos ``dias`` dias."""
    hasta = ahora or datetime.now(timezone.utc)
    if hasta.tzinfo is None:
        hasta = hasta.replace(tzinfo=timezone.utc)
    return hasta - timedelta(days=int(dias or 7)), hasta


def frase_motivo(motivo: str, n: int, *, umbral: float = 50, horas: float = 24) -> str:
    """Frase en lenguaje llano para un motivo de exclusion con su cifra."""
    plantilla = FRASES_MOTIVO.get(motivo)
    if plantilla is None:
        return f"{notify.numero(n)} por «{motivo}»."
    formas = {clave: (par[0] if n == 1 else par[1]) for clave, par in _PLURAL.items()}
    return plantilla.format(n=notify.numero(n), umbral=_entero_o_decimal(umbral),
                            horas=_entero_o_decimal(horas), **formas)


def _entero_o_decimal(valor: Any) -> str:
    try:
        numero = float(valor)
    except (TypeError, ValueError):
        return str(valor)
    if numero == int(numero):
        return str(int(numero))
    return f"{numero:.1f}".replace(".", ",")


def _confianza(tec: dict) -> float:
    valor = tec.get("confidence")
    try:
        return 1.0 if valor is None else float(valor)
    except (TypeError, ValueError):
        return 1.0


def _tecnologia_principal(vista: dict, min_confianza: float,
                          ignorar_baja: bool = False) -> Optional[dict]:
    """Tecnologia de mayor confianza (>= minima) de la amenaza, o None si solo
    hay menciones. Con ``ignorar_baja`` las de criticidad baja no cuentan.
    Las tecnologias vienen ordenadas por confianza desc."""
    for tec in vista.get("technologies") or []:
        if ignorar_baja and str(tec.get("criticality") or "").lower() == "low":
            continue
        if _confianza(tec) >= min_confianza:
            return tec
    return None


def _es_seguimiento(vista: dict, *, min_confianza: float, ignorar_baja: bool = False) -> bool:
    if _tecnologia_principal(vista, min_confianza, ignorar_baja) is None:
        return False
    try:
        relevancia = float(vista.get("relevance") or 0.0)
    except (TypeError, ValueError):
        relevancia = 0.0
    return (relevancia >= RELEVANCIA_SEGUIMIENTO
            or vista.get("severity") in ("Critical", "High"))


def _agrupar_por_tecnologia(vistas: Iterable[dict], min_confianza: float,
                            ignorar_baja: bool = False) -> list[dict]:
    grupos: dict[str, dict[str, Any]] = {}
    for vista in vistas:
        tec = _tecnologia_principal(vista, min_confianza, ignorar_baja) or {"name": "Sin tecnología"}
        grupo = grupos.setdefault(tec["name"], {
            "tecnologia": tec, "amenazas": [], "maxima_relevancia": 0.0,
            "afectada": False})
        grupo["amenazas"].append(vista)
        grupo["maxima_relevancia"] = max(grupo["maxima_relevancia"],
                                         float(vista.get("relevance") or 0.0))
        if tec.get("version_verdict") == "affected":
            grupo["afectada"] = True
    return sorted(grupos.values(),
                  key=lambda g: (-len(g["amenazas"]), -g["maxima_relevancia"],
                                 g["tecnologia"]["name"]))


def _url_base(cfg: Any) -> str:
    from .config import url_publica
    url = url_publica(cfg)
    return str(url).rstrip("/")


def _con_enlace(vistas: Iterable[dict], base: str) -> list[dict]:
    salida = []
    for vista in vistas:
        vista = dict(vista)
        vista["url"] = f"{base}/amenazas/{vista['id']}"
        salida.append(vista)
    return salida


def _estado_activos(conn: sqlite3.Connection, cfg: Any) -> dict[str, Any]:
    """Estado de los activos para el resumen semanal, tolerante a que falte OCS.

    Si el inventario esta vacio o el modulo no ofrece la funcion (base antigua sin
    migrar), se devuelve un diccionario vacio y la plantilla omite el bloque en lugar
    de fallar: el resumen semanal no puede caerse por esto.
    """
    try:
        from . import ocs
        datos = ocs.estado_activos(conn, cfg=cfg)
    except Exception as exc:  # noqa: BLE001
        log.warning("no se pudo calcular el estado de los activos para el semanal",
                    extra={"error": str(exc)})
        return {}
    return datos if datos.get("activos_presentes") else {}


def recopilar(conn: sqlite3.Connection, *, cfg: Any,
              ahora: Optional[datetime] = None, dias: int = 7) -> dict[str, Any]:
    """Reune el contenido del resumen. No escribe nada.

    Devuelve un diccionario listo para `render`:
      seguimiento        grupos por tecnologia: {tecnologia, amenazas, ...}
      seguimiento_total  numero de amenazas en seguimiento
      informativo        resto con severidad >= Media (recortado al maximo)
      omitidas           las que no cupieron en digest_max_items
      descartadas        [{motivo, n, texto}] con las frases del filtro
      descartadas_total
      alertadas          las alertadas en la semana (recordatorio)
      ids_incluidas      ids que hay que marcar con digest_at si se envia
      vacio              True si no hay nada que contar en ninguna seccion
    """
    desde, hasta = ventana(ahora, dias)
    desde_iso = _iso(desde)
    min_confianza = float(cfg.get("alert_min_match_confidence", 0.6) or 0.0)
    umbral = float(cfg.get("alert_min_relevance", 50) or 0)
    horas = float(cfg.get("alert_defer_heuristic_hours", 24) or 0)
    maximo = max(1, int(cfg.get("digest_max_items", 60) or 60))
    base = _url_base(cfg)
    ignorar_sev_baja = bool(cfg.get("ignore_low_severity", True))
    ignorar_crit_baja = bool(cfg.get("ignore_low_criticality", True))

    candidatas = queries.no_alertadas_desde(conn, desde_iso, sin_digest=True,
                                            excluir_bajas=ignorar_sev_baja)

    seguimiento = [v for v in candidatas
                   if _es_seguimiento(v, min_confianza=min_confianza, ignorar_baja=ignorar_crit_baja)]
    ids_seguimiento = {v["id"] for v in seguimiento}
    resto = [v for v in candidatas if v["id"] not in ids_seguimiento
             and v.get("severity") in SEVERIDADES_INFORMATIVO]

    # Maximo en total: primero el seguimiento (ya viene por relevancia), luego
    # el informativo con lo que quede.
    total_disponible = len(seguimiento) + len(resto)
    seguimiento = seguimiento[:maximo]
    informativo = resto[:max(0, maximo - len(seguimiento))]
    omitidas = total_disponible - len(seguimiento) - len(informativo)

    conteo = queries.conteo_exclusiones(conn, desde_iso)
    descartadas = [
        {"motivo": motivo, "n": n,
         "texto": frase_motivo(motivo, n, umbral=umbral, horas=horas)}
        for motivo in queries.MOTIVOS_EXCLUSION
        if (n := conteo.get(motivo, 0))
    ]

    alertadas_todas = queries.alertadas_desde(conn, desde_iso)
    # El recordatorio es un recordatorio: con el criterio antiguo una semana
    # podia sumar cientos de alertas y el correo pasaba del medio megabyte.
    alertadas_total = len(alertadas_todas)
    alertadas = alertadas_todas[:MAX_ALERTADAS_RECORDATORIO]

    grupos = _agrupar_por_tecnologia(_con_enlace(seguimiento, base), min_confianza, ignorar_crit_baja)
    informativo = _con_enlace(informativo, base)
    alertadas = _con_enlace(alertadas, base)

    return {
        "desde": desde, "hasta": hasta, "dias": int(dias or 7),
        "seguimiento": grupos,
        "seguimiento_total": len(seguimiento),
        "informativo": informativo,
        "omitidas": omitidas,
        "descartadas": descartadas,
        "descartadas_total": sum(d["n"] for d in descartadas),
        "alertadas": alertadas,
        "alertadas_total": alertadas_total,
        "alertadas_omitidas": alertadas_total - len(alertadas),
        "ids_incluidas": [v["id"] for v in seguimiento] + [v["id"] for v in informativo],
        "umbral_relevancia": umbral,
        "min_confianza": min_confianza,
        "horas_espera": horas,
        "maximo": maximo,
        "url_interfaz": f"{base}/amenazas/",
        "url_activos": f"{base}/activos/",
        # Estado de los activos: venia en la alerta diaria y se movio aqui el
        # 2026-09-07. Sin los que no reportan, que tienen informe propio.
        "estado_activos": _estado_activos(conn, cfg),
        "vacio": not (seguimiento or informativo or descartadas or alertadas_todas),
    }


def render(datos: dict[str, Any]) -> str:
    """HTML del resumen con la plantilla `emails/semanal.html`."""
    return notify.entorno().get_template("semanal.html").render(**datos)


def asunto(desde: datetime) -> str:
    """'[SOC] Resumen semanal de amenazas · semana del 28 de agosto'."""
    dt = desde.astimezone() if desde.tzinfo else desde
    return (f"[SOC] Resumen semanal de amenazas · semana del {dt.day} de "
            f"{notify.MESES[dt.month - 1]}")


def marcar_incluidas(conn: sqlite3.Connection, ids: Iterable[int]) -> int:
    """Anota digest_at en las amenazas que han ido en el resumen."""
    return queries.marcar_en_digest(conn, ids)

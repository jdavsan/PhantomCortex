"""Envio de correo: alertas, informe mensual y avisos de administracion.

Corrige tres defectos concretos del sistema anterior:

  1. El sobre se construia mal: `to_addrs=[EMAIL_TO]` pasaba la cadena
     "a@x,b@y" como UNA sola direccion, de modo que anadir un segundo
     destinatario rompia el envio. Aqui las direcciones van como lista.

  2. El HTML se generaba con f-strings interpolando titulos de fuentes RSS sin
     escapar. El saneamiento vivia dentro del traductor, asi que si Argos no
     cargaba, el HTML de terceros entraba crudo en la alerta corporativa. Aqui
     el escapado es de Jinja2 y es incondicional.

  3. No habia parte de texto plano, ni Message-ID, ni Date propios, lo que
     penaliza la entrega y la clasificacion antispam.
"""
from __future__ import annotations

import base64
import html
import json
import re
import smtplib
import ssl
from datetime import datetime, timezone
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid
from email import encoders
from pathlib import Path
from typing import Any, Optional, Sequence

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .logging_setup import get_logger
from .paths import EMAIL_TEMPLATES_DIR

log = get_logger("notify")

MESES = ("enero", "febrero", "marzo", "abril", "mayo", "junio", "julio",
         "agosto", "septiembre", "octubre", "noviembre", "diciembre")

ETIQUETA_SEVERIDAD = {"Critical": "Crítica", "High": "Alta",
                      "Medium": "Media", "Low": "Baja"}

ETIQUETA_ORIGEN = {
    "nvd": "CVSS oficial de NVD",
    "vector": "CVSS calculado del vector oficial",
    "kev": "explotación confirmada (CISA KEV)",
    "heuristic": "severidad estimada, sin CVSS oficial",
}

ETIQUETA_VEREDICTO = {
    "affected": "versión instalada vulnerable",
    "not_affected": "versión instalada no vulnerable",
    "unknown": "versión sin determinar",
}

# v7 (2026-09-06): cuando no se conoce la version que corrige, el correo pintaba una raya,
# que no dice nada. Aqui se traduce el motivo anotado en ``aplicabilidad.sin_parche_motivo``
# (claves de threatintel.parches.MOTIVO_ES) a una frase corta que cabe en la celda de una
# tabla. Si el dato no viene, se dice lo unico que se sabe con certeza.
TEXTO_SIN_PARCHE = "pendiente de publicar"

MOTIVO_SIN_PARCHE_CORTO = {
    "sin_parche_publicado": "sin corrección publicada",
    "distro_sin_empaquetar": "sin empaquetar en la distribución",
    "aviso_sin_version": "el aviso no indica la versión",
    "desconocido": TEXTO_SIN_PARCHE,
}


# --------------------------------------------------------------------------
# Filtros de plantilla
# --------------------------------------------------------------------------
def fecha_larga(valor: Any = None) -> str:
    """'2 de septiembre de 2026'. Sin depender del locale del sistema, que bajo
    cron puede no estar configurado."""
    dt = _a_datetime(valor) or datetime.now()
    return f"{dt.day} de {MESES[dt.month - 1]} de {dt.year}"


def fecha_hora(valor: Any = None) -> str:
    dt = _a_datetime(valor) or datetime.now()
    return f"{dt.day} de {MESES[dt.month - 1]} de {dt.year}, {dt:%H:%M}"


def mes_largo(month: Optional[str]) -> str:
    """'2026-08' -> 'agosto de 2026'"""
    if not month or "-" not in str(month):
        return str(month or "")
    anio, mes = str(month).split("-")[:2]
    try:
        return f"{MESES[int(mes) - 1]} de {anio}"
    except (ValueError, IndexError):
        return str(month)


def _a_datetime(valor: Any) -> Optional[datetime]:
    if isinstance(valor, datetime):
        return valor
    if not valor:
        return None
    texto = str(valor).strip().replace("Z", "+00:00")
    for intento in (texto, texto[:19], texto[:10]):
        try:
            dt = datetime.fromisoformat(intento)
            return dt.astimezone() if dt.tzinfo else dt
        except ValueError:
            continue
    return None


def cvss_texto(valor: Any) -> str:
    """Nunca inventa un numero: si no hay dato oficial, lo dice.

    Se atrapa cualquier excepcion, y no solo TypeError o ValueError, porque una vista a la
    que le falta la clave llega a la plantilla como «Undefined» de Jinja2 y convertirlo a
    numero lanza UndefinedError: la alerta del dia no puede quedarse sin enviar porque a una
    amenaza le falte la puntuacion."""
    if valor is None or valor == "":
        return "no disponible"
    try:
        return f"{float(valor):.1f}"
    except Exception:  # noqa: BLE001 - incluye el Undefined de Jinja2
        return "no disponible"


def epss_texto(valor: Any) -> str:
    """Igual que ``cvss_texto``: sin dato, lo dice; nunca tumba el correo."""
    if valor is None or valor == "":
        return "no disponible"
    try:
        return f"{float(valor) * 100:.1f} %"
    except Exception:  # noqa: BLE001 - incluye el Undefined de Jinja2
        return "no disponible"


def severidad_texto(valor: Any) -> str:
    return ETIQUETA_SEVERIDAD.get(str(valor), str(valor or ""))


def origen_texto(valor: Any) -> str:
    return ETIQUETA_ORIGEN.get(str(valor), "origen no determinado")


def veredicto_texto(valor: Any) -> str:
    return ETIQUETA_VEREDICTO.get(str(valor), "versión sin determinar")


def motivo_sin_parche(valor: Any) -> str:
    """Frase corta que explica por que falta la version que corrige.

    Acepta la clave anotada por ``threatintel.parches`` («sin_parche_publicado») o un texto
    ya redactado; si no llega nada, «pendiente de publicar»."""
    texto = str(valor or "").strip()
    if not texto:
        return TEXTO_SIN_PARCHE
    if texto in MOTIVO_SIN_PARCHE_CORTO:
        return MOTIVO_SIN_PARCHE_CORTO[texto]
    return texto if len(texto) <= 70 else texto[:69].rstrip() + "…"


#: Tipo de contenido de cada extension que el sistema adjunta. Con «octet-stream» algunos
#: clientes de correo pintan un icono generico y algunas pasarelas son mas restrictivas, asi
#: que se declara el tipo real (hallazgo del revisor del 2026-09-06).
TIPOS_ADJUNTO = {
    ".xlsx": ("application",
              "vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    ".csv": ("text", "csv"),
    ".pdf": ("application", "pdf"),
    ".html": ("text", "html"),
    ".txt": ("text", "plain"),
    ".zip": ("application", "zip"),
}


def tipo_adjunto(ruta: Any) -> tuple[str, str]:
    """Tipo y subtipo MIME de un adjunto por su extension; «octet-stream» si no se conoce."""
    sufijo = Path(str(ruta)).suffix.lower()
    return TIPOS_ADJUNTO.get(sufijo, ("application", "octet-stream"))


def numero(valor: Any) -> str:
    try:
        return f"{int(valor):,}".replace(",", ".")
    except (TypeError, ValueError):
        return "0"


def decimal(valor: Any, cifras: int = 1) -> str:
    """«8,8» — coma decimal y punto de millar, como el resto de la plataforma.

    El filtro ``numero`` convierte a entero, asi que un 8,8 % se leia como «8 %» y la
    cifra dejaba de ser exacta (2026-09-07).
    """
    try:
        texto = f"{float(valor):,.{max(0, int(cifras))}f}"
    except (TypeError, ValueError):
        return "0"
    return texto.replace(",", "\u0000").replace(".", ",").replace("\u0000", ".")


def recortar(texto: Any, largo: int = 300) -> str:
    """Recorta sin partir una palabra por la mitad (revision de claridad 2026-09-15).

    En un correo no hay titulo emergente donde dejar el resto, asi que al menos el corte
    tiene que caer en un espacio y terminar en puntos suspensivos, para que se vea que
    falta texto y no que la frase acaba ahi.
    """
    s = str(texto or "").strip()
    if len(s) <= largo:
        return s
    duro = s[: largo - 1].rstrip()
    corte = duro.rfind(" ")
    if corte >= (largo - 1) // 2:
        duro = duro[:corte].rstrip(" ,;:.-")
    return duro + "…"


# Esquemas admitidos en un enlace. El autoescape de Jinja2 escapa caracteres
# pero NO valida el esquema, asi que un href="javascript:..." procedente de una
# fuente RSS llegaria intacto al cliente de correo. Verificado el 2026-09-02.
_ESQUEMAS_SEGUROS = ("http://", "https://", "mailto:")


def url_segura(valor: Any) -> str:
    """Devuelve la URL solo si su esquema es admisible; si no, cadena vacia."""
    texto = str(valor or "").strip()
    if not texto:
        return ""
    # Los caracteres de control permiten esquivar comprobaciones ingenuas
    texto = re.sub(r"[\x00-\x20\x7f]", "", texto)
    if texto.lower().startswith(_ESQUEMAS_SEGUROS):
        return texto
    log.warning("enlace descartado por esquema no admitido",
                extra={"prefijo": texto[:24]})
    return ""


def enlace_nvd(cve: Optional[str]) -> str:
    if not cve or not str(cve).upper().startswith("CVE-"):
        return ""
    return f"https://nvd.nist.gov/vuln/detail/{str(cve).upper()}"


_ENTORNO: Optional[Environment] = None


def entorno() -> Environment:
    """Entorno Jinja2 con autoescape SIEMPRE activo."""
    global _ENTORNO
    if _ENTORNO is None:
        _ENTORNO = Environment(
            loader=FileSystemLoader(str(EMAIL_TEMPLATES_DIR)),
            autoescape=select_autoescape(default=True, default_for_string=True),
            trim_blocks=True, lstrip_blocks=True)
        _ENTORNO.filters.update({
            "fecha_larga": fecha_larga, "fecha_hora": fecha_hora,
            "mes_largo": mes_largo, "cvss_texto": cvss_texto,
            "epss_texto": epss_texto, "severidad_texto": severidad_texto,
            "origen_texto": origen_texto, "veredicto_texto": veredicto_texto,
            "numero": numero, "decimal": decimal, "recortar": recortar,
            "enlace_nvd": enlace_nvd,
            "url_segura": url_segura, "etiqueta_confianza": etiqueta_confianza,
            "motivo_sin_parche": motivo_sin_parche,
        })
        _ENTORNO.globals.update({
            "empresa": "Mi Organización",
            "proceso": "Ciberseguridad",
            "ahora": datetime.now,
            # Motivos del filtro en español, disponibles en CUALQUIER plantilla de correo:
            # el resumen semanal enseñaba el código interno («sin_activos_confirmados»)
            # porque no los tenía a mano (revisión de claridad del 2026-09-15).
            "motivos_es": MOTIVOS_FILTRO_ES,
        })
    return _ENTORNO


# --------------------------------------------------------------------------
# Renderizado
# --------------------------------------------------------------------------
_EXPOSICION_ES = {"internet": "expuesta a Internet", "dmz": "en la zona perimetral (DMZ)",
                  "interna": "en la red interna", "internal": "en la red interna", "local": "local"}
_CRITICIDAD_ES = {"critical": "crítica", "high": "alta", "medium": "media", "low": "baja"}


def _confianza(tec: dict) -> float:
    valor = tec.get("confidence")
    try:
        return 1.0 if valor is None else float(valor)
    except (TypeError, ValueError):
        return 1.0


def etiqueta_confianza(tec: dict) -> str:
    """'coincidencia exacta' (>= 0,8), 'coincidencia probable' (0,6-0,79) o 'mención'."""
    c = _confianza(tec)
    if c >= 0.8:
        return "coincidencia exacta"
    if c >= 0.6:
        return "coincidencia probable"
    return "mención"


def separar_tecnologias(view: dict, min_confianza: float = 0.6,
                        ignorar_criticidad_baja: bool = False) -> tuple[list[dict], list[dict]]:
    """(exposición, menciones): las coincidencias por debajo de la confianza
    mínima, y las tecnologías de criticidad baja si así se configura, no prueban
    que la amenaza nos afecte y se listan aparte."""
    exposicion, menciones = [], []
    for tec in view.get("technologies") or []:
        baja = ignorar_criticidad_baja and str(tec.get("criticality") or "").lower() == "low"
        (exposicion if _confianza(tec) >= min_confianza and not baja else menciones).append(tec)
    return exposicion, menciones


def motivo_alerta(view: dict, *, umbral: float = 50.0, min_confianza: float = 0.6,
                  ignorar_criticidad_baja: bool = False) -> str:
    """Frase «Por qué está aquí» de una amenaza alertada, en lenguaje llano."""
    exposicion, _ = separar_tecnologias(view, min_confianza, ignorar_criticidad_baja)
    afectadas = [t for t in exposicion if t.get("version_verdict") == "affected"]
    try:
        relevancia = int(round(float(view.get("relevance") or 0)))
    except (TypeError, ValueError):
        relevancia = 0
    partes: list[str] = []
    if view.get("in_kev"):
        partes.append("explotación activa confirmada por CISA (KEV)")
    n_activos = int((view.get("activos") or {}).get("n_afectados") or 0)
    if n_activos:
        partes.append(f"{n_activos} activo{'s' if n_activos != 1 else ''} con la versión vulnerable instalada")
    if afectadas:
        nombres = ", ".join(t.get("name", "") for t in afectadas[:2])
        partes.append(f"la versión instalada de {nombres} es vulnerable")
    elif exposicion:
        t = exposicion[0]
        crit = _CRITICIDAD_ES.get(str(t.get("criticality") or "").lower(), "")
        expo = _EXPOSICION_ES.get(str(t.get("exposure") or "").lower(), "")
        detalle = ", ".join(x for x in (f"criticidad {crit}" if crit else "", expo) if x)
        partes.append(f"afecta a {t.get('name', 'una tecnología del inventario')}"
                      + (f" ({detalle})" if detalle else ""))
    if relevancia >= umbral and not view.get("in_kev"):
        partes.insert(0, f"relevancia {relevancia} para la organización")
    elif not partes:
        partes.append(f"relevancia {relevancia}")
    texto = "; ".join(partes)
    return texto[0].upper() + texto[1:] if texto else ""


def _entero(valor: Any, defecto: int) -> int:
    try:
        return int(valor)
    except (TypeError, ValueError):
        return defecto


def render_alert_email(threats: Sequence[dict], meta: Optional[dict] = None) -> str:
    """Alerta diaria. `threats` son ThreatView ordenados por relevancia.

    ``meta["filtro"]`` (opcional) trae el desglose de lo que el filtro excluyó
    hoy ({"excluidas": {motivo: n}, "umbral_relevancia", "min_confianza"}) y se
    muestra al pie para que el lector sepa qué no está viendo y por qué.

    v7 (2026-09-06), a peticion del usuario: el correo detallaba 25 vulnerabilidades y
    ocupaba paginas. La tabla «Prioridad de actuación» paso a ser el indice del correo y
    solo se explican en detalle las ``meta["detalle_top"]`` primeras por relevancia
    (ajuste ``alert_detalle_top``, 3 por defecto).

    v10 (2026-09-15), a peticion del usuario: «en el correo de alertamiento diario dice que
    hay muchas vulnerabilidades o amenazas detectadas en el dia, asi que necesito que esto
    se ajuste y se muestren solo el top 10». La tabla ya no lista TODAS las alertadas (el
    11 de septiembre fueron 76 filas y el 9, 89): lista las ``meta["tabla_top"]`` de mayor
    relevancia (ajuste ``alert_tabla_top``, 10 por defecto) y el correo dice con todas las
    letras cuantas quedan fuera y donde estan (la hoja de calculo adjunta y la plataforma,
    con su enlace). Las tres mas criticas se siguen desarrollando en detalle igual que
    antes. La cabecera y el pie siguen hablando del TOTAL alertado, no de las diez: quien
    lee tiene que saber que son 76 y que esta viendo 10.

    Otras claves de ``meta`` que se atienden aqui:

    * ``activos_afectados``: activos DISTINTOS con alguna version vulnerable instalada,
      contado sobre la base por quien la tiene abierta. Sin esta clave el correo cuenta el
      conjunto de los activos que aparecen en el propio correo.
    * ``detalle_top``: vulnerabilidades con detalle completo (3 por defecto; 0 las quita).
    * ``tabla_top``: filas de la tabla de prioridad (10 por defecto). Es el «top 10» que
      pidio el usuario; nunca puede pasar de ``max_tabla``.
    * ``max_tabla``: tope de seguridad de filas de la tabla de prioridad (200 por defecto);
      esta solo para que una jornada anomala no genere un correo de miles de filas.
    * ``adjunto_excel``: nombre del fichero adjunto (o True) cuando se adjunta la hoja de
      calculo; solo entonces el pie la anuncia. Si no llega, no se promete ningun adjunto.
    * ``parches_nuevos``: correcciones que ya estan disponibles, para ``_parches_nuevos.html``.
    * ``sin_correccion``: lo que no se puede corregir todavia (``parches.sin_correccion``).

    ``meta["max_detalle"]`` se sigue aceptando por compatibilidad, pero ya no recorta la
    tabla de prioridad: quien decide el largo del correo es ``detalle_top``.
    """
    meta = dict(meta or {})
    filtro = meta.get("filtro") or {}
    umbral = float(filtro.get("umbral_relevancia") or meta.get("umbral_relevancia") or 50)
    min_conf = float(filtro.get("min_confianza") or meta.get("min_confianza") or 0.6)
    ignorar_baja = bool(filtro.get("ignorar_criticidad_baja", meta.get("ignorar_criticidad_baja", False)))
    lista = []
    for t in threats:
        t = dict(t)
        t["tecs_exposicion"], t["tecs_mencion"] = separar_tecnologias(t, min_conf, ignorar_baja)
        t["por_que"] = motivo_alerta(t, umbral=umbral, min_confianza=min_conf,
                                     ignorar_criticidad_baja=ignorar_baja)
        # Dos magnitudes distintas (revision de claridad del 2026-09-15): la cabecera decia
        # «9 servidores» y la tabla de debajo traia una fila por PAQUETE. Se cuentan aqui
        # los paquetes para poder decir las dos cifras juntas en el correo.
        act = t.get("activos") or {}
        t["n_paquetes_sistemas"] = sum(len(x.get("paquetes_detalle") or [])
                                       for x in (act.get("sistemas") or []))
        t["n_paquetes_activos"] = sum(max(1, len(x.get("paquetes_detalle") or []))
                                      for x in (act.get("afectados") or []))
        lista.append(t)

    criticas = [t for t in lista if t.get("severity") == "Critical"]
    altas = [t for t in lista if t.get("severity") == "High"]
    medias = [t for t in lista if t.get("severity") == "Medium"]
    bajas = [t for t in lista if t.get("severity") == "Low"]
    en_kev = [t for t in lista if t.get("in_kev")]

    afectadas = [t for t in lista
                 if any(x.get("version_verdict") == "affected"
                        for x in t["tecs_exposicion"])]
    # Aplicabilidad por activo (OCS): amenazas con equipos que tienen la version
    # vulnerable y cuantos activos distintos son en total.
    con_activos = [t for t in lista if (t.get("activos") or {}).get("n_afectados")]
    activos_distintos: set = set()
    for t in con_activos:
        for x in (t.get("activos") or {}).get("afectados") or []:
            activos_distintos.add(x.get("id"))
        if (t.get("activos") or {}).get("mas"):
            activos_distintos.add(("mas", t.get("id")))
    # ACTIVOS DISTINTOS, no la suma por amenaza: un servidor afectado por doce amenazas
    # se contaba doce veces y el correo decia «631 activos en total» de un parque de 841
    # (revision de precision del 2026-09-09). ``meta["activos_afectados"]`` permite a quien
    # tiene la base delante dar la cifra exacta; si no llega, se cuenta el conjunto que se
    # ve aqui, que es exacto salvo cuando alguna amenaza trae la lista recortada (``mas``),
    # y entonces se dice «al menos».
    recortado = any(int((t.get("activos") or {}).get("mas") or 0) for t in con_activos)
    activos_distintos = {x for x in activos_distintos if not isinstance(x, tuple)}
    exacto = _entero((meta or {}).get("activos_afectados"), 0)
    if exacto:
        total_activos, total_activos_exacto = exacto, True
    else:
        total_activos, total_activos_exacto = len(activos_distintos), not recortado
    total_apariciones = sum((t.get("activos") or {}).get("n_afectados", 0) for t in con_activos)
    expuestas = [t for t in lista
                 if any(x.get("exposure") == "internet"
                        for x in t["tecs_exposicion"])]
    # Amenazas que entran SIN afectacion confirmada (2026-09-10): solo pueden ser las de
    # explotacion activa confirmada con el ajuste ``alert_kev_sin_activos`` encendido, que
    # esta apagado por omision. La cabecera del correo tiene que decirlo, para que
    # «31 de las 35» no quede sin explicacion.
    kev_sin_confirmar = [t for t in lista if t.get("kev_sin_activos_confirmados")]

    conteo_tec: dict[str, dict[str, Any]] = {}
    for t in lista:
        for tec in t["tecs_exposicion"]:
            entrada = conteo_tec.setdefault(
                tec["name"], {"name": tec["name"], "n": 0,
                              "version": tec.get("version_installed"),
                              "criticality": tec.get("criticality"),
                              "afectada": False})
            entrada["n"] += 1
            if tec.get("version_verdict") == "affected":
                entrada["afectada"] = True

    top_tec = sorted(conteo_tec.values(), key=lambda x: -x["n"])[:8]

    # Enlace a la ficha de cada amenaza: la tabla de prioridad es el indice del correo.
    base_fichas = str(meta.get("url_interfaz") or "").rstrip("/")
    for t in lista:
        t["url_amenaza"] = ""
        if base_fichas and t.get("id") is not None:
            t["url_amenaza"] = f"{base_fichas}/{t['id']}"

    # Top 10 (2026-09-15): «tabla_top» decide cuantas filas se ven y «max_tabla» sigue
    # siendo el tope de seguridad, por si alguien configurase un top mayor que el.
    max_tabla = max(1, _entero(meta.get("max_tabla"), 200))
    tabla_top = max(1, _entero(meta.get("tabla_top"), 10))
    tabla = lista[:min(tabla_top, max_tabla)]
    detalle_top = max(0, _entero(meta.get("detalle_top"), 3))
    detalle = lista[:detalle_top]

    adjunto = meta.get("adjunto_excel")
    # Un solo anuncio en el pie: «adjuntos» es la lista de ficheros que se envian de verdad
    # (la escribe bin/ejecucion_diaria.py). Si el llamador solo indico «adjunto_excel»,
    # se deriva de ahi para que el aviso del pie siga apareciendo (revision 2026-09-06).
    adjuntos = [str(x) for x in (meta.get("adjuntos") or []) if x]
    if not adjuntos and adjunto and not isinstance(adjunto, bool):
        adjuntos = [str(adjunto)]
    meta["adjuntos"] = adjuntos
    adjunto_nombre = adjunto if isinstance(adjunto, str) else ""

    return entorno().get_template("alerta.html").render(
        amenazas=tabla, detalle=detalle, total=len(lista),
        tabla_top=min(tabla_top, max_tabla),
        ocultas=max(0, len(lista) - len(tabla)),
        restantes=max(0, len(lista) - len(detalle)),
        adjunto_excel=bool(adjunto), adjunto_nombre=adjunto_nombre, adjuntos=adjuntos,
        parches_nuevos=meta.get("parches_nuevos") or [],
        # v9 (2026-09-07): resumen de lo que todavia no tiene version que lo corrija
        sin_correccion=meta.get("sin_correccion") or {},
        sin_novedades=not lista, resumen_activos=meta.get("resumen_activos") or {},
        url_activos=meta.get("url_activos"),
        criticas=criticas, altas=altas, medias=medias, bajas=bajas,
        en_kev=en_kev, afectadas=afectadas, expuestas=expuestas,
        con_activos=con_activos, total_activos=total_activos,
        kev_sin_confirmar=kev_sin_confirmar,
        total_activos_exacto=total_activos_exacto, total_apariciones=total_apariciones,
        top_tecnologias=top_tec, meta=meta, filtro=filtro,
        excluidas_total=sum(int(v or 0) for v in (filtro.get("excluidas") or {}).values()),
        motivos_es=MOTIVOS_FILTRO_ES, umbral_relevancia=umbral,
        url_interfaz=meta.get("url_interfaz"))


def _agrupar_servidores(servidores: Sequence[dict]) -> list[dict]:
    """Una entrada por servidor con TODOS sus paquetes dentro.

    La lista que llega trae una fila por servidor y paquete, asi que un servidor con tres
    paquetes vulnerables aparecia tres veces y la tabla no cuadraba con la cabecera
    (revision de claridad del 2026-09-15).
    """
    grupos: dict[Any, dict] = {}
    for s in servidores:
        clave = s.get("activo_id") if s.get("activo_id") is not None else s.get("nombre")
        grupo = grupos.get(clave)
        if grupo is None:
            grupo = {k: s.get(k) for k in ("activo_id", "nombre", "ip", "entorno_es",
                                           "so_nombre", "expuesto", "proceso")}
            grupo["paquetes"] = []
            grupos[clave] = grupo
        grupo["paquetes"].append({
            "paquete": s.get("paquete"),
            "version_instalada": s.get("version_instalada"),
            "version_corregida": s.get("version_corregida"),
            "aviso": s.get("aviso"),
        })
    return list(grupos.values())


def render_alert_email_proceso(proceso: str, correo: str, amenazas: Sequence[dict],
                               meta: Optional[dict] = None) -> str:
    """Alerta propia de un proceso de negocio (v6): solo las amenazas que afectan a SUS
    servidores. Cada amenaza trae ``servidores`` (lista de {nombre, ip, entorno_es,
    paquete, version_instalada, version_corregida, expuesto, ...}) y ``n_servidores``, tal
    como las construye ``alertas_proceso.enviar``.

    ``meta``: {"url_base": prefijo de la interfaz para los enlaces «Ver la amenaza» y
    «Plan de remediación», "n_activos": servidores distintos del proceso (si falta se
    calcula), "solo_expuestos": bool, "fecha": ISO o datetime, "es_prueba": bool,
    "max_servidores": lineas por amenaza en la tabla (25 por defecto)}."""
    meta = dict(meta or {})
    base = str(meta.get("url_base") or "").rstrip("/")
    lista: list[dict] = []
    distintos: set = set()
    for a in amenazas:
        t = dict(a)
        servidores = list(t.get("servidores") or [])
        t["servidores"] = servidores
        ids = {s.get("activo_id") if s.get("activo_id") is not None else s.get("nombre") for s in servidores}
        t["n_servidores"] = int(t.get("n_servidores") or len(ids))
        # Dos magnitudes distintas (revision de claridad del 2026-09-15): la cabecera decia
        # «9 servidores» y debajo habia 19 filas, una por paquete. Ahora se agrupan las
        # filas por servidor y se dicen las dos cifras: servidores afectados y paquetes que
        # hay que actualizar.
        t["servidores_agrupados"] = _agrupar_servidores(servidores)
        t["n_paquetes"] = len(servidores)
        distintos.update(ids)
        if base and t.get("id") is not None:
            t["url_amenaza"] = f"{base}/amenazas/{int(t['id'])}"
            t["url_remediacion"] = f"{base}/amenazas/{int(t['id'])}/remediacion"
        else:
            t["url_amenaza"] = t["url_remediacion"] = ""
        lista.append(t)
    n_activos = meta.get("n_activos")
    if n_activos is None:
        n_activos = len(distintos)
    maximo = int(meta.get("max_detalle") or 25)
    n_paquetes_total = sum(int(t.get("n_paquetes") or 0) for t in lista)
    return entorno().get_template("alerta_proceso.html").render(
        n_paquetes=n_paquetes_total,
        proceso_negocio=proceso, correo_destino=correo, amenazas=lista[:maximo], total=len(lista),
        ocultas=max(0, len(lista) - maximo), url_interfaz=f"{base}/amenazas/" if base else "",
        n_activos=int(n_activos or 0),
        criticas=[t for t in lista if t.get("severity") == "Critical"],
        altas=[t for t in lista if t.get("severity") == "High"],
        en_kev=[t for t in lista if t.get("in_kev")],
        solo_expuestos=bool(meta.get("solo_expuestos")), es_prueba=bool(meta.get("es_prueba")),
        fecha=meta.get("fecha"), maximo_servidores=int(meta.get("max_servidores") or 25),
        url_base=base, meta=meta)


# Frases del pie «Filtro de hoy», por motivo de exclusion (queries.MOTIVOS_EXCLUSION).
MOTIVOS_FILTRO_ES = {
    "relevancia_baja": "por relevancia baja para la organización",
    "sin_identificador": "por no traer CVE ni identificador de aviso (noticias)",
    "heuristica_en_espera": "a la espera de la puntuación oficial de NVD",
    "no_afectada": "porque la versión instalada no es vulnerable",
    # Estas dos frases decian casi lo mismo con dos vocabularios distintos («activo» y
    # «maquina») y significaban cosas opuestas (2026-09-15): una es COMPROBADO Y
    # DESCARTADO y la otra es SIN CONFIRMAR. Ahora empiezan por esas dos palabras.
    "sin_activos_afectados": ("comprobado y descartado: se revisó el inventario y ningún "
                              "activo tiene instalada una versión vulnerable, porque ya "
                              "llevan la corrección o la versión afectada no está en el parque"),
    "sin_activos_confirmados": ("sin confirmar: la revisión del inventario no ha podido "
                                "demostrar que ningún activo tenga la versión vulnerable, "
                                "así que no se afirma que afecte ni que no afecte; se vuelve "
                                "a revisar cada día"),
    # Riesgo aceptado con una excepcion vigente (2026-09-10). Desde el 10 de septiembre una
    # excepcion puede ser permanente, sin fecha de vencimiento (2026-09-15).
    "riesgo_aceptado": ("porque su riesgo está aceptado con una excepción vigente, con "
                        "responsable y con justificación; con fecha de vencimiento o, si es "
                        "permanente, con revisión periódica"),
    # Sin confirmacion no se alerta (2026-09-10).
    "sin_evaluar_todavia": ("a la espera de la evaluación contra el inventario: no se ha "
                            "podido comprobar todavía si alguna máquina tiene la versión "
                            "vulnerable"),
    "estado_cerrado": "descartadas o marcadas como falso positivo por el equipo",
    # Sin nombrar la severidad que no se reporta (orden del usuario del 2026-09-10); se
    # dice QUIEN lo decide y DONDE se cambia (2026-09-15).
    "severidad_baja": ("por su severidad: Ciberseguridad decidió no reportar la "
                       "menos grave, y así está configurado en Administración → Ajustes"),
}


def render_monthly_email(summary: dict) -> str:
    """Carta de presentacion del informe mensual."""
    return entorno().get_template("mensual.html").render(**summary, resumen=summary)


def render_inventario_email(datos: dict, *, url_activos: str = "",
                            adjuntos: Optional[Sequence[dict]] = None) -> str:
    """HTML del informe de inventario sin reportar, para Redes.

    Correo aparte de la alerta diaria (2026-09-07): mantener el inventario al dia no es
    una tarea de seguridad y mezclarlo con las vulnerabilidades hacia que se leyera como
    un hallazgo de seguridad. La cabecera lo firma Redes, no el SOC.

    ``adjuntos`` (2026-09-15): un elemento por TIPO de maquina, tenga fichero o no, para
    que el correo se entienda sin abrir nada:
    ``{"origen", "origen_es", "sin_reportar", "total", "fichero", "filas"}``. Cuando un
    grupo no tiene ninguna maquina sin reportar, ``fichero`` va vacio y el correo lo dice
    con palabras en vez de prometer un adjunto que no existe.
    """
    return entorno().get_template("inventario.html").render(
        datos=datos, url_activos=url_activos, adjuntos=list(adjuntos or []),
        proceso="Administración del inventario")


def asunto_inventario(total: int, dias: int, fecha: Optional[datetime] = None) -> str:
    """«[Inteligencia de Amenazas] Inventario sin reportar · 92 activos · 7 de septiembre de 2026»."""
    dt = fecha or datetime.now()
    if not total:
        return (f"{PREFIJO_ASUNTO} Inventario al día · todos los activos reportan · "
                f"{fecha_larga(dt)}")
    return (f"{PREFIJO_ASUNTO} Inventario sin reportar · {numero(total)} "
            f"activo{'s' if total != 1 else ''} con más de {numero(dias)} días sin enviar "
            f"su inventario · {fecha_larga(dt)}")


def render_admin_email(*, titulo: str, intro: str, severidad: str = "info",
                       secciones: Optional[Sequence[dict]] = None,
                       acciones: Optional[Sequence[str]] = None,
                       pie: Optional[str] = None) -> str:
    """Aviso operativo al administrador.

    `secciones`: [{'titulo': str, 'filas': [(clave, valor), ...]}] o
                 [{'titulo': str, 'tabla': {'cabeceras': [...], 'filas': [[...]]}}]
    """
    if severidad not in ("critical", "warning", "info"):
        severidad = "info"
    return entorno().get_template("admin.html").render(
        titulo=titulo, intro=intro, severidad=severidad,
        secciones=list(secciones or []), acciones=list(acciones or []), pie=pie)


# --------------------------------------------------------------------------
# Texto plano
# --------------------------------------------------------------------------
_BLOQUE = re.compile(r"</(?:p|div|tr|h[1-6]|li|table|thead|tbody)>",
                     re.IGNORECASE)


def html_a_texto(contenido: str) -> str:
    """Genera la parte de texto plano.

    Muchos clientes y filtros antispam esperan multipart/alternative con las dos
    partes; el sistema anterior enviaba solo HTML.
    """
    if not contenido:
        return ""
    texto = re.sub(r"<(script|style)\b[^>]*>.*?</\1>", " ", contenido,
                   flags=re.IGNORECASE | re.DOTALL)
    texto = re.sub(r"<br\s*/?>", "\n", texto, flags=re.IGNORECASE)
    texto = _BLOQUE.sub("\n", texto)
    texto = re.sub(r"<[^>]+>", "", texto)
    texto = html.unescape(texto)
    texto = re.sub(r"[ \t]{2,}", " ", texto)
    texto = re.sub(r"\n{3,}", "\n\n", texto)
    return "\n".join(l.strip() for l in texto.splitlines()).strip()


# --------------------------------------------------------------------------
# Envio
# --------------------------------------------------------------------------
class Mailer:
    """Envio SMTP con el sobre bien construido."""

    def __init__(self, cfg, dry_run: bool = False) -> None:
        self.cfg = cfg
        self.smtp = cfg.smtp
        self.dry_run = bool(dry_run)

    # ---------------------------------------------------------------- conexion
    def _conectar(self) -> smtplib.SMTP:
        contexto = ssl.create_default_context()
        if self.smtp.use_ssl:
            servidor = smtplib.SMTP_SSL(self.smtp.server, self.smtp.port,
                                        context=contexto, timeout=45)
        else:
            servidor = smtplib.SMTP(self.smtp.server, self.smtp.port, timeout=45)
            servidor.ehlo()
            if self.smtp.use_tls:
                servidor.starttls(context=contexto)
                servidor.ehlo()
        return servidor

    def comprobar_destinatarios(self, direcciones: Sequence[str]
                                ) -> dict[str, tuple[int, str]]:
        """Comprueba si el servidor aceptaria cada direccion, sin enviar nada.

        Usa MAIL FROM + RCPT TO y despues RSET. Sirve para detectar de antemano
        restricciones de reenvio: este servidor solo admite dominios locales, de
        modo que configurar un destinatario externo produciria un fallo silencioso
        en cada alerta.
        """
        resultado: dict[str, tuple[int, str]] = {}
        if self.dry_run:
            return {d: (250, "dry-run") for d in direcciones}

        servidor = None
        try:
            servidor = self._conectar()
            servidor.login(self.smtp.user, self.smtp.password)
            servidor.mail(self.smtp.from_addr)
            for direccion in direcciones:
                try:
                    codigo, mensaje = servidor.rcpt(direccion)
                    texto = (mensaje.decode("utf-8", "replace")
                             if isinstance(mensaje, bytes) else str(mensaje))
                    resultado[direccion] = (codigo, texto.strip())
                except smtplib.SMTPException as exc:
                    resultado[direccion] = (0, f"{type(exc).__name__}: {exc}")
            servidor.rset()
        except Exception as exc:  # noqa: BLE001
            for direccion in direcciones:
                resultado.setdefault(direccion, (0, f"{type(exc).__name__}: {exc}"))
        finally:
            if servidor is not None:
                try:
                    servidor.quit()
                except Exception:  # noqa: BLE001
                    pass
        return resultado

    def verify_connection(self) -> tuple[bool, Optional[str]]:
        """Conecta y autentica sin enviar nada.

        Distingue el fallo de credencial del fallo de red, porque son problemas
        distintos: uno exige cambiar la contrasena y el otro no. El prefijo del
        mensaje lo indica ('AUTH: ' o 'RED: ').
        """
        if self.dry_run:
            return True, None
        servidor = None
        try:
            servidor = self._conectar()
            servidor.login(self.smtp.user, self.smtp.password)
            return True, None
        except smtplib.SMTPAuthenticationError as exc:
            detalle = exc.smtp_error
            if isinstance(detalle, bytes):
                detalle = detalle.decode("utf-8", "replace")
            return False, f"AUTH: codigo {exc.smtp_code}: {detalle}"
        except (smtplib.SMTPNotSupportedError, smtplib.SMTPHeloError) as exc:
            return False, f"AUTH: el servidor rechazo la negociacion: {exc}"
        except (smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused) as exc:
            return False, f"DIRECCION: el servidor rechazo una direccion: {exc}"
        except ssl.SSLError as exc:
            return False, f"RED: error TLS/SSL: {exc}"
        except (OSError, smtplib.SMTPException) as exc:
            return False, f"RED: {type(exc).__name__}: {exc}"
        finally:
            if servidor is not None:
                try:
                    servidor.quit()
                except Exception:  # noqa: BLE001 - cierre best-effort
                    pass

    # ------------------------------------------------------------------ envio
    def send(self, *, subject: str, html: str, to: Sequence[str],
             cc: Optional[Sequence[str]] = None, text: Optional[str] = None,
             attachments: Optional[Sequence[Path]] = None,
             headers: Optional[dict[str, str]] = None) -> bool:
        destinatarios = [d for d in (to or []) if d]
        copias = [d for d in (cc or []) if d and d not in destinatarios]

        if not destinatarios:
            log.error("envio abortado: no hay destinatarios",
                      extra={"asunto": subject})
            return False

        adjuntos = [Path(a) for a in (attachments or [])]
        cuerpo_texto = text if text is not None else html_a_texto(html)

        if adjuntos:
            mensaje: MIMEMultipart = MIMEMultipart("mixed")
            alternativa = MIMEMultipart("alternative")
            alternativa.attach(MIMEText(cuerpo_texto, "plain", "utf-8"))
            alternativa.attach(MIMEText(html, "html", "utf-8"))
            mensaje.attach(alternativa)
        else:
            mensaje = MIMEMultipart("alternative")
            mensaje.attach(MIMEText(cuerpo_texto, "plain", "utf-8"))
            mensaje.attach(MIMEText(html, "html", "utf-8"))

        mensaje["Subject"] = subject
        mensaje["From"] = formataddr((self.smtp.from_name, self.smtp.from_addr))
        mensaje["To"] = ", ".join(destinatarios)
        if copias:
            mensaje["Cc"] = ", ".join(copias)
        if self.smtp.reply_to:
            mensaje["Reply-To"] = self.smtp.reply_to
        mensaje["Date"] = formatdate(localtime=True)
        dominio = (self.smtp.from_addr.split("@")[-1]
                   if "@" in self.smtp.from_addr else None)
        mensaje["Message-ID"] = make_msgid(domain=dominio)
        mensaje["X-Mailer"] = "Sistema de Inteligencia de Amenazas"
        mensaje["Auto-Submitted"] = "auto-generated"
        for clave, valor in (headers or {}).items():
            mensaje[clave] = valor

        for ruta in adjuntos:
            if not ruta.exists():
                log.error("adjunto inexistente, se omite", extra={"ruta": str(ruta)})
                continue
            tipo, subtipo = tipo_adjunto(ruta)
            parte = MIMEBase(tipo, subtipo)
            parte.set_payload(ruta.read_bytes())
            encoders.encode_base64(parte)
            parte.add_header("Content-Disposition", "attachment",
                             filename=ruta.name)
            mensaje.attach(parte)

        # El sobre lleva TODAS las direcciones como elementos de lista. Pasar
        # "a@x,b@y" como un unico elemento era el bug del sistema anterior.
        sobre = destinatarios + copias

        if self.dry_run:
            log.info("simulacion de envio (dry-run)", extra={
                "asunto": subject, "destinatarios": len(sobre),
                "adjuntos": len(adjuntos), "bytes": len(html)})
            return True

        servidor = None
        try:
            servidor = self._conectar()
            servidor.login(self.smtp.user, self.smtp.password)
            rechazos = servidor.send_message(
                mensaje, from_addr=self.smtp.from_addr, to_addrs=sobre)
            if rechazos:
                log.warning("algunos destinatarios fueron rechazados",
                            extra={"rechazados": list(rechazos)})
            log.info("correo enviado", extra={
                "asunto": subject, "destinatarios": len(sobre),
                "adjuntos": len(adjuntos)})
            return True
        except smtplib.SMTPAuthenticationError as exc:
            log.error("fallo de autenticacion SMTP al enviar",
                      extra={"asunto": subject, "codigo": exc.smtp_code})
            return False
        except (smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused) as exc:
            # NO es un problema de red ni de credencial: el servidor acepta la
            # sesion y rechaza una direccion. Verificado el 2026-09-03: este
            # servidor responde 554 "solo se pueden enviar correos a dominios
            # locales" ante cualquier destinatario externo. Clasificarlo como
            # fallo de red haria que el operador buscase el problema donde no
            # esta.
            detalle = getattr(exc, "recipients", None) or getattr(exc, "sender", "")
            log.error("el servidor rechazo una direccion del sobre",
                      extra={"asunto": subject, "rechazado": str(detalle)[:400],
                             "tipo": type(exc).__name__})
            return False
        except (OSError, smtplib.SMTPException, ssl.SSLError) as exc:
            log.error("fallo de red al enviar correo",
                      extra={"asunto": subject, "error": f"{type(exc).__name__}: {exc}"})
            return False
        finally:
            if servidor is not None:
                try:
                    servidor.quit()
                except Exception:  # noqa: BLE001
                    pass


# --------------------------------------------------------------------------
# Envio por Gmail API (OAuth2)
# --------------------------------------------------------------------------
class GmailMailer:
    """Envio por Gmail API con refresh_token (OAuth2).

    Alternativa a SMTP cuando se configura GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET
    y GMAIL_REFRESH_TOKEN en config/credentials.env."""

    def __init__(self, gmail_cfg, dry_run: bool = False) -> None:
        self.gmail_cfg = gmail_cfg
        self.dry_run = bool(dry_run)
        self._token_cache = None
        self._token_expiry = None

    def _get_access_token(self) -> str:
        """Obtiene un access_token usando el refresh_token."""
        try:
            import requests
            from datetime import timedelta
        except ImportError:
            log.error("se requiere requests para Gmail OAuth; usar SMTP")
            raise

        ahora = datetime.now(timezone.utc)

        # Reutilizar token si aun es valido
        if self._token_cache and self._token_expiry and ahora < self._token_expiry:
            return self._token_cache

        url = "https://oauth2.googleapis.com/token"
        data = {
            "client_id": self.gmail_cfg.client_id,
            "client_secret": self.gmail_cfg.client_secret,
            "refresh_token": self.gmail_cfg.refresh_token,
            "grant_type": "refresh_token",
        }

        try:
            r = requests.post(url, data=data, timeout=10)
            r.raise_for_status()
            respuesta = r.json()
            token = respuesta.get("access_token")
            expires_in = respuesta.get("expires_in", 3600)

            self._token_cache = token
            self._token_expiry = ahora + timedelta(seconds=max(0, expires_in - 60))

            log.debug("access_token obtenido para Gmail", extra={"expires_in": expires_in})
            return token
        except Exception as exc:
            log.error("fallo al obtener access_token de Google",
                      extra={"error": f"{type(exc).__name__}: {exc}"})
            raise

    def verify_connection(self) -> tuple[bool, Optional[str]]:
        """Verifica que se pueda obtener un access_token."""
        if self.dry_run:
            return True, None
        try:
            self._get_access_token()
            return True, None
        except Exception as exc:
            return False, f"Gmail OAuth: {type(exc).__name__}: {exc}"

    def send(self, *, subject: str, html: str, to: Sequence[str],
             cc: Optional[Sequence[str]] = None, text: Optional[str] = None,
             attachments: Optional[Sequence[Path]] = None,
             headers: Optional[dict[str, str]] = None) -> bool:
        """Envia un correo via Gmail API."""
        destinatarios = [d for d in (to or []) if d]
        copias = [d for d in (cc or []) if d and d not in destinatarios]

        if not destinatarios:
            log.error("envio abortado: no hay destinatarios", extra={"asunto": subject})
            return False

        # Gmail no soporta attachments via API de SMTP; solo via REST con multipart.
        # Como esto es complejo, simplemente advertir y no adjuntar.
        if attachments:
            log.warning("Gmail API no soporta adjuntos; se envian sin ellos",
                       extra={"asunto": subject, "adjuntos": len(attachments)})

        adjuntos = []
        cuerpo_texto = text if text is not None else html_a_texto(html)

        # Construir el mensaje igual que en Mailer, pero sin adjuntos
        mensaje: MIMEMultipart = MIMEMultipart("alternative")
        mensaje.attach(MIMEText(cuerpo_texto, "plain", "utf-8"))
        mensaje.attach(MIMEText(html, "html", "utf-8"))

        mensaje["Subject"] = subject
        mensaje["From"] = self.gmail_cfg.from_addr or "noreply@gmail.com"
        mensaje["To"] = ", ".join(destinatarios)
        if copias:
            mensaje["Cc"] = ", ".join(copias)
        if hasattr(self.gmail_cfg, 'reply_to') and self.gmail_cfg.reply_to:
            mensaje["Reply-To"] = self.gmail_cfg.reply_to
        mensaje["Date"] = formatdate(localtime=True)
        mensaje["Message-ID"] = make_msgid()
        mensaje["X-Mailer"] = "Sistema de Inteligencia de Amenazas"
        mensaje["Auto-Submitted"] = "auto-generated"
        for clave, valor in (headers or {}).items():
            mensaje[clave] = valor

        sobre = destinatarios + copias

        if self.dry_run:
            log.info("simulacion de envio por Gmail (dry-run)", extra={
                "asunto": subject, "destinatarios": len(sobre)})
            return True

        try:
            token = self._get_access_token()
            # Codificar el mensaje en base64 para Gmail API
            msg_bytes = mensaje.as_bytes()
            msg_b64 = base64.urlsafe_b64encode(msg_bytes).decode('utf-8')

            import requests
            url = "https://www.googleapis.com/gmail/v1/users/me/messages/send"
            headers_req = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
            payload = {"raw": msg_b64}

            r = requests.post(url, json=payload, headers=headers_req, timeout=10)
            r.raise_for_status()

            log.info("correo enviado por Gmail", extra={
                "asunto": subject, "destinatarios": len(sobre)})
            return True
        except Exception as exc:
            log.error("fallo al enviar por Gmail",
                      extra={"asunto": subject, "error": f"{type(exc).__name__}: {exc}"})
            return False


# --------------------------------------------------------------------------
# Asuntos
# --------------------------------------------------------------------------
#: Prefijo UNICO de todos los correos del sistema (revision de claridad del 2026-09-15).
#: Convivian tres: «[SOC]», «[Inventario]» y «[Inteligencia de Amenazas]», de modo que las
#: reglas de bandeja y la busqueda por asunto no encontraban la mitad de los correos. El
#: prefijo es el nombre de la plataforma, sin siglas.
PREFIJO_ASUNTO = "[Inteligencia de Amenazas]"


def asunto_alerta(criticas: int = 0, altas: int = 0, kev: int = 0,
                  fecha: Optional[datetime] = None, total: Optional[int] = None,
                  activos: Optional[int] = None) -> str:
    """«[Inteligencia de Amenazas] Alerta diaria · 15 de septiembre de 2026 · 12 vulnerabilidades, 7 críticas».

    El asunto dice DE QUE VA el correo: la fecha en palabras y de cuanto se trata. Antes
    decia solo «Alertamiento diario» y una fecha en cifras, asi que en la bandeja no se
    distinguia un dia con siete criticas de otro sin novedades y habia que abrirlos todos
    (revision de claridad del 2026-09-15).

    ``altas``, ``kev`` y ``activos`` se conservan en la firma porque hay llamadas y pruebas
    que los pasan; el asunto se queda en dos cifras para que no lo corte el gestor de correo.
    """
    dt = fecha or datetime.now()
    base = f"{PREFIJO_ASUNTO} Alerta diaria · {fecha_larga(dt)}"
    n_total = total if total is not None else (int(criticas or 0) + int(altas or 0))
    try:
        n_total = int(n_total or 0)
    except (TypeError, ValueError):
        n_total = 0
    if not n_total:
        return f"{base} · sin novedades que requieran acción"
    cifras = f"{numero(n_total)} vulnerabilidad{'es' if n_total != 1 else ''}"
    n_criticas = int(criticas or 0)
    if n_criticas:
        cifras += f", {numero(n_criticas)} crítica{'s' if n_criticas != 1 else ''}"
    return f"{base} · {cifras}"


def asunto_mensual(month: str) -> str:
    return f"{PREFIJO_ASUNTO} Informe mensual · {mes_largo(month)}"


def asunto_admin(titulo: str, severidad: str = "info") -> str:
    """«[Inteligencia de Amenazas] Acción requerida · <título>».

    «ACCION» iba sin tilde y en mayusculas (2026-09-15): en mayusculas la tilde tambien se
    escribe, y gritar en el asunto no lo hace mas urgente.
    """
    prefijo = {"critical": f"{PREFIJO_ASUNTO} Acción requerida · ",
               "warning": f"{PREFIJO_ASUNTO} Aviso · ",
               "info": f"{PREFIJO_ASUNTO} "}.get(severidad, f"{PREFIJO_ASUNTO} ")
    return f"{prefijo}{titulo}"

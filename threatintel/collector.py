"""Recoleccion diaria: consulta las fuentes, correlaciona y persiste.

Diferencias de fondo con el recolector anterior:

  * La salud de CADA fuente se registra en la base de datos, de modo que una
    fuente que deja de funcionar se detecta y se avisa. Antes se hacia
    `except Exception: continue` y se imprimia "35 fuentes (100 % funcionales)".

  * La identidad de una amenaza no incluye la fecha de publicacion. Los feeds
    republican la misma entrada con fecha nueva cada dia, y con el identificador
    antiguo `md5(titulo + fecha)` eso generaba un registro nuevo a diario: 11.007
    registros para 5.638 amenazas reales, y el mismo aviso critico alertado cinco
    dias seguidos.

  * La ventana temporal es movil (N dias) en lugar de "mes actual", que perdia
    todo lo publicado a fin de mes.

  * El estado de "ya alertada" vive en la columna `alerted_at`, no en un fichero
    JSON que el cron borraba cada dia 1.
"""
from __future__ import annotations

import dataclasses
import json
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

from . import db, http, identity, matching, scoring, sources, translate
from .logging_setup import get_logger
from .paths import DAILY_JSON, LAST_EXECUTION_JSON, monthly_json

log = get_logger("collector")

#: Tipos de fuente que producen entradas (titulo, resumen, enlace, fecha) y se
#: recolectan como un feed. El resto (KEV, NVD, EPSS, conjuntos de datos) solo
#: se comprueba en comprobar_apis().
TIPOS_RECOLECTABLES: tuple[str, ...] = ("rss", "html_colcert")


def _ahora() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------
# Fuente HTML: ColCERT (Gobierno de Colombia)
# --------------------------------------------------------------------------
# ColCERT (colcert.gov.co) no publica RSS: es un CMS Newtenberg cuya portada es
# un <meta http-equiv="refresh"> hacia /800/w3-channel.html, y el listado real
# de avisos esta en la seccion "Boletines" (/800/w3-propertyvalue-412601.html).
# Cada aviso es un recuadro con esta forma (comprobado el 2026-09-05):
#
#   <div class="recuadro ..."><div class="p-4 card h-100">
#     <div class="h5 ... aid-440418"><a href="w3-article-440418.html">COLCERT AL – 20260826 - 116 Alerta: ...</a></div>
#     <h6 class="fecha ... iso8601-20260826T0800000500">26 de agosto de 2026</h6>
#     <div class="tipo filtrar my-2"><span ...><span ...>Alerta (AL)</span></span></div>
#     <div class="anio ..."><span ...><span ...>2026</span></span></div>
#   </div></div>
#
# El analizador no depende de los nombres de clase concretos mas que para
# reconocer la fecha y el tipo: una entrada es cualquier enlace a un articulo
# (w3-article-NNN.html) seguido de una fecha antes del siguiente enlace. Los
# enlaces del menu y del pie (tambien w3-article-…) no llevan fecha y se descartan.
MAX_META_REFRESH = 3

_RE_ARTICULO_COLCERT = re.compile(r"w3-article-\d+\.html?$", re.I)
#: Elementos HTML vacios (sin etiqueta de cierre). El listado real los usa dentro de los
#: recuadros (<br>, <img>, <input> de los filtros); si contaran como apertura, la
#: profundidad de captura de la fecha o del tipo se desfasaria y el cierre del recuadro
#: no cerraria la captura (hallazgo de la revision del 2026-09-05).
_ELEMENTOS_VACIOS = frozenset({
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param",
    "source", "track", "wbr",
})
#: Genero gramatical de los tipos de aviso que publica ColCERT, para concordar el
#: resumen («Alerta … publicada», «Informe … publicado»). Un tipo desconocido o
#: compuesto («Reporte semanal (RS) Advertencia (AD)») recibe una redaccion neutra.
_TIPOS_FEMENINOS = frozenset({"alerta", "advertencia", "circular", "nota", "recomendación",
                              "recomendacion", "guía", "guia", "publicación", "publicacion"})
_TIPOS_MASCULINOS = frozenset({"informe", "reporte", "boletín", "boletin", "aviso", "comunicado",
                               "documento", "manual", "lineamiento"})
# El CMS escribe el desfase sin signo («…T0800000500»): se toma la hora local
# de Colombia (UTC-5) salvo que el signo venga explicito.
_RE_ISO8601_CLASE = re.compile(
    r"iso8601-(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})(?:([+-])?(\d{2})(\d{2}))?", re.I)
_RE_FECHA_ES = re.compile(
    r"(\d{1,2})\s+de\s+([a-záéíóú]+)\s+de\s+(\d{4})", re.I)
_RE_FECHA_NUM = re.compile(r"\b(\d{1,2})/(\d{1,2})/(\d{4})\b|\b(\d{4})-(\d{2})-(\d{2})\b")
_RE_META_REFRESH_URL = re.compile(r"url\s*=\s*['\"]?\s*([^'\";\s]+)", re.I)
_MESES_ES = {
    "enero": 1, "febrero": 2, "marzo": 3, "abril": 4, "mayo": 5, "junio": 6,
    "julio": 7, "agosto": 8, "septiembre": 9, "setiembre": 9, "octubre": 10,
    "noviembre": 11, "diciembre": 12,
}
_ZONA_COLOMBIA = timezone(timedelta(hours=-5))


class _AnalizadorColcert(HTMLParser):
    """Extrae (titulo, enlace, fecha, tipo) de un listado de ColCERT y detecta
    un <meta http-equiv="refresh">. Tolera cambios menores de maquetacion."""

    def __init__(self, url_base: str) -> None:
        super().__init__(convert_charrefs=True)
        self.url_base = url_base
        self.meta_refresh: Optional[str] = None
        self.entradas: list[dict] = []
        self._actual: Optional[dict] = None
        self._en_enlace = False
        self._capturando: Optional[str] = None   # "fecha" | "tipo"
        self._profundidad_captura = 0
        self._pila: list[str] = []

    # -- utilidades -------------------------------------------------------
    @staticmethod
    def _clases(atributos: list[tuple[str, Optional[str]]]) -> str:
        return " ".join((v or "") for k, v in atributos if k == "class").lower()

    def _cerrar_actual(self) -> None:
        if self._actual is not None:
            self.entradas.append(self._actual)
        self._actual = None

    def _mismo_sitio(self, href: str) -> bool:
        """Solo enlaces relativos o del mismo dominio que la fuente: un enlace absoluto
        a otro sitio que termine en w3-article-NNN.html (otro CMS Newtenberg, un
        banner) no es un aviso de ColCERT."""
        destino = urlparse(href)
        if destino.scheme and destino.scheme.lower() not in ("http", "https"):
            return False                 # javascript:, mailto:, data:
        if not destino.netloc:
            return True                  # relativo: se resuelve contra la fuente
        propio = (urlparse(self.url_base).hostname or "").lower()
        ajeno = (destino.hostname or "").lower()
        quitar = lambda h: h[4:] if h.startswith("www.") else h  # noqa: E731
        return bool(propio) and quitar(propio) == quitar(ajeno)

    # -- eventos ----------------------------------------------------------
    def handle_startendtag(self, tag: str, attrs) -> None:
        # <meta … /> puede llevar el refresh; cualquier otro elemento autocerrado
        # (<br/>, <img/>, <div/>) no abre nada y no debe alterar la profundidad.
        if tag == "meta":
            self.handle_starttag(tag, attrs)

    def handle_starttag(self, tag: str, attrs) -> None:
        atributos = dict(attrs)
        if tag == "meta":
            equiv = (atributos.get("http-equiv") or "").strip().lower()
            contenido = atributos.get("content") or ""
            if equiv == "refresh" and self.meta_refresh is None:
                encontrado = _RE_META_REFRESH_URL.search(contenido)
                if encontrado:
                    self.meta_refresh = urljoin(self.url_base, encontrado.group(1).strip())
            return
        if tag in _ELEMENTOS_VACIOS:
            return                       # sin cierre: no cuenta para la profundidad
        if tag in ("script", "style"):
            self._pila.append(tag)
            return

        if tag == "a":
            href = (atributos.get("href") or "").strip()
            if (href and "#" not in href and _RE_ARTICULO_COLCERT.search(href)
                    and self._mismo_sitio(href)):
                self._cerrar_actual()
                self._actual = {"titulo": "", "enlace": urljoin(self.url_base, href),
                                "fecha": None, "fecha_texto": "", "tipo": ""}
                self._en_enlace = True
            return

        if self._actual is None or self._capturando:
            if self._capturando:
                self._profundidad_captura += 1
            return
        clases = self._clases(attrs)
        if "fecha" in clases.split():
            self._capturando = "fecha"
            self._profundidad_captura = 0
            iso = _RE_ISO8601_CLASE.search(clases)
            if iso and self._actual["fecha"] is None:
                self._actual["fecha"] = _fecha_iso_colcert(iso)
        elif "tipo" in clases.split():
            self._capturando = "tipo"
            self._profundidad_captura = 0

    def handle_endtag(self, tag: str) -> None:
        if tag in _ELEMENTOS_VACIOS:
            return                       # «</br>» y similares: el CMS a veces los escribe
        if tag in ("script", "style"):
            if self._pila and self._pila[-1] == tag:
                self._pila.pop()
            return
        if tag == "a" and self._en_enlace:
            self._en_enlace = False
            return
        if self._capturando:
            if self._profundidad_captura == 0:
                self._capturando = None
            else:
                self._profundidad_captura -= 1

    def handle_data(self, datos: str) -> None:
        if self._pila or self._actual is None:
            return
        if self._en_enlace:
            self._actual["titulo"] += datos
        elif self._capturando == "fecha":
            # Con espacio: «19 de<br>agosto» son dos palabras; _fecha_texto_colcert
            # tolera cualquier cantidad de blancos.
            self._actual["fecha_texto"] += " " + datos
        elif self._capturando == "tipo":
            # Con espacio: un recuadro con dos tipos («Reporte semanal (RS)» y
            # «Advertencia (AD)» en <span> consecutivos) no debe pegarlos.
            self._actual["tipo"] += " " + datos

    def close(self) -> None:  # noqa: D102
        super().close()
        self._cerrar_actual()


def _fecha_iso_colcert(coincidencia: "re.Match[str]") -> Optional[datetime]:
    """Convierte el token de clase iso8601-AAAAMMDDTHHMMSS±HHMM en datetime."""
    try:
        anio, mes, dia, hora, minuto, segundo, signo, desfase_h, desfase_m = coincidencia.groups()
        zona = _ZONA_COLOMBIA
        if signo and desfase_h is not None:
            minutos = int(desfase_h) * 60 + int(desfase_m or 0)
            zona = timezone(timedelta(minutes=(-minutos if signo == "-" else minutos)))
        return datetime(int(anio), int(mes), int(dia), int(hora), int(minuto), int(segundo),
                        tzinfo=zona)
    except (TypeError, ValueError, OverflowError):
        return None


def _fecha_en_espanol(fecha: datetime) -> str:
    """«26 de agosto de 2026» a partir de un datetime (sin ceros a la izquierda)."""
    nombres = {numero: nombre for nombre, numero in _MESES_ES.items() if nombre != "setiembre"}
    return f"{fecha.day} de {nombres.get(fecha.month, fecha.month)} de {fecha.year}"


def _fecha_texto_colcert(texto: str) -> Optional[datetime]:
    """«26 de agosto de 2026», «26/08/2026» o «2026-08-26» → datetime (hora de Colombia)."""
    limpio = " ".join((texto or "").split()).lower()
    encontrado = _RE_FECHA_ES.search(limpio)
    if encontrado:
        mes = _MESES_ES.get(encontrado.group(2))
        if mes:
            try:
                return datetime(int(encontrado.group(3)), mes, int(encontrado.group(1)),
                                tzinfo=_ZONA_COLOMBIA)
            except ValueError:
                return None
    encontrado = _RE_FECHA_NUM.search(limpio)
    if encontrado:
        try:
            if encontrado.group(1):
                return datetime(int(encontrado.group(3)), int(encontrado.group(2)),
                                int(encontrado.group(1)), tzinfo=_ZONA_COLOMBIA)
            return datetime(int(encontrado.group(4)), int(encontrado.group(5)),
                            int(encontrado.group(6)), tzinfo=_ZONA_COLOMBIA)
        except ValueError:
            return None
    return None


def _resumen_colcert(tipo: str, fecha: datetime) -> str:
    """Resumen de un aviso de ColCERT concordado con el genero del tipo.

    «Alerta (AL) publicada por ColCERT el …», «Informe (IN) publicado por ColCERT el …».
    Si el tipo no se reconoce (o es compuesto, como «Reporte semanal (RS) Advertencia (AD)»)
    se usa una redaccion neutra que no obliga a concordar; sin tipo, «Aviso publicado …»."""
    cuando = f"el {_fecha_en_espanol(fecha)}."
    tipo = " ".join((tipo or "").split())
    if not tipo:
        return f"Aviso publicado por ColCERT {cuando}"
    palabras = [p.strip("()[]«»\"',.;:").lower() for p in tipo.split()]
    tipos_presentes = sum(1 for p in palabras if p in _TIPOS_FEMENINOS or p in _TIPOS_MASCULINOS)
    primera = palabras[0]
    if tipos_presentes <= 1 and primera in _TIPOS_FEMENINOS:
        return f"{tipo} publicada por ColCERT {cuando}"
    if tipos_presentes <= 1 and primera in _TIPOS_MASCULINOS:
        return f"{tipo} publicado por ColCERT {cuando}"
    return f"ColCERT publicó este aviso ({tipo}) {cuando}"


def analizar_html_colcert(html_texto: str, url_base: str) -> tuple[list[dict], Optional[str]]:
    """Analiza una pagina de ColCERT.

    Devuelve (entradas, url_meta_refresh). Las entradas tienen el mismo formato
    que http.normalizar_entrada() para que el recolector las trate igual que las
    de un RSS: title, summary, link, published (ISO 8601 con zona), published_parsed
    (None: la fecha ISO ya lleva zona y _fecha_entrada la interpreta bien) e id.
    """
    analizador = _AnalizadorColcert(url_base)
    try:
        analizador.feed(html_texto or "")
        analizador.close()
    except Exception as exc:  # noqa: BLE001 - html.parser rara vez lanza, pero no debe tumbar la recoleccion
        log.warning("No se pudo analizar el HTML de ColCERT",
                    extra={"url_pedida": url_base, "detalle": f"{exc}"[:200]})
        return [], analizador.meta_refresh

    entradas: list[dict] = []
    vistos: set[str] = set()
    for bruto in analizador.entradas:
        titulo = " ".join(http.limpiar_html(bruto["titulo"]).split())
        fecha = bruto["fecha"] or _fecha_texto_colcert(bruto["fecha_texto"])
        if not titulo or fecha is None:
            continue                     # menu, pie o recuadro sin fecha: no es un aviso
        enlace = bruto["enlace"]
        if enlace in vistos:
            continue
        vistos.add(enlace)
        tipo = " ".join(http.limpiar_html(bruto["tipo"]).split())
        entradas.append({
            "title": titulo,
            "summary": _resumen_colcert(tipo, fecha),
            "link": enlace,
            "published": fecha.replace(microsecond=0).isoformat(),
            "published_parsed": None,
            "id": enlace,
        })
    return entradas, analizador.meta_refresh


_RE_META_CHARSET = re.compile(rb"""<meta[^>]+charset=["']?\s*([A-Za-z0-9_.:-]+)""", re.I)


def _decodificar(res: http.FetchResult) -> str:
    """Bytes → texto. ColCERT sirve text/html SIN charset en la cabecera, asi que
    requests supone ISO-8859-1 y las tildes salen rotas; manda el <meta charset>
    del propio documento, despues UTF-8 estricto y solo al final la suposicion
    de requests."""
    contenido = res.content or b""
    candidatas: list[str] = []
    meta = _RE_META_CHARSET.search(contenido[:8192])
    if meta:
        candidatas.append(meta.group(1).decode("ascii", "ignore"))
    candidatas.append("utf-8")
    if res.encoding:
        candidatas.append(res.encoding)
    for codificacion in candidatas:
        try:
            return contenido.decode(codificacion)
        except (UnicodeDecodeError, LookupError):
            continue
    return contenido.decode("utf-8", errors="replace")


def descargar_html_colcert(url: str, *, timeout: int = http.TIMEOUT_POR_DEFECTO,
                           retries: int = http.REINTENTOS_POR_DEFECTO,
                           user_agent: Optional[str] = None) -> http.FeedResult:
    """Descarga el listado de avisos de ColCERT y lo devuelve como un FeedResult.

    Sigue la cadena COMPLETA de <meta http-equiv="refresh"> (hasta MAX_META_REFRESH
    saltos, cada uno validado por threatintel.http) y se queda con la pagina que mas
    avisos produce. Antes se detenia en la primera pagina con algun recuadro fechado,
    y desde la portada eso era /800/w3-channel.html con un unico recuadro en vez del
    listado de «Boletines» (hallazgo de la revision del 2026-09-05).

    Mismo contrato que http.fetch_feed(): ok=True con cero entradas es un listado que se
    pudo leer pero no tenia avisos; decidir si eso es un fallo es cosa de health.py.
    Si un salto posterior falla pero una pagina anterior ya dio avisos, se devuelven esos.
    Una cadena que no termina (bucle o mas de MAX_META_REFRESH saltos) sin ningun aviso
    es el error «redirecciones».
    """
    actual = str(url or "").strip()
    latencia_total = 0
    mejor: Optional[http.FeedResult] = None
    visitadas: set[str] = set()
    cadena_rota = False              # bucle o cadena mas larga que MAX_META_REFRESH
    for salto in range(MAX_META_REFRESH + 1):
        visitadas.add(actual)
        res = http.fetch(actual, timeout=timeout, retries=retries, user_agent=user_agent)
        latencia_total += int(res.latency_ms or 0)
        fallo: Optional[http.FeedResult] = None
        texto = ""
        if not res.ok:
            fallo = http.FeedResult(False, res.status, [], res.error, latencia_total, False,
                                    None, final_url=res.final_url or actual)
        else:
            texto = _decodificar(res)
            if not texto.strip():
                log.warning("ColCERT: cuerpo vacío", extra={"url_pedida": actual, "status": res.status})
                fallo = http.FeedResult(False, res.status, [], "vacio", latencia_total, False, None,
                                        final_url=res.final_url or actual)
            elif "<" not in texto[:http.LIMITE_SNIFF]:
                log.warning("ColCERT: la respuesta no es HTML",
                            extra={"url_pedida": actual, "content_type": res.content_type})
                fallo = http.FeedResult(False, res.status, [], "parse", latencia_total, False, None,
                                        final_url=res.final_url or actual)
        if fallo is not None:
            if mejor is not None and mejor.entries:
                log.warning("ColCERT: fallo un salto del meta refresh; se usa la pagina anterior",
                            extra={"url_pedida": actual, "error": fallo.error,
                                   "final_url": mejor.final_url, "entradas": len(mejor.entries)})
                return dataclasses.replace(mejor, latency_ms=latencia_total)
            return fallo

        entradas, siguiente = analizar_html_colcert(texto, res.final_url or actual)
        pagina = http.FeedResult(True, res.status, entradas, None, latencia_total, False,
                                 "ColCERT – Boletines y alertas", final_url=res.final_url or actual)
        if mejor is None or len(entradas) > len(mejor.entries):
            mejor = pagina
        if not siguiente:
            break
        if siguiente in visitadas:
            log.warning("ColCERT: el meta refresh forma un bucle",
                        extra={"url_pedida": actual, "destino": siguiente})
            cadena_rota = True
            break
        if salto == MAX_META_REFRESH:
            log.warning("ColCERT: demasiados meta refresh seguidos",
                        extra={"url_pedida": url, "ultimo": actual, "maximo": MAX_META_REFRESH})
            cadena_rota = True
            break
        log.debug("ColCERT: se sigue un meta refresh", extra={"url_pedida": actual,
                                                             "destino": siguiente, "entradas": len(entradas)})
        actual = siguiente

    if mejor is not None and (mejor.entries or not cadena_rota):
        log.debug("ColCERT analizado", extra={"url_pedida": url, "final_url": mejor.final_url,
                                              "entradas": len(mejor.entries), "latency_ms": latencia_total})
        return dataclasses.replace(mejor, latency_ms=latencia_total)
    return http.FeedResult(False, mejor.status if mejor else None, [], "redirecciones",
                           latencia_total, False, None, final_url=actual)


def _descargar_fuente(fuente: dict, *, reintentos: int,
                      user_agent: Optional[str]) -> http.FeedResult:
    """Descarga una fuente recolectable segun su tipo y devuelve un FeedResult."""
    tiempo = int(fuente.get("timeout_s") or 30)
    if fuente.get("kind") == "html_colcert":
        return descargar_html_colcert(fuente["url"], timeout=tiempo, retries=reintentos,
                                      user_agent=user_agent)
    return http.fetch_feed(fuente["url"], timeout=tiempo, retries=reintentos,
                           user_agent=user_agent)


def _fecha_entrada(entrada: dict) -> Optional[datetime]:
    """Fecha de publicacion de una entrada, si es utilizable."""
    estructura = entrada.get("published_parsed")
    if estructura:
        try:
            # feedparser entrega published_parsed en UTC: timegm() lo respeta.
            # mktime() lo interpretaba como hora local y en un servidor con zona
            # America/Bogota adelantaba cinco horas cada fecha de publicacion.
            from calendar import timegm
            return datetime.fromtimestamp(timegm(estructura), timezone.utc)
        except (TypeError, ValueError, OverflowError):
            pass

    texto = entrada.get("published")
    if texto:
        try:
            from email.utils import parsedate_to_datetime
            fecha = parsedate_to_datetime(str(texto))
            return fecha if fecha.tzinfo else fecha.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            pass
        # Se incluyen las variantes SIN zona: sin ellas una fecha ISO como
        # "2026-08-25T14:00:00" devolvia None, y una entrada sin fecha se acepta
        # sin pasar por el filtro de ventana. Es el mismo tipo de fuga que tenia
        # el is_current_month() del sistema anterior.
        for formato in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ",
                        "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S.%fZ",
                        "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M",
                        "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d",
                        "%d/%m/%Y", "%Y/%m/%d"):
            try:
                fecha = datetime.strptime(str(texto)[:25], formato)
                return fecha if fecha.tzinfo else fecha.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return None


# --------------------------------------------------------------------------
# Ejecuciones
# --------------------------------------------------------------------------
def iniciar_ejecucion(conn: sqlite3.Connection, kind: str,
                      log_path: Optional[str] = None) -> int:
    cur = conn.execute(
        """INSERT INTO executions(kind, started_at, status, log_path)
           VALUES(?,?,'running',?)""", (kind, db.utcnow(), log_path))
    return cur.lastrowid


def cerrar_ejecucion(conn: sqlite3.Connection, execution_id: int, *,
                     status: str, sources_ok: int = 0, sources_failed: int = 0,
                     threats_new: int = 0, threats_alerted: int = 0,
                     error: Optional[str] = None,
                     detalle: Optional[dict] = None) -> None:
    conn.execute(
        """UPDATE executions
              SET finished_at=?, status=?, sources_ok=?, sources_failed=?,
                  threats_new=?, threats_alerted=?, error=?, detail_json=?
            WHERE id=?""",
        (db.utcnow(), status, sources_ok, sources_failed, threats_new,
         threats_alerted, error,
         json.dumps(detalle, ensure_ascii=False) if detalle else None,
         execution_id))


# --------------------------------------------------------------------------
# Persistencia de una amenaza
# --------------------------------------------------------------------------
def _guardar_amenaza(conn: sqlite3.Connection, *, huella: str, cve: Optional[str],
                     titulo_en: str, titulo_es: Optional[str],
                     resumen_en: Optional[str], resumen_es: Optional[str],
                     severidad: str, origen: str, mes: str,
                     publicada: Optional[str], motor: str,
                     source_id: int, url: str) -> tuple[int, bool]:
    """Inserta o fusiona. Devuelve (threat_id, es_nueva)."""
    ahora = db.utcnow()
    existente = conn.execute(
        "SELECT id FROM threats WHERE fingerprint=?", (huella,)).fetchone()

    if existente:
        threat_id = existente["id"]
        # Reaparicion: se actualiza la marca temporal y se completa lo que falte,
        # sin sobrescribir traducciones ni enriquecimientos ya hechos.
        conn.execute(
            """UPDATE threats
                  SET times_seen = times_seen + 1,
                      last_seen_at = ?,
                      title_es   = COALESCE(title_es, ?),
                      summary_en = COALESCE(NULLIF(summary_en,''), ?),
                      summary_es = COALESCE(NULLIF(summary_es,''), ?),
                      published_at = COALESCE(published_at, ?)
                WHERE id = ?""",
            (ahora, titulo_es, resumen_en, resumen_es, publicada, threat_id))
        nueva = False
    else:
        cur = conn.execute(
            """INSERT INTO threats(
                   fingerprint, cve, title_en, title_es, summary_en, summary_es,
                   severity, severity_source, published_at, first_seen_at,
                   last_seen_at, times_seen, translation_engine, month, relevance)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,1,?,?,0)""",
            (huella, cve, titulo_en, titulo_es, resumen_en, resumen_es,
             severidad, origen, publicada, ahora, ahora, motor, mes))
        threat_id = cur.lastrowid
        nueva = True

    if url:
        conn.execute(
            """INSERT OR IGNORE INTO threat_sources(threat_id, source_id, url, seen_at)
               VALUES(?,?,?,?)""", (threat_id, source_id, url, ahora))

    return threat_id, nueva


# --------------------------------------------------------------------------
# Recoleccion
# --------------------------------------------------------------------------
def recolectar(conn: sqlite3.Connection, *, cfg,
               solo_fuente: Optional[str] = None,
               dry_run: bool = False) -> dict[str, Any]:
    """Consulta las fuentes activas y persiste las amenazas relevantes."""
    ventana_dias = int(cfg.get("collect_lookback_days", 45) or 45)
    limite_fecha = _ahora() - timedelta(days=ventana_dias)
    exigir_tecnologia = bool(cfg.get("collect_require_technology", True))
    user_agent = cfg.get("http_user_agent")
    reintentos = int(cfg.get("http_retries", 2) or 2)

    inventario = matching.compilar_inventario(conn, cfg=cfg)
    contador_ollama = translate.ContadorLlamadas(
        int(cfg.get("ollama_max_calls_per_run", 25) or 25))

    filas = sources.listar(conn, solo_activas=True)
    if solo_fuente:
        filas = [f for f in filas
                 if f["slug"] == solo_fuente or str(f["id"]) == str(solo_fuente)]
    # Las fuentes de enriquecimiento no se recolectan como feed
    filas = [f for f in filas if f.get("kind") in TIPOS_RECOLECTABLES]

    stats: dict[str, Any] = {
        "fuentes": len(filas), "fuentes_ok": 0, "fuentes_fallo": 0,
        "entradas": 0, "aceptadas": 0, "nuevas": 0, "reaparecidas": 0,
        "descartadas_fecha": 0, "descartadas_sin_tecnologia": 0,
        "descartadas_sin_titulo": 0, "traducidas": 0,
        "fuentes_con_fallo": [],
    }

    log.info("inicio de recoleccion", extra={
        "fuentes": len(filas), "ventana_dias": ventana_dias,
        "exigir_tecnologia": exigir_tecnologia})

    for fuente in filas:
        resultado = _descargar_fuente(fuente, reintentos=reintentos, user_agent=user_agent)

        aceptadas_fuente = 0

        if not resultado.ok:
            stats["fuentes_fallo"] += 1
            stats["fuentes_con_fallo"].append({
                "slug": fuente["slug"], "name": fuente["name"],
                "error": resultado.error, "status": resultado.status})
            if not dry_run:
                sources.registrar_salud(
                    conn, fuente["id"], ok=False, http_status=resultado.status,
                    entries=0, accepted=0, latency_ms=resultado.latency_ms,
                    error=resultado.error)
            log.warning("fuente sin datos", extra={
                "source": fuente["slug"], "error": resultado.error,
                "status": resultado.status})
            continue

        stats["fuentes_ok"] += 1
        stats["entradas"] += len(resultado.entries)

        for entrada in resultado.entries:
            titulo = (entrada.get("title") or "").strip()
            if not titulo:
                stats["descartadas_sin_titulo"] += 1
                continue

            # --- ventana temporal ---
            fecha = _fecha_entrada(entrada)
            if fecha is not None and fecha < limite_fecha:
                stats["descartadas_fecha"] += 1
                continue

            resumen_bruto = entrada.get("summary") or ""
            enlace = (entrada.get("link") or "").strip()

            # --- correlacion con el inventario ---
            texto = f"{titulo} {resumen_bruto}"
            coincidencias = matching.encontrar(texto, inventario, titulo=titulo)

            if exigir_tecnologia and not coincidencias:
                stats["descartadas_sin_tecnologia"] += 1
                continue

            # --- identidad ---
            cve = identity.extraer_cve(titulo, resumen_bruto)
            mes = (fecha or _ahora()).strftime("%Y-%m")
            try:
                huella = identity.fingerprint(
                    month=mes, cve=cve, titulo=titulo, url=enlace)
            except ValueError:
                stats["descartadas_sin_titulo"] += 1
                continue

            ya_existe = conn.execute(
                "SELECT id FROM threats WHERE fingerprint=?", (huella,)).fetchone()

            # --- severidad provisional (el enriquecimiento la refinara) ---
            severidad, _ = scoring.heuristica(titulo, resumen_bruto)

            # --- traduccion: solo la primera vez que se ve la amenaza ---
            titulo_es = resumen_es = None
            motor = "none"
            if ya_existe is None:
                titulo_es, motor = translate.traducir(
                    titulo, cfg=cfg, conn=None if dry_run else conn,
                    severidad=severidad, contador=contador_ollama)
                if resumen_bruto:
                    resumen_es, _ = translate.traducir(
                        resumen_bruto[:1800], cfg=cfg,
                        conn=None if dry_run else conn,
                        severidad=severidad, contador=contador_ollama)
                if motor != "none":
                    stats["traducidas"] += 1

            if dry_run:
                stats["aceptadas"] += 1
                aceptadas_fuente += 1
                if ya_existe is None:
                    stats["nuevas"] += 1
                else:
                    stats["reaparecidas"] += 1
                continue

            threat_id, es_nueva = _guardar_amenaza(
                conn, huella=huella, cve=cve, titulo_en=titulo,
                titulo_es=titulo_es,
                resumen_en=translate.limpiar_html(resumen_bruto)[:4000] or None,
                resumen_es=resumen_es, severidad=severidad,
                origen="heuristic", mes=mes,
                publicada=fecha.astimezone(timezone.utc).replace(microsecond=0).isoformat()
                .replace("+00:00", "Z") if fecha else None,
                motor=motor, source_id=fuente["id"], url=enlace)

            matching.aplicar(conn, threat_id, coincidencias)

            # La relevancia depende de las tecnologias, ya aplicadas
            tecnologias = [dict(r) for r in conn.execute(
                """SELECT t.criticality, t.exposure, t.systems_count,
                          tt.version_verdict, tt.confidence
                     FROM threat_technologies tt
                     JOIN technologies t ON t.id = tt.technology_id
                    WHERE tt.threat_id=?""", (threat_id,))]
            fila_amenaza = conn.execute(
                "SELECT severity, cvss_score, cvss_vector, epss_score, in_kev FROM threats "
                "WHERE id=?", (threat_id,)).fetchone()
            conn.execute(
                "UPDATE threats SET relevance=? WHERE id=?",
                (scoring.relevancia(
                    severity=fila_amenaza["severity"],
                    cvss_score=fila_amenaza["cvss_score"],
                    epss=fila_amenaza["epss_score"],
                    in_kev=bool(fila_amenaza["in_kev"]),
                    tecnologias=tecnologias,
                    min_confianza=float(cfg.get("alert_min_match_confidence", 0.6)),
                    ignorar_criticidad_baja=bool(cfg.get("ignore_low_criticality", True)),
                    cvss_vector=fila_amenaza["cvss_vector"]),
                 threat_id))

            stats["aceptadas"] += 1
            aceptadas_fuente += 1
            if es_nueva:
                stats["nuevas"] += 1
            else:
                stats["reaparecidas"] += 1

        if not dry_run:
            sources.registrar_salud(
                conn, fuente["id"], ok=True, http_status=resultado.status,
                entries=len(resultado.entries), accepted=aceptadas_fuente,
                latency_ms=resultado.latency_ms, error=None)

        log.info("fuente procesada", extra={
            "source": fuente["slug"], "entradas": len(resultado.entries),
            "aceptadas": aceptadas_fuente, "latencia_ms": resultado.latency_ms})

    # Las fuentes que no son feeds (CISA KEV, NVD, EPSS) no se recolectan como
    # RSS, pero SI deben comprobarse: si dejan de responder, el enriquecimiento
    # se queda sin datos oficiales y nadie se enteraria.
    if not solo_fuente and not dry_run:
        stats["apis"] = comprobar_apis(conn, cfg=cfg)

    stats["ollama"] = contador_ollama.resumen()
    log.info("recoleccion terminada", extra={
        k: v for k, v in stats.items() if k != "fuentes_con_fallo"})
    return stats


def comprobar_apis(conn: sqlite3.Connection, *, cfg) -> dict[str, Any]:
    """Comprueba las fuentes de tipo API y registra su salud.

    Sin esto quedaban como "sin datos" para siempre, y el panel comparaba las
    fuentes comprobadas contra el total, dando cifras que no cuadraban.
    """
    resultado = {"comprobadas": 0, "ok": 0, "fallo": 0}
    filas = [f for f in sources.listar(conn, solo_activas=True)
             if f.get("kind") not in TIPOS_RECOLECTABLES]

    for fuente in filas:
        try:
            prueba = sources.probar(conn, fuente["id"], cfg=cfg)
        except Exception as exc:  # noqa: BLE001
            prueba = {"ok": False, "error": f"{type(exc).__name__}: {exc}",
                      "entries": 0, "latency_ms": 0, "status": None}

        resultado["comprobadas"] += 1
        if prueba.get("ok"):
            resultado["ok"] += 1
        else:
            resultado["fallo"] += 1

        sources.registrar_salud(
            conn, fuente["id"], ok=bool(prueba.get("ok")),
            http_status=prueba.get("status"),
            entries=int(prueba.get("entries") or 0),
            accepted=0, latency_ms=prueba.get("latency_ms"),
            error=prueba.get("error"))

        log.info("api comprobada", extra={
            "source": fuente["slug"], "ok": bool(prueba.get("ok")),
            "entradas": prueba.get("entries")})

    return resultado


# --------------------------------------------------------------------------
# Exportacion JSON (compatibilidad con el sistema anterior)
# --------------------------------------------------------------------------
def exportar_json(conn: sqlite3.Connection, *, mes: Optional[str] = None) -> None:
    """Reescribe los ficheros JSON que producia el sistema anterior.

    Se mantiene por compatibilidad: puede haber cuadros de mando o scripts
    externos que los lean. La fuente de verdad es ahora SQLite.
    """
    from . import queries

    mes = mes or _ahora().strftime("%Y-%m")

    try:
        datos_mes = queries.exportar_json_mes(conn, mes)
        ruta = monthly_json(mes)
        ruta.write_text(json.dumps(datos_mes, ensure_ascii=False, indent=2),
                        encoding="utf-8")
        ruta.chmod(0o640)

        hoy = _ahora().strftime("%Y-%m-%d")
        recientes = [a for a in datos_mes["amenazas_acumuladas"]
                     if str(a.get("fecha_deteccion") or "").startswith(hoy)]
        DAILY_JSON.write_text(json.dumps({
            "timestamp": db.utcnow(),
            "fecha": hoy,
            "fuente": "SQLite (threat_intel.db)",
            "total_amenazas": len(recientes),
            "amenazas": recientes,
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        DAILY_JSON.chmod(0o640)
    except OSError as exc:
        log.warning("no se pudieron escribir las exportaciones JSON",
                    extra={"error": str(exc)})


def registrar_ultima_ejecucion(estado: str, detalle: dict) -> None:
    try:
        LAST_EXECUTION_JSON.write_text(json.dumps({
            "timestamp": db.utcnow(), "status": estado, **detalle,
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        LAST_EXECUTION_JSON.chmod(0o640)
    except OSError as exc:
        log.warning("no se pudo escribir last_execution.json",
                    extra={"error": str(exc)})

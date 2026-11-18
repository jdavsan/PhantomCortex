"""Capa HTTP robusta: descarga, reintentos, parseo de feeds y de JSON.

El recolector anterior llamaba a `feedparser.parse(url)` directamente. Eso
significaba: sin User-Agent (Cloudflare devuelve 403), sin control de
cabeceras, sin reintentos y sin forma de distinguir "el feed esta vacio" de
"nos han bloqueado" o de "esta URL redirige a una pagina HTML". El resultado
era que diez fuentes rotas parecian fuentes sanas sin novedades.

Aqui la descarga la hace SIEMPRE requests (cabeceras y reintentos bajo nuestro
control) y feedparser solo parsea los bytes ya descargados. El campo `error`
de los resultados es un codigo estable y accionable que la GUI muestra al
operador; ver ERRORES y describir_error().
"""
from __future__ import annotations

import html as _html
import json as _json
import ipaddress
import re
import socket
import time
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from typing import Any, Mapping, Optional, Sequence
from urllib.parse import urlparse

import feedparser
import requests

from .config import DEFAULT_SETTINGS
from .logging_setup import get_logger

log = get_logger("http")

# --------------------------------------------------------------------------
# Constantes
# --------------------------------------------------------------------------
USER_AGENT_POR_DEFECTO: str = str(DEFAULT_SETTINGS["http_user_agent"])
TIMEOUT_POR_DEFECTO: int = int(DEFAULT_SETTINGS["http_timeout_s"])
REINTENTOS_POR_DEFECTO: int = int(DEFAULT_SETTINGS["http_retries"])

# Accept coherente con el User-Agent de navegador: algunos CDN comparan ambos.
ACCEPT_FEED = (
    "application/rss+xml, application/atom+xml, application/xml;q=0.9, "
    "application/rdf+xml;q=0.9, text/xml;q=0.9, text/html;q=0.5, */*;q=0.3"
)
ACCEPT_JSON = "application/json, text/plain;q=0.8, */*;q=0.5"
ACCEPT_GENERICO = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

# Solo estos estados se reintentan. Un 403/404 es configuracion mala, no un
# fallo transitorio: reintentarlo solo gasta tiempo y castiga mas la IP.
ESTADOS_REINTENTABLES = frozenset(
    {408, 425, 429, 500, 502, 503, 504, 507, 509, 520, 521, 522, 523, 524, 525, 527, 530}
)
# Errores de red que si son transitorios.
ERRORES_TRANSITORIOS = frozenset({"timeout", "conexion", "dns"})

BACKOFF_BASE_S = 1.0        # 1s, 2s, 4s...
ESPERA_MAXIMA_S = 60.0      # tope para Retry-After abusivos

# Limite de tamano de una respuesta. Verificado el 2026-09-03: un feed malicioso
# que emitia bloques sin fin consumio 4,2 GB de RAM en 107 s antes de que nadie
# lo cortase. Un feed RSS legitimo rara vez supera 2-3 MB; el de MSRC, el mayor
# del catalogo con 4.342 entradas, ronda los 6 MB.
MAX_BYTES_RESPUESTA = 15 * 1024 * 1024
_TROZO_LECTURA = 64 * 1024

# Destinos que el servidor NUNCA debe consultar aunque un administrador los
# introduzca. Verificado el 2026-09-03: "Probar fuente" alcanzaba
# http://127.0.0.1:11434 (la API de Ollama) y la propia interfaz. Es SSRF: un
# administrador comprometido, o un XSS en su sesion, podria usar el servidor
# como puente hacia la red interna.
_REDES_PROHIBIDAS = (
    ipaddress.ip_network("0.0.0.0/8"),        # "esta" red
    ipaddress.ip_network("10.0.0.0/8"),       # privada
    ipaddress.ip_network("100.64.0.0/10"),    # NAT de operador
    ipaddress.ip_network("127.0.0.0/8"),      # loopback
    ipaddress.ip_network("169.254.0.0/16"),   # link-local y metadatos cloud
    ipaddress.ip_network("172.16.0.0/12"),    # privada
    ipaddress.ip_network("192.168.0.0/16"),   # privada
    ipaddress.ip_network("224.0.0.0/4"),      # multicast
    ipaddress.ip_network("240.0.0.0/4"),      # reservada
    ipaddress.ip_network("::1/128"),          # loopback v6
    ipaddress.ip_network("fc00::/7"),         # privada v6
    ipaddress.ip_network("fe80::/10"),        # link-local v6
    ipaddress.ip_network("::ffff:0:0/96"),    # v4 mapeada en v6
)
_HOSTS_PROHIBIDOS = {"localhost", "localhost.localdomain", "metadata",
                     "metadata.google.internal", "instance-data"}


class DestinoProhibido(ValueError):
    """La URL apunta a la red interna, al propio servidor o a un esquema no admitido."""


def validar_destino(url: str) -> str:
    """Comprueba que una URL es un destino externo legitimo antes de consultarla.

    Resuelve el nombre y comprueba TODAS sus direcciones: un nombre publico que
    resuelva a 127.0.0.1 (DNS rebinding) tambien se rechaza. Devuelve el host.
    """
    partes = urlparse(url)
    if partes.scheme not in ("http", "https"):
        raise DestinoProhibido(f"esquema no admitido: {partes.scheme or '(vacio)'}")
    host = (partes.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise DestinoProhibido("URL sin nombre de host")
    if host in _HOSTS_PROHIBIDOS or host.endswith(".localhost") or host.endswith(".internal"):
        raise DestinoProhibido(f"host reservado: {host}")

    try:
        direcciones = {info[4][0] for info in socket.getaddrinfo(host, None)}
    except socket.gaierror as exc:
        raise DestinoProhibido(f"no se pudo resolver {host}: {exc}") from exc

    for direccion in direcciones:
        try:
            ip = ipaddress.ip_address(direccion.split("%")[0])
        except ValueError:
            raise DestinoProhibido(f"direccion no valida: {direccion}") from None
        if any(ip in red for red in _REDES_PROHIBIDAS) or ip.is_reserved or ip.is_unspecified:
            raise DestinoProhibido(f"{host} resuelve a una direccion interna ({ip})")
    return host
MAX_REDIRECCIONES = 5
LIMITE_SNIFF = 2048         # bytes que se miran para detectar HTML disfrazado

#: Codigos de error posibles. Cualquier otro estado HTTP se devuelve como
#: 'http_<codigo>' (p.ej. 'http_500'), asi que la GUI debe tolerar el prefijo.
ERRORES: tuple[str, ...] = (
    "http_403", "http_404", "http_429", "timeout", "dns", "ssl", "conexion",
    "parse", "no_es_feed", "vacio", "url_no_valida", "redirecciones", "clave_api_invalida",
)

_DESCRIPCION_ERROR: dict[str, str] = {
    "destino_prohibido": "destino interno o reservado: el servidor no consulta la red local ni a sí mismo",
    "respuesta_demasiado_grande": "la respuesta supera el límite de 15 MB y se descarta por seguridad",
    "http_403": "El servidor bloquea la petición (403). Suele ser Cloudflare o un feed "
                "retirado: comprueba la URL en un navegador y busca la nueva dirección.",
    "http_404": "La URL no existe (404). El feed se ha movido o se ha retirado: "
                "hay que corregir la URL o desactivar la fuente.",
    "http_429": "Demasiadas peticiones (429). Reduce la frecuencia de consulta o "
                "configura una clave de API para esta fuente.",
    "timeout": "El servidor no respondió dentro del tiempo límite. Si se repite, "
               "aumenta timeout_s o desactiva la fuente.",
    "dns": "No se pudo resolver el dominio. Revisa el nombre de host y el DNS del servidor.",
    "ssl": "Fallo en el certificado TLS. Revisa la URL (¿https correcto?) o el "
           "almacén de certificados del sistema.",
    "conexion": "No se pudo conectar con el servidor (red, cortafuegos o proxy).",
    "parse": "La respuesta llegó pero no se pudo interpretar (XML o JSON mal formado).",
    "no_es_feed": "El servidor devolvió 200 pero el contenido es HTML, no un feed. "
                  "Normalmente indica una redirección a una página de aviso.",
    "vacio": "El servidor respondió con un cuerpo vacío.",
    "url_no_valida": "La URL configurada no es válida (debe empezar por http:// o https://).",
    "redirecciones": "Demasiadas redirecciones seguidas. La URL final no es estable.",
    "clave_api_invalida": "La clave de API configurada no es válida: el servicio responde con "
                          "error al enviarla y funciona sin ella. Corrige la clave en "
                          "config/credentials.env o bórrala para usar el acceso anónimo.",
}


def describir_error(codigo: Optional[str]) -> str:
    """Mensaje accionable en español para un codigo de error. Para la GUI."""
    if not codigo:
        return "Sin errores."
    if codigo in _DESCRIPCION_ERROR:
        return _DESCRIPCION_ERROR[codigo]
    if codigo.startswith("http_"):
        return (f"El servidor respondió con el estado HTTP {codigo[5:]}. "
                "Si persiste, revisa la URL o desactiva la fuente.")
    return f"Error no clasificado: {codigo}"


# --------------------------------------------------------------------------
# Resultados
# --------------------------------------------------------------------------
@dataclass
class FetchResult:
    """Resultado de una descarga. `latency_ms` es del intento que se devuelve."""
    ok: bool
    status: Optional[int]
    content: Optional[bytes]
    error: Optional[str]
    latency_ms: int
    final_url: Optional[str]
    from_cache: bool = False
    # Extras utiles para el diagnostico; no forman parte del contrato minimo.
    content_type: Optional[str] = None
    encoding: Optional[str] = None
    attempts: int = 1

    @property
    def descripcion_error(self) -> str:
        return describir_error(self.error)


@dataclass
class FeedResult:
    """Feed descargado y normalizado. `bozo` = feedparser encontro rarezas."""
    ok: bool
    status: Optional[int]
    entries: list[dict]
    error: Optional[str]
    latency_ms: int
    bozo: bool
    title: Optional[str]
    final_url: Optional[str] = None
    bozo_detail: Optional[str] = None

    @property
    def descripcion_error(self) -> str:
        return describir_error(self.error)


@dataclass
class JsonResult:
    """Respuesta JSON ya decodificada."""
    ok: bool
    status: Optional[int]
    data: Any
    error: Optional[str]
    latency_ms: int
    final_url: Optional[str] = None

    @property
    def descripcion_error(self) -> str:
        return describir_error(self.error)


# --------------------------------------------------------------------------
# Limpieza de texto
# --------------------------------------------------------------------------
_RE_BLOQUE = re.compile(r"<(script|style)\b[^>]*>.*?</\1\s*>", re.I | re.S)
_RE_COMENTARIO = re.compile(r"<!--.*?-->", re.S)
_RE_SALTO = re.compile(r"</\s*(p|div|li|tr|h[1-6]|blockquote)\s*>|<\s*br\s*/?\s*>", re.I)
_RE_ETIQUETA = re.compile(r"<[^<>]{0,4000}?>", re.S)
_RE_ESPACIOS = re.compile(r"[ \t\f\v ]+")
_RE_LINEAS = re.compile(r"\n\s*\n\s*\n+")


def limpiar_html(texto: Optional[str]) -> str:
    """Convierte un fragmento HTML de RSS en texto plano legible.

    Se hace en dos pasadas de etiquetas porque `html.unescape` puede revelar
    marcado que venia escapado (`&lt;script&gt;`): si no se vuelve a limpiar,
    ese texto acaba en el correo o en el informe como HTML crudo.
    """
    if not texto:
        return ""
    t = str(texto)
    t = _RE_COMENTARIO.sub(" ", t)
    t = _RE_BLOQUE.sub(" ", t)
    t = _RE_SALTO.sub("\n", t)
    t = _RE_ETIQUETA.sub(" ", t)
    t = _html.unescape(t)
    t = _RE_ETIQUETA.sub(" ", t)
    t = t.replace("\r\n", "\n").replace("\r", "\n")
    t = _RE_ESPACIOS.sub(" ", t)
    t = "\n".join(linea.strip() for linea in t.split("\n"))
    t = _RE_LINEAS.sub("\n\n", t)
    return t.strip()


# --------------------------------------------------------------------------
# Clasificacion de errores
# --------------------------------------------------------------------------
_PISTAS_DNS = (
    "name or service not known", "nodename nor servname", "temporary failure in name resolution",
    "failed to resolve", "getaddrinfo", "name does not resolve", "no address associated",
)


def clasificar_excepcion(exc: BaseException) -> str:
    """Traduce una excepcion de requests a un codigo de ERRORES."""
    if isinstance(exc, requests.exceptions.SSLError):
        return "ssl"
    if isinstance(exc, (requests.exceptions.Timeout, TimeoutError)):
        return "timeout"
    if isinstance(exc, requests.exceptions.TooManyRedirects):
        return "redirecciones"
    if isinstance(exc, requests.exceptions.MissingSchema):
        return "url_no_valida"
    if isinstance(exc, requests.exceptions.InvalidURL):
        return "url_no_valida"
    if isinstance(exc, requests.exceptions.URLRequired):
        return "url_no_valida"
    texto = f"{exc}".lower()
    if isinstance(exc, requests.exceptions.ConnectionError):
        if any(p in texto for p in _PISTAS_DNS):
            return "dns"
        if "timed out" in texto or "timeout" in texto:
            return "timeout"
        return "conexion"
    if isinstance(exc, requests.exceptions.ContentDecodingError):
        return "parse"
    if isinstance(exc, requests.exceptions.RequestException):
        if any(p in texto for p in _PISTAS_DNS):
            return "dns"
        if "timed out" in texto:
            return "timeout"
        return "conexion"
    return "conexion"


def _error_http(status: int) -> str:
    return f"http_{status}"


def _url_valida(url: Optional[str]) -> bool:
    if not url or not isinstance(url, str):
        return False
    try:
        partes = urlparse(url.strip())
    except ValueError:
        return False
    return partes.scheme in ("http", "https") and bool(partes.netloc)


def _ms(inicio: float) -> int:
    return int((time.perf_counter() - inicio) * 1000)


def _backoff(intento: int) -> float:
    """1s, 2s, 4s, 8s... con tope."""
    return min(BACKOFF_BASE_S * (2 ** intento), ESPERA_MAXIMA_S)


def _retry_after_segundos(resp: requests.Response) -> Optional[float]:
    """Lee la cabecera Retry-After (segundos o fecha HTTP). None si no la hay."""
    valor = resp.headers.get("Retry-After")
    if not valor:
        return None
    valor = valor.strip()
    try:
        return max(0.0, min(float(valor), ESPERA_MAXIMA_S))
    except ValueError:
        pass
    try:
        objetivo = parsedate_to_datetime(valor)
    except (TypeError, ValueError, IndexError):
        return None
    if objetivo is None:
        return None
    try:
        from datetime import datetime, timezone
        ahora = datetime.now(objetivo.tzinfo or timezone.utc)
        return max(0.0, min((objetivo - ahora).total_seconds(), ESPERA_MAXIMA_S))
    except (TypeError, ValueError, OverflowError):
        return None


def _cabeceras(user_agent: Optional[str], accept: str,
               extra: Optional[Mapping[str, str]]) -> dict[str, str]:
    cab = {
        "User-Agent": (user_agent or USER_AGENT_POR_DEFECTO).strip(),
        "Accept": accept,
        "Accept-Language": "en-US,en;q=0.8,es;q=0.7",
        # br/zstd solo si la libreria esta instalada; gzip/deflate siempre lo esta.
        "Accept-Encoding": "gzip, deflate",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }
    if extra:
        for clave, valor in extra.items():
            if valor is None:
                cab.pop(str(clave), None)
            else:
                cab[str(clave)] = str(valor)
    return cab


# --------------------------------------------------------------------------
# Descarga
# --------------------------------------------------------------------------
def _get_con_redirecciones_validadas(sesion, url: str, *, timeout, params=None,
                                     max_saltos: int = MAX_REDIRECCIONES):
    """GET que sigue redirecciones validando el destino de cada salto.

    `allow_redirects=True` de requests seguiria a ciegas un 302 hacia
    http://127.0.0.1:11434 emitido por un servidor externo. Aqui cada salto pasa
    por validar_destino() antes de solicitarse.
    """
    actual = url
    for _ in range(max_saltos + 1):
        resp = sesion.get(actual, timeout=timeout, allow_redirects=False,
                          params=params if actual == url else None, stream=True)
        if resp.status_code not in (301, 302, 303, 307, 308):
            return resp
        destino = resp.headers.get("Location")
        resp.close()
        if not destino:
            return resp
        from urllib.parse import urljoin
        siguiente = urljoin(actual, destino)
        validar_destino(siguiente)                 # lanza DestinoProhibido si procede
        actual = siguiente
    raise requests.TooManyRedirects(f"mas de {max_saltos} redirecciones desde {url}")


def _leer_acotado(resp, limite: int, *, parcial: bool = False) -> tuple[bytes, bool]:
    """Lee el cuerpo por trozos y se detiene al superar `limite`.

    Devuelve (contenido, excedido). Con Content-Length declarado por encima del
    limite ni siquiera empieza a leer... salvo con ``parcial``: entonces se leen
    los primeros bytes hasta el limite y se devuelven (sondeo de conjuntos de
    datos grandes, como el Debian Security Tracker de 72 MB).
    """
    declarado = resp.headers.get("Content-Length")
    try:
        if declarado is not None and int(declarado) > limite and not parcial:
            resp.close()
            return b"", True
    except ValueError:
        pass

    trozos: list[bytes] = []
    total = 0
    try:
        for trozo in resp.iter_content(chunk_size=_TROZO_LECTURA):
            if not trozo:
                continue
            total += len(trozo)
            if total > limite:
                if parcial:
                    trozos.append(trozo[: max(0, limite - (total - len(trozo)))])
                    resp.close()
                    return b"".join(trozos), True
                resp.close()
                return b"", True
            trozos.append(trozo)
    finally:
        resp.close()
    return b"".join(trozos), False


def _descargar(url: str, *, timeout: int, retries: int, user_agent: Optional[str],
               headers: Optional[Mapping[str, str]], params: Optional[Mapping[str, Any]],
               accept: str, limite_bytes: int = MAX_BYTES_RESPUESTA,
               parcial: bool = False, silenciar_http: bool = False) -> FetchResult:
    """Motor comun de fetch/fetch_feed/fetch_json. Una sesion por llamada.

    ``parcial`` lee solo los primeros ``limite_bytes`` y da la respuesta por buena
    aunque el cuerpo sea mayor: sirve para sondear la disponibilidad de un
    conjunto de datos sin descargarlo entero.
    """
    if not _url_valida(url):
        log.error("URL no válida, no se intenta la descarga", extra={"url_pedida": str(url)})
        return FetchResult(False, None, None, "url_no_valida", 0, None)

    url = url.strip()
    intentos = max(1, int(retries) + 1)
    tiempo = max(1, int(timeout))
    sesion = requests.Session()
    sesion.max_redirects = MAX_REDIRECCIONES
    sesion.headers.clear()
    sesion.headers.update(_cabeceras(user_agent, accept, headers))

    ultimo: FetchResult | None = None
    # SSRF (A01:2025): rechazar destinos internos antes de tocar la red.
    try:
        validar_destino(url)
    except DestinoProhibido as exc:
        log.warning("Destino rechazado por politica de red", extra={"url_pedida": url,
                                                                    "motivo": str(exc)})
        return FetchResult(False, None, None, "destino_prohibido", 0, None)

    try:
        for intento in range(intentos):
            es_ultimo = intento == intentos - 1
            inicio = time.perf_counter()
            try:
                # Las redirecciones se siguen A MANO para validar cada salto:
                # un destino externo legitimo podria redirigir a 127.0.0.1.
                resp = _get_con_redirecciones_validadas(
                    sesion, url, timeout=tiempo, params=params)
            except DestinoProhibido as exc:
                log.warning("Redireccion hacia destino prohibido", extra={"url_pedida": url,
                                                                          "motivo": str(exc)})
                return FetchResult(False, None, None, "destino_prohibido", 0, None)
            except Exception as exc:                      # requests.RequestException y afines
                latencia = _ms(inicio)
                tipo = clasificar_excepcion(exc)
                ultimo = FetchResult(False, None, None, tipo, latencia, None,
                                     attempts=intento + 1)
                if tipo in ERRORES_TRANSITORIOS and not es_ultimo:
                    espera = _backoff(intento)
                    log.warning("Fallo de red, se reintenta",
                                extra={"url_pedida": url, "err": tipo,
                                       "intento": intento + 1, "espera_s": espera})
                    time.sleep(espera)
                    continue
                log.warning("Descarga fallida", extra={"url_pedida": url, "err": tipo,
                                                       "intentos": intento + 1,
                                                       "detalle": f"{exc}"[:300]})
                return ultimo

            latencia = _ms(inicio)
            status = resp.status_code
            tipo_contenido = (resp.headers.get("Content-Type") or "").split(";")[0].strip().lower() or None

            if status in ESTADOS_REINTENTABLES and not es_ultimo:
                espera = _retry_after_segundos(resp) if status in (429, 503) else None
                if espera is None:
                    espera = _backoff(intento)
                log.warning("Respuesta reintentable",
                            extra={"url_pedida": url, "status": status,
                                   "intento": intento + 1, "espera_s": round(espera, 2)})
                resp.close()
                time.sleep(espera)
                continue

            if 200 <= status < 300:
                contenido, excedido = _leer_acotado(resp, limite_bytes, parcial=parcial)
                if excedido and not parcial:
                    log.error("Respuesta demasiado grande, se descarta",
                              extra={"url_pedida": url, "limite_mb": MAX_BYTES_RESPUESTA // 2**20})
                    return FetchResult(False, resp.status_code, None,
                                       "respuesta_demasiado_grande", latencia, resp.url)
                res = FetchResult(True, status, contenido, None, latencia,
                                  resp.url, content_type=tipo_contenido,
                                  encoding=resp.encoding, attempts=intento + 1)
                log.debug("Descarga correcta",
                          extra={"url_pedida": url, "status": status, "bytes": len(contenido),
                                 "latency_ms": latencia, "intentos": intento + 1})
                return res

            error = _error_http(status)
            # silenciar_http: un 404 esperado (registro OSV inexistente) no es un aviso
            (log.debug if silenciar_http else log.warning)("Estado HTTP no válido",
                        extra={"url_pedida": url, "status": status, "err": error,
                               "final_url": resp.url, "intentos": intento + 1})
            return FetchResult(False, status, None, error, latencia, resp.url,
                               content_type=tipo_contenido, attempts=intento + 1)
    finally:
        sesion.close()

    # Solo se llega aqui si el ultimo intento fue un estado reintentable.
    if ultimo is None:
        ultimo = FetchResult(False, None, None, "conexion", 0, None, attempts=intentos)
    return ultimo


def fetch_parcial(url: str, *, max_bytes: int = 65536, timeout: int = TIMEOUT_POR_DEFECTO,
                  retries: int = 0, user_agent: Optional[str] = None,
                  headers: Optional[Mapping[str, str]] = None) -> FetchResult:
    """Sondea una URL leyendo solo los primeros ``max_bytes`` (conjuntos de datos
    grandes: JSON de 72 MB, XML de 10 MB). Misma validacion de destino y de
    redirecciones que fetch(); el contenido devuelto puede estar truncado."""
    return _descargar(url, timeout=timeout, retries=retries, user_agent=user_agent,
                      headers=headers, params=None, accept=ACCEPT_GENERICO,
                      limite_bytes=max(1024, int(max_bytes)), parcial=True)


def fetch(url: str, *, timeout: int = TIMEOUT_POR_DEFECTO,
          retries: int = REINTENTOS_POR_DEFECTO, user_agent: Optional[str] = None,
          headers: Optional[Mapping[str, str]] = None) -> FetchResult:
    """Descarga una URL con User-Agent real, redirecciones y reintentos."""
    accept = ACCEPT_GENERICO
    if headers:
        for clave, valor in headers.items():
            if str(clave).lower() == "accept" and valor:
                accept = str(valor)
    return _descargar(url, timeout=timeout, retries=retries, user_agent=user_agent,
                      headers=headers, params=None, accept=accept)


# --------------------------------------------------------------------------
# Feeds
# --------------------------------------------------------------------------
_MARCAS_FEED = ("<rss", "<feed", "<rdf:rdf", "<opml", "<channel")
_MARCAS_HTML = ("<!doctype html", "<html", "<head>", "<body")


def _parece_html(contenido: bytes) -> bool:
    """True si el cuerpo es una pagina HTML y no un feed.

    Es el caso de SUSE: 200 (tras redireccion) con una pagina de aviso. Antes
    se contaba como fuente sana con cero entradas.
    """
    prefijo = contenido[:LIMITE_SNIFF].decode("utf-8", "ignore").lower()
    prefijo = prefijo.lstrip("﻿ \t\r\n")
    posiciones_html = [prefijo.find(m) for m in _MARCAS_HTML]
    posiciones_html = [p for p in posiciones_html if p >= 0]
    if not posiciones_html:
        return False
    posiciones_feed = [prefijo.find(m) for m in _MARCAS_FEED]
    posiciones_feed = [p for p in posiciones_feed if p >= 0]
    if not posiciones_feed:
        return True
    return min(posiciones_html) < min(posiciones_feed)


def _primer_valor(entry: Mapping[str, Any], claves: Sequence[str]) -> Optional[Any]:
    for clave in claves:
        valor = entry.get(clave)
        if valor:
            return valor
    return None


def _enlace_de(entry: Mapping[str, Any], url_fuente: str) -> str:
    enlace = entry.get("link")
    if isinstance(enlace, str) and enlace.strip():
        return enlace.strip()
    for candidato in entry.get("links") or []:
        try:
            rel = candidato.get("rel")
            href = candidato.get("href")
        except AttributeError:
            continue
        if href and rel in (None, "", "alternate"):
            return str(href).strip()
    identificador = entry.get("id") or entry.get("guid") or ""
    if isinstance(identificador, str) and identificador.startswith("http"):
        return identificador.strip()
    return url_fuente


def normalizar_entrada(entry: Mapping[str, Any], url_fuente: str = "") -> dict:
    """Aplana una entrada de feedparser al dict que consume el recolector."""
    titulo = limpiar_html(entry.get("title") or "")
    resumen_bruto = _primer_valor(entry, ("summary", "description", "subtitle"))
    if not resumen_bruto:
        for bloque in entry.get("content") or []:
            try:
                valor = bloque.get("value")
            except AttributeError:
                continue
            if valor:
                resumen_bruto = valor
                break
    enlace = _enlace_de(entry, url_fuente)
    publicado = _primer_valor(entry, ("published", "updated", "created", "date"))
    publicado_parsed = _primer_valor(
        entry, ("published_parsed", "updated_parsed", "created_parsed"))
    identificador = _primer_valor(entry, ("id", "guid")) or enlace or titulo
    return {
        "title": titulo,
        "summary": limpiar_html(resumen_bruto),
        "link": enlace,
        "published": str(publicado) if publicado else None,
        "published_parsed": publicado_parsed,
        "id": str(identificador),
    }


def fetch_feed(url: str, *, timeout: int = TIMEOUT_POR_DEFECTO,
               retries: int = REINTENTOS_POR_DEFECTO,
               user_agent: Optional[str] = None) -> FeedResult:
    """Descarga y parsea un feed RSS/Atom.

    ok=True solo si hubo respuesta valida Y parseo correcto. Cero entradas con
    parseo bueno es ok=True con entries=[]: decidir si eso es un fallo es
    trabajo de health.py, no de esta capa.
    """
    res = _descargar(url, timeout=timeout, retries=retries, user_agent=user_agent,
                     headers=None, params=None, accept=ACCEPT_FEED)
    if not res.ok:
        return FeedResult(False, res.status, [], res.error, res.latency_ms, False, None,
                          final_url=res.final_url)

    contenido = res.content or b""
    if not contenido.strip():
        log.warning("Feed con cuerpo vacío", extra={"url_pedida": url, "status": res.status})
        return FeedResult(False, res.status, [], "vacio", res.latency_ms, False, None,
                          final_url=res.final_url)

    if _parece_html(contenido):
        log.warning("La respuesta es HTML, no un feed",
                    extra={"url_pedida": url, "status": res.status,
                           "final_url": res.final_url, "content_type": res.content_type})
        return FeedResult(False, res.status, [], "no_es_feed", res.latency_ms, False, None,
                          final_url=res.final_url)

    try:
        parsed = feedparser.parse(contenido)
    except Exception as exc:            # feedparser rara vez lanza, pero si lo hace
        log.warning("feedparser no pudo parsear el contenido",
                    extra={"url_pedida": url, "detalle": f"{exc}"[:300]})
        return FeedResult(False, res.status, [], "parse", res.latency_ms, True, None,
                          final_url=res.final_url)

    bozo = bool(parsed.get("bozo", 0))
    detalle_bozo = None
    if bozo:
        excepcion = parsed.get("bozo_exception")
        detalle_bozo = f"{excepcion}"[:300] if excepcion else "desconocido"
    version = str(parsed.get("version") or "")
    entradas = [normalizar_entrada(e, url) for e in (parsed.entries or [])]
    titulo = limpiar_html((parsed.get("feed") or {}).get("title")) or None

    if not entradas and not version:
        # feedparser no reconocio ningun formato de feed: no es un feed.
        log.warning("El contenido no es un feed reconocible",
                    extra={"url_pedida": url, "status": res.status,
                           "content_type": res.content_type, "detalle": detalle_bozo})
        return FeedResult(False, res.status, [], "no_es_feed", res.latency_ms, bozo, titulo,
                          final_url=res.final_url, bozo_detail=detalle_bozo)

    if bozo and not entradas:
        log.warning("Feed mal formado y sin entradas",
                    extra={"url_pedida": url, "status": res.status, "detalle": detalle_bozo})
        return FeedResult(False, res.status, [], "parse", res.latency_ms, True, titulo,
                          final_url=res.final_url, bozo_detail=detalle_bozo)

    log.debug("Feed parseado", extra={"url_pedida": url, "entradas": len(entradas),
                                      "bozo": bozo, "latency_ms": res.latency_ms})
    return FeedResult(True, res.status, entradas, None, res.latency_ms, bozo, titulo,
                      final_url=res.final_url, bozo_detail=detalle_bozo)


# --------------------------------------------------------------------------
# JSON
# --------------------------------------------------------------------------
def _cabecera_api(api_key_header: Any) -> dict[str, str]:
    """Acepta {'apiKey': 'x'} o ('apiKey', 'x'). Nunca se registra su valor."""
    if not api_key_header:
        return {}
    if isinstance(api_key_header, Mapping):
        return {str(k): str(v) for k, v in api_key_header.items() if v is not None}
    if isinstance(api_key_header, (tuple, list)) and len(api_key_header) == 2:
        clave, valor = api_key_header
        return {} if valor is None else {str(clave): str(valor)}
    raise ValueError("api_key_header debe ser un dict {cabecera: valor} o una tupla "
                     "(cabecera, valor)")


def fetch_json(url: str, *, timeout: int = TIMEOUT_POR_DEFECTO,
               retries: int = REINTENTOS_POR_DEFECTO, user_agent: Optional[str] = None,
               params: Optional[Mapping[str, Any]] = None,
               api_key_header: Any = None, silenciar_http: bool = False) -> JsonResult:
    """Descarga una API JSON (KEV, NVD, EPSS, OSV) con la misma politica de reintentos.
    ``silenciar_http`` registra los errores HTTP esperados (404 de OSV) como depuracion."""
    cabeceras = _cabecera_api(api_key_header)
    res = _descargar(url, timeout=timeout, retries=retries, user_agent=user_agent,
                     headers=cabeceras or None, params=params, accept=ACCEPT_JSON,
                     silenciar_http=silenciar_http)
    if not res.ok:
        return JsonResult(False, res.status, None, res.error, res.latency_ms,
                          final_url=res.final_url)

    contenido = res.content or b""
    if not contenido.strip():
        log.warning("Respuesta JSON vacía", extra={"url_pedida": url, "status": res.status})
        return JsonResult(False, res.status, None, "vacio", res.latency_ms,
                          final_url=res.final_url)
    try:
        datos = _json.loads(contenido)
    except (ValueError, UnicodeDecodeError) as exc:
        log.warning("La respuesta no es JSON válido",
                    extra={"url_pedida": url, "status": res.status,
                           "content_type": res.content_type, "detalle": f"{exc}"[:300]})
        return JsonResult(False, res.status, None, "parse", res.latency_ms,
                          final_url=res.final_url)

    log.debug("JSON descargado", extra={"url_pedida": url, "bytes": len(contenido),
                                        "latency_ms": res.latency_ms})
    return JsonResult(True, res.status, datos, None, res.latency_ms, final_url=res.final_url)


def post_json(url: str, cuerpo: Any, *, timeout: int = TIMEOUT_POR_DEFECTO,
              user_agent: Optional[str] = None, max_bytes: int = MAX_BYTES_RESPUESTA) -> JsonResult:
    """POST con cuerpo JSON a una API (OSV querybatch). Misma politica que fetch_json:
    destino validado contra redes internas, sin redirecciones, tamano acotado, sin
    registrar el cuerpo. Un solo intento: quien llama decide si reintenta."""
    if not _url_valida(url):
        return JsonResult(False, None, None, "url_no_valida", 0)
    try:
        validar_destino(url)
    except DestinoProhibido:
        return JsonResult(False, None, None, "destino_prohibido", 0)
    inicio = time.perf_counter()
    try:
        resp = requests.post(url.strip(), json=cuerpo, timeout=max(1, int(timeout)), allow_redirects=False,
                             headers=_cabeceras(user_agent, ACCEPT_JSON, None), stream=True)
    except requests.RequestException as exc:
        return JsonResult(False, None, None, clasificar_excepcion(exc), _ms(inicio))
    try:
        if resp.status_code >= 400 or 300 <= resp.status_code < 400:
            return JsonResult(False, resp.status_code, None, _error_http(resp.status_code), _ms(inicio))
        contenido, excedido = _leer_acotado(resp, max_bytes)
        if excedido:
            return JsonResult(False, resp.status_code, None, "demasiado_grande", _ms(inicio))
        try:
            return JsonResult(True, resp.status_code, _json.loads(contenido or b"{}"), None, _ms(inicio))
        except (ValueError, UnicodeDecodeError):
            return JsonResult(False, resp.status_code, None, "parse", _ms(inicio))
    finally:
        resp.close()

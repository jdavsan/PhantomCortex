"""Registro de fuentes: catalogo por defecto, CRUD y prueba en vivo.

El sistema anterior tenia las 35 fuentes incrustadas en una lista de Python
dentro del recolector: para desactivar una URL muerta habia que editar codigo
en produccion, y diez de ellas llevaban meses devolviendo 403/404 sin que nadie
lo supiera. Aqui las fuentes viven en la tabla `sources`, el CATALOGO es solo
la semilla inicial y `probar()` permite validar una fuente desde la GUI sin
guardar amenazas.

Cada URL del CATALOGO se ha probado en vivo contra el servidor real: las que
quedan con enabled=0 estan confirmadas como rotas y sin sustituto, y el motivo
esta escrito en `notes` para que el operador no vuelva a intentarlo a ciegas.
"""
from __future__ import annotations

import re
import sqlite3
from typing import Any, Iterable, Mapping, Optional, Sequence, Union

from . import db, http
from .logging_setup import get_logger

log = get_logger("sources")

KINDS: tuple[str, ...] = ("rss", "kev_json", "nvd_api", "epss_api", "dataset", "html_colcert")

# 'html_colcert' es el listado HTML de avisos de ColCERT (colcert.gov.co), que no
# ofrece RSS. Lo descarga y analiza collector.descargar_html_colcert() y sus
# entradas siguen el mismo camino que las de un RSS.

# Un 'dataset' es una API de consulta o un conjunto de datos (OSV.dev, Debian
# Security Tracker, FreeBSD VuXML, CVE.org, endoflife.date) que NO genera amenazas
# por si mismo: lo consume el motor de aplicabilidad por activo. Del catalogo solo
# se toma su salud (disponible, latencia, tamano). Para sondearlo se sustituyen
# los marcadores de la URL por un ejemplo fijo y, en OSV, se usa el GET por id.
_EJEMPLOS_SONDEO = {"{cve}": "CVE-2024-3094", "{producto}": "ubuntu", "{paquete}": "curl",
                    "{ecosistema}": "Ubuntu:22.04", "{version}": "7.81.0-1ubuntu1.20"}
_SONDEO_MAX_BYTES = 65536


def url_de_sondeo(url: str) -> str:
    """URL concreta con la que se prueba un 'dataset' (plantillas sustituidas)."""
    destino = str(url or "").strip()
    if "api.osv.dev" in destino:
        return "https://api.osv.dev/v1/vulns/CVE-2024-3094"
    for marcador, ejemplo in _EJEMPLOS_SONDEO.items():
        destino = destino.replace(marcador, ejemplo)
    return destino
CATEGORIAS: tuple[str, ...] = ("government", "vendor", "news", "blog", "database", "exploits")
PRIORIDADES: tuple[str, ...] = ("critical", "high", "medium", "low")

_ORDEN_PRIORIDAD = ("critical", "high", "medium", "low")
_RE_SLUG = re.compile(r"^[a-z0-9][a-z0-9_]{1,63}$")

# Campos que se pueden crear o editar. `id`, `created_at` y `updated_at` no.
CAMPOS_EDITABLES: tuple[str, ...] = (
    "slug", "name", "url", "kind", "category", "priority", "enabled", "timeout_s", "notes",
)

TIMEOUT_MINIMO = 5
TIMEOUT_MAXIMO = 300

# URL de las tres fuentes autoritativas que sustituyen a los RSS retirados.
URL_CISA_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
URL_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
URL_EPSS_API = "https://api.first.org/data/v1/epss"


# --------------------------------------------------------------------------
# CATALOGO
# --------------------------------------------------------------------------
#: Semilla de fuentes. Probada en vivo el 2026-09-02 (ver notes de cada fila).
CATALOGO: list[dict] = [
    # ------------------------------------------------ autoritativas (API/JSON)
    {
        "slug": "cisa_kev", "name": "CISA KEV (explotación confirmada)",
        "url": URL_CISA_KEV, "kind": "kev_json", "category": "government",
        "priority": "critical", "timeout_s": 60, "enabled": 1,
        "notes": "Catálogo de vulnerabilidades explotadas activamente. 1694 entradas en la "
                 "prueba en vivo. Es la única fuente que confirma explotación real: manda "
                 "sobre cualquier heurística de severidad.",
    },
    {
        "slug": "nvd_api", "name": "NVD API 2.0",
        "url": URL_NVD_API, "kind": "nvd_api", "category": "database",
        "priority": "critical", "timeout_s": 45, "enabled": 1,
        "notes": "Sustituye a nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml (404: NIST retiró "
                 "el RSS). Sin clave de API: 5 peticiones cada 30 s; con NIST_NVD_API_KEY: 50.",
    },
    {
        "slug": "epss_api", "name": "EPSS (FIRST) API",
        "url": URL_EPSS_API, "kind": "epss_api", "category": "database",
        "priority": "high", "timeout_s": 30, "enabled": 1,
        "notes": "Probabilidad de explotación a 30 días por CVE. Se usa para ordenar la "
                 "cola de parcheo cuando hay muchas vulnerabilidades con el mismo CVSS.",
    },
    # ------------------------------------------------------------ gobierno/CSIRT
    {
        "slug": "cisa_advisories", "name": "CISA Advisories (todas)",
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml", "kind": "rss",
        "category": "government", "priority": "critical", "timeout_s": 30, "enabled": 1,
        "notes": "30 entradas en la prueba en vivo. El recolector antiguo la daba por muerta "
                 "con 403: era feedparser pidiendo la URL sin User-Agent. Con cabeceras de "
                 "navegador responde 200. Unifica avisos, alertas e ICS.",
    },
    {
        "slug": "cisa_ics_advisories", "name": "CISA ICS Advisories",
        "url": "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml", "kind": "rss",
        "category": "government", "priority": "high", "timeout_s": 30, "enabled": 1,
        "notes": "URL canónica: la antigua cisa.gov/uscert/ics/advisories/advisories.xml "
                 "redirige aquí. Se mantiene aparte de all.xml porque los avisos ICS quedan "
                 "desplazados de la portada cuando hay mucha actividad.",
    },
    {
        "slug": "circl_vulnerability", "name": "CIRCL Vulnerability-Lookup",
        "url": "https://vulnerability.circl.lu/recent/all.atom", "kind": "rss",
        "category": "government", "priority": "high", "timeout_s": 30, "enabled": 1,
        "notes": "CSIRT de Luxemburgo. Agrega CVE, GHSA y PySec recientes.",
    },
    {
        "slug": "csirt_financiero", "name": "CSIRT Financiero (Asobancaria)",
        "url": "https://www.csirtasobancaria.com/rss.xml", "kind": "rss",
        "category": "government", "priority": "high", "timeout_s": 30, "enabled": 1,
        "notes": "CSIRT del sector financiero colombiano (Asobancaria): alertas de malware "
                 "bancario, campañas de fraude y actores que atacan banca y pagos en "
                 "Latinoamérica, en español. Casi nunca traen CVE: se registran como noticias "
                 "correlacionadas con el inventario y no alertan por sí solas. El servidor "
                 "anuncia application/atom+xml pero sirve RSS 2.0 de Plone sin <link>: el "
                 "enlace se toma del <guid>. Prueba en vivo del 2026-09-05: 15 entradas.",
    },
    {
        "slug": "colcert", "name": "ColCERT (Gobierno de Colombia)",
        "url": "https://www.colcert.gov.co/800/w3-propertyvalue-412601.html",
        "kind": "html_colcert", "category": "government", "priority": "high",
        "timeout_s": 45, "enabled": 1,
        "notes": "Grupo de respuesta a emergencias cibernéticas de Colombia (MinTIC). No "
                 "publica RSS (/feed, /rss.xml y /800/rss.xml dan 404), así que se analiza el "
                 "HTML de la sección «Boletines», que lista alertas (AL), advertencias (AD), "
                 "informes (IN) y reportes semanales (RS) con título, fecha y enlace; el "
                 "texto de cada aviso está en PDF, por lo que el resumen es solo el tipo y la "
                 "fecha y el CVE se extrae del título cuando lo lleva. La sección «Alertas de "
                 "Seguridad» del menú es una página fija que enlaza a US-CERT y NVD: no sirve. "
                 "Prueba en vivo del 2026-09-05: 218 entradas, 10 con CVE.",
    },
    # ------------------------------------------------------- vendors de sistema
    {
        "slug": "debian_security", "name": "Debian Security Advisories (DSA)",
        "url": "https://www.debian.org/security/dsa", "kind": "rss",
        "category": "vendor", "priority": "high", "timeout_s": 30, "enabled": 1,
        "notes": "Esta URL sirve RDF con Content-Type application/rss+xml (30 entradas). "
                 "dsa.en.rdf y dsa-long.en.rdf devuelven 404: no cambiarla.",
    },
    {
        "slug": "ubuntu_security", "name": "Ubuntu Security Notices",
        "url": "https://ubuntu.com/security/notices/rss.xml", "kind": "rss",
        "category": "vendor", "priority": "high", "timeout_s": 30, "enabled": 1,
        "notes": "USN oficiales. 10 entradas por página.",
    },
    {
        "slug": "opensuse_security", "name": "openSUSE Security Announce",
        "url": "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/feed/",
        "kind": "rss", "category": "vendor", "priority": "high", "timeout_s": 30, "enabled": 1,
        "notes": "Sustituto verificado del feed de SUSE: suse.com/support/update/announcement/"
                 "suse-security.html/rss redirige a scc.suse.com y termina en 404. Aquí llegan "
                 "los mismos openSUSE-SU/SUSE-SU (30 entradas en la prueba).",
    },
    {
        "slug": "redhat_security", "name": "Red Hat Security",
        "url": "https://www.redhat.com/en/rss/blog/channel/security", "kind": "rss",
        "category": "vendor", "priority": "medium", "timeout_s": 30, "enabled": 1,
        "notes": "Sustituye a access.redhat.com/blogs/product-security/rss.xml (404).",
    },
    {
        "slug": "cisco_psirt", "name": "Cisco PSIRT Advisories",
        "url": "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
        "kind": "rss", "category": "vendor", "priority": "high", "timeout_s": 30, "enabled": 1,
        "notes": "URL final tras la redirección de tools.cisco.com (50 entradas).",
    },
    {
        "slug": "cisco_talos", "name": "Cisco Talos Intelligence",
        "url": "https://blog.talosintelligence.com/rss/", "kind": "rss",
        "category": "vendor", "priority": "medium", "timeout_s": 30, "enabled": 1,
        "notes": "Análisis de campañas y vulnerabilidades descubiertas por Talos.",
    },
    {
        "slug": "msrc_update_guide", "name": "Microsoft MSRC Update Guide",
        "url": "https://api.msrc.microsoft.com/update-guide/rss", "kind": "rss",
        "category": "vendor", "priority": "critical", "timeout_s": 60, "enabled": 1,
        "notes": "Unas 4300 entradas por petición, casi todas con CVE en el título. Es la "
                 "fuente principal para Windows, SQL Server y Active Directory. Timeout alto "
                 "a propósito: el XML pesa varios MB.",
    },
    {
        "slug": "chrome_releases", "name": "Google Chrome Releases",
        "url": "https://chromereleases.googleblog.com/atom.xml", "kind": "rss",
        "category": "vendor", "priority": "medium", "timeout_s": 30, "enabled": 1,
        "notes": "Actualizaciones de seguridad de Chrome (y por extensión de Edge/Brave, que "
                 "comparten Chromium). El inventario incluye los tres.",
    },
    {
        "slug": "postgresql_news", "name": "PostgreSQL News",
        "url": "https://www.postgresql.org/news.rss", "kind": "rss",
        "category": "vendor", "priority": "low", "timeout_s": 30, "enabled": 1,
        "notes": "Anuncios de versiones con correcciones de seguridad. Poco volumen (10).",
    },
    {
        "slug": "bitdefender_labs", "name": "Bitdefender Labs",
        "url": "https://www.bitdefender.com/blog/api/rss/labs/", "kind": "rss",
        "category": "vendor", "priority": "low", "timeout_s": 30, "enabled": 1,
        "notes": "Responde 308 hacia /nuxt/api/en-us/rss/labs/; se sigue la redirección y "
                 "devuelve 15 entradas. Se guarda la URL pública porque la de nuxt cambia.",
    },
    # --------------------------------------------------- vulnerabilidades/exploits
    {
        "slug": "zdi_published", "name": "Zero Day Initiative (avisos publicados)",
        "url": "https://www.zerodayinitiative.com/rss/published/", "kind": "rss",
        "category": "exploits", "priority": "high", "timeout_s": 30, "enabled": 1,
        "notes": "200 avisos con detalle técnico y CVE. Añadida: es la mejor fuente de "
                 "vulnerabilidades de producto que no pasan por CISA.",
    },
    {
        "slug": "exploit_db", "name": "Exploit-DB",
        "url": "https://www.exploit-db.com/rss.xml", "kind": "rss",
        "category": "exploits", "priority": "low", "timeout_s": 30, "enabled": 1,
        "notes": "Funciona (50 entradas), pero la mayoría son PoC sin CVE y sin relación con "
                 "el inventario. Prioridad baja para que no infle el informe mensual.",
    },
    {
        "slug": "sans_isc", "name": "SANS Internet Storm Center",
        "url": "https://isc.sans.edu/rssfeed_full.xml", "kind": "rss",
        "category": "news", "priority": "medium", "timeout_s": 30, "enabled": 1,
        "notes": "Diario de incidentes y explotación observada en la práctica.",
    },
    {
        "slug": "project_zero", "name": "Google Project Zero",
        "url": "https://googleprojectzero.blogspot.com/feeds/posts/default", "kind": "rss",
        "category": "blog", "priority": "medium", "timeout_s": 30, "enabled": 1,
        "notes": "Poco volumen y muy técnico; útil para 0-day de alto impacto. OJO: publica "
                 "cada varias semanas (en la prueba del 2026-09-02 la entrada más reciente era "
                 "del 2026-05-13). Devuelve 10 entradas válidas, así que health.py la ve sana, "
                 "pero es normal que no aporte nada dentro de la ventana de collect_lookback_days.",
    },
    # ------------------------------------------------------------------- medios
    {
        "slug": "the_hacker_news", "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews", "kind": "rss",
        "category": "news", "priority": "high", "timeout_s": 30, "enabled": 1,
        "notes": "50 entradas por petición.",
    },
    {
        "slug": "bleeping_computer", "name": "Bleeping Computer",
        "url": "https://www.bleepingcomputer.com/feed/", "kind": "rss",
        "category": "news", "priority": "high", "timeout_s": 30, "enabled": 1,
        "notes": "Feed general. El feed por etiqueta /feed/tag/vulnerability/ del catálogo "
                 "antiguo da 404: este lo cubre.",
    },
    {
        "slug": "cybersecurity_news", "name": "Cyber Security News",
        "url": "https://cybersecuritynews.com/feed/", "kind": "rss",
        "category": "news", "priority": "medium", "timeout_s": 30, "enabled": 1, "notes": None,
    },
    {
        "slug": "security_week", "name": "SecurityWeek",
        "url": "https://www.securityweek.com/feed/", "kind": "rss",
        "category": "news", "priority": "medium", "timeout_s": 30, "enabled": 1, "notes": None,
    },
    {
        "slug": "dark_reading", "name": "Dark Reading",
        "url": "https://www.darkreading.com/rss.xml", "kind": "rss",
        "category": "news", "priority": "medium", "timeout_s": 30, "enabled": 1, "notes": None,
    },
    {
        "slug": "cyberscoop", "name": "CyberScoop",
        "url": "https://cyberscoop.com/feed/", "kind": "rss",
        "category": "news", "priority": "low", "timeout_s": 30, "enabled": 1, "notes": None,
    },
    {
        "slug": "infosecurity_magazine", "name": "Infosecurity Magazine",
        "url": "https://www.infosecurity-magazine.com/rss/news/", "kind": "rss",
        "category": "news", "priority": "medium", "timeout_s": 30, "enabled": 1,
        "notes": "250 entradas por petición (unos dos meses de histórico).",
    },
    {
        "slug": "krebs_on_security", "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com/feed/", "kind": "rss",
        "category": "news", "priority": "low", "timeout_s": 30, "enabled": 1, "notes": None,
    },
    {
        "slug": "ars_technica_security", "name": "Ars Technica Security",
        "url": "https://arstechnica.com/security/feed/", "kind": "rss",
        "category": "news", "priority": "low", "timeout_s": 30, "enabled": 1,
        "notes": "Sustituye a feeds.arstechnica.com/arstechnica/security (404). Verificada: "
                 "20 entradas.",
    },
    {
        "slug": "the_register_security", "name": "The Register Security",
        "url": "https://www.theregister.com/security/headlines.atom", "kind": "rss",
        "category": "news", "priority": "low", "timeout_s": 30, "enabled": 1,
        "notes": "Añadida: 50 entradas, cobertura rápida de vulnerabilidades explotadas.",
    },
    {
        "slug": "help_net_security", "name": "Help Net Security",
        "url": "https://www.helpnetsecurity.com/feed/", "kind": "rss",
        "category": "news", "priority": "low", "timeout_s": 30, "enabled": 1,
        "notes": "Añadida como sustituto de los medios caídos (ZDNet, Threatpost).",
    },
    {
        "slug": "hispasec_unaaldia", "name": "Hispasec - Una al día",
        "url": "https://unaaldia.hispasec.com/feed", "kind": "rss",
        "category": "news", "priority": "medium", "timeout_s": 30, "enabled": 1,
        "notes": "Añadida: fuente en español, no necesita traducción.",
    },
    # -------------------------------------------------------------------- blogs
    {
        "slug": "securelist_en", "name": "Kaspersky Securelist (EN)",
        "url": "https://securelist.com/feed/", "kind": "rss",
        "category": "blog", "priority": "medium", "timeout_s": 30, "enabled": 1,
        "notes": "Sustituye al feed en español securelist.lat, cuyo dominio ya no resuelve.",
    },
    {
        "slug": "segu_info", "name": "Segu-Info",
        "url": "https://blog.segu-info.com.ar/feeds/posts/default", "kind": "rss",
        "category": "blog", "priority": "medium", "timeout_s": 30, "enabled": 1,
        "notes": "Fuente en español (25 entradas).",
    },
    {
        "slug": "rapid7_blog", "name": "Rapid7 Blog",
        "url": "https://blog.rapid7.com/rss/", "kind": "rss",
        "category": "blog", "priority": "medium", "timeout_s": 30, "enabled": 1,
        "notes": "Redirige a rapid7.com/rss.xml; se sigue la redirección.",
    },
    {
        "slug": "malwarebytes_labs", "name": "Malwarebytes Labs",
        "url": "https://www.malwarebytes.com/blog/feed", "kind": "rss",
        "category": "blog", "priority": "low", "timeout_s": 30, "enabled": 1, "notes": None,
    },
    {
        "slug": "gbhackers", "name": "GBHackers",
        "url": "https://gbhackers.com/feed/", "kind": "rss",
        "category": "blog", "priority": "low", "timeout_s": 30, "enabled": 1, "notes": None,
    },
    {
        "slug": "schneier_on_security", "name": "Schneier on Security",
        "url": "https://www.schneier.com/feed/atom/", "kind": "rss",
        "category": "blog", "priority": "low", "timeout_s": 30, "enabled": 1, "notes": None,
    },
    {
        "slug": "troy_hunt", "name": "Troy Hunt",
        "url": "https://www.troyhunt.com/rss/", "kind": "rss",
        "category": "blog", "priority": "low", "timeout_s": 30, "enabled": 1, "notes": None,
    },
    # ------------------------------------- rotas y sin sustituto: enabled = 0
    {
        "slug": "zdnet_security", "name": "ZDNet Security",
        "url": "https://www.zdnet.com/topic/security/rss.xml", "kind": "rss",
        "category": "news", "priority": "low", "timeout_s": 30, "enabled": 0,
        "notes": "DESACTIVADA (probado 2026-09-02): 404. También dan 404 /news/rss.xml y "
                 "/rss.xml, así que ZDNet ya no publica RSS. Sin sustituto: se cubre con "
                 "help_net_security y the_register_security.",
    },
    {
        "slug": "threatpost", "name": "Threatpost",
        "url": "https://threatpost.com/feed/", "kind": "rss",
        "category": "news", "priority": "low", "timeout_s": 30, "enabled": 0,
        "notes": "DESACTIVADA (probado 2026-09-02): responde 200 con 10 entradas, pero la más "
                 "reciente es de agosto de 2022. El sitio cerró y solo sirve archivo; el "
                 "recolector antiguo la contaba como fuente sana.",
    },
    {
        "slug": "naked_security", "name": "Naked Security (Sophos)",
        "url": "https://nakedsecurity.sophos.com/feed/", "kind": "rss",
        "category": "blog", "priority": "low", "timeout_s": 30, "enabled": 0,
        "notes": "DESACTIVADA (probado 2026-09-02): agota el tiempo de espera. Sophos migró a "
                 "news.sophos.com/en-us/feed/, que también agota el tiempo desde este "
                 "servidor, así que no hay sustituto verificado.",
    },
    {
        "slug": "securelist_es", "name": "Kaspersky Securelist (ES)",
        "url": "https://securelist.lat/feed/", "kind": "rss",
        "category": "blog", "priority": "low", "timeout_s": 30, "enabled": 0,
        "notes": "DESACTIVADA (probado 2026-09-02): el dominio securelist.lat no resuelve por "
                 "DNS. Sustituida por securelist_en (inglés, se traduce en el pipeline).",
    },
]

CATALOGO_POR_SLUG: dict[str, dict] = {f["slug"]: f for f in CATALOGO}


# --------------------------------------------------------------------------
# Validacion
# --------------------------------------------------------------------------
def _texto(valor: Any) -> Optional[str]:
    if valor is None:
        return None
    texto = str(valor).strip()
    return texto or None


def _entero_bool(valor: Any) -> int:
    if isinstance(valor, str):
        return 1 if valor.strip().lower() in {"1", "true", "si", "sí", "yes", "on"} else 0
    return 1 if bool(valor) else 0


def _validar(campos: Mapping[str, Any], *, para_crear: bool) -> dict[str, Any]:
    """Normaliza y valida los campos de una fuente. Lanza ValueError si algo no cuadra.

    `slug` y los campos de vocabulario cerrado (kind, category, priority) se pasan
    a minusculas antes de validarlos: asi el formulario de la GUI no rechaza un
    alta por una mayuscula, y no se pueden crear dos fuentes que solo difieran en
    el caso. Lo que no se normaliza es el resto: un slug con espacios, acentos o
    simbolos se rechaza en lugar de "arreglarlo" por su cuenta.
    """
    desconocidos = sorted(set(campos) - set(CAMPOS_EDITABLES))
    if desconocidos:
        raise ValueError(f"Campos no editables o inexistentes: {', '.join(desconocidos)}")

    datos: dict[str, Any] = {}

    if "slug" in campos:
        slug = (_texto(campos["slug"]) or "").lower()
        if not _RE_SLUG.match(slug):
            raise ValueError(
                f"slug no válido: {campos['slug']!r}. Solo minúsculas, dígitos y guion bajo, "
                "entre 2 y 64 caracteres.")
        datos["slug"] = slug
    if "name" in campos:
        nombre = _texto(campos["name"])
        if not nombre:
            raise ValueError("name no puede estar vacío")
        datos["name"] = nombre
    if "url" in campos:
        url = _texto(campos["url"])
        if not http._url_valida(url):
            raise ValueError(f"url no válida: {campos['url']!r}. Debe empezar por http:// o https://")
        datos["url"] = url
    if "kind" in campos:
        kind = (_texto(campos["kind"]) or "").lower()
        if kind not in KINDS:
            raise ValueError(f"kind no válido: {campos['kind']!r}. Valores: {', '.join(KINDS)}")
        datos["kind"] = kind
    if "category" in campos:
        categoria = (_texto(campos["category"]) or "").lower()
        if categoria not in CATEGORIAS:
            raise ValueError(
                f"category no válida: {campos['category']!r}. Valores: {', '.join(CATEGORIAS)}")
        datos["category"] = categoria
    if "priority" in campos:
        prioridad = (_texto(campos["priority"]) or "").lower()
        if prioridad not in PRIORIDADES:
            raise ValueError(
                f"priority no válida: {campos['priority']!r}. Valores: {', '.join(PRIORIDADES)}")
        datos["priority"] = prioridad
    if "enabled" in campos:
        datos["enabled"] = _entero_bool(campos["enabled"])
    if "timeout_s" in campos:
        try:
            timeout = int(campos["timeout_s"])
        except (TypeError, ValueError) as exc:
            raise ValueError(f"timeout_s no es un número: {campos['timeout_s']!r}") from exc
        if not TIMEOUT_MINIMO <= timeout <= TIMEOUT_MAXIMO:
            raise ValueError(
                f"timeout_s fuera de rango ({TIMEOUT_MINIMO}-{TIMEOUT_MAXIMO}): {timeout}")
        datos["timeout_s"] = timeout
    if "notes" in campos:
        datos["notes"] = _texto(campos["notes"])

    if para_crear:
        for obligatorio in ("slug", "name", "url"):
            if not datos.get(obligatorio):
                raise ValueError(f"Falta el campo obligatorio: {obligatorio}")
        datos.setdefault("kind", "rss")
        datos.setdefault("category", "news")
        datos.setdefault("priority", "medium")
        datos.setdefault("enabled", 1)
        datos.setdefault("timeout_s", 30)
        datos.setdefault("notes", None)
    return datos


def _fila_a_dict(fila: Optional[sqlite3.Row]) -> Optional[dict]:
    """`enabled` se expone como bool: la GUI y las plantillas trabajan con bools."""
    if fila is None:
        return None
    datos = dict(fila)
    if "enabled" in datos:
        datos["enabled"] = bool(datos["enabled"])
    return datos


# --------------------------------------------------------------------------
# Semilla
# --------------------------------------------------------------------------
def seed(conn: sqlite3.Connection, *, solo_nuevas: bool = True) -> dict:
    """Inserta el CATALOGO en `sources`. Idempotente.

    Con solo_nuevas=False refresca name/url/kind/category/priority/timeout_s/notes
    de las que ya existen, pero NUNCA toca `enabled`: ese interruptor es del
    operador (y de health.py), y un reseed no debe volver a encender una fuente
    que alguien apagó a mano.
    """
    resumen = {"creadas": 0, "actualizadas": 0, "omitidas": 0}
    refrescables = ("name", "url", "kind", "category", "priority", "timeout_s", "notes")

    for entrada in CATALOGO:
        datos = _validar(entrada, para_crear=True)
        fila = conn.execute(
            "SELECT * FROM sources WHERE slug=?", (datos["slug"],)).fetchone()

        if fila is None:
            ahora = db.utcnow()
            conn.execute(
                "INSERT INTO sources(slug, name, url, kind, category, priority, enabled, "
                "timeout_s, notes, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (datos["slug"], datos["name"], datos["url"], datos["kind"], datos["category"],
                 datos["priority"], datos["enabled"], datos["timeout_s"], datos["notes"],
                 ahora, ahora),
            )
            resumen["creadas"] += 1
            continue

        if solo_nuevas:
            resumen["omitidas"] += 1
            continue

        cambios = {c: datos[c] for c in refrescables if fila[c] != datos[c]}
        if not cambios:
            resumen["omitidas"] += 1
            continue
        asignaciones = ", ".join(f"{c}=?" for c in cambios)
        conn.execute(
            f"UPDATE sources SET {asignaciones}, updated_at=? WHERE id=?",
            (*cambios.values(), db.utcnow(), fila["id"]),
        )
        resumen["actualizadas"] += 1
        log.info("Fuente actualizada desde el catálogo",
                 extra={"slug": datos["slug"], "cambios": ",".join(sorted(cambios))})

    log.info("Semilla de fuentes aplicada", extra=dict(resumen, catalogo=len(CATALOGO)))
    return resumen


# --------------------------------------------------------------------------
# CRUD
# --------------------------------------------------------------------------
def listar(conn: sqlite3.Connection, *, solo_activas: bool = False) -> list[dict]:
    """Fuentes ordenadas por prioridad y nombre. solo_activas => enabled=1."""
    orden = " ".join(
        f"WHEN '{p}' THEN {i}" for i, p in enumerate(_ORDEN_PRIORIDAD))
    sql = ("SELECT * FROM sources "
           + ("WHERE enabled=1 " if solo_activas else "")
           + f"ORDER BY CASE priority {orden} ELSE 9 END, name COLLATE NOCASE")
    return [_fila_a_dict(f) for f in conn.execute(sql)]


def obtener(conn: sqlite3.Connection, slug: str) -> Optional[dict]:
    """Devuelve la fuente por slug, o None si no existe."""
    fila = conn.execute(
        "SELECT * FROM sources WHERE slug=?", ((_texto(slug) or "").lower(),)).fetchone()
    return _fila_a_dict(fila)


def obtener_por_id(conn: sqlite3.Connection, source_id: int) -> Optional[dict]:
    fila = conn.execute("SELECT * FROM sources WHERE id=?", (int(source_id),)).fetchone()
    return _fila_a_dict(fila)


def crear(conn: sqlite3.Connection, **campos: Any) -> int:
    """Crea una fuente y devuelve su id. `usuario` es opcional, solo para auditar."""
    usuario = campos.pop("usuario", None) or "sistema"
    datos = _validar(campos, para_crear=True)
    ahora = db.utcnow()
    try:
        cursor = conn.execute(
            "INSERT INTO sources(slug, name, url, kind, category, priority, enabled, "
            "timeout_s, notes, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (datos["slug"], datos["name"], datos["url"], datos["kind"], datos["category"],
             datos["priority"], datos["enabled"], datos["timeout_s"], datos["notes"],
             ahora, ahora),
        )
    except sqlite3.IntegrityError as exc:
        raise ValueError(f"Ya existe una fuente con el slug {datos['slug']!r}") from exc
    source_id = int(cursor.lastrowid)
    db.audit(conn, usuario, "source.create", entity="sources", entity_id=source_id,
             detail=f"{datos['slug']} {datos['url']}")
    log.info("Fuente creada", extra={"slug": datos["slug"], "source_id": source_id})
    return source_id


def actualizar(conn: sqlite3.Connection, source_id: int, **campos: Any) -> None:
    """Actualiza los campos indicados. Lanza ValueError si la fuente no existe."""
    usuario = campos.pop("usuario", None) or "sistema"
    if not campos:
        raise ValueError("No se ha indicado ningún campo que actualizar")
    datos = _validar(campos, para_crear=False)
    fila = conn.execute("SELECT id FROM sources WHERE id=?", (int(source_id),)).fetchone()
    if fila is None:
        raise ValueError(f"No existe ninguna fuente con id={source_id}")
    asignaciones = ", ".join(f"{c}=?" for c in datos)
    try:
        conn.execute(
            f"UPDATE sources SET {asignaciones}, updated_at=? WHERE id=?",
            (*datos.values(), db.utcnow(), int(source_id)),
        )
    except sqlite3.IntegrityError as exc:
        raise ValueError("El slug indicado ya lo usa otra fuente") from exc
    db.audit(conn, usuario, "source.update", entity="sources", entity_id=source_id,
             detail=", ".join(f"{c}={datos[c]!r}" for c in sorted(datos)))
    log.info("Fuente actualizada", extra={"source_id": int(source_id),
                                          "campos": ",".join(sorted(datos))})


def borrar(conn: sqlite3.Connection, source_id: int, *, usuario: str = "sistema") -> None:
    """Borra una fuente.

    ON DELETE CASCADE se lleva su historial de salud y sus filas de
    threat_sources, es decir, la trazabilidad de qué fuente reportó cada
    amenaza. Para dejar de consultar una fuente use actualizar(enabled=0).
    """
    fila = conn.execute(
        "SELECT slug FROM sources WHERE id=?", (int(source_id),)).fetchone()
    if fila is None:
        raise ValueError(f"No existe ninguna fuente con id={source_id}")
    conn.execute("DELETE FROM sources WHERE id=?", (int(source_id),))
    db.audit(conn, usuario, "source.delete", entity="sources", entity_id=source_id,
             detail=fila["slug"])
    log.warning("Fuente borrada", extra={"source_id": int(source_id), "slug": fila["slug"]})


# --------------------------------------------------------------------------
# Salud
# --------------------------------------------------------------------------
def registrar_salud(conn: sqlite3.Connection, source_id: int, *, ok: bool,
                    http_status: Optional[int], entries: int, accepted: int,
                    latency_ms: Optional[int], error: Optional[str]) -> None:
    """Anota el resultado de una consulta en source_health (histórico por fuente)."""
    conn.execute(
        "INSERT INTO source_health(source_id, checked_at, ok, http_status, entries, "
        "accepted, latency_ms, error) VALUES(?,?,?,?,?,?,?,?)",
        (int(source_id), db.utcnow(), 1 if ok else 0,
         None if http_status is None else int(http_status),
         int(entries or 0), int(accepted or 0),
         None if latency_ms is None else int(latency_ms),
         _texto(error)),
    )


# --------------------------------------------------------------------------
# Prueba en vivo
# --------------------------------------------------------------------------
def _ajustes_http(cfg: Any, timeout_s: Optional[int]) -> dict:
    """Saca user_agent/retries/timeout de la Config, con respaldo en http.py."""
    if cfg is not None and hasattr(cfg, "get"):
        agente = cfg.get("http_user_agent") or http.USER_AGENT_POR_DEFECTO
        reintentos = cfg.get("http_retries", http.REINTENTOS_POR_DEFECTO)
        por_defecto = cfg.get("http_timeout_s", http.TIMEOUT_POR_DEFECTO)
    else:
        agente = http.USER_AGENT_POR_DEFECTO
        reintentos = http.REINTENTOS_POR_DEFECTO
        por_defecto = http.TIMEOUT_POR_DEFECTO
    return {
        "user_agent": str(agente),
        "retries": int(reintentos),
        "timeout": int(timeout_s or por_defecto),
    }


def _muestra_json(datos: Any, clave: str, formato) -> tuple[int, list[str], Optional[str]]:
    """Cuenta elementos y saca 3 ejemplos de una respuesta JSON de lista."""
    if not isinstance(datos, Mapping) or not isinstance(datos.get(clave), list):
        return 0, [], "parse"
    elementos = datos[clave]
    muestra = []
    for elemento in elementos[:3]:
        try:
            muestra.append(formato(elemento)[:200])
        except (KeyError, TypeError, ValueError, AttributeError):
            muestra.append("(elemento con formato inesperado)")
    return len(elementos), muestra, None


def probar_url(url: str, *, kind: str = "rss", timeout_s: Optional[int] = None,
               cfg: Any = None, nvd_api_key: Optional[str] = None) -> dict:
    """Prueba una URL en vivo sin tocar la base de datos.

    La usa la GUI tanto en el botón "Probar fuente" como en el formulario de
    alta, antes de que la fuente exista.
    """
    kind = (kind or "rss").lower()
    if kind not in KINDS:
        raise ValueError(f"kind no válido: {kind!r}. Valores: {', '.join(KINDS)}")
    ajustes = _ajustes_http(cfg, timeout_s)
    clave_nvd = nvd_api_key or getattr(cfg, "nvd_api_key", None)

    if kind in ("rss", "html_colcert"):
        if kind == "rss":
            res = http.fetch_feed(url, **ajustes)
        else:
            # Importacion diferida: collector importa este modulo al cargarse.
            from . import collector
            res = collector.descargar_html_colcert(url, **ajustes)
        muestra = [e["title"][:200] for e in res.entries[:3] if e.get("title")]
        return {"ok": bool(res.ok), "status": res.status, "entries": len(res.entries),
                "error": res.error, "latency_ms": res.latency_ms, "muestra": muestra}

    if kind == "dataset":
        destino = url_de_sondeo(url)
        res = http.fetch_parcial(destino, max_bytes=_SONDEO_MAX_BYTES,
                                 timeout=ajustes.get("timeout", 30),
                                 user_agent=ajustes.get("user_agent"))
        if not res.ok or not res.content:
            return {"ok": False, "status": res.status, "entries": 0,
                    "error": res.error or "respuesta_vacia", "latency_ms": res.latency_ms,
                    "muestra": []}
        cabecera = res.content[:160].decode("utf-8", errors="replace").replace("\n", " ").strip()
        tipo = res.content_type or "desconocido"
        return {"ok": True, "status": res.status, "entries": 1, "error": None,
                "latency_ms": res.latency_ms,
                "muestra": [f"{tipo} · {cabecera[:120]}" if cabecera else tipo]}

    if kind == "kev_json":
        res = http.fetch_json(url, **ajustes)
        clave, formato = "vulnerabilities", (
            lambda v: f"{v.get('cveID', 'sin CVE')}: {v.get('vulnerabilityName', '')}".strip())
    elif kind == "nvd_api":
        cabecera = {"apiKey": clave_nvd} if clave_nvd else None
        res = http.fetch_json(url, params={"resultsPerPage": 3}, api_key_header=cabecera,
                              **ajustes)
        if clave_nvd and not res.ok and res.status == 404:
            # NVD responde 404 (no 401) a una clave de API invalida, asi que un
            # 404 pelado haria buscar el fallo en la URL. Se repite la peticion
            # sin clave para señalar al culpable de verdad.
            anonimo = http.fetch_json(url, params={"resultsPerPage": 3}, **ajustes)
            if anonimo.ok:
                log.warning(
                    "La clave de API de NVD no es válida: NVD devuelve 404 con ella y "
                    "200 sin ella. Corrija NIST_NVD_API_KEY en config/credentials.env "
                    "o bórrela para usar el acceso anónimo (5 peticiones cada 30 s).",
                    extra={"url_pedida": url, "status_con_clave": res.status})
                # La fuente SI funciona: el modulo de enriquecimiento ignora una
                # clave mal formada y consulta de forma anonima. Marcarla como
                # caida haria que el aviso de fuentes caidas se disparase por algo
                # que no impide la recoleccion. Se devuelve correcta, con aviso.
                res = anonimo
        clave, formato = "vulnerabilities", (
            lambda v: f"{v['cve']['id']}: "
                      f"{(v['cve'].get('descriptions') or [{}])[0].get('value', '')}".strip())
    else:  # epss_api
        res = http.fetch_json(url, params={"limit": 3}, **ajustes)
        clave, formato = "data", (
            lambda v: f"{v.get('cve', 'sin CVE')}: EPSS {v.get('epss', '?')}")

    if not res.ok:
        return {"ok": False, "status": res.status, "entries": 0, "error": res.error,
                "latency_ms": res.latency_ms, "muestra": []}

    total, muestra, error = _muestra_json(res.data, clave, formato)
    if error:
        log.warning("Respuesta JSON con formato inesperado",
                    extra={"url_pedida": url, "kind": kind, "clave_esperada": clave})
        return {"ok": False, "status": res.status, "entries": 0, "error": error,
                "latency_ms": res.latency_ms, "muestra": []}
    return {"ok": True, "status": res.status, "entries": total, "error": None,
            "latency_ms": res.latency_ms, "muestra": muestra}


def probar(conn: sqlite3.Connection, source_id_o_slug: Union[int, str],
           cfg: Any = None) -> dict:
    """Prueba en vivo una fuente ya registrada. NO guarda amenazas ni salud.

    No escribe en source_health a propósito: una prueba manual repetida desde la
    GUI falsearía la racha de fallos que usa health.py para avisar por correo.
    """
    fuente = _resolver(conn, source_id_o_slug)
    resultado = probar_url(fuente["url"], kind=fuente["kind"],
                           timeout_s=fuente["timeout_s"], cfg=cfg)
    log.info("Prueba de fuente",
             extra={"slug": fuente["slug"], "ok": resultado["ok"],
                    "status": resultado["status"], "entradas": resultado["entries"],
                    "err": resultado["error"], "latency_ms": resultado["latency_ms"]})
    return resultado


def _resolver(conn: sqlite3.Connection, source_id_o_slug: Union[int, str]) -> dict:
    """Acepta id numerico o slug. Lanza ValueError si no existe."""
    fuente = None
    if isinstance(source_id_o_slug, bool):
        raise ValueError(f"Identificador de fuente no válido: {source_id_o_slug!r}")
    if isinstance(source_id_o_slug, int):
        fuente = obtener_por_id(conn, source_id_o_slug)
    else:
        texto = _texto(source_id_o_slug) or ""
        if texto.isdigit():
            fuente = obtener_por_id(conn, int(texto))
        if fuente is None:
            fuente = obtener(conn, texto)
    if fuente is None:
        raise ValueError(f"No existe la fuente {source_id_o_slug!r}")
    return fuente

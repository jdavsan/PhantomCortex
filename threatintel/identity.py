"""Identidad y deduplicacion de amenazas.

El sistema anterior usaba md5(titulo + fecha) como identificador, asi que la
misma vulnerabilidad recogida de cinco fuentes generaba cinco registros
(CVE-2026-53224 aparecia 7 veces en agosto de 2026).

Regla nueva: una amenaza es unica por (mes, CVE) cuando hay CVE, y por
(mes, titulo normalizado) cuando no lo hay. Las apariciones adicionales
incrementan `times_seen` y anaden una fila en `threat_sources`.
"""
from __future__ import annotations

import hashlib
import re
import unicodedata
from datetime import datetime, timezone
from urllib.parse import urlsplit
from typing import Optional

CVE_RE = re.compile(r"CVE-(\d{4})-(\d{4,7})", re.IGNORECASE)

# Ruido habitual en los titulos de los boletines, que impide reconocer que dos
# entradas hablan de lo mismo.
_PREFIJOS_RUIDO = re.compile(
    r"^\s*(?:"
    r"\[[^\]]{1,40}\]|"                       # [Actualizado], [Critico]
    r"(?:dsa|dla|usn|rhsa|rhba|suse-su|suse-ru|esa|msrc|va)[-\s]?[\d\-]+\s*[-:]?|"
    r"update\s+\d+[-:]?|"
    r"security\s+(?:advisory|update|bulletin)\s*[-:]?"
    r")\s*",
    re.IGNORECASE,
)

_SUFIJOS_RUIDO = re.compile(
    r"\s*[-–|]\s*(?:security\s+update|actualizaci[oó]n\s+de\s+seguridad|"
    r"the\s+hacker\s+news|bleepingcomputer|securityweek|dark\s+reading)\s*$",
    re.IGNORECASE,
)


def extraer_cve(*textos: Optional[str]) -> Optional[str]:
    """Devuelve el primer CVE bien formado que aparezca, en mayusculas."""
    for texto in textos:
        if not texto:
            continue
        match = CVE_RE.search(texto)
        if match:
            return f"CVE-{match.group(1)}-{match.group(2)}"
    return None


def extraer_todos_cve(*textos: Optional[str]) -> list[str]:
    vistos: list[str] = []
    for texto in textos:
        if not texto:
            continue
        for anio, num in CVE_RE.findall(texto):
            cve = f"CVE-{anio}-{num}"
            if cve not in vistos:
                vistos.append(cve)
    return vistos


def anio_cve(cve: Optional[str]) -> Optional[int]:
    if not cve:
        return None
    match = CVE_RE.search(cve)
    return int(match.group(1)) if match else None


# Identificadores de aviso de proveedor. Son la clave natural de la amenaza
# cuando no hay CVE: DSA-6157-1 y DSA-6151-1 son avisos DISTINTOS aunque ambos
# hablen de chromium. Normalizarlos fuera del titulo (como hacia la primera
# version de este modulo) fusionaba avisos que no son el mismo.
ID_AVISO_RE = re.compile(
    r"\b("
    r"DSA-\d{3,5}(?:-\d+)?|"          # Debian
    r"DLA-\d{3,5}(?:-\d+)?|"          # Debian LTS
    r"USN-\d{3,5}(?:-\d+)?|"          # Ubuntu
    r"RHSA-\d{4}:\d{3,5}|"            # Red Hat
    r"RHBA-\d{4}:\d{3,5}|"
    r"SUSE-SU-\d{4}:\d{3,5}(?:-\d+)?|"
    r"SUSE-RU-\d{4}:\d{3,5}(?:-\d+)?|"
    r"ELSA-\d{4}-\d{3,5}|"            # Oracle Linux
    r"FEDORA-\d{4}-[0-9a-f]{6,}|"
    r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|"   # GitHub Security Advisory
    r"ICSA-\d{2}-\d{3}-\d{2}|"       # CISA ICS
    r"AA\d{2}-\d{3}[A-Z]?|"           # CISA alerts
    r"VMSA-\d{4}-\d{4}|"
    r"cisco-sa-[0-9a-zA-Z\-]{6,40}|"
    r"ADV\d{6}"                        # Microsoft advisory
    r")\b",
    re.IGNORECASE,
)


def extraer_id_aviso(*textos: Optional[str]) -> Optional[str]:
    """Devuelve el identificador de aviso del proveedor, normalizado a mayusculas."""
    for texto in textos:
        if not texto:
            continue
        match = ID_AVISO_RE.search(texto)
        if match:
            return match.group(1).upper()
    return None


def normalizar_titulo(titulo: str) -> str:
    """Normaliza para comparar: sin tildes, sin ruido de boletin, sin puntuacion."""
    if not titulo:
        return ""
    texto = unicodedata.normalize("NFKD", titulo)
    texto = "".join(c for c in texto if not unicodedata.combining(c))
    texto = texto.lower().strip()

    anterior = None
    while anterior != texto:                      # los prefijos se acumulan
        anterior = texto
        texto = _PREFIJOS_RUIDO.sub("", texto).strip()
    texto = _SUFIJOS_RUIDO.sub("", texto).strip()

    texto = re.sub(r"[^\w\s]", " ", texto)
    texto = re.sub(r"\s+", " ", texto).strip()
    return texto


def normalizar_url(url: Optional[str]) -> Optional[str]:
    """Normaliza una URL para usarla como clave de identidad.

    Devuelve None si la URL no identifica un articulo concreto (portada, raiz del
    feed). El recolector anterior hacia `link = entry.get('link', source['url'])`,
    asi que las entradas sin enlace heredaban la URL de la fuente: usar eso como
    identidad fusionaria todo lo de una misma fuente en un solo registro.
    """
    if not url:
        return None
    try:
        partes = urlsplit(url.strip())
    except ValueError:
        return None
    if partes.scheme not in ("http", "https") or not partes.netloc:
        return None

    camino = (partes.path or "").rstrip("/")
    segmentos = [s for s in camino.split("/") if s]

    # Portada o raiz: no identifica nada
    if not segmentos:
        return None
    # Rutas de feed genericas
    if segmentos[-1].lower() in {"feed", "rss", "rss.xml", "atom", "atom.xml",
                                 "index.html", "index.xml", "all.xml", "news"}:
        return None
    # Un solo segmento corto suele ser una seccion, no un articulo
    if len(segmentos) == 1 and len(segmentos[0]) < 12:
        return None

    host = partes.netloc.lower()
    if host.startswith("www."):
        host = host[4:]
    return f"{host}{camino.lower()}"


def fingerprint(*, month: str, cve: Optional[str] = None,
                titulo: Optional[str] = None,
                id_aviso: Optional[str] = None,
                url: Optional[str] = None) -> str:
    """Huella estable de una amenaza dentro de un mes.

    Precedencia, de mas fiable a menos:
      1. CVE            -> dos fuentes que informen del mismo CVE colapsan en una fila
      2. ID de aviso    -> DSA-6157-1 distingue avisos que el titulo no distingue
      3. URL del articulo -> identifica la entrada concreta
      4. Titulo normalizado

    El mes forma parte de la huella porque la unidad de reporte del sistema es
    el mes: una amenaza que reaparece en el mes siguiente genera una fila nueva
    en ese mes, y `cve_recurrentes()` la detecta como deuda de parcheo.
    """
    if cve:
        base = f"{month}|cve|{cve.upper()}"
    else:
        aviso = id_aviso or extraer_id_aviso(titulo)
        if aviso:
            base = f"{month}|aviso|{aviso.upper()}"
        else:
            clave_url = normalizar_url(url)
            if clave_url:
                base = f"{month}|url|{clave_url}"
            else:
                norma = normalizar_titulo(titulo or "")
                if not norma:
                    raise ValueError(
                        "se necesita cve, id de aviso, url o titulo para la huella")
                base = f"{month}|titulo|{norma}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()[:32]


def mes_de(fecha: Optional[str | datetime]) -> str:
    """Devuelve 'YYYY-MM'. Si no hay fecha utilizable, usa el mes actual en UTC."""
    if isinstance(fecha, datetime):
        return fecha.strftime("%Y-%m")
    if fecha:
        texto = str(fecha).strip()
        match = re.search(r"(\d{4})[-/](\d{2})", texto)
        if match:
            mes = int(match.group(2))
            if 1 <= mes <= 12:
                return f"{match.group(1)}-{match.group(2)}"
        for formato in ("%a, %d %b %Y %H:%M:%S %z", "%a, %d %b %Y %H:%M:%S %Z",
                        "%d %b %Y %H:%M:%S %z", "%Y-%m-%dT%H:%M:%S%z"):
            try:
                return datetime.strptime(texto, formato).strftime("%Y-%m")
            except ValueError:
                continue
    return datetime.now(timezone.utc).strftime("%Y-%m")

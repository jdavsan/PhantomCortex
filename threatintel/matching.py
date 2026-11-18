"""Correlacion de amenazas con el inventario tecnico.

Este es el modulo que decide si una amenaza le importa a esta organizacion. El
sistema anterior resolvia la pregunta con `if tech.lower() in texto.lower()`, y
eso producia, medido sobre las 2034 amenazas de agosto de 2026:

  * 'edge'   dentro de 'acknowledgement' / 'knowledge' -> 135 falsos positivos
  * 'java'   dentro de 'javascript'                    ->  24 falsos positivos
  * 'debian' dentro de la URL del tracker de cada DSA  -> 922 coincidencias por
    accidente en enlaces, no por el contenido del boletin
  * nombres de actores ('Nightmare-Eclipse'), adjetivos ('corchete angular',
    'cutting-edge') y menciones de la casa investigadora ('Sophos advierte')
    contados como tecnologia propia

Las reglas, en el orden en que se aplican:
  0. Normalizacion: se quitan etiquetas HTML, se resuelven entidades y se borran
     las URL. Una URL es una referencia, no una afirmacion sobre lo afectado.
  1. match_mode 'word'   -> limites de palabra alrededor del alias.
  2. match_mode 'phrase' -> frase completa, con espacios flexibles y limites.
  3. match_mode 'regex'  -> el alias ES una expresion regular. Si no compila se
     registra el error y se salta ese alias, sin tumbar la ejecucion.
  4. context_required    -> exige que al menos uno de esos terminos aparezca
     tambien en el texto. Ejemplo canonico: el alias 'Access' solo vale si el
     texto trae ademas 'microsoft' u 'office'.
  5. is_exclusion=1      -> si el alias aparece, se descarta la tecnologia entera
     para esa amenaza.
  6. confidence          -> 1.0 alias exacto multi-palabra, 0.9 nombre propio de
     una palabra, 0.6 alias generico; -0.2 si solo aparece en el resumen.
  7. Version             -> se buscan restricciones a +-200 caracteres de la
     mencion y se evaluan con versions.evaluar contra version_installed.
"""
from __future__ import annotations

import html
import json
import re
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional, Sequence

from pathlib import Path

from . import versions
from .db import audit, utcnow
from .paths import BASE_DIR
from .logging_setup import get_logger

log = get_logger("matching")

VENTANA_VERSION = 200        # caracteres a cada lado de la mencion
PENALIZACION_RESUMEN = 0.2   # solo aparece en el resumen, no en el titulo

# --- Precision (2026-09-04) -------------------------------------------------
# Confianza de una coincidencia que solo prueba que el texto ES de una
# distribucion (identificador DSA/DLA/USN), no que nos afecte: mencion.
CONFIANZA_MENCION = 0.3
# Confianza del paquete nombrado por un aviso de distribucion cuando esta en el
# inventario: el aviso lo identifica de forma explicita.
CONFIANZA_PAQUETE_AVISO = 0.95

# Terminos que deben acompanar a un alias generico para que cuente. Un texto
# que habla de una vulnerabilidad los trae siempre; una noticia de malware que
# menciona "Windows" de pasada, no. Se toleran plurales (ver _patron_contexto).
CONTEXTO_VULNERABILIDAD: tuple[str, ...] = (
    "vulnerability", "vulnerabilidad", "CVE", "flaw", "patch", "parche",
    "security update", "actualización de seguridad", "security advisory",
    "aviso de seguridad", "security fix", "exploit", "exploited", "zero-day", "0-day",
    "RCE", "remote code execution", "ejecución de código", "privilege escalation",
    "escalada de privilegios", "buffer overflow", "use-after-free", "denial of service",
    "denegación de servicio", "CVSS", "KEV", "advisory",
)

# Alias de una sola palabra corriente que, sin contexto, correlacionaban noticias
# enteras (5.150 coincidencias por 'windows', 'chrome' y 'edge' hasta septiembre).
GENERICOS_CON_CONTEXTO: frozenset[str] = frozenset({
    "windows", "linux", "kernel", "ubuntu", "debian", "chrome", "chromium", "edge",
    "firefox", "java", "php", "docker", "ldap", "nginx", "git", "python", "node",
    "redis", "apache", "asterisk", "mysql", "sqlite", "postgres", "outlook", "office",
    "exchange", "teams", "android",
})

# Exclusiones por tecnologia (slug): si aparecen, la tecnologia se descarta en
# ese texto. "Chrome for Android" no es el Chrome de escritorio del inventario.
EXCLUSIONES_BASE: dict[str, tuple[str, ...]] = {
    "chrome": ("Chrome for Android", "Chrome for iOS", "Chrome OS", "ChromeOS"),
    "windows": ("Windows Phone", "Windows Mobile", "Xbox"),
    "edge": ("edge computing", "edge device", "edge devices", "network edge",
             "edge server", "edge servers", "edge router", "edge routers"),
}

# Identificador de aviso de distribucion + nombre del paquete que corrige:
# "DSA-6479-1 roundcube - security update", "USN-7123-1: Linux kernel ...".
_RE_PAQUETE_AVISO = re.compile(
    r"\b(?:DSA|DLA|USN)-\d{3,5}(?:-\d+)?\s*[:\-\u2013]?\s*([A-Za-z][A-Za-z0-9.+_-]*)",
    re.IGNORECASE)
_RE_ID_DISTRO_EN_ALIAS = re.compile(r"DS\[AL\]|DSA|DLA|USN", re.IGNORECASE)
_PALABRAS_NO_PAQUETE = frozenset({"security", "update", "updates", "vulnerabilit", "vulnerability",
                                  "vulnerabilities", "regression", "new", "the"})
_SUFIJOS_PAQUETE = ("-esr", "-lts", "-bin", "-common", "-dev", "-core", "-server", "-client")
MODOS = ("word", "phrase", "regex")

# Solo etiquetas de verdad: un patron laxo como r"<[^>]+>" se comia el
# "< 8.1.3.1" de un boletin, que es justo el dato de version que interesa.
_RE_ETIQUETAS = re.compile(r"</?[a-zA-Z!][^<>]*>")
_RE_URL = re.compile(r"(?:https?://|ftp://|www\.)\S+", re.IGNORECASE)
_RE_CORREO = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_RE_ESPACIOS = re.compile(r"[ \t\r\f\v]+")


# --------------------------------------------------------------------------
# Normalizacion del texto de la amenaza
# --------------------------------------------------------------------------
def normalizar(texto: Optional[str], *, quitar_urls: bool = True) -> str:
    """Deja el texto listo para buscar: sin HTML, sin entidades y sin URL.

    Las URL se borran a proposito. En los avisos DSA la unica aparicion de
    'debian' esta en el enlace al tracker, y contarla convertia cada boletin de
    un paquete cualquiera en una coincidencia de la tecnologia Debian. Lo mismo
    pasaba con '.php' o 'gitlab.com' dentro de enlaces de noticias. Un boletin
    que de verdad habla de una tecnologia la nombra en el texto.
    """
    if not texto:
        return ""
    limpio = _RE_ETIQUETAS.sub(" ", str(texto))
    limpio = html.unescape(limpio)
    limpio = _RE_ETIQUETAS.sub(" ", limpio)   # entidades que escondian etiquetas
    if quitar_urls:
        limpio = _RE_URL.sub(" ", limpio)
        limpio = _RE_CORREO.sub(" ", limpio)
    limpio = limpio.replace("\u00a0", " ")   # espacio duro
    return _RE_ESPACIOS.sub(" ", limpio).strip()


# --------------------------------------------------------------------------
# Estructuras
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Coincidencia:
    """Una tecnologia del inventario detectada en una amenaza."""

    technology_id: int
    slug: str
    name: str
    matched_alias: str
    confidence: float
    version_verdict: str
    version_evidence: Optional[str]


@dataclass(frozen=True)
class AliasCompilado:
    technology_id: int
    alias: str
    match_mode: str
    is_exclusion: bool
    regex: re.Pattern
    contexto: tuple[re.Pattern, ...]
    contexto_terminos: tuple[str, ...]
    confianza_base: float


@dataclass(frozen=True)
class TecnologiaCompilada:
    id: int
    slug: str
    name: str
    version_installed: Optional[str]
    criticality: str
    systems_count: int


@dataclass
class InventarioCompilado:
    """Inventario con los regex ya compilados.

    Se construye UNA vez por ejecucion: con 2000 amenazas y 60 tecnologias con
    varios alias cada una, recompilar por amenaza multiplicaria el coste por
    2000 sin ninguna ganancia.
    """

    tecnologias: dict[int, TecnologiaCompilada] = field(default_factory=dict)
    inclusiones: tuple[AliasCompilado, ...] = ()
    exclusiones: dict[int, tuple[AliasCompilado, ...]] = field(default_factory=dict)
    errores: tuple[str, ...] = ()
    compilado_en: str = ""
    # Precision: nombre de paquete/alias en minusculas -> technology_id, para
    # correlar el paquete que nombra un aviso DSA/DLA/USN.
    indice_paquetes: dict[str, int] = field(default_factory=dict)
    # Paquetes instalados en los servidores (dpkg-query), si el operador los aporta.
    paquetes_instalados: frozenset[str] = frozenset()
    fichero_paquetes: str = ""

    def __len__(self) -> int:
        return len(self.tecnologias)

    @property
    def total_alias(self) -> int:
        return len(self.inclusiones) + sum(len(v) for v in self.exclusiones.values())

    def por_slug(self, slug: str) -> Optional[TecnologiaCompilada]:
        for tecnologia in self.tecnologias.values():
            if tecnologia.slug == slug:
                return tecnologia
        return None


# --------------------------------------------------------------------------
# Compilacion de alias
# --------------------------------------------------------------------------
def _limites(cuerpo: str, alias: str) -> str:
    """Envuelve el patron en limites de palabra donde tenga sentido.

    Un `\\b` detras de 'Notepad++' nunca casaria, porque exige un caracter de
    palabra justo despues del '+'. Por eso el limite solo se pone en los extremos
    que son alfanumericos.
    """
    izquierda = r"\b" if alias[:1].isalnum() or alias[:1] == "_" else ""
    derecha = r"\b" if alias[-1:].isalnum() or alias[-1:] == "_" else ""
    return f"{izquierda}{cuerpo}{derecha}"


def _patron_literal(alias: str) -> str:
    """Alias literal con espacios flexibles: 'Check Point' casa 'check-point'."""
    partes = [re.escape(p) for p in alias.split() if p]
    cuerpo = r"[\s\-_]+".join(partes) if partes else re.escape(alias)
    return _limites(cuerpo, alias)


def _confianza_base(alias: str, match_mode: str) -> float:
    """1.0 multi-palabra, 0.9 nombre propio, 0.6 termino generico.

    El criterio de "nombre propio" es que el alias lleve alguna mayuscula, asi
    que el sembrado escribe 'Java', 'Debian' o 'NGINX' y deja en minusculas los
    genericos ('ldap', 'httpd', 'svn'), que valen menos como evidencia.
    """
    if match_mode == "regex":
        if _RE_ID_DISTRO_EN_ALIAS.search(alias):
            # Un identificador DSA/DLA/USN prueba que el aviso es de la
            # distribucion, no que el paquete corregido este instalado: mencion.
            return CONFIANZA_MENCION
        return 0.9        # lo ha escrito un administrador a proposito
    if len(alias.split()) > 1:
        return 1.0
    if any(c.isupper() for c in alias):
        return 0.9
    return 0.6


def _patron_contexto(termino: str) -> str:
    """Como _patron_literal, pero tolerando el plural.

    Un termino de contexto es una senal gruesa de tema, no una identificacion: si
    se exige 'browser' al pie de la letra, el titulo "synced across Chrome,
    Firefox, and Edge - I use multiple browsers every day" se queda fuera y se
    pierde una mencion legitima de Microsoft Edge. Solo se admite el plural, no
    un prefijo libre, para que 'ide' no case con 'identity'.
    """
    patron = _patron_literal(termino)
    if termino[-1:].isalpha() and patron.endswith(r"\b"):
        return patron[:-2] + r"(?:e?s)?\b"
    return patron


def _compilar_contexto(terminos: Sequence[str]) -> tuple[re.Pattern, ...]:
    return tuple(re.compile(_patron_contexto(t), re.IGNORECASE) for t in terminos if t)


def _leer_contexto(bruto: Optional[str], *, referencia: str) -> tuple[str, ...]:
    """context_required se guarda como array JSON. Un valor invalido no debe
    romper la ejecucion: se registra y se ignora."""
    if not bruto:
        return ()
    try:
        datos = json.loads(bruto)
    except (json.JSONDecodeError, TypeError):
        log.warning("context_required no es JSON valido; se ignora",
                    extra={"alias": referencia, "valor": str(bruto)[:120]})
        return ()
    if isinstance(datos, str):
        datos = [datos]
    if not isinstance(datos, list):
        log.warning("context_required no es una lista; se ignora",
                    extra={"alias": referencia})
        return ()
    return tuple(str(x).strip() for x in datos if str(x).strip())


def compilar_alias(technology_id: int, alias: str, match_mode: str = "word",
                   is_exclusion: bool = False,
                   context_required: Optional[str] = None) -> Optional[AliasCompilado]:
    """Compila un alias. Devuelve None si es inservible (y lo registra)."""
    alias = (alias or "").strip()
    if not alias:
        log.warning("alias vacio en el inventario", extra={"technology_id": technology_id})
        return None

    modo = (match_mode or "word").strip().lower()
    if modo not in MODOS:
        log.warning("match_mode desconocido; se trata como 'word'",
                    extra={"alias": alias, "match_mode": match_mode})
        modo = "word"

    if modo == "regex":
        try:
            compilado = re.compile(alias, re.IGNORECASE)
        except re.error as exc:
            log.error("alias con regex no valida; se salta",
                      extra={"alias": alias, "technology_id": technology_id,
                             "detalle": str(exc)})
            return None
    else:
        compilado = re.compile(_patron_literal(alias), re.IGNORECASE)

    terminos = _leer_contexto(context_required, referencia=alias)
    return AliasCompilado(
        technology_id=technology_id,
        alias=alias,
        match_mode=modo,
        is_exclusion=bool(is_exclusion),
        regex=compilado,
        contexto=_compilar_contexto(terminos),
        contexto_terminos=terminos,
        confianza_base=_confianza_base(alias, modo),
    )


def extraer_paquete_aviso(titulo: Optional[str]) -> Optional[str]:
    """Nombre del paquete que corrige un aviso DSA/DLA/USN, en minusculas.

    'DSA-6479-1 roundcube - security update' -> 'roundcube';
    'USN-7123-1: Linux kernel vulnerabilities' -> 'linux'. None si el texto no
    es un aviso de distribucion o la palabra siguiente no parece un paquete.
    """
    if not titulo:
        return None
    m = _RE_PAQUETE_AVISO.search(str(titulo))
    if not m:
        return None
    paquete = m.group(1).lower().rstrip(".:,;")
    if not paquete or paquete in _PALABRAS_NO_PAQUETE:
        return None
    return paquete


def _variantes_paquete(paquete: str) -> list[str]:
    """'firefox-esr' -> ['firefox-esr', 'firefox']; 'linux' -> ['linux']."""
    variantes = [paquete]
    for sufijo in _SUFIJOS_PAQUETE:
        if paquete.endswith(sufijo) and len(paquete) > len(sufijo) + 2:
            variantes.append(paquete[: -len(sufijo)])
    if "-" in paquete:
        base = paquete.split("-", 1)[0]
        if len(base) >= 4:
            variantes.append(base)
    return variantes


def _tecnologia_del_paquete(paquete: str, inventario: "InventarioCompilado") -> Optional[int]:
    for variante in _variantes_paquete(paquete):
        tid = inventario.indice_paquetes.get(variante)
        if tid is not None:
            return tid
    return None


def _cargar_paquetes_instalados(ruta: Optional[str]) -> tuple[frozenset[str], str]:
    """Lee la lista de paquetes instalados (una linea por paquete; se admite un
    directorio con varios ficheros .txt, uno por servidor). Vacio si no hay."""
    if not ruta or not str(ruta).strip():
        return frozenset(), ""
    camino = Path(str(ruta).strip())
    if not camino.is_absolute():
        camino = BASE_DIR / camino
    ficheros: list[Path]
    if camino.is_dir():
        ficheros = sorted(camino.glob("*.txt"))
    elif camino.is_file():
        ficheros = [camino]
    else:
        log.warning("la lista de paquetes instalados no existe; se ignora",
                    extra={"ruta": str(camino)})
        return frozenset(), ""
    paquetes: set[str] = set()
    for fichero in ficheros:
        try:
            for linea in fichero.read_text(encoding="utf-8", errors="replace").splitlines():
                nombre = linea.strip().split()[0].lower() if linea.strip() else ""
                if nombre and not nombre.startswith("#"):
                    paquetes.add(nombre.split(":", 1)[0])   # 'libc6:amd64' -> 'libc6'
        except OSError as exc:
            log.warning("no se pudo leer la lista de paquetes", extra={"ruta": str(fichero), "error": str(exc)})
    return frozenset(paquetes), str(camino)


def compilar_inventario(conn: sqlite3.Connection, *,
                        solo_habilitadas: bool = True, cfg: Any = None) -> InventarioCompilado:
    """Lee el inventario y precompila sus regex. Una llamada por ejecucion.

    Con ``cfg`` carga tambien la lista de paquetes instalados
    (``debian_packages_file``) para decidir si un aviso DSA/DLA/USN nos afecta.
    """
    filtro = "WHERE enabled=1" if solo_habilitadas else ""
    tecnologias: dict[int, TecnologiaCompilada] = {}
    for fila in conn.execute(
            f"SELECT id, slug, name, version_installed, criticality, systems_count "
            f"FROM technologies {filtro} ORDER BY name"):
        tecnologias[fila["id"]] = TecnologiaCompilada(
            id=fila["id"],
            slug=fila["slug"],
            name=fila["name"],
            version_installed=fila["version_installed"],
            criticality=fila["criticality"],
            systems_count=fila["systems_count"],
        )

    inclusiones: list[AliasCompilado] = []
    exclusiones: dict[int, list[AliasCompilado]] = {}
    errores: list[str] = []

    for fila in conn.execute(
            "SELECT technology_id, alias, match_mode, is_exclusion, context_required "
            "FROM tech_aliases ORDER BY technology_id, id"):
        if fila["technology_id"] not in tecnologias:
            continue
        compilado = compilar_alias(
            fila["technology_id"], fila["alias"], fila["match_mode"],
            bool(fila["is_exclusion"]), fila["context_required"])
        if compilado is None:
            errores.append(f"{fila['technology_id']}:{fila['alias']}")
            continue
        if compilado.is_exclusion:
            exclusiones.setdefault(compilado.technology_id, []).append(compilado)
        else:
            inclusiones.append(compilado)

    # Alias mas largo primero: si 'Microsoft Edge' y 'Edge' casan, gana el primero.
    inclusiones.sort(key=lambda a: (-len(a.alias), a.alias.lower()))

    # Indice paquete -> tecnologia: slug, nombre y alias literales (no regex).
    indice: dict[str, int] = {}
    for tid, tec in tecnologias.items():
        indice.setdefault(tec.slug.lower(), tid)
        indice.setdefault(tec.name.lower(), tid)
    for alias in inclusiones:
        if alias.match_mode in ("word", "phrase"):
            indice.setdefault(alias.alias.lower(), alias.technology_id)
    paquetes, fichero = _cargar_paquetes_instalados(
        cfg.get("debian_packages_file") if cfg is not None else None)

    inventario = InventarioCompilado(
        tecnologias=tecnologias,
        inclusiones=tuple(inclusiones),
        exclusiones={k: tuple(v) for k, v in exclusiones.items()},
        errores=tuple(errores),
        compilado_en=utcnow(),
        indice_paquetes=indice,
        paquetes_instalados=paquetes,
        fichero_paquetes=fichero,
    )
    log.info("inventario compilado", extra={
        "tecnologias": len(inventario),
        "alias": inventario.total_alias,
        "alias_invalidos": len(errores),
    })
    return inventario


# --------------------------------------------------------------------------
# Busqueda
# --------------------------------------------------------------------------
def _contexto_ok(alias: AliasCompilado, texto: str) -> bool:
    if not alias.contexto:
        return True
    return any(patron.search(texto) for patron in alias.contexto)


# Cuanto mas prudente, mas prioridad: nunca se prefiere 'not_affected'.
_PRIORIDAD_VEREDICTO = {versions.AFFECTED: 0, versions.UNKNOWN: 1, versions.NOT_AFFECTED: 2}

# Fin de frase. No parte los numeros de version: el punto de '10.3.5' no cuenta.
_RE_FIN_FRASE = re.compile(r"(?<!\d)[.!?](?:\s|$)")


def _frase_alrededor(texto: str, inicio: int, fin: int) -> str:
    """Devuelve la frase que contiene el fragmento [inicio, fin)."""
    principio = 0
    for corte in _RE_FIN_FRASE.finditer(texto, 0, inicio):
        principio = corte.end()
    final = len(texto)
    siguiente = _RE_FIN_FRASE.search(texto, fin)
    if siguiente is not None:
        final = siguiente.start() + 1
    return texto[principio:final]


def _veredicto_version(texto: str, apariciones: Sequence[re.Match],
                       version_instalada: Optional[str],
                       ventana: int) -> tuple[str, Optional[str]]:
    """Evalua la version mirando solo alrededor de cada mencion.

    Se limita a la ventana a proposito: un boletin puede citar versiones de
    varios productos, y leer todo el texto haria comparar la version de otro.
    Entre varias ventanas gana la mas prudente ('affected' antes que 'unknown',
    y 'not_affected' solo si ninguna otra dice nada mejor).
    """
    if not version_instalada or not str(version_instalada).strip():
        return versions.evaluar(None, [])
    if not apariciones:
        return versions.evaluar(version_instalada, [])

    resultados: list[tuple[str, str]] = []
    for aparicion in apariciones:
        inicio = max(0, aparicion.start() - ventana)
        fin = min(len(texto), aparicion.end() + ventana)
        restricciones = versions.extraer_restricciones(texto[inicio:fin])
        veredicto, evidencia = versions.evaluar(version_instalada, restricciones)

        # Descartar por version exige que el limite este en la MISMA frase que la
        # mencion. Medido sobre agosto de 2026, la ventana de 200 caracteres
        # arrastraba el "<= 1.56.1" de un plugin de WordPress hasta la mencion de
        # PHP dos frases mas arriba y declaraba PHP 'not_affected'. Un rango de
        # otro producto no puede dar por segura una tecnologia propia.
        if veredicto == versions.NOT_AFFECTED:
            frase = _frase_alrededor(texto, aparicion.start(), aparicion.end())
            if not versions.extraer_restricciones(frase):
                veredicto = versions.UNKNOWN
                evidencia = (f"{evidencia} | la version del anuncio no aparece en la "
                             "misma frase que la mencion, asi que podria ser de otro "
                             "producto; conviene revisarla a mano")
        resultados.append((veredicto, evidencia))

    resultados.sort(key=lambda r: _PRIORIDAD_VEREDICTO.get(r[0], 1))
    return resultados[0]


def encontrar(texto: str, inventario: InventarioCompilado, *,
              titulo: Optional[str] = None,
              ventana: int = VENTANA_VERSION) -> list[Coincidencia]:
    """Devuelve las tecnologias del inventario mencionadas en el texto.

    `texto` es el cuerpo completo a examinar (titulo + resumen suele ser lo util).
    `titulo` es opcional y sirve solo para la regla 6: si el alias no aparece en
    el titulo, la confianza baja 0.2.
    """
    cuerpo = normalizar(texto)
    if not cuerpo or not inventario.tecnologias:
        return []
    cabecera = normalizar(titulo) if titulo else ""

    descartadas: set[int] = set()
    for technology_id, aliases in inventario.exclusiones.items():
        for alias in aliases:
            if alias.regex.search(cuerpo) and _contexto_ok(alias, cuerpo):
                descartadas.add(technology_id)
                log.debug("tecnologia descartada por alias de exclusion",
                          extra={"technology_id": technology_id, "alias": alias.alias})
                break

    mejores: dict[int, tuple[float, str, list[re.Match]]] = {}
    for alias in inventario.inclusiones:
        if alias.technology_id in descartadas:
            continue
        apariciones = list(alias.regex.finditer(cuerpo))
        if not apariciones:
            continue
        if not _contexto_ok(alias, cuerpo):
            log.debug("alias descartado por falta de contexto",
                      extra={"alias": alias.alias,
                             "contexto": ",".join(alias.contexto_terminos)})
            continue

        confianza = alias.confianza_base
        if cabecera and not alias.regex.search(cabecera):
            confianza -= PENALIZACION_RESUMEN
        confianza = round(max(0.1, min(1.0, confianza)), 2)

        etiqueta = apariciones[0].group(0) if alias.match_mode == "regex" else alias.alias
        previo = mejores.get(alias.technology_id)
        if previo is None or confianza > previo[0] or (
                confianza == previo[0] and len(etiqueta) > len(previo[1])):
            mejores[alias.technology_id] = (confianza, etiqueta, apariciones)

    # --- avisos de distribucion: correlar el PAQUETE, no la distribucion ------
    evidencia_forzada: dict[int, str] = {}
    paquete = extraer_paquete_aviso(titulo) or extraer_paquete_aviso(cuerpo[:300])
    if paquete:
        tid_paquete = _tecnologia_del_paquete(paquete, inventario)
        if tid_paquete is not None and tid_paquete not in descartadas:
            apariciones = list(re.compile(_patron_literal(paquete), re.IGNORECASE).finditer(cuerpo))
            previo = mejores.get(tid_paquete)
            if previo is None or previo[0] < CONFIANZA_PAQUETE_AVISO:
                mejores[tid_paquete] = (CONFIANZA_PAQUETE_AVISO, paquete,
                                        apariciones or (previo[2] if previo else []))
        if paquete in inventario.paquetes_instalados:
            # El paquete esta en nuestros servidores: la distribucion pasa de
            # mencion a coincidencia plena, con la prueba de donde sale.
            for tid, (confianza, etiqueta, apariciones) in list(mejores.items()):
                if confianza <= CONFIANZA_MENCION:
                    mejores[tid] = (1.0, etiqueta, apariciones)
                    evidencia_forzada[tid] = (f"paquete «{paquete}» instalado según "
                                              f"{Path(inventario.fichero_paquetes).name or 'la lista de paquetes'}")

    coincidencias: list[Coincidencia] = []
    for technology_id, (confianza, etiqueta, apariciones) in mejores.items():
        tecnologia = inventario.tecnologias[technology_id]
        veredicto, evidencia = _veredicto_version(
            cuerpo, apariciones, tecnologia.version_installed, ventana)
        if technology_id in evidencia_forzada:
            evidencia = evidencia_forzada[technology_id] + (f"; {evidencia}" if evidencia else "")
        coincidencias.append(Coincidencia(
            technology_id=technology_id,
            slug=tecnologia.slug,
            name=tecnologia.name,
            matched_alias=etiqueta,
            confidence=confianza,
            version_verdict=veredicto,
            version_evidence=evidencia,
        ))

    coincidencias.sort(key=lambda c: (-c.confidence, c.name.lower()))
    return coincidencias


# --------------------------------------------------------------------------
# Persistencia
# --------------------------------------------------------------------------
def aplicar(conn: sqlite3.Connection, threat_id: int,
            coincidencias: Iterable[Coincidencia]) -> None:
    """Sincroniza threat_technologies con las coincidencias dadas.

    Sincroniza, no acumula: si se vuelve a correlacionar una amenaza con un
    inventario corregido, las asignaciones viejas y equivocadas tienen que
    desaparecer. Por eso se borran las que ya no casan.
    """
    lista = list(coincidencias)
    ids = [c.technology_id for c in lista]

    if ids:
        marcas = ",".join("?" for _ in ids)
        conn.execute(
            f"DELETE FROM threat_technologies WHERE threat_id=? "
            f"AND technology_id NOT IN ({marcas})",
            [threat_id, *ids],
        )
    else:
        conn.execute("DELETE FROM threat_technologies WHERE threat_id=?", (threat_id,))
        return

    conn.executemany(
        "INSERT INTO threat_technologies("
        "  threat_id, technology_id, matched_alias, confidence,"
        "  version_verdict, version_evidence) "
        "VALUES(?,?,?,?,?,?) "
        "ON CONFLICT(threat_id, technology_id) DO UPDATE SET "
        "  matched_alias=excluded.matched_alias,"
        "  confidence=excluded.confidence,"
        "  version_verdict=excluded.version_verdict,"
        "  version_evidence=excluded.version_evidence",
        [(threat_id, c.technology_id, c.matched_alias, c.confidence,
          c.version_verdict, c.version_evidence) for c in lista],
    )


# --------------------------------------------------------------------------
# SEMBRADO DEL INVENTARIO
# --------------------------------------------------------------------------
# Deriva de TECNOLOGIAS_MONITOREADAS de collect_threats_rss.py, pero limpio:
#   * sin duplicados: 'gitlab' x2, 'moodle' x2, 'Tuleap'/'tuleap'
#   * typos corregidos: 'docusing' -> DocuSign, '7zip' -> 7-Zip,
#     'cristaldisk' -> CrystalDiskInfo, 'svn version control' -> Subversion
#   * 'central telefonica' pasa a ser alias de Asterisk, no una tecnologia
#   * 'Adobe' (un fabricante entero) pasa a ser Adobe Acrobat Reader, que es lo
#     que de verdad esta instalado; asi los avisos de Adobe Campaign o ColdFusion
#     dejan de contarse como propios
#   * context_required en los terminos ambiguos ('Edge', 'Brave', 'Angular',
#     'Eclipse', 'Asterisk', 'Gaia', 'Apache') y exclusiones donde el termino
#     aparece como casa investigadora ('Sophos advierte', 'Check Point Research')
#
# version_installed se deja en None a proposito: lo rellena el usuario desde la
# GUI. Sin version instalada el veredicto es 'unknown', que es lo honesto.
INVENTARIO_BASE: list[dict[str, Any]] = [
    # ------------------------------------------------ sistemas operativos
    {"slug": "windows", "name": "Microsoft Windows", "vendor": "Microsoft",
     "category": "sistema-operativo", "criticality": "high", "exposure": "interna",
     "aliases": ["Windows", {"alias": "Microsoft Windows", "match_mode": "phrase"},
                 {"alias": r"\bWin(?:32k?|64)\b", "match_mode": "regex"}]},
    {"slug": "windows-server", "name": "Windows Server", "vendor": "Microsoft",
     "category": "sistema-operativo", "criticality": "high", "exposure": "interna",
     "aliases": [{"alias": "Windows Server", "match_mode": "phrase"}]},
    {"slug": "linux", "name": "Linux", "vendor": "varios",
     "category": "sistema-operativo", "criticality": "high", "exposure": "interna",
     "aliases": ["Linux", {"alias": "Linux kernel", "match_mode": "phrase"}]},
    {"slug": "ubuntu", "name": "Ubuntu", "vendor": "Canonical",
     "category": "sistema-operativo", "criticality": "medium", "exposure": "interna",
     "notes": "El identificador USN-... marca un aviso oficial de Ubuntu.",
     "aliases": ["Ubuntu", {"alias": r"\bUSN-\d{3,}(?:-\d+)?\b", "match_mode": "regex"}]},
    {"slug": "debian", "name": "Debian GNU/Linux", "vendor": "Debian Project",
     "category": "sistema-operativo", "criticality": "high", "exposure": "interna",
     "notes": "El alias DSA-... sustituye a la coincidencia accidental de la "
              "palabra 'debian' dentro del enlace al tracker de cada aviso.",
     "aliases": ["Debian",
                 {"alias": r"\bDS[AL]-\d{3,}(?:-\d+)?\b", "match_mode": "regex"},
                 {"alias": r"\bDLA-\d{3,}(?:-\d+)?\b", "match_mode": "regex"}]},
    {"slug": "freebsd", "name": "FreeBSD", "vendor": "FreeBSD Project",
     "category": "sistema-operativo", "criticality": "medium", "exposure": "interna",
     "aliases": ["FreeBSD", {"alias": r"\bFreeBSD-SA-\d{2}", "match_mode": "regex"}]},

    # ------------------------------------------------------ servidores web
    {"slug": "apache-httpd", "name": "Apache HTTP Server",
     "vendor": "Apache Software Foundation", "category": "servidor-web",
     "criticality": "high", "exposure": "dmz",
     "notes": "'Apache' a secas casaba con Tomcat, Struts, Kafka y cualquier otro "
              "proyecto de la fundacion; ahora exige contexto de servidor web.",
     "aliases": [{"alias": "Apache HTTP Server", "match_mode": "phrase"},
                 {"alias": "Apache httpd", "match_mode": "phrase"},
                 "httpd",
                 {"alias": "Apache", "match_mode": "word",
                  "context_required": ["httpd", "http server", "web server",
                                       "servidor web", "mod_ssl", "mod_proxy",
                                       "mod_rewrite"]}]},
    {"slug": "nginx", "name": "NGINX", "vendor": "F5",
     "category": "servidor-web", "criticality": "high", "exposure": "dmz",
     "aliases": ["NGINX"]},
    {"slug": "jboss", "name": "JBoss / WildFly", "vendor": "Red Hat",
     "category": "servidor-aplicaciones", "criticality": "medium", "exposure": "interna",
     "aliases": ["JBoss", "WildFly", {"alias": "JBoss EAP", "match_mode": "phrase"}]},

    # ------------------------------------------------------ bases de datos
    {"slug": "postgresql", "name": "PostgreSQL", "vendor": "PostgreSQL Global Group",
     "category": "base-de-datos", "criticality": "high", "exposure": "interna",
     "aliases": ["PostgreSQL", "Postgres"]},
    {"slug": "mysql", "name": "MySQL", "vendor": "Oracle",
     "category": "base-de-datos", "criticality": "high", "exposure": "interna",
     "aliases": ["MySQL"]},
    {"slug": "mariadb", "name": "MariaDB", "vendor": "MariaDB Foundation",
     "category": "base-de-datos", "criticality": "high", "exposure": "interna",
     "aliases": ["MariaDB"]},
    {"slug": "sql-server", "name": "Microsoft SQL Server", "vendor": "Microsoft",
     "category": "base-de-datos", "criticality": "high", "exposure": "interna",
     "aliases": [{"alias": "SQL Server", "match_mode": "phrase"},
                 {"alias": "Microsoft SQL Server", "match_mode": "phrase"},
                 "MSSQL"]},
    {"slug": "sqlite", "name": "SQLite", "vendor": "SQLite Consortium",
     "category": "base-de-datos", "criticality": "high", "exposure": "interna",
     "aliases": ["SQLite"]},
    {"slug": "mongodb", "name": "MongoDB", "vendor": "MongoDB Inc.",
     "category": "base-de-datos", "criticality": "high", "exposure": "interna",
     "aliases": ["MongoDB"]},

    # ------------------------------------------------------- perimetro y red
    {"slug": "pfsense", "name": "pfSense", "vendor": "Netgate",
     "category": "red", "criticality": "critical", "exposure": "internet",
     "notes": "Cortafuegos perimetral: expuesto a Internet, criticidad maxima.",
     "aliases": ["pfSense", {"alias": "Netgate pfSense", "match_mode": "phrase"}]},
    {"slug": "checkpoint-vpn", "name": "Check Point VPN", "vendor": "Check Point",
     "category": "red", "criticality": "critical", "exposure": "internet",
     "notes": "Acceso remoto expuesto a Internet, criticidad maxima. Las "
              "exclusiones evitan contar los informes de Check Point Research.",
     "aliases": [{"alias": "Check Point VPN", "match_mode": "phrase"},
                 {"alias": "Check Point", "match_mode": "phrase"},
                 {"alias": "Quantum Security Gateway", "match_mode": "phrase"},
                 {"alias": "Mobile Access", "match_mode": "phrase",
                  "context_required": ["check point", "checkpoint"]},
                 {"alias": "Check Point Research", "match_mode": "phrase",
                  "is_exclusion": True},
                 {"alias": "Check Point researchers", "match_mode": "phrase",
                  "is_exclusion": True}]},
    {"slug": "gaia", "name": "Check Point Gaia OS", "vendor": "Check Point",
     "category": "sistema-operativo", "criticality": "high", "exposure": "dmz",
     "notes": "Se interpreta el 'gaia' de la lista antigua como el sistema "
              "operativo de los equipos Check Point. Confirmar desde la GUI.",
     "aliases": [{"alias": "Gaia OS", "match_mode": "phrase"},
                 {"alias": "Gaia", "match_mode": "word",
                  "context_required": ["check point", "checkpoint", "gateway",
                                       "clish", "firewall", "sk1"]}]},
    {"slug": "sophos", "name": "Sophos", "vendor": "Sophos",
     "category": "seguridad", "criticality": "high", "exposure": "dmz",
     "notes": "Sophos aparece a menudo como firma investigadora en las noticias; "
              "esas menciones no son vulnerabilidades del producto propio.",
     "aliases": ["Sophos",
                 {"alias": "Sophos X-Ops", "match_mode": "phrase", "is_exclusion": True},
                 {"alias": "Sophos researchers", "match_mode": "phrase", "is_exclusion": True},
                 {"alias": "Sophos Labs", "match_mode": "phrase", "is_exclusion": True},
                 {"alias": "Sophos warns", "match_mode": "phrase", "is_exclusion": True},
                 {"alias": "Sophos says", "match_mode": "phrase", "is_exclusion": True},
                 {"alias": "according to Sophos", "match_mode": "phrase", "is_exclusion": True},
                 {"alias": "Sophos advierte", "match_mode": "phrase", "is_exclusion": True}]},
    {"slug": "wazuh", "name": "Wazuh", "vendor": "Wazuh Inc.",
     "category": "seguridad", "criticality": "high", "exposure": "interna",
     "aliases": ["Wazuh"]},
    {"slug": "openssh", "name": "OpenSSH", "vendor": "OpenBSD Project",
     "category": "acceso-remoto", "criticality": "high", "exposure": "dmz",
     "aliases": ["OpenSSH", "sshd"]},
    {"slug": "openssl", "name": "OpenSSL", "vendor": "OpenSSL Project",
     "category": "criptografia", "criticality": "high", "exposure": "interna",
     "aliases": ["OpenSSL"]},
    {"slug": "keepass", "name": "KeePass", "vendor": "Dominik Reichl",
     "category": "seguridad", "criticality": "high", "exposure": "interna",
     "notes": "Almacen de contrasenas: un fallo aqui compromete todo lo demas.",
     "aliases": ["KeePass", "KeePassXC"]},

    # ------------------------------------------------------- virtualizacion
    {"slug": "proxmox", "name": "Proxmox VE", "vendor": "Proxmox Server Solutions",
     "category": "virtualizacion", "criticality": "high", "exposure": "interna",
     "aliases": ["Proxmox", {"alias": "Proxmox VE", "match_mode": "phrase"}]},
    {"slug": "docker", "name": "Docker", "vendor": "Docker Inc.",
     "category": "contenedores", "criticality": "high", "exposure": "interna",
     "aliases": ["Docker", {"alias": "Docker Engine", "match_mode": "phrase"},
                 {"alias": r"\bdocker\.io\b", "match_mode": "regex"}]},

    # ------------------------------------------------------------ directorio
    {"slug": "active-directory", "name": "Active Directory", "vendor": "Microsoft",
     "category": "directorio", "criticality": "high", "exposure": "interna",
     "notes": "Se excluye Entra ID / Azure AD: es un servicio distinto que no "
              "esta desplegado aqui.",
     "aliases": [{"alias": "Active Directory", "match_mode": "phrase"},
                 {"alias": "AD DS", "match_mode": "phrase"},
                 {"alias": "Azure Active Directory", "match_mode": "phrase",
                  "is_exclusion": True},
                 {"alias": "Entra ID", "match_mode": "phrase", "is_exclusion": True}]},
    {"slug": "openldap", "name": "OpenLDAP / LDAP", "vendor": "OpenLDAP Project",
     "category": "directorio", "criticality": "medium", "exposure": "interna",
     "aliases": ["OpenLDAP", "slapd", "ldap"]},

    # ----------------------------------------------------------- navegadores
    {"slug": "chrome", "name": "Google Chrome", "vendor": "Google",
     "category": "navegador", "criticality": "high", "exposure": "interna",
     "aliases": ["Chrome", "Chromium", {"alias": "Google Chrome", "match_mode": "phrase"}]},
    {"slug": "firefox", "name": "Mozilla Firefox", "vendor": "Mozilla",
     "category": "navegador", "criticality": "high", "exposure": "interna",
     "aliases": ["Firefox", {"alias": "Mozilla Firefox", "match_mode": "phrase"},
                 {"alias": r"\bMFSA\s?\d{4}-\d{1,3}\b", "match_mode": "regex"}]},
    {"slug": "edge", "name": "Microsoft Edge", "vendor": "Microsoft",
     "category": "navegador", "criticality": "high", "exposure": "interna",
     "notes": "El alias de una palabra exige contexto: 'edge' suelto aparece en "
              "'edge devices', 'cutting-edge' y 'network edge', que no son el "
              "navegador. Los limites de palabra ya evitan 'acknowledgement'.",
     "aliases": [{"alias": "Microsoft Edge", "match_mode": "phrase"},
                 {"alias": "Edge", "match_mode": "word",
                  "context_required": ["microsoft", "msedge", "chromium",
                                       "browser", "navegador", "edgehtml",
                                       "webview2"]},
                 {"alias": "edge device", "match_mode": "phrase", "is_exclusion": True},
                 {"alias": "edge devices", "match_mode": "phrase", "is_exclusion": True}]},
    {"slug": "brave", "name": "Brave Browser", "vendor": "Brave Software",
     "category": "navegador", "criticality": "medium", "exposure": "interna",
     "notes": "'brave' es tambien un adjetivo comun en ingles: exige contexto.",
     "aliases": [{"alias": "Brave Browser", "match_mode": "phrase"},
                 {"alias": "Brave", "match_mode": "word",
                  "context_required": ["browser", "navegador", "chromium",
                                       "brave software", "brave shields"]}]},

    # -------------------------------------------------- ofimatica y correo
    {"slug": "libreoffice", "name": "LibreOffice", "vendor": "The Document Foundation",
     "category": "ofimatica", "criticality": "medium", "exposure": "interna",
     "aliases": ["LibreOffice"]},
    {"slug": "thunderbird", "name": "Mozilla Thunderbird", "vendor": "Mozilla",
     "category": "correo", "criticality": "medium", "exposure": "interna",
     "aliases": ["Thunderbird"]},
    {"slug": "adobe-acrobat", "name": "Adobe Acrobat Reader", "vendor": "Adobe",
     "category": "ofimatica", "criticality": "medium", "exposure": "interna",
     "notes": "Sustituye al 'Adobe' generico de la lista antigua, que casaba con "
              "Adobe Campaign, ColdFusion o Commerce, ninguno instalado aqui.",
     "aliases": [{"alias": "Adobe Acrobat", "match_mode": "phrase"},
                 {"alias": "Adobe Reader", "match_mode": "phrase"},
                 {"alias": "Acrobat Reader", "match_mode": "phrase"},
                 {"alias": "Acrobat", "match_mode": "word"}]},
    {"slug": "pdf24", "name": "PDF24 Creator", "vendor": "geek software GmbH",
     "category": "ofimatica", "criticality": "low", "exposure": "interna",
     "aliases": ["PDF24"]},
    {"slug": "docusign", "name": "DocuSign", "vendor": "Docusign Inc.",
     "category": "gestion-documental", "criticality": "medium", "exposure": "internet",
     "notes": "En la lista antigua estaba escrito 'docusing'.",
     "aliases": ["DocuSign", "Docusign"]},

    # -------------------------------------------------------- desarrollo
    {"slug": "php", "name": "PHP", "vendor": "PHP Group",
     "category": "desarrollo", "criticality": "high", "exposure": "dmz",
     "notes": "El alias de regex recoge los nombres de paquete tipo 'php8.4', "
              "que un limite de palabra sobre 'php' se dejaria fuera.",
     "aliases": ["PHP", {"alias": r"\bphp\d+(?:\.\d+)*\b", "match_mode": "regex"},
                 {"alias": r"\bphp-fpm\b", "match_mode": "regex"}]},
    {"slug": "java", "name": "Java", "vendor": "Oracle / OpenJDK",
     "category": "desarrollo", "criticality": "high", "exposure": "interna",
     "notes": "Con limites de palabra 'java' ya no casa dentro de 'javascript' "
              "ni de 'javaserver'.",
     "aliases": ["Java", "OpenJDK", {"alias": "Oracle Java", "match_mode": "phrase"},
                 {"alias": r"\bJRE\b|\bJDK\b", "match_mode": "regex"}]},
    {"slug": "angular", "name": "Angular", "vendor": "Google",
     "category": "desarrollo", "criticality": "medium", "exposure": "interna",
     "notes": "'angular' es adjetivo en espanol ('corchete angular'): exige contexto.",
     "aliases": ["AngularJS",
                 {"alias": "Angular", "match_mode": "word",
                  "context_required": ["javascript", "typescript", "npm", "node",
                                       "framework", "angularjs", "frontend",
                                       "google"]}]},
    {"slug": "netbeans", "name": "Apache NetBeans", "vendor": "Apache Software Foundation",
     "category": "desarrollo", "criticality": "low", "exposure": "interna",
     "aliases": ["NetBeans"]},
    {"slug": "eclipse", "name": "Eclipse IDE", "vendor": "Eclipse Foundation",
     "category": "desarrollo", "criticality": "medium", "exposure": "interna",
     "notes": "'Eclipse' aparece en nombres de actores ('Nightmare-Eclipse', "
              "'Chaotic Eclipse'): exige contexto de entorno de desarrollo.",
     "aliases": [{"alias": "Eclipse IDE", "match_mode": "phrase"},
                 {"alias": "Eclipse Foundation", "match_mode": "phrase"},
                 {"alias": "Eclipse", "match_mode": "word",
                  "context_required": ["ide", "java", "plugin", "jdt", "equinox",
                                       "eclipse foundation", "workspace"]}]},
    {"slug": "jmeter", "name": "Apache JMeter", "vendor": "Apache Software Foundation",
     "category": "desarrollo", "criticality": "low", "exposure": "interna",
     "aliases": ["JMeter", {"alias": "Apache JMeter", "match_mode": "phrase"}]},
    {"slug": "subversion", "name": "Apache Subversion", "vendor": "Apache Software Foundation",
     "category": "desarrollo", "criticality": "medium", "exposure": "interna",
     "notes": "En la lista antigua figuraba como 'svn version control'.",
     "aliases": ["Subversion", {"alias": "Apache Subversion", "match_mode": "phrase"},
                 "TortoiseSVN", "svn"]},
    {"slug": "gitlab", "name": "GitLab", "vendor": "GitLab Inc.",
     "category": "desarrollo", "criticality": "high", "exposure": "dmz",
     "notes": "Repositorio de codigo accesible desde la red: criticidad alta.",
     "aliases": ["GitLab", {"alias": "GitLab CE", "match_mode": "phrase"},
                 {"alias": "GitLab EE", "match_mode": "phrase"}]},

    # ------------------------------------------------------- colaboracion
    {"slug": "moodle", "name": "Moodle", "vendor": "Moodle HQ",
     "category": "colaboracion", "criticality": "high", "exposure": "internet",
     "notes": "Plataforma publicada en Internet: criticidad alta.",
     "aliases": ["Moodle"]},
    {"slug": "carbonio", "name": "Zextras Carbonio", "vendor": "Zextras",
     "category": "correo", "criticality": "high", "exposure": "internet",
     "notes": "Correo publicado en Internet: criticidad alta.",
     "aliases": ["Carbonio", "Zextras",
                 {"alias": "Carbonio CE", "match_mode": "phrase"}]},
    {"slug": "owncloud", "name": "ownCloud", "vendor": "ownCloud GmbH",
     "category": "colaboracion", "criticality": "high", "exposure": "dmz",
     "aliases": ["ownCloud"]},
    {"slug": "mattermost", "name": "Mattermost", "vendor": "Mattermost Inc.",
     "category": "colaboracion", "criticality": "medium", "exposure": "dmz",
     "aliases": ["Mattermost"]},
    {"slug": "tuleap", "name": "Tuleap", "vendor": "Enalean",
     "category": "colaboracion", "criticality": "medium", "exposure": "interna",
     "notes": "En la lista antigua aparecia dos veces: 'Tuleap' y 'tuleap'.",
     "aliases": ["Tuleap"]},
    {"slug": "dotproject", "name": "dotProject", "vendor": "dotProject",
     "category": "aplicacion", "criticality": "low", "exposure": "interna",
     "aliases": ["dotProject"]},
    {"slug": "livehelperchat", "name": "Live Helper Chat", "vendor": "Remigijus Kiminas",
     "category": "colaboracion", "criticality": "medium", "exposure": "internet",
     "aliases": [{"alias": "Live Helper Chat", "match_mode": "phrase"},
                 "livehelperchat"]},
    {"slug": "chatwoot", "name": "Chatwoot", "vendor": "Chatwoot Inc.",
     "category": "colaboracion", "criticality": "medium", "exposure": "internet",
     "aliases": ["Chatwoot"]},
    {"slug": "ofbiz", "name": "Apache OFBiz", "vendor": "Apache Software Foundation",
     "category": "aplicacion", "criticality": "high", "exposure": "dmz",
     "notes": "OFBiz acumula RCE criticas explotadas en cadena.",
     "aliases": ["OFBiz", {"alias": "Apache OFBiz", "match_mode": "phrase"}]},
    {"slug": "kawak", "name": "Kawak", "vendor": "Kawak",
     "category": "aplicacion", "criticality": "medium", "exposure": "internet",
     "aliases": ["Kawak"]},
    {"slug": "gestor-clientes", "name": "Gestor de Clientes", "vendor": "desarrollo propio",
     "category": "aplicacion", "criticality": "medium", "exposure": "interna",
     "notes": "Aplicacion interna: no tiene boletines publicos, se conserva para "
              "que la GUI la muestre en el inventario.",
     "aliases": [{"alias": "Gestor de Clientes", "match_mode": "phrase"},
                 {"alias": "Gestor Clientes", "match_mode": "phrase"}]},

    # ------------------------------------------------------ comunicaciones
    {"slug": "asterisk", "name": "Asterisk", "vendor": "Sangoma",
     "category": "comunicaciones", "criticality": "high", "exposure": "dmz",
     "notes": "'asterisk' es tambien el nombre del caracter '*': exige contexto "
              "de telefonia. Absorbe el 'central telefonica' de la lista antigua.",
     "aliases": [{"alias": "Asterisk PBX", "match_mode": "phrase"},
                 "FreePBX",
                 {"alias": "central telefonica", "match_mode": "phrase"},
                 {"alias": "central telefónica", "match_mode": "phrase"},
                 {"alias": "Asterisk", "match_mode": "word",
                  "context_required": ["sip", "pbx", "voip", "telephony",
                                       "telefonia", "telefonía", "sangoma",
                                       "pjsip", "iax", "ari"]}]},
    {"slug": "linphone", "name": "Linphone", "vendor": "Belledonne Communications",
     "category": "comunicaciones", "criticality": "medium", "exposure": "interna",
     "aliases": ["Linphone"]},

    # ------------------------------------------------------------ utilidades
    {"slug": "7-zip", "name": "7-Zip", "vendor": "Igor Pavlov",
     "category": "utilidad", "criticality": "medium", "exposure": "interna",
     "notes": "En la lista antigua estaba escrito '7zip'.",
     "aliases": ["7-Zip", "7zip", "p7zip"]},
    {"slug": "winrar", "name": "WinRAR", "vendor": "win.rar GmbH",
     "category": "utilidad", "criticality": "medium", "exposure": "interna",
     "aliases": ["WinRAR"]},
    {"slug": "notepad-plus-plus", "name": "Notepad++", "vendor": "Don Ho",
     "category": "utilidad", "criticality": "low", "exposure": "interna",
     "aliases": [{"alias": "Notepad++", "match_mode": "phrase"},
                 {"alias": "Notepad", "match_mode": "word"}]},
    {"slug": "textpad", "name": "TextPad", "vendor": "Helios Software",
     "category": "utilidad", "criticality": "low", "exposure": "interna",
     "aliases": ["TextPad"]},
    {"slug": "crystaldiskinfo", "name": "CrystalDiskInfo", "vendor": "Crystal Dew World",
     "category": "monitorizacion", "criticality": "low", "exposure": "interna",
     "notes": "En la lista antigua estaba escrito 'cristaldisk'.",
     "aliases": ["CrystalDiskInfo", "CrystalDiskMark", "CrystalDisk"]},
    {"slug": "manictime", "name": "ManicTime", "vendor": "Finkit",
     "category": "monitorizacion", "criticality": "low", "exposure": "interna",
     "aliases": ["ManicTime"]},
    {"slug": "aspell", "name": "GNU Aspell", "vendor": "GNU Project",
     "category": "utilidad", "criticality": "low", "exposure": "interna",
     "aliases": [{"alias": "GNU Aspell", "match_mode": "phrase"}, "aspell"]},
]


def _normalizar_alias(bruto: Any) -> Optional[dict[str, Any]]:
    """Acepta una cadena o un dict y devuelve la fila lista para tech_aliases."""
    if isinstance(bruto, str):
        bruto = {"alias": bruto}
    if not isinstance(bruto, dict):
        log.warning("definicion de alias no reconocida", extra={"valor": repr(bruto)[:120]})
        return None
    alias = str(bruto.get("alias", "")).strip()
    if not alias:
        return None
    contexto = bruto.get("context_required")
    return {
        "alias": alias,
        "match_mode": str(bruto.get("match_mode", "word")).lower(),
        "is_exclusion": 1 if bruto.get("is_exclusion") else 0,
        "context_required": (json.dumps(list(contexto), ensure_ascii=False)
                             if contexto else None),
    }


def _reforzar_generico(fila: dict[str, Any]) -> dict[str, Any]:
    """Un alias generico sin contexto recibe el contexto de vulnerabilidad."""
    if (not fila.get("is_exclusion") and fila.get("match_mode") in ("word", "phrase")
            and fila["alias"].lower() in GENERICOS_CON_CONTEXTO
            and not fila.get("context_required")):
        fila = dict(fila, context_required=json.dumps(list(CONTEXTO_VULNERABILIDAD),
                                                      ensure_ascii=False))
    return fila


def _exclusiones_de(slug: Optional[str]) -> list[dict[str, Any]]:
    return [{"alias": texto, "match_mode": "phrase", "is_exclusion": True}
            for texto in EXCLUSIONES_BASE.get((slug or "").lower(), ())]


def _escribir_alias(conn: sqlite3.Connection, technology_id: int,
                    definiciones: Sequence[Any]) -> int:
    """Reescribe los alias de una tecnologia. Devuelve cuantos quedan.

    Anade el contexto de vulnerabilidad a los alias genericos y las exclusiones
    base de la tecnologia (EXCLUSIONES_BASE) aunque la definicion no las traiga.
    """
    conn.execute("DELETE FROM tech_aliases WHERE technology_id=?", (technology_id,))
    fila_tec = conn.execute("SELECT slug FROM technologies WHERE id=?", (technology_id,)).fetchone()
    slug = fila_tec["slug"] if fila_tec else None
    definiciones = list(definiciones) + _exclusiones_de(slug)
    filas = []
    vistos: set[tuple[str, int]] = set()
    for bruto in definiciones:
        fila = _normalizar_alias(bruto)
        if fila is None:
            continue
        fila = _reforzar_generico(fila)
        clave = (fila["alias"].lower(), int(fila["is_exclusion"]))
        if clave in vistos:
            continue
        vistos.add(clave)
        # Validar antes de guardar: un regex roto en la base se arrastraria a
        # cada ejecucion, y aqui todavia se puede avisar.
        if compilar_alias(technology_id, fila["alias"], fila["match_mode"],
                          bool(fila["is_exclusion"]), fila["context_required"]) is None:
            continue
        filas.append((technology_id, fila["alias"], fila["match_mode"],
                      fila["is_exclusion"], fila["context_required"]))
    conn.executemany(
        "INSERT INTO tech_aliases(technology_id, alias, match_mode, is_exclusion, "
        "context_required) VALUES(?,?,?,?,?) "
        "ON CONFLICT(technology_id, alias, is_exclusion) DO UPDATE SET "
        "match_mode=excluded.match_mode, context_required=excluded.context_required",
        filas,
    )
    return len(filas)


def seed_inventario(conn: sqlite3.Connection, *, solo_nuevas: bool = True) -> dict[str, int]:
    """Siembra INVENTARIO_BASE en las tablas technologies y tech_aliases.

    Con `solo_nuevas=True` (lo normal) no toca nada de lo que ya existe: el
    usuario habra rellenado version_installed y systems_count desde la GUI y no
    hay que pisarselo.

    Con `solo_nuevas=False` refresca los metadatos y reescribe los alias, pero
    sigue conservando lo que es dato del usuario: version_installed,
    version_latest, systems_count, owner, criticality, exposure y enabled.
    """
    resumen = {"tecnologias_creadas": 0, "tecnologias_actualizadas": 0,
               "tecnologias_intactas": 0, "alias_escritos": 0}
    ahora = utcnow()

    for entrada in INVENTARIO_BASE:
        slug = entrada["slug"]
        fila = conn.execute("SELECT id FROM technologies WHERE slug=?", (slug,)).fetchone()

        if fila is None:
            cursor = conn.execute(
                "INSERT INTO technologies(slug, name, vendor, category, "
                "version_installed, criticality, systems_count, exposure, notes, "
                "enabled, created_at, updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,1,?,?)",
                (slug, entrada["name"], entrada.get("vendor"),
                 entrada.get("category", "aplicacion"), None,
                 entrada.get("criticality", "medium"), 0,
                 entrada.get("exposure", "interna"), entrada.get("notes"),
                 ahora, ahora),
            )
            technology_id = int(cursor.lastrowid)
            resumen["tecnologias_creadas"] += 1
            resumen["alias_escritos"] += _escribir_alias(conn, technology_id,
                                                         entrada.get("aliases", []))
            continue

        if solo_nuevas:
            resumen["tecnologias_intactas"] += 1
            continue

        technology_id = int(fila["id"])
        conn.execute(
            "UPDATE technologies SET name=?, vendor=?, category=?, notes=?, "
            "updated_at=? WHERE id=?",
            (entrada["name"], entrada.get("vendor"),
             entrada.get("category", "aplicacion"), entrada.get("notes"),
             ahora, technology_id),
        )
        resumen["tecnologias_actualizadas"] += 1
        resumen["alias_escritos"] += _escribir_alias(conn, technology_id,
                                                     entrada.get("aliases", []))

    audit(conn, "system", "seed_inventario", entity="technologies",
          detail=json.dumps(resumen, ensure_ascii=False))
    log.info("inventario sembrado", extra=dict(resumen, solo_nuevas=solo_nuevas))
    return resumen


def aplicar_precision_alias(conn: sqlite3.Connection, *, aplicar: bool = False) -> dict[str, Any]:
    """Lleva a una base existente las reglas de precision del 2026-09-04 sin
    borrar alias del operador: contexto de vulnerabilidad en los alias genericos
    y exclusiones base de cada tecnologia. Idempotente: la segunda pasada no
    cambia nada. Con ``aplicar=False`` solo describe lo que cambiaria."""
    contexto_json = json.dumps(list(CONTEXTO_VULNERABILIDAD), ensure_ascii=False)
    cambios: dict[str, list[tuple[str, str]]] = {"contexto": [], "exclusiones": []}

    for fila in conn.execute(
            """SELECT a.id, a.alias, a.match_mode, a.context_required, t.slug
                 FROM tech_aliases a JOIN technologies t ON t.id = a.technology_id
                WHERE a.is_exclusion = 0 AND a.match_mode IN ('word', 'phrase')"""):
        contexto = (fila["context_required"] or "").strip()
        if fila["alias"].lower() in GENERICOS_CON_CONTEXTO and contexto in ("", "[]", "null"):
            cambios["contexto"].append((fila["slug"], fila["alias"]))
            if aplicar:
                conn.execute("UPDATE tech_aliases SET context_required=? WHERE id=?",
                             (contexto_json, fila["id"]))

    for slug, textos in EXCLUSIONES_BASE.items():
        tec = conn.execute("SELECT id FROM technologies WHERE slug=?", (slug,)).fetchone()
        if tec is None:
            continue
        existentes = {r[0].lower() for r in conn.execute(
            "SELECT alias FROM tech_aliases WHERE technology_id=? AND is_exclusion=1", (tec["id"],))}
        for texto in textos:
            if texto.lower() in existentes:
                continue
            cambios["exclusiones"].append((slug, texto))
            if aplicar:
                conn.execute(
                    "INSERT INTO tech_aliases(technology_id, alias, match_mode, is_exclusion, "
                    "context_required) VALUES(?,?,?,1,NULL) "
                    "ON CONFLICT(technology_id, alias, is_exclusion) DO NOTHING",
                    (tec["id"], texto, "phrase"))

    if aplicar and (cambios["contexto"] or cambios["exclusiones"]):
        audit(conn, "system", "precision_alias", entity="tech_aliases",
              detail=json.dumps({k: len(v) for k, v in cambios.items()}, ensure_ascii=False))
    return cambios


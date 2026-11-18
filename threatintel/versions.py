"""Extraccion y comparacion de versiones en boletines de seguridad.

Por que existe este modulo:
El sistema anterior marcaba una tecnologia como afectada por el simple hecho de
que su nombre apareciese en el texto, sin mirar nunca la version instalada. El
resultado era una alerta indistinguible de ruido: "Debian afectado" 925 veces en
un mes. Aqui se traduce la prosa del boletin ("prior to 4.3", "fixed in 19.2.2",
"anteriores a 4.3") a restricciones comparables con `technologies.version_installed`.

Principio rector: PRUDENCIA. Ante cualquier ambiguedad se devuelve 'unknown', nunca
'not_affected'. Un falso negativo en seguridad (dar por seguro algo vulnerable) es
mucho peor que un falso positivo (revisar algo que no hacia falta).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Optional, Sequence, Union

from .logging_setup import get_logger

log = get_logger("versions")

OPERADORES = ("<", "<=", ">", ">=", "==", "!=")

# Veredictos posibles de `evaluar`
AFFECTED = "affected"
NOT_AFFECTED = "not_affected"
UNKNOWN = "unknown"

# --------------------------------------------------------------------------
# Analisis de una version suelta
# --------------------------------------------------------------------------

# Marcas de prerelease: 4.3-rc1 es ANTERIOR a 4.3
_PRERELEASE = {"rc", "beta", "alpha", "pre", "dev", "snapshot", "milestone", "m", "a"}
# Marcas de parche: 4.3-p2 es POSTERIOR a 4.3
_PARCHE = {"p", "patch", "patched", "sp", "u", "update", "build", "b", "r", "rev",
           "hf", "hotfix", "fix", "release", "el"}

_RE_NUCLEO = re.compile(r"^[vV]?(\d+(?:\.\d+)*)(.*)$", re.DOTALL)
_RE_SUFIJO = re.compile(r"^[\s\-_.+]*([A-Za-z]+)[\s\-_.]*(\d*)")


def parse_version(texto: Union[str, tuple, None]) -> Optional[tuple]:
    """'4.3.1' -> (4,3,1). Tolera 'v15', '4.3-p2', '8u45', '4.3-rc1'.

    Las marcas de parche se anaden como componente adicional ('4.3-p2' -> (4,3,2)).
    Las de prerelease se marcan con un componente negativo ('4.3-rc1' -> (4,3,-1,1))
    para que `comparar` las ordene por debajo de la version final. Devuelve None si
    el texto no empieza por un numero: preferimos no saber a inventar.
    """
    if texto is None:
        return None
    if isinstance(texto, tuple):
        return texto
    if isinstance(texto, list):
        try:
            return tuple(int(x) for x in texto)
        except (TypeError, ValueError):
            log.debug("lista de version no interpretable", extra={"valor": repr(texto)[:60]})
            return None

    cadena = str(texto).strip()
    if not cadena:
        return None

    nucleo = _RE_NUCLEO.match(cadena)
    if nucleo is None:
        return None

    try:
        partes = [int(x) for x in nucleo.group(1).split(".")]
    except ValueError:
        log.debug("version no interpretable", extra={"valor": cadena[:60]})
        return None

    resto = nucleo.group(2) or ""
    sufijo = _RE_SUFIJO.match(resto)
    if sufijo is not None:
        marca = sufijo.group(1).lower()
        numero = int(sufijo.group(2)) if sufijo.group(2) else 0
        if marca in _PRERELEASE:
            partes.extend((-1, numero))
        elif marca in _PARCHE:
            partes.append(numero)
        # Cualquier otra palabra ('4.3 stable', '4.3 and earlier') se ignora:
        # no aporta orden y no queremos adivinar.

    return tuple(partes)


def comparar(a: Union[str, tuple, None], b: Union[str, tuple, None]) -> int:
    """-1 si a<b, 0 si a==b, 1 si a>b. Acepta cadenas o tuplas y tolera None.

    Rellena con ceros la mas corta, de modo que '4.3' == '4.3.0'. None se considera
    "sin version" y ordena por debajo de cualquier version concreta.
    """
    ta = a if isinstance(a, tuple) else parse_version(a)
    tb = b if isinstance(b, tuple) else parse_version(b)

    if ta is None and tb is None:
        return 0
    if ta is None:
        return -1
    if tb is None:
        return 1

    largo = max(len(ta), len(tb))
    ta = tuple(ta) + (0,) * (largo - len(ta))
    tb = tuple(tb) + (0,) * (largo - len(tb))
    return (ta > tb) - (ta < tb)


# --------------------------------------------------------------------------
# Restricciones
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Restriccion:
    """Una condicion de version extraida del boletin, p.ej. ('<', '4.3')."""

    operador: str
    version: str

    def __post_init__(self) -> None:
        if self.operador not in OPERADORES:
            raise ValueError(f"Operador no valido: {self.operador!r}")

    def __str__(self) -> str:
        return f"{self.operador} {self.version}"

    @property
    def tupla(self) -> Optional[tuple]:
        return parse_version(self.version)

    def cumple(self, version_instalada: Union[str, tuple, None]) -> Optional[bool]:
        """True si la version instalada satisface la restriccion (=> es vulnerable).

        None si no se puede decidir porque alguna de las dos versiones no se
        interpreta. El que llama debe tratar None como 'unknown'.
        """
        propia = self.tupla
        otra = (version_instalada if isinstance(version_instalada, tuple)
                else parse_version(version_instalada))
        if propia is None or otra is None:
            return None
        signo = comparar(otra, propia)
        if self.operador == "<":
            return signo < 0
        if self.operador == "<=":
            return signo <= 0
        if self.operador == ">":
            return signo > 0
        if self.operador == ">=":
            return signo >= 0
        if self.operador == "==":
            return signo == 0
        return signo != 0  # '!='


# Token de version. El sufijo de parche exige una letra ('-p2', 'u45') para que
# '4.0-4.2' no se lea como un solo token con parche.
_T = r"[vV]?\d+(?:\.\d+)*(?:[-_.]?(?:p|patch|sp|rc|beta|alpha|build|update|u)\d*)?"

# Identificadores que contienen numeros y NO son versiones.
_RE_IDENTIFICADORES = re.compile(
    r"\b(?:CVE|DSA|DLA|USN|MFSA|RHSA|RHBA|GHSA|ELSA|ALAS|VU|ZDI|MS)[-#]?\d{2,}(?:[-:]\d+)*",
    re.IGNORECASE,
)

# Comodines de rama: '4.2.x' o '4.2.*'. Un '<= 4.2' extraido de "4.2.x and earlier"
# declararia 'not_affected' una 4.2.5 que SI es vulnerable, asi que ante un comodin
# se descarta la restriccion entera y el veredicto se queda en 'unknown'.
_RE_COMODIN = re.compile(r"^\s*\.\s*[xX*]")

# Enumeraciones: "fixed in 19.2.2, 19.1.4 and 18.5.9" son tres limites, no uno.
_RE_CONTINUACION = re.compile(
    rf"\s*(?:,|;|/|\band\b|\bor\b|\by\b|\bo\b)\s*({_T})", re.IGNORECASE)

# (patron, operadores, enumeracion). Un operador por grupo capturado del patron.
# `enumeracion=True` significa que tras el ultimo grupo puede venir una lista de
# versiones mas que comparten operador ("prior to 4.3, 5.1 and 6.0").
# El orden importa: lo mas especifico primero, y los rangos antes que los limites
# sueltos, porque cada coincidencia consume su trozo de texto.
_PATRONES: tuple[tuple[str, tuple[str, ...], bool], ...] = (
    # --- rangos: dos restricciones de una sola frase ---
    (rf"(?:affects?|affected|impacts?|vulnerable)\s+(?:only\s+)?(?:versions?\s+)?"
     rf"({_T})\s*(?:-|--|–|—|\.\.)\s*({_T})", (">=", "<="), False),
    (rf"versions?\s+({_T})\s*(?:-|--|–|—|\.\.)\s*({_T})", (">=", "<="), False),
    (rf"(?:from|between|desde|entre)\s+(?:the\s+)?(?:versions?|releases?|builds?|"
     rf"versi(?:on|ón)(?:es)?)\s+({_T})\s+"
     rf"(?:to|and|through|until|up\s+to|a|hasta|y)\s+(?:versions?\s+|la\s+)?({_T})",
     (">=", "<="), False),
    (rf"({_T})\s+(?:through|thru)\s+({_T})", (">=", "<="), False),
    # --- "fixed in X" => todo lo anterior es vulnerable ---
    (rf"(?:fixed|patched|resolved|corrected|addressed|remediated)\s+in\s+"
     rf"(?:version|release)?\s*({_T})", ("<",), True),
    # "the fixed release is version 10.3.6 and later" es un fixed-in, no un
    # limite inferior: hay que consumirlo antes que los patrones de ">=".
    (rf"(?:fix(?:ed)?|patched|corrected|resolved|remediated|secure)\s+"
     rf"(?:version|release|build)s?\s*(?:is|are|was|were)?\s*:?\s*"
     rf"(?:versions?\s+)?({_T})", ("<",), True),
    (rf"(?:corregid[oa]s?|corrige[n]?|solucionad[oa]s?|soluciona[n]?|parchead[oa]s?"
     rf"|arreglad[oa]s?|resuelt[oa]s?|subsanad[oa]s?)\s+en\s+"
     rf"(?:la\s+)?(?:versi[oó]n\s+)?({_T})", ("<",), True),
    (rf"(?:upgrade|update|upgrading|updating)\s+to\s+(?:version\s+)?({_T})", ("<",), True),
    (rf"(?:actualizar|actualice|actualizad?)\s+a\s+(?:la\s+)?(?:versi[oó]n\s+)?({_T})", ("<",), True),
    (rf"(?:released?|releases|publish(?:ed|es)?|shipped)\s+(?:security\s+)?"
     rf"(?:versions?|releases?|updates?|patch(?:es)?|builds?)\s+({_T})", ("<",), True),
    (rf"(?:publica|publicado|libera|liberado)\s+(?:la\s+)?"
     rf"(?:versi[oó]n|actualizaci[oó]n)\s+({_T})", ("<",), True),
    # --- limites superiores explicitos ---
    (rf"up\s+to\s+and\s+including\s+(?:versions?\s+)?({_T})", ("<=",), True),
    (rf"up\s+to\s+(?:but\s+not\s+including|excluding)\s+(?:versions?\s+)?({_T})", ("<",), True),
    (rf"(?:prior\s+to|before|earlier\s+than|older\s+than|lower\s+than|below)\s+"
     rf"(?:versions?\s+)?({_T})", ("<",), True),
    (rf"(?:anteriores?\s+a|antes\s+de|previas?\s+a|inferiores?\s+a)\s+"
     rf"(?:la\s+)?(?:versi[oó]n\s+)?({_T})", ("<",), True),
    (rf"(?:through|thru|inclusive\s+of)\s+(?:versions?\s+)?({_T})", ("<=",), True),
    (rf"hasta\s+(?:la\s+|el\s+|las\s+)?(?:versi[oó]n\s+)?({_T})", ("<=",), True),
    (rf"({_T})(?:\s+(?:build|release|revision|patch|rev)\s+\d+)?\s+"
     rf"(?:and|or)\s+(?:earlier|older|below|prior|previous|lower)", ("<=",), True),
    (rf"({_T})(?:\s+(?:build|compilaci[oó]n|revisi[oó]n)\s+\d+)?\s+"
     rf"(?:y|o)\s+(?:anteriores|inferiores|previas|menores)", ("<=",), True),
    # --- limites inferiores ---
    (rf"({_T})\s+(?:and|or)\s+(?:later|newer|above|higher|greater)", (">=",), False),
    (rf"({_T})\s+(?:y|o)\s+(?:posteriores|superiores|mayores)", (">=",), False),
    (rf"(?:since|starting\s+(?:with|in|from)|desde\s+la)\s+(?:versions?\s+)?({_T})", (">=",), False),
    # --- operadores escritos tal cual ---
    (rf"versions?\s*<=\s*({_T})", ("<=",), False),
    (rf"versions?\s*>=\s*({_T})", (">=",), False),
    (rf"versions?\s*(?:<|&lt;)\s*({_T})", ("<",), False),
    (rf"versions?\s*(?:>|&gt;)\s*({_T})", (">",), False),
    (rf"versions?\s*(?:!=|<>)\s*({_T})", ("!=",), False),
    (rf"versions?\s*==?\s*({_T})", ("==",), False),
    (rf"<=\s*({_T})", ("<=",), False),
    (rf">=\s*({_T})", (">=",), False),
    (rf"(?:<|&lt;)\s*({_T})", ("<",), False),
    (rf"(?:>|&gt;)\s*({_T})", (">",), False),
    # --- igualdad prudente: solo cuando el texto lo afirma ---
    (rf"versions?\s+({_T})\s+(?:is|are)\s+(?:affected|vulnerable)", ("==",), False),
    (rf"(?:la\s+)?versi[oó]n\s+({_T})\s+(?:esta|est[aá]|es)\s+(?:afectada|vulnerable)", ("==",), False),
)

_COMPILADOS = tuple((re.compile(p, re.IGNORECASE), ops, enum)
                    for p, ops, enum in _PATRONES)


# Delante de un "from 5.9 to 8.1" puede haber una puntuacion CVSS, no un rango de
# versiones. Confundirlas dejaria una version instalada fuera del rango y el
# veredicto seria 'not_affected': el falso negativo que hay que evitar a toda costa.
_RE_RUIDO_PREVIO = re.compile(
    r"(?:cvss|score|scores|scoring|puntuaci[oó]n|rating|severity|severidad|"
    r"epss|probabilit|percentile)[^.]{0,30}$", re.IGNORECASE)


def _limpiar_token(bruto: str) -> Optional[str]:
    """Normaliza un token de version y descarta lo que parezca un ano suelto.

    'v15' -> '15'. '2026' sin puntos se rechaza: casi siempre es un ano o un
    identificador, y confundirlo con una version produciria veredictos falsos.
    """
    token = bruto.strip().strip(".,;:()[]")
    if not token:
        return None
    tenia_v = token[0] in "vV"
    if tenia_v:
        token = token[1:]
    if not token or not token[0].isdigit():
        return None
    if "." not in token and not tenia_v:
        soloc = re.match(r"^(\d+)$", token)
        if soloc is not None and not (10 <= int(soloc.group(1)) <= 999):
            # Un digito suelto ('released 8 patches'), un ano ('2026') o un
            # numero de compilacion ('build 9398') no son versiones comparables.
            return None
    return token


def extraer_restricciones(texto: Optional[str]) -> list[Restriccion]:
    """Traduce la prosa del boletin a una lista de restricciones de version.

    Cada coincidencia consume su fragmento de texto para que un mismo numero no se
    cuente dos veces con dos operadores distintos, y los patrones se prueban de mas
    especifico a mas generico.
    """
    if not texto:
        return []

    trabajo = _RE_IDENTIFICADORES.sub(" ", str(texto))
    encontradas: list[Restriccion] = []
    vistas: set[tuple[str, str]] = set()

    for patron, operadores, enumeracion in _COMPILADOS:
        for match in list(patron.finditer(trabajo)):
            indices = [i for i in range(1, patron.groups + 1) if match.group(i) is not None]
            if len(indices) < len(operadores):
                continue

            if _RE_RUIDO_PREVIO.search(trabajo[max(0, match.start() - 40):match.start()]):
                continue
            nuevas: list[Restriccion] = []
            valido = True
            for operador, indice in zip(operadores, indices):
                if _RE_COMODIN.match(trabajo[match.end(indice):match.end(indice) + 3]):
                    valido = False   # '4.2.x': rama abierta, no se puede acotar
                    break
                token = _limpiar_token(match.group(indice))
                if token is None:
                    valido = False
                    break
                nuevas.append(Restriccion(operador, token))
            if not valido or not nuevas:
                continue

            fin = match.end()
            if enumeracion:
                posicion = match.end(indices[-1])
                operador = nuevas[-1].operador
                while True:
                    cont = _RE_CONTINUACION.match(trabajo, posicion)
                    if cont is None:
                        break
                    if _RE_COMODIN.match(trabajo[cont.end(1):cont.end(1) + 3]):
                        break
                    token = _limpiar_token(cont.group(1))
                    if token is None:
                        break
                    nuevas.append(Restriccion(operador, token))
                    posicion = cont.end()
                fin = max(fin, posicion)

            for restriccion in nuevas:
                clave = (restriccion.operador, restriccion.version)
                if clave not in vistas:
                    vistas.add(clave)
                    encontradas.append(restriccion)

            # Tachar el fragmento ya interpretado, conservando las posiciones.
            trabajo = trabajo[:match.start()] + " " * (fin - match.start()) + trabajo[fin:]

    return encontradas


# --------------------------------------------------------------------------
# Veredicto
# --------------------------------------------------------------------------
def _texto_restricciones(restricciones: Sequence[Restriccion]) -> str:
    return ", ".join(str(r) for r in restricciones)


def evaluar(version_instalada: Optional[str],
            restricciones: Optional[Iterable[Restriccion]]) -> tuple[str, str]:
    """Decide si la version instalada esta afectada. Devuelve (veredicto, evidencia).

    Semantica deliberada de los limites superiores: varios '<' en el mismo boletin
    suelen referirse a ramas distintas ("prior to 4.3.7 and prior to 5.1.2"), asi
    que basta cumplir UNO para considerarse afectado. Solo si la version instalada
    supera TODOS los limites se declara 'not_affected'.
    """
    if version_instalada is None or not str(version_instalada).strip():
        return UNKNOWN, "versión no registrada en el inventario"

    instalada = str(version_instalada).strip()
    lista = [r for r in (restricciones or [])]
    if not lista:
        return UNKNOWN, "el anuncio no especifica versiones"

    if parse_version(instalada) is None:
        return UNKNOWN, f"no se pudo interpretar la version instalada '{instalada}'"

    evaluables = [(r, r.cumple(instalada)) for r in lista]
    evaluables = [(r, c) for r, c in evaluables if c is not None]
    if not evaluables:
        return UNKNOWN, (f"anuncio: {_texto_restricciones(lista)} | instalado: {instalada} "
                         "| no se pudieron interpretar las versiones del anuncio")

    cabecera = (f"anuncio: {_texto_restricciones([r for r, _ in evaluables])} "
                f"| instalado: {instalada}")

    superiores = [(r, c) for r, c in evaluables if r.operador in ("<", "<=")]
    inferiores = [(r, c) for r, c in evaluables if r.operador in (">", ">=")]
    iguales = [(r, c) for r, c in evaluables if r.operador == "=="]
    distintos = [(r, c) for r, c in evaluables if r.operador == "!="]

    if any(c for _, c in iguales):
        return AFFECTED, f"{cabecera} | el anuncio senala esa version como vulnerable"

    if superiores:
        dentro_sup = any(c for _, c in superiores)
        if not dentro_sup:
            return NOT_AFFECTED, (f"{cabecera} | la version instalada es igual o posterior "
                                  "a todas las corregidas")
        if inferiores and not any(c for _, c in inferiores):
            return UNKNOWN, (f"{cabecera} | la version instalada es anterior al rango "
                             "indicado; conviene revisarla a mano")
        return AFFECTED, f"{cabecera} | la version instalada esta en el rango afectado"

    if inferiores:
        if any(c for _, c in inferiores):
            return AFFECTED, f"{cabecera} | la version instalada esta en el rango afectado"
        return UNKNOWN, (f"{cabecera} | la version instalada queda fuera del rango "
                         "indicado, pero el anuncio no fija un limite superior")

    if iguales:
        return UNKNOWN, (f"{cabecera} | el anuncio solo cita versiones concretas y ninguna "
                         "coincide; conviene revisarla a mano")

    if distintos and not all(c for _, c in distintos):
        return NOT_AFFECTED, f"{cabecera} | el anuncio excluye expresamente esa version"

    return UNKNOWN, f"{cabecera} | no se pudo decidir con las condiciones del anuncio"

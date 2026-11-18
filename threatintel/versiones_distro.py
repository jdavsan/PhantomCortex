"""Comparación de versiones de paquetes de distribución.

La comparación genérica de ``versions.py`` sirve para «versiones anteriores a
4.3» en un aviso. Pero decidir si el paquete ``curl 8.5.0-2ubuntu10.13`` de un
servidor Ubuntu ya lleva la corrección ``8.5.0-2ubuntu10.16`` exige las reglas
exactas de cada distribución:

* **dpkg** (Debian y Ubuntu): ``[época:]versión[-revisión]`` con el orden
  especial de ``~`` (anterior a todo) y de letras frente a signos. Es el mismo
  algoritmo que ``dpkg --compare-versions``.
* **pkg** (FreeBSD): ``versión[_revisión][,época]``; los componentes se separan
  por puntos y cada uno lleva número, letras y número («9.9.p2_1,1»). El
  sistema base se expresa como ``14.4_6`` para «14.4-RELEASE-p6».

Además de comparar, el módulo **explica** la comparación en español
(``explicar_comparacion``): el equipo que aplica el parche necesita entender por qué
``1.11.1-1build2`` es anterior a ``1.11.1-1ubuntu0.26.04.2`` cuando la versión de
origen es la misma y solo cambia la revisión del paquete.

Sin dependencias externas: todo es texto, y todo tiene prueba en
tests/test_activos_ocs.py y tests/test_precision_versiones.py.
"""
from __future__ import annotations

import re
from itertools import zip_longest
from typing import Optional


# --------------------------------------------------------------------------
# dpkg (Debian / Ubuntu)
# --------------------------------------------------------------------------
def _orden_dpkg(c: str) -> int:
    """Orden de un carácter no numérico según dpkg: ``~`` antes que el fin de
    cadena, las letras por su código y el resto de signos después de las letras."""
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _verrevcmp(a: str, b: str) -> int:
    """Compara dos fragmentos (versión o revisión) con el algoritmo de dpkg."""
    i = j = 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        primera_dif = 0
        while (i < la and not a[i].isdigit()) or (j < lb and not b[j].isdigit()):
            ac = _orden_dpkg(a[i]) if i < la else 0
            bc = _orden_dpkg(b[j]) if j < lb else 0
            if ac != bc:
                return -1 if ac < bc else 1
            i += 1
            j += 1
        while i < la and a[i] == "0":
            i += 1
        while j < lb and b[j] == "0":
            j += 1
        while i < la and j < lb and a[i].isdigit() and b[j].isdigit():
            if not primera_dif:
                primera_dif = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < la and a[i].isdigit():
            return 1
        if j < lb and b[j].isdigit():
            return -1
        if primera_dif:
            return -1 if primera_dif < 0 else 1
    return 0


def dividir_dpkg(version: Optional[str]) -> tuple[int, str, str]:
    """'1:9.6p1-3ubuntu13.19' -> (1, '9.6p1', '3ubuntu13.19')."""
    v = (version or "").strip()
    epoca = 0
    if ":" in v:
        cabeza, _, resto = v.partition(":")
        if cabeza.isdigit():
            epoca = int(cabeza)
            v = resto
    if "-" in v:
        upstream, _, revision = v.rpartition("-")
    else:
        upstream, revision = v, ""
    return epoca, upstream, revision


def comparar_dpkg(a: Optional[str], b: Optional[str]) -> int:
    """-1, 0 o 1 como ``dpkg --compare-versions``."""
    ea, ua, ra = dividir_dpkg(a)
    eb, ub, rb = dividir_dpkg(b)
    if ea != eb:
        return -1 if ea < eb else 1
    r = _verrevcmp(ua, ub)
    if r:
        return r
    return _verrevcmp(ra, rb)


def version_upstream(version: Optional[str]) -> str:
    """Versión «de programa» sin época ni revisión: '1:9.6p1-3ubuntu13.19' -> '9.6p1'.
    Es lo que se compara con los rangos de un aviso genérico («anterior a 9.7»)."""
    return dividir_dpkg(version)[1]


# --------------------------------------------------------------------------
# pkg (FreeBSD)
# --------------------------------------------------------------------------
_RE_TROZO_PKG = re.compile(r"(\d*)([A-Za-z]*)(\d*)")


def dividir_pkg(version: Optional[str]) -> tuple[int, str, int]:
    """'9.9.p2_1,1' -> (1, '9.9.p2', 1): (época, versión, revisión)."""
    v = (version or "").strip()
    epoca = revision = 0
    if "," in v:
        v, _, e = v.rpartition(",")
        epoca = int(e) if e.isdigit() else 0
    if "_" in v:
        v, _, r = v.rpartition("_")
        revision = int(r) if r.isdigit() else 0
    return epoca, v, revision


def _peso_letras(letras: str) -> int:
    """Sin letras: 0. «pl» y «p» (nivel de parche) también 0: el número que sigue
    manda. Otras letras ordenan por su primer carácter (a < b < rc…)."""
    if not letras or letras.lower() in ("pl", "p"):
        return 0
    return ord(letras[0].lower())


def _componentes_pkg(v: str) -> list[tuple[int, int, int]]:
    salida: list[tuple[int, int, int]] = []
    for trozo in re.split(r"[.+\-]", v):
        pos = 0
        while pos < len(trozo):
            m = _RE_TROZO_PKG.match(trozo, pos)
            if not m or not m.group(0):
                pos += 1
                continue
            n1, letras, n2 = m.groups()
            salida.append((int(n1) if n1 else 0, _peso_letras(letras), int(n2) if n2 else 0))
            pos = m.end()
    return salida


def comparar_pkg(a: Optional[str], b: Optional[str]) -> int:
    """-1, 0 o 1 con las reglas de ``pkg version``."""
    ea, va, ra = dividir_pkg(a)
    eb, vb, rb = dividir_pkg(b)
    if ea != eb:
        return -1 if ea < eb else 1
    for x, y in zip_longest(_componentes_pkg(va), _componentes_pkg(vb), fillvalue=(0, 0, 0)):
        if x != y:
            return -1 if x < y else 1
    if ra != rb:
        return -1 if ra < rb else 1
    return 0


_RE_FREEBSD_BASE = re.compile(r"^\s*(\d+\.\d+)(?:-[A-Za-z]+\d*)*?(?:-p(\d+))?\s*$")


def version_base_freebsd(osversion: Optional[str]) -> Optional[str]:
    """'14.4-RELEASE-p6' -> '14.4_6'; '15.0-RELEASE' -> '15.0'. Es la notación que
    usa VuXML para los paquetes FreeBSD y FreeBSD-kernel."""
    m = _RE_FREEBSD_BASE.match(osversion or "")
    if not m:
        return None
    return m.group(1) + (f"_{m.group(2)}" if m.group(2) else "")


# --------------------------------------------------------------------------
# Comparación según la familia y rangos de VuXML
# --------------------------------------------------------------------------
def comparar(familia: Optional[str], a: Optional[str], b: Optional[str]) -> int:
    fam = (familia or "").lower()
    if fam == "freebsd":
        return comparar_pkg(a, b)
    if fam in ("debian", "ubuntu"):
        return comparar_dpkg(a, b)
    from . import versions
    return versions.comparar(a, b)


_OPERADORES_RANGO = {
    "lt": lambda c: c < 0, "le": lambda c: c <= 0,
    "gt": lambda c: c > 0, "ge": lambda c: c >= 0, "eq": lambda c: c == 0,
}


def en_rango_pkg(version: Optional[str], limites: dict[str, str]) -> bool:
    """¿Cumple ``version`` TODOS los límites de un <range> de VuXML
    ({'ge': '14.4', 'lt': '14.4_9'})? Un rango vacío no acota nada."""
    if not limites:
        return False
    for operador, referencia in limites.items():
        prueba = _OPERADORES_RANGO.get(operador)
        if prueba is None or not prueba(comparar_pkg(version, referencia)):
            return False
    return True


def texto_rango(limites: dict[str, str]) -> str:
    simbolos = {"lt": "<", "le": "≤", "gt": ">", "ge": "≥", "eq": "="}
    return " y ".join(f"{simbolos.get(k, k)} {v}" for k, v in limites.items())


# --------------------------------------------------------------------------
# Explicacion legible de la comparacion (2026-09-06)
# --------------------------------------------------------------------------
# El usuario pidio mas precision: en la tabla de activos afectados el 65 % de las filas
# ensenaban una version instalada y una corregida que «parecen iguales»
# («1.11.1-1build2 -> 1.11.1-1ubuntu0.26.04.2») porque solo cambia la revision del
# paquete, que es justo donde Debian, Ubuntu y FreeBSD aplican el parche de seguridad.
# La comparacion era correcta (el orden de dpkg lo confirma), pero no se entendia. Estas
# funciones devuelven la frase que lo explica y los trozos con los que pintarla, mas la
# orden con la que cualquiera puede verificarlo en el propio servidor.
DISTRIBUCION_ES = {"debian": "Debian", "ubuntu": "Ubuntu", "freebsd": "FreeBSD",
                   "windows": "Windows"}

#: Textos de respaldo para el dato que NO existe. Nunca se escribe un cero ni una epoca
#: que la cadena de version no lleva: si el dato no lo dice, la frase lo dice con palabras
#: (revision adversaria del 2026-09-06, hallazgo 6).
SIN_REVISION = "sin revisión de paquete"
SIN_NIVEL_PARCHE = "sin nivel de parche"
SIN_EPOCA = "sin época"
SIN_ACTUALIZACION = "sin número de actualización acumulativa"

_RE_BUILD_WINDOWS = re.compile(r"^\s*(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?\s*$")


def _familia_normalizada(familia: Optional[str]) -> str:
    fam = (familia or "").strip().lower()
    if fam in ("debian", "ubuntu", "freebsd", "windows"):
        return fam
    return "otro"


def _vacia(dato: Optional[str]) -> bool:
    return not (dato or "").strip()


def epoca_escrita_dpkg(version: Optional[str]) -> bool:
    """¿La cadena lleva la época escrita («1:9.6p1-3»)? ``dividir_dpkg`` devuelve 0 tanto
    cuando la época es 0 como cuando no hay época, y decir «0:9.6p1» sería inventarla."""
    cabeza, dos_puntos, _ = (version or "").strip().partition(":")
    return bool(dos_puntos) and cabeza.isdigit()


def epoca_escrita_pkg(version: Optional[str]) -> bool:
    """¿La cadena lleva la época escrita («3.0.22,1»)? Igual que en dpkg: sin coma no hay
    época y escribir «3.0.16,0» sería inventarla."""
    _, coma, cola = (version or "").strip().rpartition(",")
    return bool(coma) and cola.isdigit()


def _texto_epoca_dpkg(original: Optional[str], origen: str, epoca: int) -> str:
    """«1:9.6p1» si la época está en el dato; «9.6p1 (sin época)» si no lo está."""
    return f"{epoca}:{origen}" if epoca_escrita_dpkg(original) else f"{origen} ({SIN_EPOCA})"


def _texto_epoca_pkg(original: Optional[str], version: str, epoca: int) -> str:
    """«3.0.22,1» si la época está en el dato; «3.0.16 (sin época)» si no lo está."""
    return f"{version},{epoca}" if epoca_escrita_pkg(original) else f"{version} ({SIN_EPOCA})"


def _de_a(desde: Optional[str], hasta: Optional[str], respaldo: str) -> str:
    """«del 1 al 4», «de sin nivel de parche al 9», «del 1 a sin nivel de parche»: el
    número solo aparece cuando el dato lo trae."""
    texto_desde = f"del {desde}" if desde else f"de {respaldo}"
    texto_hasta = f"al {hasta}" if hasta else f"a {respaldo}"
    return f"{texto_desde} {texto_hasta}"


def _explicacion_base(familia: str, instalada: Optional[str], corregida: Optional[str]) -> dict:
    return {"familia": familia, "distribucion": DISTRIBUCION_ES.get(familia, ""),
            "instalada": (instalada or "").strip() or None,
            "corregida": (corregida or "").strip() or None,
            "misma_origen": False, "identicas": False, "origen": None,
            "revision_instalada": None, "revision_corregida": None,
            "orden": None, "texto": "", "verificacion": None}


def _explicar_dpkg(datos: dict) -> dict:
    """Debian y Ubuntu: ``[epoca:]origen-revision``. La correccion de seguridad casi
    siempre va en la revision (``-1ubuntu0.26.04.2``, ``-3+deb12u1``)."""
    distro = datos["distribucion"] or "la distribución"
    epoca_i, origen_i, revision_i = dividir_dpkg(datos["instalada"])
    epoca_c, origen_c, revision_c = dividir_dpkg(datos["corregida"])
    datos.update(revision_instalada=revision_i or None, revision_corregida=revision_c or None)
    datos["verificacion"] = (f'dpkg --compare-versions "{datos["instalada"]}" lt '
                             f'"{datos["corregida"]}"')
    if epoca_i != epoca_c:
        datos["texto"] = (f"De la versión {_texto_epoca_dpkg(datos['instalada'], origen_i, epoca_i)} "
                          f"a la {_texto_epoca_dpkg(datos['corregida'], origen_c, epoca_c)}: "
                          f"cambia la época del paquete, que manda sobre el resto del número")
        return datos
    if _verrevcmp(origen_i, origen_c) != 0:
        datos["texto"] = f"De la versión {origen_i} a la {origen_c}"
        return datos
    datos.update(misma_origen=True, origen=origen_i)
    datos["texto"] = (f"Misma versión de origen ({origen_i}): la corrección va en la revisión "
                      f"del paquete de {distro}, de {revision_i or SIN_REVISION} "
                      f"a {revision_c or SIN_REVISION}")
    return datos


def _explicar_pkg(datos: dict) -> dict:
    """FreeBSD: ``version[_nivel][,epoca]``. El nivel de parche (``_6``) es lo que sube
    tanto en los puertos como en el sistema base («14.4_6» es 14.4-RELEASE-p6)."""
    epoca_i, version_i, nivel_i = dividir_pkg(datos["instalada"])
    epoca_c, version_c, nivel_c = dividir_pkg(datos["corregida"])
    datos.update(revision_instalada=str(nivel_i) if nivel_i else None,
                 revision_corregida=str(nivel_c) if nivel_c else None)
    datos["verificacion"] = f'pkg version -t "{datos["instalada"]}" "{datos["corregida"]}"'
    if epoca_i != epoca_c:
        datos["texto"] = (f"De la versión {_texto_epoca_pkg(datos['instalada'], version_i, epoca_i)} "
                          f"a la {_texto_epoca_pkg(datos['corregida'], version_c, epoca_c)}: "
                          f"cambia la época del paquete, que manda sobre el resto del número")
        return datos
    if comparar_pkg(version_i, version_c) != 0:
        datos["texto"] = f"De la versión {version_i} a la {version_c}"
        return datos
    datos.update(misma_origen=True, origen=version_i)
    datos["texto"] = (f"Misma versión de origen ({version_i}): la corrección va en el nivel de "
                      f"parche de FreeBSD, "
                      + _de_a(str(nivel_i) if nivel_i else None,
                              str(nivel_c) if nivel_c else None, SIN_NIVEL_PARCHE))
    return datos


def _explicar_windows(datos: dict) -> dict:
    """Windows: compilaciones ``10.0.26100.4351``. Los tres primeros números son la
    versión del sistema y el último, el que sube con cada actualización acumulativa."""
    mi = _RE_BUILD_WINDOWS.match(datos["instalada"] or "")
    mc = _RE_BUILD_WINDOWS.match(datos["corregida"] or "")
    if not mi or not mc:
        datos["texto"] = f"De la versión {datos['instalada']} a la {datos['corregida']}"
        return datos
    base_i = ".".join(mi.group(1, 2, 3))
    base_c = ".".join(mc.group(1, 2, 3))
    # El cuarto numero (la actualizacion acumulativa) puede faltar: «10.0.26100» es un dato
    # legitimo y escribir «0» seria inventarlo.
    ultimo_i, ultimo_c = mi.group(4), mc.group(4)
    datos.update(revision_instalada=ultimo_i, revision_corregida=ultimo_c)
    datos["verificacion"] = "winver (o «systeminfo | findstr Compilación») en el equipo"
    if base_i != base_c:
        datos["texto"] = (f"De la compilación {base_i} a la {base_c}: cambia la versión de "
                          f"Windows, no solo la actualización acumulativa")
        return datos
    datos.update(misma_origen=True, origen=base_i)
    datos["texto"] = (f"Misma compilación de Windows ({base_i}): la corrección llega en la "
                      f"actualización acumulativa, "
                      + _de_a(f"número {ultimo_i}" if ultimo_i else None, ultimo_c,
                              SIN_ACTUALIZACION))
    return datos


def explicar_comparacion(familia: Optional[str], instalada: Optional[str],
                         corregida: Optional[str]) -> dict:
    """Explica en español por qué la versión instalada es anterior a la que corrige.

    Devuelve siempre las mismas claves, de modo que el correo y la interfaz no tengan
    que preguntar por nada:

    * ``misma_origen``: la versión de origen (la del programa) es la misma y lo único
      que cambia es la revisión del paquete de la distribución. Es el caso que
      confundía al equipo que aplica el parche.
    * ``origen``, ``revision_instalada``, ``revision_corregida``: los trozos con los
      que pintar la diferencia.
    * ``identicas``: las dos cadenas son idénticas (dato raro: no hay nada que aplicar).
    * ``orden``: -1, 0 o 1 con las reglas de la familia (lo que decidió el veredicto).
    * ``texto``: la frase corta, ya redactada.
    * ``verificacion``: orden con la que comprobarlo en el propio equipo.

    Con datos ausentes no inventa nada: lo dice.
    """
    fam = _familia_normalizada(familia)
    datos = _explicacion_base(fam, instalada, corregida)
    if _vacia(datos["instalada"]) and _vacia(datos["corregida"]):
        datos["texto"] = "No se conocen ni la versión instalada ni la que corrige el fallo"
        return datos
    if _vacia(datos["instalada"]):
        datos["texto"] = ("No se conoce la versión instalada, así que no se puede explicar la "
                          "comparación con la que corrige el fallo")
        return datos
    if _vacia(datos["corregida"]):
        datos["texto"] = ("Todavía no hay versión que corrija el fallo con la que comparar la "
                          "instalada")
        return datos
    datos["orden"] = comparar(fam if fam != "otro" else None, datos["instalada"], datos["corregida"])
    if datos["instalada"] == datos["corregida"]:
        datos.update(misma_origen=True, identicas=True, origen=datos["instalada"])
        datos["texto"] = ("La versión instalada y la que corrige el fallo son la misma cadena: "
                          "no hay nada que aplicar")
        return datos
    if fam in ("debian", "ubuntu"):
        return _explicar_dpkg(datos)
    if fam == "freebsd":
        return _explicar_pkg(datos)
    if fam == "windows":
        return _explicar_windows(datos)
    datos["texto"] = f"De la versión {datos['instalada']} a la {datos['corregida']}"
    return datos

"""Que fuentes de inventario tecnologico tiene configuradas esta instalacion.

Antes de este modulo, ``threatintel/ocs.py`` sincronizaba SIEMPRE las mismas dos bases
de OCS Inventory (``ORIGENES = {"servidores": "OCS_SERVIDORES", "equipos":
"OCS_EQUIPOS"}``, un diccionario fijo). Para poder conectar un inventario distinto
(GLPI, Snipe-IT, Lansweeper, una exportacion de Active Directory...) sin tocar el motor
de amenazas, esa lista pasa a declararse en ``config/inventarios.yml`` (plantilla en
``config/inventarios.yml.example``): nombre, tipo y lo que cada tipo necesite para
construir su lector.

Sin ese fichero (ninguna instalacion existente lo tiene todavia, 2026-11-15) se
devuelven exactamente las dos fuentes de OCS de siempre: ninguna instalacion nota el
cambio sin tocar nada. Es la regla de compatibilidad que
``tests/test_inventario_multifuente.py`` comprueba de forma explicita, la mas
importante de las pruebas nuevas.

Este modulo nunca deja a la plataforma sin ninguna fuente utilizable: un
``config/inventarios.yml`` que no se pueda leer, sin la clave ``fuentes``, u con
entradas invalidas, se registra como error (``logs/threatintel.jsonl``) y se cae a las
dos fuentes de OCS de siempre en lugar de romper cualquier pagina que consulte
``threatintel.ocs.ORIGENES`` (que es casi toda la interfaz). Una fuente concreta mal
escrita se omite SOLO a ella; las demas, validas, se conservan.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import yaml

from ..logging_setup import get_logger
from ..paths import BASE_DIR, CONFIG_DIR

log = get_logger("inventario.registro")

#: Fichero que declara las fuentes de esta instalacion. Si no existe, se usan las dos
#: de OCS de siempre (ver ``FUENTES_OCS_POR_DEFECTO``).
RUTA_INVENTARIOS = CONFIG_DIR / "inventarios.yml"

#: Las dos fuentes de toda la vida: (nombre, prefijo de credenciales en
#: ``config/credentials.env``). Es el ``ORIGENES`` de antes de que existiera este
#: modulo, ahora en un solo sitio para que el camino de compatibilidad no se
#: desincronice de lo que de verdad usa ``threatintel/inventario/ocs_mysql.py``.
FUENTES_OCS_POR_DEFECTO: tuple[tuple[str, str], ...] = (
    ("servidores", "OCS_SERVIDORES"),
    ("equipos", "OCS_EQUIPOS"),
)

#: Tipos de fuente que sabe instanciar ``threatintel.ocs.sincronizar``.
TIPOS_VALIDOS = ("ocs_mysql", "csv")


@dataclass(frozen=True)
class FuenteConfigurada:
    """Una fuente de inventario declarada (o una de las dos de defecto): nombre, tipo
    y lo que su tipo necesita para construir el lector.

    No abre ninguna conexion ni lee ningun fichero: es solo una descripcion, para que
    listar las fuentes configuradas (la pagina de Sincronizaciones, el filtro de
    Activos, ``bin/sincronizar_ocs.py --origen``...) no dependa de que esa fuente
    responda en ese instante.
    """

    nombre: str
    tipo: str
    #: tipo ``ocs_mysql``: prefijo de las variables en ``config/credentials.env``.
    prefijo_credenciales: Optional[str] = None
    #: tipo ``csv``: fichero de datos y de mapeo de columnas, relativos a la raiz del
    #: proyecto (o ya absolutos). Ver :func:`ruta_absoluta`.
    ruta: Optional[str] = None
    mapeo: Optional[str] = None


def ruta_absoluta(ruta: str) -> Path:
    """``ruta`` tal como se escribio en ``inventarios.yml`` (relativa a la raiz del
    proyecto) o ya absoluta -> ``Path`` absoluto."""
    p = Path(ruta)
    return p if p.is_absolute() else (BASE_DIR / p)


def _validar_fuente(bruto: Any, *, indice: int) -> FuenteConfigurada:
    if not isinstance(bruto, dict):
        raise ValueError(f"la fuente #{indice + 1} no es un diccionario («nombre:, tipo:, ...»)")
    nombre = str(bruto.get("nombre") or "").strip()
    tipo = str(bruto.get("tipo") or "").strip().lower()
    if not nombre:
        raise ValueError(f"la fuente #{indice + 1} no tiene «nombre»")
    if tipo not in TIPOS_VALIDOS:
        raise ValueError(f"la fuente «{nombre}» tiene un tipo desconocido ({tipo!r}); "
                         f"los tipos admitidos son: {', '.join(TIPOS_VALIDOS)}")
    if tipo == "ocs_mysql":
        prefijo = str(bruto.get("prefijo_credenciales") or "").strip()
        if not prefijo:
            raise ValueError(f"la fuente «{nombre}» (ocs_mysql) necesita «prefijo_credenciales»")
        return FuenteConfigurada(nombre=nombre, tipo=tipo, prefijo_credenciales=prefijo)
    # tipo == "csv"
    ruta = str(bruto.get("ruta") or "").strip()
    mapeo = str(bruto.get("mapeo") or "").strip()
    if not ruta or not mapeo:
        raise ValueError(f"la fuente «{nombre}» (csv) necesita «ruta» y «mapeo»")
    return FuenteConfigurada(nombre=nombre, tipo=tipo, ruta=ruta, mapeo=mapeo)


def _fuentes_ocs_por_defecto() -> list[FuenteConfigurada]:
    return [FuenteConfigurada(nombre=nombre, tipo="ocs_mysql", prefijo_credenciales=prefijo)
            for nombre, prefijo in FUENTES_OCS_POR_DEFECTO]


def fuentes_configuradas(secretos: Optional[dict[str, Any]] = None, *, cfg: Any = None,
                         ruta: Optional[Path] = None) -> list[FuenteConfigurada]:
    """Las fuentes de inventario de esta instalacion, en el orden del fichero.

    Sin ``config/inventarios.yml`` (``ruta`` por omision) devuelve exactamente las dos
    fuentes de OCS de siempre (``FUENTES_OCS_POR_DEFECTO``): es el camino que recorren
    TODAS las instalaciones existentes, que no tienen ese fichero. Con el fichero,
    cada entrada de la lista ``fuentes`` se valida por separado: la que este mal
    escrita se descarta (con un error en el registro) sin tirar las demas: si, tras
    descartar las invalidas, no queda ninguna fuente utilizable, tambien se cae a las
    dos de OCS de siempre en vez de dejar la plataforma sin ningun inventario.

    ``secretos`` es opcional y solo se usa para un aviso NO bloqueante (al registro, no
    a la pantalla): si una fuente ``ocs_mysql`` declara un ``prefijo_credenciales`` sin
    ``_HOST`` configurado en ``config/credentials.env``, se registra un aviso para que
    se note al revisar la configuracion y no solo cuando falle una sincronizacion
    (``threatintel.inventario.ocs_mysql.conectar`` ya da ese mismo motivo, con mas
    detalle, en ese momento). ``cfg`` se acepta por si una instalacion futura necesita
    activar o desactivar fuentes por ajuste de la interfaz; hoy no se usa.
    """
    ruta_fichero = ruta if ruta is not None else RUTA_INVENTARIOS
    if not ruta_fichero.exists():
        return _fuentes_ocs_por_defecto()

    try:
        with ruta_fichero.open("r", encoding="utf-8") as f:
            datos = yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as exc:
        log.error("no se pudo leer el fichero de fuentes de inventario; se usan las dos "
                 "fuentes de OCS Inventory de siempre",
                 extra={"ruta": str(ruta_fichero), "error": str(exc)})
        return _fuentes_ocs_por_defecto()

    crudo = datos.get("fuentes") if isinstance(datos, dict) else None
    if not isinstance(crudo, list) or not crudo:
        log.error("el fichero de fuentes de inventario no declara ninguna (clave «fuentes» "
                 "ausente, vacia o con forma incorrecta); se usan las dos fuentes de OCS "
                 "Inventory de siempre", extra={"ruta": str(ruta_fichero)})
        return _fuentes_ocs_por_defecto()

    fuentes: list[FuenteConfigurada] = []
    nombres_vistos: set[str] = set()
    for indice, bruto in enumerate(crudo):
        try:
            fuente = _validar_fuente(bruto, indice=indice)
        except ValueError as exc:
            log.error("fuente de inventario invalida en config/inventarios.yml; se omite",
                     extra={"indice": indice, "error": str(exc)})
            continue
        if fuente.nombre in nombres_vistos:
            log.error("nombre de fuente de inventario repetido en config/inventarios.yml; "
                     "se omite la repeticion", extra={"origen": fuente.nombre})
            continue
        nombres_vistos.add(fuente.nombre)
        fuentes.append(fuente)

    if not fuentes:
        log.error("ninguna fuente de config/inventarios.yml es valida; se usan las dos "
                 "fuentes de OCS Inventory de siempre", extra={"ruta": str(ruta_fichero)})
        return _fuentes_ocs_por_defecto()

    if secretos is not None:
        for fuente in fuentes:
            if fuente.tipo == "ocs_mysql" and not (secretos.get(f"{fuente.prefijo_credenciales}_HOST") or "").strip():
                log.warning("fuente de inventario sin credenciales configuradas todavia",
                           extra={"origen": fuente.nombre, "prefijo": fuente.prefijo_credenciales})
    return fuentes

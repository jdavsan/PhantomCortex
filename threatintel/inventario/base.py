"""Contrato comun de las fuentes de inventario tecnologico (OCS Inventory, CSV/JSON...).

La plataforma correlaciona amenazas contra el inventario real de activos
(``threatintel.matching``, tablas ``activos``/``activo_software``), que no sabe ni le
importa de donde vino ese inventario. La pieza que SI lo sabe es un «lector»: un objeto
con tres metodos que ``threatintel.ocs.sincronizar_origen`` ya aceptaba de forma
informal (tipado por duck typing, no por herencia) desde que existe la sincronizacion
con OCS Inventory. Este modulo (2026-11-15) solo pone nombre y forma a ese contrato que
ya funcionaba, para que anadir una fuente nueva (``threatintel/inventario/csv_generico.py``
es la primera que no es OCS) sea evidente sin tener que leer ``sincronizar_origen``
entero.

Es un ``typing.Protocol`` (tipado estructural) y no una clase base abstracta, a
proposito: ni ``threatintel.inventario.ocs_mysql.LectorOCS`` ni
``threatintel.inventario.csv_generico.LectorCSV`` heredan de ``FuenteInventario``,
igual que los lectores falsos que ya usan las pruebas (``LectorFalso`` en
``tests/test_activos_ocs.py``, que tampoco hereda de nada). El resto del codigo del
proyecto no usa ``Protocol`` ni ``ABC`` en ningun otro sitio: es un proyecto de tipado
gradual con ``Any``/``Optional`` normales. Se elige ``Protocol`` sobre una clase
abstracta porque el contrato YA era estructural antes de que existiera este modulo;
una ABC habria obligado a reescribir ``LectorOCS`` para heredar de ella sin ganar nada
a cambio, y a las pruebas a heredar de ella tambien.
"""
from __future__ import annotations

from typing import Any, Iterator, Optional, Protocol, runtime_checkable


@runtime_checkable
class FuenteInventario(Protocol):
    """Lo que necesita ``threatintel.ocs.sincronizar_origen`` de un lector de inventario.

    Las claves que citan los docstrings de cada metodo son las mismas que ya usa OCS
    Inventory (``LectorOCS``): un adaptador nuevo las rellena con lo que tenga
    disponible y deja en ``None`` (o fuera del diccionario) lo que no pueda ofrecer. No
    representan ningun requisito de "venir de una base de datos": son solo el
    vocabulario que ``threatintel.ocs`` ya entiende (``normalizar_so``, ``entorno_de``,
    ``proceso_de``...).
    """

    def hardware(self) -> list[dict[str, Any]]:
        """Un diccionario por equipo.

        Obligatorias: ``ID`` (identificador unico y estable dentro de ESTA fuente;
        debe ser el mismo en sincronizaciones sucesivas para que la plataforma
        reconozca que es el mismo equipo) y ``NAME``. El resto mejora el inventario
        pero su ausencia no rompe la sincronizacion, que lo trata como dato
        desconocido: ``DEVICEID``, ``OSNAME``, ``OSVERSION``, ``OSCOMMENTS``,
        ``IPADDR``, ``LASTCOME``, ``LASTDATE``, ``USERID``, ``ARCH``, ``WORKGROUP``,
        ``DESCRIPTION``.
        """
        ...

    def accountinfo(self) -> dict[int, dict[str, Any]]:
        """Campos administrativos por equipo (clave ``ID`` de :meth:`hardware`).

        OPCIONAL: ``sincronizar_origen`` comprueba con ``hasattr`` si el lector define
        este metodo antes de llamarlo, asi que uno sin estos datos puede omitirlo por
        completo en vez de implementar esta version por defecto (que no aporta nada).
        ``threatintel.ocs.entorno_de`` busca aqui el entorno (produccion,
        contingencia...) en cualquier campo que no sea ``HARDWARE_ID``/``TAG``; en el
        origen de servidores de OCS, ademas, ``threatintel.ocs.proceso_de`` usa ``TAG``
        como proceso de negocio (una regla propia de ese origen, no del contrato
        general).
        """
        return {}

    def software(self) -> Iterator[tuple[int, str, Optional[str], Optional[str]]]:
        """``(id_equipo, nombre, version, fabricante)`` por cada programa instalado.

        Debe recorrer las filas AGRUPADAS por equipo (todas las de un mismo
        ``id_equipo`` seguidas, sin intercalar con las de otro): ``sincronizar_origen``
        cierra un equipo en cuanto aparece uno distinto en el flujo, igual que hace la
        consulta SQL de OCS Inventory (``ORDER BY HARDWARE_ID``). Un equipo sin ningun
        programa reportado simplemente no aparece aqui.
        """
        ...

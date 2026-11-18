"""Adaptador generico de inventario: lee un fichero CSV o JSON externo (solo lectura).

Pensado para cualquier inventario que no sea OCS Inventory pero pueda exportar su
parque a un fichero plano: GLPI, Snipe-IT, Lansweeper, una exportacion de Active
Directory... No intenta cubrir todas las variantes posibles de esos productos (cada
uno exporta distinto); cubre un formato razonable y bien probado, y deja la
correspondencia de columnas en un fichero de mapeo YAML separado
(``config/mapeos/*.yml``, plantilla en ``config/mapeos/glpi.yml.example``) para que
cada instalacion lo ajuste a su propia exportacion sin tocar codigo.

Formato esperado del fichero de datos (CSV o JSON): UNA FILA (CSV) O UN OBJETO (JSON)
POR CADA PROGRAMA INSTALADO, con los datos del equipo repetidos en cada fila -- el
mismo formato "ancho" que usa OCS Inventory por debajo (tabla ``software``, con
``HARDWARE_ID`` repetido). Un equipo sin ningun programa reportado basta con una fila
suya sin las columnas de software (en blanco o ausentes). Es el formato mas comun en
exportaciones "activo + su software" de las herramientas de inventario, y permite usar
EL MISMO mapeo de columnas para CSV y para JSON.

Ejemplo minimo (ver ``config/mapeos/glpi.yml.example`` para uno comentado):

    columnas:
      id: id_equipo
      nombre: nombre_equipo
      so_nombre: sistema_operativo
      software_nombre: programa
      software_version: version_programa

Con ese mapeo, una fila CSV ``id_equipo=7,nombre_equipo=portatil-07,
sistema_operativo=Windows 11,programa=7-Zip,version_programa=23.01`` aporta el equipo
7 («portatil-07», Windows 11) con el programa «7-Zip» 23.01 instalado.

El identificador del equipo (columna ``id``) no necesita ser numerico: si no lo es
(una referencia de texto, un UUID...) se deriva un entero ESTABLE por hash (siempre el
mismo para el mismo texto), porque la tabla ``activos`` exige un ``ocs_id`` entero y
las sincronizaciones sucesivas necesitan reconocer que es el mismo equipo.
"""
from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
from typing import Any, Iterator, Optional

import yaml

from ..logging_setup import get_logger

log = get_logger("inventario.csv_generico")

#: Claves de ``columnas`` que el mapeo DEBE declarar: sin ellas no hay equipo que
#: identificar. El resto son opcionales (ver el docstring del modulo y el ejemplo).
_OBLIGATORIAS = ("id", "nombre")

#: Formatos de fichero de datos admitidos.
FORMATOS_VALIDOS = ("csv", "json")


def cargar_mapeo(ruta_mapeo: Path | str) -> dict[str, Any]:
    """Lee y valida el fichero YAML de mapeo de columnas (``config/mapeos/*.yml``)."""
    ruta_mapeo = Path(ruta_mapeo)
    if not ruta_mapeo.exists():
        raise FileNotFoundError(f"no existe el fichero de mapeo de columnas: {ruta_mapeo}")
    with ruta_mapeo.open("r", encoding="utf-8") as f:
        datos = yaml.safe_load(f) or {}
    if not isinstance(datos, dict):
        raise ValueError(f"{ruta_mapeo}: el mapeo debe ser un diccionario («formato:, columnas: ...»)")
    columnas = datos.get("columnas") or {}
    if not isinstance(columnas, dict):
        raise ValueError(f"{ruta_mapeo}: «columnas» debe ser un diccionario «campo: columna»")
    faltan = [c for c in _OBLIGATORIAS if not str(columnas.get(c) or "").strip()]
    if faltan:
        raise ValueError(f"{ruta_mapeo}: el mapeo no declara las columnas obligatorias: {', '.join(faltan)}")
    formato = str(datos.get("formato") or "csv").strip().lower()
    if formato not in FORMATOS_VALIDOS:
        raise ValueError(f"{ruta_mapeo}: formato {formato!r} no admitido (usa csv o json)")
    return {
        "formato": formato,
        "delimitador": str(datos.get("delimitador") or ","),
        "columnas": {str(k): str(v) for k, v in columnas.items() if str(v or "").strip()},
    }


def _id_numerico(texto: str) -> int:
    """Identificador entero ESTABLE para ``activos.ocs_id`` (``UNIQUE(origen, ocs_id)``).

    Si el identificador del fichero de origen ya es numerico se usa tal cual (igual que
    los ID autonumericos de OCS); si no lo es (una referencia de texto, un UUID...) se
    deriva un entero por hash, siempre el mismo para el mismo texto, para que
    sincronizaciones sucesivas reconozcan que es el mismo equipo.
    """
    texto = texto.strip()
    if texto.isdigit():
        return int(texto)
    return int(hashlib.sha1(texto.encode("utf-8")).hexdigest()[:15], 16)


def _registros_json(contenido: Any) -> list[dict[str, Any]]:
    if isinstance(contenido, list):
        crudos = contenido
    elif isinstance(contenido, dict):
        crudos = None
        for clave in ("equipos", "activos", "registros", "datos"):
            if isinstance(contenido.get(clave), list):
                crudos = contenido[clave]
                break
        if crudos is None:
            raise ValueError('el JSON debe ser una lista, o un diccionario con una lista en '
                             '"equipos" (o "activos"/"registros"/"datos")')
    else:
        raise ValueError("el JSON debe ser una lista de equipos/programas")
    return [r for r in crudos if isinstance(r, dict)]


def _leer_registros(ruta: Path, mapeo: dict[str, Any]) -> list[dict[str, Any]]:
    """Cada registro es una fila (CSV) u objeto (JSON) con las claves CRUDAS del fichero
    (los nombres de columna que declara el mapeo, no los campos internos)."""
    if mapeo["formato"] == "json":
        with ruta.open("r", encoding="utf-8") as f:
            contenido = json.load(f)
        return _registros_json(contenido)
    with ruta.open("r", encoding="utf-8-sig", newline="") as f:
        lector = csv.DictReader(f, delimiter=mapeo["delimitador"])
        return [dict(fila) for fila in lector]


def _valor(registro: dict[str, Any], columnas: dict[str, str], clave: str) -> Optional[str]:
    columna = columnas.get(clave)
    if not columna:
        return None
    bruto = registro.get(columna)
    if bruto is None:
        return None
    texto = str(bruto).strip()
    return texto or None


class LectorCSV:
    """Lee hardware y software de un fichero CSV o JSON externo, segun un mapeo de
    columnas (``cargar_mapeo``). Implementa el mismo contrato que ``LectorOCS``
    (:class:`threatintel.inventario.base.FuenteInventario`): ``hardware()``,
    ``accountinfo()`` y ``software()``.

    No lee nada en el constructor: el fichero de mapeo y el de datos se cargan la
    primera vez que se pide hardware/software/accountinfo, dentro del mismo bloque que
    ``threatintel.ocs.sincronizar_origen`` ya protege con su propio control de errores
    (un fichero que falta o esta mal formado termina la sincronizacion de ESTA fuente
    como «fallida», con el motivo, exactamente igual que una base de OCS inalcanzable;
    no tira la ejecucion entera ni las demas fuentes).
    """

    def __init__(self, ruta: Path | str, ruta_mapeo: Path | str):
        self.ruta = Path(ruta)
        self.ruta_mapeo = Path(ruta_mapeo)
        self._mapeo: Optional[dict[str, Any]] = None
        self._registros: Optional[list[dict[str, Any]]] = None

    def _mapeo_cargado(self) -> dict[str, Any]:
        if self._mapeo is None:
            self._mapeo = cargar_mapeo(self.ruta_mapeo)
        return self._mapeo

    def _cargar(self) -> list[dict[str, Any]]:
        if self._registros is None:
            mapeo = self._mapeo_cargado()
            if not self.ruta.exists():
                raise FileNotFoundError(f"no existe el fichero de inventario: {self.ruta}")
            self._registros = _leer_registros(self.ruta, mapeo)
        return self._registros

    def hardware(self) -> list[dict[str, Any]]:
        columnas = self._mapeo_cargado()["columnas"]
        vistos: dict[int, dict[str, Any]] = {}
        for registro in self._cargar():
            id_textual = _valor(registro, columnas, "id")
            nombre = _valor(registro, columnas, "nombre")
            if not id_textual or not nombre:
                continue   # fila sin equipo valido: se ignora, no se inventa un activo
            ocs_id = _id_numerico(id_textual)
            if ocs_id in vistos:
                continue
            vistos[ocs_id] = {
                "ID": ocs_id,
                "DEVICEID": _valor(registro, columnas, "device_id") or id_textual,
                "NAME": nombre,
                "OSNAME": _valor(registro, columnas, "so_nombre"),
                "OSVERSION": _valor(registro, columnas, "so_version"),
                "OSCOMMENTS": _valor(registro, columnas, "so_detalle"),
                "IPADDR": _valor(registro, columnas, "ip"),
                "LASTCOME": _valor(registro, columnas, "ultima_conexion"),
                "LASTDATE": _valor(registro, columnas, "ultimo_inventario"),
                "USERID": _valor(registro, columnas, "usuario"),
                "ARCH": _valor(registro, columnas, "arquitectura"),
                "WORKGROUP": _valor(registro, columnas, "grupo"),
                "DESCRIPTION": _valor(registro, columnas, "descripcion"),
            }
        return list(vistos.values())

    def accountinfo(self) -> dict[int, dict[str, Any]]:
        """Solo aporta el ENTORNO (produccion, contingencia...) si el mapeo declara una
        columna ``entorno``; el proceso de negocio por etiqueta (``TAG``) es una regla
        propia del origen «servidores» de OCS y no se traslada a esta fuente."""
        columnas = self._mapeo_cargado()["columnas"]
        if "entorno" not in columnas:
            return {}
        salida: dict[int, dict[str, Any]] = {}
        for registro in self._cargar():
            id_textual = _valor(registro, columnas, "id")
            entorno = _valor(registro, columnas, "entorno")
            if id_textual and entorno:
                salida[_id_numerico(id_textual)] = {"ENTORNO": entorno}
        return salida

    def software(self) -> Iterator[tuple[int, str, Optional[str], Optional[str]]]:
        columnas = self._mapeo_cargado()["columnas"]
        # Agrupado por equipo en memoria (y no tal cual viene el fichero): un CSV
        # exportado a mano no siempre trae las filas de un mismo equipo contiguas, y
        # sincronizar_origen necesita que software() se las entregue seguidas.
        agrupado: dict[int, list[tuple[str, Optional[str], Optional[str]]]] = {}
        for registro in self._cargar():
            id_textual = _valor(registro, columnas, "id")
            nombre_sw = _valor(registro, columnas, "software_nombre")
            if not id_textual or not nombre_sw:
                continue
            agrupado.setdefault(_id_numerico(id_textual), []).append(
                (nombre_sw, _valor(registro, columnas, "software_version"),
                 _valor(registro, columnas, "software_fabricante")))
        for ocs_id, filas in agrupado.items():
            for nombre_sw, version, fabricante in filas:
                yield ocs_id, nombre_sw, version, fabricante

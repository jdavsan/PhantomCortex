"""Motor de aplicabilidad por activo: ¿le aplica este CVE a este equipo?

Cruza cada amenaza con CVE contra el inventario real (``activos`` y
``activo_software``, sincronizados desde OCS) y guarda un veredicto por
(activo, CVE, paquete) en ``aplicabilidad``:

* **Debian y Ubuntu** — registro ``DEBIAN-CVE-…`` / ``UBUNTU-CVE-…`` de OSV.dev:
  por cada version de la distribucion trae el paquete fuente, la version que
  corrige el fallo y, en Ubuntu, la lista de paquetes binarios. La version
  instalada se compara con las reglas exactas de dpkg. Cache de siete dias en
  ``osv_cache``; el cupo de consultas por ejecucion se controla desde Ajustes.
* **FreeBSD** — VuXML (puertos y sistema base, con rangos por nivel de parche):
  el fichero se descarga a ``data/cache/vuxml.xml`` una vez al dia.
* **Windows y software de escritorio** — la version instalada frente a las
  restricciones de version que el aviso enuncia («anterior a 152.0.7632»),
  con el analizador de ``versions.py``. Vale tambien para software que no es un
  paquete de la distribucion (Chrome en Ubuntu).
* **Fin de soporte** — ciclos de endoflife.date (``fin_soporte``) para Ubuntu,
  Debian, FreeBSD y Windows; genera hallazgos «fuera de soporte» sin CVE.

Los veredictos son ``afectado``, ``no_afectado`` o ``sin_dato``, siempre con la
evidencia legible («curl 8.5.0-2ubuntu10.13 es anterior a la correccion
8.5.0-2ubuntu10.16 (Ubuntu 24.04)»). Nunca se descarta nada por suposicion:
sin dato es sin dato.

Desde el 2026-09-06, a peticion del usuario, cada fila se **entiende** y se **verifica**,
y desde la revision adversaria del mismo dia nada de eso se dice por aproximacion:

* ``explicar_fila`` (y ``versiones_distro.explicar_comparacion``) dicen en espanol por que
  la version instalada es anterior a la corregida cuando «parecen iguales» porque solo
  cambia la revision del paquete: «Misma version de origen (1.11.1): la correccion va en
  la revision del paquete de Ubuntu, de 1build2 a 1ubuntu0.26.04.2». Ninguna frase escribe
  un dato que la version no traiga (una epoca 0, un nivel de parche 0).
* cada veredicto guarda la **referencia oficial** que lo sustenta en la columna
  ``aplicabilidad.referencia`` (esquema v8): nota de seguridad de Ubuntu, rastreador de
  Debian, entrada de VuXML, guia de Microsoft o ficha del NIST. La direccion se valida por
  **nombre de servidor** (``es_fuente_oficial``): una direccion que solo contenga
  «ubuntu.com» en la ruta no se presenta como nota de seguridad de Ubuntu.
  ``repasar_referencias`` rellena la columna de las filas antiguas aprovechando la cache de
  OSV.dev, y ``partir_evidencia`` sigue leyendo la marca «[Fuente oficial: …]» que llevan
  dentro de la evidencia las filas guardadas antes de que la columna existiera.
* el plan de actualizacion va **por paquete**: ``activos_de_amenaza`` devuelve, de cada
  activo y de cada sistema operativo, un ``paquetes_detalle`` con una entrada por paquete
  (su version instalada, su version corregida, su explicacion, su aviso y su fuente). Solo
  se resume en una pareja «de X a Y» cuando de verdad hay una sola: la version que corrige
  no es la misma en Ubuntu 22.04, en Ubuntu 26.04 y en Debian 13, ni es la misma para el
  sistema base de FreeBSD (14.4_5) y para el puerto openssl (3.0.16,1) del mismo servidor.
"""
from __future__ import annotations

import html
import json
import re
import sqlite3
import time
from datetime import date, datetime, timedelta, timezone
from typing import Any, Callable, Iterable, Optional
from urllib.parse import urlsplit

from . import db, excepciones, http, versions
from .logging_setup import get_logger
from .ocs import (ENTORNOS_EXPUESTOS, FAMILIA_ES, FUENTE_DEBIAN, normalizar_nombre,
                  paquete_fuente, registrar_hallazgos, reglas_fuente)
from .paths import DATA_DIR
from .versiones_distro import (comparar as comparar_familia, comparar_dpkg, en_rango_pkg,
                               explicar_comparacion, texto_rango, version_base_freebsd,
                               version_upstream)

log = get_logger("aplicabilidad")

URL_OSV_VULN = "https://api.osv.dev/v1/vulns/{id}"
URL_VUXML = "https://vuxml.freebsd.org/freebsd/vuln.xml"
URL_EOL = "https://endoflife.date/api/{producto}.json"
CACHE_DIR = DATA_DIR / "cache"
CACHE_VUXML = CACHE_DIR / "vuxml.xml"

AFECTADO, NO_AFECTADO, SIN_DATO = "afectado", "no_afectado", "sin_dato"
VEREDICTOS = (AFECTADO, NO_AFECTADO, SIN_DATO)
VEREDICTO_ES = {AFECTADO: "Afectado", NO_AFECTADO: "No afectado", SIN_DATO: "Sin dato"}
VEREDICTO_CLAVE = {AFECTADO: "critico", NO_AFECTADO: "exito", SIN_DATO: "neutro"}
MOTORES = ("osv", "vuxml", "version", "manual")
MOTOR_ES = {"osv": "OSV.dev (paquetes de la distribución)", "vuxml": "FreeBSD VuXML",
            "version": "Comparación de versión con el aviso", "manual": "Consulta manual",
            "msrc": "Boletín de seguridad de Microsoft (MSRC)"}
PREFIJO_OSV = {"ubuntu": "UBUNTU", "debian": "DEBIAN"}
PRODUCTOS_EOL = ("ubuntu", "debian", "freebsd", "windows", "windows-server")
ESTADOS_CERRADOS_SQL = "('descartada','falso_positivo')"

# --------------------------------------------------------------------------
# La severidad BAJA no cuenta en nada (2026-09-10)
#
# Orden del usuario: «las amenazas y vulnerabilidades de severidad baja no se deben tener
# en cuenta en absolutamente nada […] solo es lo de severidad crítica, alta y media».
#
# Hay que distinguir DOS cosas en este modulo y no confundirlas nunca:
#
# * EVALUAR (``evaluar_amenaza``, ``evaluar_pendientes``, ``responder_cve``,
#   ``repasar_referencias``, ``recalcular_resumenes``, ``_guardar_filas``): se sigue
#   evaluando TODO, tambien la severidad baja. El veredicto es un hecho comprobado contra
#   OCS Inventory y hay que guardarlo: la severidad de un CVE cambia (un fallo publicado
#   como bajo sube a alto cuando llega la puntuacion oficial o entra en el catalogo KEV
#   de CISA), y si no se hubiera evaluado ese dia no habria nada que ensenar.
# * CONTAR y MOSTRAR (``plan_remediacion``, ``vulnerabilidades_activo``,
#   ``versiones_pedidas_por_paquete``, ``anotar_version_ultima``,
#   ``contar_veredictos_activo``, ``conteo_activo``, ``resumen_informe``…): la severidad
#   baja queda fuera, gobernada por el ajuste ``ignore_low_severity``.
#
# Nada se borra: si el ajuste se desactiva, todo vuelve a aparecer sin migracion.
#
# La misma frontera vale, desde el 2026-09-10, para el RIESGO ACEPTADO con una excepcion
# vigente (``threatintel.excepciones``): se evalua y se guarda igual, y queda fuera de lo
# que cuenta y de lo que manda trabajo (ver :func:`_y_sin_excepcion`, que explica sitio
# por sitio donde se aplica y donde no). Tampoco se borra nada: la excepcion caduca sola
# y la vulnerabilidad vuelve sin ninguna migracion.
# --------------------------------------------------------------------------
#: Valor de ``threats.severity`` que no se reporta.
SEVERIDAD_BAJA = "Low"

#: Deja fuera la severidad baja de una consulta cuyo alias de ``aplicabilidad`` sea ``ap``.
#: Se escribe con NOT EXISTS para que valga tambien donde ``threats`` no esta unida. Una
#: fila sin amenaza conocida NO es «baja» y se conserva, igual que en ``ocs.estado_activos``.
_SIN_BAJAS_SQL = ("NOT EXISTS (SELECT 1 FROM threats tb WHERE tb.id = ap.threat_id "
                  f"AND tb.severity = '{SEVERIDAD_BAJA}')")


def excluir_bajas(conn: sqlite3.Connection) -> bool:
    """Si la severidad baja se deja fuera de lo que se cuenta y se muestra.

    Lee el ajuste ``ignore_low_severity`` de la propia base con la misma conexion de la
    consulta, como ``alertas_proceso.incluir_bajas`` y ``remediacion.excluir_bajas``: asi
    la pagina de Activos, la de Amenazas, el plan de remediacion, el correo y el informe
    cuentan lo mismo sin tener que pasarse el ajuste unos a otros.
    """
    return bool(db.get_setting(conn, "ignore_low_severity", True))


def _y_sin_bajas(conn: sqlite3.Connection) -> str:
    """« AND <condición>» para pegar a un WHERE, o cadena vacia si las bajas cuentan."""
    return f" AND {_SIN_BAJAS_SQL}" if excluir_bajas(conn) else ""


#: Condicion SQL «esta fila NO esta cubierta por una excepcion vigente» para las
#: consultas cuyo alias de ``aplicabilidad`` sea ``ap`` (``threatintel.excepciones``).
_SIN_EXCEPCION_SQL = excepciones.SQL_SIN_EXCEPCION_APLICABILIDAD


def _y_sin_excepcion(conn: sqlite3.Connection) -> str:
    """« AND <condición>» para pegar a un WHERE, o cadena vacia si no hay ninguna vigente.

    El riesgo aceptado con una excepcion vigente (responsable, justificacion y fecha de
    vencimiento obligatoria) no cuenta en las CIFRAS ni en lo que se manda actualizar,
    exactamente igual que la severidad baja, y por eso este gemelo se pega en los mismos
    sitios que :func:`_y_sin_bajas`. La frontera esta clara y es deliberada:

    * SI se aplica en lo que CUENTA o MANDA TRABAJO (``versiones_pedidas_por_paquete``,
      ``anotar_version_ultima_sistemas``, ``activos_distintos``, ``plan_remediacion``,
      ``resumen_informe``): una vulnerabilidad cuyo riesgo se acepto por escrito no puede
      fijar la version que hay que instalar hoy ni sumar en un indicador de riesgo.
    * NO se aplica en lo que EVALUA ni en lo que RECALCULA (``evaluar_amenaza``,
      ``recalcular_resumenes``, ``adjuntar_resumen``) ni en la ficha del activo
      (``contar_veredictos_activo``, ``veredictos_de_activo``, ``conteo_activo``,
      ``vulnerabilidades_activo``): el veredicto de aplicabilidad es un HECHO TECNICO
      —esta maquina tiene esta version y esta version es vulnerable— y la excepcion es
      una DECISION DE RIESGO. Mezclarlas haria que al vencer la excepcion no hubiera
      ningun dato guardado con el que volver a la cola, y ademas dejaria dos cifras
      distintas de lo mismo en la misma pantalla.
    """
    return f" AND {_SIN_EXCEPCION_SQL}" if excepciones.hay_excepciones(conn) else ""


#: Alias privado de :func:`excluir_bajas`. ``vulnerabilidades_activo`` tiene un parametro
#: que se llama igual (viene del 2026-09-09 y otras llamadas lo pasan), y dentro de esa
#: funcion el nombre esta ocupado por el parametro.
_ajuste_excluir_bajas = excluir_bajas


_RE_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
_RE_AVISO = re.compile(r"^(?:USN|DSA|DLA|ELA)-\d+(?:-\d+)?$", re.I)


class ErrorOSV(RuntimeError):
    """OSV no respondio o se agoto el cupo de consultas de la ejecucion."""


def cves_de(amenaza: dict) -> list[str]:
    vistos: list[str] = []
    for c in _RE_CVE.findall(str(amenaza.get("cve") or "")):
        c = c.upper()
        if c not in vistos:
            vistos.append(c)
    return vistos


def _parse_iso(valor: Any) -> Optional[datetime]:
    if not valor:
        return None
    try:
        dt = datetime.fromisoformat(str(valor).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def marca_evaluacion() -> str:
    """Marca de tiempo UTC con microsegundos: cada evaluacion tiene la suya y las
    filas de la evaluacion anterior se distinguen aunque caigan en el mismo segundo."""
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _ajuste(cfg: Any, clave: str, defecto: Any) -> Any:
    if cfg is None:
        return defecto
    valor = cfg.get(clave, defecto)
    return defecto if valor in (None, "") else valor


# --------------------------------------------------------------------------
# OSV.dev
# --------------------------------------------------------------------------
class ClienteOSV:
    """Registros ``{PREFIJO}-{CVE}`` de OSV.dev con cache en ``osv_cache``.

    ``max_peticiones`` limita las consultas de red por ejecucion; al agotarse se
    sirve la cache aunque este caducada y, si no hay cache, se lanza ErrorOSV
    para que la amenaza quede pendiente (incompleta) y se reintente otro dia.
    """

    def __init__(self, conn: sqlite3.Connection, *, cfg: Any = None,
                 max_peticiones: Optional[int] = None, fetch=None):
        self.conn = conn
        self.ttl = timedelta(hours=float(_ajuste(cfg, "osv_cache_hours", 168)))
        self.max = int(max_peticiones if max_peticiones is not None
                       else _ajuste(cfg, "applicability_max_osv_per_run", 300))
        self.user_agent = _ajuste(cfg, "http_user_agent", None)
        self._fetch = fetch or http.fetch_json
        self.peticiones = 0
        self.fallos = 0
        self.aciertos_cache = 0

    @property
    def agotado(self) -> bool:
        return self.peticiones >= self.max

    def en_cache(self, id_osv: str) -> bool:
        """¿Hay registro (o ausencia confirmada) en cache, aunque este caducado?"""
        return self.conn.execute("SELECT 1 FROM osv_cache WHERE id=?", (id_osv,)).fetchone() is not None

    def _guardar(self, id_osv: str, encontrado: bool, datos: Optional[dict]) -> None:
        self.conn.execute(
            """INSERT INTO osv_cache(id, encontrado, json, consultado_at) VALUES(?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET encontrado=excluded.encontrado, json=excluded.json,
                   consultado_at=excluded.consultado_at""",
            (id_osv, 1 if encontrado else 0,
             json.dumps(datos, ensure_ascii=False) if datos is not None else None, db.utcnow()))

    def registro(self, id_osv: str) -> Optional[dict]:
        fila = self.conn.execute("SELECT encontrado, json, consultado_at FROM osv_cache WHERE id=?",
                                 (id_osv,)).fetchone()
        if fila is not None:
            consultado = _parse_iso(fila["consultado_at"])
            fresco = consultado is not None and datetime.now(timezone.utc) - consultado < self.ttl
            if fresco or self.agotado:
                self.aciertos_cache += 1
                return json.loads(fila["json"]) if fila["encontrado"] and fila["json"] else None
        if self.agotado:
            raise ErrorOSV("cupo de consultas a OSV.dev agotado en esta ejecución")
        self.peticiones += 1
        res = self._fetch(URL_OSV_VULN.format(id=id_osv), timeout=20, retries=1,
                          user_agent=self.user_agent, silenciar_http=True)
        if res.ok and isinstance(res.data, dict) and res.data.get("id"):
            self._guardar(id_osv, True, res.data)
            return res.data
        if res.status == 404:
            self._guardar(id_osv, False, None)
            return None
        self.fallos += 1
        raise ErrorOSV(f"OSV.dev no respondió para {id_osv}: {res.error or res.status}")


def _eco_base(eco: Optional[str]) -> str:
    """'Ubuntu:22.04:LTS' -> 'Ubuntu:22.04'; 'Ubuntu:Pro:18.04:LTS' se deja tal cual
    (no casa con ningun activo: Ubuntu Pro no se contrata aqui)."""
    partes = (eco or "").split(":")
    if len(partes) >= 2 and partes[1].lower() != "pro":
        return f"{partes[0]}:{partes[1]}"
    return eco or ""


def ecosistemas_del_registro(registro: dict) -> set[str]:
    """Ecosistemas que el registro de OSV.dev SI menciona («Debian:13», «Ubuntu:22.04»).

    Sirve para distinguir dos ausencias que no son lo mismo (2026-09-15):

    * el aviso lista OTRA version de la misma distribucion y no la nuestra: la distribucion
      YA trio el fallo y decidio que esa version no entra, asi que es una prueba de que NO
      afecta y se puede cerrar;
    * el aviso no lista ninguna version de nuestra distribucion: nadie lo ha triado todavia
      (o dejo de publicarse al salir del soporte estandar), y ahi no se puede afirmar nada.

    Sin esta distincion, cualquier ausencia se quedaba en «no se puede confirmar ni
    descartar» y el operador no recibia cierre nunca.
    """
    salida: set[str] = set()
    for a in registro.get("affected") or []:
        eco = _eco_base(((a.get("package") or {}).get("ecosystem")))
        if eco:
            salida.add(eco)
    return salida


def afectaciones(registro: dict, ecosistema: str) -> list[dict[str, Any]]:
    """Entradas ``affected`` del registro para un ecosistema exacto: paquete
    fuente, versiones que corrigen y (Ubuntu) binarios con su version corregida."""
    salida: list[dict[str, Any]] = []
    for a in registro.get("affected") or []:
        paquete = a.get("package") or {}
        if _eco_base(paquete.get("ecosystem")) != ecosistema:
            continue
        corregidas = [e["fixed"] for r in (a.get("ranges") or [])
                      for e in (r.get("events") or []) if e.get("fixed")]
        esp = a.get("ecosystem_specific") or {}
        binarios: dict[str, Optional[str]] = {}
        for b in esp.get("binaries") or []:
            nombre = (b.get("binary_name") or "").strip().lower()
            if nombre:
                binarios[nombre] = (b.get("binary_version") or "").strip() or None
        salida.append({"fuente": (paquete.get("name") or "").strip().lower(),
                       "corregidas": corregidas, "binarios": binarios,
                       "urgencia": esp.get("urgency") or esp.get("priority")})
    return salida


def ecosistemas_afectados(registro: dict) -> list[str]:
    vistos: list[str] = []
    for a in registro.get("affected") or []:
        eco = _eco_base((a.get("package") or {}).get("ecosystem"))
        if eco and eco not in vistos:
            vistos.append(eco)
    return vistos


def avisos_de(registro: dict) -> list[str]:
    """USN/DSA/DLA citados por el registro (``related`` y referencias)."""
    avisos: list[str] = []
    for r in registro.get("related") or []:
        if _RE_AVISO.match(str(r)) and r not in avisos:
            avisos.append(str(r))
    for ref in registro.get("references") or []:
        m = re.search(r"/(USN-\d+-\d+|DSA-\d+(?:-\d+)?|DLA-\d+(?:-\d+)?)\b", str(ref.get("url") or ""), re.I)
        if m and m.group(1).upper() not in [a.upper() for a in avisos]:
            avisos.append(m.group(1).upper())
    return avisos


# --------------------------------------------------------------------------
# Referencia oficial que sustenta cada veredicto (2026-09-06)
# --------------------------------------------------------------------------
# El usuario pidio que cada fila de «activos afectados» se pueda verificar con una fuente
# real: el equipo que aplica el parche tiene que poder abrir la nota del fabricante o el
# rastreador de la distribucion y comprobar que la version corregida es la que dice el
# sistema.
#
# Desde el esquema v8 la direccion vive en su propia columna, ``aplicabilidad.referencia``,
# y ``evidencia`` queda limpia. Las filas guardadas antes de la columna llevan la direccion
# pegada al final de la evidencia con la marca «[Fuente oficial: …]»: ``partir_evidencia``
# sigue separandola para poder LEERLAS, pero ya no se escribe asi (``con_referencia`` solo
# se conserva para las pruebas y para no romper llamadas antiguas).
MARCA_REFERENCIA = "Fuente oficial:"
_RE_REFERENCIA = re.compile(r"\s*\[" + re.escape(MARCA_REFERENCIA) + r"\s*(\S+?)\s*\]\s*$")

#: Direcciones canonicas por familia y tipo de aviso. Todas son del propio fabricante o de
#: la distribucion: nunca una copia de terceros.
URL_TRACKER_DEBIAN = "https://security-tracker.debian.org/tracker/{id}"
URL_UBUNTU_CVE = "https://ubuntu.com/security/{cve}"
URL_UBUNTU_USN = "https://ubuntu.com/security/notices/{id}"
URL_FREEXIAN_ELA = "https://deb.freexian.com/extended-lts/tracker/{id}"
URL_VUXML_ENTRADA = "https://vuxml.freebsd.org/freebsd/{vid}.html"
URL_FREEBSD_SA = "https://www.freebsd.org/security/advisories/{id}.asc"
URL_MSRC_CVE = "https://msrc.microsoft.com/update-guide/vulnerability/{cve}"
URL_MICROSOFT_KB = "https://support.microsoft.com/help/{numero}"
URL_NVD_CVE = "https://nvd.nist.gov/vuln/detail/{cve}"

#: Fuentes oficiales admitidas: (servidor, prefijo de ruta). El orden es el de
#: preferencia: primero la nota de seguridad y el rastreador de la distribucion (dicen la
#: version exacta que corrige), despues la pagina del CVE y la ficha del NIST.
#:
#: SE COMPARA EL SERVIDOR, NUNCA UNA SUBCADENA (revision adversaria del 2026-09-06,
#: hallazgo 1): con la comprobacion anterior, «https://malicioso.example/ubuntu.com/aviso»
#: se presentaba al equipo que aplica el parche como «Nota de seguridad de Ubuntu». Ahora
#: la direccion se analiza y solo pasa si el nombre de servidor es exactamente el de la
#: lista o un subdominio propio suyo («esm.ubuntu.com» si, «ubuntu.com.malicioso.example»
#: no), con esquema https, sin credenciales, sin puerto raro y con la ruta esperada.
_FUENTES_OFICIALES = (
    ("ubuntu.com", "/security/notices/"),          # nota de seguridad de Ubuntu (USN)
    ("security-tracker.debian.org", "/tracker/"),  # rastreador de seguridad de Debian
    ("deb.freexian.com", "/extended-lts/"),        # soporte ampliado de Debian (Freexian)
    ("vuxml.freebsd.org", "/"),                    # entrada de VuXML de FreeBSD
    ("freebsd.org", "/security/"),                 # aviso de seguridad de FreeBSD
    ("msrc.microsoft.com", "/update-guide/"),      # guia de actualizaciones de Microsoft
    ("support.microsoft.com", "/"),                # articulo de soporte de Microsoft
    ("ubuntu.com", "/security/"),                  # ficha del CVE en Ubuntu
    ("nvd.nist.gov", "/vuln/detail/"),             # ficha del CVE en el NIST
)

#: Caracteres validos en un nombre de servidor: cualquier otro (letras acentuadas, espacios,
#: subrayado) delata una direccion manipulada y se rechaza.
_CARACTERES_SERVIDOR = frozenset("abcdefghijklmnopqrstuvwxyz0123456789.-")
#: Longitud maxima razonable de una direccion que sustenta un veredicto.
_MAX_LARGO_DIRECCION = 500


def _analizar_direccion(url: Optional[str]) -> Optional[tuple[str, str]]:
    """(servidor, ruta) de una direccion segura y verificable, o ``None``.

    Exige ``https``, prohibe credenciales en la direccion («https://usuario:clave@…»),
    puertos distintos del 443, nombres de servidor con caracteres raros o etiquetas
    punycode («xn--…», que permiten servidores de aspecto parecido) y rutas con «..».
    """
    bruto = str(url or "").strip()
    if not bruto or len(bruto) > _MAX_LARGO_DIRECCION:
        return None
    if any(c.isspace() for c in bruto) or "\\" in bruto:
        return None
    try:
        partes = urlsplit(bruto)
    except ValueError:
        return None
    if partes.scheme.lower() != "https":
        return None
    if partes.username or partes.password or "@" in partes.netloc:
        return None
    try:
        puerto = partes.port
    except ValueError:
        return None
    if puerto not in (None, 443):
        return None
    servidor = (partes.hostname or "").strip().rstrip(".").lower()
    if not servidor or servidor.startswith(".") or ".." in servidor:
        return None
    if not set(servidor) <= _CARACTERES_SERVIDOR:
        return None
    if "xn--" in servidor:
        return None
    ruta = partes.path or "/"
    if "/../" in ruta or ruta.endswith("/..") or "/./" in ruta:
        return None
    return servidor, ruta


def _mismo_servidor(servidor: str, oficial: str) -> bool:
    """El servidor es exactamente el oficial o un subdominio propio suyo. «ubuntu.com» y
    «esm.ubuntu.com» si; «ubuntu.com.malicioso.example» y «mi-ubuntu.com» no."""
    return servidor == oficial or servidor.endswith("." + oficial)


def peso_fuente_oficial(url: Optional[str]) -> Optional[int]:
    """Orden de preferencia (0 = el mejor) si la direccion es de una fuente oficial
    verificable; ``None`` si no lo es. Es la unica puerta de entrada: nada que no pase por
    aqui se presenta como fuente oficial."""
    datos = _analizar_direccion(url)
    if datos is None:
        return None
    servidor, ruta = datos
    ruta_baja = ruta.lower()
    for peso, (oficial, prefijo) in enumerate(_FUENTES_OFICIALES):
        if _mismo_servidor(servidor, oficial) and ruta_baja.startswith(prefijo.lower()):
            return peso
    return None


def es_fuente_oficial(url: Optional[str]) -> bool:
    """¿La direccion se puede presentar como fuente oficial del fabricante?"""
    return peso_fuente_oficial(url) is not None

_RE_USN = re.compile(r"^USN-\d+-\d+$", re.I)
_RE_DEBIAN_AVISO = re.compile(r"^D(?:SA|LA)-\d+(?:-\d+)?$", re.I)
_RE_ELA = re.compile(r"^ELA-\d+(?:-\d+)?$", re.I)
_RE_FREEBSD_SA = re.compile(r"^FreeBSD-(?:SA|EN)-\d{2}:\d{2}\.[A-Za-z0-9_.+-]+$", re.I)
_RE_KB = re.compile(r"^KB(\d{5,9})$", re.I)


def url_aviso(identificador: Optional[str]) -> str:
    """Direccion oficial de un identificador de aviso, o cadena vacia si no se reconoce.

    ``USN-8486-1`` -> nota de seguridad de Ubuntu; ``DSA-5678-1`` y ``DLA-4773-1`` ->
    rastreador de Debian; ``ELA-1234-1`` -> LTS ampliado de Freexian;
    ``FreeBSD-SA-26:33.unbound`` -> aviso de FreeBSD; ``KB5058405`` -> articulo de
    Microsoft. Un identificador inventado devuelve '' y la interfaz lo pinta como texto,
    no como enlace: nunca se enlaza a una direccion que no existe."""
    ident = (identificador or "").strip()
    if not ident:
        return ""
    if _RE_USN.match(ident):
        return URL_UBUNTU_USN.format(id=ident.upper())
    if _RE_DEBIAN_AVISO.match(ident):
        return URL_TRACKER_DEBIAN.format(id=ident.upper())
    if _RE_ELA.match(ident):
        return URL_FREEXIAN_ELA.format(id=ident.upper())
    if _RE_FREEBSD_SA.match(ident):
        return URL_FREEBSD_SA.format(id=ident)
    m = _RE_KB.match(ident)
    if m:
        return URL_MICROSOFT_KB.format(numero=m.group(1))
    return ""


def avisos_con_url(texto: Optional[str]) -> list[dict[str, str]]:
    """Convierte el campo ``aviso`` («USN-8486-1, USN-8487-1») en una lista
    ``[{'id': 'USN-8486-1', 'url': 'https://…'}]`` para pintarlo como enlace."""
    salida: list[dict[str, str]] = []
    for trozo in re.split(r"[,;\s]+", str(texto or "")):
        ident = trozo.strip(" .·")
        if not ident or any(ident.upper() == a["id"].upper() for a in salida):
            continue
        salida.append({"id": ident, "url": url_aviso(ident)})
    return salida


def familia_de_ecosistema(ecosistema: Optional[str]) -> str:
    """'Ubuntu:22.04' -> 'ubuntu'; vacio -> ''."""
    return (ecosistema or "").split(":")[0].strip().lower()


def referencia_canonica(cve: Optional[str], *, ecosistema: Optional[str] = None,
                        familia: Optional[str] = None) -> str:
    """Direccion oficial que siempre existe para un CVE en esa familia, cuando el
    registro no trae ninguna: Ubuntu y Debian publican una pagina por CVE, Microsoft
    tiene su guia de actualizaciones y para el resto queda la ficha del NIST."""
    ident = (cve or "").strip().upper()
    if not _RE_CVE.fullmatch(ident):
        return ""
    fam = (familia or familia_de_ecosistema(ecosistema) or "").lower()
    if fam == "ubuntu":
        return URL_UBUNTU_CVE.format(cve=ident)
    if fam == "debian":
        return URL_TRACKER_DEBIAN.format(id=ident)
    if fam == "windows":
        return URL_MSRC_CVE.format(cve=ident)
    return URL_NVD_CVE.format(cve=ident)


#: Familia con la que se construye la direccion canonica cuando la fila no dice de que
#: sistema es: el motor ya lo determina (``msrc`` solo evalua Windows).
_FAMILIA_CANONICA_POR_MOTOR = {"msrc": "windows"}


def referencia_por_motor(motor: Optional[str], cve: Optional[str], *,
                        ecosistema: Optional[str] = None,
                        familia: Optional[str] = None) -> str:
    """Direccion canonica que sustenta una fila segun el motor que la evaluo.

    El motor ``version`` compara la version del PROGRAMA con la que enuncia el aviso
    (Chrome «151.0» en un equipo Ubuntu): la distribucion no dice nada de esa version, asi
    que se sustenta SIEMPRE con la ficha del NIST del CVE y nunca con la pagina de la
    distribucion del activo (revision adversaria del 2026-09-06, hallazgo 4)."""
    mot = (motor or "").strip().lower()
    if mot == "version":
        return referencia_canonica(cve)
    return referencia_canonica(cve, ecosistema=ecosistema,
                               familia=familia or _FAMILIA_CANONICA_POR_MOTOR.get(mot))


def referencia_segura(url: Optional[str], *, cve: Optional[str] = None,
                      ecosistema: Optional[str] = None, familia: Optional[str] = None,
                      motor: Optional[str] = None) -> str:
    """La direccion que se puede ensenar como respaldo del veredicto.

    Devuelve ``url`` solo si es de una fuente oficial verificable; si no, construye la
    direccion canonica del CVE segun el motor y la familia, y si tampoco se puede,
    cadena vacia (la interfaz y el correo pintan el texto sin enlace). Nunca devuelve una
    direccion que solo *parezca* oficial."""
    if (motor or "").strip().lower() == "version":
        canonica = referencia_canonica(cve)
        if canonica:
            return canonica
    if es_fuente_oficial(url):
        return str(url).strip()
    return referencia_por_motor(motor, cve, ecosistema=ecosistema, familia=familia)


def referencia_osv(registro: Optional[dict], *, ecosistema: Optional[str] = None,
                   cve: Optional[str] = None) -> str:
    """Referencia oficial verificable del registro de OSV.dev.

    Prefiere la nota de seguridad de la distribucion o su rastreador (que dicen la
    version exacta que corrige); si el registro no trae ninguna reconocible, construye
    la canonica de la familia. Nunca devuelve una direccion de terceros."""
    identificador = (cve or (registro or {}).get("id") or "")
    m = _RE_CVE.search(str(identificador))
    ident_cve = m.group(0).upper() if m else None
    candidatas: list[tuple[int, int, str]] = []
    for orden, ref in enumerate((registro or {}).get("references") or []):
        url = str(ref.get("url") or "").strip() if isinstance(ref, dict) else str(ref or "").strip()
        # El servidor tiene que ser el de la fuente oficial, no una direccion que lo
        # contenga en cualquier posicion (hallazgo 1 de la revision del 2026-09-06).
        peso = peso_fuente_oficial(url)
        if peso is not None:
            candidatas.append((peso, orden, url))
    if candidatas:
        return sorted(candidatas)[0][2]
    return referencia_canonica(ident_cve, ecosistema=ecosistema)


#: Como se llama cada fuente cuando se pinta el enlace, con el MISMO criterio de servidor
#: y ruta que ``_FUENTES_OFICIALES``. El texto del enlace tiene que decir adonde lleva
#: (accesibilidad): «Fuente oficial» a secas no dice nada.
_ETIQUETAS_REFERENCIA = (
    ("ubuntu.com", "/security/notices/", "Nota de seguridad de Ubuntu"),
    ("ubuntu.com", "/security/", "Ficha del CVE en Ubuntu"),
    ("security-tracker.debian.org", "/tracker/", "Rastreador de seguridad de Debian"),
    ("deb.freexian.com", "/extended-lts/", "Rastreador del soporte ampliado de Debian"),
    ("vuxml.freebsd.org", "/", "Entrada de VuXML de FreeBSD"),
    ("freebsd.org", "/security/", "Aviso de seguridad de FreeBSD"),
    ("msrc.microsoft.com", "/update-guide/", "Guía de actualizaciones de Microsoft"),
    ("support.microsoft.com", "/", "Artículo de soporte de Microsoft"),
    ("nvd.nist.gov", "/vuln/detail/", "Ficha del CVE en el NIST"),
)


def etiqueta_referencia(url: Optional[str]) -> str:
    """Nombre de la fuente para usarlo como texto del enlace.

    Cadena vacia si la direccion no es de una fuente oficial verificable: una direccion que
    solo contenga «ubuntu.com» en la ruta no se anuncia como nota de seguridad de Ubuntu
    (hallazgo 1 de la revision del 2026-09-06). La interfaz y el correo solo pintan el
    enlace cuando hay etiqueta."""
    datos = _analizar_direccion(url)
    if datos is None:
        return ""
    servidor, ruta = datos
    ruta_baja = ruta.lower()
    for oficial, prefijo, etiqueta in _ETIQUETAS_REFERENCIA:
        if _mismo_servidor(servidor, oficial) and ruta_baja.startswith(prefijo.lower()):
            return etiqueta
    return ""


def partir_evidencia(evidencia: Optional[str]) -> tuple[str, Optional[str]]:
    """Separa el texto de evidencia de la referencia oficial que lleva pegada al final."""
    texto = str(evidencia or "").strip()
    m = _RE_REFERENCIA.search(texto)
    if not m:
        return texto, None
    return texto[: m.start()].rstrip(), m.group(1)


def referencia_de_fila(fila: Any) -> Optional[str]:
    """Referencia guardada de una fila de ``aplicabilidad``.

    Primero la columna propia ``referencia`` (esquema v8); si esta vacia, la marca
    «[Fuente oficial: …]» que llevan pegada a la evidencia las filas guardadas antes de que
    la columna existiera. Asi el repaso y la interfaz siguen entendiendo lo antiguo sin
    escribir nada nuevo con la marca."""
    directa = str(dato_fila(fila, "referencia", "") or "").strip()
    if directa:
        return directa
    return partir_evidencia(dato_fila(fila, "evidencia", ""))[1]


def con_referencia(evidencia: Optional[str], referencia: Optional[str]) -> str:
    """Deja la referencia oficial al final del texto de evidencia, sin duplicarla.

    Formato antiguo: se conserva para poder leer y para las pruebas de compatibilidad, pero
    desde el esquema v8 la referencia se guarda en su columna y la evidencia queda limpia."""
    texto, ya = partir_evidencia(evidencia)
    destino = (referencia or ya or "").strip()
    if not destino:
        return texto
    return f"{texto} [{MARCA_REFERENCIA} {destino}]".strip()


#: Que reglas de version usa cada motor. No basta la familia del activo: el motor
#: ``version`` compara la version del PROGRAMA (Chrome «151.0») aunque el equipo sea
#: Ubuntu, y explicarlo como «revision del paquete de Ubuntu» seria falso.
_FAMILIA_POR_MOTOR = {"vuxml": "freebsd", "msrc": "windows"}


def familia_comparacion(motor: Optional[str], ecosistema: Optional[str] = None,
                        so_familia: Optional[str] = None) -> Optional[str]:
    """Familia con cuyas reglas se comparo la version de esa fila."""
    mot = (motor or "").strip().lower()
    if mot in _FAMILIA_POR_MOTOR:
        return _FAMILIA_POR_MOTOR[mot]
    if mot == "osv":
        fam = familia_de_ecosistema(ecosistema) or (so_familia or "").lower()
        return fam if fam in ("debian", "ubuntu") else None
    return None


def explicar_fila(fila: Any) -> dict:
    """Explicacion de la comparacion de una fila de ``aplicabilidad`` (acepta ``sqlite3.Row``
    o diccionario). Es lo que responde a «no se entiende 1.11.1-1build2 -> 1.11.1-1ubuntu0.26.04.2»."""
    familia = familia_comparacion(dato_fila(fila, "motor"), dato_fila(fila, "ecosistema"),
                                  dato_fila(fila, "so_familia"))
    return explicar_comparacion(familia, dato_fila(fila, "version_instalada"),
                                dato_fila(fila, "version_corregida"))


#: Frase corta de por que falta la version que corrige. Se repite aqui (y no se importa de
#: ``threatintel.parches``) porque ese modulo importa este: la dependencia solo va en un
#: sentido. Los textos son los mismos que ve el usuario en la hoja de correcciones.
MOTIVO_SIN_PARCHE_ES = {
    "aviso_sin_version": "el aviso de seguridad no indica en qué versión se corrige",
    "sin_parche_publicado": "el fabricante todavía no ha publicado la corrección",
    "distro_sin_empaquetar": "la distribución todavía no ha empaquetado la corrección",
    "desconocido": "no se ha podido determinar la versión que corrige",
}
TEXTO_SIN_CORRECCION = "sin corrección publicada todavía"


def motivo_sin_parche_es(motivo: Optional[str]) -> str:
    """Frase que explica por que no hay version que corrija; cadena vacia si no se sabe."""
    clave = str(motivo or "").strip()
    return MOTIVO_SIN_PARCHE_ES.get(clave, clave)


def texto_sin_correccion(motivo: Optional[str]) -> str:
    """«sin corrección publicada todavía: el fabricante todavía no ha publicado la corrección»."""
    detalle = motivo_sin_parche_es(motivo)
    return f"{TEXTO_SIN_CORRECCION}: {detalle}" if detalle else TEXTO_SIN_CORRECCION


def _mayor_dpkg(versiones: Iterable[str]) -> Optional[str]:
    mejor: Optional[str] = None
    for v in versiones:
        if v and (mejor is None or comparar_dpkg(v, mejor) > 0):
            mejor = v
    return mejor


def evaluar_dpkg(afect: list[dict], nombre_norm: str, version: str,
                 fuentes: Iterable[str]) -> Optional[dict[str, Any]]:
    """Veredicto de un paquete instalado frente a las afectaciones de su
    ecosistema. None si el paquete no figura (ni como binario ni como fuente)."""
    fuentes = list(fuentes)
    for a in afect:
        corregida: Optional[str] = None
        if nombre_norm in a["binarios"]:
            corregida = a["binarios"][nombre_norm]
        elif a["fuente"] in fuentes and not a["binarios"]:
            pass                       # Debian: solo hay paquete fuente
        elif a["fuente"] in fuentes and a["binarios"]:
            continue                   # Ubuntu lista los binarios y este no es uno de ellos
        else:
            continue
        corregida = corregida or _mayor_dpkg(a["corregidas"])
        if not corregida:
            return {"veredicto": AFECTADO, "version_corregida": None, "fuente": a["fuente"],
                    "evidencia": f"{nombre_norm} {version}: todavía no hay corrección publicada "
                                 f"para el paquete {a['fuente']}"}
        cmp = comparar_dpkg(version, corregida)
        if cmp < 0:
            return {"veredicto": AFECTADO, "version_corregida": corregida, "fuente": a["fuente"],
                    "evidencia": f"{nombre_norm} {version} es anterior a la corrección {corregida}"}
        return {"veredicto": NO_AFECTADO, "version_corregida": corregida, "fuente": a["fuente"],
                "evidencia": f"{nombre_norm} {version} ya incluye la corrección {corregida}"}
    return None


def _patrones_fuente(fuente: str) -> list[str]:
    """Patrones LIKE de binarios que derivan de un paquete fuente sin lista de binarios."""
    if fuente == "linux":
        return ["linux-image-%", "linux-modules-%", "linux-headers-%"]
    if re.match(r"^php\d+\.\d+$", fuente):
        return [f"{fuente}-%", f"libapache2-mod-{fuente}"]
    m = re.match(r"^postgresql-(\d+)$", fuente)
    if m:
        return [f"postgresql-%-{m.group(1)}"]
    m = re.match(r"^python(\d\.\d+)$", fuente)
    if m:
        return [f"python{m.group(1)}-%", f"libpython{m.group(1)}%"]
    if fuente.startswith("lib"):
        return [f"{fuente}%"]
    return []


# --------------------------------------------------------------------------
# FreeBSD VuXML
# --------------------------------------------------------------------------
_RE_VULN = re.compile(r'<vuln\s+vid="([^"]+)">(.*?)</vuln>', re.S)
_RE_TOPIC = re.compile(r"<topic>(.*?)</topic>", re.S)
_RE_PACKAGE = re.compile(r"<package>(.*?)</package>", re.S)
_RE_NAME = re.compile(r"<name>(.*?)</name>", re.S)
_RE_RANGE = re.compile(r"<range>(.*?)</range>", re.S)
_RE_BOUND = re.compile(r"<(lt|le|gt|ge|eq)>(.*?)</\1>", re.S)
_RE_CVENAME = re.compile(r"<cvename>\s*(CVE-\d{4}-\d+)\s*</cvename>", re.I)
_RE_SA = re.compile(r"<freebsdsa>\s*(.*?)\s*</freebsdsa>", re.S)
NOMBRES_BASE_FREEBSD = frozenset({"freebsd", "freebsd-kernel"})


class IndiceVuXML:
    """Indice CVE -> entradas VuXML (paquetes y rangos afectados)."""

    def __init__(self, texto: str):
        self.entradas: list[dict[str, Any]] = []
        self.por_cve: dict[str, list[int]] = {}
        for m in _RE_VULN.finditer(texto or ""):
            vid, cuerpo = m.group(1), m.group(2)
            if "<cancelled" in cuerpo:
                continue
            cves = sorted({c.upper() for c in _RE_CVENAME.findall(cuerpo)})
            if not cves:
                continue
            mt = _RE_TOPIC.search(cuerpo)
            topic = html.unescape(re.sub(r"\s+", " ", mt.group(1))).strip() if mt else ""
            paquetes: list[tuple[list[str], list[dict[str, str]]]] = []
            for pm in _RE_PACKAGE.finditer(cuerpo):
                nombres = [html.unescape(n).strip().lower() for n in _RE_NAME.findall(pm.group(1))]
                rangos = [{k: html.unescape(v).strip() for k, v in _RE_BOUND.findall(r)}
                          for r in _RE_RANGE.findall(pm.group(1))]
                if nombres:
                    paquetes.append((nombres, rangos))
            sa = _RE_SA.search(cuerpo)
            indice = len(self.entradas)
            self.entradas.append({"vid": vid, "topic": topic, "paquetes": paquetes,
                                  "sa": (f"FreeBSD-{sa.group(1)}" if sa else None), "cves": cves,
                                  # Pagina oficial de esa entrada de VuXML: sustenta el veredicto
                                  "referencia": URL_VUXML_ENTRADA.format(vid=vid)})
            for c in cves:
                self.por_cve.setdefault(c, []).append(indice)

    def __len__(self) -> int:
        return len(self.entradas)

    def paquetes_de(self, cve: str) -> set[str]:
        nombres: set[str] = set()
        for i in self.por_cve.get(cve.upper(), []):
            for lista, _ in self.entradas[i]["paquetes"]:
                nombres.update(lista)
        return nombres

    def evaluar(self, cve: str, nombre_norm: str, version: Optional[str]) -> Optional[dict[str, Any]]:
        """None si ningun registro del CVE menciona el paquete."""
        version = (version or "").strip()
        visto = False
        for i in self.por_cve.get(cve.upper(), []):
            e = self.entradas[i]
            for nombres, rangos in e["paquetes"]:
                if nombre_norm not in nombres:
                    continue
                visto = True
                if not version:
                    return {"veredicto": SIN_DATO, "version_corregida": None, "aviso": e["sa"],
                            "referencia": e["referencia"],
                            "evidencia": f"{nombre_norm}: sin versión en el inventario · {e['topic']}"}
                for limites in rangos:
                    if en_rango_pkg(version, limites):
                        return {"veredicto": AFECTADO, "version_corregida": limites.get("lt"),
                                "aviso": e["sa"], "referencia": e["referencia"],
                                "evidencia": f"{nombre_norm} {version} está en el rango afectado "
                                             f"({texto_rango(limites)}) · {e['topic']}"}
                descripcion = "; ".join(texto_rango(r) for r in rangos) or "sin rango"
                return {"veredicto": NO_AFECTADO,
                        "version_corregida": next((r.get("lt") for r in rangos if r.get("lt")), None),
                        "aviso": e["sa"], "referencia": e["referencia"],
                        "evidencia": f"{nombre_norm} {version} queda fuera de los rangos afectados "
                                     f"({descripcion}) · {e['topic']}"}
        return None if not visto else None


_INDICE_VUXML: Optional[IndiceVuXML] = None
_INDICE_VUXML_MTIME: Optional[float] = None


def cargar_vuxml(*, cfg: Any = None, forzar: bool = False, fetch=None) -> Optional[IndiceVuXML]:
    """Descarga (si la cache tiene mas de ``vuxml_cache_hours``) y analiza VuXML.
    El indice se conserva en memoria durante el proceso."""
    global _INDICE_VUXML, _INDICE_VUXML_MTIME
    ttl = timedelta(hours=float(_ajuste(cfg, "vuxml_cache_hours", 24)))
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    fresco = (CACHE_VUXML.exists() and not forzar and
              datetime.now(timezone.utc) - datetime.fromtimestamp(CACHE_VUXML.stat().st_mtime, timezone.utc) < ttl)
    if not fresco:
        res = (fetch or http.fetch)(URL_VUXML, timeout=120, retries=1,
                                    user_agent=_ajuste(cfg, "http_user_agent", None))
        if res.ok and res.content and b"<vuln " in res.content:
            CACHE_VUXML.write_bytes(res.content)
            try:
                CACHE_VUXML.chmod(0o640)
            except OSError:
                pass
            log.info("VuXML descargado", extra={"bytes": len(res.content)})
        elif not CACHE_VUXML.exists():
            log.warning("no se pudo descargar VuXML y no hay cache", extra={"error": res.error})
            return None
        else:
            log.warning("no se pudo descargar VuXML; se usa la cache", extra={"error": res.error})
    mtime = CACHE_VUXML.stat().st_mtime
    if _INDICE_VUXML is None or _INDICE_VUXML_MTIME != mtime:
        inicio = time.perf_counter()
        _INDICE_VUXML = IndiceVuXML(CACHE_VUXML.read_text(encoding="utf-8", errors="replace"))
        _INDICE_VUXML_MTIME = mtime
        log.info("VuXML indexado", extra={"entradas": len(_INDICE_VUXML),
                                          "ms": int((time.perf_counter() - inicio) * 1000)})
    return _INDICE_VUXML


# --------------------------------------------------------------------------
# Fin de soporte (endoflife.date)
# --------------------------------------------------------------------------
def actualizar_fin_soporte(conn: sqlite3.Connection, *, cfg: Any = None, forzar: bool = False,
                           fetch=None) -> dict[str, Any]:
    ttl = timedelta(hours=float(_ajuste(cfg, "eol_cache_hours", 168)))
    fetch = fetch or http.fetch_json
    actualizados: list[str] = []
    errores: list[str] = []
    ahora = db.utcnow()
    for producto in PRODUCTOS_EOL:
        fila = conn.execute("SELECT MAX(actualizado_at) AS m FROM fin_soporte WHERE producto=?",
                            (producto,)).fetchone()
        ultimo = _parse_iso(fila["m"]) if fila else None
        if ultimo and not forzar and datetime.now(timezone.utc) - ultimo < ttl:
            continue
        res = fetch(URL_EOL.format(producto=producto), timeout=20, retries=1,
                    user_agent=_ajuste(cfg, "http_user_agent", None))
        if not res.ok or not isinstance(res.data, list):
            errores.append(f"{producto}: {res.error or res.status}")
            continue
        for c in res.data:
            if not isinstance(c, dict) or c.get("cycle") is None:
                continue
            eol = c.get("eol")
            soporte = c.get("support")
            extendido = c.get("extendedSupport")
            conn.execute(
                """INSERT INTO fin_soporte(producto, ciclo, etiqueta, eol, soporte, soporte_extendido, ultima_version,
                       lts, actualizado_at)
                   VALUES(?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(producto, ciclo) DO UPDATE SET etiqueta=excluded.etiqueta, eol=excluded.eol,
                       soporte=excluded.soporte, soporte_extendido=excluded.soporte_extendido,
                       ultima_version=excluded.ultima_version, lts=excluded.lts, actualizado_at=excluded.actualizado_at""",
                (producto, str(c["cycle"]), str(c.get("releaseLabel") or c.get("codename") or c["cycle"]),
                 eol if isinstance(eol, str) else None, soporte if isinstance(soporte, str) else None,
                 extendido if isinstance(extendido, str) else None,
                 str(c.get("latest")) if c.get("latest") is not None else None,
                 1 if c.get("lts") else 0, ahora))
        actualizados.append(producto)
    return {"actualizados": actualizados, "errores": errores}


def tabla_fin_soporte(conn: sqlite3.Connection) -> dict[tuple[str, str], dict]:
    return {(r["producto"], r["ciclo"]): dict(r) for r in conn.execute("SELECT * FROM fin_soporte")}


def producto_eol(activo: dict) -> Optional[str]:
    familia = activo.get("so_familia")
    if familia == "windows":
        return "windows-server" if "server" in str(activo.get("so_nombre") or "").lower() else "windows"
    if familia in ("ubuntu", "debian", "freebsd"):
        return familia
    return None


def ciclos_candidatos(activo: dict) -> list[str]:
    ciclo = activo.get("so_ciclo")
    if not ciclo:
        return []
    if producto_eol(activo) == "windows":
        nombre = str(activo.get("so_nombre") or "").lower()
        if "ltsc" in nombre:
            edicion = "e-lts"
        elif "enterprise" in nombre or "education" in nombre:
            edicion = "e"
        else:
            edicion = "w"
        return [f"{ciclo}-{edicion}", ciclo, f"{ciclo}-e", f"{ciclo}-w", f"{ciclo}-e-lts"]
    return [ciclo]


def estado_soporte(tabla: dict[tuple[str, str], dict], activo: dict,
                   *, hoy: Optional[date] = None) -> Optional[dict[str, Any]]:
    """Ciclo, fecha de fin de soporte y dias restantes (negativos si ya paso).
    None si el sistema no esta cubierto por endoflife.date."""
    producto = producto_eol(activo)
    candidatos = ciclos_candidatos(activo)
    if producto is None or not candidatos:
        return None
    hoy = hoy or date.today()
    for ciclo in candidatos:
        fila = tabla.get((producto, ciclo))
        if fila is None:
            continue
        eol = fila.get("eol")
        # Debian: el equipo LTS mantiene la version gratis hasta el soporte extendido;
        # en Ubuntu el extendido es de pago (Ubuntu Pro) y no cuenta.
        if producto == "debian" and fila.get("soporte_extendido"):
            eol = max(eol or "", fila["soporte_extendido"])
        dias: Optional[int] = None
        if eol:
            try:
                dias = (date.fromisoformat(eol[:10]) - hoy).days
            except ValueError:
                dias = None
        return {"producto": producto, "ciclo": ciclo, "etiqueta": fila.get("etiqueta") or ciclo,
                "eol": eol, "dias": dias, "fuera": dias is not None and dias < 0,
                "proximo": dias is not None and 0 <= dias <= 180,
                "ultima_version": fila.get("ultima_version"), "lts": bool(fila.get("lts")),
                "sin_datos": False}
    return {"producto": producto, "ciclo": candidatos[0], "etiqueta": candidatos[0], "eol": None,
            "dias": None, "fuera": False, "proximo": False, "ultima_version": None, "lts": False,
            "sin_datos": True}


def hallazgos_fin_soporte(conn: sqlite3.Connection, *, hoy: Optional[date] = None,
                          ahora: Optional[str] = None) -> dict[str, int]:
    tabla = tabla_fin_soporte(conn)
    actuales: dict[tuple[int, str], str] = {}
    if tabla:
        for a in conn.execute("SELECT id, so_familia, so_ciclo, so_nombre, so_version FROM activos "
                              "WHERE presente=1 AND so_ciclo IS NOT NULL"):
            est = estado_soporte(tabla, dict(a), hoy=hoy)
            if est and est["fuera"]:
                actuales[(a["id"], f"{est['producto']}:{est['ciclo']}")] = (
                    f"{a['so_nombre']} {a['so_version'] or ''}".strip()
                    + f" sin soporte desde el {est['eol']}")
    return registrar_hallazgos(conn, "fin_soporte", actuales, ahora=ahora)


# --------------------------------------------------------------------------
# Evaluacion de amenazas
# --------------------------------------------------------------------------
def _tecnologias_amenaza(conn: sqlite3.Connection, threat_id: int, min_conf: float) -> list[dict]:
    return [dict(r) for r in conn.execute(
        """SELECT t.id, t.slug, t.name, tt.confidence FROM threat_technologies tt
             JOIN technologies t ON t.id = tt.technology_id
            WHERE tt.threat_id=? AND COALESCE(tt.confidence, 1.0) >= ? AND t.enabled=1
            ORDER BY tt.confidence DESC""", (threat_id, min_conf))]


def _software_en(conn: sqlite3.Connection, *, nombres: Iterable[str], patrones: Iterable[str] = (),
                 ecosistema: Optional[str] = None, familia: Optional[str] = None,
                 activo_id: Optional[int] = None) -> list[dict]:
    """Instalaciones (en activos presentes) cuyo nombre normalizado este en
    ``nombres`` o cumpla alguno de los ``patrones`` LIKE, acotadas por
    ecosistema, familia o activo."""
    nombres = sorted({n for n in nombres if n})
    patrones = [p for p in patrones if p]
    if not nombres and not patrones:
        return []
    condiciones: list[str] = []
    params: list[Any] = []
    if nombres:
        for lote in range(0, len(nombres), 500):
            trozo = nombres[lote:lote + 500]
            condiciones.append(f"s.nombre_norm IN ({','.join('?' * len(trozo))})")
            params.extend(trozo)
    for p in patrones:
        condiciones.append("s.nombre_norm LIKE ?")
        params.append(p)
    sql = f"""SELECT s.activo_id, s.nombre, s.nombre_norm, s.version, s.technology_id,
                     a.so_familia, a.ecosistema, a.nombre AS activo, a.ip
                FROM activo_software s JOIN activos a ON a.id = s.activo_id
               WHERE a.presente=1 AND ({' OR '.join(condiciones)})"""
    if ecosistema:
        sql += " AND a.ecosistema=?"
        params.append(ecosistema)
    if familia:
        sql += " AND a.so_familia=?"
        params.append(familia)
    if activo_id is not None:
        sql += " AND a.id=?"
        params.append(activo_id)
    return [dict(r) for r in conn.execute(sql, params)]


def _guardar_filas(conn: sqlite3.Connection, filas: list[dict]) -> None:
    if not filas:
        return
    # v8: ``referencia`` es columna propia. La evidencia se guarda limpia y la direccion
    # oficial se puede consultar, ordenar y repasar sin analizar texto. Las filas que llegan
    # de otros motores (``msrc``, ``sbom``) no traen la clave: se rellena con la direccion
    # canonica del CVE, y una direccion que no se pueda verificar se sustituye por ella.
    for f in filas:
        f["referencia"] = referencia_segura(f.get("referencia"), cve=f.get("cve"),
                                            motor=f.get("motor")) or None
    conn.executemany(
        """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete, version_instalada, version_corregida,
               veredicto, motor, evidencia, aviso, evaluado_at, referencia)
           VALUES(:activo_id, :threat_id, :cve, :paquete, :version_instalada, :version_corregida,
                  :veredicto, :motor, :evidencia, :aviso, :evaluado_at, :referencia)
           ON CONFLICT(activo_id, cve, paquete) DO UPDATE SET
               threat_id=COALESCE(excluded.threat_id, aplicabilidad.threat_id),
               version_instalada=excluded.version_instalada, version_corregida=excluded.version_corregida,
               veredicto=excluded.veredicto, motor=excluded.motor, evidencia=excluded.evidencia,
               aviso=excluded.aviso, evaluado_at=excluded.evaluado_at,
               referencia=COALESCE(excluded.referencia, aplicabilidad.referencia)""",
        filas)


def _fila(activo_id: int, threat_id: Optional[int], cve: str, paquete: str, version: Optional[str],
          res: dict, motor: str, ahora: str, *, sufijo: str = "", aviso: Optional[str] = None,
          referencia: Optional[str] = None, ecosistema: Optional[str] = None,
          familia: Optional[str] = None) -> dict:
    # La referencia oficial (nota de seguridad, rastreador de la distribucion, entrada de
    # VuXML o ficha del NIST) va en su columna, ya validada por servidor: es lo que permite
    # al equipo que aplica el parche comprobar la version corregida en la fuente real.
    evidencia = (res.get("evidencia") or "") + (f" ({sufijo})" if sufijo else "")
    fuente = referencia_segura(referencia or res.get("referencia"), cve=cve, motor=motor,
                               ecosistema=ecosistema, familia=familia)
    return {"activo_id": activo_id, "threat_id": threat_id, "cve": cve, "paquete": paquete[:200],
            "version_instalada": version, "version_corregida": res.get("version_corregida"),
            "veredicto": res["veredicto"], "motor": motor, "evidencia": evidencia.strip(),
            "aviso": aviso or res.get("aviso"), "evaluado_at": ahora,
            "referencia": fuente or None}


_VEREDICTO_DESDE_VERSIONS = {versions.AFFECTED: AFECTADO, versions.NOT_AFFECTED: NO_AFECTADO,
                             versions.UNKNOWN: SIN_DATO}


def _version_comparable(familia: Optional[str], version: Optional[str]) -> Optional[str]:
    if not version:
        return None
    if familia in ("debian", "ubuntu"):
        return version_upstream(version) or version
    return version


def _texto_amenaza(amenaza: dict) -> str:
    return " ".join(str(amenaza.get(k) or "") for k in ("title_en", "summary_en", "title_es", "summary_es"))


def _contar(filas: list[dict]) -> dict[str, int]:
    por_activo: dict[int, set[str]] = {}
    for f in filas:
        por_activo.setdefault(f["activo_id"], set()).add(f["veredicto"])
    afectados = sum(1 for v in por_activo.values() if AFECTADO in v)
    no_afectados = sum(1 for v in por_activo.values() if AFECTADO not in v and NO_AFECTADO in v)
    sin_dato = len(por_activo) - afectados - no_afectados
    return {"afectados": afectados, "no_afectados": no_afectados, "sin_dato": sin_dato,
            "activos": len(por_activo)}


def evaluar_amenaza(conn: sqlite3.Connection, amenaza: dict, *, cfg: Any = None,
                    osv: Optional[ClienteOSV] = None, vuxml: Optional[IndiceVuXML] = None,
                    ahora: Optional[str] = None, reglas_f: Optional[dict[str, str]] = None,
                    solo_activo: Optional[int] = None) -> dict[str, Any]:
    """Evalua una amenaza con CVE contra todos los activos presentes (o uno) y
    persiste los veredictos. Devuelve el recuento y las lineas de explicacion."""
    ahora = ahora or marca_evaluacion()
    threat_id = amenaza.get("id")
    cves = cves_de(amenaza)
    resultado: dict[str, Any] = {"threat_id": threat_id, "cves": cves, "afectados": 0, "no_afectados": 0,
                                 "sin_dato": 0, "filas": 0, "detalle": [], "errores": [], "incompleta": False}
    if not cves:
        return resultado
    osv = osv or ClienteOSV(conn, cfg=cfg)
    reglas_f = reglas_fuente(conn) if reglas_f is None else reglas_f
    min_conf = float(_ajuste(cfg, "alert_min_match_confidence", 0.6))
    tecs = _tecnologias_amenaza(conn, threat_id, min_conf) if threat_id else []
    tec_ids = [t["id"] for t in tecs]

    filtro_activo = " AND id=?" if solo_activo is not None else ""
    params_activo: tuple = (solo_activo,) if solo_activo is not None else ()
    ecosistemas = [r[0] for r in conn.execute(
        f"SELECT DISTINCT ecosistema FROM activos WHERE presente=1 AND ecosistema IS NOT NULL{filtro_activo}",
        params_activo)]
    freebsd = [dict(r) for r in conn.execute(
        f"SELECT id, nombre, so_version FROM activos WHERE presente=1 AND so_familia='freebsd'{filtro_activo}",
        params_activo)]

    filas: list[dict] = []
    detalle: list[str] = resultado["detalle"]
    errores: list[str] = resultado["errores"]
    evaluados: set[tuple[int, str]] = set()
    # Cobertura: ¿las bases de datos de las distribuciones dijeron algo? Sirve para
    # decidir «no afecta a ningun activo» con fundamento (queries.motivo_exclusion).
    familias_consultadas = 0
    familias_sin_afectacion = 0
    slugs_so = {"linux", "ubuntu", "debian", "freebsd", "linux-kernel", "kernel"}
    tecnologias_solo_so = bool(tecs) and all(t["slug"] in slugs_so for t in tecs)

    for cve in cves:
        # ------------------------------------------------ Debian / Ubuntu (OSV)
        for familia, prefijo in PREFIJO_OSV.items():
            ecos = [e for e in ecosistemas if e.lower().startswith(familia)]
            if not ecos:
                continue
            try:
                registro = osv.registro(f"{prefijo}-{cve}")
            except ErrorOSV as exc:
                errores.append(f"{FAMILIA_ES[familia]}: {exc}")
                continue
            familias_consultadas += 1
            if registro is None:
                familias_sin_afectacion += 1
                detalle.append(f"{FAMILIA_ES[familia]}: OSV.dev no tiene registro de {cve}; no afecta "
                               f"a paquetes de la distribución o aún no está evaluado")
                continue
            avisos = avisos_de(registro)
            texto_avisos = ", ".join(avisos[:2]) or None
            hubo_afectacion = False
            for eco in sorted(ecos):
                nombre_eco = eco.replace(":", " ")
                # Referencia oficial del propio registro (nota de seguridad o rastreador de la
                # distribucion): es la prueba con la que el resolutor verifica la version corregida.
                referencia_eco = referencia_osv(registro, ecosistema=eco, cve=cve)
                afect = afectaciones(registro, eco)
                if not afect:
                    # ¿El aviso menciona OTRA version de la misma distribucion? Si la lista,
                    # la distribucion ya trio el fallo y dejo la nuestra fuera a proposito:
                    # eso SI es prueba de que no afecta, y el operador puede cerrarlo.
                    otras = {e for e in ecosistemas_del_registro(registro)
                             if e.split(":")[0] == eco.split(":")[0] and e != eco}
                    if otras:
                        detalle.append(
                            f"{nombre_eco}: el aviso de la distribución sí trata "
                            f"{', '.join(sorted(x.replace(':', ' ') for x in otras))} pero "
                            f"no la lista entre las versiones afectadas, así que no afecta a "
                            f"sus activos")
                        familias_sin_afectacion += 1
                        continue
                    # El aviso existe, pero NO menciona esta version de la distribucion.
                    # Puede significar dos cosas que no se distinguen desde fuera: que esa
                    # version no esta afectada, o que la distribucion todavia no la ha
                    # triado (o ha dejado de publicarla al salir del soporte estandar). Por
                    # eso no se escribe ninguna fila de aplicabilidad: afirmar «no
                    # afectado» a partir de una ausencia cerraria remediaciones reales.
                    # La consecuencia esta medida y explicada en
                    # docs/DISENO_INTERFAZ_2026-09-03.md (2026-09-15): las remediaciones ya
                    # abiertas de esa version quedan sin fila de evaluacion y
                    # ``remediacion.sincronizar`` (paso 4) las deja pendientes sin cerrarlas.
                    detalle.append(f"{nombre_eco}: el aviso de la distribución no menciona esta "
                                   f"versión entre las afectadas, así que no se puede ni confirmar "
                                   f"ni descartar en sus activos; las remediaciones que ya estuvieran "
                                   f"abiertas siguen pendientes hasta que la distribución vuelva a "
                                   f"publicarla o el paquete cambie de versión")
                    continue
                hubo_afectacion = True
                nombres: set[str] = set()
                patrones: list[str] = []
                fuentes: set[str] = set()
                for a in afect:
                    fuentes.add(a["fuente"])
                    nombres.add(a["fuente"])
                    nombres.update(a["binarios"])
                    nombres.update(b for b, f in FUENTE_DEBIAN.items() if f == a["fuente"])
                    nombres.update(p for p, f in reglas_f.items() if f == a["fuente"])
                    if not a["binarios"]:
                        patrones.extend(_patrones_fuente(a["fuente"]))
                instalaciones = _software_en(conn, nombres=nombres, patrones=patrones, ecosistema=eco,
                                             activo_id=solo_activo)
                n_af = n_no = 0
                activos_eco: set[int] = set()
                for s in instalaciones:
                    res = evaluar_dpkg(afect, s["nombre_norm"], s["version"],
                                       paquete_fuente(s["nombre_norm"], reglas=reglas_f))
                    if res is None:
                        continue
                    filas.append(_fila(s["activo_id"], threat_id, cve, s["nombre_norm"], s["version"],
                                       res, "osv", ahora, sufijo=nombre_eco, aviso=texto_avisos,
                                       referencia=referencia_eco, ecosistema=eco, familia=familia))
                    evaluados.add((s["activo_id"], s["nombre_norm"]))
                    activos_eco.add(s["activo_id"])
                    if res["veredicto"] == AFECTADO:
                        n_af += 1
                    else:
                        n_no += 1
                if not activos_eco:
                    detalle.append(f"{nombre_eco}: ningún activo tiene instalados los paquetes afectados "
                                   f"({', '.join(sorted(fuentes))})")
                else:
                    # «instalación» hace el plural en «instalaciones», sin tilde: la
                    # concatenación anterior escribía «102 instalaciónes afectadas» en la
                    # explicación que se lee en la ficha de la amenaza (2026-09-15).
                    detalle.append(f"{nombre_eco}: {n_af} "
                                   f"{'instalaciones' if n_af != 1 else 'instalación'} "
                                   f"afectada{'s' if n_af != 1 else ''} y {n_no} ya corregida{'s' if n_no != 1 else ''} "
                                   f"en {len(activos_eco)} activo{'s' if len(activos_eco) != 1 else ''}"
                                   + (f" · {texto_avisos}" if texto_avisos else ""))
            if not hubo_afectacion:
                familias_sin_afectacion += 1

        # -------------------------------------------------------- FreeBSD (VuXML)
        if freebsd:
            if vuxml is None:
                errores.append("FreeBSD: VuXML no disponible")
            else:
                paquetes = vuxml.paquetes_de(cve)
                if not paquetes:
                    detalle.append(f"FreeBSD: VuXML no relaciona {cve} con ningún puerto ni con el sistema base")
                else:
                    base = paquetes & NOMBRES_BASE_FREEBSD
                    puertos = paquetes - NOMBRES_BASE_FREEBSD
                    n_af = n_no = 0
                    activos_bsd: set[int] = set()
                    for s in _software_en(conn, nombres=puertos, familia="freebsd", activo_id=solo_activo):
                        res = vuxml.evaluar(cve, s["nombre_norm"], s["version"])
                        if res is None:
                            continue
                        filas.append(_fila(s["activo_id"], threat_id, cve, s["nombre_norm"], s["version"],
                                           res, "vuxml", ahora, sufijo="FreeBSD", familia="freebsd"))
                        evaluados.add((s["activo_id"], s["nombre_norm"]))
                        activos_bsd.add(s["activo_id"])
                        n_af += res["veredicto"] == AFECTADO
                        n_no += res["veredicto"] == NO_AFECTADO
                    for a in freebsd if base else []:
                        vb = version_base_freebsd(a["so_version"])
                        for nombre in sorted(base):
                            res = vuxml.evaluar(cve, nombre, vb)
                            if res is None:
                                continue
                            filas.append(_fila(a["id"], threat_id, cve, nombre, vb, res, "vuxml", ahora,
                                               sufijo=f"sistema base {a['so_version'] or ''}".strip(),
                                               familia="freebsd"))
                            evaluados.add((a["id"], nombre))
                            activos_bsd.add(a["id"])
                            n_af += res["veredicto"] == AFECTADO
                            n_no += res["veredicto"] == NO_AFECTADO
                    if activos_bsd:
                        detalle.append(f"FreeBSD: {n_af} afectada{'s' if n_af != 1 else ''} y {n_no} fuera de "
                                       f"rango en {len(activos_bsd)} servidor{'es' if len(activos_bsd) != 1 else ''} "
                                       f"({', '.join(sorted(paquetes))})")
                    else:
                        detalle.append(f"FreeBSD: ningún servidor tiene {', '.join(sorted(paquetes))}")

        # ------------------------------ resto: version instalada frente al aviso
        # Solo cuando el aviso apunta a UNA tecnologia con coincidencia fuerte: si nombra
        # varias (WordPress y PHP, Malcolm y nginx) sus versiones no se pueden atribuir
        # a un paquete concreto y compararlas produciria falsos positivos.
        tecs_fuertes = [t for t in tecs if float(t.get("confidence") if t.get("confidence") is not None else 1.0) >= 0.8]
        restricciones = versions.extraer_restricciones(_texto_amenaza(amenaza)) if tecs else []
        if len(tecs) > 1:
            detalle.append("Comparación de versión omitida: el aviso nombra varias tecnologías ("
                           + ", ".join(t["name"] for t in tecs[:4]) + ") y sus versiones no se pueden "
                           "atribuir a un paquete concreto")
        elif tecs and not tecs_fuertes:
            detalle.append(f"Comparación de versión omitida: la coincidencia con {tecs[0]['name']} no es "
                           f"exacta (confianza {float(tecs[0].get('confidence') or 0):.1f})")
        elif tecs and not restricciones:
            detalle.append(f"Comparación de versión omitida: el aviso no precisa versiones de {tecs[0]['name']}")
        if tec_ids and len(tecs) == 1 and tecs_fuertes and restricciones:
            tec_ids = [tecs_fuertes[0]["id"]]
            marcas = ",".join("?" * len(tec_ids))
            sql = f"""SELECT s.activo_id, s.nombre, s.nombre_norm, s.version, a.so_familia, a.nombre AS activo
                        FROM activo_software s JOIN activos a ON a.id=s.activo_id
                       WHERE a.presente=1 AND s.technology_id IN ({marcas})"""
            params: list[Any] = list(tec_ids)
            if solo_activo is not None:
                sql += " AND a.id=?"
                params.append(solo_activo)
            conteo = {AFECTADO: 0, NO_AFECTADO: 0, SIN_DATO: 0}
            activos_v: set[int] = set()
            for s in conn.execute(sql, params):
                clave = (s["activo_id"], s["nombre_norm"])
                if clave in evaluados:
                    continue
                veredicto, evidencia = versions.evaluar(
                    _version_comparable(s["so_familia"], s["version"]), restricciones)
                res = {"veredicto": _VEREDICTO_DESDE_VERSIONS.get(veredicto, SIN_DATO),
                       "evidencia": f"{s['nombre']} {s['version']}: {evidencia}".strip(),
                       "version_corregida": None, "referencia": referencia_canonica(cve)}
                filas.append(_fila(s["activo_id"], threat_id, cve, s["nombre_norm"], s["version"],
                                   res, "version", ahora))
                evaluados.add(clave)
                conteo[res["veredicto"]] += 1
                activos_v.add(s["activo_id"])
            if activos_v:
                nombres_tec = ", ".join(t["name"] for t in tecs[:3])
                detalle.append(f"Comparación de versión ({nombres_tec}): {conteo[AFECTADO]} afectada"
                               f"{'s' if conteo[AFECTADO] != 1 else ''}, {conteo[NO_AFECTADO]} no afectada"
                               f"{'s' if conteo[NO_AFECTADO] != 1 else ''} y {conteo[SIN_DATO]} sin dato en "
                               f"{len(activos_v)} activo{'s' if len(activos_v) != 1 else ''}")

    propia = not conn.in_transaction
    if propia:
        conn.execute("BEGIN")
    try:
        _guardar_filas(conn, filas)
        if threat_id is not None and solo_activo is None:
            # Filas de evaluaciones anteriores que ya no se dan (software desinstalado, activo ausente)
            conn.execute("DELETE FROM aplicabilidad WHERE threat_id=? AND evaluado_at < ?", (threat_id, ahora))
            totales = _contar([dict(r) for r in conn.execute(
                "SELECT activo_id, veredicto FROM aplicabilidad WHERE threat_id=?", (threat_id,))])
            expuestos = conn.execute(
                """SELECT COUNT(DISTINCT ap.activo_id) FROM aplicabilidad ap JOIN activos a ON a.id=ap.activo_id
                    WHERE ap.threat_id=? AND ap.veredicto='afectado' AND a.entorno IN ('produccion','contingencia')""",
                (threat_id,)).fetchone()[0]
            parche = conn.execute(
                "SELECT 1 FROM aplicabilidad WHERE threat_id=? AND veredicto='afectado' AND version_corregida IS NOT NULL LIMIT 1",
                (threat_id,)).fetchone() is not None
            totales["afectados_expuestos"] = int(expuestos or 0)
            totales["parche_disponible"] = 1 if parche else 0
            resultado.update(totales)
            resultado["incompleta"] = bool(errores)
            distro_no_afectada = (familias_consultadas > 0 and familias_sin_afectacion == familias_consultadas
                                  and not any(f["veredicto"] == AFECTADO for f in filas))
            conn.execute(
                """INSERT INTO aplicabilidad_amenaza(threat_id, evaluado_at, afectados, no_afectados, sin_dato,
                       afectados_expuestos, parche_disponible, detalle)
                   VALUES(?,?,?,?,?,?,?,?)
                   ON CONFLICT(threat_id) DO UPDATE SET evaluado_at=excluded.evaluado_at, afectados=excluded.afectados,
                       no_afectados=excluded.no_afectados, sin_dato=excluded.sin_dato,
                       afectados_expuestos=excluded.afectados_expuestos, parche_disponible=excluded.parche_disponible,
                       detalle=excluded.detalle""",
                (threat_id, ahora, totales["afectados"], totales["no_afectados"], totales["sin_dato"],
                 totales["afectados_expuestos"], totales["parche_disponible"],
                 json.dumps({"lineas": detalle, "errores": errores, "incompleta": 1 if errores else 0,
                             "ecosistemas": ecosistemas, "freebsd": len(freebsd),
                             "distro_no_afectada": 1 if distro_no_afectada else 0,
                             "tecnologias_solo_so": 1 if tecnologias_solo_so else 0}, ensure_ascii=False)))
        else:
            resultado.update(_contar(filas))
            resultado["incompleta"] = bool(errores)
        if propia:
            conn.execute("COMMIT")
    except Exception:
        if propia and conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    resultado["filas"] = len(filas)
    return resultado


def evaluar_pendientes(conn: sqlite3.Connection, *, cfg: Any = None, limite: Optional[int] = None,
                       osv: Optional[ClienteOSV] = None, vuxml: Optional[IndiceVuXML] = None,
                       ahora: Optional[datetime] = None, recalcular: bool = True) -> dict[str, Any]:
    """Evalua las amenazas con CVE abiertas y recientes que no se han evaluado
    nunca, llevan mas de ``applicability_reevaluate_days`` sin reevaluar o
    quedaron incompletas. Recalcula la relevancia de las tocadas."""
    if cfg is not None and not cfg.get("applicability_enabled", True):
        return {"omitido": True, "motivo": "desactivado en ajustes"}
    if not conn.execute("SELECT 1 FROM activos WHERE presente=1 LIMIT 1").fetchone():
        return {"omitido": True, "motivo": "sin activos sincronizados"}
    ahora = ahora or datetime.now(timezone.utc)
    dias = int(float(_ajuste(cfg, "collect_lookback_days", 45)))
    reeval = int(float(_ajuste(cfg, "applicability_reevaluate_days", 7)))
    limite = int(limite or _ajuste(cfg, "applicability_max_threats_per_run", 150))
    amenazas = [dict(r) for r in conn.execute(
        f"""SELECT t.id, t.cve, t.title_en, t.summary_en, t.title_es, t.summary_es, t.in_kev, t.relevance
              FROM threats t LEFT JOIN aplicabilidad_amenaza aa ON aa.threat_id = t.id
             WHERE t.cve IS NOT NULL AND t.cve <> '' AND t.estado NOT IN {ESTADOS_CERRADOS_SQL}
               AND t.first_seen_at >= ?
               AND (aa.threat_id IS NULL OR aa.evaluado_at < ?
                    OR json_extract(aa.detalle, '$.incompleta') = 1)
             ORDER BY t.in_kev DESC, t.relevance DESC, (aa.threat_id IS NULL) DESC, t.first_seen_at DESC
             LIMIT ?""",
        (_iso(ahora - timedelta(days=dias)), _iso(ahora - timedelta(days=reeval)), limite))]
    osv = osv or ClienteOSV(conn, cfg=cfg)
    hay_freebsd = conn.execute("SELECT 1 FROM activos WHERE presente=1 AND so_familia='freebsd' LIMIT 1").fetchone()
    if vuxml is None and hay_freebsd:
        vuxml = cargar_vuxml(cfg=cfg)
    reglas_f = reglas_fuente(conn)
    stats: dict[str, Any] = {"candidatas": len(amenazas), "evaluadas": 0, "con_afectados": 0,
                             "activos_afectados": set(), "incompletas": 0, "cupo_agotado": False,
                             "aplazadas": 0}
    familias = [f for f in PREFIJO_OSV if conn.execute(
        "SELECT 1 FROM activos WHERE presente=1 AND ecosistema LIKE ? LIMIT 1", (f"{f.capitalize()}:%",)).fetchone()]
    ids: list[int] = []
    for a in amenazas:
        if osv.agotado:
            # Sin cupo de red solo se evaluan las amenazas cuyos registros OSV ya estan en
            # cache; el resto se aplaza a la siguiente ejecucion sin marcarlo incompleto.
            necesarios = [f"{PREFIJO_OSV[f]}-{cve}" for f in familias for cve in cves_de(a)]
            if any(not osv.en_cache(i) for i in necesarios):
                stats["aplazadas"] += 1
                stats["cupo_agotado"] = True
                continue
        r = evaluar_amenaza(conn, a, cfg=cfg, osv=osv, vuxml=vuxml, reglas_f=reglas_f)
        stats["evaluadas"] += 1
        ids.append(a["id"])
        if r["afectados"]:
            stats["con_afectados"] += 1
            for fila in conn.execute("SELECT DISTINCT activo_id FROM aplicabilidad WHERE threat_id=? "
                                     "AND veredicto='afectado'", (a["id"],)):
                stats["activos_afectados"].add(fila[0])
        if r["incompleta"]:
            stats["incompletas"] += 1
        if osv.agotado:
            stats["cupo_agotado"] = True
    stats["activos_afectados"] = len(stats["activos_afectados"])
    stats["peticiones_osv"] = osv.peticiones
    stats["cache_osv"] = osv.aciertos_cache
    if recalcular and ids:
        from . import enrich
        stats["relevancia_recalculada"] = enrich.recalcular_relevancia(conn, cfg, threat_ids=ids)
    return stats


# --------------------------------------------------------------------------
# Evaluacion DIRIGIDA antes de decidir la alerta (2026-09-10)
#
# Peticion del usuario, tras el correo del 2026-09-10: «me debe alertar lo que realmente
# me este afectando, de lo contrario no». Ese dia se alertaron 35 amenazas y 4 no tenian
# ningun activo afectado confirmado: las cuatro NUNCA se habian evaluado, asi que el
# filtro de afectacion se abstuvo (no puede callar una amenaza por un fallo nuestro) y
# pasaron con el aviso «Afectacion todavia sin evaluar».
#
# Causa medida: ``evaluar_pendientes`` reparte un cupo de
# ``applicability_max_threats_per_run`` (150) entre las primeras evaluaciones y las
# reevaluaciones, y ese dia entraron 923 amenazas nuevas: amenazas de relevancia 74 y 70
# se quedaron sin evaluar. La solucion no es callarlas a ciegas, es EVALUARLAS ANTES DE
# DECIDIR: son unas pocas (7 candidatas ese dia, 4 con CVE) y se pueden evaluar dirigidas,
# sin cupo, justo antes de aplicar el filtro.
# --------------------------------------------------------------------------
#: Tope de seguridad de la evaluacion dirigida. No es un cupo de reparto como
#: ``applicability_max_threats_per_run``: es una cota para que un dia anomalo (una fuente
#: que publique cientos de criticas de golpe, o un recalculo de relevancia que suba muchas
#: a la vez) no convierta el paso de alerta en una tarea de horas. Medido el 2026-09-10
#: sobre la base real: las candidatas de un dia normal son 7. Con 250 hay 35 veces margen y
#: el peor caso sigue acotado por el cupo de red de OSV.dev
#: (``applicability_max_osv_per_run``), que no se toca.
LIMITE_EVALUACION_DIRIGIDA = 250


def evaluar_dirigido(conn: sqlite3.Connection, threat_ids: Iterable[int], *, cfg: Any = None,
                     osv: Optional[ClienteOSV] = None, vuxml: Optional[IndiceVuXML] = None,
                     ahora: Optional[datetime] = None, limite: Optional[int] = None,
                     recalcular: bool = True) -> dict[str, Any]:
    """Evalua EXACTAMENTE esas amenazas contra el inventario, sin pasar por la cola general.

    Es la evaluacion que se hace justo antes de decidir la alerta, para que la decision se
    tome con datos en la mano y no por abstencion (ver el comentario de arriba).
    Diferencias con :func:`evaluar_pendientes`, todas a proposito:

    * no elige candidatas: evalua las que se le dan, en el orden que se le dan (quien
      llama las ordena por explotacion activa y relevancia);
    * no aplica el cupo de reparto ``applicability_max_threats_per_run``, solo el tope de
      seguridad :data:`LIMITE_EVALUACION_DIRIGIDA`;
    * no mira la ventana de dias ni los dias de reevaluacion: si se pide, se evalua;
    * devuelve ``sin_evaluar``, los identificadores que NO se pudieron evaluar (sin CVE,
      cupo de red agotado sin cache, o fallo del motor), que es lo que necesita quien
      llama para avisar de que la plataforma no pudo comprobar algo en vez de callarlo.

    Las amenazas sin CVE no se evaluan (el motor solo sabe evaluar CVE) y se devuelven en
    ``sin_evaluar`` con el motivo ``sin_cve``: no es un fallo, es que no hay nada que
    comparar contra el inventario.
    """
    ids = []
    for valor in threat_ids or []:
        try:
            numero = int(valor)
        except (TypeError, ValueError):
            continue
        if numero not in ids:
            ids.append(numero)
    if not ids:
        return {"candidatas": 0, "evaluadas": 0, "con_afectados": 0, "sin_afectados": 0,
                "incompletas": 0, "sin_evaluar": [], "omitido": False,
                "activos_afectados": 0, "peticiones_osv": 0}
    if cfg is not None and not cfg.get("applicability_enabled", True):
        return {"candidatas": len(ids), "evaluadas": 0, "con_afectados": 0, "sin_afectados": 0,
                "incompletas": 0, "sin_evaluar": [{"id": i, "motivo": "desactivado"} for i in ids],
                "omitido": True, "motivo": "desactivado en ajustes",
                "activos_afectados": 0, "peticiones_osv": 0}
    if not conn.execute("SELECT 1 FROM activos WHERE presente=1 LIMIT 1").fetchone():
        return {"candidatas": len(ids), "evaluadas": 0, "con_afectados": 0, "sin_afectados": 0,
                "incompletas": 0,
                "sin_evaluar": [{"id": i, "motivo": "sin_inventario"} for i in ids],
                "omitido": True, "motivo": "sin activos sincronizados",
                "activos_afectados": 0, "peticiones_osv": 0}
    tope = int(limite or LIMITE_EVALUACION_DIRIGIDA)
    sobrantes = ids[tope:]
    ids = ids[:tope]
    marcas = ",".join("?" * len(ids))
    filas = {int(r["id"]): dict(r) for r in conn.execute(
        f"""SELECT t.id, t.cve, t.title_en, t.summary_en, t.title_es, t.summary_es,
                   t.in_kev, t.relevance
              FROM threats t WHERE t.id IN ({marcas})""", ids)}
    osv = osv or ClienteOSV(conn, cfg=cfg)
    hay_freebsd = conn.execute(
        "SELECT 1 FROM activos WHERE presente=1 AND so_familia='freebsd' LIMIT 1").fetchone()
    if vuxml is None and hay_freebsd:
        vuxml = cargar_vuxml(cfg=cfg)
    reglas_f = reglas_fuente(conn)
    stats: dict[str, Any] = {"candidatas": len(ids) + len(sobrantes), "evaluadas": 0,
                             "con_afectados": 0, "sin_afectados": 0, "incompletas": 0,
                             "activos_afectados": set(), "sin_evaluar": [],
                             "cupo_agotado": False, "omitido": False}
    for numero in sobrantes:
        stats["sin_evaluar"].append({"id": numero, "motivo": "tope_dirigido"})
    evaluados: list[int] = []
    for numero in ids:
        amenaza = filas.get(numero)
        if amenaza is None:
            stats["sin_evaluar"].append({"id": numero, "motivo": "no_existe"})
            continue
        if not (amenaza.get("cve") or "").strip():
            stats["sin_evaluar"].append({"id": numero, "motivo": "sin_cve",
                                         "cve": amenaza.get("cve")})
            continue
        try:
            # ``ahora`` de esta funcion es un datetime (igual que en
            # ``evaluar_pendientes``) y no la marca de texto que espera
            # ``evaluar_amenaza``: la marca la pone ella con ``marca_evaluacion()``.
            resultado = evaluar_amenaza(conn, amenaza, cfg=cfg, osv=osv, vuxml=vuxml,
                                        reglas_f=reglas_f)
        except Exception as exc:  # noqa: BLE001 - un fallo del motor no puede callar la amenaza
            log.error("fallo la evaluacion dirigida de una candidata a alertar",
                      extra={"threat_id": numero, "cve": amenaza.get("cve"),
                             "error": str(exc)}, exc_info=True)
            stats["sin_evaluar"].append({"id": numero, "motivo": "error",
                                         "cve": amenaza.get("cve"), "error": str(exc)})
            continue
        stats["evaluadas"] += 1
        evaluados.append(numero)
        if resultado["afectados"]:
            stats["con_afectados"] += 1
            for fila in conn.execute(
                    "SELECT DISTINCT activo_id FROM aplicabilidad WHERE threat_id=? "
                    "AND veredicto='afectado'", (numero,)):
                stats["activos_afectados"].add(fila[0])
        else:
            stats["sin_afectados"] += 1
        if resultado["incompleta"]:
            stats["incompletas"] += 1
            stats["sin_evaluar"].append({"id": numero, "motivo": "incompleta",
                                         "cve": amenaza.get("cve")})
        if osv.agotado:
            stats["cupo_agotado"] = True
    stats["activos_afectados"] = len(stats["activos_afectados"])
    stats["peticiones_osv"] = osv.peticiones
    stats["cache_osv"] = osv.aciertos_cache
    if recalcular and evaluados:
        from . import enrich
        stats["relevancia_recalculada"] = enrich.recalcular_relevancia(
            conn, cfg, threat_ids=evaluados)
    log.info("evaluacion dirigida antes de la alerta",
             extra={"candidatas": stats["candidatas"], "evaluadas": stats["evaluadas"],
                    "con_afectados": stats["con_afectados"],
                    "sin_evaluar": len(stats["sin_evaluar"])})
    return stats


#: Tipo de aviso en ``admin_notices`` para las candidatas que no se pudieron evaluar.
TIPO_AVISO_SIN_EVALUAR = "aplicabilidad_sin_evaluar"
#: Horas de silencio entre dos avisos de la MISMA amenaza sin evaluar. Un dia: si la
#: plataforma no pudo comprobar algo hoy, hay que decirlo hoy, y si sigue sin poder
#: mañana, hay que volver a decirlo. No se acumula ruido porque el aviso solo existe
#: cuando la evaluacion dirigida falla, que no es lo normal.
SILENCIO_SIN_EVALUAR_HORAS = 24
#: Cuantas amenazas se detallan en la tabla del aviso.
MAX_EN_AVISO_SIN_EVALUAR = 30

#: Por que no se pudo evaluar, en español, para el aviso de administracion.
MOTIVO_SIN_EVALUAR_ES = {
    "sin_cve": "no trae CVE: el motor no puede compararla con el inventario",
    "incompleta": "la evaluación no se pudo completar (OSV.dev o VuXML sin respuesta)",
    "error": "fallo del motor de evaluación",
    "tope_dirigido": "quedó fuera del tope de la evaluación dirigida de esta ejecución",
    "no_existe": "la amenaza ya no está en el catálogo",
    "desactivado": "la evaluación por activo está desactivada en Ajustes",
    "sin_inventario": "no hay inventario sincronizado con el que comparar",
    "sin_evaluar": "la evaluación no llegó a ejecutarse",
}


def avisar_sin_evaluar(conn: sqlite3.Connection, *, cfg: Any, pendientes: Iterable[dict],
                       mailer: Any = None, ahora: Optional[datetime] = None
                       ) -> Optional[dict[str, Any]]:
    """Aviso de administracion con las candidatas a alertar que NO se pudieron evaluar.

    Desde el 2026-09-10 una amenaza sin afectacion confirmada no se alerta
    (``queries.motivo_exclusion`` devuelve ``sin_evaluar_todavia``). Eso resuelve la queja
    del usuario —«me debe alertar lo que realmente me este afectando»— pero abre un riesgo
    nuevo: si la evaluacion falla por un problema tecnico (cupo de OSV.dev agotado, red
    caida, motor con error), una vulnerabilidad critica se quedaria fuera del correo SIN
    QUE NADIE LO SUPIERA. Este aviso es la contrapartida: el fallo se ve, con nombre y
    cifra, en un correo de administracion como el de la caducidad del certificado, y no
    llena el correo de seguridad de amenazas que no afectan.

    ``pendientes`` son los elementos de ``evaluar_dirigido()["sin_evaluar"]``, enriquecidos
    con lo que se sepa de cada amenaza (``cve``, ``severity``, ``in_kev``, ``relevance``).
    Devuelve el aviso enviado o None si no habia nada que avisar, si no hay destinatarios
    de administracion o si el correo no se pudo enviar (entonces no se marca nada como
    avisado y se reintenta al dia siguiente).
    """
    filas = [dict(p) for p in (pendientes or []) if p and p.get("id") is not None]
    if not filas:
        return None
    destinatarios = list(getattr(cfg, "admin_to", None) or [])
    if not destinatarios:
        log.warning("candidatas a alertar sin evaluar y sin destinatarios de administracion",
                    extra={"pendientes": len(filas)})
        return None
    momento = ahora or datetime.now(timezone.utc)
    limite = _iso(momento - timedelta(hours=SILENCIO_SIN_EVALUAR_HORAS))
    nuevas = []
    for fila in filas:
        clave = f"{fila['id']}|{fila.get('motivo') or 'sin_evaluar'}"
        ya = conn.execute(
            "SELECT 1 FROM admin_notices WHERE kind = ? AND subject_key = ? AND sent_at >= ? LIMIT 1",
            (TIPO_AVISO_SIN_EVALUAR, clave, limite)).fetchone()
        if ya is None:
            nuevas.append((clave, fila))
    if not nuevas:
        return None
    from .notify import Mailer, asunto_admin, render_admin_email, severidad_texto
    mailer = mailer or Mailer(cfg)
    kev = sum(1 for f in filas if f.get("in_kev"))
    titulo = (f"{len(filas)} vulnerabilidad candidata a alertar sin evaluar contra el inventario"
              if len(filas) == 1 else
              f"{len(filas)} vulnerabilidades candidatas a alertar sin evaluar contra el inventario")
    intro = ("La alerta diaria solo avisa de lo que está confirmado en alguna máquina del "
             "inventario (OCS Inventory). Estas vulnerabilidades cumplían el criterio para "
             "alertar, pero la plataforma NO ha podido comprobar si alguna máquina tiene la "
             "versión vulnerable, así que no han entrado en el correo de seguridad. No se "
             "han perdido: siguen pendientes en la plataforma con su motivo, se vuelven a "
             "evaluar en la siguiente ejecución y entran en el resumen semanal. Este aviso "
             "existe para que un fallo técnico nuestro no pueda callar una vulnerabilidad "
             "sin que nadie se entere.")
    tabla = {"cabeceras": ["Vulnerabilidad", "Severidad", "Explotación activa",
                           "Relevancia", "Por qué no se pudo evaluar"],
             "filas": []}
    for fila in filas[:MAX_EN_AVISO_SIN_EVALUAR]:
        relevancia = fila.get("relevance")
        tabla["filas"].append([
            fila.get("cve") or fila.get("title_es") or fila.get("title_en") or f"amenaza {fila['id']}",
            severidad_texto(fila.get("severity")) if fila.get("severity") else "sin dato",
            "sí (CISA KEV)" if fila.get("in_kev") else "no",
            ("sin dato" if relevancia is None else f"{float(relevancia):.1f}".replace(".", ",")),
            MOTIVO_SIN_EVALUAR_ES.get(fila.get("motivo") or "sin_evaluar",
                                      fila.get("motivo") or "sin dato")])
    if len(filas) > MAX_EN_AVISO_SIN_EVALUAR:
        tabla["filas"].append([f"y {len(filas) - MAX_EN_AVISO_SIN_EVALUAR} más en la plataforma",
                               "—", "—", "—", "—"])
    acciones = ["Revisar en la plataforma, en Amenazas, las que quedaron con el motivo "
                "«a la espera de la evaluación contra el inventario».",
                "Comprobar en Administración → Fuentes si alguna fuente de datos está "
                "caída, y en Administración → Consultas a OCS si la lectura del inventario "
                "ha fallado."]
    if kev:
        acciones.insert(0, f"{kev} de ellas tienen explotación activa confirmada por CISA: "
                           f"conviene comprobarlas a mano hoy mismo.")
    html = render_admin_email(
        titulo=titulo, intro=intro, severidad="critical" if kev else "warning",
        secciones=[{"titulo": "Candidatas a alertar que no se pudieron evaluar",
                    "tabla": tabla}],
        acciones=acciones,
        pie=("Este aviso se repite como mucho una vez al día por vulnerabilidad mientras la "
             "situación siga igual. El criterio de alertar solo lo confirmado se cambia en "
             "Administración → Ajustes, en «Alertar solo lo que afecta a algún activo»."))
    if not mailer.send(subject=asunto_admin(titulo, "critical" if kev else "warning"),
                       html=html, to=destinatarios):
        log.error("no se pudo enviar el aviso de candidatas sin evaluar")
        return None
    sello = _iso(momento)
    for clave, fila in nuevas:
        conn.execute(
            "INSERT OR IGNORE INTO admin_notices(kind, subject_key, sent_at, detail) VALUES(?,?,?,?)",
            (TIPO_AVISO_SIN_EVALUAR, clave, sello,
             f"threat_id={fila['id']} cve={fila.get('cve')} motivo={fila.get('motivo')}"))
    log.info("aviso de candidatas sin evaluar enviado",
             extra={"pendientes": len(filas), "nuevas": len(nuevas), "kev": kev})
    return {"kind": TIPO_AVISO_SIN_EVALUAR, "titulo": titulo,
            "severidad": "critical" if kev else "warning",
            "pendientes": len(filas), "avisadas": len(nuevas), "kev": kev}


# --------------------------------------------------------------------------
# Repaso: recuperar la referencia oficial de las filas ya guardadas (2026-09-06)
# --------------------------------------------------------------------------
def _registro_en_cache(conn: sqlite3.Connection, id_osv: str) -> tuple[bool, Optional[dict]]:
    """(estaba en cache, registro). Lee ``osv_cache`` sin red y sin mirar la caducidad:
    para recuperar la referencia oficial da igual que el registro sea de hace ocho dias."""
    fila = conn.execute("SELECT encontrado, json FROM osv_cache WHERE id=?", (id_osv,)).fetchone()
    if fila is None:
        return False, None
    if not fila["encontrado"] or not fila["json"]:
        return True, None
    try:
        return True, json.loads(fila["json"])
    except ValueError:
        return True, None


#: Fila sin respaldo: ni la columna ``referencia`` del esquema v8 ni la marca antigua
#: dentro de la evidencia.
_SQL_SIN_REFERENCIA = ("(ap.referencia IS NULL OR TRIM(ap.referencia) = '') "
                       "AND (ap.evidencia IS NULL OR ap.evidencia NOT LIKE ?)")


def repasar_referencias(conn: sqlite3.Connection, *, cfg: Any = None,
                        osv: Optional[ClienteOSV] = None, limite_consultas: Optional[int] = None,
                        limite_grupos: int = 500, veredictos: Iterable[str] = (AFECTADO,),
                        vuxml: Optional[IndiceVuXML] = None,
                        cargar_indice_vuxml: Optional[Callable[[], Optional[IndiceVuXML]]] = None
                        ) -> dict[str, Any]:
    """Pone la referencia oficial en las filas de ``aplicabilidad`` que se guardaron sin ella.

    Al 2026-09-06 la base real tenia 24.476 filas «afectado» sin ningun aviso ni fuente que
    las sustentara: sin eso el equipo que aplica el parche no puede comprobar nada. Este
    repaso las agrupa por (CVE, motor, sistema) y resuelve cada grupo con UNA sola sentencia:

    * motor ``osv``: registro de OSV.dev, **primero desde la cache** (``osv_cache``, sin red);
      solo si no esta en cache se gasta una consulta, y nunca mas de ``limite_consultas``
      por ejecucion. De ahi salen la referencia oficial y los identificadores USN/DSA/DLA.
    * motor ``vuxml``: la pagina de la entrada de VuXML. Si no se pasa el indice, el repaso
      lo CARGA POR SI MISMO en cuanto encuentra un grupo de ese motor (cache diaria de
      ``data/cache/vuxml.xml``): antes esas filas caian al respaldo generico.
    * motor ``version``: la ficha del CVE en el NIST, siempre. Ese motor compara la version
      del programa con la que enuncia el aviso, no el paquete de la distribucion.
    * resto de motores: el aviso que ya tenia la fila o la direccion canonica del CVE.

    No borra ni reescribe nada mas: solo anade la referencia al final de la evidencia y
    rellena ``aviso`` cuando estaba vacio. Es idempotente (las filas que ya la tienen no
    entran) y se puede ejecutar tantas veces como haga falta.
    """
    marca_like = f"%[{MARCA_REFERENCIA}%"
    lista_veredictos = [v for v in veredictos if v in VEREDICTOS] or [AFECTADO]
    marcas_v = ",".join("?" * len(lista_veredictos))
    stats: dict[str, Any] = {"grupos": 0, "resueltos": 0, "filas": 0, "peticiones": 0,
                             "desde_cache": 0, "sin_referencia": 0, "avisos": 0,
                             "cupo_agotado": False, "vuxml_cargado": False}
    indice_vuxml = vuxml
    vuxml_intentado = vuxml is not None
    grupos = [dict(r) for r in conn.execute(
        f"""SELECT ap.cve, ap.motor, a.ecosistema, a.so_familia, COUNT(*) AS filas,
                   MIN(ap.aviso) AS aviso
              FROM aplicabilidad ap JOIN activos a ON a.id = ap.activo_id
             WHERE ap.veredicto IN ({marcas_v}) AND {_SQL_SIN_REFERENCIA}
             GROUP BY ap.cve, ap.motor, a.ecosistema, a.so_familia
             ORDER BY filas DESC
             LIMIT ?""", (*lista_veredictos, marca_like, int(limite_grupos)))]
    stats["grupos"] = len(grupos)
    if not grupos:
        return stats
    if osv is None:
        osv = ClienteOSV(conn, cfg=cfg, max_peticiones=(
            limite_consultas if limite_consultas is not None
            else _ajuste(cfg, "applicability_max_osv_per_run", 300)))
    elif limite_consultas is not None:
        osv.max = min(osv.max, int(limite_consultas))

    propia = not conn.in_transaction
    if propia:
        conn.execute("BEGIN")
    try:
        for grupo in grupos:
            cve = (grupo["cve"] or "").upper()
            familia = familia_de_ecosistema(grupo["ecosistema"]) or (grupo["so_familia"] or "")
            referencia = ""
            avisos_texto: Optional[str] = None
            if grupo["motor"] == "osv" and grupo["ecosistema"] and familia in PREFIJO_OSV:
                id_osv = f"{PREFIJO_OSV[familia]}-{cve}"
                estaba, registro = _registro_en_cache(conn, id_osv)
                if estaba:
                    stats["desde_cache"] += 1
                elif osv.agotado:
                    stats["cupo_agotado"] = True
                    stats["sin_referencia"] += 1
                    continue
                else:
                    try:
                        registro = osv.registro(id_osv)
                    except ErrorOSV:
                        stats["sin_referencia"] += 1
                        continue
                    stats["peticiones"] += 1
                if registro is not None:
                    referencia = referencia_osv(registro, ecosistema=grupo["ecosistema"], cve=cve)
                    avisos = avisos_de(registro)
                    avisos_texto = ", ".join(avisos[:2]) or None
            elif grupo["motor"] == "vuxml":
                if indice_vuxml is None and not vuxml_intentado:
                    # Hallazgo 5: sin el indice, las filas de FreeBSD caian al respaldo
                    # generico. Se carga una sola vez y solo si hace falta.
                    vuxml_intentado = True
                    try:
                        cargar = cargar_indice_vuxml or (lambda: cargar_vuxml(cfg=cfg))
                        indice_vuxml = cargar()
                    except Exception as exc:  # noqa: BLE001 - el repaso no depende de VuXML
                        log.warning("el repaso no pudo cargar VuXML", extra={"error": str(exc)})
                        indice_vuxml = None
                    stats["vuxml_cargado"] = indice_vuxml is not None
                if indice_vuxml is not None:
                    indices = indice_vuxml.por_cve.get(cve, [])
                    referencia = indice_vuxml.entradas[indices[0]]["referencia"] if indices else ""
            # El aviso de la propia fila solo vale si su direccion es de un servidor oficial;
            # si no, se usa la canonica del CVE segun el motor (hallazgos 1 y 4).
            referencia = referencia_segura(
                referencia or next((a["url"] for a in avisos_con_url(grupo["aviso"]) if a["url"]), ""),
                cve=cve, ecosistema=grupo["ecosistema"], familia=familia, motor=grupo["motor"])
            if not referencia:
                stats["sin_referencia"] += 1
                continue
            cur = conn.execute(
                f"""UPDATE aplicabilidad
                       SET referencia = ?,
                           aviso = COALESCE(aviso, ?)
                     WHERE cve = ? AND motor = ? AND veredicto IN ({marcas_v})
                       AND (referencia IS NULL OR TRIM(referencia) = '')
                       AND (evidencia IS NULL OR evidencia NOT LIKE ?)
                       AND activo_id IN (SELECT id FROM activos
                                          WHERE ecosistema IS ? AND so_familia IS ?)""",
                (referencia, avisos_texto, grupo["cve"], grupo["motor"],
                 *lista_veredictos, marca_like, grupo["ecosistema"], grupo["so_familia"]))
            stats["resueltos"] += 1
            stats["filas"] += cur.rowcount or 0
            if avisos_texto:
                stats["avisos"] += 1
        if propia:
            conn.execute("COMMIT")
    except Exception:
        if propia and conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    log.info("repaso de referencias oficiales", extra={k: stats[k] for k in
                                                       ("grupos", "resueltos", "filas", "peticiones")})
    return stats


# --------------------------------------------------------------------------
# Consulta manual: ¿le aplica este CVE a este activo?
# --------------------------------------------------------------------------
def responder_cve(conn: sqlite3.Connection, activo_id: int, cve: str, *, cfg: Any = None,
                  osv: Optional[ClienteOSV] = None, vuxml: Optional[IndiceVuXML] = None) -> dict[str, Any]:
    """Respuesta inmediata para la ficha del activo: veredicto global, filas por
    paquete y lineas de explicacion. Persiste lo que evalua.

    Es una funcion de EVALUACION y evalua TODO, tambien la severidad baja (2026-09-10).
    No es una cifra ni una lista: es la respuesta a una pregunta concreta que alguien
    escribe («¿me afecta CVE-2026-1234 en este servidor?»), y responder «no hay datos»
    porque el CVE es de severidad baja seria mentir sobre un hecho comprobado contra OCS
    Inventory. Lo que evalua se guarda en ``aplicabilidad``, y de ahi NO pasa a ninguna
    cifra ni a ninguna lista mientras el ajuste ``ignore_low_severity`` este activo: las
    lecturas de este modulo (``conteo_activo``, ``vulnerabilidades_activo``,
    ``plan_remediacion``, ``veredictos_de_activo``…) lo dejan fuera."""
    cve = (cve or "").strip().upper()
    activo = conn.execute("SELECT * FROM activos WHERE id=?", (activo_id,)).fetchone()
    if activo is None or not _RE_CVE.fullmatch(cve):
        return {"cve": cve, "veredicto": SIN_DATO, "filas": [], "lineas": ["CVE o activo no válido"],
                "amenaza": None}
    activo = dict(activo)
    amenaza = conn.execute(
        "SELECT id, cve, title_en, title_es, summary_en, summary_es, severity, in_kev, relevance FROM threats "
        "WHERE cve LIKE ? ORDER BY relevance DESC LIMIT 1", (f"%{cve}%",)).fetchone()
    amenaza = dict(amenaza) if amenaza else None
    osv = osv or ClienteOSV(conn, cfg=cfg)
    if vuxml is None and activo["so_familia"] == "freebsd":
        vuxml = cargar_vuxml(cfg=cfg)
    ahora = marca_evaluacion()
    pseudo = dict(amenaza or {"id": None, "title_en": "", "summary_en": ""})
    pseudo["cve"] = cve
    r = evaluar_amenaza(conn, pseudo, cfg=cfg, osv=osv, vuxml=vuxml, ahora=ahora, solo_activo=activo_id)
    filas = [dict(f) for f in conn.execute(
        """SELECT * FROM aplicabilidad WHERE activo_id=? AND cve=? AND evaluado_at=?
           ORDER BY CASE veredicto WHEN 'afectado' THEN 0 WHEN 'no_afectado' THEN 1 ELSE 2 END, paquete""",
        (activo_id, cve, ahora))]
    lineas = list(r["detalle"]) + [f"Sin respuesta: {e}" for e in r["errores"]]
    if any(f["veredicto"] == AFECTADO for f in filas):
        veredicto = AFECTADO
    elif any(f["veredicto"] == NO_AFECTADO for f in filas):
        veredicto = NO_AFECTADO
    elif filas:
        veredicto = SIN_DATO
    else:
        # Sin filas: o la distribucion no esta afectada (OSV lo dice) o no hay datos
        no_lista = any("no la lista" in l or "no tiene instalados" in l or "ningún servidor tiene" in l
                       for l in lineas)
        veredicto = NO_AFECTADO if (no_lista and not r["errores"]) else SIN_DATO
        if not lineas:
            lineas.append("No hay datos de la distribución ni versiones comparables para este activo")
    if amenaza and r["filas"]:
        from . import enrich
        enrich.recalcular_relevancia(conn, cfg, threat_ids=[amenaza["id"]])
    return {"cve": cve, "veredicto": veredicto, "filas": filas, "lineas": lineas, "amenaza": amenaza,
            "evaluado_at": ahora}


# --------------------------------------------------------------------------
# Lecturas para la interfaz, el correo y el informe
# --------------------------------------------------------------------------
# --------------------------------------------------------------------------
# Desglose por sistema operativo (2026-09-06)
# --------------------------------------------------------------------------
# El usuario pidio comprobar «si para todos los sistemas operativos aplica la misma version
# y vulnerabilidad o no»: un mismo CVE se corrige en Ubuntu 22.04 con 5.34.0-3ubuntu1.8, en
# Ubuntu 26.04 con 5.40.1-7ubuntu0.1 y en Debian 12 y 13 todavia no se corrige. Cada activo
# recibe SOLO la version de su propio ecosistema (asi lo evalua ``evaluar_amenaza``), y este
# desglose lo pone por escrito: una fila por sistema, con su version que corrige o el motivo
# de que no exista, y la fuente oficial que lo sustenta.
def nombre_sistema(ecosistema: Optional[str] = None, so_nombre: Optional[str] = None,
                   so_ciclo: Optional[str] = None, so_familia: Optional[str] = None) -> str:
    """Nombre legible del sistema operativo: 'Ubuntu:22.04' -> «Ubuntu 22.04»;
    FreeBSD y Windows no tienen ecosistema en OSV.dev y se nombran con ``so_nombre``
    (y el ciclo, si aporta algo: «Windows 11 Pro (25H2)»)."""
    eco = (ecosistema or "").strip()
    if eco:
        familia, _, resto = eco.partition(":")
        etiqueta = FAMILIA_ES.get(familia.lower(), familia)
        return f"{etiqueta} {resto.replace(':', ' ')}".strip()
    nombre = (so_nombre or "").strip()
    ciclo = (so_ciclo or "").strip()
    if not nombre:
        nombre = FAMILIA_ES.get((so_familia or "").lower(), "Sin datos de sistema")
    if ciclo:
        if (so_familia or "").lower() == "windows" and "-" in ciclo:
            ciclo = ciclo.partition("-")[2].upper()
        if ciclo and ciclo.lower() not in nombre.lower():
            return f"{nombre} ({ciclo})"
    return nombre


def _familia_activo(ecosistema: Optional[str], so_familia: Optional[str]) -> Optional[str]:
    fam = familia_de_ecosistema(ecosistema) or (so_familia or "").strip().lower()
    return fam or None


def _mas_antigua(familia: Optional[str], versiones: Iterable[str]) -> Optional[str]:
    peor: Optional[str] = None
    for v in versiones:
        if v and (peor is None or comparar_familia(familia, v, peor) < 0):
            peor = v
    return peor


def dato_fila(fila: Any, clave: str, defecto: Any = None) -> Any:
    """Lee una clave de una fila que puede ser ``sqlite3.Row`` o diccionario incompleto."""
    try:
        valor = fila[clave]
    except (KeyError, IndexError, TypeError):
        return defecto
    return defecto if valor is None else valor


#: Nombre de respaldo cuando la fila no trae paquete: nunca se pierde la fila ni se le
#: atribuye el nombre de otra.
SIN_PAQUETE = "sin nombre de paquete"


def _paquetes_de_fila(fila: Any) -> list[str]:
    """Nombres de paquete de una fila. Una fila de ``aplicabilidad`` es SIEMPRE un paquete
    (clave unica activo, CVE, paquete); si llega una lista ya agrupada se respeta."""
    uno = str(dato_fila(fila, "paquete", "") or "").strip()
    if uno:
        return [uno]
    nombres: list[str] = []
    for p in (dato_fila(fila, "paquetes") or []):
        nombre = str((p.get("paquete") if isinstance(p, dict) else p) or "").strip()
        if nombre and nombre not in nombres:
            nombres.append(nombre)
    return nombres or [SIN_PAQUETE]


def _mas_visto(conteo: dict) -> Any:
    """La clave mas repetida (empates por orden alfabetico, para que sea reproducible)."""
    if not conteo:
        return None
    return sorted(conteo.items(), key=lambda kv: (-kv[1], str(kv[0])))[0][0]


def _acumular_sistema(grupos: dict[str, dict], fila: Any) -> None:
    """Suma una fila de ``aplicabilidad`` (ya con los datos del activo) a su sistema.

    Todo lo que tiene que ver con versiones se acumula POR PAQUETE, y ademas por pareja
    (instalada, corregida) tal como aparece en el dato: asi ninguna frase puede afirmar una
    pareja que no exista (hallazgo 3 de la revision del 2026-09-06)."""
    ecosistema = str(dato_fila(fila, "ecosistema", "")).strip()
    so_nombre = str(dato_fila(fila, "so_nombre", "")).strip()
    so_ciclo = str(dato_fila(fila, "so_ciclo", "")).strip()
    so_familia = str(dato_fila(fila, "so_familia", "")).strip()
    clave = ecosistema or f"{so_nombre}|{so_ciclo}"
    grupo = grupos.get(clave)
    if grupo is None:
        grupo = grupos[clave] = {
            "clave": clave, "ecosistema": ecosistema or None,
            "nombre": nombre_sistema(ecosistema, so_nombre, so_ciclo, so_familia),
            "familia": _familia_activo(ecosistema, so_familia),
            "_activos": set(), "_expuestos": set(), "_por_paquete": {},
            "_avisos": {}, "_referencias": {}, "_motores": {}}
    identificador = dato_fila(fila, "activo_id", dato_fila(fila, "id"))
    grupo["_activos"].add(identificador)
    if dato_fila(fila, "entorno", "") in ENTORNOS_EXPUESTOS:
        grupo["_expuestos"].add(identificador)
    instalada = dato_fila(fila, "version_instalada")
    corregida = dato_fila(fila, "version_corregida")
    clave_motivo = dato_fila(fila, "sin_parche_motivo") or "desconocido"
    motor = str(dato_fila(fila, "motor", "") or "").strip().lower() or None
    avisos_fila = avisos_con_url(dato_fila(fila, "aviso", ""))
    referencia = referencia_de_fila(fila)
    for paquete in _paquetes_de_fila(fila):
        detalle = grupo["_por_paquete"].setdefault(paquete, {
            "instaladas": set(), "corregidas": set(), "parejas": {}, "motivos": {},
            "avisos": {}, "referencias": {}, "motores": {}, "n_filas": 0})
        detalle["n_filas"] += 1
        if instalada:
            detalle["instaladas"].add(instalada)
        if corregida:
            detalle["corregidas"].add(corregida)
            pareja = (instalada, corregida)
            detalle["parejas"][pareja] = detalle["parejas"].get(pareja, 0) + 1
        else:
            detalle["motivos"][clave_motivo] = detalle["motivos"].get(clave_motivo, 0) + 1
        for aviso in avisos_fila:
            detalle["avisos"].setdefault(aviso["id"].upper(), aviso)
        if referencia:
            detalle["referencias"][referencia] = detalle["referencias"].get(referencia, 0) + 1
        if motor:
            detalle["motores"][motor] = detalle["motores"].get(motor, 0) + 1
    for aviso in avisos_fila:
        grupo["_avisos"].setdefault(aviso["id"].upper(), aviso)
    if referencia:
        grupo["_referencias"][referencia] = grupo["_referencias"].get(referencia, 0) + 1
    if motor:
        grupo["_motores"][motor] = grupo["_motores"].get(motor, 0) + 1


def _cerrar_paquete(familia: Optional[str], paquete: str, detalle: dict, *,
                    cve: Optional[str] = None, ecosistema: Optional[str] = None) -> dict:
    """Plan de UN paquete dentro de un sistema: de que version a que version, con que
    explicacion y con que fuente oficial.

    Si el mismo paquete tiene varias versiones que lo corrigen en el mismo sistema (dos
    avisos, o el mismo puerto en dos ramas), no se inventa una pareja: se dicen las parejas
    que hay, una por una."""
    corregidas = sorted(detalle["corregidas"])
    parejas_conteo: dict = detalle["parejas"]
    motivos = detalle["motivos"]
    motivo = _mas_visto(motivos)
    avisos = list(detalle["avisos"].values())
    motor = _mas_visto(detalle["motores"])
    referencia = referencia_segura(
        _mas_visto(detalle["referencias"]) or next((a["url"] for a in avisos if a["url"]), ""),
        cve=cve, ecosistema=ecosistema, familia=familia, motor=motor)
    varias_corregidas = len(corregidas) > 1
    if len(corregidas) == 1:
        corregida = corregidas[0]
        # La instalada se elige entre las que de verdad van con ESA version corregida.
        instalada = _mas_antigua(familia, [i for (i, c) in parejas_conteo if c == corregida and i])
    else:
        corregida = None
        instalada = None if varias_corregidas else _mas_antigua(familia, detalle["instaladas"])
    parejas = [{"instalada": i, "corregida": c, "n_filas": n,
                "comparacion": explicar_comparacion(familia, i, c)}
               for (i, c), n in sorted(parejas_conteo.items(),
                                       key=lambda kv: (str(kv[0][1]), str(kv[0][0])))]
    salida = {
        "paquete": paquete, "version_instalada": instalada, "version_corregida": corregida,
        "versiones_corregidas": corregidas, "varias_corregidas": varias_corregidas,
        "hay_correccion": bool(corregidas), "parejas": parejas, "n_filas": detalle["n_filas"],
        "motor": motor, "motor_es": MOTOR_ES.get(str(motor or ""), motor),
        "avisos": avisos, "referencia": referencia,
        "referencia_es": etiqueta_referencia(referencia),
        "sin_parche_motivo": None if corregidas else motivo,
        "sin_parche_texto": None if corregidas else texto_sin_correccion(motivo),
        "sin_parche_motivo_es": None if corregidas else motivo_sin_parche_es(motivo),
        "comparacion": (None if varias_corregidas
                        else explicar_comparacion(familia, instalada, corregida))}
    if corregida:
        salida["accion"] = f"actualizar de {instalada or 'la versión instalada'} a {corregida}"
    elif varias_corregidas:
        trozos = [f"de {p['instalada'] or 'la versión instalada'} a {p['corregida']}"
                  for p in parejas[:3]]
        salida["accion"] = ("actualizar a la versión que indica el aviso de cada equipo: "
                            + "; ".join(trozos)
                            + (f"; y {len(parejas) - 3} parejas más" if len(parejas) > 3 else ""))
    else:
        salida["accion"] = salida["sin_parche_texto"]
    return salida


def _cerrar_sistema(grupo: dict, cve: Optional[str] = None) -> dict:
    """Convierte los acumuladores en la fila que ven el correo y la interfaz.

    ``paquetes_detalle`` es la FUENTE DE VERDAD del plan. Solo cuando el sistema tiene un
    unico paquete se resume en una sola pareja de versiones (``plan_unico``); con varios,
    las claves ``version_instalada`` y ``version_corregida`` quedan vacias a proposito y
    quien pinta la fila tiene que recorrer ``paquetes_detalle``, porque mezclar el sistema
    base 14.4_5 con el puerto openssl 3.0.22,1 seria falso."""
    familia = grupo["familia"]
    por_paquete = grupo.pop("_por_paquete")
    avisos = list(grupo.pop("_avisos").values())
    referencias = grupo.pop("_referencias")
    motor = _mas_visto(grupo.pop("_motores"))
    detalle = [_cerrar_paquete(familia, nombre, datos, cve=cve, ecosistema=grupo["ecosistema"])
               for nombre, datos in sorted(por_paquete.items())]
    referencia = referencia_segura(
        _mas_visto(referencias) or next((a["url"] for a in avisos if a["url"]), ""),
        cve=cve, ecosistema=grupo["ecosistema"], familia=familia, motor=motor)
    corregidas = sorted({v for d in detalle for v in d["versiones_corregidas"]})
    hay_correccion = any(d["hay_correccion"] for d in detalle)
    plan_unico = len(detalle) == 1
    motivos: dict[str, int] = {}
    for d in detalle:
        if d["sin_parche_motivo"]:
            motivos[d["sin_parche_motivo"]] = motivos.get(d["sin_parche_motivo"], 0) + 1
    motivo = _mas_visto(motivos)
    if plan_unico:
        uno = detalle[0]
        instalada, corregida = uno["version_instalada"], uno["version_corregida"]
        comparacion, accion = uno["comparacion"], uno["accion"]
    else:
        instalada = corregida = comparacion = None
        trozos = [f"{d['paquete']}, {d['accion']}" for d in detalle[:4]]
        accion = "plan por paquete: " + "; ".join(trozos)
        if len(detalle) > 4:
            accion += f"; y otros {len(detalle) - 4} paquetes"
    grupo.update(
        n_activos=len(grupo.pop("_activos")), n_expuestos=len(grupo.pop("_expuestos")),
        paquetes=sorted(por_paquete), paquetes_detalle=detalle, n_paquetes=len(detalle),
        plan_unico=plan_unico, version_instalada=instalada, version_corregida=corregida,
        versiones_corregidas=corregidas, hay_correccion=hay_correccion,
        todas_con_correccion=bool(detalle) and all(d["hay_correccion"] for d in detalle),
        sin_parche_motivo=None if hay_correccion else motivo,
        sin_parche_texto=None if hay_correccion else texto_sin_correccion(motivo),
        sin_parche_motivo_es=None if hay_correccion else motivo_sin_parche_es(motivo),
        motor=motor, motor_es=MOTOR_ES.get(str(motor or ""), motor),
        avisos=avisos, referencia=referencia, referencia_es=etiqueta_referencia(referencia),
        comparacion=comparacion, accion=accion)
    return grupo


def desglose_por_sistema(filas: Iterable[Any], *, cve: Optional[str] = None) -> list[dict]:
    """Agrupa filas de ``aplicabilidad`` por sistema operativo. Las de mas activos primero."""
    grupos: dict[str, dict] = {}
    for fila in filas:
        _acumular_sistema(grupos, fila)
    salida = [_cerrar_sistema(g, cve) for g in grupos.values()]
    salida.sort(key=lambda g: (-g["n_activos"], g["nombre"]))
    return salida


def detalle_paquete_de_fila(fila: Any, *, cve: Optional[str] = None) -> dict:
    """Plan de UN paquete de UN activo, calculado con los datos de SU fila.

    Es la pieza que arregla el hallazgo 2 de la revision del 2026-09-06: la explicacion de
    la comparacion, la version instalada, la corregida, el aviso y la fuente oficial salen
    de la misma fila, asi que la frase describe siempre el paquete que se esta mirando."""
    motor = dato_fila(fila, "motor")
    ecosistema = dato_fila(fila, "ecosistema")
    so_familia = dato_fila(fila, "so_familia")
    instalada = dato_fila(fila, "version_instalada")
    corregida = dato_fila(fila, "version_corregida")
    motivo = dato_fila(fila, "sin_parche_motivo")
    evidencia = partir_evidencia(dato_fila(fila, "evidencia", ""))[0]
    avisos = avisos_con_url(dato_fila(fila, "aviso", ""))
    referencia = referencia_segura(
        referencia_de_fila(fila) or next((a["url"] for a in avisos if a["url"]), ""),
        cve=dato_fila(fila, "cve", cve), ecosistema=ecosistema, familia=so_familia, motor=motor)
    salida = {
        "paquete": str(dato_fila(fila, "paquete", "") or SIN_PAQUETE),
        "version_instalada": instalada, "version_corregida": corregida,
        "hay_correccion": bool(corregida), "motor": motor,
        "motor_es": MOTOR_ES.get(str(motor or ""), motor),
        "evidencia": evidencia, "aviso": dato_fila(fila, "aviso"), "avisos": avisos,
        "referencia": referencia, "referencia_es": etiqueta_referencia(referencia),
        "comparacion": explicar_comparacion(
            familia_comparacion(motor, ecosistema, so_familia), instalada, corregida),
        "sin_parche_motivo": None if corregida else motivo,
        "sin_parche_texto": None if corregida else texto_sin_correccion(motivo),
        "sin_parche_motivo_es": None if corregida else motivo_sin_parche_es(motivo)}
    salida["accion"] = (f"actualizar de {instalada or 'la versión instalada'} a {corregida}"
                        if corregida else salida["sin_parche_texto"])
    return salida


def _cerrar_activo(activo: dict, *, cve: Optional[str] = None) -> dict:
    """Cierra un activo de la lista de afectados a partir de sus paquetes.

    ``paquetes_detalle`` es la fuente de verdad. ``mismo_plan`` dice si TODOS sus paquetes
    coinciden en la version instalada y en la corregida: solo entonces tiene sentido una
    sola linea por activo con una pareja de versiones. Si no coinciden, esas claves quedan
    vacias y la interfaz y el correo pintan una fila por paquete."""
    detalle: list[dict] = activo["paquetes_detalle"]
    parejas = {(d["version_instalada"], d["version_corregida"]) for d in detalle}
    activo["n_paquetes"] = len(detalle)
    activo["mismo_plan"] = len(parejas) <= 1
    activo["versiones_corregidas"] = sorted({d["version_corregida"] for d in detalle
                                             if d["version_corregida"]})
    activo["hay_correccion"] = any(d["hay_correccion"] for d in detalle)
    avisos: dict[str, dict] = {}
    referencias: dict[str, int] = {}
    motores: dict[str, int] = {}
    for d in detalle:
        for aviso in d["avisos"]:
            avisos.setdefault(aviso["id"].upper(), aviso)
        if d["referencia"]:
            referencias[d["referencia"]] = referencias.get(d["referencia"], 0) + 1
        if d["motor"]:
            motores[str(d["motor"])] = motores.get(str(d["motor"]), 0) + 1
    activo["avisos"] = list(avisos.values())
    activo["motor"] = _mas_visto(motores)
    activo["motor_es"] = MOTOR_ES.get(str(activo["motor"] or ""), activo["motor"])
    activo["referencia"] = referencia_segura(
        _mas_visto(referencias) or next((a["url"] for a in activo["avisos"] if a["url"]), ""),
        cve=cve, ecosistema=activo.get("ecosistema"), familia=activo.get("so_familia"),
        motor=activo["motor"])
    activo["referencia_es"] = etiqueta_referencia(activo["referencia"])
    if activo["mismo_plan"] and detalle:
        uno = detalle[0]
        activo.update(version_instalada=uno["version_instalada"],
                      version_corregida=uno["version_corregida"],
                      comparacion=uno["comparacion"], accion=uno["accion"],
                      evidencia=uno["evidencia"],
                      sin_parche_motivo=uno["sin_parche_motivo"],
                      sin_parche_texto=uno["sin_parche_texto"],
                      sin_parche_motivo_es=uno["sin_parche_motivo_es"])
        return activo
    # Paquetes con planes distintos: ninguna pareja de versiones representa al activo.
    trozos = [f"{d['paquete']}, {d['accion']}" for d in detalle[:4]]
    activo.update(version_instalada=None, version_corregida=None, comparacion=None,
                  evidencia="", sin_parche_motivo=None, sin_parche_texto=None,
                  sin_parche_motivo_es=None,
                  accion="plan por paquete: " + "; ".join(trozos)
                         + (f"; y otros {len(detalle) - 4} paquetes" if len(detalle) > 4 else ""))
    return activo


def versiones_pedidas_por_paquete(conn: sqlite3.Connection,
                                  pares: Iterable[tuple[int, str]]) -> dict[tuple[int, str], dict]:
    """Para cada (activo, paquete): la version MAS ALTA pedida y cuantas piden los avisos.

    El correo, el libro y el informe escribian la version de ESE aviso, que puede ser mas
    baja que la que de verdad hay que instalar. Medido el 2026-09-09 en produccion: en el
    servidor SRV-EJEMPLO-511 el paquete `linux-tools-common` tiene 29 vulnerabilidades
    abiertas que piden siete versiones distintas, de 6.8.0-117.117 a 6.8.0-139.139; el
    correo de la primera decia «actualizar a 6.8.0-117.117», que ya no basta. Peticion
    literal del usuario: «que la remediacion indique si o si la ultima version a la que se
    debe actualizar». Hay 1.456 pares (activo, paquete) en esa situacion, y el caso mayor
    es `windows` con 1.233 vulnerabilidades y ocho compilaciones destino.

    Devuelve ``{(activo_id, paquete): {"version_objetivo", "versiones_pedidas",
    "vulnerabilidades"}}`` para los pares pedidos; los que no tienen ninguna correccion
    conocida no aparecen.

    La severidad baja no entra en la cuenta (2026-09-10, ajuste ``ignore_low_severity``):
    ni suma vulnerabilidades ni puede ser la que fije la version objetivo. Si la version
    mas alta la pidiera una vulnerabilidad baja, el correo y el informe mandarian instalar
    una version por algo que no se reporta.

    Lo que cubre una excepcion vigente tampoco entra (2026-09-10, mismo motivo): mandar
    instalar una version por una vulnerabilidad cuyo riesgo la organizacion acepto por
    escrito, con responsable y con fecha, seria contradecir la decision que se tomo.
    """
    from .remediacion import version_objetivo
    sin_bajas = _y_sin_bajas(conn) + _y_sin_excepcion(conn)
    pares = list({(int(a), str(p)) for a, p in pares if a and p})
    if not pares:
        return {}
    salida: dict[tuple[int, str], dict] = {}
    for inicio in range(0, len(pares), 300):
        lote = pares[inicio:inicio + 300]
        marcas = ",".join("(?,?)" for _ in lote)
        parametros: list[Any] = []
        for activo_id, paquete in lote:
            parametros.extend((activo_id, paquete))
        crudas: dict[tuple[int, str], dict] = {}
        for r in conn.execute(
                f"""SELECT ap.activo_id, ap.paquete, ap.version_corregida, ap.cve, a.so_familia
                      FROM aplicabilidad ap JOIN activos a ON a.id = ap.activo_id
                     WHERE ap.veredicto='afectado' AND a.presente=1{sin_bajas}
                       AND (ap.activo_id, ap.paquete) IN ({marcas})""", parametros):
            clave = (int(r["activo_id"]), str(r["paquete"]))
            entrada = crudas.setdefault(clave, {"versiones": set(), "cves": set(),
                                                "familia": r["so_familia"]})
            if r["version_corregida"]:
                entrada["versiones"].add(r["version_corregida"])
            if r["cve"]:
                entrada["cves"].add(r["cve"])
        for clave, entrada in crudas.items():
            if not entrada["versiones"]:
                continue
            salida[clave] = {
                "version_objetivo": version_objetivo(entrada["familia"], entrada["versiones"]),
                "versiones_pedidas": len(entrada["versiones"]),
                "vulnerabilidades": len(entrada["cves"]),
            }
    return salida


def anotar_version_ultima(conn: sqlite3.Connection, activos: Iterable[dict]) -> None:
    """Escribe en cada ``paquetes_detalle`` la ultima version que hay que instalar.

    Anade ``version_ultima``, ``versiones_pedidas`` y ``vulnerabilidades_paquete``, y
    ``version_ultima_distinta`` cuando la de ese aviso no es la definitiva: quien lea el
    correo o el informe tiene que instalar la ultima, no la del aviso que dispara el envio
    (peticion del usuario del 2026-09-09).
    """
    activos = [a for a in activos if a]
    pares = [(a.get("id"), d.get("paquete"))
             for a in activos for d in (a.get("paquetes_detalle") or [])
             if a.get("id") and d.get("paquete")]
    if not pares:
        return
    mapa = versiones_pedidas_por_paquete(conn, pares)
    for a in activos:
        for d in a.get("paquetes_detalle") or []:
            info = mapa.get((int(a["id"]), str(d.get("paquete") or "")))
            if not info:
                continue
            d["version_ultima"] = info["version_objetivo"]
            d["versiones_pedidas"] = info["versiones_pedidas"]
            d["vulnerabilidades_paquete"] = info["vulnerabilidades"]
            # El libro de la alerta llama «corregida» a la misma clave que el correo llama
            # «version_corregida»: se admiten las dos para no dar por «igual» lo distinto.
            pedida = d.get("version_corregida") or d.get("corregida")
            d["version_ultima_distinta"] = bool(
                info["version_objetivo"] and pedida and info["version_objetivo"] != pedida)


def anotar_version_ultima_sistemas(conn: sqlite3.Connection, sistemas: Iterable[dict]) -> None:
    """La ultima version a instalar de cada paquete, por sistema operativo.

    El correo agrupa por sistema, no por activo, y escribia la version que pedia ESE aviso.
    Aqui se anade la mas alta que piden TODAS las vulnerabilidades abiertas de ese paquete
    en los activos de ese sistema, que es la unica que resuelve la cola completa (peticion
    del usuario del 2026-09-09). Anade ``version_ultima``, ``versiones_pedidas``,
    ``vulnerabilidades_paquete`` y ``version_ultima_distinta`` a cada ``paquetes_detalle``.

    La severidad baja no cuenta (2026-09-10, ajuste ``ignore_low_severity``): ni en el
    numero de vulnerabilidades del paquete ni en la version que se manda instalar. El
    riesgo aceptado con una excepcion vigente tampoco (2026-09-10).
    """
    from .remediacion import version_objetivo
    sin_bajas = _y_sin_bajas(conn) + _y_sin_excepcion(conn)
    sistemas = [g for g in sistemas if g]
    peticiones: dict[tuple[str, str], list[dict]] = {}
    for g in sistemas:
        familia = str(g.get("familia") or "")
        for d in g.get("paquetes_detalle") or []:
            paquete = str(d.get("paquete") or "")
            if paquete:
                peticiones.setdefault((familia, paquete), []).append(d)
    if not peticiones:
        return
    for familia, paquete in list(peticiones):
        filas = conn.execute(
            f"""SELECT ap.version_corregida, ap.cve FROM aplicabilidad ap
                 JOIN activos a ON a.id = ap.activo_id
                WHERE ap.veredicto='afectado' AND a.presente=1 AND ap.paquete=?{sin_bajas}
                  AND (? = '' OR a.so_familia = ? OR a.ecosistema = ?)""",
            (paquete, familia, familia, familia)).fetchall()
        versiones = {r["version_corregida"] for r in filas if r["version_corregida"]}
        if not versiones:
            continue
        cves = {r["cve"] for r in filas if r["cve"]}
        ultima = version_objetivo(familia or None, versiones)
        for d in peticiones[(familia, paquete)]:
            d["version_ultima"] = ultima
            d["versiones_pedidas"] = len(versiones)
            d["vulnerabilidades_paquete"] = len(cves)
            d["version_ultima_distinta"] = bool(
                ultima and d.get("version_corregida") and ultima != d.get("version_corregida"))


def activos_de_amenaza(conn: sqlite3.Connection, threat_id: int, *, limite: int = 10) -> dict[str, Any]:
    """Resumen de la ultima evaluacion, lista de activos afectados y desglose por sistema.

    Cada activo trae ``paquetes_detalle``: UNA entrada por paquete instalado, con su version
    instalada, su version corregida, la explicacion de la comparacion, su aviso y la fuente
    oficial que lo sustenta. ``paquetes`` sigue siendo la lista de nombres, y ``mismo_plan``
    dice si todos los paquetes del activo coinciden en instalada y corregida (solo entonces
    el activo tiene una pareja de versiones propia: si no, se pinta una fila por paquete).

    ``sistemas`` es el desglose por sistema operativo, con el mismo criterio: el plan vive
    en ``paquetes_detalle`` y solo se resume en una linea cuando el sistema tiene un unico
    paquete (``plan_unico``).

    NO filtra la severidad baja, y es a proposito (revision del 2026-09-10). La consulta
    esta acotada a UNA amenaza, asi que todas sus filas tienen la severidad de esa
    amenaza: para las que no son bajas el filtro no cambiaria nada, y para una baja
    vaciaria la lista mientras los recuentos guardados de la evaluacion
    (``aplicabilidad_amenaza.afectados``, que la evaluacion sigue escribiendo sobre todo
    por orden del usuario) seguirian diciendo 326 activos en el caso mayor de produccion:
    seria dejar dos cifras de lo mismo en la misma pantalla, que es justo lo que este
    proyecto no admite. Nada que cuente ni que se reporte llega aqui con una amenaza baja:
    :func:`adjuntar_activos` solo se llama con amenazas que ya pasaron el filtro de
    severidad, una baja nunca genera alerta (``queries.motivo_exclusion`` devuelve
    «severidad_baja») y el informe mensual no la incluye. Lo que queda pendiente es una
    decision de la pagina de Amenazas: o su catalogo deja de ofrecer la severidad baja en
    el filtro y en la ficha, o la ficha dice que esa amenaza no se reporta por su
    severidad.

    TAMPOCO filtra el riesgo aceptado con una excepcion vigente, y tambien a proposito
    (2026-09-10). Esta funcion es la LISTA de activos de la ficha de la amenaza, no una
    cifra de riesgo: es el sitio donde hay que poder ver que ese servidor sigue teniendo
    la version vulnerable aunque la organizacion haya aceptado el riesgo hasta una fecha.
    Si se filtrara, la ficha ensenaria una tabla vacia mientras los recuentos guardados de
    la evaluacion (``aplicabilidad_amenaza.afectados``, que la evaluacion sigue
    escribiendo) seguirian diciendo 326 activos en el caso mayor de produccion: dos cifras
    de lo mismo en la misma pantalla. La plantilla ``amenaza_detalle.html`` marca esos
    activos con la insignia «Riesgo aceptado» a partir de ``excepciones.por_cve``, con el
    responsable, la fecha de vencimiento y el enlace a la excepcion. Lo que SI queda fuera
    es el plan de remediacion de esa amenaza (``plan_remediacion``), que es la orden de
    trabajo, y las cifras de ``queries.resumen_amenazas``."""
    fila = conn.execute("SELECT * FROM aplicabilidad_amenaza WHERE threat_id=?", (threat_id,)).fetchone()
    salida: dict[str, Any] = {"evaluada": fila is not None, "evaluado_at": None, "n_afectados": 0,
                              "n_no_afectados": 0, "n_sin_dato": 0, "afectados": [], "mas": 0,
                              "lineas": [], "incompleta": False, "sistemas": [], "cve": None}
    if fila is None:
        return salida
    try:
        detalle = json.loads(fila["detalle"] or "{}")
    except ValueError:
        detalle = {}
    salida.update(evaluado_at=fila["evaluado_at"], n_afectados=int(fila["afectados"] or 0),
                  n_no_afectados=int(fila["no_afectados"] or 0), n_sin_dato=int(fila["sin_dato"] or 0),
                  lineas=list(detalle.get("lineas") or []), incompleta=bool(detalle.get("incompleta")),
                  errores=list(detalle.get("errores") or []))
    por_activo: dict[int, dict] = {}
    cve_principal: Optional[str] = None
    grupos: dict[str, dict] = {}
    for r in conn.execute(
            """SELECT a.id, a.nombre, a.ip, a.origen, a.so_nombre, a.so_version, a.so_familia,
                      a.so_ciclo, a.ecosistema, a.zona, a.entorno, a.proceso,
                      ap.cve, ap.paquete, ap.version_instalada, ap.version_corregida, ap.evidencia,
                      ap.aviso, ap.motor, ap.sin_parche_motivo, ap.referencia
                 FROM aplicabilidad ap JOIN activos a ON a.id = ap.activo_id
                WHERE ap.threat_id=? AND ap.veredicto='afectado' AND a.presente=1
                ORDER BY a.origen, a.nombre, ap.paquete""", (threat_id,)):
        cve_principal = cve_principal or r["cve"]
        # Desglose por sistema operativo: se acumula sobre TODAS las filas, no solo sobre las
        # que caben en la lista, para que las cifras por sistema sean las reales.
        _acumular_sistema(grupos, {**dict(r), "activo_id": r["id"]})
        e = por_activo.setdefault(r["id"], {
            "id": r["id"], "nombre": r["nombre"], "ip": r["ip"], "origen": r["origen"],
            "so_nombre": r["so_nombre"], "so_version": r["so_version"], "zona": r["zona"],
            "so_familia": r["so_familia"], "so_ciclo": r["so_ciclo"], "ecosistema": r["ecosistema"],
            "entorno": r["entorno"], "proceso": r["proceso"],
            "sistema": nombre_sistema(r["ecosistema"], r["so_nombre"], r["so_ciclo"], r["so_familia"]),
            "paquetes": [], "paquetes_detalle": [], "aviso": r["aviso"]})
        e["paquetes"].append(r["paquete"])
        # v8 (2026-09-06, hallazgo 2): una entrada por paquete, con SUS versiones, SU
        # explicacion, SU aviso y SU fuente oficial. Nunca la pareja de la primera fila.
        e["paquetes_detalle"].append(detalle_paquete_de_fila(r, cve=cve_principal))
    lista = [_cerrar_activo(a, cve=cve_principal) for a in por_activo.values()]
    # La ultima version a instalar por paquete, mirando TODAS las vulnerabilidades abiertas
    # de ese paquete en ese activo y no solo esta (peticion del usuario del 2026-09-09).
    salida["afectados"] = lista[:limite] if limite else lista
    anotar_version_ultima(conn, salida["afectados"])
    salida["mas"] = max(0, len(lista) - limite) if limite else 0
    salida["sistemas"] = [_cerrar_sistema(g, cve_principal) for g in grupos.values()]
    anotar_version_ultima_sistemas(conn, salida["sistemas"])
    salida["sistemas"].sort(key=lambda g: (-g["n_activos"], g["nombre"]))
    salida["cve"] = cve_principal
    return salida


def recalcular_resumenes(conn: sqlite3.Connection, *, cfg: Any = None, recalcular_relevancia: bool = True) -> int:
    """Recalcula, sin red, los recuentos por amenaza que dependen del estado actual de los
    activos (afectados en produccion o contingencia, parche disponible, activos presentes).
    Necesario tras una sincronizacion: el entorno o la presencia de un activo pueden cambiar."""
    ids = [r[0] for r in conn.execute("SELECT threat_id FROM aplicabilidad_amenaza")]
    for tid in ids:
        fila = conn.execute(
            """SELECT COUNT(DISTINCT CASE WHEN ap.veredicto='afectado' THEN ap.activo_id END) AS af,
                      COUNT(DISTINCT CASE WHEN ap.veredicto='afectado' AND a.entorno IN ('produccion','contingencia')
                                          THEN ap.activo_id END) AS ex,
                      SUM(ap.veredicto='afectado' AND ap.version_corregida IS NOT NULL) AS parche
                 FROM aplicabilidad ap JOIN activos a ON a.id=ap.activo_id
                WHERE ap.threat_id=? AND a.presente=1""", (tid,)).fetchone()
        no_af = conn.execute(
            """SELECT COUNT(DISTINCT ap.activo_id) FROM aplicabilidad ap JOIN activos a ON a.id=ap.activo_id
                WHERE ap.threat_id=? AND a.presente=1 AND ap.veredicto='no_afectado'
                  AND ap.activo_id NOT IN (SELECT activo_id FROM aplicabilidad WHERE threat_id=? AND veredicto='afectado')""",
            (tid, tid)).fetchone()[0]
        sin_dato = conn.execute(
            """SELECT COUNT(DISTINCT ap.activo_id) FROM aplicabilidad ap JOIN activos a ON a.id=ap.activo_id
                WHERE ap.threat_id=? AND a.presente=1 AND ap.veredicto='sin_dato'
                  AND ap.activo_id NOT IN (SELECT activo_id FROM aplicabilidad WHERE threat_id=? AND veredicto IN ('afectado','no_afectado'))""",
            (tid, tid)).fetchone()[0]
        conn.execute("UPDATE aplicabilidad_amenaza SET afectados=?, no_afectados=?, sin_dato=?, afectados_expuestos=?, "
                     "parche_disponible=? WHERE threat_id=?",
                     (int(fila["af"] or 0), int(no_af or 0), int(sin_dato or 0), int(fila["ex"] or 0),
                      1 if fila["parche"] else 0, tid))
    if recalcular_relevancia and ids:
        from . import enrich
        enrich.recalcular_relevancia(conn, cfg, threat_ids=ids)
    return len(ids)


def adjuntar_activos(conn: sqlite3.Connection, vistas: Iterable[dict], *, limite: int = 10) -> None:
    for v in vistas:
        if v.get("id") is not None:
            v["activos"] = activos_de_amenaza(conn, v["id"], limite=limite)


def adjuntar_resumen(conn: sqlite3.Connection, vistas: list[dict]) -> None:
    """Pone en cada vista ``activos_resumen`` (cifras de la ultima evaluacion) en una
    sola consulta; lo usa el filtro de alertas para no alertar sin activos afectados.

    NO descuenta el riesgo aceptado con una excepcion vigente, a proposito (2026-09-10):
    lee los recuentos GUARDADOS de ``aplicabilidad_amenaza``, que son el resultado de la
    ultima evaluacion tecnica (cuantos activos tenian la version vulnerable, cuantos ya
    la habian corregido y en cuantos no se pudo saber). Restar ahi las excepciones
    confundiria dos cosas distintas: si el resumen dijera «0 afectados» por una decision
    de riesgo, el motivo que se guardaria seria «sin_activos_afectados» —«los activos ya
    llevan la correccion»—, que es falso y borraria de la trazabilidad la decision. Quien
    decide callar la alerta es ``queries._adjuntar_activos_afectados``, que cuenta los
    activos contra la base en el momento y devuelve los aceptados APARTE, para que el
    motivo registrado sea ``riesgo_aceptado`` y el correo lo diga con su nombre."""
    ids = [v["id"] for v in vistas if v.get("id") is not None]
    if not ids:
        return
    por_id: dict[int, dict] = {}
    try:
        for lote in range(0, len(ids), 800):
            trozo = ids[lote:lote + 800]
            for r in conn.execute(
                    f"""SELECT threat_id, evaluado_at, afectados, no_afectados, sin_dato, afectados_expuestos,
                               parche_disponible, detalle FROM aplicabilidad_amenaza
                         WHERE threat_id IN ({','.join('?' * len(trozo))})""", trozo):
                try:
                    detalle = json.loads(r["detalle"] or "{}")
                except ValueError:
                    detalle = {}
                por_id[r["threat_id"]] = {
                    "evaluado_at": r["evaluado_at"], "afectados": int(r["afectados"] or 0),
                    "no_afectados": int(r["no_afectados"] or 0), "sin_dato": int(r["sin_dato"] or 0),
                    "afectados_expuestos": int(r["afectados_expuestos"] or 0),
                    "parche_disponible": int(r["parche_disponible"] or 0),
                    "incompleta": bool(detalle.get("incompleta")),
                    "distro_no_afectada": bool(detalle.get("distro_no_afectada")),
                    "tecnologias_solo_so": bool(detalle.get("tecnologias_solo_so")),
                }
    except sqlite3.OperationalError:
        return
    for v in vistas:
        v["activos_resumen"] = por_id.get(v.get("id"))


def activos_distintos(conn: sqlite3.Connection, threat_ids: Iterable[int]) -> int:
    """Numero de activos presentes distintos con la version vulnerable en cualquiera de las amenazas.

    Sin los de severidad baja y sin los que tienen el riesgo aceptado con una excepcion
    vigente (2026-09-10): es una cifra de riesgo (la usan el correo y los resumenes), y
    las dos exclusiones significan lo mismo, «esto no cuenta»."""
    ids = list(threat_ids)
    if not ids:
        return 0
    sin_bajas = _y_sin_bajas(conn) + _y_sin_excepcion(conn)
    total: set[int] = set()
    for lote in range(0, len(ids), 800):
        trozo = ids[lote:lote + 800]
        for r in conn.execute(
                f"""SELECT DISTINCT ap.activo_id FROM aplicabilidad ap JOIN activos a ON a.id=ap.activo_id
                     WHERE ap.veredicto='afectado' AND a.presente=1{sin_bajas}
                       AND ap.threat_id IN ({','.join('?' * len(trozo))})""",
                trozo):
            total.add(r[0])
    return len(total)


def vulnerabilidades_activo(conn: sqlite3.Connection, activo_id: int, *, limite: int = 100,
                            excluir_bajas: Optional[bool] = None) -> list[dict]:
    """Vulnerabilidades confirmadas de un activo (una fila por CVE, con sus paquetes),
    para el desplegable «N · ver» de la lista de activos.

    ``excluir_bajas`` (regla interna, ajuste ``ignore_low_severity``, activo): la
    severidad Baja no se reporta, asi que tampoco cuenta aqui. Antes no se filtraba y el
    desplegable de un activo ensenaba 74 vulnerabilidades donde la pagina de Amenazas y
    el Panel decian 71 sobre la misma maquina (revision de precision del 2026-09-09);
    el operador veia dos cifras de lo mismo sin manera de saber cual valia. Con ``None``
    (2026-09-10) manda el ajuste guardado en la base, como en el resto del modulo; las
    pruebas pueden forzarlo con True o False.

    La severidad de cada CVE es la MAS ALTA de las amenazas que lo declaran
    (``queries.SEVERIDAD_ORDEN``): una vulnerabilidad tiene una sola severidad, la peor,
    y no la de la primera fila que devolviera la consulta.
    """
    from .queries import SEVERIDAD_ORDEN
    if excluir_bajas is None:
        excluir_bajas = _ajuste_excluir_bajas(conn)
    sin_bajas = " AND (t.severity IS NULL OR t.severity <> 'Low')" if excluir_bajas else ""
    por_cve: dict[str, dict] = {}
    for r in conn.execute(
            f"""SELECT ap.cve, ap.paquete, ap.version_instalada, ap.version_corregida, ap.aviso, ap.motor,
                      ap.referencia, ap.sin_parche_motivo, a.ecosistema, a.so_familia,
                      ap.threat_id, t.title_es, t.title_en, t.severity, t.in_kev, t.relevance, t.estado
                 FROM aplicabilidad ap JOIN activos a ON a.id=ap.activo_id
                 LEFT JOIN threats t ON t.id=ap.threat_id
                WHERE ap.activo_id=? AND ap.veredicto='afectado'
                  AND (t.id IS NULL OR t.estado NOT IN ('descartada','falso_positivo','mitigada')){sin_bajas}
                ORDER BY t.in_kev DESC, t.relevance DESC, ap.cve""", (activo_id,)):
        e = por_cve.setdefault(r["cve"], {
            "cve": r["cve"], "threat_id": r["threat_id"], "titulo": r["title_es"] or r["title_en"] or r["cve"],
            "severidad": r["severity"], "kev": bool(r["in_kev"]), "relevancia": r["relevance"],
            "paquetes": [], "corregida": r["version_corregida"], "aviso": r["aviso"], "motor": MOTOR_ES.get(r["motor"], r["motor"])})
        if SEVERIDAD_ORDEN.get(r["severity"], 9) < SEVERIDAD_ORDEN.get(e["severidad"], 9):
            e["severidad"] = r["severity"]
        e["kev"] = e["kev"] or bool(r["in_kev"])
        # Cada paquete con SU plan y SU fuente: en el desplegable de la lista de activos
        # tampoco vale que la frase de un paquete describa otro (hallazgo 2). Las claves
        # ``instalada`` y ``corregida`` se mantienen porque son las que lee ``app.js``.
        plan = detalle_paquete_de_fila(r)
        plan["instalada"] = plan["version_instalada"]
        plan["corregida"] = plan["version_corregida"]
        e["paquetes"].append(plan)
        if not e["corregida"] and r["version_corregida"]:
            e["corregida"] = r["version_corregida"]
    return list(por_cve.values())[:limite]


# --------------------------------------------------------------------------
# Plan de remediacion
# --------------------------------------------------------------------------
_PAQUETES_KERNEL = re.compile(r"^(linux-(image|modules|headers|tools|generic|virtual|signed)|bpftool|linux-perf)")


def _orden_remediacion(familia: Optional[str], ecosistema: Optional[str], paquetes: list[str],
                       corregida: Optional[str], base_freebsd: bool) -> tuple[str, str]:
    """(comando, nota) para actualizar los paquetes en esa familia."""
    lista = " ".join(sorted(set(paquetes)))
    if familia in ("ubuntu", "debian"):
        if any(_PAQUETES_KERNEL.match(p) for p in paquetes):
            return ("sudo apt-get update && sudo apt-get dist-upgrade -y && sudo reboot",
                    "El núcleo se actualiza con dist-upgrade y exige reiniciar para que la corrección esté activa"
                    + (f" (versión objetivo {corregida})" if corregida else "") + ".")
        return (f"sudo apt-get update && sudo apt-get install --only-upgrade -y {lista}",
                f"Deja los paquetes en la versión corregida{(' ' + corregida) if corregida else ''} de la distribución "
                f"({ecosistema or familia}); reiniciar el servicio afectado si procede.")
    if familia == "freebsd":
        if base_freebsd:
            return ("sudo freebsd-update fetch install && sudo reboot",
                    f"Corrige el sistema base al nivel de parche {corregida or 'publicado'}; requiere reiniciar.")
        return (f"sudo pkg update && sudo pkg upgrade -y {lista}",
                f"Actualiza los puertos a la versión corregida{(' ' + corregida) if corregida else ''}.")
    if familia == "windows":
        return (f"Actualizar {lista} a la versión {corregida or 'corregida por el fabricante'} (gestor de software o instalador del fabricante)",
                "En Windows la corrección llega por el instalador del programa o por Windows Update; comprobar la versión tras actualizar.")
    return (f"Actualizar {lista} a la versión {corregida or 'corregida'}", "Sin receta automática para este sistema.")


def plan_remediacion(conn: sqlite3.Connection, *, threat_id: Optional[int] = None,
                     activo_id: Optional[int] = None) -> dict[str, Any]:
    """Agrupa los activos afectados por sistema y paquete y propone la orden concreta
    para corregir cada grupo. Para una amenaza (todos sus activos) o para un activo
    (todas sus vulnerabilidades).

    La severidad baja queda fuera (2026-09-10, ajuste ``ignore_low_severity``): el plan
    es una orden de trabajo y la baja no se trabaja. Como ``plan_remediacion_texto``
    parte de estos mismos grupos, la descarga en texto tampoco la incluye.

    Los grupos salen ya FUSIONADOS con ``remediacion.fusionar_plan`` (2026-09-09): los que
    son la MISMA orden —mismo sistema, mismos paquetes, misma version objetivo y mismos
    activos— se juntan en uno, con ``nombre`` («Núcleo Linux 6.8.0-60-generic»),
    ``es_fusion`` y ``grupos_fusionados``. La fusion se hace aqui, y no en la plantilla,
    porque asi la reciben TODOS los que llaman: la pagina y la descarga en texto. Cuando
    solo la hacia la plantilla, la pagina del activo 20 decia «40 grupos de remediacion» y
    el fichero descargado traia 105 bloques, que es la duplicidad que el usuario reclamo
    (hallazgo MEDIO de la revision del 2026-09-09). El plan de un activo agrupa tambien
    por CVE (cada vulnerabilidad tiene su fila), y de ahi salian los 105.
    """
    condiciones = ["ap.veredicto='afectado'", "a.presente=1",
                   "(t.id IS NULL OR t.estado NOT IN ('descartada','falso_positivo','mitigada'))"]
    # La severidad baja no entra en el plan (2026-09-10, orden del usuario; ajuste
    # ``ignore_low_severity``): ni en la pantalla ni en el fichero de texto que se
    # descarga, ni suma activos, ni puede fijar la version objetivo de una orden.
    if excluir_bajas(conn):
        condiciones.append(_SIN_BAJAS_SQL)
    # Y el riesgo aceptado con una excepcion vigente tampoco (2026-09-10): el plan es la
    # ORDEN DE TRABAJO que alguien va a ejecutar hoy, y no se puede mandar corregir lo que
    # la organizacion decidio aplazar por escrito, con responsable y con fecha. La
    # vulnerabilidad sigue visible en la ficha del activo, en la de la amenaza y en
    # /excepciones/, con su insignia; al vencer la excepcion vuelve sola al plan.
    if excepciones.hay_excepciones(conn):
        condiciones.append(_SIN_EXCEPCION_SQL)
    params: list[Any] = []
    if threat_id is not None:
        condiciones.append("ap.threat_id=?")
        params.append(threat_id)
    if activo_id is not None:
        condiciones.append("ap.activo_id=?")
        params.append(activo_id)
    filas = [dict(r) for r in conn.execute(
        f"""SELECT ap.cve, ap.paquete, ap.version_instalada, ap.version_corregida, ap.aviso, ap.motor, ap.threat_id,
                   a.id AS activo_id, a.nombre, a.ip, a.origen, a.so_familia, a.so_nombre, a.ecosistema, a.entorno,
                   a.proceso, t.title_es, t.title_en, t.severity, t.in_kev
              FROM aplicabilidad ap JOIN activos a ON a.id=ap.activo_id LEFT JOIN threats t ON t.id=ap.threat_id
             WHERE {' AND '.join(condiciones)}
             ORDER BY a.entorno IN ('produccion','contingencia') DESC, a.nombre""", params)]
    grupos: dict[tuple, dict] = {}
    for f in filas:
        base = f["paquete"] in NOMBRES_BASE_FREEBSD
        clave = (f["so_familia"], f["ecosistema"] or f["so_nombre"], "base" if base else "paquetes",
                 f["version_corregida"] or "", f["cve"] if activo_id is not None else "")
        g = grupos.setdefault(clave, {"familia": f["so_familia"], "sistema": f["ecosistema"] or f["so_nombre"],
                                      "paquetes": set(), "corregida": f["version_corregida"], "base": base,
                                      "activos": {}, "cves": set(), "avisos": set()})
        g["paquetes"].add(f["paquete"])
        g["cves"].add(f["cve"])
        if f["aviso"]:
            g["avisos"].add(f["aviso"])
        act = g["activos"].setdefault(f["activo_id"], {"id": f["activo_id"], "nombre": f["nombre"], "ip": f["ip"],
                                                        "origen": f["origen"], "entorno": f["entorno"], "proceso": f["proceso"],
                                                        "instalada": f["version_instalada"], "paquetes": set()})
        act["paquetes"].add(f["paquete"])
    salida = []
    for g in grupos.values():
        paquetes = sorted(g["paquetes"])
        comando, nota = _orden_remediacion(g["familia"], g["sistema"], paquetes, g["corregida"], g["base"])
        activos = sorted(g["activos"].values(), key=lambda x: (x["entorno"] not in ("produccion", "contingencia"), x["nombre"]))
        for a in activos:
            a["paquetes"] = sorted(a["paquetes"])
        salida.append({"familia": g["familia"], "sistema": g["sistema"], "paquetes": paquetes, "corregida": g["corregida"],
                       "comando": comando, "nota": nota, "activos": activos, "n_activos": len(activos),
                       "expuestos": sum(1 for a in activos if a["entorno"] in ("produccion", "contingencia")),
                       "cves": sorted(g["cves"]), "avisos": sorted(g["avisos"])})
    # La fusion va antes de ordenar: dos grupos que son la misma orden tienen que ocupar
    # una sola posicion. La importacion es local porque ``remediacion`` es un modulo de
    # nivel superior (usa ``aplicabilidad`` conceptualmente, no al contrario) y asi no se
    # crea una dependencia circular al cargar el paquete.
    from .remediacion import fusionar_plan
    salida = fusionar_plan(salida)
    salida.sort(key=lambda g: (-g["expuestos"], -g["n_activos"]))
    total_activos = len({a["id"] for g in salida for a in g["activos"]})
    return {"grupos": salida, "total_activos": total_activos,
            "total_expuestos": len({a["id"] for g in salida for a in g["activos"] if a["entorno"] in ("produccion", "contingencia")}),
            "cves": sorted({c for g in salida for c in g["cves"]})}


def plan_remediacion_texto(plan: dict, *, titulo: str) -> str:
    """Version en texto plano del plan, para descargar o pegar en un ticket.

    Los grupos se fusionan tambien aqui (``remediacion.fusionar_plan``, que es
    idempotente): ``plan_remediacion`` ya los devuelve fusionados, pero esta funcion
    tambien recibe planes recortados al alcance del perfil, y el fichero descargado tiene
    que traer EXACTAMENTE los mismos bloques que la pagina ensena grupos. Antes no era
    asi: la pagina del activo 20 decia 40 grupos y el fichero traia 105 bloques (revision
    del 2026-09-09). Cada bloque lleva el nombre de la actualizacion y debajo la lista de
    sus paquetes, que es la orden que hay que ejecutar.
    """
    from .remediacion import fusionar_plan
    grupos = fusionar_plan(plan.get("grupos") or [])
    lineas = [titulo, "=" * len(titulo), "",
              f"Activos afectados: {plan['total_activos']} ({plan['total_expuestos']} en producción o contingencia)",
              f"CVE: {', '.join(plan['cves']) or '—'}",
              f"Actualizaciones por aplicar: {len(grupos)} (una orden por sistema y origen de paquete)", ""]
    for i, g in enumerate(grupos, 1):
        paquetes = g.get("paquetes") or []
        nombre = g.get("nombre") or ", ".join(paquetes)
        lineas += [f"{i}. {g['sistema'] or g['familia']} · {nombre}"
                   + (f" · versión objetivo {g['corregida']}" if g["corregida"] else ""),
                   f"   Paquetes ({len(paquetes)}): {', '.join(paquetes) or '—'}",
                   f"   Vulnerabilidades ({len(g.get('cves') or [])}): "
                   + (", ".join(g.get("cves") or []) or "—"),
                   f"   Orden: {g['comando']}", f"   Nota: {g['nota']}",
                   f"   Activos ({g['n_activos']}, {g['expuestos']} expuestos):"]
        for a in g["activos"]:
            lineas.append(f"     - {a['nombre']}" + (f" ({a['ip']})" if a.get("ip") else "")
                          + (f" · {a['entorno']}" if a.get("entorno") else "") + (f" · {a['proceso']}" if a.get("proceso") else "")
                          + (f" · instalada {a['instalada']}" if a.get("instalada") else ""))
        lineas.append("")
    return "\n".join(lineas)


def contar_veredictos_activo(conn: sqlite3.Connection, activo_id: int) -> int:
    """Filas evaluadas de un activo, sin recorte: el total que necesita la paginacion.

    Sin las de severidad baja (2026-09-10, ajuste ``ignore_low_severity``), igual que
    :func:`veredictos_de_activo`: un total que no case con la lista que pagina es un
    error visible en cuanto alguien llega a la ultima pagina."""
    return int(conn.execute(
        f"SELECT COUNT(*) FROM aplicabilidad ap WHERE ap.activo_id=?{_y_sin_bajas(conn)}",
        (activo_id,)).fetchone()[0] or 0)


def veredictos_de_activo(conn: sqlite3.Connection, activo_id: int, *, limite: int = 300,
                         desplazamiento: int = 0) -> list[dict]:
    """Amenazas evaluadas para un activo, las afectadas primero, con datos de la amenaza.

    Cada fila trae ademas (v8, 2026-09-06) la explicacion de la comparacion de versiones,
    los avisos con su direccion oficial y la referencia que sustenta el veredicto; la
    evidencia sale ya sin la marca interna de la referencia.

    ``desplazamiento`` (2026-09-07) pagina la lista en la ficha del activo. El orden
    termina en ``ap.id``, que es unico: con empates, LIMIT/OFFSET podia repetir una fila
    en dos paginas y perder otra."""
    filas = [dict(r) for r in conn.execute(
        f"""SELECT ap.*, ap.referencia AS referencia_guardada,
                  a.ecosistema, a.so_familia, a.so_nombre, a.so_ciclo,
                  t.title_es, t.title_en, t.severity, t.in_kev, t.relevance, t.estado, t.month,
                  t.cvss_score
             FROM aplicabilidad ap JOIN activos a ON a.id = ap.activo_id
             LEFT JOIN threats t ON t.id = ap.threat_id
            WHERE ap.activo_id=?{_y_sin_bajas(conn)}
            ORDER BY CASE ap.veredicto WHEN 'afectado' THEN 0 WHEN 'no_afectado' THEN 1 ELSE 2 END,
                     t.in_kev DESC, t.relevance DESC, ap.evaluado_at DESC, ap.id
            LIMIT ? OFFSET ?""",
        (activo_id, max(1, int(limite or 1)), max(0, int(desplazamiento or 0))))]
    for f in filas:
        guardada = referencia_de_fila(f)
        f["evidencia"] = partir_evidencia(f.get("evidencia"))[0]
        f["avisos"] = avisos_con_url(f.get("aviso"))
        f["comparacion"] = explicar_fila(f)
        f["sin_parche_texto"] = (None if f.get("version_corregida")
                                 else texto_sin_correccion(f.get("sin_parche_motivo")))
        f["sin_parche_motivo_es"] = (None if f.get("version_corregida")
                                     else motivo_sin_parche_es(f.get("sin_parche_motivo")))
        f["sistema"] = nombre_sistema(f.get("ecosistema"), f.get("so_nombre"), f.get("so_ciclo"),
                                      f.get("so_familia"))
        # La direccion se valida por servidor antes de ensenarla, y el motor «version» se
        # sustenta con la ficha del NIST (hallazgos 1 y 4 de la revision del 2026-09-06).
        f["referencia"] = referencia_segura(
            guardada or next((a["url"] for a in f["avisos"] if a["url"]), ""),
            cve=f.get("cve"), ecosistema=f.get("ecosistema"), familia=f.get("so_familia"),
            motor=f.get("motor"))
        f["referencia_es"] = etiqueta_referencia(f["referencia"])
    return filas


def conteo_activo(conn: sqlite3.Connection, activo_id: int) -> dict[str, int]:
    """CVE distintos de un activo por veredicto, para las tarjetas de su ficha.

    Sin la severidad baja (2026-09-10, ajuste ``ignore_low_severity``)."""
    fila = conn.execute(
        f"""SELECT COUNT(DISTINCT CASE WHEN ap.veredicto='afectado' THEN ap.cve END) AS afectado,
                  COUNT(DISTINCT CASE WHEN ap.veredicto='no_afectado' THEN ap.cve END) AS no_afectado,
                  COUNT(DISTINCT CASE WHEN ap.veredicto='sin_dato' THEN ap.cve END) AS sin_dato,
                  COUNT(DISTINCT CASE WHEN ap.veredicto='afectado' AND t.in_kev=1 THEN ap.cve END) AS kev
             FROM aplicabilidad ap LEFT JOIN threats t ON t.id=ap.threat_id
            WHERE ap.activo_id=?{_y_sin_bajas(conn)}""", (activo_id,)).fetchone()
    return {k: int(fila[k] or 0) for k in ("afectado", "no_afectado", "sin_dato", "kev")}


def resumen_informe(conn: sqlite3.Connection, month: str, *, cfg: Any = None,
                    limite: int = 40) -> dict[str, Any]:
    """Para el informe mensual: activos con vulnerabilidades confirmadas entre las
    amenazas del periodo, fin de soporte y cobertura del inventario.

    Sin la severidad baja (2026-09-10, ajuste ``ignore_low_severity``): el informe
    mensual ya la dejaba fuera de sus graficas y de sus recuentos de amenazas, pero esta
    tabla de activos afectados y sus totales todavia la contaban.

    Sin el riesgo aceptado con una excepcion vigente (2026-09-10) en la tabla de activos
    afectados y en sus totales, por la misma razon. En las CORREGIDAS del periodo si
    cuenta: una correccion es trabajo hecho de verdad, y restarla porque exista una
    excepcion sobre ese mismo par activo-CVE seria borrar el avance del mes."""
    from .ocs import resumen as resumen_ocs
    base = resumen_ocs(conn, cfg=cfg)
    sin_bajas = _y_sin_bajas(conn)
    sin_excepcion = _y_sin_excepcion(conn)
    afectados = [dict(r) for r in conn.execute(
        f"""SELECT a.id, a.nombre, a.ip, a.origen, a.so_nombre, a.so_version, a.zona,
                  COUNT(DISTINCT ap.cve) AS cves,
                  COUNT(DISTINCT CASE WHEN t.in_kev=1 THEN ap.cve END) AS kev,
                  GROUP_CONCAT(DISTINCT ap.cve) AS lista_cves
             FROM aplicabilidad ap JOIN activos a ON a.id=ap.activo_id JOIN threats t ON t.id=ap.threat_id
            WHERE ap.veredicto='afectado' AND a.presente=1 AND t.month=?
              AND t.estado NOT IN ('descartada','falso_positivo'){sin_bajas}{sin_excepcion}
            GROUP BY a.id ORDER BY kev DESC, cves DESC, a.nombre LIMIT ?""", (month, limite))]
    # Totales del periodo sin el recorte de la tabla (2026-09-09): la tabla lista como
    # mucho ``limite`` activos y el informe decia «en total 40 activos» cuando eran mas.
    # Una vulnerabilidad es un CVE en un activo, contado una sola vez aunque toque varios
    # paquetes (``queries.sql_vulnerabilidades``, el unico punto de verdad del conteo).
    from .queries import sql_vulnerabilidades
    totales = conn.execute(
        f"""SELECT COUNT(DISTINCT ap.activo_id) AS activos,
                   {sql_vulnerabilidades()} AS vulnerabilidades,
                   {sql_vulnerabilidades(condicion="t.in_kev=1")} AS vulnerabilidades_kev
              FROM aplicabilidad ap JOIN activos a ON a.id=ap.activo_id JOIN threats t ON t.id=ap.threat_id
             WHERE ap.veredicto='afectado' AND a.presente=1 AND t.month=?
               AND t.estado NOT IN ('descartada','falso_positivo'){sin_bajas}{sin_excepcion}""",
        (month,)).fetchone()
    # Mismo punto de verdad que el resto (2026-09-09): las corregidas son pares
    # (activo, CVE) ya al dia, contados con ``queries.sql_vulnerabilidades`` y no con un
    # ``COUNT(DISTINCT ap.activo_id || ':' || ap.cve)`` escrito a mano, que era la misma
    # cuenta con otro separador y podia divergir de la definicion oficial.
    corregidas = conn.execute(
        f"""SELECT {sql_vulnerabilidades()} FROM aplicabilidad ap
             JOIN activos a ON a.id=ap.activo_id JOIN threats t ON t.id=ap.threat_id
            WHERE ap.veredicto='no_afectado' AND ap.version_corregida IS NOT NULL
              AND a.presente=1 AND t.month=?{sin_bajas}""",
        (month,)).fetchone()[0]
    amenazas_con_activos = conn.execute(
        """SELECT COUNT(*) FROM aplicabilidad_amenaza aa JOIN threats t ON t.id=aa.threat_id
            WHERE t.month=? AND aa.afectados > 0""", (month,)).fetchone()[0]
    evaluadas = conn.execute(
        "SELECT COUNT(*) FROM aplicabilidad_amenaza aa JOIN threats t ON t.id=aa.threat_id WHERE t.month=?",
        (month,)).fetchone()[0]
    tabla = tabla_fin_soporte(conn)
    fuera: dict[str, dict] = {}
    proximos: dict[str, dict] = {}
    hoy = date.today()
    for a in conn.execute("SELECT id, nombre, so_nombre, so_version, so_familia, so_ciclo, origen FROM activos "
                          "WHERE presente=1 AND so_ciclo IS NOT NULL"):
        est = estado_soporte(tabla, dict(a), hoy=hoy)
        if not est or est.get("sin_datos"):
            continue
        destino = fuera if est["fuera"] else (proximos if est["proximo"] else None)
        if destino is None:
            continue
        clave = f"{a['so_nombre']} ({est['etiqueta']})"
        e = destino.setdefault(clave, {"sistema": clave, "eol": est["eol"], "dias": est["dias"],
                                       "activos": 0, "ejemplos": []})
        e["activos"] += 1
        if len(e["ejemplos"]) < 5:
            e["ejemplos"].append(a["nombre"])
    hallazgos = [dict(r) for r in conn.execute(
        """SELECT h.tipo, COUNT(DISTINCT h.activo_id) AS activos FROM hallazgos_activos h
             JOIN activos a ON a.id=h.activo_id WHERE h.resuelto_at IS NULL AND a.presente=1
            GROUP BY h.tipo ORDER BY activos DESC""")]
    return {**base, "afectados": afectados, "corregidas": int(corregidas or 0),
            "activos_afectados": int(totales["activos"] or 0),
            "vulnerabilidades": int(totales["vulnerabilidades"] or 0),
            "vulnerabilidades_kev": int(totales["vulnerabilidades_kev"] or 0),
            "amenazas_con_activos": int(amenazas_con_activos or 0), "amenazas_evaluadas": int(evaluadas or 0),
            "fuera_soporte_sistemas": sorted(fuera.values(), key=lambda x: -x["activos"]),
            "proximos_fin_soporte": sorted(proximos.values(), key=lambda x: x["dias"] or 0),
            "hallazgos_por_tipo": hallazgos}

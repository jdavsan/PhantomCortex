"""Seguimiento de las correcciones que todavia no existen (tabla ``parches_pendientes``, v7).

Peticion del usuario (2026-09-06): «si no dice cuál es la versión corregida, porque la noticia
no la menciona o porque el fabricante no ha sacado el parche, se debe poner eso, tenerlo en
cuenta en el inventario, buscarlo cada día y, cuando aparezca, mencionarlo en el correo».

Una fila por (CVE, paquete, ecosistema) cuya evaluacion dice «afectado» sin version corregida.
Cada dia se vuelve a consultar; cuando la correccion aparece, la fila queda «encontrada» y el
correo del dia la incluye en su propia seccion, ademas de rellenar ``aplicabilidad``.

Como funciona
-------------
``sincronizar`` agrupa por conjuntos las filas de ``aplicabilidad`` con veredicto «afectado» y
sin ``version_corregida`` (en la base real son decenas de miles de filas y unos cientos de
grupos), abre las que faltan, actualiza los recuentos de activos y cierra las que ya no estan:
si el grupo desaparecio porque la evaluacion diaria ya conoce la version, la fila NO se borra,
se marca como encontrada para que el correo la anuncie; si desaparecio porque el paquete se
desinstalo o el activo se retiro, se borra (no hay nada que anunciar).

El motivo por el que no se conoce la version se deduce de lo que ya se sabe, sin red:

* ``distro_sin_empaquetar`` — el registro de OSV.dev publica la correccion del mismo paquete
  para otra version de la distribucion (Debian 14, por ejemplo) pero no para la nuestra.
* ``sin_parche_publicado`` — el texto del aviso dice explicitamente que todavia no hay
  correccion, o el registro de la distribucion marca el fallo como que no se va a corregir
  (urgencia «unimportant» o «end-of-life»).
* ``aviso_sin_version`` — el registro lista el paquete como afectado sin ningun rango «fixed»,
  o el aviso solo enumera versiones afectadas sin decir cual corrige.
* ``desconocido`` — el resto.

``buscar`` vuelve a preguntar a OSV.dev (``aplicabilidad.ClienteOSV``, que respeta cupo y
cache) por las filas en seguimiento, empezando por las que mas activos expuestos tienen. Para
que la consulta diaria sirva de algo, la cache se considera caducada a las
``CACHE_HORAS`` horas: si se sirviera la cache de siete dias nunca se veria una correccion
nueva. Cuando el paquete no lo cubre el registro de la distribucion se prueba el registro del
propio CVE y, en ultimo termino, las restricciones de version del aviso, pero SOLO para el
software cuyo veredicto salio del motor de comparacion de versiones (el que no es un paquete de
Debian ni de Ubuntu): la version del aviso es la del proyecto original («2.41») y la instalada
la del paquete de la distribucion («2.40-2+deb13u1», que puede llevar la correccion
incorporada), asi que darla por buena en un paquete de la distribucion ordenaria instalar una
version inexistente y dejaria el activo como afectado para siempre. Ademas solo se acepta si el
aviso deja UNA sola cota «anterior a X»; con varias ramas («< 19.2.2, < 19.1.4») no se puede
afirmar cual corresponde a la version instalada y la fila sigue en seguimiento.

Una correccion se anuncia UNA sola vez. La evaluacion diaria vuelve a poner
``aplicabilidad.version_corregida`` a NULL en su UPSERT, de modo que la fila se reabre cada dia;
al reabrirla se conservan la version que se conocio y ``avisado_at``, y solo se vuelve a avisar
si la version que aparece es distinta de la ya anunciada. Las amenazas que el analista cerro
(descartada, falso positivo o mitigada) salen del seguimiento y no se consultan mas.

NVD no se consulta: sus rangos CPE dan la version corregida del proyecto original, que no es la
version del paquete de la distribucion (2.41-12+deb13u3 frente a 2.41), y mezclarlas produciria
comparaciones falsas. Queda anotado como mejora para el software que no es de la distribucion.
"""
from __future__ import annotations

import json
import re
import sqlite3
from datetime import timedelta
from typing import Any, Iterable, Optional

from . import db, excepciones, versions
from .aplicabilidad import (AFECTADO, ClienteOSV, ErrorOSV, PREFIJO_OSV, afectaciones,
                            avisos_de)
from .logging_setup import get_logger
from .ocs import (ENTORNO_ES, ENTORNOS_EXPUESTOS, FAMILIA_ES, ORIGEN_ES,
                  normalizar_nombre, paquete_fuente, reglas_fuente)
from .versiones_distro import comparar_dpkg

log = get_logger("parches")

#: Por que no se conoce la version que corrige. El texto es el que ve el usuario.
MOTIVO_ES = {
    "aviso_sin_version": "El aviso de seguridad no indica en qué versión se corrige",
    "sin_parche_publicado": "El fabricante todavía no ha publicado la corrección",
    "distro_sin_empaquetar": "La distribución todavía no ha empaquetado la corrección",
    "desconocido": "No se ha podido determinar la versión que corrige",
}
MOTIVOS = tuple(MOTIVO_ES)
#: Insignia de cada motivo (texto + color: nunca solo color).
MOTIVO_CLAVE = {"aviso_sin_version": "medio", "sin_parche_publicado": "critico",
                "distro_sin_empaquetar": "alto", "desconocido": "neutra"}
ESTADOS = ("seguimiento", "encontradas")
ESTADO_ES = {"seguimiento": "En seguimiento", "encontradas": "Ya disponibles"}

#: Estados en los que el analista ya cerro la amenaza: no se sigue buscando su correccion ni se
#: anuncia en el correo (los mismos que excluyen ``bin/ejecucion_diaria.py`` y el resto de la
#: plataforma). «aceptada» no cierra nada: el riesgo se acepta, pero la correccion sigue interesando.
ESTADOS_CERRADOS = ("descartada", "falso_positivo", "mitigada")
_ESTADOS_CERRADOS_SQL = "(" + ",".join("'" + e + "'" for e in ESTADOS_CERRADOS) + ")"

#: Motores de ``aplicabilidad`` cuyos veredictos comparan la version instalada con las versiones
#: del aviso original. Solo en esos grupos se puede tomar la version del aviso (o de un registro
#: generico de OSV.dev) como version que corrige: en un paquete de la distribucion la version del
#: aviso es la del proyecto original («2.41») y la instalada la del paquete («2.40-2+deb13u1»,
#: que puede llevar la correccion incorporada por la propia distribucion).
MOTORES_VERSION_ORIGINAL = frozenset({"version"})

#: Filas de la seccion del correo: mas alla de este tope se resume («y otras N correcciones»).
#: Gmail y Outlook recortan los mensajes de mas de unos 102 KB y esconderian el resto de la
#: alerta; cada fila de la tabla pesa unos 1,6 KB por el estilo en linea que exigen los clientes
#: de correo, asi que 15 filas dejan la seccion en unos 28 KB.
TOPE_CORREO = 15

#: Horas que se da por buena la cache de OSV.dev al buscar correcciones. La cache general dura
#: una semana (``osv_cache_hours``); aqui se busca cada dia, asi que se refresca cada dia.
CACHE_HORAS = 20
#: Urgencias con las que la distribucion declara que no va a publicar correccion.
URGENCIAS_SIN_CORRECCION = frozenset({"unimportant", "end-of-life", "not-affected"})

#: El aviso dice con todas las letras que todavia no hay correccion.
_RE_SIN_PARCHE = re.compile(
    r"no\s+(?:hay|existe|se\s+ha\s+publicado|está\s+disponible|esta\s+disponible)[^.;]{0,40}"
    r"(?:parche|corrección|correccion|actualización|actualizacion)"
    r"|sin\s+parche\s+(?:disponible|oficial|todavía|todavia)"
    r"|(?:el\s+)?fabricante\s+(?:todavía\s+|todavia\s+)?no\s+ha\s+[^.;]{0,30}"
    r"(?:parche|corrección|correccion)"
    r"|no\s+patch(?:es)?\s+(?:is\s+|are\s+)?(?:currently\s+)?available"
    r"|no\s+fix(?:es)?\s+(?:is\s+|are\s+)?(?:currently\s+)?available"
    r"|has\s+not\s+(?:yet\s+)?been\s+(?:patched|fixed)"
    r"|unpatched", re.IGNORECASE)

_ENTORNOS_SQL = "(" + ",".join("'" + e + "'" for e in ENTORNOS_EXPUESTOS) + ")"
#: Ecosistema con el que se agrupa: el de OSV.dev si el activo lo tiene («Debian:13») y, si no,
#: la familia del sistema («freebsd», «windows»). Un mismo paquete se corrige en una version de
#: la distribucion y no en otra, asi que el ecosistema forma parte de la identidad del grupo.
_ECO_SQL = "COALESCE(a.ecosistema, a.so_familia, '')"

#: La amenaza de la fila de ``parches_pendientes`` sigue abierta (el analista no la ha cerrado).
#: Sin ``threat_id`` no hay amenaza que consultar y la fila se da por viva.
_VIVA_SQL = ("NOT EXISTS(SELECT 1 FROM threats tc WHERE tc.id = p.threat_id "
             f"AND tc.estado IN {_ESTADOS_CERRADOS_SQL})")

# --------------------------------------------------------------------------
# La severidad BAJA no cuenta en nada (2026-09-10)
#
# Orden del usuario: solo se reportan la critica, la alta y la media. «Correcciones
# pendientes» seguia contando y listando las bajas. Se filtran en TODAS las lecturas
# (pagina, correo diario y resumen), nunca en la escritura: ``sincronizar`` y ``buscar``
# siguen abriendo la fila y buscando la correccion cada dia, de modo que si el ajuste
# ``ignore_low_severity`` se desactivara todo reaparece en el acto, sin migracion.
# --------------------------------------------------------------------------
#: Valor de ``threats.severity`` que no se reporta.
SEVERIDAD_BAJA = "Low"

#: Deja fuera la severidad baja de una consulta cuyo alias de ``parches_pendientes`` sea
#: ``p``. Una fila sin amenaza conocida NO es «baja» y se conserva, igual que en el resto
#: de la plataforma.
_SIN_BAJAS_SQL = ("NOT EXISTS(SELECT 1 FROM threats tb WHERE tb.id = p.threat_id "
                  f"AND tb.severity = '{SEVERIDAD_BAJA}')")

#: Lo mismo para las consultas que recorren ``aplicabilidad`` con el alias ``ap``.
_SIN_BAJAS_APLICABILIDAD_SQL = ("NOT EXISTS(SELECT 1 FROM threats tb WHERE tb.id = ap.threat_id "
                                f"AND tb.severity = '{SEVERIDAD_BAJA}')")


def excluir_bajas(conn: sqlite3.Connection) -> bool:
    """Si la severidad baja se deja fuera, segun el ajuste ``ignore_low_severity``.

    Se lee de la propia base con la misma conexion de la consulta, como en
    ``alertas_proceso.incluir_bajas`` y en ``remediacion.excluir_bajas``: asi la pagina,
    el correo y el resumen cuentan lo mismo sin pasarse el ajuste unos a otros.
    """
    return bool(db.get_setting(conn, "ignore_low_severity", True))


def _y_sin_bajas(conn: sqlite3.Connection, *, aplicabilidad: bool = False) -> str:
    """« AND <condición>» para pegar a un WHERE, o cadena vacia si las bajas cuentan."""
    if not excluir_bajas(conn):
        return ""
    return " AND " + (_SIN_BAJAS_APLICABILIDAD_SQL if aplicabilidad else _SIN_BAJAS_SQL)


# --------------------------------------------------------------------------
# El riesgo aceptado tampoco cuenta (excepciones con vencimiento, 2026-09-10, tarde)
#
# Una excepcion vigente significa lo mismo que la severidad baja para esta pagina:
# «esto no cuenta como trabajo pendiente». Va, por tanto, en los MISMOS cuatro sitios
# que :func:`_y_sin_bajas` (``resumen``, ``_condicion`` —que comparten la lista y el
# total—, ``novedades`` y ``sin_correccion``) y nunca en la escritura: ``sincronizar`` y
# ``buscar`` siguen abriendo la fila y preguntando por la correccion cada dia, porque la
# excepcion CADUCA SOLA y el dia que venza la pagina tiene que quedar como si nunca
# hubiera existido.
#
# Aqui hay una dificultad propia que no tienen ``remediacion`` ni ``aplicabilidad``:
# ``parches_pendientes`` NO tiene columna ``activo_id``. Cada fila es un grupo
# (CVE, paquete, ecosistema) que agrupa de uno a varios cientos de activos, asi que los
# alcances «un CVE en un activo» y «un paquete en un activo» no se pueden decidir sobre
# la fila. La condicion se traduce entonces a lo que de verdad significa para un grupo:
# el grupo SIGUE siendo trabajo pendiente mientras quede AL MENOS UN activo presente
# afectado por ese (CVE, paquete) cuyo riesgo no este aceptado. Es la unica lectura que
# no miente: con el alcance «un CVE en toda la organizacion» el grupo desaparece
# entero, y con un alcance por activo desaparece solo si ese activo era el ultimo.
# --------------------------------------------------------------------------
#: Condicion «queda algun activo presente afectado por este grupo cuyo riesgo NO este
#: aceptado», para las consultas cuyo alias de ``parches_pendientes`` sea ``p``.
def _sql_grupo_con_activo_pendiente(sin_excepcion: str) -> str:
    return (f"EXISTS (SELECT 1 FROM aplicabilidad ap JOIN activos ax ON ax.id = ap.activo_id "
            f"WHERE ap.cve = p.cve AND ap.paquete = p.paquete AND ap.veredicto = '{AFECTADO}' "
            f"AND ax.presente = 1{sin_excepcion})")


def _y_sin_excepcion(conn: sqlite3.Connection, *, aplicabilidad: bool = False) -> str:
    """« AND <condición>» que deja fuera el riesgo aceptado, o cadena vacia.

    ``aplicabilidad=True`` devuelve la condicion directa para el alias ``ap`` de
    ``aplicabilidad`` (los recuentos de activos de :func:`resumen`); en otro caso, la
    condicion traducida a grupos para el alias ``p`` de ``parches_pendientes``.

    Cadena vacia mientras no haya ninguna excepcion vigente, que es el caso normal: las
    consultas quedan EXACTAMENTE como estaban, sin un milisegundo de mas.
    """
    condicion = excepciones.y_sin_excepcion(conn, activo="ap.activo_id", cve="ap.cve",
                                            paquete="ap.paquete")
    if not condicion:
        return ""
    if aplicabilidad:
        return condicion
    return " AND " + _sql_grupo_con_activo_pendiente(condicion)

#: Grupos en seguimiento: veredicto «afectado» sin version corregida, en activos presentes.
_SQL_GRUPOS = f"""
SELECT ap.cve                                        AS cve,
       ap.paquete                                    AS paquete,
       {_ECO_SQL}                                    AS ecosistema,
       MAX(ap.threat_id)                             AS threat_id,
       MIN(ap.motor)                                 AS motor,
       COUNT(DISTINCT ap.activo_id)                  AS n_activos,
       COUNT(DISTINCT CASE WHEN a.entorno IN {_ENTORNOS_SQL} THEN ap.activo_id END) AS n_activos_expuestos,
       MIN(ap.evaluado_at)                           AS detectado_at,
       MIN(ap.evidencia)                             AS evidencia,
       MAX(ap.aviso)                                 AS aviso
  FROM aplicabilidad ap JOIN activos a ON a.id = ap.activo_id
       LEFT JOIN threats t ON t.id = ap.threat_id
 WHERE ap.veredicto = ? AND ap.version_corregida IS NULL AND a.presente = 1
   AND (t.id IS NULL OR t.estado NOT IN {_ESTADOS_CERRADOS_SQL})
 GROUP BY ap.cve, ap.paquete, {_ECO_SQL}"""

#: Grupos que ya tienen version: sirven para cerrar el seguimiento anunciando la correccion.
_SQL_RESUELTOS = f"""
SELECT ap.cve                                        AS cve,
       ap.paquete                                    AS paquete,
       {_ECO_SQL}                                    AS ecosistema,
       MIN(ap.version_corregida)                     AS version_corregida,
       MAX(ap.aviso)                                 AS aviso,
       MAX(ap.evaluado_at)                           AS evaluado_at
  FROM aplicabilidad ap JOIN activos a ON a.id = ap.activo_id
       LEFT JOIN threats t ON t.id = ap.threat_id
 WHERE ap.veredicto = ? AND ap.version_corregida IS NOT NULL AND a.presente = 1
   AND (t.id IS NULL OR t.estado NOT IN {_ESTADOS_CERRADOS_SQL})
 GROUP BY ap.cve, ap.paquete, {_ECO_SQL}"""


# --------------------------------------------------------------------------
# Utilidades
# --------------------------------------------------------------------------
def _ajuste(cfg: Any, clave: str, defecto: Any) -> Any:
    if cfg is None:
        return defecto
    valor = cfg.get(clave, defecto)
    return defecto if valor in (None, "") else valor


def ecosistema_es(ecosistema: Optional[str]) -> str:
    """'Debian:13' -> 'Debian 13'; 'freebsd' -> 'FreeBSD'; vacio -> 'Sin sistema declarado'."""
    eco = (ecosistema or "").strip()
    if not eco:
        return "Sin sistema declarado"
    if ":" in eco:
        familia, _, resto = eco.partition(":")
        return f"{FAMILIA_ES.get(familia.lower(), familia)} {resto.replace(':', ' ')}".strip()
    return FAMILIA_ES.get(eco.lower(), eco)


def _mayor(versiones: Iterable[str]) -> Optional[str]:
    """La mas alta de una lista de versiones de paquete (reglas de dpkg)."""
    mejor: Optional[str] = None
    for v in versiones:
        if v and (mejor is None or comparar_dpkg(v, mejor) > 0):
            mejor = v
    return mejor


def _dias(valor: Any) -> int:
    try:
        return max(0, int(round(float(valor or 0))))
    except (TypeError, ValueError):
        return 0


def _decimal_es(valor: Any, decimales: int = 1) -> Optional[str]:
    """1.5 -> «1,5»: numeros con decimales en formato español (el filtro ``numero`` de la
    interfaz solo da enteros y truncaria «2,5 días de espera media» a «2»)."""
    try:
        numero = float(valor)
    except (TypeError, ValueError):
        return None
    entero, _, resto = f"{numero:,.{decimales}f}".partition(".")
    entero = entero.replace(",", ".")
    return f"{entero},{resto}" if resto else entero


def _prefijo_osv(ecosistema: Optional[str]) -> Optional[str]:
    eco = (ecosistema or "").strip().lower()
    for familia, prefijo in PREFIJO_OSV.items():
        if eco.startswith(familia):
            return prefijo
    return None


def _texto_amenaza(amenaza: Optional[dict]) -> str:
    if not amenaza:
        return ""
    return " ".join(str(amenaza.get(c) or "") for c in
                    ("title_es", "title_en", "summary_es", "summary_en", "remediation_es"))


def _fragmento(texto: str, coincidencia: re.Match) -> str:
    """Trozo legible del aviso alrededor de lo que se reconocio, para explicar el motivo."""
    inicio = max(0, coincidencia.start() - 40)
    fin = min(len(texto), coincidencia.end() + 60)
    trozo = " ".join(texto[inicio:fin].split())
    return ("…" if inicio else "") + trozo + ("…" if fin < len(texto) else "")


def _corregida_para(afect: list[dict], paquete: str, fuentes: Iterable[str]) -> tuple[Optional[str], Optional[str]]:
    """Version que corrige ese paquete segun las entradas de OSV.dev de su ecosistema, con las
    mismas reglas que ``aplicabilidad.evaluar_dpkg``. Devuelve (version, paquete_fuente)."""
    fuentes = list(fuentes)
    for a in afect:
        corregida: Optional[str] = None
        if paquete in a["binarios"]:
            corregida = a["binarios"][paquete]
        elif a["fuente"] in fuentes and not a["binarios"]:
            pass                         # Debian: solo hay paquete fuente
        else:
            continue                     # este binario no figura en la entrada
        corregida = corregida or _mayor(a["corregidas"])
        if corregida:
            return corregida, a["fuente"]
    return None, None


def _listado_en_osv(afect: list[dict], paquete: str, fuentes: Iterable[str]) -> bool:
    """¿El registro de la distribucion nombra ese paquete (como binario o como fuente)?"""
    fuentes = list(fuentes)
    return any(paquete in a["binarios"] or (a["fuente"] in fuentes and not a["binarios"])
               for a in afect)


def _corregidas_en_otros(registro: dict, ecosistema: str, fuente: Optional[str]) -> list[tuple[str, str]]:
    """(ecosistema, version) donde el MISMO paquete fuente ya tiene correccion publicada."""
    salida: list[tuple[str, str]] = []
    for a in registro.get("affected") or []:
        paq = a.get("package") or {}
        eco = (paq.get("ecosystem") or "").strip()
        if not eco or eco == ecosistema:
            continue
        if fuente and (paq.get("name") or "").strip().lower() != fuente:
            continue
        corregidas = [e["fixed"] for r in (a.get("ranges") or [])
                      for e in (r.get("events") or []) if e.get("fixed")]
        binarias = [b.get("binary_version") for b in ((a.get("ecosystem_specific") or {}).get("binaries") or [])
                    if b.get("binary_version")]
        version = _mayor(corregidas + binarias)
        if version:
            salida.append((eco, version))
    return salida


def _urgencia(afect: list[dict]) -> Optional[str]:
    for a in afect:
        urgencia = (a.get("urgencia") or "").strip().lower()
        if urgencia:
            return urgencia
    return None


def _cota_unica(texto: str) -> Optional[str]:
    """Version que corrige deducida del aviso: solo si enuncia UNA sola cota «anterior a X».

    Con varias ramas («anterior a 19.2.2, 19.1.4 y 19.0.6») no se puede saber cual corresponde
    a la version instalada de cada activo, asi que no se afirma nada.
    """
    cotas = {r.version for r in versions.extraer_restricciones(texto) if r.operador == "<"}
    return cotas.pop() if len(cotas) == 1 else None


# --------------------------------------------------------------------------
# Motivo por el que no se conoce la version que corrige
# --------------------------------------------------------------------------
def _version_del_aviso_es_comparable(motores: Optional[set[str]]) -> bool:
    """¿Se puede tomar la version que dice el aviso original como version que corrige?

    Solo cuando TODOS los veredictos «afectado» del grupo salieron del motor de comparacion de
    versiones, es decir, software que no es un paquete de la distribucion. Si algun veredicto
    viene del motor de la distribucion (OSV.dev con reglas de dpkg) o de VuXML, la version del
    aviso es la del proyecto original y no la del paquete instalado: escribirla haria que el
    plan de remediacion ordenase instalar una version que no existe en el repositorio y que el
    activo siguiera figurando como afectado para siempre.
    """
    return bool(motores) and set(motores) <= MOTORES_VERSION_ORIGINAL


def _motores_por_grupo(conn: sqlite3.Connection,
                       filas: list[dict]) -> dict[tuple[str, str, str], set[str]]:
    """Motores de evaluacion que sostienen cada grupo (cve, paquete, ecosistema): una sola
    consulta agrupada para todas las filas que se van a buscar, no una por fila."""
    cves = sorted({f["cve"] for f in filas if f.get("cve")})
    salida: dict[tuple[str, str, str], set[str]] = {}
    for inicio in range(0, len(cves), 400):
        trozo = cves[inicio:inicio + 400]
        marcas = ",".join("?" * len(trozo))
        for fila in conn.execute(
                f"""SELECT ap.cve AS cve, ap.paquete AS paquete, {_ECO_SQL} AS ecosistema,
                           ap.motor AS motor
                      FROM aplicabilidad ap JOIN activos a ON a.id = ap.activo_id
                     WHERE ap.cve IN ({marcas}) AND ap.veredicto = ?
                       AND ap.version_corregida IS NULL AND a.presente = 1
                     GROUP BY ap.cve, ap.paquete, {_ECO_SQL}, ap.motor""",
                trozo + [AFECTADO]):
            clave = (fila["cve"], fila["paquete"], fila["ecosistema"])
            salida.setdefault(clave, set()).add((fila["motor"] or "").strip())
    return salida


def motivo_de(grupo: dict, *, registro: Optional[dict] = None,
              amenaza: Optional[dict] = None) -> tuple[str, str]:
    """(motivo, detalle en español) de un grupo (cve, paquete, ecosistema).

    Se decide con lo que ya esta en la base: el registro de OSV.dev que se guardo en cache al
    evaluar, el texto del aviso y la evidencia que escribio el motor de aplicabilidad. Primero
    la prueba mas fuerte (hay correccion publicada para otra version de la distribucion), luego
    lo que el aviso dice con todas las letras y por ultimo lo que se puede leer del registro.
    """
    paquete = normalizar_nombre(grupo.get("paquete"))
    ecosistema = grupo.get("ecosistema") or ""
    texto = _texto_amenaza(amenaza)
    afect = afectaciones(registro, ecosistema) if registro else []
    fuentes = paquete_fuente(paquete, reglas=grupo.get("reglas") or None)
    listado = _listado_en_osv(afect, paquete, fuentes) if afect else False

    if listado:
        _, fuente = _corregida_para(afect, paquete, fuentes)
        if fuente is None:
            for a in afect:
                if paquete in a["binarios"] or a["fuente"] in fuentes:
                    fuente = a["fuente"]
                    break
        otros = _corregidas_en_otros(registro or {}, ecosistema, fuente)
        if otros:
            eco_otro, version_otro = otros[0]
            return ("distro_sin_empaquetar",
                    f"OSV.dev ya publica la corrección {version_otro} del paquete "
                    f"{fuente or paquete} para {ecosistema_es(eco_otro)}, pero todavía no para "
                    f"{ecosistema_es(ecosistema)}.")
        urgencia = _urgencia(afect)
        if urgencia in URGENCIAS_SIN_CORRECCION:
            return ("sin_parche_publicado",
                    f"El registro de OSV.dev marca la urgencia «{urgencia}» para el paquete "
                    f"{fuente or paquete} en {ecosistema_es(ecosistema)}: la distribución no "
                    f"prevé publicar una corrección.")

    coincidencia = _RE_SIN_PARCHE.search(texto)
    if coincidencia:
        return ("sin_parche_publicado",
                f"El aviso dice que todavía no hay corrección: «{_fragmento(texto, coincidencia)}».")

    if listado:
        urgencia = _urgencia(afect)
        return ("aviso_sin_version",
                f"El registro de OSV.dev lista {paquete} como afectado en "
                f"{ecosistema_es(ecosistema)} sin ningún rango con la versión que lo corrige"
                + (f" (urgencia «{urgencia}»)." if urgencia else "."))

    if (grupo.get("motor") or "") == "version":
        return ("aviso_sin_version",
                "El aviso solo enumera las versiones afectadas; no dice en qué versión se "
                "corrige. Evidencia de la evaluación: "
                f"«{(grupo.get('evidencia') or '').strip()[:180]}».")

    evidencia = (grupo.get("evidencia") or "")
    if "todavía no hay corrección publicada" in evidencia:
        return ("aviso_sin_version",
                "El registro de la distribución lista el paquete como afectado sin publicar la "
                f"versión que lo corrige. Evidencia: «{evidencia.strip()[:180]}».")

    return ("desconocido",
            "Ni el registro de la distribución ni el aviso indican la versión que corrige el "
            "fallo. Se vuelve a consultar cada día.")


# --------------------------------------------------------------------------
# Sincronizacion
# --------------------------------------------------------------------------
def _amenazas(conn: sqlite3.Connection, ids: Iterable[Any]) -> dict[int, dict]:
    ids = sorted({int(i) for i in ids if i is not None})
    salida: dict[int, dict] = {}
    for inicio in range(0, len(ids), 400):
        trozo = ids[inicio:inicio + 400]
        marcas = ",".join("?" * len(trozo))
        for fila in conn.execute(
                f"""SELECT id, title_es, title_en, summary_es, summary_en, remediation_es
                      FROM threats WHERE id IN ({marcas})""", trozo):
            salida[int(fila["id"])] = dict(fila)
    return salida


def _registros_osv(conn: sqlite3.Connection, ids: Iterable[str]) -> dict[str, dict]:
    """Registros ya guardados en ``osv_cache``: sirven para deducir el motivo sin tocar la red."""
    ids = sorted(set(ids))
    salida: dict[str, dict] = {}
    for inicio in range(0, len(ids), 400):
        trozo = ids[inicio:inicio + 400]
        marcas = ",".join("?" * len(trozo))
        for fila in conn.execute(
                f"SELECT id, encontrado, json FROM osv_cache WHERE id IN ({marcas})", trozo):
            if fila["encontrado"] and fila["json"]:
                try:
                    salida[fila["id"]] = json.loads(fila["json"])
                except (TypeError, ValueError):
                    continue
    return salida


def sincronizar(conn: sqlite3.Connection, *, cfg: Any = None, ahora: Optional[str] = None) -> dict[str, Any]:
    """Abre, actualiza y cierra filas de ``parches_pendientes`` segun ``aplicabilidad``:
    cada (cve, paquete, ecosistema) con veredicto «afectado» y sin version corregida entra en
    seguimiento con su motivo y su numero de activos; las que ya tienen version salen.
    Devuelve {"nuevas": n, "actualizadas": n, "cerradas": n, "en_seguimiento": n}."""
    ahora = ahora or db.utcnow()
    grupos = [dict(f) for f in conn.execute(_SQL_GRUPOS, (AFECTADO,))]
    resueltos = {(f["cve"], f["paquete"], f["ecosistema"]): dict(f)
                 for f in conn.execute(_SQL_RESUELTOS, (AFECTADO,))}
    reglas = reglas_fuente(conn)
    amenazas = _amenazas(conn, [g["threat_id"] for g in grupos])
    ids_osv = {f"{_prefijo_osv(g['ecosistema'])}-{g['cve']}" for g in grupos
               if _prefijo_osv(g["ecosistema"])}
    registros = _registros_osv(conn, ids_osv)

    for g in grupos:
        g["reglas"] = reglas
        prefijo = _prefijo_osv(g["ecosistema"])
        registro = registros.get(f"{prefijo}-{g['cve']}") if prefijo else None
        g["motivo"], g["motivo_detalle"] = motivo_de(
            g, registro=registro, amenaza=amenazas.get(g["threat_id"]))

    propia = not conn.in_transaction
    if propia:
        conn.execute("BEGIN")
    try:
        existentes = {(f["cve"], f["paquete"], f["ecosistema"]): dict(f) for f in conn.execute(
            """SELECT id, cve, paquete, ecosistema, version_corregida, encontrado_at, avisado_at
                 FROM parches_pendientes""")}
        nuevas = actualizadas = reabiertas = 0
        for g in grupos:
            clave = (g["cve"], g["paquete"], g["ecosistema"])
            previa = existentes.get(clave)
            if previa is None:
                # ON CONFLICT por si otra ejecucion la abrio entre la lectura y la escritura:
                # una carrera no puede tumbar la ejecucion diaria entera.
                conn.execute(
                    """INSERT INTO parches_pendientes(cve, paquete, ecosistema, threat_id, motivo,
                           motivo_detalle, n_activos, n_activos_expuestos, detectado_at)
                       VALUES(?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(cve, paquete, ecosistema) DO UPDATE SET
                           threat_id=COALESCE(excluded.threat_id, parches_pendientes.threat_id),
                           motivo=excluded.motivo, motivo_detalle=excluded.motivo_detalle,
                           n_activos=excluded.n_activos,
                           n_activos_expuestos=excluded.n_activos_expuestos""",
                    (g["cve"], g["paquete"], g["ecosistema"], g["threat_id"], g["motivo"],
                     g["motivo_detalle"], g["n_activos"], g["n_activos_expuestos"],
                     g["detectado_at"] or ahora))
                nuevas += 1
                continue
            if previa["encontrado_at"]:
                # Regresion: la correccion que se dio por publicada vuelve a faltar. Se conservan
                # ``version_corregida`` y ``avisado_at`` como memoria de lo ya anunciado: la
                # evaluacion diaria vuelve a poner aplicabilidad.version_corregida a NULL en su
                # UPSERT, de modo que sin esta memoria la MISMA correccion se reabriria, se
                # volveria a encontrar y se anunciaria en el correo todos los dias.
                nota = (" La versión que se había encontrado"
                        + (f" ({previa['version_corregida']})" if previa["version_corregida"] else "")
                        + " ya no figura en la evaluación: vuelve al seguimiento"
                        + (" y, si vuelve a aparecer la misma versión, no se anuncia otra vez en "
                           "el correo." if previa["avisado_at"] else "."))
                conn.execute(
                    """UPDATE parches_pendientes
                          SET encontrado_at=NULL, motivo=?, motivo_detalle=?,
                              threat_id=COALESCE(?, threat_id),
                              n_activos=?, n_activos_expuestos=?
                        WHERE id=?""",
                    (g["motivo"], g["motivo_detalle"] + nota, g["threat_id"],
                     g["n_activos"], g["n_activos_expuestos"], previa["id"]))
                reabiertas += 1
                continue
            actualizadas += conn.execute(
                """UPDATE parches_pendientes
                      SET motivo=?, motivo_detalle=?, threat_id=COALESCE(?, threat_id),
                          n_activos=?, n_activos_expuestos=?
                    WHERE id=?""",
                (g["motivo"], g["motivo_detalle"], g["threat_id"], g["n_activos"],
                 g["n_activos_expuestos"], previa["id"])).rowcount

        # Cierre: los grupos que ya no estan en seguimiento.
        vivos = {(g["cve"], g["paquete"], g["ecosistema"]) for g in grupos}
        encontradas = borradas = 0
        for clave, previa in existentes.items():
            if clave in vivos or previa["encontrado_at"]:
                continue
            resuelto = resueltos.get(clave)
            if resuelto:
                # La evaluacion diaria ya conoce la version: se anuncia en el correo, salvo que
                # sea exactamente la que ya se anuncio antes de una reapertura (no se repite).
                repetida = bool(previa["avisado_at"]) and (
                    previa["version_corregida"] == resuelto["version_corregida"])
                conn.execute(
                    """UPDATE parches_pendientes SET version_corregida=?, aviso=COALESCE(?, aviso),
                              encontrado_at=?, buscado_at=?, avisado_at=? WHERE id=?""",
                    (resuelto["version_corregida"], resuelto["aviso"],
                     resuelto["evaluado_at"] or ahora, ahora,
                     previa["avisado_at"] if repetida else None, previa["id"]))
                encontradas += 1
            else:
                # Ni afectados ni corregidos: el paquete se desinstalo o el activo se retiro.
                conn.execute("DELETE FROM parches_pendientes WHERE id=?", (previa["id"],))
                borradas += 1

        marcadas = _marcar_aplicabilidad(conn, grupos)
        en_seguimiento = conn.execute(
            "SELECT COUNT(*) FROM parches_pendientes WHERE encontrado_at IS NULL").fetchone()[0]
        resultado = {"nuevas": nuevas, "actualizadas": actualizadas, "cerradas": encontradas + borradas,
                     "encontradas": encontradas, "borradas": borradas, "reabiertas": reabiertas,
                     "en_seguimiento": int(en_seguimiento or 0),
                     "filas_marcadas": max(0, marcadas),
                     "sin_columna_motivo": marcadas < 0,
                     "por_motivo": _conteo_motivos(grupos)}
        if nuevas or encontradas or borradas or reabiertas:
            db.audit(conn, "sistema", "parches.sincronizar", "parches_pendientes", None,
                     f"{nuevas} nuevas, {actualizadas} actualizadas, {encontradas} con corrección ya "
                     f"disponible, {borradas} retiradas, {reabiertas} reabiertas; "
                     f"{en_seguimiento} en seguimiento")
        if propia:
            conn.execute("COMMIT")
        return resultado
    except Exception:
        if propia and conn.in_transaction:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
        raise


def _conteo_motivos(grupos: list[dict]) -> dict[str, int]:
    conteo: dict[str, int] = {}
    for g in grupos:
        conteo[g["motivo"]] = conteo.get(g["motivo"], 0) + 1
    return conteo


def _hay_columna(conn: sqlite3.Connection, tabla: str, columna: str) -> bool:
    return any(r[1] == columna for r in conn.execute(f"PRAGMA table_info({tabla})"))


def _marcar_aplicabilidad(conn: sqlite3.Connection, grupos: list[dict]) -> int:
    """Escribe ``aplicabilidad.sin_parche_motivo`` para que el correo de alerta y la hoja de
    calculo digan por que falta la version en vez de dejar la casilla vacia, y lo borra donde ya
    no aplica (aparecio la version, cambio el veredicto o el analista cerro la amenaza).

    Quien lee la columna hoy es el correo (``threatintel/emails/alerta.html``) y el libro de
    Excel (``threatintel/libro_alerta.py``); las fichas de la interfaz todavia no la muestran.

    Si la base todavia no tiene la columna (esquema anterior a la v7 sin migrar) no se escribe
    nada y el seguimiento sigue funcionando: se avisa en el registro para que se migre.
    """
    if not _hay_columna(conn, "aplicabilidad", "sin_parche_motivo"):
        log.warning("falta la columna aplicabilidad.sin_parche_motivo: el motivo no se anota "
                    "en el inventario hasta que se migre el esquema")
        return -1
    conn.execute(f"""UPDATE aplicabilidad SET sin_parche_motivo=NULL
                      WHERE sin_parche_motivo IS NOT NULL
                        AND (version_corregida IS NOT NULL OR veredicto<>?
                             OR threat_id IN (SELECT id FROM threats
                                               WHERE estado IN {_ESTADOS_CERRADOS_SQL}))""",
                 (AFECTADO,))
    tocadas = 0
    for g in grupos:
        tocadas += conn.execute(
            f"""UPDATE aplicabilidad SET sin_parche_motivo=?
                 WHERE cve=? AND paquete=? AND veredicto=? AND version_corregida IS NULL
                   AND (sin_parche_motivo IS NULL OR sin_parche_motivo<>?)
                   AND activo_id IN (SELECT a.id FROM activos a WHERE {_ECO_SQL}=?)""",
            (g["motivo"], g["cve"], g["paquete"], AFECTADO, g["motivo"], g["ecosistema"])).rowcount
    return tocadas


# --------------------------------------------------------------------------
# Busqueda diaria de la version que corrige
# --------------------------------------------------------------------------
_SQL_A_BUSCAR = f"""
SELECT p.id, p.cve, p.paquete, p.ecosistema, p.threat_id, p.motivo, p.intentos,
       p.n_activos, p.n_activos_expuestos, p.version_corregida, p.avisado_at
  FROM parches_pendientes p
 WHERE p.encontrado_at IS NULL
   AND {_VIVA_SQL}
   AND (p.buscado_at IS NULL OR substr(p.buscado_at, 1, 10) < ?)
 ORDER BY p.n_activos_expuestos DESC, p.n_activos DESC, p.intentos ASC, p.id ASC
 LIMIT ?"""


def buscar(conn: sqlite3.Connection, *, cfg: Any = None, osv=None, limite: Optional[int] = None,
           ahora: Optional[str] = None) -> dict[str, Any]:
    """Consulta OSV.dev para las filas en seguimiento, empezando por las de mas activos
    expuestos. Al encontrar la version la escribe en ``parches_pendientes`` y en las filas de
    ``aplicabilidad`` correspondientes.

    La version que dice el aviso original (o un registro generico de OSV.dev) solo se acepta en
    los grupos cuyo veredicto salio del motor de comparacion de versiones, es decir, software
    que no es un paquete de la distribucion: en un paquete de Debian o de Ubuntu esa version es
    la del proyecto original y no la del paquete, y escribirla ordenaria instalar una version
    inexistente. El resto sigue en seguimiento con su motivo.

    Devuelve {"consultadas": n, "encontradas": n, "sin_novedad": n, "errores": [...],
    "omitido": bool, "cupo_agotado": bool}. ``parches_max_consultas`` limita las consultas de
    red: con paquetes que la distribucion no cubre una fila puede necesitar dos, asi que el
    numero de filas revisadas puede ser menor que el limite."""
    ahora = ahora or db.utcnow()
    if cfg is not None and not cfg.get("parches_buscar_diario", True):
        return {"consultadas": 0, "encontradas": 0, "sin_novedad": 0, "errores": [], "omitido": True,
                "motivo": "desactivado en ajustes (buscar cada día las correcciones que faltan)"}
    if limite is None:
        try:
            limite = int(_ajuste(cfg, "parches_max_consultas", 150))
        except (TypeError, ValueError):
            limite = 150
    limite = max(0, int(limite))
    if limite == 0:
        return {"consultadas": 0, "encontradas": 0, "sin_novedad": 0, "errores": [], "omitido": True,
                "motivo": "el límite de consultas por ejecución está en cero"}

    filas = [dict(f) for f in conn.execute(_SQL_A_BUSCAR, (str(ahora)[:10], limite))]
    if not filas:
        return {"consultadas": 0, "encontradas": 0, "sin_novedad": 0, "errores": [], "omitido": False,
                "motivo": "no hay filas pendientes de buscar hoy"}

    cliente = osv or ClienteOSV(conn, cfg=cfg, max_peticiones=limite)
    if osv is None:
        # La cache general dura una semana; aqui se busca a diario y hay que refrescarla.
        cliente.ttl = timedelta(hours=CACHE_HORAS)
    reglas = reglas_fuente(conn)
    amenazas = _amenazas(conn, [f["threat_id"] for f in filas])
    motores = _motores_por_grupo(conn, filas)
    hay_motivo = _hay_columna(conn, "aplicabilidad", "sin_parche_motivo")

    consultadas = encontradas = sin_novedad = ya_avisadas = 0
    cupo_agotado = False
    errores: list[str] = []
    hallazgos: list[dict] = []
    for fila in filas:
        if getattr(cliente, "agotado", False):
            # El cupo de consultas de red se agoto: las filas que quedan se revisan mañana.
            cupo_agotado = True
            break
        paquete = normalizar_nombre(fila["paquete"])
        fuentes = paquete_fuente(paquete, reglas=reglas)
        clave_grupo = (fila["cve"], fila["paquete"], fila["ecosistema"])
        del_aviso = _version_del_aviso_es_comparable(motores.get(clave_grupo))
        version = aviso = None
        origen = ""
        try:
            prefijo = _prefijo_osv(fila["ecosistema"])
            registro = cliente.registro(f"{prefijo}-{fila['cve']}") if prefijo else None
            listado = False
            if registro:
                afect = afectaciones(registro, fila["ecosistema"])
                listado = _listado_en_osv(afect, paquete, fuentes)
                version, _ = _corregida_para(afect, paquete, fuentes)
                if version:
                    origen = f"registro {prefijo}-{fila['cve']} de OSV.dev"
                    aviso = ", ".join(avisos_de(registro)[:2]) or None
            if version is None and not listado and del_aviso:
                # Software que no cubre el registro de la distribucion (y cuyo veredicto salio de
                # comparar versiones del aviso): el registro del propio CVE.
                registro_cve = cliente.registro(fila["cve"])
                if registro_cve:
                    version, aviso = _corregida_generica(registro_cve, paquete)
                    if version:
                        origen = f"registro {fila['cve']} de OSV.dev"
            if version is None and not listado and del_aviso:
                version = _cota_unica(_texto_amenaza(amenazas.get(fila["threat_id"])))
                if version:
                    origen = "restricciones de versión del propio aviso"
        except ErrorOSV as exc:
            errores.append(f"{fila['cve']} ({fila['paquete']}): {exc}")
            conn.execute("UPDATE parches_pendientes SET buscado_at=?, intentos=intentos+1 WHERE id=?",
                         (ahora, fila["id"]))
            if cliente.agotado:
                cupo_agotado = True
                break
            continue
        except Exception as exc:  # noqa: BLE001  (una fila mala no puede tumbar la ejecucion)
            log.error("fallo al buscar la corrección", extra={"cve": fila["cve"], "error": str(exc)})
            errores.append(f"{fila['cve']} ({fila['paquete']}): {type(exc).__name__}: {exc}")
            conn.execute("UPDATE parches_pendientes SET buscado_at=?, intentos=intentos+1 WHERE id=?",
                         (ahora, fila["id"]))
            continue

        consultadas += 1
        if version:
            # ``avisado_at`` se conserva solo si es exactamente la version que ya se anuncio
            # antes de una reapertura: asi la misma correccion no se repite en el correo cada dia.
            repetida = bool(fila["avisado_at"]) and fila["version_corregida"] == version
            detalle = (f"Corrección encontrada el {str(ahora)[:10]} en {origen}: versión {version}"
                       + (f" (aviso {aviso})" if aviso else "") + ".")
            if repetida:
                detalle += (" Ya se anunció en el correo del "
                            f"{str(fila['avisado_at'])[:10]}: no se vuelve a anunciar.")
                ya_avisadas += 1
            conn.execute(
                """UPDATE parches_pendientes
                      SET buscado_at=?, intentos=intentos+1, version_corregida=?,
                          aviso=COALESCE(?, aviso), encontrado_at=?, motivo_detalle=?, avisado_at=?
                    WHERE id=?""",
                (ahora, version, aviso, ahora, detalle,
                 fila["avisado_at"] if repetida else None, fila["id"]))
            limpia = ", sin_parche_motivo=NULL" if hay_motivo else ""
            conn.execute(
                f"""UPDATE aplicabilidad SET version_corregida=?, aviso=COALESCE(aviso, ?){limpia}
                     WHERE cve=? AND paquete=? AND veredicto=? AND version_corregida IS NULL
                       AND activo_id IN (SELECT a.id FROM activos a WHERE {_ECO_SQL}=?)""",
                (version, aviso, fila["cve"], fila["paquete"], AFECTADO, fila["ecosistema"]))
            encontradas += 1
            hallazgos.append({"cve": fila["cve"], "paquete": fila["paquete"],
                              "ecosistema": fila["ecosistema"], "version_corregida": version,
                              "aviso": aviso, "origen": origen})
        else:
            conn.execute("UPDATE parches_pendientes SET buscado_at=?, intentos=intentos+1 WHERE id=?",
                         (ahora, fila["id"]))
            sin_novedad += 1

    if encontradas:
        db.audit(conn, "sistema", "parches.buscar", "parches_pendientes", None,
                 f"{consultadas} filas consultadas, {encontradas} correcciones encontradas: "
                 + "; ".join(f"{h['cve']} {h['paquete']} → {h['version_corregida']}" for h in hallazgos[:8]))
    return {"consultadas": consultadas, "encontradas": encontradas, "sin_novedad": sin_novedad,
            "ya_avisadas": ya_avisadas, "errores": errores, "omitido": False,
            "hallazgos": hallazgos, "cupo_agotado": cupo_agotado,
            "peticiones": getattr(cliente, "peticiones", 0)}


def _corregida_generica(registro: dict, paquete: str) -> tuple[Optional[str], Optional[str]]:
    """Version que corrige en un registro de OSV.dev que no es de una distribucion: se busca la
    entrada cuyo paquete se llama igual (PyPI, npm, Go...)."""
    for a in registro.get("affected") or []:
        nombre = ((a.get("package") or {}).get("name") or "").strip().lower()
        if not nombre or normalizar_nombre(nombre) != paquete:
            continue
        corregidas = [e["fixed"] for r in (a.get("ranges") or [])
                      for e in (r.get("events") or []) if e.get("fixed")]
        version = _mayor(corregidas)
        if version:
            return version, (registro.get("id") or None)
    return None, None


# --------------------------------------------------------------------------
# Novedades para el correo
# --------------------------------------------------------------------------
_CAMPOS_NOVEDAD = """p.id, p.cve, p.paquete, p.ecosistema, p.threat_id, p.motivo, p.motivo_detalle,
       p.version_corregida, p.aviso, p.detectado_at, p.encontrado_at, p.n_activos,
       p.n_activos_expuestos, t.title_es, t.title_en, t.severity, t.in_kev,
       (julianday(COALESCE(p.encontrado_at, 'now')) - julianday(p.detectado_at)) AS dias_crudos"""

_ORDEN_SEVERIDAD = ("CASE t.severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 "
                    "WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END")


def _fila_es(fila: sqlite3.Row) -> dict[str, Any]:
    d = dict(fila)
    d["titulo"] = d.get("title_es") or d.get("title_en") or d.get("cve")
    d["severidad"] = d.get("severity")
    d["motivo_es"] = MOTIVO_ES.get(d.get("motivo") or "", MOTIVO_ES["desconocido"])
    d["motivo_clave"] = MOTIVO_CLAVE.get(d.get("motivo") or "", "neutra")
    d["sistema"] = ecosistema_es(d.get("ecosistema"))
    d["dias_en_espera"] = _dias(d.pop("dias_crudos", 0))
    d["in_kev"] = bool(d.get("in_kev"))
    return d


#: Orden de exposicion de un entorno: cuanto mas alto, mas urge. Sirve para elegir «el
#: activo mas expuesto» de una espera, que es el que decide si hay que contener el riesgo
#: hoy o se puede esperar a que el fabricante publique.
_ORDEN_ENTORNO = {"produccion": 0, "contingencia": 1, "desarrollo": 2, "pruebas": 3,
                  "soporte": 4}


def anotar_activo_mas_expuesto(conn: sqlite3.Connection, filas: list[dict]) -> list[dict]:
    """Anade a cada fila ``activo_mas_expuesto`` (2026-09-10): el activo de la espera que
    mas urge vigilar, con su nombre, su tipo de maquina y su entorno.

    Por que hace falta: la pagina decia «37 activos» de una espera de 60 dias y no se
    podia saber si eran 37 puestos de trabajo de pruebas o el servidor de nomina en
    produccion. Mientras no exista correccion, la unica defensa es la contencion, y la
    contencion se decide mirando la maquina mas expuesta.

    Se resuelve con UNA consulta para toda la pagina (no una por fila): las filas se
    piden de 20 en 20, pero cada una puede tocar cientos de activos.
    """
    filas = [f for f in filas if f.get("cve") and f.get("paquete")]
    if not filas:
        return filas
    for fila in filas:
        fila["activo_mas_expuesto"] = None
    claves = {(f["cve"], f["paquete"]) for f in filas}
    condicion = " OR ".join(["(ap.cve = ? AND ap.paquete = ?)"] * len(claves))
    valores: list[Any] = [AFECTADO]
    for cve, paquete in claves:
        valores += [cve, paquete]
    orden = "CASE a.entorno " + " ".join(
        f"WHEN '{e}' THEN {n}" for e, n in _ORDEN_ENTORNO.items()) + " ELSE 9 END"
    mejor: dict[tuple[str, str], dict] = {}
    for r in conn.execute(
            f"""SELECT ap.cve, ap.paquete, a.nombre, a.origen, a.entorno, a.proceso,
                       {orden} AS prioridad
                  FROM aplicabilidad ap JOIN activos a ON a.id = ap.activo_id
                 WHERE ap.veredicto = ? AND a.presente = 1 AND ({condicion})
                 ORDER BY prioridad, a.nombre""", valores):
        clave = (r["cve"], r["paquete"])
        if clave in mejor:
            continue
        mejor[clave] = {
            "nombre": r["nombre"],
            "origen": r["origen"],
            "origen_es": ORIGEN_ES.get(r["origen"], r["origen"]),
            "entorno": r["entorno"],
            "entorno_es": ENTORNO_ES.get(r["entorno"] or "", "Sin entorno"),
            "proceso": r["proceso"],
            "expuesto": (r["entorno"] or "") in ENTORNOS_EXPUESTOS,
        }
    for fila in filas:
        fila["activo_mas_expuesto"] = mejor.get((fila["cve"], fila["paquete"]))
    return filas


def novedades(conn: sqlite3.Connection, *, marcar: bool = False, ahora: Optional[str] = None) -> list[dict]:
    """Correcciones encontradas y todavia no avisadas, para la seccion del correo: cve, paquete,
    ecosistema, version_corregida, aviso, dias_en_espera, n_activos, n_activos_expuestos,
    titulo y severidad de la amenaza. No devuelve las de amenazas que el analista ya cerro.

    Con ``marcar`` sella ``avisado_at`` en el acto. Si el correo puede fallar, es mejor llamar
    sin ``marcar`` y sellar con ``marcar_avisadas`` DESPUES del envio: si se sella antes y el
    envio falla, esas correcciones no se anuncian nunca.

    La severidad baja no se anuncia (2026-09-10, ajuste ``ignore_low_severity``)."""
    filas = [_fila_es(f) for f in conn.execute(
        f"""SELECT {_CAMPOS_NOVEDAD}
              FROM parches_pendientes p LEFT JOIN threats t ON t.id = p.threat_id
             WHERE p.encontrado_at IS NOT NULL AND p.avisado_at IS NULL AND {_VIVA_SQL}
               {_y_sin_bajas(conn)}{_y_sin_excepcion(conn)}
             ORDER BY p.n_activos_expuestos DESC, p.n_activos DESC, {_ORDEN_SEVERIDAD}, p.cve""")]
    if marcar and filas:
        marcar_avisadas(conn, [f["id"] for f in filas], ahora=ahora)
    return filas


def marcar_avisadas(conn: sqlite3.Connection, ids: Iterable[Any], *,
                    ahora: Optional[str] = None) -> int:
    """Sella ``avisado_at`` en las filas indicadas y devuelve cuantas se sellaron.

    Permite a la ejecucion diaria pedir las novedades sin marcarlas, enviar el correo y sellar
    solo si el envio salio bien: sellar antes del envio pierde el aviso para siempre cuando el
    servidor de correo falla."""
    numeros = sorted({int(i) for i in ids if i is not None})
    if not numeros:
        return 0
    ahora = ahora or db.utcnow()
    total = 0
    for inicio in range(0, len(numeros), 400):
        trozo = numeros[inicio:inicio + 400]
        marcas = ",".join("?" * len(trozo))
        total += conn.execute(
            f"""UPDATE parches_pendientes SET avisado_at=?
                 WHERE avisado_at IS NULL AND id IN ({marcas})""", [ahora] + trozo).rowcount
    return total


# --------------------------------------------------------------------------
# Consultas para la pagina
# --------------------------------------------------------------------------
def resumen(conn: sqlite3.Connection) -> dict[str, Any]:
    """Para la interfaz: {"en_seguimiento": n, "por_motivo": {...}, "encontradas_hoy": n,
    "activos_afectados": n, "mas_antigua_dias": n|None}.

    ``en_seguimiento`` cuenta FILAS del catalogo, una por identificador CVE, paquete y
    version del sistema operativo. Para poder escribir en pantalla que 191 filas no son 191
    vulnerabilidades, el resumen trae tambien ``cve_distintos``, ``paquetes`` y
    ``ecosistemas`` (auditoria de tableros del 2026-09-15).

    Solo cuenta amenazas abiertas: las que el analista cerro (descartada, falso positivo o
    mitigada) no se siguen ni se anuncian, y sus activos no deben inflar los indicadores (es el
    mismo criterio del panel y del correo diario).

    Tampoco cuenta la severidad baja (2026-09-10, ajuste ``ignore_low_severity``): la
    pagina y estas cifras dicen lo mismo que Amenazas, el Panel y el informe."""
    viva = _VIVA_SQL + _y_sin_bajas(conn) + _y_sin_excepcion(conn)
    viva_ap = _y_sin_bajas(conn, aplicabilidad=True) + _y_sin_excepcion(conn, aplicabilidad=True)
    # Una fila del catalogo NO es una vulnerabilidad distinta: es la combinacion de un
    # identificador CVE, un paquete y una version del sistema operativo. Sobre la base real
    # del 2026-09-15 son 191 filas para 34 identificadores distintos en 58 paquetes y 8
    # ecosistemas. La pagina decia «191 en seguimiento» sin unidad y se leia como 191
    # vulnerabilidades (auditoria de tableros): estas tres cifras existen para poder
    # escribir lo que 191 significa, en la misma consulta y sin recorrer filas.
    catalogo = conn.execute(
        f"""SELECT COUNT(*) AS filas, COUNT(DISTINCT p.cve) AS cve_distintos,
                   COUNT(DISTINCT p.paquete) AS paquetes,
                   COUNT(DISTINCT p.ecosistema) AS ecosistemas
              FROM parches_pendientes p
             WHERE p.encontrado_at IS NULL AND {viva}""").fetchone()
    en_seguimiento = catalogo["filas"]
    por_motivo = {m: 0 for m in MOTIVOS}
    for fila in conn.execute(f"""SELECT p.motivo AS motivo, COUNT(*) AS n FROM parches_pendientes p
                                  WHERE p.encontrado_at IS NULL AND {viva}
                                  GROUP BY p.motivo"""):
        por_motivo[fila["motivo"] if fila["motivo"] in por_motivo else "desconocido"] += int(fila["n"] or 0)
    encontradas_hoy = conn.execute(
        f"""SELECT COUNT(*) FROM parches_pendientes p
             WHERE p.encontrado_at IS NOT NULL AND {viva}
               AND substr(p.encontrado_at,1,10) = substr(?,1,10)""",
        (db.utcnow(),)).fetchone()[0]
    encontradas_semana = conn.execute(
        f"""SELECT COUNT(*) FROM parches_pendientes p
             WHERE p.encontrado_at IS NOT NULL AND {viva}
               AND julianday('now') - julianday(p.encontrado_at) <= 7""").fetchone()[0]
    encontradas = conn.execute(
        f"""SELECT COUNT(*) FROM parches_pendientes p
             WHERE p.encontrado_at IS NOT NULL AND {viva}""").fetchone()[0]
    activos = conn.execute(
        f"""SELECT COUNT(DISTINCT ap.activo_id) FROM aplicabilidad ap
              JOIN activos a ON a.id=ap.activo_id
              LEFT JOIN threats t ON t.id=ap.threat_id
             WHERE ap.veredicto=? AND ap.version_corregida IS NULL AND a.presente=1
               AND (t.id IS NULL OR t.estado NOT IN {_ESTADOS_CERRADOS_SQL}){viva_ap}""",
        (AFECTADO,)).fetchone()[0]
    expuestos = conn.execute(
        f"""SELECT COUNT(DISTINCT ap.activo_id) FROM aplicabilidad ap
              JOIN activos a ON a.id=ap.activo_id
              LEFT JOIN threats t ON t.id=ap.threat_id
             WHERE ap.veredicto=? AND ap.version_corregida IS NULL AND a.presente=1
               AND (t.id IS NULL OR t.estado NOT IN {_ESTADOS_CERRADOS_SQL}){viva_ap}
               AND a.entorno IN {_ENTORNOS_SQL}""", (AFECTADO,)).fetchone()[0]
    antigua = conn.execute(
        f"""SELECT julianday('now') - julianday(MIN(p.detectado_at)) FROM parches_pendientes p
             WHERE p.encontrado_at IS NULL AND {viva}""").fetchone()[0]
    espera = conn.execute(
        f"""SELECT AVG(julianday(p.encontrado_at) - julianday(p.detectado_at))
              FROM parches_pendientes p
             WHERE p.encontrado_at IS NOT NULL AND {viva}""").fetchone()[0]
    ultima = conn.execute(
        f"SELECT MAX(p.buscado_at) FROM parches_pendientes p WHERE {viva}").fetchone()[0]
    return {"en_seguimiento": int(en_seguimiento or 0), "por_motivo": por_motivo,
            # Que es cada una de las 191 filas (2026-09-15): identificadores CVE distintos,
            # paquetes distintos y versiones de sistema distintas del mismo seguimiento.
            "cve_distintos": int(catalogo["cve_distintos"] or 0),
            "paquetes": int(catalogo["paquetes"] or 0),
            "ecosistemas": int(catalogo["ecosistemas"] or 0),
            "encontradas_hoy": int(encontradas_hoy or 0),
            "encontradas_semana": int(encontradas_semana or 0),
            "encontradas": int(encontradas or 0),
            "activos_afectados": int(activos or 0), "activos_expuestos": int(expuestos or 0),
            "mas_antigua_dias": _dias(antigua) if antigua is not None else None,
            "espera_media_dias": round(float(espera), 1) if espera is not None else None,
            # Texto ya formateado en español («2,5»): el filtro «numero» de la interfaz solo
            # sabe de enteros y truncaria los decimales.
            "espera_media_es": _decimal_es(espera) if espera is not None else None,
            "ultima_busqueda_at": ultima}


def _condicion(conn: sqlite3.Connection, estado: str, q: str) -> tuple[str, str, list[Any]]:
    """(estado normalizado, condicion SQL, parametros) del filtro de la pagina: lo comparten
    ``listar`` y ``contar`` para que la lista y el total digan siempre lo mismo.

    Recibe la conexion desde el 2026-09-10 porque la condicion incluye la severidad baja:
    se lee el ajuste ``ignore_low_severity`` de la propia base, y asi la lista, el total y
    la version acotada por tipo de maquina de ``webui.vistas.parches`` no pueden
    discrepar."""
    if estado not in ESTADOS:
        estado = "seguimiento"
    condicion = ("p.encontrado_at IS NULL" if estado == "seguimiento"
                 else "p.encontrado_at IS NOT NULL")
    condicion += f" AND {_VIVA_SQL}" + _y_sin_bajas(conn) + _y_sin_excepcion(conn)
    params: list[Any] = []
    texto_q = (q or "").strip()[:120]
    if texto_q:
        condicion += (" AND (p.cve LIKE ? ESCAPE '\\' OR p.paquete LIKE ? ESCAPE '\\' "
                      "OR p.ecosistema LIKE ? ESCAPE '\\' OR COALESCE(t.title_es, t.title_en, '') "
                      "LIKE ? ESCAPE '\\')")
        patron = "%" + texto_q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        params.extend([patron] * 4)
    return estado, condicion, params


def listar(conn: sqlite3.Connection, *, estado: str = "seguimiento", limite: int = 500,
           q: str = "", desplazamiento: int = 0) -> list[dict]:
    """Filas para la pagina: ``estado`` es «seguimiento» o «encontradas».

    ``desplazamiento`` salta las primeras filas (paginacion en el servidor, 2026-09-07).
    El orden termina en ``p.id``, que es unico, para que ninguna fila salga en dos
    paginas ni se quede sin salir cuando varias empatan."""
    estado, condicion, params = _condicion(conn, estado, q)
    orden = ("p.n_activos_expuestos DESC, p.n_activos DESC, p.detectado_at ASC, p.id"
             if estado == "seguimiento" else "p.encontrado_at DESC, p.n_activos DESC, p.id")
    filas = conn.execute(
        f"""SELECT {_CAMPOS_NOVEDAD}, p.buscado_at, p.intentos, p.avisado_at
              FROM parches_pendientes p LEFT JOIN threats t ON t.id = p.threat_id
             WHERE {condicion}
             ORDER BY {orden}
             LIMIT ? OFFSET ?""", params + [int(limite), max(0, int(desplazamiento))]).fetchall()
    return anotar_activo_mas_expuesto(conn, [_fila_es(f) for f in filas])


def contar(conn: sqlite3.Connection, *, estado: str = "seguimiento", q: str = "") -> int:
    """Filas que cumplen el filtro, sin recorte (la pagina avisa cuando muestra menos).

    Es un COUNT(*): la pagina lo consulta en cada carga y las filas «Ya disponibles» no se
    purgan nunca, asi que no puede costar en memoria lo que crezca la tabla."""
    _, condicion, params = _condicion(conn, estado, q)
    total = conn.execute(
        f"""SELECT COUNT(*) FROM parches_pendientes p LEFT JOIN threats t ON t.id = p.threat_id
             WHERE {condicion}""", params).fetchone()[0]
    return int(total or 0)


def sin_correccion(conn: sqlite3.Connection, *, limite_por_motivo: int = 5) -> dict[str, Any]:
    """Resumen de lo que NO se puede corregir todavia, agrupado por el motivo.

    Peticion del usuario del 2026-09-07: «un resumen de lo que no puedo parchar por
    ahora, ya que no se tiene la version disponible a actualizar, bien sea porque no la
    han desarrollado o porque sea una vulnerabilidad de dia 0».

    Los tres motivos responden justo a eso, y estan ordenados de mas a menos grave para
    quien tiene que decidir:

    * ``sin_parche_publicado`` — el fabricante dice que todavia no hay correccion. Es el
      caso del dia cero: no existe version a la que actualizar y la unica defensa es la
      contencion (cortar el acceso, desactivar el servicio, reglas en el cortafuegos).
    * ``distro_sin_empaquetar`` — la correccion existe en el proyecto original, pero la
      distribucion no la ha empaquetado. Se espera, o se compila a mano.
    * ``aviso_sin_version`` — el aviso no dice en que version se corrige. Puede que exista
      y no este publicada la referencia; la plataforma la busca cada dia.

    Se marca aparte lo que ademas figura en el catalogo KEV de CISA: sin correccion y con
    explotacion activa confirmada es lo que hay que contener hoy.

    La severidad baja no aparece en ningun motivo (2026-09-10, ``ignore_low_severity``).
    """
    viva = _VIVA_SQL + _y_sin_bajas(conn) + _y_sin_excepcion(conn)
    grupos: list[dict[str, Any]] = []
    total = 0
    total_kev = 0
    activos_expuestos = 0
    for motivo in ("sin_parche_publicado", "distro_sin_empaquetar", "aviso_sin_version",
                   "desconocido"):
        filas = [_fila_es(f) for f in conn.execute(
            f"""SELECT {_CAMPOS_NOVEDAD} FROM parches_pendientes p
                  LEFT JOIN threats t ON t.id = p.threat_id
                 WHERE p.encontrado_at IS NULL AND p.motivo = ? AND {viva}
                 ORDER BY t.in_kev DESC, {_ORDEN_SEVERIDAD},
                          p.n_activos_expuestos DESC, p.n_activos DESC, p.id""",
            (motivo,))]
        if not filas:
            continue
        kev = [f for f in filas if f["in_kev"]]
        total += len(filas)
        total_kev += len(kev)
        activos_expuestos += sum(int(f.get("n_activos_expuestos") or 0) for f in filas)
        grupos.append({
            "motivo": motivo,
            "motivo_es": MOTIVO_ES.get(motivo, MOTIVO_ES["desconocido"]),
            "clave": MOTIVO_CLAVE.get(motivo, "neutra"),
            "total": len(filas),
            "con_kev": len(kev),
            "activos": sum(int(f.get("n_activos") or 0) for f in filas),
            "activos_expuestos": sum(int(f.get("n_activos_expuestos") or 0) for f in filas),
            "dias_mas_antigua": max((int(f.get("dias_en_espera") or 0) for f in filas), default=0),
            # Primero las de explotacion activa: son las que hay que contener hoy
            "muestra": anotar_activo_mas_expuesto(
                conn, (kev + [f for f in filas if not f["in_kev"]])[:max(1, int(limite_por_motivo))]),
            "restantes": max(0, len(filas) - max(1, int(limite_por_motivo))),
        })
    return {
        "total": total,
        "con_kev": total_kev,
        "activos_expuestos": activos_expuestos,
        "grupos": grupos,
        "limite_por_motivo": int(limite_por_motivo),
    }

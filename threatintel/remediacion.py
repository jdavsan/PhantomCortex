"""Seguimiento de remediacion por activo y CVE (tabla ``remediaciones``, esquema v6).

Regla: una remediacion se ABRE cuando la evaluacion de aplicabilidad confirma que un activo
tiene la version vulnerable de un paquete para un CVE (veredicto ``afectado``). Se CIERRA
sola, sin intervencion humana, cuando una sincronizacion posterior con OCS ve la correccion:
el mismo (activo, cve, paquete) pasa a ``no_afectado`` o deja de existir porque el paquete
cambio de version o se desinstalo. Si el activo desaparece de OCS, se cierra con estado
``activo_ausente``. Nunca se cierra porque la amenaza se descarte a mano: eso es otra cosa
(estado de la amenaza) y la vista lo muestra como dimension aparte.

Desde el 2026-09-10 (esquema v14) hay un cuarto estado, ``esperando_datos``: la evaluacion
de hoy no puede ni confirmar ni descartar la vulnerabilidad porque el inventario no trae
los datos que hacen falta. Ni se cierra ni cuenta como trabajo pendiente; ver
:data:`ESTADOS_SIN_DATO` y :func:`esperando_datos`.

Fuente de verdad: la tabla ``aplicabilidad`` (una fila por activo, CVE y paquete con el
veredicto de la ultima evaluacion). ``sincronizar`` compara ambas tablas por conjuntos
(JOIN / NOT EXISTS), sin bucles por fila: en la base real hay decenas de miles de filas.

Orden de ``sincronizar``:
  1. Activos con ``presente = 0``: las pendientes pasan a ``activo_ausente``.
  2. Pendientes cuya fila sigue ``afectado``: solo se actualiza ``comprobado_at``.
  3. Pendientes (y las que esperaban datos) cuya fila paso a ``no_afectado``:
     ``corregida`` con la version vista y su evidencia.
  3 bis. Pendientes cuya fila dice ``sin_dato`` y no tienen ninguna fila ``afectado``:
     pasan a ``esperando_datos``. La evaluacion no puede ni confirmar ni descartar, asi
     que ni se cierran ni cuentan como trabajo pendiente; su fecha de deteccion no se
     toca y el paso 5 las devuelve a la cola en cuanto vuelva a haber datos.
  4. Pendientes cuya fila desaparecio: ``corregida`` SOLO si OCS confirma el cambio, es decir,
     si el paquete ya no esta en ``activo_software`` (desinstalado) o si la version instalada ya
     no es la vulnerable. Si el paquete sigue instalado con la misma version, la remediacion se
     queda pendiente: las filas de aplicabilidad tambien desaparecen por una evaluacion incompleta
     (OSV.dev sin respuesta o cupo agotado, VuXML no disponible), por la purga de retencion de la
     amenaza o por un cambio en el mapa de nombres, y nada de eso es una correccion. El sistema
     base de FreeBSD (paquetes ``freebsd`` y ``freebsd-kernel`` de VuXML) cuenta como instalado
     con la version de ``activos.so_version``. Las filas del motor de parches de Windows
     (``motor='msrc'``, ``paquete='windows'``: la actualizacion acumulativa del sistema, que
     tampoco esta en ``activo_software``) NUNCA se cierran en este paso: desaparecen cuando la
     correccion sale de la ventana de boletines, cuando el equipo pierde su producto MSRC o
     cuando el motor principal las borra antes de que ``msrc`` las regenere, y nada de eso es una
     correccion. Solo las cierra el paso 3, cuando los boletines de Microsoft dejan de senalar el
     CVE en la compilacion instalada (fila ``no_afectado`` con compilacion conocida).
  5. Cerradas cuya fila vuelve a ser ``afectado``: se reabren conservando el motivo anterior. Si
     venian de ``corregida`` es una regresion y ``detectado_at`` es la evaluacion nueva; si venian
     de ``activo_ausente`` o de ``esperando_datos`` nada se corrigio y se conserva la fecha de
     deteccion original.
  6. Filas ``afectado`` sin remediacion: se abren.
Dos ejecuciones seguidas sin cambios solo tocan ``comprobado_at`` (idempotente).
"""
from __future__ import annotations

import os.path
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from . import db, excepciones
from .logging_setup import get_logger
from .notify import fecha_larga
from .ocs import ENTORNO_ES, ENTORNOS_EXPUESTOS, ORIGEN_ES, normalizar_nombre
from .queries import ESTADO_ES as ESTADO_AMENAZA_ES
from .versiones_distro import version_base_freebsd  # noqa: F401  (lo usa el resto del modulo)

# Nombres con los que VuXML designa el sistema base de FreeBSD: no son paquetes de
# activo_software, su version instalada es la del sistema operativo (activos.so_version).
NOMBRES_BASE_FREEBSD = ("freebsd", "freebsd-kernel")

# --------------------------------------------------------------------------
# Estados de una remediacion
#
# «esperando_datos» es nuevo del 2026-09-10 (esquema v14) y responde a un defecto medido:
# habia 2.480 remediaciones abiertas SIN NINGUNA vulnerabilidad confirmada detras. Todas
# de cuatro equipos de computo con Windows 11 (so_version 10.0.26200) cuya compilacion no
# se puede calcular porque OCS no informa de ninguna actualizacion acumulativa reconocida:
# la evaluacion de hoy dice «sin dato» para las 2.480. Antes se quedaban en «abierta»
# para siempre, ensenandose en la cola como trabajo que NADIE PUEDE HACER, y ni el paso 3
# (cierra con fila ``no_afectado``) ni el 4 (cierra si la fila desaparecio) las tocaban.
#
# Decision, tomada con el usuario:
#   * NO se cierran: nadie ha comprobado que esten corregidas y cerrarlas seria mentir.
#   * NO cuentan como trabajo pendiente: no salen en la cola, ni en las cifras, ni en la
#     vista agrupada, ni en la grafica, porque no se pueden hacer.
#   * Aparecen en su propia lista, con el activo senalado, para que Servicios
#     Tecnologicos revise el agente de OCS de esa maquina: se arregla la causa y no el
#     sintoma. La lista sale de :func:`esperando_datos`.
#   * Es REVERSIBLE sin intervencion: el paso 5 de :func:`sincronizar` las devuelve a
#     «abierta» CON SU FECHA DE DETECCION ORIGINAL en cuanto la evaluacion vuelva a
#     confirmar la vulnerabilidad, igual que hace con «activo_ausente».
# --------------------------------------------------------------------------
ESTADOS = ("abierta", "esperando_datos", "corregida", "activo_ausente")
ESTADO_ES = {"abierta": "Pendiente", "esperando_datos": "Esperando datos del inventario",
             "corregida": "Corregida", "activo_ausente": "Activo retirado"}
# Clase de insignia por estado (texto + color: nunca solo color). «Esperando datos» va en
# ambar: no es un riesgo confirmado (no seria honesto pintarlo en rojo) ni algo resuelto
# (no seria honesto pintarlo en verde); es algo que reclama atencion de otra area.
#
# «Activo retirado» pasa de gris a ambar el 2026-09-15, por el mismo motivo: es
# exactamente el mismo caso —no se corrigio nada y nadie puede corregirlo hasta que
# Redes aclare si la maquina sigue en servicio— y el gris lo hacia
# parecer un estado cerrado y sin interes. Ademas se contradecia consigo mismo dentro de
# la misma pantalla: en la ficha del activo 511 la tarjeta «142 remediaciones congeladas»
# y la insignia «20 congeladas por activo retirado» ya salian en ambar mientras la
# columna «Estado» de cada fila pintaba «Activo retirado» en gris. Un concepto, un color.
ESTADO_CLAVE = {"abierta": "critical", "esperando_datos": "medio",
                "corregida": "ok", "activo_ausente": "medio"}
ESTADO_EXPLICACION = {
    "abierta": ("La evaluación confirma que el activo tiene la versión vulnerable: hay "
                "trabajo pendiente."),
    "esperando_datos": ("La evaluación de hoy no puede afirmar ni negar que el activo "
                        "siga afectado, porque el inventario no trae los datos que hacen "
                        "falta (en Windows, la actualización acumulativa instalada). No "
                        "se cierra, porque nadie ha comprobado que esté corregida, y no "
                        "cuenta como trabajo pendiente, porque nadie puede hacerla: hay "
                        "que revisar el agente de OCS Inventory de esa máquina. En "
                        "cuanto el inventario vuelva a informar, la remediación regresa a "
                        "la cola con su fecha de detección original."),
    "corregida": "Una sincronización posterior vio la corrección instalada.",
    "activo_ausente": "El activo dejó de figurar en OCS Inventory antes de corregirla.",
}

#: Estados que NO cuentan como trabajo pendiente pero tampoco estan cerrados. Hoy solo
#: «esperando_datos»; se nombra aparte para que ninguna consulta lo confunda con
#: «corregida» (no se corrigio nada) ni con «abierta» (no se puede hacer).
ESTADOS_SIN_DATO = ("esperando_datos",)

MOTIVO_CORREGIDA = "La sincronización vio la versión {version}, que ya incluye la corrección"
MOTIVO_DESINSTALADO = "El paquete ya no está instalado"
# Cierre de una remediacion del motor de parches de Windows (msrc): la compilacion instalada ya
# no figura como vulnerable en los boletines de Microsoft; {kb} es la acumulativa instalada.
MOTIVO_MSRC = "Los boletines de Microsoft ya no señalan este CVE en la compilación instalada {version} ({kb})"
MOTIVO_SIN_FILA = ("La versión instalada cambió de {vulnerable} a {version} y la evaluación "
                   "ya no señala este paquete como vulnerable")
MOTIVO_AUSENTE = "El activo ya no figura en OCS Inventory"
# Paso a «esperando_datos»: la evaluacion existe pero no puede decidir. {motivo} es la
# evidencia que dejo la evaluacion (por ejemplo «sin KB reconocida en el inventario»).
MOTIVO_SIN_DATO = ("La evaluación del {fecha} no pudo decidir si sigue afectado: {evidencia}. "
                   "No se cierra (nadie ha comprobado que esté corregida) y no cuenta como "
                   "trabajo pendiente: hay que revisar el agente de OCS Inventory del activo")
# Vuelta a la cola desde «esperando_datos»: se conserva la fecha de deteccion original.
MOTIVO_VUELVE_CON_DATOS = ("Vuelve a la cola el {fecha}: el inventario ya trae los datos y la "
                           "evaluación confirma que sigue afectado")
MOTIVO_REABIERTA = "Reabierta el {fecha}: la versión volvió a ser vulnerable"
MOTIVO_REAPARECIDO = "Reabierta el {fecha}: el activo volvió a figurar en OCS Inventory con la versión vulnerable"

log = get_logger("remediacion")

# --------------------------------------------------------------------------
# La severidad BAJA no cuenta en nada (2026-09-10)
#
# Orden del usuario: «las amenazas y vulnerabilidades de severidad baja no se deben tener
# en cuenta en absolutamente nada, así que no cuentan, recuerde que solo es lo de
# severidad crítica, alta y media». Remediacion era el ultimo sitio donde si contaban,
# porque es la cola de trabajo: hasta el 2026-09-09 la pagina decia 48.216 filas
# pendientes y 33.695 vulnerabilidades, de las que 2.774 filas y 964 vulnerabilidades
# eran de severidad baja, y habia 1 activo cuyas UNICAS pendientes eran bajas.
#
# La regla la gobierna el ajuste ``ignore_low_severity`` (activo), igual que en el resto
# del codigo: si alguna vez se desactiva, las bajas vuelven a aparecer en todo sin
# migracion ninguna, porque NO se borra nada de la base ni se deja de abrir la
# remediacion (ver :func:`sincronizar`). Solo se dejan de contar y de listar.
# --------------------------------------------------------------------------
#: Valor de ``threats.severity`` que no se reporta.
SEVERIDAD_BAJA = "Low"

#: Condicion SQL que deja fuera la severidad Baja de cualquier consulta cuyo alias de
#: ``remediaciones`` sea ``r``. Se escribe con NOT EXISTS y no con ``t.severity <> 'Low'``
#: para que valga tambien donde ``threats`` no esta unida, y para no depender de que quien
#: escriba la consulta se acuerde del LEFT JOIN. ``threats.id`` es clave primaria, asi que
#: la comprobacion es una busqueda por rowid: coste medido sobre la base real el
#: 2026-09-10 con las 66.326 filas de la tabla, ``resumen`` pasa de 363 ms a 427 ms,
#: ``contar_actualizaciones`` de 176 ms a 192 ms y ``pagina_actualizaciones`` de 294 ms a
#: 305 ms. Se paga una vez por fila y no se acerca al presupuesto de la pagina.
#: Una remediacion SIN amenaza conocida no es «baja»: se conserva, igual que en
#: ``ocs.estado_activos`` y en ``webui.vistas.activos``.
_SIN_BAJAS_SQL = (f"NOT EXISTS (SELECT 1 FROM threats tb WHERE tb.id = r.threat_id "
                  f"AND tb.severity = '{SEVERIDAD_BAJA}')")


def excluir_bajas(conn: sqlite3.Connection) -> bool:
    """Si la severidad Baja se deja fuera, segun el ajuste ``ignore_low_severity``.

    Se lee de la tabla ``settings`` con la MISMA conexion de la consulta (igual que hace
    ``alertas_proceso.incluir_bajas``), no de un ``cfg`` recibido: asi cualquiera que
    llame a estas funciones —la pagina de Remediacion, la ficha del activo, la pagina de
    Activos, el correo o el informe— cuenta lo mismo sin tener que acordarse de pasar el
    ajuste. Si el ajuste no esta guardado se aplica la regla: las bajas no cuentan.
    """
    return bool(db.get_setting(conn, "ignore_low_severity", True))


def _y_sin_bajas(conn: sqlite3.Connection) -> str:
    """« AND <condición>» para pegar a un WHERE, o cadena vacia si las bajas cuentan."""
    return f" AND {_SIN_BAJAS_SQL}" if excluir_bajas(conn) else ""


# --------------------------------------------------------------------------
# El riesgo aceptado tampoco cuenta (excepciones con vencimiento, 2026-09-10)
#
# Una excepcion vigente (``threatintel.excepciones``) significa exactamente lo mismo que
# la severidad baja para esta cola de trabajo: «esta fila no cuenta». Tiene responsable
# con nombre y correo, justificacion, fecha de vencimiento obligatoria y auditoria, y
# CADUCA SOLA: la condicion se evalua contra la fecha de hoy en cada consulta, asi que el
# dia que venza la remediacion vuelve a la cola sin que nadie ejecute nada. La revocacion
# la devuelve en el acto por el mismo camino.
#
# Por eso va en LOS MISMOS SITIOS que :data:`_SIN_BAJAS_SQL` y con la misma forma (un
# helper que devuelve « AND …» o cadena vacia), con tres excepciones deliberadas:
# ``contar_historial_activo`` y ``historial_activo`` (la ficha del activo, donde la fila
# DEBE seguir viendose con su insignia «Riesgo aceptado») y ``sincronizar`` (la
# remediacion se sigue abriendo, cerrando y reabriendo igual: nada se borra, para que al
# vencer la excepcion la cola quede como si nunca hubiera existido).
# --------------------------------------------------------------------------
#: Condicion SQL «esta fila de remediacion NO esta cubierta por una excepcion vigente»,
#: para las consultas cuyo alias de ``remediaciones`` sea ``r``.
_SIN_EXCEPCION_SQL = excepciones.SQL_SIN_EXCEPCION_REMEDIACION


def _y_sin_excepcion(conn: sqlite3.Connection) -> str:
    """« AND <condición>» para pegar a un WHERE, o cadena vacia si no hay ninguna vigente.

    Cadena vacia es el caso normal (sin excepciones registradas): las consultas quedan
    EXACTAMENTE como estaban, sin un milisegundo de mas. Cuesta una busqueda por indice
    sobre una tabla de decenas de filas (``excepciones.hay_excepciones``).
    """
    return f" AND {_SIN_EXCEPCION_SQL}" if excepciones.hay_excepciones(conn) else ""


def _where_y(*condiciones: str) -> str:
    """Clausula WHERE con las condiciones que no esten vacias, o cadena vacia.

    Las condiciones pueden venir con « AND » delante (es lo que devuelve
    :func:`_y_sin_bajas`): se recorta para que la primera no empiece por «AND».
    """
    limpias = [c.strip()[4:].strip() if c.strip().upper().startswith("AND ") else c.strip()
               for c in condiciones if c and c.strip()]
    return (" WHERE " + " AND ".join(limpias)) if limpias else ""


_ORDEN_SEVERIDAD = "CASE t.severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END"
# Orden de los estados en las listas: primero lo que hay que hacer, despues lo que no se
# puede hacer todavia (esperando datos del inventario), despues lo hecho y al final lo que
# ya no aplica porque el activo se retiro.
_ORDEN_ESTADO = ("CASE r.estado WHEN 'abierta' THEN 0 WHEN 'esperando_datos' THEN 1 "
                 "WHEN 'corregida' THEN 2 ELSE 3 END")
# Dias transcurridos desde la deteccion: hasta la correccion si esta corregida, hasta la ultima
# comprobacion si el activo se retiro de OCS y hasta ahora mismo si sigue pendiente.
# «esperando_datos» NO congela el contador, a proposito: los dias siguen corriendo desde
# la deteccion, porque el problema (un agente de OCS que no informa) sigue vivo hoy y lo
# que la lista tiene que ensenar es cuanto lleva sin resolverse.
_DIAS = ("julianday(CASE r.estado WHEN 'corregida' THEN COALESCE(r.corregido_at, r.comprobado_at) "
         "WHEN 'activo_ausente' THEN r.comprobado_at ELSE 'now' END) - julianday(r.detectado_at)")
_EXPUESTO_SQL = "(" + ",".join("'" + e + "'" for e in ENTORNOS_EXPUESTOS) + ")"
# Subconsultas para el paso 4 de sincronizar: version del paquete de la remediacion que OCS ve
# instalada en el activo (la mas alta si hay varias arquitecturas) y, para el sistema base de
# FreeBSD, la version del sistema operativo en la notacion de VuXML (funcion SQL registrada
# en la conexion a partir de versiones_distro.version_base_freebsd).
_BASE_FREEBSD_SQL = "(" + ",".join("'" + n + "'" for n in NOMBRES_BASE_FREEBSD) + ")"
_VERSION_PAQUETE = ("(SELECT s.version FROM activo_software s WHERE s.activo_id=remediaciones.activo_id "
                    "AND s.nombre_norm=remediaciones.paquete ORDER BY s.version DESC LIMIT 1)")
_VERSION_BASE = (f"(SELECT version_base_freebsd(a.so_version) FROM activos a WHERE a.id=remediaciones.activo_id "
                 f"AND a.so_familia='freebsd' AND remediaciones.paquete IN {_BASE_FREEBSD_SQL})")
_VERSION_INSTALADA = f"COALESCE({_VERSION_PAQUETE}, {_VERSION_BASE})"
# Remediaciones del motor de parches de Windows (threatintel.msrc): motor 'msrc' y paquete 'windows'
# (se admiten ambas senas por si el motor de una fila reabierta cambiara). El COALESCE evita la
# logica de tres valores de SQL: con motor NULL (fila heredada o importada a mano) la expresion
# valdria NULL y su negacion tampoco seria cierta, de modo que esa remediacion no se cerraria
# nunca ni por el paso 3 ni por el paso 4.
_ES_MSRC = "(COALESCE(remediaciones.motor, '')='msrc' OR remediaciones.paquete='windows')"
# Actualizacion acumulativa que OCS ve instalada en el equipo Windows (activos.windows_kb).
_KB_INSTALADA = ("COALESCE((SELECT a.windows_kb FROM activos a WHERE a.id=remediaciones.activo_id), "
                 "'sin KB reconocida')")


def _escapar_like(texto: str) -> str:
    """Escapa los comodines de LIKE («%», «_» y la propia barra) para buscar texto literal."""
    return texto.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _dias(valor: Any) -> int:
    try:
        return max(0, int(round(float(valor or 0))))
    except (TypeError, ValueError):
        return 0


def _dict(fila: sqlite3.Row) -> dict[str, Any]:
    d = dict(fila)
    d["estado_es"] = ESTADO_ES.get(d.get("estado"), d.get("estado"))
    d["estado_clave"] = ESTADO_CLAVE.get(d.get("estado"), "neutra")
    d["dias"] = _dias(d.pop("dias_crudos", 0))
    d["titulo"] = d.get("title_es") or d.get("title_en") or d.get("cve")
    d["in_kev"] = bool(d.get("in_kev"))
    d["desinstalado"] = d.get("estado") == "corregida" and d.get("cerrado_motivo") == MOTIVO_DESINSTALADO
    # Parche de Windows: el «paquete» es la actualizacion acumulativa del sistema, no un programa.
    d["msrc"] = d.get("motor") == "msrc" or d.get("paquete") == "windows"
    if "estado_amenaza" in d:
        d["estado_amenaza_es"] = ESTADO_AMENAZA_ES.get(d.get("estado_amenaza") or "", d.get("estado_amenaza") or "")
    if "entorno" in d:
        d["entorno_es"] = ENTORNO_ES.get(d.get("entorno") or "", d.get("entorno") or "Sin entorno")
    return d


# --------------------------------------------------------------------------
# Sincronizacion (abrir, comprobar, cerrar, reabrir)
# --------------------------------------------------------------------------
def sincronizar(conn: sqlite3.Connection, *, ahora: Optional[str] = None) -> dict[str, Any]:
    """Compara ``aplicabilidad`` con ``remediaciones``: abre las nuevas, marca comprobadas las
    que siguen y cierra las corregidas o cuyo activo ya no esta. Devuelve
    {"abiertas_nuevas": n, "cerradas": n, "activo_ausente": n, "abiertas": n, "comprobadas": n}
    (mas "reabiertas": n y "sin_evaluar": n, las pendientes cuya fila de aplicabilidad desaparecio
    mientras el paquete sigue instalado con la misma version: no se puede afirmar nada y esperan
    a la siguiente evaluacion).

    LA SEVERIDAD BAJA SE SIGUE SINCRONIZANDO (decision del 2026-09-10). La orden del
    usuario es que la baja no cuente en nada, y desde hoy no cuenta: no sale en ninguna
    cifra, lista, cola, grafica, correo, informe ni exportacion, porque TODAS las lecturas
    de este modulo la dejan fuera (:data:`_SIN_BAJAS_SQL`). Lo mismo vale para el riesgo
    aceptado con una excepcion vigente (:data:`_SIN_EXCEPCION_SQL`, 2026-09-10): la
    remediacion se sigue abriendo, comprobando, cerrando y reabriendo exactamente igual,
    porque la excepcion CADUCA SOLA y el dia que venza la cola tiene que quedar como si
    nunca hubiera existido, con su fecha de deteccion real. Si aqui se filtrara, una
    excepcion registrada hoy borraria el rastro de la vulnerabilidad y al vencer nadie
    sabria desde cuando estaba pendiente. Lo que no se toca es la
    escritura, por tres motivos:

    1. Reversibilidad inmediata. El usuario pidio que, si el ajuste ``ignore_low_severity``
       se desactivara, la severidad baja volviera a aparecer «sin migración». Si esta
       funcion dejara de abrirla, al desactivar el ajuste no habria nada que ensenar hasta
       la siguiente sincronizacion con OCS Inventory (una vez al dia), y las
       remediaciones nuevas habrian perdido su fecha de deteccion real.
    2. La severidad de una amenaza CAMBIA. Un CVE publicado como bajo se reevalua a alto
       cuando aparece la puntuacion oficial o entra en el catalogo KEV de CISA. Si no se
       hubiera abierto la remediacion, ese dia empezaria a contar desde cero y los dias de
       espera y el tiempo medio de correccion mentirian; abierta y callada, el dia que
       sube de severidad aparece con su antiguedad verdadera.
    3. No cuesta nada. Son 2.774 filas de 48.216 pendientes (2026-09-10): menos del 6 %
       de la tabla, sin efecto medible en el tiempo de sincronizacion.

    Nada se borra de la base: las bajas que ya estaban abiertas siguen abiertas y con su
    historial, simplemente dejan de contarse y de listarse."""
    ahora = ahora or db.utcnow()
    conn.create_function("version_base_freebsd", 1, version_base_freebsd, deterministic=True)
    propia = not conn.in_transaction
    if propia:
        conn.execute("BEGIN")
    try:
        # 1. El activo desaparecio de OCS: las pendientes quedan como «activo retirado».
        #    Tambien las que esperaban datos del inventario (2026-09-10): si el activo ya
        #    no esta, no hay agente que arreglar ni evaluacion que esperar.
        ausentes = conn.execute(
            """UPDATE remediaciones SET estado='activo_ausente', comprobado_at=?, corregido_at=NULL,
                      version_final=NULL, cerrado_motivo=?
                WHERE estado IN ('abierta', 'esperando_datos')
                  AND activo_id IN (SELECT id FROM activos WHERE presente=0)""",
            (ahora, MOTIVO_AUSENTE)).rowcount

        # 2. Siguen vulnerables: solo se anota que se comprobo hoy.
        comprobadas = conn.execute(
            """UPDATE remediaciones SET comprobado_at=?
                WHERE estado='abierta'
                  AND EXISTS (SELECT 1 FROM activos a WHERE a.id=remediaciones.activo_id AND a.presente=1)
                  AND EXISTS (SELECT 1 FROM aplicabilidad ap
                               WHERE ap.activo_id=remediaciones.activo_id AND ap.cve=remediaciones.cve
                                 AND ap.paquete=remediaciones.paquete AND ap.veredicto='afectado')""",
            (ahora,)).rowcount

        # 3. La evaluacion ya ve la version corregida. Para el parche de Windows (msrc) la
        #    «version» es la compilacion instalada y el motivo cita los boletines de Microsoft y
        #    la acumulativa (KB) que lleva el equipo; sin compilacion conocida (fila sin version
        #    o activo sin windows_build) no se afirma nada y la remediacion sigue pendiente.
        corregidas = conn.execute(
            f"""UPDATE remediaciones SET estado='corregida', comprobado_at=?,
                      corregido_at=MAX(COALESCE(ap.evaluado_at, ?), remediaciones.detectado_at),
                      version_final=ap.version_instalada,
                      cerrado_motivo=CASE WHEN {_ES_MSRC}
                                          THEN REPLACE(REPLACE(?, '{{version}}', ap.version_instalada), '{{kb}}', {_KB_INSTALADA})
                                          ELSE REPLACE(?, '{{version}}', COALESCE(ap.version_instalada, 'desconocida')) END
                 FROM aplicabilidad ap
                WHERE remediaciones.estado IN ('abierta', 'esperando_datos')
                  AND ap.activo_id=remediaciones.activo_id AND ap.cve=remediaciones.cve
                  AND ap.paquete=remediaciones.paquete AND ap.veredicto='no_afectado'
                  AND EXISTS (SELECT 1 FROM activos a WHERE a.id=remediaciones.activo_id AND a.presente=1)
                  AND (NOT {_ES_MSRC}
                       OR (ap.version_instalada IS NOT NULL
                           AND EXISTS (SELECT 1 FROM activos a WHERE a.id=remediaciones.activo_id
                                        AND a.windows_build IS NOT NULL)))""",
            (ahora, ahora, MOTIVO_MSRC, MOTIVO_CORREGIDA)).rowcount

        # 3 bis. La evaluacion de hoy NO PUEDE DECIDIR: la fila existe con veredicto
        #    «sin_dato» y no hay ninguna fila «afectado» de ese (activo, CVE, paquete).
        #    Defecto medido el 2026-09-10: 2.480 remediaciones abiertas sin ninguna
        #    vulnerabilidad confirmada detras, todas de cuatro equipos de computo con
        #    Windows 11 cuya compilacion no se puede calcular porque OCS no informa de
        #    ninguna actualizacion acumulativa reconocida. Se apartan de la cola (nadie
        #    puede hacerlas) SIN cerrarlas (nadie ha comprobado que esten corregidas) y sin
        #    tocar ``detectado_at``, de modo que al volver los datos regresan con su
        #    antiguedad verdadera (paso 5). El motivo lleva la evidencia de la evaluacion,
        #    para que la lista diga POR QUE no se puede decidir.
        sin_datos = conn.execute(
            f"""UPDATE remediaciones SET estado='esperando_datos', comprobado_at=?,
                       corregido_at=NULL, version_final=NULL,
                       cerrado_motivo=REPLACE(REPLACE(?, '{{fecha}}', ?), '{{evidencia}}',
                                              COALESCE(NULLIF(ap.evidencia, ''), 'la evaluación no dejó evidencia'))
                  FROM aplicabilidad ap
                 WHERE remediaciones.estado='abierta'
                   AND ap.activo_id=remediaciones.activo_id AND ap.cve=remediaciones.cve
                   AND ap.paquete=remediaciones.paquete AND ap.veredicto='sin_dato'
                   AND EXISTS (SELECT 1 FROM activos a WHERE a.id=remediaciones.activo_id AND a.presente=1)
                   AND NOT EXISTS (SELECT 1 FROM aplicabilidad ap2
                                    WHERE ap2.activo_id=remediaciones.activo_id AND ap2.cve=remediaciones.cve
                                      AND ap2.paquete=remediaciones.paquete AND ap2.veredicto='afectado')""",
            (ahora, MOTIVO_SIN_DATO, fecha_larga(ahora))).rowcount

        # 4. La fila de aplicabilidad desaparecio. Solo se cierra si OCS confirma el cambio:
        #    el paquete ya no esta instalado, o esta con una version distinta de la vulnerable.
        #    Si sigue con la misma version no se afirma nada (evaluacion incompleta, amenaza
        #    purgada, mapa de nombres cambiado...) y la remediacion se queda pendiente. El
        #    sistema base de FreeBSD nunca se «desinstala»: cuenta como instalado con la version
        #    del sistema operativo. El parche de Windows (msrc) tampoco: su fila desaparece por la
        #    ventana de boletines, por perder el producto MSRC o por el borrado del motor principal,
        #    asi que aqui nunca se cierra (solo lo hace el paso 3 con una fila no_afectado).
        sin_fila = """estado='abierta'
                  AND EXISTS (SELECT 1 FROM activos a WHERE a.id=remediaciones.activo_id AND a.presente=1)
                  AND NOT EXISTS (SELECT 1 FROM aplicabilidad ap
                                   WHERE ap.activo_id=remediaciones.activo_id AND ap.cve=remediaciones.cve
                                     AND ap.paquete=remediaciones.paquete)"""
        instalado = f"""(EXISTS (SELECT 1 FROM activo_software s
                                  WHERE s.activo_id=remediaciones.activo_id AND s.nombre_norm=remediaciones.paquete)
                         OR (remediaciones.paquete IN {_BASE_FREEBSD_SQL}
                             AND EXISTS (SELECT 1 FROM activos a WHERE a.id=remediaciones.activo_id
                                          AND a.so_familia='freebsd')))"""
        # Alguna instalacion del paquete (o el sistema base) conserva la version vulnerable, o no
        # se conoce la version instalada: en ambos casos no hay cambio que afirmar.
        misma_version = f"""(EXISTS (SELECT 1 FROM activo_software s
                                      WHERE s.activo_id=remediaciones.activo_id AND s.nombre_norm=remediaciones.paquete
                                        AND (s.version IS NULL OR s.version=remediaciones.version_vulnerable))
                             OR {_VERSION_INSTALADA} IS NULL
                             OR {_VERSION_INSTALADA}=remediaciones.version_vulnerable)"""
        desinstaladas = conn.execute(
            f"""UPDATE remediaciones SET estado='corregida', comprobado_at=?, corregido_at=?,
                       version_final=NULL, cerrado_motivo=?
                 WHERE {sin_fila} AND NOT {_ES_MSRC} AND NOT {instalado}""",
            (ahora, ahora, MOTIVO_DESINSTALADO)).rowcount
        cambiadas = conn.execute(
            f"""UPDATE remediaciones SET estado='corregida', comprobado_at=?, corregido_at=?,
                       version_final={_VERSION_INSTALADA},
                       cerrado_motivo=REPLACE(REPLACE(?, '{{vulnerable}}', remediaciones.version_vulnerable),
                                              '{{version}}', {_VERSION_INSTALADA})
                 WHERE {sin_fila} AND NOT {_ES_MSRC} AND {instalado} AND remediaciones.version_vulnerable IS NOT NULL
                   AND NOT {misma_version}""",
            (ahora, ahora, MOTIVO_SIN_FILA)).rowcount
        sin_evaluar = conn.execute(f"SELECT COUNT(*) FROM remediaciones WHERE {sin_fila}").fetchone()[0]
        desaparecidas = desinstaladas + cambiadas

        # 5. Regresion o activo que reaparece: la fila vuelve a ser «afectado». Tras una
        #    correccion real es una deteccion nueva; tras una retirada del activo no se corrigio
        #    nada y se conserva la fecha de deteccion original.
        #    Y las que esperaban datos del inventario: en cuanto la evaluacion vuelve a
        #    confirmar la vulnerabilidad regresan a la cola CON SU FECHA DE DETECCION
        #    ORIGINAL, porque no se corrigio nada mientras tanto (es el mismo caso que
        #    «activo_ausente», no una deteccion nueva). Asi la espera no borra los dias de
        #    antiguedad ni falsea el tiempo medio de correccion.
        reabiertas = conn.execute(
            """UPDATE remediaciones SET estado='abierta',
                      detectado_at=CASE remediaciones.estado WHEN 'corregida' THEN COALESCE(ap.evaluado_at, ?)
                                        ELSE remediaciones.detectado_at END,
                      comprobado_at=?, corregido_at=NULL, version_final=NULL, version_vulnerable=ap.version_instalada,
                      version_corregida=COALESCE(ap.version_corregida, remediaciones.version_corregida),
                      motor=ap.motor, threat_id=COALESCE(ap.threat_id, remediaciones.threat_id),
                      cerrado_motivo=CASE remediaciones.estado
                                          WHEN 'corregida' THEN ?
                                          WHEN 'esperando_datos' THEN ?
                                          ELSE ? END
                                     || COALESCE('. Antes: ' || remediaciones.cerrado_motivo, '')
                 FROM aplicabilidad ap
                WHERE remediaciones.estado IN ('corregida', 'activo_ausente', 'esperando_datos')
                  AND ap.activo_id=remediaciones.activo_id AND ap.cve=remediaciones.cve
                  AND ap.paquete=remediaciones.paquete AND ap.veredicto='afectado'
                  AND EXISTS (SELECT 1 FROM activos a WHERE a.id=remediaciones.activo_id AND a.presente=1)""",
            (ahora, ahora, MOTIVO_REABIERTA.format(fecha=fecha_larga(ahora)),
             MOTIVO_VUELVE_CON_DATOS.format(fecha=fecha_larga(ahora)),
             MOTIVO_REAPARECIDO.format(fecha=fecha_larga(ahora)))).rowcount

        # 6. Vulnerabilidades confirmadas sin remediacion: se abren.
        nuevas = conn.execute(
            """INSERT INTO remediaciones(activo_id, threat_id, cve, paquete, version_vulnerable, version_corregida,
                                         motor, estado, detectado_at, comprobado_at)
               SELECT ap.activo_id, ap.threat_id, ap.cve, ap.paquete, ap.version_instalada, ap.version_corregida,
                      ap.motor, 'abierta', COALESCE(ap.evaluado_at, ?), ?
                 FROM aplicabilidad ap JOIN activos a ON a.id=ap.activo_id
                WHERE ap.veredicto='afectado' AND a.presente=1
                  AND NOT EXISTS (SELECT 1 FROM remediaciones r
                                   WHERE r.activo_id=ap.activo_id AND r.cve=ap.cve AND r.paquete=ap.paquete)""",
            (ahora, ahora)).rowcount

        abiertas = conn.execute("SELECT COUNT(*) FROM remediaciones WHERE estado='abierta'").fetchone()[0]
        esperando = conn.execute(
            "SELECT COUNT(*) FROM remediaciones WHERE estado='esperando_datos'").fetchone()[0]
        resultado = {"abiertas_nuevas": nuevas, "cerradas": corregidas + desaparecidas, "activo_ausente": ausentes,
                     "abiertas": abiertas, "comprobadas": comprobadas, "reabiertas": reabiertas,
                     "sin_evaluar": int(sin_evaluar or 0),
                     # Las que se apartaron HOY y el total que espera datos del inventario.
                     "esperando_datos_nuevas": int(sin_datos or 0),
                     "esperando_datos": int(esperando or 0)}
        if nuevas or corregidas or desaparecidas or ausentes or reabiertas or sin_datos:
            db.audit(conn, "sistema", "remediacion.sincronizar", "remediaciones", None,
                     f"{nuevas} abiertas, {corregidas + desaparecidas} corregidas ({desinstaladas} por desinstalación, "
                     f"{cambiadas} por cambio de versión sin fila de evaluación), {ausentes} de activos retirados, "
                     f"{reabiertas} reabiertas, {sin_datos} pasadas a esperando datos del inventario; "
                     f"{abiertas} pendientes ({sin_evaluar} sin fila de evaluación) y {esperando} esperando datos")
        if propia:
            conn.execute("COMMIT")
        return resultado
    except Exception:
        if propia:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
        raise


# --------------------------------------------------------------------------
# Consultas para las vistas
# --------------------------------------------------------------------------
_CAMPOS = f"""r.id, r.activo_id, r.threat_id, r.cve, r.paquete, r.version_vulnerable, r.version_corregida,
              r.version_final, r.motor, r.estado, r.detectado_at, r.comprobado_at, r.corregido_at, r.cerrado_motivo,
              r.comprobacion_veredicto, r.comprobacion_at, r.comprobacion_pedida_por, r.notas,
              t.title_es, t.title_en, t.severity, t.in_kev, t.estado AS estado_amenaza,
              ({_DIAS}) AS dias_crudos"""


def contar_historial_activo(conn: sqlite3.Connection, activo_id: int) -> int:
    """Remediaciones de un activo, sin recorte: el total que necesita la paginacion.

    Sin las de severidad baja (2026-09-10, ajuste ``ignore_low_severity``): la lista que
    se pagina tampoco las trae, y un total que no case con la lista es un error visible.

    SI cuenta lo que cubre una excepcion vigente, a proposito (2026-09-10): esta cifra
    pagina el historial de la ficha del activo, que es el UNICO sitio donde una
    vulnerabilidad con el riesgo aceptado tiene que seguir viendose y abriendose, marcada
    con su insignia «Riesgo aceptado». Una excepcion no borra ni oculta nada: solo saca la
    fila de la cola de trabajo y de las cifras de riesgo. Si aqui se excluyera, el total
    dejaria de casar con la lista de ``historial_activo``, que si las trae."""
    return int(conn.execute(
        f"SELECT COUNT(*) FROM remediaciones r WHERE r.activo_id=?{_y_sin_bajas(conn)}",
        (activo_id,)).fetchone()[0] or 0)


def contar_congeladas_activo(conn: sqlite3.Connection, activo_id: int) -> int:
    """Remediaciones CONGELADAS de un activo: las que quedaron en «Activo retirado».

    Un activo que ya no figura en OCS Inventory no vuelve a evaluarse: sus remediaciones
    no se pueden confirmar ni cerrar. La ficha del activo y su plan de remediación dicen
    esta cifra, y la dicen con el MISMO criterio que el resto de la plataforma —sin la
    severidad baja (ajuste ``ignore_low_severity``)—, porque si no la tarjeta decía 155 y
    el aviso de la misma pantalla 142 (revisión de claridad del 2026-09-15).

    SI cuenta lo que cubre una excepción vigente, por el mismo motivo que
    ``contar_historial_activo``: esta cifra acompaña a la tabla de la ficha del activo,
    que es el único sitio donde una vulnerabilidad con el riesgo aceptado tiene que seguir
    viéndose, marcada con su insignia. Si aquí se excluyera, el aviso diría menos
    remediaciones congeladas de las que la propia página enseña a continuación, que es
    justo la contradicción que este cambio viene a cerrar.
    """
    return int(conn.execute(
        f"SELECT COUNT(*) FROM remediaciones r WHERE r.activo_id=? "
        f"AND r.estado='activo_ausente'{_y_sin_bajas(conn)}",
        (activo_id,)).fetchone()[0] or 0)


def historial_activo(conn: sqlite3.Connection, activo_id: int, *, limite: int = 100,
                     desplazamiento: int = 0) -> list[dict]:
    """Remediaciones de un activo (abiertas primero, luego corregidas mas recientes).

    ``desplazamiento`` (2026-09-07) pagina la lista en la ficha del activo; el orden
    termina en ``r.id`` para que sea total. La severidad baja queda fuera (2026-09-10,
    ajuste ``ignore_low_severity``).

    El riesgo aceptado NO queda fuera, a proposito (2026-09-10): la ficha del activo es
    el sitio donde una vulnerabilidad cubierta por una excepcion vigente tiene que seguir
    apareciendo, con la insignia «Riesgo aceptado hasta el …», su responsable y el enlace
    a la excepcion. Sacarla de aqui la esconderia, y una excepcion no esconde nada; la
    plantilla ``activo_detalle.html`` pinta la insignia con ``excepciones.por_activo``."""
    filas = conn.execute(
        f"""SELECT {_CAMPOS}
              FROM remediaciones r LEFT JOIN threats t ON t.id=r.threat_id
             WHERE r.activo_id=?{_y_sin_bajas(conn)}
             ORDER BY {_ORDEN_ESTADO}, t.in_kev DESC, {_ORDEN_SEVERIDAD}, r.corregido_at DESC,
                      r.detectado_at DESC, r.cve, r.id
             LIMIT ? OFFSET ?""",
        (activo_id, max(1, int(limite or 1)), max(0, int(desplazamiento or 0)))).fetchall()
    return [_dict(f) for f in filas]


def resumen(conn: sqlite3.Connection, *, dias: int = 30,
            origen: Optional[str] = None, solo_cifras: bool = False,
            ahora: Optional[datetime] = None) -> dict[str, Any]:
    """Cifras para paneles: {"abiertas": n, "actualizaciones": n, "corregidas_periodo": n,
    "dias": dias, "tiempo_medio_dias": float|None, "por_proceso": [...],
    "activos_con_abiertas": n, "servidores_con_abiertas": n, "equipos_con_abiertas": n,
    "semanas": [...]} (serie semanal de detectadas y corregidas para un grafico).

    ``abiertas`` son FILAS de remediacion pendientes (una por activo, CVE y paquete) y
    ``actualizaciones`` son las tareas en que se agrupan: una por activo y ORIGEN de
    paquete desde el 2026-09-09 (los paquetes de un activo con la misma version
    instalada, la misma version objetivo y los mismos CVE pendientes cuentan como una;
    ver ``_cte_firmas``). Son magnitudes distintas y el tablero tiene que decirlas sin
    mezclarlas: confundirlas es lo que hacia que 47.526 filas parecieran 47.526 trabajos
    cuando son 8.864 (produccion, 2026-09-09).

    Y tres cifras mas, todas de la revision del 2026-09-08:

    * ``actualizaciones_con_version`` / ``actualizaciones_sin_version``: no se puede
      prometer «instalar la version mas alta resuelve todas sus vulnerabilidades» de un
      grupo que todavia no tiene ninguna version que instalar (4.414 de 19.284).
    * ``vulnerabilidades_unicas``: la misma vulnerabilidad contada UNA vez por maquina,
      aunque el aviso obligue a actualizar varios paquetes de esa maquina. Es la cifra
      que el usuario pidio ver («si hay una vulnerabilidad de nucleo que se repite que se
      cuente como una»).
    * ``cve_distintos``: cuantas vulnerabilidades distintas hay en total, sin repetir por
      maquina.

    La severidad BAJA no cuenta en ninguna de estas cifras desde el 2026-09-10 (orden del
    usuario; ajuste ``ignore_low_severity``, activo). Hasta el 2026-09-09 esta funcion
    devolvia ademas ``abiertas_bajas``, ``abiertas_sin_bajas``, ``vulnerabilidades_bajas``,
    ``vulnerabilidades_sin_bajas``, ``cve_distintos_bajos``,
    ``activos_con_abiertas_sin_bajas`` y ``activos_solo_bajas`` para poder explicar en
    pantalla la diferencia con el resto de la plataforma; esas claves DESAPARECEN, porque
    ya no hay diferencia que explicar. Medido sobre la base real el 2026-09-10: 48.216
    filas pendientes y 33.695 vulnerabilidades antes, 45.442 y 32.731 despues (2.774 filas
    y 964 vulnerabilidades de severidad baja), y 602 activos con pendientes frente a 601.

    ``origen`` («servidores» o «equipos», 2026-09-08) acota TODAS las cifras a ese tipo de
    maquina: es lo que ve el perfil de Redes o el de Mantenimiento, y lo que el bloque
    «Avance por tipo de maquina» pide una vez por tipo. Sin ``origen`` nada cambia.

    El RIESGO ACEPTADO tampoco cuenta en ninguna de estas cifras desde el 2026-09-10:
    lo que cubre una excepcion vigente (``threatintel.excepciones``) sale de la cola, de
    los indicadores, del reparto por proceso, del avance por tipo de maquina y de la
    grafica semanal, y vuelve solo cuando la excepcion vence o se revoca. La clave
    ``sin_excepcion`` dice si esa exclusion se esta aplicando.

    ``solo_cifras`` (2026-09-09, revision de seguridad) devuelve las metricas y NO calcula
    el reparto por proceso, el reparto por tipo de maquina ni la serie semanal, que solo
    pinta la propia pagina de Remediacion: esas tres claves valen None y quien las lea
    sabe que no se pidieron. Medido sobre la base real el 2026-09-09: el resumen completo
    costaba 590 ms (259 de ellos la serie semanal, ya reescrita: hoy son 411 ms) y con
    ``solo_cifras`` cuesta 220 ms. Lo usan el bloque «Avance por tipo de maquina», que
    pide un resumen por tipo de maquina, y la pagina de Activos, que solo pinta cinco
    cifras: la pagina de Remediacion calculaba tres veces lo mismo y tardaba 2,0 s
    (hallazgo MEDIO del 2026-09-09).

    ``ahora`` (2026-11-15) es la fecha de referencia para calcular el inicio del periodo
    (``desde``): por omision sigue siendo el reloj real del motor SQLite (``'now'``), pero
    las pruebas pueden fijarla para no depender de cuando se ejecuten. Mismo patron que
    :func:`threatintel.ocs.inventario_sin_reportar_detallado`.
    """
    dias = max(1, int(dias or 30))
    if ahora is not None:
        referencia = ahora if ahora.tzinfo else ahora.replace(tzinfo=timezone.utc)
        desde = (referencia - timedelta(days=dias)).replace(
            microsecond=0).isoformat().replace("+00:00", "Z")
    else:
        desde = conn.execute(
            "SELECT strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?)", (f"-{dias} days",)).fetchone()[0]
    cond_origen, params_origen = _filtro_origen_sql(origen)
    # La severidad Baja fuera de TODAS las cifras (2026-09-10): la condicion se calcula
    # una vez y se pega a cada consulta de la funcion, para que ninguna se quede sin ella.
    sin_bajas = _y_sin_bajas(conn)
    # Lo mismo con el riesgo aceptado (2026-09-10): una excepcion vigente saca la fila de
    # TODAS estas cifras, igual que la severidad baja, y se calcula una sola vez.
    sin_excepcion = _y_sin_excepcion(conn)
    # Solo se une con activos cuando hay recorte: sin el, la consulta es la de siempre.
    # Los parametros van con nombre; el del recorte se llama :origen.
    de_donde = ("remediaciones r JOIN activos a ON a.id=r.activo_id WHERE a.origen = :origen"
                if cond_origen else "remediaciones r")
    # La primera condicion que se pegue abre el WHERE si el recorte por tipo no lo abrio.
    for condicion, texto in ((sin_bajas, _SIN_BAJAS_SQL), (sin_excepcion, _SIN_EXCEPCION_SQL)):
        if condicion:
            de_donde += (condicion if " WHERE " in de_donde else " WHERE " + texto)
    y_origen = f" AND {cond_origen}" if cond_origen else ""
    parametros = {"desde": desde, "desinstalado": MOTIVO_DESINSTALADO, "origen": origen}
    fila = conn.execute(
        f"""SELECT SUM(r.estado='abierta') AS abiertas,
                  COUNT(DISTINCT CASE WHEN r.estado='abierta' THEN r.activo_id END) AS activos_con_abiertas,
                  -- La misma vulnerabilidad contada UNA vez por maquina, aunque el mismo
                  -- aviso obligue a actualizar varios paquetes de esa maquina (el caso del
                  -- nucleo que denuncio el usuario: 18 binarios de sssd para un solo CVE).
                  COUNT(DISTINCT CASE WHEN r.estado='abierta' AND r.cve IS NOT NULL AND r.cve <> ''
                        THEN r.activo_id || char(31) || r.cve END) AS vulnerabilidades_unicas,
                  COUNT(DISTINCT CASE WHEN r.estado='abierta' AND r.cve IS NOT NULL AND r.cve <> ''
                        THEN r.cve END) AS cve_distintos,
                  SUM(r.estado='corregida' AND r.corregido_at >= :desde) AS corregidas_periodo,
                  AVG(CASE WHEN r.estado='corregida' AND r.corregido_at >= :desde
                           THEN julianday(r.corregido_at) - julianday(r.detectado_at) END) AS media,
                  SUM(r.estado='corregida' AND r.corregido_at >= :desde AND r.cerrado_motivo = :desinstalado) AS desinstaladas,
                  SUM(r.estado='activo_ausente') AS activo_ausente,
                  -- Trabajo que NADIE PUEDE HACER porque el inventario no trae los datos
                  -- (2026-09-10). No cuenta como pendiente, pero tampoco se esconde: se
                  -- dice aparte, con cuantos activos la provocan, para que Servicios
                  -- Tecnologicos revise su agente de OCS Inventory.
                  SUM(r.estado='esperando_datos') AS esperando_datos,
                  COUNT(DISTINCT CASE WHEN r.estado='esperando_datos' THEN r.activo_id END)
                      AS esperando_datos_activos,
                  COUNT(DISTINCT CASE WHEN r.estado='esperando_datos' AND r.cve IS NOT NULL AND r.cve <> ''
                        THEN r.activo_id || char(31) || r.cve END) AS esperando_datos_vulnerabilidades
             FROM {de_donde}""", parametros).fetchone()
    media = fila["media"]
    # Actualizaciones pendientes: UNA por activo y origen de paquete (2026-09-09), que es
    # la unidad de trabajo real. No es lo mismo que «abiertas» (filas de remediacion) ni
    # que «vulnerabilidades_unicas», y el tablero tiene que decir las tres sin
    # mezclarlas: en produccion el 2026-09-09 eran 8.864 actualizaciones, 27.355
    # vulnerabilidades por maquina y 47.510 filas. Se cuentan con la misma firma que la
    # vista agrupada (``_cte_firmas``), asi que no pueden discrepar de ella. Y se separan
    # las que YA tienen una version que instalar de las que no: el indicador prometia que
    # «instalar la version mas alta resuelve todas sus vulnerabilidades», y para una de
    # cada cuatro no habia nada que instalar todavia (revision del 2026-09-08).
    cte, params_cte = _cte_firmas(solo_abiertas=True, con_version=True,
                                  sin_bajas=bool(sin_bajas),
                                  sin_excepcion=bool(sin_excepcion))
    union_origen = " JOIN activos a ON a.id=f.activo_id WHERE a.origen=?" if cond_origen else ""
    fusiones = conn.execute(
        f"""{cte}
            SELECT COUNT(*) AS actualizaciones, COALESCE(SUM(cv), 0) AS con_version
              FROM (SELECT f.activo_id, f.firma, MAX(f.con_version) AS cv
                      FROM firmas f{union_origen}
                     GROUP BY f.activo_id, f.firma)""", [*params_cte, *params_origen]).fetchone()
    # Reparto de los activos con pendientes por tipo de maquina. El usuario protesto
    # (2026-09-08) porque la interfaz decia «equipos» a secas y no se sabia si eran
    # servidores o equipos de computo: aqui se cuentan por separado y la plantilla los
    # nombra con su nombre.
    tipos = None if solo_cifras else conn.execute(
        f"""SELECT COUNT(DISTINCT CASE WHEN a.origen='servidores' THEN r.activo_id END) AS servidores,
                  COUNT(DISTINCT CASE WHEN a.origen='equipos' THEN r.activo_id END) AS equipos
             FROM remediaciones r JOIN activos a ON a.id=r.activo_id
            WHERE r.estado='abierta'{y_origen}{sin_bajas}{sin_excepcion}""", params_origen).fetchone()
    por_proceso = None if solo_cifras else [dict(r) for r in conn.execute(
        f"""SELECT {GRUPO_SQL} AS proceso,
                   SUM(r.estado='abierta') AS abiertas,
                   SUM(r.estado='abierta' AND a.entorno IN {_EXPUESTO_SQL}) AS abiertas_expuestas,
                   SUM(r.estado='corregida' AND r.corregido_at >= ?) AS corregidas_periodo,
                   -- Las tres cifras que se PINTAN son vulnerabilidades (un CVE en un
                   -- activo), no filas de remediacion: la tabla decia «Remediaciones
                   -- pendientes» y sus numeros no cuadraban con las tarjetas de arriba de
                   -- la misma pagina (peticion del usuario del 2026-09-15). Las filas se
                   -- conservan arriba para quien necesite la trazabilidad.
                   COUNT(DISTINCT CASE WHEN r.estado='abierta'
                         THEN r.activo_id || char(31) || r.cve END) AS vulnerables,
                   COUNT(DISTINCT CASE WHEN r.estado='abierta' AND a.entorno IN {_EXPUESTO_SQL}
                         THEN r.activo_id || char(31) || r.cve END) AS vulnerables_expuestas,
                   COUNT(DISTINCT CASE WHEN r.estado='corregida' AND r.corregido_at >= ?
                         THEN r.activo_id || char(31) || r.cve END) AS vulnerables_corregidas,
                   COUNT(DISTINCT CASE WHEN r.estado='abierta' THEN r.activo_id END) AS activos_con_abiertas,
                   SUM(a.origen='equipos') AS de_equipos,
                   SUM(a.origen='servidores') AS de_servidores,
                   MAX(COALESCE(NULLIF(a.proceso, ''), '') = '') AS sin_proceso
              FROM remediaciones r JOIN activos a ON a.id=r.activo_id
             {_where_y(cond_origen, sin_bajas, sin_excepcion)}
             GROUP BY 1
            HAVING abiertas > 0 OR corregidas_periodo > 0
             ORDER BY abiertas DESC, corregidas_periodo DESC, proceso
             LIMIT 12""", (desde, desde, *params_origen))]
    semanas = None if solo_cifras else _serie_semanal(conn, dias, origen=origen, ahora=ahora)
    return {"abiertas": int(fila["abiertas"] or 0), "corregidas_periodo": int(fila["corregidas_periodo"] or 0),
            "dias": dias, "tiempo_medio_dias": None if media is None else round(float(media), 1),
            "origen": origen if cond_origen else None,
            "por_proceso": por_proceso, "activos_con_abiertas": int(fila["activos_con_abiertas"] or 0),
            "desinstaladas_periodo": int(fila["desinstaladas"] or 0), "activo_ausente": int(fila["activo_ausente"] or 0),
            "actualizaciones": int(fusiones["actualizaciones"] or 0),
            "actualizaciones_con_version": int(fusiones["con_version"] or 0),
            "actualizaciones_sin_version": max(0, int(fusiones["actualizaciones"] or 0)
                                               - int(fusiones["con_version"] or 0)),
            "vulnerabilidades_unicas": int(fila["vulnerabilidades_unicas"] or 0),
            "cve_distintos": int(fila["cve_distintos"] or 0),
            #: Remediaciones apartadas de la cola porque la evaluacion no puede decidir
            #: (2026-09-10, esquema v14): ni cerradas ni pendientes. Con cuantos activos
            #: y cuantas vulnerabilidades distintas, para poder decirlo con su unidad.
            "esperando_datos": int(fila["esperando_datos"] or 0),
            "esperando_datos_activos": int(fila["esperando_datos_activos"] or 0),
            "esperando_datos_vulnerabilidades": int(fila["esperando_datos_vulnerabilidades"] or 0),
            #: Si la severidad Baja esta fuera de estas cifras (2026-09-10). Es siempre
            #: cierto salvo que el ajuste ``ignore_low_severity`` se desactive, y la
            #: plantilla lo necesita para no prometer «solo críticas, altas y medias»
            #: cuando alguien decida volver a contarlas.
            "sin_bajas": bool(sin_bajas),
            #: Si hay alguna excepcion vigente sacando filas de estas cifras
            #: (2026-09-10). La plantilla lo necesita para decir «N vulnerabilidades con
            #: el riesgo aceptado» y enlazar a /excepciones/: una cifra que baja por
            #: aceptacion de riesgo y no por correccion tiene que verse.
            "sin_excepcion": bool(sin_excepcion),
            "servidores_con_abiertas": None if tipos is None else int(tipos["servidores"] or 0),
            "equipos_con_abiertas": None if tipos is None else int(tipos["equipos"] or 0),
            #: None (no «0») cuando se pidio con ``solo_cifras``: nadie puede confundir
            #: «no se calculó» con «no hay».
            "solo_cifras": bool(solo_cifras),
            "semanas": semanas}


def _serie_semanal(conn: sqlite3.Connection, dias: int,
                   origen: Optional[str] = None,
                   ahora: Optional[datetime] = None) -> list[dict[str, Any]]:
    """Una entrada por semana del periodo (la mas antigua primero) con las remediaciones
    detectadas y corregidas esa semana. Vacia si no hubo ninguna en todo el periodo.
    Con ``origen`` (2026-09-08) solo las de ese tipo de maquina.

    Las semanas empiezan en lunes y la ultima es la del lunes pasado, igual que antes. Lo
    que cambio el 2026-09-09 es COMO se cuentan: antes eran dos subconsultas por semana
    (hasta 52 recorridos de ``remediaciones`` para cinco barras) y costaba 259 ms de los
    590 del resumen; ahora son dos recorridos, uno por fecha, con el numero de semana
    calculado en SQL. Se comprobo sobre la base real que la serie es identica, semana a
    semana, para 30, 60, 90 y 182 dias y para los dos tipos de maquina.

    Los ACTIVOS RETIRADOS quedan fuera (``estado='activo_ausente'``, revision visual del
    2026-09-09): la grafica sumaba 66.326 remediaciones detectadas cuando la pagina
    entera decia 62.985, porque contaba tambien las 3.341 filas de activos que ya no
    figuran en OCS Inventory. Esas no son trabajo pendiente ni trabajo hecho: son filas
    que se quedaron sin activo, y la pagina las dice aparte en la tarjeta de activos.

    Cada semana lleva ``sin_datos`` (no hubo ni detecciones ni correcciones): una barra
    ausente y un cero se ven igual, y la plantilla tiene que poder decir cual es cual.

    La unidad es la VULNERABILIDAD (un CVE en un activo), no la fila de remediacion
    (2026-09-15, peticion del usuario: «no es muy claro, no son vulnerabilidades o amenazas
    detectadas y remediadas?»). Contando filas, la grafica decia 56.723 detectadas mientras
    las tarjetas de la MISMA pantalla decian 32.823 vulnerabilidades y 48.291 filas: tres
    numeros distintos a la vez. Ahora la grafica cuenta lo mismo que la tarjeta que encabeza
    la pagina, de modo que las dos cifras se pueden comparar de un vistazo.

    La severidad BAJA no entra en ninguna de las dos series (2026-09-10, ajuste
    ``ignore_low_severity``), y tampoco lo que cubre una excepcion vigente (2026-09-10):
    la grafica dice lo mismo que las tarjetas de arriba.

    ``ahora`` (2026-11-15) fija el lunes de la semana en curso desde el que se cuentan
    las semanas hacia atras, resuelto en Python. Por omision sigue usando el reloj real;
    lo necesitan las pruebas para no depender de cuando se ejecuten.

    Hallazgo adicional del 2026-11-15, en esta misma funcion: la formula anterior,
    ``date('now', 'weekday 1', '-7 days')``, calculaba mal el lunes de la semana en curso
    justo cuando «ahora» ES lunes. El modificador ``weekday 1`` de SQLite no avanza si el
    dia ya es lunes (es un no-op), y la resta de 7 dias que le sigue —pensada para
    deshacer el avance de ``weekday 1`` cuando SI hace falta avanzar— restaba una semana de
    mas en ese caso, dejando la semana en curso (la de hoy) fuera de toda ventana: la
    grafica saltaba a la semana anterior sin avisar, y lo detectado o corregido HOY no
    aparecia en ninguna barra. Se comprobo contra los siete dias de una semana (lunes a
    domingo) que ``date('now', '-6 days', 'weekday 1')`` da el lunes correcto, incluido
    hoy mismo, en los siete casos. El equivalente en Python es ``ahora - timedelta(days=
    ahora.weekday())``, sin el caso especial que tenia antes.
    """
    n_semanas = max(1, min(26, -(-dias // 7)))
    cond_origen, _params = _filtro_origen_sql(origen)
    union = " JOIN activos a ON a.id=r.activo_id" if cond_origen else ""
    y_origen = " AND a.origen = :origen" if cond_origen else ""
    sin_bajas = _y_sin_bajas(conn)
    sin_excepcion = _y_sin_excepcion(conn)
    if ahora is not None:
        referencia = ahora.date() if hasattr(ahora, "date") else ahora
        base = referencia - timedelta(days=referencia.weekday())
        limites = conn.execute(
            """WITH RECURSIVE semanas(i, inicio) AS (
                   SELECT 0, date(:base)
                   UNION ALL SELECT i + 1, date(inicio, '-7 days') FROM semanas WHERE i + 1 < :n)
               SELECT inicio FROM semanas ORDER BY inicio""",
            {"n": n_semanas, "base": base.isoformat()}).fetchall()
    else:
        limites = conn.execute(
            """WITH RECURSIVE semanas(i, inicio) AS (
                   SELECT 0, date('now', '-6 days', 'weekday 1')
                   UNION ALL SELECT i + 1, date(inicio, '-7 days') FROM semanas WHERE i + 1 < :n)
               SELECT inicio FROM semanas ORDER BY inicio""", {"n": n_semanas}).fetchall()
    inicios = [f["inicio"] for f in limites]
    fin = conn.execute("SELECT date(?, '+7 days')", (inicios[-1],)).fetchone()[0]
    serie = [{"inicio": i, "etiqueta": _etiqueta_semana(i),
              "etiqueta_larga": _etiqueta_semana(i, larga=True),
              "detectadas": 0, "corregidas": 0, "sin_datos": True}
             for i in inicios]
    # Numero de semana = dias enteros desde el primer lunes, entre siete. El WHERE deja
    # fuera lo anterior al periodo, que es lo que evita que el truncado hacia cero de
    # CAST() meta una fecha anterior en la primera semana. ``r.estado<>'activo_ausente'``
    # deja fuera los activos retirados en las DOS series.
    for clave, columna, condicion in (
            ("detectadas", "r.detectado_at", " AND r.estado <> 'activo_ausente'"),
            ("corregidas", "r.corregido_at", " AND r.estado='corregida'")):
        for fila in conn.execute(
                f"""SELECT CAST((julianday(date({columna})) - julianday(:base)) / 7 AS INTEGER) AS semana,
                           COUNT(DISTINCT r.activo_id || char(31) || r.cve) AS n
                      FROM remediaciones r{union}
                     WHERE date({columna}) >= :base AND date({columna}) < :fin{condicion}{y_origen}{sin_bajas}{sin_excepcion}
                     GROUP BY semana""",
                {"base": inicios[0], "fin": fin, "origen": origen}):
            i = fila["semana"]
            if i is not None and 0 <= int(i) < len(serie):
                serie[int(i)][clave] = int(fila["n"] or 0)
    for s in serie:
        s["sin_datos"] = not (s["detectadas"] or s["corregidas"])
    if all(s["sin_datos"] for s in serie):
        return []
    return serie


_MESES = ("enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto",
          "septiembre", "octubre", "noviembre", "diciembre")


def _etiqueta_semana(fecha: str, *, larga: bool = False) -> str:
    """Rotulo de la semana que empieza en ``fecha``, con el mes en palabras y el ano.

    Hasta el 2026-09-09 decia «10 ago», sin ano y con el mes abreviado, y en el eje de la
    grafica no se podia saber de que ano era («ago» tampoco es una palabra en espanol).
    Ahora son dos lineas, «10 de agosto» y «2026», que es lo que el eje X de
    ``webui.graficos.barras_apiladas`` sabe pintar una debajo de otra; con ``larga`` se
    devuelve en una sola linea («10 de agosto de 2026») para el texto corrido.
    """
    try:
        anio, mes, dia = (int(x) for x in str(fecha)[:10].split("-"))
        nombre = _MESES[mes - 1]
    except (ValueError, IndexError):
        return str(fecha)
    if larga:
        return f"{dia} de {nombre} de {anio}"
    return f"{dia} de {nombre}\n{anio}"


#: Grupos que sustituyen al antiguo «Sin proceso» (2026-09-07). Un activo sin proceso de
#: negocio no es un caso unico: un equipo de usuario sin proceso lo mantiene
#: Mantenimiento, mientras que un servidor sin proceso es una etiqueta que falta en OCS y
#: hay que corregirla. Mezclarlos escondia las dos cosas.
GRUPO_EQUIPOS_SIN_PROCESO = "Equipos de cómputo (Mantenimiento)"
GRUPO_SERVIDORES_SIN_PROCESO = "Servidores sin proceso asignado"

#: SQL que da el nombre del grupo de una fila: el proceso, o el grupo por tipo de equipo.
GRUPO_SQL = (f"CASE WHEN COALESCE(NULLIF(a.proceso, ''), '') <> '' THEN a.proceso "
             f"WHEN a.origen = 'equipos' THEN '{GRUPO_EQUIPOS_SIN_PROCESO}' "
             f"ELSE '{GRUPO_SERVIDORES_SIN_PROCESO}' END")


#: Tipos de maquina admitidos en el filtro ``origen`` (columna ``activos.origen``).
ORIGENES = ("servidores", "equipos")


def _filtro_origen_sql(origen: Optional[str], alias: str = "a") -> tuple[str, list]:
    """Condicion (sin « AND ») y parametros que acotan al tipo de maquina, o vacio.

    Es el recorte de los perfiles Redes (servidores) y Mantenimiento (equipos de computo),
    2026-09-08. Un valor que no sea un tipo conocido no filtra nada, para que un
    parametro corrupto no vacie la pagina en silencio: las vistas ya validan el suyo.
    """
    if origen in ORIGENES:
        return f"{alias}.origen=?", [origen]
    return "", []


#: Valores del filtro de severidad de la pagina de Remediacion.
#:
#: Desde el 2026-09-10 la severidad baja NO se ofrece: la orden del usuario es que no
#: cuente en nada, asi que la cola de trabajo son las criticas, las altas y las medias y
#: la opcion de omision, «todas», ya significa exactamente eso. Hasta el 2026-09-09 habia
#: dos opciones mas —«Todas, incluida la baja (la cola completa)» y «Solo severidad
#: baja»— que se retiran: ofrecerlas era ofrecer una cola de trabajo que no existe.
SEVERIDADES_FILTRO = ("todas", "critical", "high", "medium")
SEVERIDAD_FILTRO_ES = {
    "todas": "Todas las que se reportan (crítica, alta y media)",
    "critical": "Solo severidad crítica",
    "high": "Solo severidad alta",
    "medium": "Solo severidad media",
}


def _filtro_severidad_sql(severidad: Optional[str]) -> tuple[str, list]:
    """Condicion (sin « AND ») y parametros que acotan por severidad, o vacio.

    Usa el alias ``t`` de ``threats``, asi que toda consulta que aplique este filtro tiene
    que unirse a esa tabla (LEFT JOIN: una remediacion puede no tener amenaza registrada y
    entonces no se le conoce severidad). Un valor desconocido no filtra nada, para que un
    parametro corrupto no vacie la pagina en silencio: la severidad baja la deja fuera
    :data:`_SIN_BAJAS_SQL`, que se aplica siempre y no depende de este filtro.
    """
    valor = (severidad or "").strip().lower()
    if valor in ("", "todas"):
        return "", []
    if valor in ("critical", "high", "medium"):
        return "LOWER(COALESCE(t.severity, '')) = ?", [valor]
    return "", []


def _filtros_sql(estado: Optional[str], proceso: Optional[str], q: str,
                 activo_id: Optional[int] = None,
                 origen: Optional[str] = None,
                 severidad: Optional[str] = None,
                 sin_bajas: bool = False,
                 sin_excepcion: bool = False) -> tuple[str, list]:
    """Clausula WHERE (con el espacio inicial) y parametros para ``listar`` y ``contar``.
    Los comodines del texto buscado se escapan: «%» y «_» se buscan como texto literal.
    ``activo_id`` acota a UN activo: es lo que necesita el enlace a los paquetes hermanos
    de una actualizacion (buscar el nombre del paquete con ``q`` llevaba a los grupos de
    todos los activos: 106 en vez de 1, revision del 2026-09-08).
    ``origen`` (2026-09-08) acota a un tipo de maquina, «servidores» o «equipos»: es el
    alcance de los perfiles Redes y Mantenimiento; None no filtra.
    ``severidad`` (2026-09-09) acota por severidad de la amenaza (ver
    ``SEVERIDADES_FILTRO``); necesita el LEFT JOIN con ``threats`` como alias ``t``.
    ``sin_bajas`` (2026-09-10) deja fuera la severidad baja SIEMPRE, con independencia
    del filtro que haya elegido la persona: lo decide el ajuste ``ignore_low_severity``
    y no la direccion, para que ningun parametro pueda devolverla a la cola.
    ``sin_excepcion`` (2026-09-10) deja fuera lo que cubre una excepcion vigente, por la
    misma razon y con el mismo caracter incondicional: es un riesgo aceptado por escrito,
    con responsable y con fecha, y ningun parametro de la direccion puede devolverlo a la
    cola antes de que la excepcion venza o se revoque."""
    condiciones, params = [], []
    if sin_bajas:
        condiciones.append(_SIN_BAJAS_SQL)
    if sin_excepcion:
        condiciones.append(_SIN_EXCEPCION_SQL)
    if activo_id:
        condiciones.append("r.activo_id=?")
        params.append(int(activo_id))
    cond_origen, params_origen = _filtro_origen_sql(origen)
    if cond_origen:
        condiciones.append(cond_origen)
        params.extend(params_origen)
    cond_sev, params_sev = _filtro_severidad_sql(severidad)
    if cond_sev:
        condiciones.append(cond_sev)
        params.extend(params_sev)
    if estado in ESTADOS:
        condiciones.append("r.estado=?")
        params.append(estado)
    if proceso:
        sin_proceso = "(a.proceso IS NULL OR a.proceso='')"
        if proceso == GRUPO_EQUIPOS_SIN_PROCESO:
            condiciones.append(f"({sin_proceso} AND a.origen='equipos')")
        elif proceso == GRUPO_SERVIDORES_SIN_PROCESO:
            condiciones.append(f"({sin_proceso} AND a.origen='servidores')")
        elif proceso == "Sin proceso":
            # Nombre antiguo del grupo: se acepta para no romper enlaces guardados.
            condiciones.append(f"({sin_proceso})")
        else:
            condiciones.append("a.proceso=?")
            params.append(proceso)
    q = (q or "").strip()
    if q:
        patron = f"%{_escapar_like(q)}%"
        condiciones.append("(a.nombre LIKE ? ESCAPE '\\' OR a.ip LIKE ? ESCAPE '\\' "
                           "OR r.cve LIKE ? ESCAPE '\\' OR r.paquete LIKE ? ESCAPE '\\')")
        params += [patron, patron, patron, patron]
    where = (" WHERE " + " AND ".join(condiciones)) if condiciones else ""
    return where, params


def contar(conn: sqlite3.Connection, *, estado: Optional[str] = None, proceso: Optional[str] = None,
           q: str = "", activo_id: Optional[int] = None, origen: Optional[str] = None,
           severidad: Optional[str] = None) -> int:
    """Numero total de remediaciones que cumplen los mismos filtros que ``listar`` (sin limite),
    para avisar en la pagina cuando la lista se recorta.

    El LEFT JOIN con ``threats`` esta para que el filtro de severidad (2026-09-09) pueda
    aplicarse aqui igual que en ``listar``: si las dos consultas no unieran las mismas
    tablas, el recuento y la lista discreparian. La severidad baja y el riesgo aceptado
    con una excepcion vigente quedan fuera de las dos (2026-09-10)."""
    where, params = _filtros_sql(estado, proceso, q, activo_id, origen, severidad,
                                 excluir_bajas(conn), excepciones.hay_excepciones(conn))
    return int(conn.execute(
        f"""SELECT COUNT(*) FROM remediaciones r JOIN activos a ON a.id=r.activo_id
              LEFT JOIN threats t ON t.id=r.threat_id{where}""", params).fetchone()[0] or 0)


def listar(conn: sqlite3.Connection, *, estado: Optional[str] = None, proceso: Optional[str] = None,
           q: str = "", limite: int = 500, desplazamiento: int = 0,
           activo_id: Optional[int] = None, origen: Optional[str] = None,
           severidad: Optional[str] = None) -> list[dict]:
    """Listado filtrable para la pagina Remediacion. ``estado`` admite 'abierta', 'corregida',
    'activo_ausente' o vacio/'todas'; ``proceso`` el nombre exacto ('Sin proceso' para los
    servidores sin TAG); ``q`` busca texto literal en nombre del activo, IP, CVE o paquete;
    ``origen`` («servidores» o «equipos», 2026-09-08) acota al tipo de maquina del perfil.

    ``desplazamiento`` salta las primeras filas del resultado (paginacion en el servidor,
    2026-09-07): sin el, la ultima pagina de las 42.902 remediaciones obligaba a traer
    todo lo anterior y recortarlo en Python (1.114 ms frente a los 310 ms de la primera).

    ``severidad`` («critical», «high», «medium», 2026-09-09) acota por severidad de la
    amenaza (ver ``SEVERIDADES_FILTRO``). La severidad BAJA no se lista nunca mientras el
    ajuste ``ignore_low_severity`` este activo (2026-09-10), pida lo que pida el filtro.
    Lo que cubre una excepcion vigente tampoco se lista (2026-09-10): sigue en la ficha
    del activo y en ``/excepciones/``, con su responsable y su fecha de vencimiento.

    El orden termina en ``r.id``, que es unico: con un orden que empataba, SQLite podia
    devolver la misma fila en dos paginas y perder otra."""
    where, params = _filtros_sql(estado, proceso, q, activo_id, origen, severidad,
                                 excluir_bajas(conn), excepciones.hay_excepciones(conn))
    params.extend([int(limite), max(0, int(desplazamiento))])
    filas = conn.execute(
        f"""SELECT {_CAMPOS}, a.nombre AS activo_nombre, a.ip, a.entorno, a.proceso, a.so_nombre, a.origen, a.presente
              FROM remediaciones r JOIN activos a ON a.id=r.activo_id
              LEFT JOIN threats t ON t.id=r.threat_id{where}
             ORDER BY {_ORDEN_ESTADO}, t.in_kev DESC, {_ORDEN_SEVERIDAD},
                      (a.entorno IN {_EXPUESTO_SQL}) DESC, r.corregido_at DESC, r.detectado_at DESC,
                      a.nombre, r.cve, r.id
             LIMIT ? OFFSET ?""", params).fetchall()
    return [_dict(f) for f in filas]


def procesos(conn: sqlite3.Connection, *, origen: Optional[str] = None) -> list[str]:
    """Procesos de negocio con alguna remediacion, para el selector de la pagina.
    Con ``origen`` (2026-09-08) solo los grupos con remediaciones de ese tipo de maquina.
    Un proceso cuyas unicas remediaciones son de severidad baja, o cuyas unicas
    remediaciones tienen el riesgo aceptado con una excepcion vigente, no aparece
    (2026-09-10): pulsarlo llevaria a una lista vacia."""
    cond, params = _filtro_origen_sql(origen)
    where = _where_y(cond, _y_sin_bajas(conn), _y_sin_excepcion(conn))
    return [r[0] for r in conn.execute(
        f"""SELECT DISTINCT {GRUPO_SQL}
             FROM remediaciones r JOIN activos a ON a.id=r.activo_id{where}
            ORDER BY 1""", params)]


# --------------------------------------------------------------------------
# La lista de lo que espera datos del inventario (2026-09-10, esquema v14)
# --------------------------------------------------------------------------
def esperando_datos(conn: sqlite3.Connection, *, origen: Optional[str] = None,
                    limite: int = 50) -> dict[str, Any]:
    """Los activos cuyas remediaciones estan apartadas de la cola porque la evaluacion no
    puede decidir, con lo que hace falta para arreglar la CAUSA y no el sintoma.

    Devuelve ``{"filas": [...], "total_filas": n, "total_activos": n,
    "total_vulnerabilidades": n, "recortado": bool, "limite": n}``. Cada fila es UN
    ACTIVO (no una remediacion), porque el trabajo que hay que hacer es uno por maquina:
    revisar su agente de OCS Inventory. Lleva su nombre, tipo, sistema, la fecha del
    ultimo inventario, cuantas remediaciones y cuantas vulnerabilidades distintas espera,
    desde cuando (la mas antigua) y el motivo que dejo la evaluacion.

    Se resuelve en UNA consulta agrupada, no en una por activo: en produccion son 2.480
    filas de cuatro equipos de computo, pero nada impide que manana sean cuarenta mil.

    ``origen`` acota a «servidores» o «equipos de computo», que es el alcance de los
    perfiles de Redes y de Mantenimiento.
    """
    cond, params = _filtro_origen_sql(origen)
    # Las mismas dos exclusiones que el resto de la cola: la severidad baja no cuenta en
    # nada y el riesgo aceptado tampoco. Sin ellas, esta lista y la cifra
    # ``resumen["esperando_datos"]`` dirian dos numeros distintos de lo mismo (en la base
    # real, 2.480 y 2.477: tres remediaciones de severidad baja).
    where = (" AND " + cond if cond else "") + _y_sin_bajas(conn) + _y_sin_excepcion(conn)
    filas = [dict(r) for r in conn.execute(
        f"""SELECT a.id AS activo_id, a.nombre AS activo_nombre, a.origen, a.ip,
                   a.so_nombre, a.so_version, a.proceso, a.entorno, a.usuario,
                   a.ultimo_inventario, a.windows_build, a.windows_kb,
                   COUNT(*) AS filas,
                   COUNT(DISTINCT r.cve) AS vulnerabilidades,
                   MIN(r.detectado_at) AS desde,
                   MAX(r.comprobado_at) AS comprobado_at,
                   MIN(r.cerrado_motivo) AS motivo,
                   SUM(r.paquete='windows' OR COALESCE(r.motor,'')='msrc') AS de_windows
              FROM remediaciones r JOIN activos a ON a.id=r.activo_id
             WHERE r.estado='esperando_datos'{where}
             GROUP BY a.id
             ORDER BY filas DESC, a.nombre
             LIMIT ?""", [*params, max(1, int(limite)) + 1])]
    recortado = len(filas) > max(1, int(limite))
    filas = filas[:max(1, int(limite))]
    for f in filas:
        f["origen_es"] = ORIGEN_ES.get(f["origen"], f["origen"])
        f["entorno_es"] = ENTORNO_ES.get(f.get("entorno") or "", "Sin entorno")
        f["dias"] = _dias(conn.execute("SELECT julianday('now') - julianday(?)",
                                       (f["desde"],)).fetchone()[0])
        # Todas las filas de este activo son del motor de parches de Windows: entonces la
        # causa es la de produccion (OCS no informa de ninguna actualizacion acumulativa
        # reconocida y no se puede calcular la compilacion) y se puede decir con nombre.
        f["solo_windows"] = int(f.get("de_windows") or 0) == int(f["filas"])
    totales = conn.execute(
        f"""SELECT COUNT(*) AS filas, COUNT(DISTINCT r.activo_id) AS activos,
                   COUNT(DISTINCT r.activo_id || char(31) || r.cve) AS vulnerabilidades
              FROM remediaciones r JOIN activos a ON a.id=r.activo_id
             WHERE r.estado='esperando_datos'{where}""", params).fetchone()
    return {"filas": filas,
            "total_filas": int(totales["filas"] or 0),
            "total_activos": int(totales["activos"] or 0),
            "total_vulnerabilidades": int(totales["vulnerabilidades"] or 0),
            "recortado": recortado, "limite": max(1, int(limite)), "origen": origen}


# --------------------------------------------------------------------------
# «Ya lo remedie, compruebalo» (v10, 2026-09-07)
#
# Peticion del usuario: que Redes pueda marcar una vulnerabilidad de un
# activo como remediada y que «el sistema vaya y realice la respectiva consulta en la base
# de datos segun el activo y verifique si la vulnerabilidad esta o no esta presente
# consultando la version actual cruzandola con la informacion que se reporto de la
# vulnerabilidad».
#
# La decision de diseno importante: la marca de una persona NO cierra la remediacion. Lo
# unico que hace es pedir la comprobacion; el veredicto lo pone la plataforma comparando
# la version que OCS Inventory reporta de ESE paquete en ESE equipo con la que corrige el
# fallo, con el comparador de versiones de la distribucion correspondiente. Una
# remediacion que se cierra porque alguien lo dice es un programa de vulnerabilidades que
# se enga�a a si mismo.
#
# El limite honesto: OCS es tan fresco como su ultima sincronizacion. Si el equipo se
# parcheo hace diez minutos y OCS no ha vuelto a inventariar, la comprobacion dira que
# sigue vulnerable. Por eso el veredicto SIEMPRE dice con que inventario se comprobo y de
# cuando es, y la comprobacion se repite sola en la siguiente sincronizacion.
# --------------------------------------------------------------------------

#: Veredictos de una comprobacion, con el texto que ve la persona.
VEREDICTO_ES = {
    "corregida": "Corregida: la versión instalada ya incluye la corrección",
    "sigue_vulnerable": "Sigue vulnerable: la versión instalada es anterior a la que corrige",
    "desinstalado": "Corregida: el paquete ya no está instalado en el equipo",
    "sin_datos": "No se puede comprobar todavía",
    # Solo para el veredicto de una ACTUALIZACION entera: unas de sus vulnerabilidades
    # estan corregidas y otras no, o falta comprobar alguna. Una actualizacion no esta
    # corregida hasta que lo estan todas las vulnerabilidades que cubre.
    "parcial": "Comprobación parcial: quedan vulnerabilidades sin corregir",
}
VEREDICTO_CLAVE = {"corregida": "exito", "desinstalado": "exito",
                   "sigue_vulnerable": "critico", "sin_datos": "medio",
                   "parcial": "medio"}

#: El mismo veredicto en dos o tres palabras, para la INSIGNIA de las tablas (2026-09-08).
#: ``VEREDICTO_ES`` es una frase entera y las insignias llevan ``white-space: nowrap``: una
#: frase dentro de una insignia estiraba la columna hasta sacar la tabla de la pantalla.
#: La frase completa sigue estando, en el ``title`` de la insignia y en el mensaje de la
#: accion, que es donde se lee entera.
VEREDICTO_CORTO = {
    "corregida": "Corregida",
    "sigue_vulnerable": "Sigue vulnerable",
    "desinstalado": "Paquete desinstalado",
    "sin_datos": "Sin datos todavía",
    "parcial": "Corregida en parte",
}

#: Motivo con el que se cierra una remediacion comprobada a peticion de una persona.
MOTIVO_COMPROBADA = "comprobada_a_peticion"


def _version_instalada(conn: sqlite3.Connection, activo_id: int, paquete: str,
                       familia: Optional[str] = None) -> tuple[Optional[str], bool]:
    """(version que OCS reporta de ese paquete en ese equipo, estaba_instalado).

    Se busca por el nombre normalizado, que es como lo guarda la sincronizacion. Si el
    paquete no aparece, el equipo ya no lo tiene instalado: tambien es una correccion.

    Cuando la maquina reporta mas de una version del mismo paquete (multiarquitectura;
    315 casos con remediacion abierta en produccion el 2026-09-08) se elige la MAS ALTA
    con el comparador de la distribucion, no por orden de texto: con el orden de texto
    la comparacion podia hacerse contra la mas baja y decir «sigue vulnerable» un equipo
    que ya esta corregido. Es el mismo fallo que ``version_objetivo`` evita en el otro
    extremo (revision del 2026-09-08).
    """
    # `nombre_norm` lo escribe ocs.normalizar_nombre (quita tambien el sufijo de
    # arquitectura, «bind9-libs:amd64» -> «bind9-libs»); compararlo con un simple
    # lower().strip() funcionaba por coincidencia, no por garantia (revision 2026-09-08).
    filas = conn.execute(
        """SELECT version FROM activo_software
            WHERE activo_id = ? AND (nombre = ? OR nombre_norm = ?)""",
        (activo_id, paquete, normalizar_nombre(paquete))).fetchall()
    if not filas:
        return None, False
    versiones = [f["version"] for f in filas if f["version"]]
    if not versiones:
        return None, True
    return version_objetivo(familia, versiones), True


def comprobar(conn: sqlite3.Connection, remediacion_id: int, *, solicitante: str,
              ip: Optional[str] = None, cerrar: bool = True) -> dict[str, Any]:
    """Comprueba si una remediacion concreta esta realmente corregida en el equipo.

    Devuelve ``{"veredicto": ..., "veredicto_es": ..., "detalle": ..., ...}``. Con
    ``cerrar`` (por omision) una remediacion verificada pasa a «corregida»; el veredicto
    contrario NUNCA la reabre ni la cierra: solo deja constancia.
    """
    fila = conn.execute(
        """SELECT r.*, a.nombre AS activo_nombre, a.so_familia, a.so_version,
                  a.ultimo_inventario, a.presente, a.windows_build, a.windows_kb
             FROM remediaciones r JOIN activos a ON a.id = r.activo_id
            WHERE r.id = ?""", (remediacion_id,)).fetchone()
    if fila is None:
        raise ValueError("La remediación indicada no existe.")
    datos = dict(fila)
    ahora = db.utcnow()
    familia = (datos.get("so_familia") or "").lower()
    corregida = datos.get("version_corregida")
    inventario = datos.get("ultimo_inventario")

    # Dos familias NO estan en `activo_software` por diseno, y leer su ausencia como
    # «paquete desinstalado» cerraba como corregidas vulnerabilidades sin ninguna prueba
    # (revision de seguridad del 2026-09-08, hallazgo critico: un solo clic de grupo
    # cerraba 797 parches de Windows de un equipo de computo, y la sincronizacion no
    # los reabria porque su aplicabilidad esta en «sin_dato»). Es la misma distincion
    # que ya hace `sincronizar` con `_ES_MSRC` y `_VERSION_BASE`:
    #   * parches de Windows (motor 'msrc', paquete 'windows'): la «version» es la
    #     compilacion efectiva que OCS deduce de las KB instaladas (activos.windows_build);
    #   * sistema base de FreeBSD ('freebsd', 'freebsd-kernel'): la version del sistema
    #     operativo en la notacion de VuXML (version_base_freebsd(activos.so_version)).
    es_windows = (datos.get("motor") or "") == "msrc" or datos.get("paquete") == "windows"
    es_base_freebsd = familia == "freebsd" and datos.get("paquete") in NOMBRES_BASE_FREEBSD
    if es_windows:
        instalada, instalado = datos.get("windows_build"), True
    elif es_base_freebsd:
        instalada, instalado = version_base_freebsd(datos.get("so_version")), True
    else:
        instalada, instalado = _version_instalada(conn, datos["activo_id"],
                                                  datos["paquete"], familia)

    if not datos.get("presente"):
        veredicto = "sin_datos"
        detalle = ("El equipo ya no aparece en OCS Inventory, así que no se puede leer su "
                   "versión actual. Si se retiró, dese de baja en OCS; si sigue en uso, "
                   "revise su agente.")
    elif es_windows and not instalada:
        veredicto = "sin_datos"
        detalle = (f"OCS Inventory no reporta en {datos['activo_nombre']} ninguna "
                   f"actualización acumulativa (KB) reconocida, así que no se conoce la "
                   f"compilación de Windows instalada y no hay con qué comparar. Los parches "
                   f"de Windows los comprueba la sincronización con los boletines de "
                   f"Microsoft en cuanto OCS reporte la KB.")
    elif es_base_freebsd and not instalada:
        veredicto = "sin_datos"
        detalle = (f"OCS Inventory no reporta la versión del sistema FreeBSD de "
                   f"{datos['activo_nombre']}, así que no se puede comparar el sistema base.")
    elif not instalado:
        veredicto = "desinstalado"
        detalle = (f"OCS Inventory ya no informa el paquete «{datos['paquete']}» en "
                   f"{datos['activo_nombre']}: si se desinstaló, la vulnerabilidad deja de "
                   f"aplicar.")
    elif not corregida:
        veredicto = "sin_datos"
        detalle = ("Todavía no se conoce la versión que corrige este fallo, así que no hay "
                   "nada con lo que comparar. Aparece en «Correcciones pendientes».")
    elif not instalada:
        veredicto = "sin_datos"
        detalle = (f"OCS Inventory informa el paquete «{datos['paquete']}» sin número de "
                   f"versión, así que no se puede comparar.")
    else:
        if es_windows:
            from . import msrc
            comparacion = msrc.comparar_builds(instalada, corregida)
            que = "compilación"
        else:
            comparacion = comparar_versiones(familia, instalada, corregida)
            que = "versión"
        if comparacion is None:
            veredicto = "sin_datos"
            detalle = (f"No se pudo comparar la {que} instalada ({instalada}) con la que "
                       f"corrige el fallo ({corregida}): alguna de las dos no tiene un formato "
                       f"reconocible.")
        elif comparacion >= 0:
            veredicto = "corregida"
            detalle = (f"La {que} instalada ({instalada}) es igual o posterior a la que "
                       f"corrige el fallo ({corregida}).")
        else:
            veredicto = "sigue_vulnerable"
            detalle = (f"La {que} instalada ({instalada}) es anterior a la que corrige el "
                       f"fallo ({corregida}): la actualización todavía no está aplicada, o "
                       f"el equipo no ha vuelto a inventariar desde que se aplicó.")

    if inventario:
        detalle += (f" Comprobado con el inventario de {fecha_larga(inventario)}, que es el "
                    f"último que OCS Inventory tiene de este equipo.")

    conn.execute(
        """INSERT INTO remediacion_comprobaciones(
                remediacion_id, activo_id, cve, paquete, solicitado_por, solicitado_at,
                veredicto, version_instalada, version_corregida, inventario_at, detalle, ip)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
        (remediacion_id, datos["activo_id"], datos["cve"], datos["paquete"], solicitante,
         ahora, veredicto, instalada, corregida, inventario, detalle, ip))
    conn.execute(
        """UPDATE remediaciones SET comprobacion_pedida_por=?, comprobacion_pedida_at=?,
               comprobacion_veredicto=?, comprobacion_at=?, comprobado_at=?
             WHERE id=?""",
        (solicitante, ahora, veredicto, ahora, ahora, remediacion_id))

    cerrada = False
    if cerrar and veredicto in ("corregida", "desinstalado") and datos["estado"] != "corregida":
        conn.execute(
            """UPDATE remediaciones SET estado='corregida', corregido_at=?,
                   version_final=?, cerrado_motivo=? WHERE id=?""",
            (ahora, instalada, MOTIVO_COMPROBADA if veredicto == "corregida"
             else MOTIVO_DESINSTALADO, remediacion_id))
        cerrada = True

    db.audit(conn, solicitante, "remediacion.comprobar", "remediaciones", remediacion_id,
             f"{datos['cve']} {datos['paquete']} en {datos['activo_nombre']}: {veredicto}"
             + (f" (instalada {instalada}, corrige {corregida})" if instalada and corregida else ""),
             ip)
    return {
        "remediacion_id": remediacion_id,
        "veredicto": veredicto,
        "veredicto_es": VEREDICTO_ES.get(veredicto, veredicto),
        "clave": VEREDICTO_CLAVE.get(veredicto, "neutra"),
        "detalle": detalle,
        "version_instalada": instalada,
        "version_corregida": corregida,
        "inventario_at": inventario,
        "cerrada": cerrada,
        "activo_nombre": datos["activo_nombre"],
        "cve": datos["cve"],
        "paquete": datos["paquete"],
    }


def comparar_versiones(familia: Optional[str], instalada: str, corregida: str) -> int:
    """-1, 0 o 1 comparando dos versiones con las reglas de la distribucion.

    Se aisla en su propia funcion para poder probarla sin base de datos.
    ``versiones_distro.comparar`` ya elige el comparador correcto por familia: el de dpkg
    para Debian y Ubuntu (que entiende epoch, «~» y «+deb13u1»), el de pkg para FreeBSD y
    la comparacion generica para el resto.
    """
    from .versiones_distro import comparar
    return comparar(familia, instalada, corregida)


def normalizar_nota(texto: str) -> str:
    """El texto de una nota tal como se guarda: sin espacios de sobra y a 2.000 caracteres.

    Se aisla para que la comprobacion de nota repetida de ``anotar_grupo`` compare
    exactamente lo que se guardaria y no el texto crudo del formulario: «  ya  se hizo »
    y «ya se hizo» son la misma nota.
    """
    texto = " ".join((texto or "").split())[:2000]
    if len(texto) < 3:
        raise ValueError("Escriba al menos unas palabras sobre lo que hizo o lo que falta.")
    return texto


def anotar(conn: sqlite3.Connection, remediacion_id: int, *, autor: str, texto: str,
           ip: Optional[str] = None, auditar: bool = True) -> int:
    """Guarda una nota de Redes sobre esa vulnerabilidad del activo.

    ``auditar`` solo lo pone en False ``anotar_grupo``, que escribe UNA entrada de
    auditoria por accion en lugar de una por fila (ver esa funcion). La nota sigue
    quedando en ``remediacion_notas`` fila a fila: eso es el historial, no la auditoria.
    """
    texto = normalizar_nota(texto)
    fila = conn.execute(
        """SELECT r.activo_id, r.cve, r.paquete, a.nombre FROM remediaciones r
             JOIN activos a ON a.id = r.activo_id WHERE r.id = ?""",
        (remediacion_id,)).fetchone()
    if fila is None:
        raise ValueError("La remediación indicada no existe.")
    cur = conn.execute(
        """INSERT INTO remediacion_notas(remediacion_id, activo_id, autor, creado_at, texto, ip)
           VALUES(?,?,?,?,?,?)""",
        (remediacion_id, fila["activo_id"], autor, db.utcnow(), texto, ip))
    conn.execute("UPDATE remediaciones SET notas = COALESCE(notas,0) + 1 WHERE id=?",
                 (remediacion_id,))
    if auditar:
        db.audit(conn, autor, "remediacion.nota", "remediaciones", remediacion_id,
                 f"{fila['cve']} {fila['paquete']} en {fila['nombre']}: {texto[:160]}", ip)
    return int(cur.lastrowid)


def historial_comprobaciones(conn: sqlite3.Connection, remediacion_id: int, *,
                             limite: int = 20) -> list[dict]:
    """Comprobaciones pedidas para una remediacion, de la mas reciente a la mas antigua."""
    filas = [dict(r) for r in conn.execute(
        """SELECT * FROM remediacion_comprobaciones WHERE remediacion_id=?
            ORDER BY id DESC LIMIT ?""", (remediacion_id, max(1, int(limite))))]
    for f in filas:
        f["veredicto_es"] = VEREDICTO_ES.get(f["veredicto"], f["veredicto"])
        f["clave"] = VEREDICTO_CLAVE.get(f["veredicto"], "neutra")
    return filas


def notas(conn: sqlite3.Connection, remediacion_id: int, *, limite: int = 20) -> list[dict]:
    """Notas de una remediacion, de la mas reciente a la mas antigua."""
    return [dict(r) for r in conn.execute(
        """SELECT * FROM remediacion_notas WHERE remediacion_id=?
            ORDER BY id DESC LIMIT ?""", (remediacion_id, max(1, int(limite))))]


# --------------------------------------------------------------------------
# Agrupacion por ACTUALIZACION (v11, 2026-09-08)
#
# Queja del usuario (2026-09-08): «sigo viendo duplicidad en el reporte de vulnerabilidades
# y fue lo que pedi, si hay una vulnerabilidad de kernel que se repite que se cuente como
# una y se vea como la trazabilidad de las versiones a las que se solicita actualizar».
# Lo habia explicado el 2026-09-07: «una vulnerabilidad de kernel hoy me dice que se debe
# actualizar a la version 5.4 pero manana me dice que debo actualizar a la version 5.6
# porque la 5.4 ya es vulnerable, es decir que se cree como una cola de estas que puedan
# llegar a ser de lo mismo, en el mismo sistema operativo pero diferentes versiones de
# acuerdo a alertas y asi evitar duplicados y reprocesos».
#
# POR QUE PASABA: la tabla ``remediaciones`` tiene una fila por (activo, CVE, paquete). Esa
# es la unidad correcta para el SEGUIMIENTO de cada vulnerabilidad, pero no es la unidad de
# TRABAJO de quien parchea: cada aviso nuevo del kernel abre otra fila del mismo paquete en
# el mismo equipo con SU version corregida, y el listado por CVE las muestra todas como si
# fueran tareas distintas. Medido en produccion el 2026-09-08: 47.526 remediaciones
# pendientes que son solo 19.284 actualizaciones; 1.428 de esos grupos piden mas de una
# version del mismo paquete (18.822 filas), y hay equipos Windows con 725 pendientes de un
# unico paquete y siete compilaciones objetivo distintas.
#
# LA REGLA: instalar la version MAS ALTA de las solicitadas resuelve todas las anteriores,
# porque la version que corrige un aviso posterior del mismo paquete incluye las
# correcciones de los anteriores. Asi que el grupo tiene UNA version objetivo, la mayor, y
# la lista de CVE con la version que pedia cada uno se conserva como trazabilidad: es
# literalmente «la cola» que pidio el usuario.
#
# LO QUE NO SE HACE: ordenar las versiones como texto. Medido en produccion, en 313 de los
# 14.870 grupos con version objetivo el orden alfabetico elige la equivocada. El caso mas
# claro es un kernel Debian con nueve versiones solicitadas entre 6.12.85-1 y 6.12.105-1:
# como texto la «mayor» seria 6.12.96-1 (porque el caracter '9' va despues del '1'), y el
# equipo se quedaria sin las correcciones de 6.12.100-1, 6.12.101-1 y 6.12.105-1. Se ordena
# con ``comparar_versiones``, que elige el comparador de la distribucion del activo.
# --------------------------------------------------------------------------

#: Orden de severidad en Python: el mismo que ``_ORDEN_SEVERIDAD`` hace en SQL, para que
#: la severidad que se pinta del grupo sea la misma por la que se ordeno la pagina.
ORDEN_SEVERIDAD = {"critical": 0, "high": 1, "medium": 2, "low": 3}

#: Cuantas actualizaciones lleva una pagina de la vista agrupada, si no se dice otra cosa.
LIMITE_GRUPOS = 20

#: Cuantas vulnerabilidades (CVE distintos) se PINTAN de cada actualizacion. El limite de
#: LIMITE_GRUPOS acota FILAS, no contenido: medido el 2026-09-09 sobre la base real,
#: «/remediaciones/?q=w» devolvia 7,81 MiB y «?q=windows» 8,32 MiB con 1,9 s de proceso,
#: alcanzable con el perfil de solo lectura, porque las 20 actualizaciones de la pagina
#: sumaban 17.030 vulnerabilidades (la mayor, 1.358 en un solo equipo Windows). Con el
#: recorte se pintan las 25 primeras de cada una y el grupo dice cuantas quedan y donde
#: verlas (``truncado``, ``cves_truncados``): las cifras del grupo siguen siendo las del
#: grupo ENTERO y la version objetivo se calcula sobre TODAS sus filas, que es lo que la
#: revision del 2026-09-08 exigio y no se puede perder.
LIMITE_CVES_GRUPO = 25

#: Presupuesto de vulnerabilidades PINTADAS por actualizacion en la ficha de UN activo
#: (2026-09-09) y tope por version de la cola. Ahi no se recorta la cola de versiones —es
#: la trazabilidad que el usuario pidio ver— sino los CVE de cada version. Medido sobre la
#: base real: el peor caso es un equipo de computo con una sola actualizacion («windows»)
#: de 1.358 vulnerabilidades en 6 versiones; con estos valores se pintan 6 versiones y
#: hasta 20 CVE de cada una, y la pagina dice cuantos no se listan y donde estan todos.
LIMITE_CVES_FICHA = 400
LIMITE_CVES_POR_VERSION_FICHA = 20


def _orden_severidad(severidad: Optional[str]) -> int:
    return ORDEN_SEVERIDAD.get((severidad or "").strip().lower(), 4)


def _clave_version(familia: Optional[str]):
    """Clave de ordenacion para ``sorted``/``max`` con las reglas de version de la distro.

    Se envuelve ``comparar_versiones`` porque comparar versiones no es una relacion que
    se pueda expresar con una clave escalar: «6.12.100-1» es mayor que «6.12.95-1» pero
    su texto es menor, y cualquier clave derivada de la cadena se equivoca igual.
    """
    from functools import cmp_to_key
    return cmp_to_key(lambda a, b: comparar_versiones(familia, a, b))


def ordenar_versiones(familia: Optional[str], versiones) -> list[str]:
    """Las versiones distintas de ``versiones``, de la MAS ALTA a la mas baja.

    Descarta las vacias. El desempate va por texto ascendente para que dos versiones que
    el comparador considera iguales salgan siempre en el mismo orden: una lista que
    cambia de orden entre dos recargas de la pagina no se puede leer.
    """
    limpias = sorted({(v or "").strip() for v in versiones} - {""})
    return sorted(limpias, key=_clave_version(familia), reverse=True)


def version_objetivo(familia: Optional[str], versiones) -> Optional[str]:
    """La version a la que hay que actualizar: la MAYOR de las solicitadas, o ``None``.

    Es el corazon de la deduplicacion. No se ordena como texto (ver el comentario de
    seccion): con las nueve versiones de un kernel Debian el texto elige 6.12.96-1 y esta
    funcion elige 6.12.105-1, que es la unica que resuelve las nueve.
    """
    ordenadas = ordenar_versiones(familia, versiones)
    return ordenadas[0] if ordenadas else None


# --------------------------------------------------------------------------
# Una actualizacion por ORIGEN DE PAQUETE (2026-09-09)
#
# Agrupar por (activo, paquete) no bastaba. El usuario lo reclamo dos veces: en un mismo
# servidor el nucleo salia cinco veces (linux-headers-6.8.0-60-generic, linux-image-…,
# linux-modules-…, linux-tools-…, todos de 6.8.0-60.63 a 6.8.0-60.63.1 con los mismos 32
# CVE) y sssd dieciocho (sssd, sssd-ad, libnss-sss… con el mismo CVE). Son binarios del
# MISMO paquete fuente: una unica orden de actualizacion los resuelve todos, asi que para
# quien parchea son UNA actualizacion, no cinco ni dieciocho.
#
# LA REGLA (sin diccionarios ni red): dentro de un activo, los grupos (activo, paquete)
# que comparten la misma version instalada, la misma version objetivo y el mismo
# conjunto de CVE pendientes son una sola actualizacion. Se detecta con una FIRMA por
# paquete: la lista ordenada de «cve=version_corregida@version_vulnerable» de sus filas
# pendientes. Dos paquetes con la misma firma en el mismo activo se fusionan. Un paquete
# que no la comparte (linux-tools-common con otra version) queda en su fila y aparece
# como «hermano» de la fusion, con enlace.
#
# Medido en produccion el 2026-09-09: 19.283 grupos (activo, paquete) pasan a 8.864
# actualizaciones (4.359 con mas de un paquete); el nucleo, de 688 a 554. La firma se
# calcula en SQL con GROUP_CONCAT sobre una subconsulta ORDENADA (SQLite 3.37 no admite
# ORDER BY dentro del agregado): verificada contra el mismo calculo en Python en los
# 19.283 grupos sin una discrepancia; sin la subconsulta ordenada discrepaban 3.338.
# --------------------------------------------------------------------------

#: Campos del activo que necesita cada grupo (los mismos que ``listar``, mas so_familia:
#: sin la familia no se puede elegir el comparador de versiones correcto).
_CAMPOS_ACTIVO_GRUPO = ("a.nombre AS activo_nombre, a.ip, a.entorno, a.proceso, a.origen, "
                        "a.so_familia, a.so_nombre, a.presente")

#: Agregados que SQL sabe calcular: SOLO los que sirven para ORDENAR las paginas. Todo lo
#: que se pinta (recuentos, dias de espera, notas, version objetivo) se calcula en Python
#: sobre las filas de detalle de la pagina: la version objetivo porque SQLite no puede
#: compararla bien (ver la seccion), y el resto porque calcularlo aqui costaba dos
#: julianday por cada una de las 47.510 filas para no usarlo (medido 2026-09-09).
#: Los dias de espera que se muestran se cuentan SOLO sobre lo que sigue pendiente, y
#: por eso el orden usa la deteccion pendiente mas antigua (revision del 2026-09-08).
_AGREGADOS_GRUPO = f"""COUNT(*) AS vulnerabilidades,
              SUM(r.estado='abierta') AS pendientes,
              MAX(COALESCE(t.in_kev, 0)) AS in_kev,
              MIN({_ORDEN_SEVERIDAD}) AS orden_severidad,
              MIN(r.detectado_at) AS detectado_at,
              MIN(CASE WHEN r.estado='abierta' THEN r.detectado_at END) AS detectado_pendiente_at"""

#: Campos que el detalle de la vista agrupada necesita de TODAS las filas del grupo: los
#: que se agregan (recuentos, versiones, dias, notas, comprobaciones) y los que ordenan.
#: Fuera quedan los textos largos —titulo de la amenaza, motivo de cierre, aviso y
#: referencia de la evaluacion—, que solo hacen falta en las vulnerabilidades que de
#: verdad se pintan y que ``_completar_cves_pintados`` trae despues para ellas. Traerlos
#: de las 17.030 filas de una pagina «?q=windows» costaba 202 ms y varios MiB de memoria
#: para tirar el 97 % (revision de seguridad del 2026-09-09).
_CAMPOS_AGREGADO = f"""r.id, r.activo_id, r.threat_id, r.cve, r.paquete, r.version_vulnerable,
              r.version_corregida, r.version_final, r.motor, r.estado, r.detectado_at,
              r.comprobado_at, r.corregido_at, r.comprobacion_veredicto, r.comprobacion_at,
              r.comprobacion_pedida_por, r.notas, t.severity, t.in_kev,
              ({_DIAS}) AS dias_crudos"""

#: Separador de la firma: char(31) no aparece en ningun CVE ni version.
_SEPARADOR_FIRMA = "\x1f"

#: Una entrada de la firma por fila: el CVE, la version que lo corrige y la que estaba
#: instalada al detectarlo. Dos paquetes con las mismas entradas piden lo mismo.
_ENTRADA_FIRMA = ("r.cve || '=' || COALESCE(r.version_corregida, '') || '@' || "
                  "COALESCE(r.version_vulnerable, '')")


def _cte_firmas(*, solo_abiertas: bool = True, activo_id: Optional[int] = None,
                activos: Optional[list] = None, con_version: bool = False,
                sin_bajas: bool = False,
                sin_excepcion: bool = False) -> tuple[str, list]:
    """CTE ``firmas(activo_id, paquete, firma, con_version)``: una fila por (activo, paquete).

    Con ``solo_abiertas`` (el caso de la vista de pendientes, que es la que se trabaja)
    la firma sale de las filas pendientes y solo existen los paquetes con alguna. Sin ella,
    la firma es la de las pendientes si quedan y, si no, la de todas las filas: asi un
    grupo ya corregido tambien se fusiona con sus hermanos. ``activo_id`` o ``activos``
    acotan el calculo a una o varias maquinas (ficha del activo, acciones de grupo,
    detalle de la pagina), que con ``idx_remed_activo`` cuesta milisegundos.

    El ORDER BY de la subconsulta es lo que hace canonica la firma: GROUP_CONCAT respeta
    el orden en que le llegan las filas y SQLite 3.37 no admite ORDER BY dentro del
    agregado. Devuelve el texto del CTE (empieza por «WITH») y sus parametros.

    ``sin_bajas`` (2026-09-10) calcula la firma SIN las remediaciones de severidad baja.
    Tiene que ir aqui y no solo en la consulta de fuera: la firma es el conjunto de CVE
    que pide un paquete, y si una baja entrara en ella dos paquetes que hoy piden lo
    mismo dejarian de fusionarse, la version objetivo podria ser la que exige una baja y
    la cuenta de actualizaciones no casaria con la lista.

    ``sin_excepcion`` (2026-09-10) hace lo mismo con el riesgo aceptado, y por la misma
    razon: una vulnerabilidad con el riesgo aceptado no puede fijar la version objetivo
    de una actualizacion que se va a ejecutar hoy, ni partir en dos una fusion.
    """
    condiciones, params = [], []
    if sin_bajas:
        condiciones.append(_SIN_BAJAS_SQL)
    if sin_excepcion:
        condiciones.append(_SIN_EXCEPCION_SQL)
    if solo_abiertas:
        condiciones.append("r.estado='abierta'")
    if activo_id is not None:
        condiciones.append("r.activo_id=?")
        params.append(int(activo_id))
    if activos:
        condiciones.append(f"r.activo_id IN ({','.join('?' * len(activos))})")
        params.extend(int(a) for a in activos)
    where = (" WHERE " + " AND ".join(condiciones)) if condiciones else ""
    # ``con_version`` (si el paquete tiene alguna version que instalar) solo lo necesita
    # ``resumen``; no se calcula por fila cuando nadie lo va a leer.
    columna_version = ("(COALESCE(NULLIF(TRIM(r.version_corregida), ''), '') <> '')"
                       if con_version else "0")
    if solo_abiertas:
        firma = "GROUP_CONCAT(entrada, char(31))"
        version = "MAX(con_version)"
    else:
        firma = ("COALESCE(GROUP_CONCAT(CASE WHEN estado='abierta' THEN entrada END, char(31)), "
                 "GROUP_CONCAT(entrada, char(31)))")
        version = "MAX(CASE WHEN estado='abierta' THEN con_version END)"
    # (activo_id, cve, paquete) es UNIQUE, asi que ordenar por activo, paquete y CVE basta
    # para que la firma sea canonica.
    cte = f"""WITH ordenadas AS (
               SELECT r.activo_id, r.paquete, r.estado, {_ENTRADA_FIRMA} AS entrada,
                      {columna_version} AS con_version
                 FROM remediaciones r{where}
                ORDER BY r.activo_id, r.paquete, r.cve),
           firmas AS (
               SELECT activo_id, paquete, {firma} AS firma, {version} AS con_version
                 FROM ordenadas GROUP BY activo_id, paquete)"""
    return cte, params


#: Componentes que Debian y Ubuntu ponen entre «linux-» y la variante del nucleo. Se
#: quitan del principio del nombre para quedarse con la variante («6.8.0-60-generic»).
_COMPONENTES_NUCLEO = frozenset((
    "image", "headers", "modules", "extra", "tools", "cloud", "buildinfo", "signed",
    "unsigned", "source", "doc", "libc", "dev", "perf", "common", "kbuild", "support",
    "compiler", "config", "base", "kernel"))


def _variante_nucleo(paquete: str) -> str:
    """«linux-modules-extra-6.8.0-60-generic» → «6.8.0-60-generic»; «linux-libc-dev» → «»."""
    partes = paquete[len("linux-"):].split("-")
    while partes and partes[0] in _COMPONENTES_NUCLEO:
        partes.pop(0)
    return "-".join(partes)


#: Una variante del nucleo «lleva version» si contiene un numero de version de verdad
#: («6.12.90+deb13.1-amd64»). No basta con que tenga digitos: «amd64» los tiene y no dice
#: nada de la version instalada (revision visual del 2026-09-09).
_RE_VERSION_VARIANTE = re.compile(r"\d+\.\d+")


def nombre_actualizacion(paquetes, *, version_instalada: Optional[str] = None) -> dict[str, Any]:
    """Como se llama una actualizacion que cubre varios paquetes del mismo origen.

    - Si todos empiezan por «linux-» (image, headers, modules, tools…): «Núcleo Linux» y la
      variante tras el prefijo («Núcleo Linux 6.8.0-60-generic»). La variante se elige en
      este orden:
        1. la MAS ESPECIFICA (la mas larga) de las que llevan un numero de version
           («6.12.90+deb13.1-amd64» frente a «amd64»);
        2. si ninguna lleva version pero todas son prefijo de la mas larga
           («6.8.0-60» y «6.8.0-60-generic»), la mas larga;
        3. si no hay ninguna, la ``version_instalada`` que reporta OCS Inventory.
      Solo si tampoco se conoce esa version la fila se llama «Núcleo Linux» a secas.

      El paso 1 y el paso 3 son de la revision visual del 2026-09-09: con la regla
      anterior (solo el prefijo comun) 121 de las 124 filas fusionadas del nucleo de
      produccion se llamaban «Núcleo Linux» sin decir la version, porque
      ``linux-image-6.12.90+deb13.1-amd64`` y ``linux-image-amd64`` conviven en el mismo
      activo y «6.12.90+deb13.1-amd64» no empieza por «amd64». Era justo lo que habia que
      evitar: 65 servidores con el mismo nombre de fila y sin saber cual es el nucleo.
    - Si no, el paquete PRINCIPAL (el que coincide con el prefijo comun de todos, o el mas
      corto) seguido de «y N paquetes más»: «sssd y 17 paquetes más».
    - Un solo paquete se llama como el paquete.

    Devuelve ``nombre``, ``principal``, ``es_nucleo``, ``variante``, ``otros`` (N) y
    ``variante_origen`` («paquete» si la variante sale del nombre de un paquete,
    «instalada» si sale de la version que OCS reporta, ``None`` si no hay variante), que
    la plantilla usa para explicar de donde viene la version que lee.
    """
    nombres = sorted({str(p) for p in paquetes if p})
    if not nombres:
        return {"nombre": "—", "principal": None, "es_nucleo": False, "variante": None,
                "variante_origen": None, "otros": 0}
    if len(nombres) == 1:
        return {"nombre": nombres[0], "principal": nombres[0], "es_nucleo": False,
                "variante": None, "variante_origen": None, "otros": 0}
    if all(n.startswith("linux-") for n in nombres):
        # Orden estable: primero la mas larga y, a igual longitud, la menor por texto.
        variantes = sorted({_variante_nucleo(n) for n in nombres} - {""},
                           key=lambda v: (-len(v), v))
        con_version = [v for v in variantes if _RE_VERSION_VARIANTE.search(v)]
        variante, origen = None, None
        if con_version:
            variante, origen = con_version[0], "paquete"
        elif variantes and all(variantes[0].startswith(v) for v in variantes):
            variante, origen = variantes[0], "paquete"
        elif (version_instalada or "").strip():
            variante, origen = str(version_instalada).strip(), "instalada"
        principal = next((n for n in nombres if n.startswith("linux-image")), nombres[0])
        return {"nombre": f"Núcleo Linux {variante}" if variante else "Núcleo Linux",
                "principal": principal, "es_nucleo": True, "variante": variante,
                "variante_origen": origen, "otros": len(nombres) - 1}
    prefijo = os.path.commonprefix(nombres).rstrip("-_.")
    principal = prefijo if prefijo in nombres else min(nombres, key=lambda n: (len(n), n))
    otros = len(nombres) - 1
    return {"nombre": f"{principal} y {otros} paquete{'s' if otros != 1 else ''} más",
            "principal": principal, "es_nucleo": False, "variante": None,
            "variante_origen": None, "otros": otros}


def _sql_pagina(cte: str, where: str) -> str:
    """La consulta agrupada en dos niveles: primero (activo, paquete) con los agregados
    de siempre, luego (activo, firma) que junta los paquetes del mismo origen. El
    ``COUNT(*) OVER ()`` da el total de actualizaciones sin una segunda pasada."""
    return f"""{cte},
      grupos AS (
          SELECT r.activo_id, r.paquete, {_AGREGADOS_GRUPO}
            FROM remediaciones r JOIN activos a ON a.id=r.activo_id
            LEFT JOIN threats t ON t.id=r.threat_id{where}
           GROUP BY r.activo_id, r.paquete)
      SELECT g.activo_id AS activo_id, f.firma AS firma, MIN(g.paquete) AS paquete,
             COUNT(*) AS n_paquetes,
             SUM(g.vulnerabilidades) AS vulnerabilidades, SUM(g.pendientes) AS pendientes,
             MAX(g.in_kev) AS in_kev, MIN(g.orden_severidad) AS orden_severidad,
             MIN(g.detectado_at) AS detectado_at,
             MIN(g.detectado_pendiente_at) AS detectado_pendiente_at,
             {_CAMPOS_ACTIVO_GRUPO}, COUNT(*) OVER () AS total
        FROM grupos g JOIN firmas f ON f.activo_id=g.activo_id AND f.paquete=g.paquete
        JOIN activos a ON a.id=g.activo_id
       GROUP BY g.activo_id, f.firma
       ORDER BY in_kev DESC, orden_severidad, (a.entorno IN {_EXPUESTO_SQL}) DESC,
                COALESCE(detectado_pendiente_at, detectado_at),
                a.nombre, paquete, g.activo_id
       LIMIT ? OFFSET ?"""


def contar_actualizaciones(conn: sqlite3.Connection, *, estado: Optional[str] = "abierta",
                           proceso: Optional[str] = None, q: str = "",
                           activo_id: Optional[int] = None,
                           origen: Optional[str] = None,
                           severidad: Optional[str] = None) -> int:
    """Cuantas ACTUALIZACIONES (una por activo y origen de paquete) cumplen los filtros.

    Es la cifra que necesita la paginacion de la vista agrupada, y la que hay que decir
    junto a la de vulnerabilidades para no confundir las dos magnitudes: 8.864
    actualizaciones pendientes que cubren 47.510 filas de remediacion y 27.355
    vulnerabilidades distintas por maquina (produccion, 2026-09-09). ``origen`` acota al
    tipo de maquina (perfiles Redes y Mantenimiento).
    """
    sin_bajas = excluir_bajas(conn)
    sin_excepcion = excepciones.hay_excepciones(conn)
    where, params = _filtros_sql(estado, proceso, q, activo_id, origen, severidad,
                                 sin_bajas, sin_excepcion)
    cte, params_cte = _cte_firmas(solo_abiertas=(estado == "abierta"), activo_id=activo_id,
                                  sin_bajas=sin_bajas, sin_excepcion=sin_excepcion)
    return int(conn.execute(
        f"""{cte}
            SELECT COUNT(*) FROM (
                SELECT 1 FROM (SELECT DISTINCT r.activo_id, r.paquete
                                 FROM remediaciones r JOIN activos a ON a.id=r.activo_id
                                 LEFT JOIN threats t ON t.id=r.threat_id{where}) g
                  JOIN firmas f ON f.activo_id=g.activo_id AND f.paquete=g.paquete
                 GROUP BY g.activo_id, f.firma)""", [*params_cte, *params]).fetchone()[0] or 0)


def pagina_actualizaciones(conn: sqlite3.Connection, *, estado: Optional[str] = "abierta",
                           proceso: Optional[str] = None, q: str = "",
                           limite: int = LIMITE_GRUPOS, desplazamiento: int = 0,
                           activo_id: Optional[int] = None,
                           origen: Optional[str] = None,
                           severidad: Optional[str] = None,
                           limite_cves: int = LIMITE_CVES_GRUPO,
                           limite_cves_por_version: Optional[int] = None) -> dict[str, Any]:
    """Una pagina de actualizaciones y el total que cumple los filtros, en una consulta.

    Es lo que usa la pagina de Remediacion: pedir el total aparte repetia el calculo de
    las firmas (unos 110 ms en produccion). ``total`` es None solo si la pagina viene
    vacia con desplazamiento (no hay filas de las que leer la ventana); la vista pide
    entonces ``contar_actualizaciones``. Ver ``listar_actualizaciones`` para el contenido
    de cada grupo.

    ``limite_cves`` acota cuantas vulnerabilidades trae PINTADAS cada grupo (25 por
    omision): el limite de grupos acotaba filas y no contenido, y una sola peticion
    autenticada devolvia 8,32 MiB (revision de seguridad del 2026-09-09). Las cifras de
    cada grupo y su version objetivo siguen saliendo de TODAS sus filas.

    ``limite_cves_por_version`` (ficha de UN activo, 2026-09-09) cambia el reparto de ese
    presupuesto: conserva TODAS las versiones de la cola y acota los CVE de cada una. La
    cola de versiones es la trazabilidad que el usuario pidio («que en esa misma se deje la
    trazabilidad de las versiones y de la ultima version a la que se debe actualizar»), asi
    que en la ficha de un activo no se puede recortar; en el listado general si, porque ahi
    hay veinte actualizaciones por pagina.
    """
    sin_bajas = excluir_bajas(conn)
    sin_excepcion = excepciones.hay_excepciones(conn)
    where, params = _filtros_sql(estado, proceso, q, activo_id, origen, severidad,
                                 sin_bajas, sin_excepcion)
    solo_abiertas = estado == "abierta"
    cte, params_cte = _cte_firmas(solo_abiertas=solo_abiertas, activo_id=activo_id,
                                  sin_bajas=sin_bajas, sin_excepcion=sin_excepcion)
    limite = max(1, int(limite or 1))
    desplazamiento = max(0, int(desplazamiento or 0))
    cabeceras = conn.execute(_sql_pagina(cte, where),
                             [*params_cte, *params, limite, desplazamiento]).fetchall()
    if not cabeceras:
        return {"total": 0 if desplazamiento == 0 else None, "grupos": []}
    total = int(cabeceras[0]["total"] or 0)
    activos = sorted({int(c["activo_id"]) for c in cabeceras})
    paquetes_por_fusion = _paquetes_de_fusiones(conn, activos, solo_abiertas=solo_abiertas,
                                                sin_bajas=sin_bajas,
                                                sin_excepcion=sin_excepcion)
    # La firma se calcula dos veces con la MISMA condicion (``solo_abiertas`` sale de una
    # sola variable y va a las dos consultas), asi que las dos tienen que coincidir. Si
    # alguna vez no coincidieran —por ejemplo porque el orden del GROUP_CONCAT cambiara
    # con otra version de SQLite—, el respaldo mostraba un solo paquete en una fila que
    # agrupaba varios SIN NINGUN AVISO (hallazgo BAJO de la revision del 2026-09-09).
    # Ahora ese respaldo es ruidoso: queda en el diario del servicio y la fila se marca
    # como fusion incompleta para quien la lee.
    fusiones = []
    incompletas: set = set()
    for c in cabeceras:
        activo = int(c["activo_id"])
        paquetes = paquetes_por_fusion.get((activo, c["firma"]))
        if paquetes is None:
            paquetes = [c["paquete"]]
            incompletas.add((activo, c["paquete"]))
            log.warning(
                "fusión incompleta en la vista de actualizaciones: la firma del paquete "
                "«%s» del activo %s no se pudo recalcular, así que la fila se muestra con "
                "un solo paquete y puede cubrir más", c["paquete"], activo)
        fusiones.append((activo, paquetes))
    pares = [(activo, paquete) for activo, paquetes in fusiones for paquete in paquetes]
    # El detalle se trae COMPLETO, sin el filtro: los filtros deciden que actualizaciones
    # se muestran, no que version hay que instalar. Recortarlo hacia que al buscar por un
    # CVE la fila dijera «Actualizar a 6.12.85-1» cuando lo que resuelve ese paquete en
    # ese servidor es 6.12.105-1, y quien la ejecutara dejaba 28 vulnerabilidades
    # abiertas (revision del 2026-09-08). `coinciden` marca las que casan con el filtro
    # para poder decir «coincide 1 de sus 29 vulnerabilidades con su búsqueda».
    # Los unicos recortes que siguen aqui son la severidad baja y el riesgo aceptado
    # (2026-09-10): no son filtros de la persona, es que esas vulnerabilidades no
    # cuentan, asi que tampoco pueden decidir la version objetivo del grupo ni sumar a
    # sus recuentos.
    detalle = _detalle_de_grupos(conn, pares, "", [], sin_bajas=sin_bajas,
                                 sin_excepcion=sin_excepcion)
    # ``coinciden`` marca las filas que casan con los filtros que recortan POR
    # VULNERABILIDAD (el texto buscado y, desde el 2026-09-09, la severidad): son los que
    # pueden hacer que una actualizacion aparezca por unas pocas de sus vulnerabilidades,
    # y la fila tiene que decirlo para que nadie crea que la actualizacion es solo eso.
    # El proceso y el tipo de maquina no se marcan: son del activo, y si el activo casa,
    # casan todas sus filas.
    recorta_por_cve = bool((q or "").strip()) or bool(_filtro_severidad_sql(severidad)[0])
    coinciden = (_ids_que_coinciden(conn, pares, where, params)
                 if recorta_por_cve else None)
    instaladas = _instaladas_de_grupos(conn, pares)
    hermanos = _paquetes_hermanos(conn, fusiones, sin_bajas=sin_bajas,
                                  sin_excepcion=sin_excepcion)
    grupos = [_grupo(dict(c), paquetes,
                     {p: detalle.get((activo, p), []) for p in paquetes},
                     coinciden=coinciden,
                     instaladas={p: instaladas.get((activo, p)) for p in paquetes},
                     hermanos=hermanos[i], limite_cves=limite_cves,
                     limite_cves_por_version=limite_cves_por_version,
                     fusion_incompleta=(activo, c["paquete"]) in incompletas)
              for i, (c, (activo, paquetes)) in enumerate(zip(cabeceras, fusiones))]
    # Los textos largos, solo de las vulnerabilidades que se pintan (ver la funcion).
    _completar_cves_pintados(conn, grupos)
    return {"total": total, "grupos": grupos}


def listar_actualizaciones(conn: sqlite3.Connection, *, estado: Optional[str] = "abierta",
                           proceso: Optional[str] = None, q: str = "",
                           limite: int = LIMITE_GRUPOS,
                           desplazamiento: int = 0,
                           activo_id: Optional[int] = None,
                           origen: Optional[str] = None,
                           severidad: Optional[str] = None,
                           limite_cves: int = LIMITE_CVES_GRUPO,
                           limite_cves_por_version: Optional[int] = None) -> list[dict]:
    """Las remediaciones agrupadas por actualizacion: UNA fila por activo y ORIGEN de paquete.
    ``origen`` («servidores» o «equipos», 2026-09-08) acota al tipo de maquina del perfil.

    Por omision agrupa las PENDIENTES, que es lo que se trabaja; ``estado`` acepta los
    mismos valores que ``listar`` (``None`` o «todas» para no filtrar por estado) y los
    filtros de proceso y texto son exactamente los mismos, porque se reutiliza
    ``_filtros_sql``: los grupos no pueden discrepar del listado por CVE.

    Cada grupo trae:
      ``nombre``             «Núcleo Linux 6.8.0-60-generic», «sssd y 17 paquetes más» o el
                             paquete si es uno solo (ver ``nombre_actualizacion``).
      ``paquetes``           la lista de paquetes de la fusion, cada uno con su version
                             instalada y sus identificadores: es la trazabilidad.
      ``version_objetivo``   la MAYOR de las version_corregida del grupo (comparador de
                             la distribucion, nunca orden de texto).
      ``versiones``          una entrada por version solicitada, de la mas alta a la mas
                             baja, con los CVE que pedian cada una (uno por CVE distinto).
      ``cves``               la misma lista en plano, en el mismo orden: un elemento por
                             CVE distinto, con ``ids`` de todas sus filas. Recortada a
                             ``limite_cves`` (25) para que una pagina no pueda pesar
                             megabytes; ``cves_mostrados``, ``cves_truncados`` y
                             ``truncado`` dicen cuantas quedan fuera y ``vulnerabilidades``
                             sigue siendo el total del grupo.
      ``vulnerabilidades``   cuantos CVE distintos cubre la actualizacion (ya no se
                             multiplican por paquete); ``filas`` cuantas filas de
                             remediacion son.
      ``severidad``/``in_kev`` lo peor del grupo, que es lo que marca la prioridad.
      ``detectado_at``/``dias`` la deteccion MAS ANTIGUA: los dias de espera reales.
      ``remediacion_ids`` y ``remediacion_ids_pendientes`` para poder actuar sobre todas.
      ``hermanos``           paquetes del mismo activo que comparten algun CVE pero no
                             cumplen la regla (otra version u otro conjunto): van aparte.

    Medido en produccion el 2026-09-09 sobre 47.510 pendientes: 290 ms la primera
    pagina con el total incluido (8.864 actualizaciones).
    """
    return pagina_actualizaciones(conn, estado=estado, proceso=proceso, q=q, limite=limite,
                                  desplazamiento=desplazamiento, activo_id=activo_id,
                                  origen=origen, severidad=severidad,
                                  limite_cves=limite_cves,
                                  limite_cves_por_version=limite_cves_por_version)["grupos"]


def _paquetes_de_fusiones(conn: sqlite3.Connection, activos: list,
                          *, solo_abiertas: bool, sin_bajas: bool = False,
                          sin_excepcion: bool = False) -> dict:
    """(activo_id, firma) -> paquetes con esa firma, solo para los activos de la pagina.

    La firma nunca viaja como parametro (la mayor de produccion tiene 797 entradas): se
    recalcula acotada a los activos de la pagina, que con el indice por activo cuesta
    milisegundos, y se casa en Python con la de cada cabecera.
    """
    if not activos:
        return {}
    cte, params = _cte_firmas(solo_abiertas=solo_abiertas, activos=activos,
                              sin_bajas=sin_bajas, sin_excepcion=sin_excepcion)
    salida: dict = {}
    for fila in conn.execute(f"{cte} SELECT activo_id, paquete, firma FROM firmas", params):
        salida.setdefault((int(fila["activo_id"]), fila["firma"]), []).append(fila["paquete"])
    return {clave: sorted(paquetes) for clave, paquetes in salida.items()}


def _ids_que_coinciden(conn: sqlite3.Connection, pares: list, where: str,
                       params: list) -> set:
    """Identificadores de remediacion de esos grupos que SI casan con el filtro.

    Se pregunta a SQL con el mismo ``where`` que la consulta agrupada en vez de repetir
    el filtro en Python: cualquier version «parecida» acabaria discrepando del listado.
    """
    if not pares:
        return set()
    condicion, claves, pedidos = _condicion_pares(pares)
    union = " AND " if where else " WHERE "
    return {int(f["id"]) for f in conn.execute(
        f"""SELECT r.id, r.activo_id, r.paquete
              FROM remediaciones r JOIN activos a ON a.id=r.activo_id
              LEFT JOIN threats t ON t.id=r.threat_id
            {where}{union}{condicion}""", [*params, *claves])
            if (int(f["activo_id"]), f["paquete"]) in pedidos}


def _condicion_pares(pares: list) -> tuple[str, list, set]:
    """Condicion SQL para acotar a unos pares (activo, paquete) sin una cadena de OR.

    Con una fusion de 18 paquetes en cada una de las 100 actualizaciones de una ficha, la
    cadena «(activo=? AND paquete=?) OR …» superaba la profundidad maxima de expresion de
    SQLite («Expression tree is too large»). Se pide el producto (activos IN, paquetes IN),
    que usa el indice por activo, y quien llama descarta en Python los pares que no pidio
    con el conjunto ``pedidos`` que se devuelve.
    """
    activos = sorted({int(a) for a, _ in pares})
    paquetes = sorted({p for _, p in pares})
    condicion = (f"(r.activo_id IN ({','.join('?' * len(activos))}) "
                 f"AND r.paquete IN ({','.join('?' * len(paquetes))}))")
    return condicion, [*activos, *paquetes], {(int(a), p) for a, p in pares}


def _instaladas_de_grupos(conn: sqlite3.Connection, pares: list) -> dict:
    """Version que OCS Inventory reporta HOY de cada paquete, por grupo.

    La fila decia «Instalada: X» usando ``version_vulnerable``, que se congela cuando se
    detecta la vulnerabilidad y no se actualiza nunca: en produccion 326 filas (164
    actualizaciones) mandaban instalar una version que la maquina ya tenia (revision del
    2026-09-08). La version de verdad esta en ``activo_software``, que es la que usa
    ``comprobar``, y se elige con el comparador de la distribucion, no por orden de texto.
    """
    if not pares:
        return {}
    por_activo: dict = {}
    for activo_id, paquete in pares:
        por_activo.setdefault(activo_id, {})[normalizar_nombre(paquete)] = paquete
    salida: dict = {}
    activos_info = {int(f["id"]): dict(f) for f in conn.execute(
        f"""SELECT id, so_familia, so_version, windows_build FROM activos
             WHERE id IN ({','.join('?' * len(por_activo))})""", list(por_activo))}
    for activo_id, paquetes in por_activo.items():
        info = activos_info.get(int(activo_id), {})
        familia = (info.get("so_familia") or "").lower()
        # Las dos familias que no estan en activo_software (ver `comprobar`).
        for norm, paquete in list(paquetes.items()):
            if paquete == "windows":
                salida[(activo_id, paquete)] = info.get("windows_build")
                paquetes.pop(norm)
            elif familia == "freebsd" and paquete in NOMBRES_BASE_FREEBSD:
                salida[(activo_id, paquete)] = version_base_freebsd(info.get("so_version"))
                paquetes.pop(norm)
        if not paquetes:
            continue
        marcas = ",".join("?" * len(paquetes))
        candidatas: dict = {}
        for fila in conn.execute(
                f"""SELECT nombre, nombre_norm, version FROM activo_software
                     WHERE activo_id = ? AND (nombre IN ({marcas}) OR nombre_norm IN ({marcas}))""",
                [activo_id, *paquetes.values(), *paquetes]):
            for clave in (normalizar_nombre(fila["nombre"]), fila["nombre_norm"]):
                paquete = paquetes.get(clave or "")
                if paquete is not None and fila["version"]:
                    candidatas.setdefault(paquete, []).append(fila["version"])
        for paquete, versiones in candidatas.items():
            salida[(activo_id, paquete)] = version_objetivo(familia, versiones)
    return salida


def _paquetes_hermanos(conn: sqlite3.Connection, fusiones: list,
                       *, sin_bajas: bool = False,
                       sin_excepcion: bool = False) -> list:
    """Por cada fusion (activo, [paquetes]), los OTROS paquetes del activo que comparten
    algun CVE pendiente con ella pero no cumplen la regla de fusion.

    Antes de fusionar (2026-09-08) esta lista era la unica pista de que el CVE del nucleo
    en `linux-image-…`, `linux-headers-…` y `linux-modules-…` era UN aviso; ahora esos
    tres van en la misma fila y aqui quedan solo los que se apartan: el
    `linux-tools-common` con otra version instalada, que comparte 29 de los 32 CVE del
    nucleo pero necesita su propia orden. Devuelve una lista alineada con ``fusiones``:
    cada elemento es una lista de ``{"paquete", "cves"}`` ordenada por CVE en comun.
    """
    if not fusiones:
        return []
    activos = sorted({int(a) for a, _ in fusiones})
    marcas = ",".join("?" * len(activos))
    y_sin_bajas = f" AND {_SIN_BAJAS_SQL}" if sin_bajas else ""
    # El riesgo aceptado tampoco genera un paquete hermano (2026-09-10): seria mandar
    # actualizar un paquete por una vulnerabilidad que la organizacion decidio aplazar.
    y_sin_excepcion = f" AND {_SIN_EXCEPCION_SQL}" if sin_excepcion else ""
    filas = conn.execute(
        f"""SELECT r.activo_id, r.paquete, r.cve, r.version_corregida, a.so_familia
              FROM remediaciones r JOIN activos a ON a.id=r.activo_id
             WHERE r.estado='abierta' AND r.cve IS NOT NULL AND r.cve <> ''
               AND r.activo_id IN ({marcas}){y_sin_bajas}{y_sin_excepcion}""", activos).fetchall()
    # (activo, cve) -> paquetes que lo piden
    por_cve: dict = {}
    for f in filas:
        por_cve.setdefault((int(f["activo_id"]), f["cve"]), set()).add(f["paquete"])
    # (activo, paquete) -> cves pendientes; y las versiones que piden sus avisos
    por_paquete: dict = {}
    versiones_paquete: dict = {}
    familia_activo: dict = {}
    for f in filas:
        clave = (int(f["activo_id"]), f["paquete"])
        por_paquete.setdefault(clave, set()).add(f["cve"])
        versiones_paquete.setdefault(clave, set()).add(f["version_corregida"])
        familia_activo[int(f["activo_id"])] = f["so_familia"]
    salida = []
    for activo_id, paquetes in fusiones:
        propios = set(paquetes)
        familia = familia_activo.get(int(activo_id))
        cuenta: dict = {}
        for paquete in paquetes:
            for cve in por_paquete.get((int(activo_id), paquete), ()):
                for otro in por_cve.get((int(activo_id), cve), ()):
                    if otro not in propios:
                        cuenta.setdefault(otro, set()).add(cve)
        hermanos = []
        for paquete, compartidos in cuenta.items():
            clave = (int(activo_id), paquete)
            todos = por_paquete.get(clave, set())
            hermanos.append({
                "paquete": paquete,
                "cves": len(compartidos),
                #: Vulnerabilidades pendientes del hermano, compartidas o no: si coincide
                #: con las compartidas, los dos paquetes piden EXACTAMENTE lo mismo.
                "cves_pendientes": len(todos),
                #: La version a la que sus avisos piden actualizarlo. Si es la misma que
                #: la de esta actualizacion y ademas comparten todas las
                #: vulnerabilidades, la MISMA orden resuelve las dos filas: van separadas
                #: solo porque OCS Inventory informa una version instalada distinta
                #: (tipico de un activo con dos imagenes del nucleo instaladas a la vez).
                #: La ficha del activo y la pagina de Remediacion lo dicen con todas las
                #: letras en vez de prometer que el listado «no repite el trabajo»
                #: (revision de claridad del 2026-09-15, punto 5).
                "version_objetivo": version_objetivo(
                    familia, versiones_paquete.get(clave, set())),
            })
        salida.append(sorted(hermanos, key=lambda x: (-x["cves"], x["paquete"])))
    return salida


def _detalle_de_grupos(conn: sqlite3.Connection, pares: list, where: str,
                       params: list, *, sin_bajas: bool = False,
                       sin_excepcion: bool = False) -> dict:
    """Las remediaciones de los grupos de la pagina, indexadas por (activo_id, paquete).

    Se repite el MISMO ``where`` que la consulta agrupada (no una version parecida) para
    que ninguna fila entre en el detalle sin haber contado en el grupo, ni al contrario.

    Trae TODAS las filas del grupo porque de ellas salen la version objetivo y los
    recuentos, que son del grupo entero (revision del 2026-09-08: recortarlas mandaba
    instalar una version que dejaba el equipo vulnerable), pero solo con los campos que se
    agregan (``_CAMPOS_AGREGADO``). Los textos largos y el aviso de ``aplicabilidad`` se
    piden despues solo para las vulnerabilidades que se pintan
    (``_completar_cves_pintados``): con el LEFT JOIN a ``aplicabilidad`` sobre las 17.030
    filas de una pagina «?q=windows» esta consulta costaba 202 ms para tirar el 97 % del
    texto (revision de seguridad del 2026-09-09).
    """
    if not pares:
        return {}
    condicion, claves, pedidos = _condicion_pares(pares)
    if sin_bajas:
        condicion += f" AND {_SIN_BAJAS_SQL}"
    if sin_excepcion:
        condicion += f" AND {_SIN_EXCEPCION_SQL}"
    union = " AND " if where else " WHERE "
    filas = conn.execute(
        f"""SELECT {_CAMPOS_AGREGADO}
              FROM remediaciones r JOIN activos a ON a.id=r.activo_id
              LEFT JOIN threats t ON t.id=r.threat_id
            {where}{union}{condicion}""", [*params, *claves]).fetchall()
    indice: dict = {}
    for fila in filas:
        d = _dict(fila)
        if (int(d["activo_id"]), d["paquete"]) in pedidos:
            indice.setdefault((d["activo_id"], d["paquete"]), []).append(d)
    return indice


def _completar_cves_pintados(conn: sqlite3.Connection, grupos: list[dict]) -> None:
    """Rellena los textos largos SOLO de las vulnerabilidades que la pagina va a pintar.

    Son como maximo ``LIMITE_CVES_GRUPO`` por actualizacion (25 x 20 = 500 en una pagina
    llena) en vez de las 17.030 que llegaba a traer el detalle completo. Trae el titulo de
    la amenaza, su estado, el motivo de cierre y el aviso y la referencia de la evaluacion
    (tabla ``aplicabilidad``, LEFT JOIN por su clave UNIQUE (activo_id, cve, paquete)).
    Se pide por lotes de 400 identificadores para no acercarse al maximo de parametros de
    SQLite. No escribe nada: solo completa los diccionarios que ya estan en memoria.
    """
    representantes = {int(c["id"]): c for g in grupos for c in (g.get("cves") or [])}
    if not representantes:
        return
    ids = sorted(representantes)
    for lote in range(0, len(ids), 400):
        trozo = ids[lote:lote + 400]
        for fila in conn.execute(
                f"""SELECT r.id, r.cve, r.estado, r.cerrado_motivo, t.title_es, t.title_en,
                           t.estado AS estado_amenaza, ap.aviso, ap.referencia
                      FROM remediaciones r
                      LEFT JOIN threats t ON t.id=r.threat_id
                      LEFT JOIN aplicabilidad ap ON ap.activo_id=r.activo_id AND ap.cve=r.cve
                                                AND ap.paquete=r.paquete
                     WHERE r.id IN ({','.join('?' * len(trozo))})""", trozo):
            c = representantes.get(int(fila["id"]))
            if c is None:
                continue
            c["titulo"] = fila["title_es"] or fila["title_en"] or fila["cve"]
            c["cerrado_motivo"] = fila["cerrado_motivo"]
            c["estado_amenaza"] = fila["estado_amenaza"]
            c["estado_amenaza_es"] = ESTADO_AMENAZA_ES.get(fila["estado_amenaza"] or "",
                                                           fila["estado_amenaza"] or "")
            c["aviso"] = fila["aviso"]
            c["referencia"] = fila["referencia"]
            c["desinstalado"] = (fila["estado"] == "corregida"
                                 and fila["cerrado_motivo"] == MOTIVO_DESINSTALADO)


def _recortar_versiones(versiones: list[dict], limite: int, *,
                        por_version: Optional[int] = None) -> tuple[list[dict], list[dict]]:
    """Deja para PINTAR solo las primeras ``limite`` vulnerabilidades de la cola.

    Reparte un presupuesto de ``limite`` vulnerabilidades por el orden en que se leen (de
    la version mas alta a la mas baja, y dentro de cada una por severidad y KEV), que es
    el orden en que importan. Cada entrada conserva su ``total`` real y gana ``mostrados``
    y ``truncados`` para que la pagina pueda decir la verdad («se muestran las 25 primeras
    de 1.358») en lugar de pintar 1.358 filas de tabla.

    Se recorta la LISTA DE ENTRADAS y no solo los CVE de cada una: hay grupos con una
    version distinta por vulnerabilidad (un equipo Windows con 200 compilaciones
    solicitadas), y una entrada vacia por version seguia costando cientos de lineas de
    HTML. Lo comprobo la prueba del peso de la pagina, que crecia 99.998 caracteres al
    anadir un grupo de 200 vulnerabilidades.

    Con ``por_version`` (ficha de UN activo, 2026-09-09) el reparto cambia: se conservan
    TODAS las entradas de la cola —la cola de versiones es la trazabilidad que pidio el
    usuario y no se puede recortar— y lo que se acota son los CVE de cada una. El
    presupuesto global ``limite`` sigue existiendo como tope de peso de la pagina: cuando
    se agota, las entradas siguientes se pintan sin CVE, con su version y su recuento, que
    es lo que de verdad hay que leer. Cada entrada dice cuantos se muestran y cuantos no.

    Devuelve (lista plana de lo que se pinta, entradas que se pintan). Ninguna cifra del
    grupo sale de aqui: todas se calculan antes, sobre las filas completas.
    """
    resto = max(0, int(limite))
    pintados: list[dict] = []
    entradas: list[dict] = []
    for entrada in versiones:
        if resto <= 0 and por_version is None:
            break
        todos = entrada["cves"]
        cabe = resto if por_version is None else min(resto, max(0, int(por_version)))
        entrada["cves"] = todos[:cabe]
        entrada["mostrados"] = len(entrada["cves"])
        entrada["truncados"] = max(0, int(entrada.get("total") or 0) - entrada["mostrados"])
        resto -= entrada["mostrados"]
        pintados.extend(entrada["cves"])
        entradas.append(entrada)
    return pintados, entradas


def _estado_conjunto(filas: list[dict]) -> str:
    """Estado de un conjunto de filas: pendiente si alguna lo esta; corregido si alguna lo
    esta y ninguna pendiente; si no, de activo retirado."""
    if any(f["estado"] == "abierta" for f in filas):
        return "abierta"
    if any(f["estado"] == "corregida" for f in filas):
        return "corregida"
    return "activo_ausente"


def _grupo(cabecera: dict, paquetes: list, filas_por_paquete: dict, *,
           coinciden: Optional[set] = None, instaladas: Optional[dict] = None,
           hermanos: Optional[list[dict]] = None,
           limite_cves: int = LIMITE_CVES_GRUPO,
           limite_cves_por_version: Optional[int] = None,
           fusion_incompleta: bool = False) -> dict:
    """Monta una actualizacion a partir de su fila agregada, sus paquetes y sus filas.

    Lo que SQL no puede hacer se hace aqui: elegir la version objetivo y ordenar la cola de
    versiones necesita el comparador de la distribucion, que vive en Python. Lo demas (los
    recuentos para ordenar y paginar) ya viene resuelto en la fila agregada, que es lo que
    permite paginar 8.864 actualizaciones sin traerlas todas.

    Con varios paquetes del mismo origen, cada CVE aparece una vez por paquete en las
    filas: aqui se cuenta UNA vez (``cves`` lleva un representante por CVE, con los
    identificadores de todas sus filas en ``ids``) y los paquetes se listan aparte con su
    version instalada, que es la trazabilidad que pidio el usuario.
    """
    familia = cabecera.get("so_familia")
    instaladas = instaladas or {}
    # Version instalada MAS ALTA que OCS Inventory reporta de los paquetes de la fusion.
    # Se calcula aqui arriba porque es el respaldo del NOMBRE de la fila cuando ningun
    # nombre de paquete lleva la version del nucleo (revision visual del 2026-09-09: las
    # fusiones de «linux-perf» con «linux-tools-common» no la llevan en ninguno).
    instalada_para_nombre = version_objetivo(familia, [v for v in instaladas.values() if v])
    nombre = nombre_actualizacion(paquetes, version_instalada=instalada_para_nombre)
    principal = nombre["principal"] or (paquetes[0] if paquetes else cabecera.get("paquete"))
    orden_paquetes = [principal] + sorted(p for p in paquetes if p != principal)
    filas = [f for p in orden_paquetes for f in filas_por_paquete.get(p, [])]
    # Un representante por CVE (el del paquete principal si existe) con las filas de todos.
    por_cve: dict = {}
    for f in filas:
        por_cve.setdefault(f["cve"], []).append(f)
    representantes: list[dict] = []
    for cve, suyas in por_cve.items():
        rep = dict(next((f for f in suyas if f["paquete"] == principal), suyas[0]))
        rep["ids"] = [f["id"] for f in suyas]
        rep["n_paquetes"] = len({f["paquete"] for f in suyas})
        rep["estado"] = _estado_conjunto(suyas)
        rep["estado_es"] = ESTADO_ES.get(rep["estado"], rep["estado"])
        rep["estado_clave"] = ESTADO_CLAVE.get(rep["estado"], "neutra")
        rep["notas"] = sum(int(f.get("notas") or 0) for f in suyas)
        rep["in_kev"] = any(f["in_kev"] for f in suyas)
        representantes.append(rep)
    pendientes_filas = [f for f in filas if f["estado"] == "abierta"]
    pendientes_cves = [c for c in representantes if c["estado"] == "abierta"]
    # La version objetivo se calcula sobre lo que SIGUE PENDIENTE: es lo que hay que
    # instalar. Si ya no queda nada pendiente (grupo corregido o de activo retirado) se
    # calcula sobre todas, para que la fila siga diciendo a que version se actualizo.
    # Y sobre TODAS las filas del grupo, nunca sobre las que casan con el filtro: eso
    # ultimo mandaba instalar una version que dejaba el equipo vulnerable.
    base = pendientes_cves or representantes
    objetivo = version_objetivo(familia, [f.get("version_corregida") for f in base])
    orden = ordenar_versiones(familia, [f.get("version_corregida") for f in representantes])
    # Trazabilidad: una entrada por version solicitada, de la mas alta a la mas baja, y al
    # final las vulnerabilidades para las que todavia no se conoce version que corrija.
    por_version: dict = {v: [] for v in orden}
    sin_version: list[dict] = []
    for f in representantes:
        v = (f.get("version_corregida") or "").strip()
        (por_version[v] if v in por_version else sin_version).append(f)
    for lista in list(por_version.values()) + [sin_version]:
        lista.sort(key=lambda f: (_orden_severidad(f.get("severity")), not f["in_kev"], f["cve"]))
    versiones = [{"version": v, "cves": por_version[v], "total": len(por_version[v]),
                  "es_objetivo": v == objetivo} for v in orden]
    if sin_version:
        versiones.append({"version": None, "cves": sin_version, "total": len(sin_version),
                          "es_objetivo": False})
    # ``cves_del_grupo`` es la lista PLANA y ORDENADA del grupo ENTERO, y de ella salen
    # TODAS las cifras: asi dos peticiones iguales devuelven exactamente lo mismo. Tomarlos
    # de las filas tal como las devuelve SQL (sin ORDER BY) haria que el identificador de
    # referencia, y con el el ancla y el destino del formulario, cambiaran entre recargas.
    cves_del_grupo = [c for entrada in versiones for c in entrada["cves"]]
    pendientes_ordenadas = [c for c in cves_del_grupo if c["estado"] == "abierta"]
    ids_pendientes = [f["id"] for c in cves_del_grupo for f in por_cve[c["cve"]]
                      if f["estado"] == "abierta"]
    # Y ``cves`` es lo que la pagina PINTA: las primeras ``limite_cves``. El grupo dice
    # cuantas son en total (``vulnerabilidades``), cuantas se muestran y cuantas quedan
    # fuera, y la plantilla enlaza la ficha del activo, donde estan todas paginadas. Sin
    # este recorte una sola peticion autenticada devolvia 8,32 MiB (revision del
    # 2026-09-09); con el, las cifras y la version objetivo no cambian porque se calculan
    # arriba, sobre las filas completas.
    cves, versiones_pintadas = _recortar_versiones(
        versiones, limite_cves, por_version=limite_cves_por_version)
    # La version instalada es la que OCS Inventory reporta HOY (``instaladas``); la
    # ``version_vulnerable`` de las filas es la del momento de la deteccion y solo se usa
    # como respaldo cuando el paquete ya no figura en el inventario. Con varios paquetes,
    # la de la fila es la mas alta de todas y cada paquete lleva la suya en ``paquetes``.
    detalle_paquetes = []
    for p in orden_paquetes:
        suyas = filas_por_paquete.get(p, [])
        detectada_p = version_objetivo(familia, [f.get("version_vulnerable") for f in suyas])
        real_p = instaladas.get(p)
        detalle_paquetes.append({
            "paquete": p, "principal": p == principal,
            "version_instalada": real_p or detectada_p,
            "version_instalada_es_real": bool(real_p),
            "version_detectada": detectada_p,
            "filas": len(suyas),
            "pendientes": sum(1 for f in suyas if f["estado"] == "abierta"),
            "remediacion_ids": [f["id"] for f in suyas],
        })
    detectada = version_objetivo(familia, [f.get("version_vulnerable") for f in filas])
    reales = [d["version_instalada"] for d in detalle_paquetes if d["version_instalada_es_real"]]
    instalada = version_objetivo(familia, reales) if reales else detectada
    instaladas_distintas = len({d["version_instalada"] for d in detalle_paquetes
                                if d["version_instalada"]}) > 1
    # Veredicto del grupo por CONSENSO, no por recencia: pintar el de la ultima
    # comprobacion ponia la insignia verde «Corregida» en un grupo con dos de tres
    # vulnerabilidades todavia abiertas (revision del 2026-09-08).
    comprobadas = [f for f in filas if f.get("comprobacion_at")]
    ultima = max(comprobadas, key=lambda c: (c["comprobacion_at"], c["id"]), default=None)
    veredictos = {c.get("comprobacion_veredicto") for c in comprobadas}
    if not comprobadas:
        veredicto_grupo = None
    elif "sigue_vulnerable" in veredictos:
        veredicto_grupo = "sigue_vulnerable"
    elif len(comprobadas) < len(filas) or veredictos - {"corregida", "desinstalado"}:
        veredicto_grupo = "parcial"
    else:
        veredicto_grupo = (ultima or {}).get("comprobacion_veredicto")
    # Los dias de espera se cuentan sobre lo que SIGUE pendiente. `dias_crudos` vale
    # «hasta hoy» para las abiertas y «hasta la correccion» para las cerradas, asi que un
    # maximo sobre un grupo mixto devolvia el tiempo de vida de una fila ya cerrada: la
    # celda decia «304 dias esperando» cuando lo unico pendiente se detecto hace tres.
    crudos_pendientes = [f.get("dias") for f in pendientes_filas if f.get("dias") is not None]
    crudos_todos = [f.get("dias") for f in filas if f.get("dias") is not None]
    dias = _dias(max(crudos_pendientes)) if crudos_pendientes else None
    dias_totales = _dias(max(crudos_todos)) if crudos_todos else None
    fechas_pendientes = [f.get("detectado_at") for f in pendientes_filas if f.get("detectado_at")]
    fechas_todas = [f.get("detectado_at") for f in filas if f.get("detectado_at")]
    detectado = min(fechas_pendientes) if fechas_pendientes else (
        min(fechas_todas) if fechas_todas else None)
    estado = _estado_conjunto(filas) if filas else "activo_ausente"
    coincidencias = None
    if coinciden is not None:
        coincidencias = sum(1 for c in cves_del_grupo if any(i in coinciden for i in c["ids"]))
    grupo = {
        # La clave sigue siendo «activo-paquete»: el paquete principal es de esta fusion
        # y de ninguna otra del activo, asi que identifica la fila y no cambia con la
        # pagina. Solo se usa en pruebas y comparaciones, nunca sin escapar en HTML.
        "clave": f"{cabecera['activo_id']}-{principal}",
        "activo_id": cabecera["activo_id"],
        "activo_nombre": cabecera.get("activo_nombre"),
        "ip": cabecera.get("ip"),
        "entorno": cabecera.get("entorno"),
        "entorno_es": ENTORNO_ES.get(cabecera.get("entorno") or "",
                                     cabecera.get("entorno") or "Sin entorno"),
        "proceso": cabecera.get("proceso"),
        "origen": cabecera.get("origen"),
        "so_familia": familia,
        "so_nombre": cabecera.get("so_nombre"),
        "presente": bool(cabecera.get("presente")),
        #: El paquete principal (el unico si no hay fusion) y el nombre de la fila.
        "paquete": principal,
        "nombre": nombre["nombre"],
        "es_nucleo": nombre["es_nucleo"],
        "variante_nucleo": nombre["variante"],
        #: De donde sale la version que lleva el nombre: «paquete» (del nombre de uno de
        #: los paquetes) o «instalada» (de la version que OCS reporta). La plantilla lo
        #: explica en el titulo emergente para que nadie confunda las dos cosas.
        "variante_origen": nombre["variante_origen"],
        "paquetes": detalle_paquetes,
        "n_paquetes": len(detalle_paquetes),
        "es_fusion": len(detalle_paquetes) > 1,
        "msrc": any(c.get("msrc") for c in filas),
        "version_instalada": instalada,
        "version_detectada": detectada,
        "version_instalada_es_real": bool(reales),
        "instaladas_distintas": instaladas_distintas,
        "version_objetivo": objetivo,
        "version_final": next((c.get("version_final") for c in filas if c.get("version_final")), None),
        #: Las entradas de la cola que se PINTAN; ``versiones_pedidas`` sigue siendo
        #: cuantas versiones distintas piden los avisos del grupo entero.
        "versiones": versiones_pintadas,
        "versiones_mostradas": len(versiones_pintadas),
        "versiones_truncadas": len(versiones) - len(versiones_pintadas),
        "versiones_pedidas": len(orden),
        "sin_version_objetivo": len(sin_version),
        #: Paquetes hermanos: otros paquetes del mismo activo que comparten CVE con esta
        #: actualizacion pero no cumplen la regla de fusion (otra version instalada u otro
        #: conjunto de CVE). Van en su propia fila y aqui se enlazan.
        "hermanos": hermanos or [],
        #: Los hermanos que la MISMA orden resuelve: piden la misma version objetivo y
        #: todas sus vulnerabilidades pendientes son las que comparten con esta
        #: actualizacion. Van en fila aparte porque la version instalada es distinta
        #: (varias imagenes del nucleo en la misma maquina, openssl/libssl3 a distinto
        #: nivel). Medido sobre la base real el 2026-09-15: 58 filas de 7.265 (el 0,8 %).
        "hermanos_misma_orden": [
            h for h in (hermanos or [])
            if objetivo and h.get("version_objetivo") == objetivo
            and h.get("cves") == h.get("cves_pendientes") == len(cves_del_grupo)],
        #: Cuantas de sus vulnerabilidades casan con el filtro (None = sin filtro).
        "coincidencias": coincidencias,
        #: Las vulnerabilidades que se PINTAN (las ``limite_cves`` primeras). Las cifras de
        #: abajo son del grupo entero; ``cves_truncados`` dice cuantas no se pintan.
        "cves": cves,
        "cves_mostrados": len(cves),
        "cves_truncados": len(cves_del_grupo) - len(cves),
        "truncado": len(cves) < len(cves_del_grupo),
        "limite_cves": int(limite_cves),
        #: Marca ruidosa (2026-09-09): la firma de fusion no se pudo recalcular para esta
        #: fila, asi que puede cubrir mas paquetes del activo de los que se listan. La
        #: plantilla lo dice y queda en el diario del servicio; sin esta marca el respaldo
        #: mostraba un solo paquete sin ningun aviso.
        "fusion_incompleta": bool(fusion_incompleta),
        # Las cifras del grupo son las del GRUPO ENTERO (`cves` ya trae todas sus filas,
        # sin recortar por el filtro): la actualizacion es la actualizacion. Los
        # agregados de la cabecera se calculan con el filtro y solo sirven para ordenar
        # y paginar. «vulnerabilidades» son CVE DISTINTOS; «filas», filas de remediacion.
        "vulnerabilidades": len(cves_del_grupo),
        "pendientes": len(pendientes_ordenadas),
        "corregidas": sum(1 for c in cves_del_grupo if c["estado"] == "corregida"),
        "retiradas": sum(1 for c in cves_del_grupo if c["estado"] == "activo_ausente"),
        "filas": len(filas),
        "filas_pendientes": len(ids_pendientes),
        "estado": estado,
        "estado_es": ESTADO_ES.get(estado, estado),
        "estado_clave": ESTADO_CLAVE.get(estado, "neutra"),
        "severidad": min((c.get("severity") for c in cves_del_grupo if c.get("severity")),
                         key=_orden_severidad, default=None),
        "in_kev": any(c["in_kev"] for c in cves_del_grupo),
        "detectado_at": detectado,
        #: Dias que llevan esperando las vulnerabilidades que SIGUEN pendientes. Si no
        #: queda ninguna, `dias` es None y `dias_totales` dice cuanto tardo en cerrarse.
        "dias": dias,
        "dias_totales": dias_totales,
        "notas": sum(int(f.get("notas") or 0) for f in filas),
        "remediacion_ids": [f["id"] for f in filas],
        "remediacion_ids_pendientes": ids_pendientes,
        #: Sobre esta remediacion se envian las acciones del grupo: la vista pasa
        #: ``alcance=grupo`` y el modulo resuelve el resto de la actualizacion a partir
        #: de ella (todos los paquetes de la fusion).
        "remediacion_id": ((pendientes_ordenadas or cves_del_grupo)[0]["id"]
                           if cves_del_grupo else None),
        "comprobacion_veredicto": veredicto_grupo,
        "comprobacion_comprobadas": len(comprobadas),
        "comprobacion_corregidas": sum(
            1 for c in comprobadas
            if c.get("comprobacion_veredicto") in ("corregida", "desinstalado")),
        "comprobacion_at": (ultima or {}).get("comprobacion_at"),
        "comprobacion_pedida_por": (ultima or {}).get("comprobacion_pedida_por"),
    }
    grupo["comprobacion_veredicto_es"] = VEREDICTO_ES.get(grupo["comprobacion_veredicto"] or "",
                                                          grupo["comprobacion_veredicto"])
    grupo["comprobacion_clave"] = VEREDICTO_CLAVE.get(grupo["comprobacion_veredicto"] or "",
                                                      "neutra")
    return grupo


def fusionar_plan(grupos: list) -> list:
    """Fusiona los grupos de ``aplicabilidad.plan_remediacion`` que son la misma orden.

    Es IDEMPOTENTE: aplicarla a un plan ya fusionado devuelve el mismo plan (los grupos
    que quedan no comparten clave), y por eso ``plan_remediacion`` la aplica de salida y
    la plantilla puede repetirla despues de recortar el plan al alcance del perfil.

    El plan de un activo agrupa por (sistema, version corregida, CVE), asi que el nucleo
    con 32 CVE salia como 32 grupos con los mismos cuatro paquetes y la misma orden. Aqui
    se juntan los grupos con el mismo sistema, los mismos paquetes y los mismos activos:
    los CVE y los avisos se suman y la orden que queda es la de la version MAS ALTA.

    La version NO entra en la clave desde el 2026-09-09. Antes si, y por eso el plan del
    servidor SRV-EJEMPLO-511 traia tres ordenes para el mismo `linux-tools-common`
    (una para 6.8.0-117.117, otra para 6.8.0-136.136 y otra para 6.8.0-139.139) y 35
    ordenes en total donde la ficha decia 28 actualizaciones. Es exactamente lo que el
    usuario rechazo: «que la remediacion indique si o si la ultima version a la que se
    debe actualizar y no una por una porque entonces estaria contando 3 vulnerabilidades y
    no una sola». Ahora queda UNA orden por sistema y origen de paquete, con la version
    mas alta —comparada con el comparador de la distribucion, nunca por orden de texto— y
    la cola completa de versiones solicitadas en ``cola_versiones``, de la mas alta a la
    mas baja, para que la trazabilidad no se pierda.

    Cada grupo resultante lleva ``nombre`` (ver ``nombre_actualizacion``),
    ``versiones_pedidas`` (cuantas versiones distintas pidieron los avisos) y
    ``cola_versiones``. No toca la entrada.
    """
    salida: list = []
    indice: dict = {}
    colas: dict = {}
    for g in grupos or []:
        clave = (g.get("familia"), g.get("sistema"),
                 tuple(sorted(g.get("paquetes") or [])),
                 tuple(sorted(a.get("id") for a in (g.get("activos") or []))))
        version = (g.get("corregida") or "").strip()
        if clave in indice:
            destino = salida[indice[clave]]
            destino["cves"] = sorted(set(destino.get("cves") or []) | set(g.get("cves") or []))
            destino["avisos"] = sorted(set(destino.get("avisos") or []) | set(g.get("avisos") or []))
            destino["grupos_fusionados"] += int(g.get("grupos_fusionados") or 1)
            colas[clave] |= {version} if version else set()
            colas[clave] |= set(g.get("cola_versiones") or [])
            # La orden que queda es la de la version MAS ALTA: si la que llega ahora es
            # mayor, se queda con su version, su comando y su nota. Instalar la mas alta
            # resuelve tambien las anteriores, asi que una sola orden basta.
            actual = (destino.get("corregida") or "").strip()
            if version and (not actual
                            or comparar_versiones(g.get("familia"), version, actual) > 0):
                for campo in ("corregida", "comando", "nota"):
                    if g.get(campo) is not None:
                        destino[campo] = g.get(campo)
            continue
        copia = dict(g)
        copia["cves"] = sorted(set(copia.get("cves") or []))
        copia["avisos"] = sorted(set(copia.get("avisos") or []))
        # Se conserva el recuento que ya trajera el grupo: asi fusionar dos veces lo mismo
        # (``plan_remediacion`` ya lo hace y la plantilla lo repite tras recortar el plan
        # al alcance del perfil) no pierde el «de cuantos grupos sale esta orden».
        copia["grupos_fusionados"] = int(g.get("grupos_fusionados") or 1)
        indice[clave] = len(salida)
        colas[clave] = ({version} if version else set()) | set(copia.get("cola_versiones") or [])
        salida.append(copia)
    for clave, posicion in indice.items():
        g = salida[posicion]
        cola = ordenar_versiones(g.get("familia"), colas.get(clave) or set())
        g["cola_versiones"] = cola
        g["versiones_pedidas"] = len(cola)
        info = nombre_actualizacion(g.get("paquetes") or [])
        g["nombre"] = info["nombre"]
        g["es_fusion"] = info["otros"] > 0
    return salida


# --------------------------------------------------------------------------
# Acciones sobre una actualizacion entera (2026-09-08; fusion por origen 2026-09-09)
#
# Una sola actualizacion resuelve TODAS las vulnerabilidades de su grupo, asi que pedir la
# comprobacion de una en una serian 725 clics para una unica tarea en el peor equipo
# medido. Estas dos funciones aplican la accion a todo el grupo, pero por dentro llaman a
# ``comprobar`` y ``anotar`` una vez por fila: cada una deja su fila en
# ``remediacion_comprobaciones`` o ``remediacion_notas`` y su entrada de auditoria, de modo
# que la trazabilidad por CVE y paquete no se pierde y el veredicto lo sigue poniendo la
# plataforma. Desde el 2026-09-09 el grupo es la ACTUALIZACION FUSIONADA: todos los
# paquetes del activo con la misma firma que el de la remediacion recibida.
#
# No hay ruta nueva: la vista reutiliza /remediaciones/<id>/comprobar y /<id>/nota con un
# campo «alcance=grupo». Es a proposito: el mapa de rutas es lo que fija el alcance del
# perfil «Redes» y una ruta nueva lo ampliaria sin que nadie lo revisara.
# --------------------------------------------------------------------------
def _remediaciones_del_grupo(conn: sqlite3.Connection, remediacion_id: int) -> dict[str, Any]:
    """Datos de la actualizacion (activo y paquetes del mismo origen) de una remediacion.

    ``ids`` son las PENDIENTES de todos los paquetes con la misma firma en ese activo, que
    son las unicas sobre las que tiene sentido actuar. Si el paquete no tiene ninguna
    pendiente se devuelve la propia remediacion: la accion sigue siendo valida
    (documentar algo ya cerrado es legitimo) y nunca se actua sobre nada mas. La firma se
    calcula solo para ese activo: nunca se sale de el.
    """
    fila = conn.execute(
        """SELECT r.activo_id, r.paquete, r.estado, a.nombre AS activo_nombre, a.so_familia
             FROM remediaciones r JOIN activos a ON a.id = r.activo_id
            WHERE r.id = ?""", (remediacion_id,)).fetchone()
    if fila is None:
        raise ValueError("La remediación indicada no existe.")
    datos = dict(fila)
    # Ni la severidad baja ni el riesgo aceptado entran en el grupo (2026-09-10): el
    # grupo tiene que ser EXACTAMENTE el que la pagina ensena, o la accion de grupo
    # tocaria filas que nadie ve y el mensaje diria un numero de vulnerabilidades
    # distinto del de la fila.
    sin_bajas = _y_sin_bajas(conn)
    sin_excepcion = _y_sin_excepcion(conn)
    cte, params = _cte_firmas(solo_abiertas=True, activo_id=datos["activo_id"],
                              sin_bajas=bool(sin_bajas),
                              sin_excepcion=bool(sin_excepcion))
    firmas = {f["paquete"]: f["firma"] for f in conn.execute(
        f"{cte} SELECT paquete, firma FROM firmas", params)}
    propia = firmas.get(datos["paquete"])
    paquetes = sorted(p for p, f in firmas.items() if f == propia) if propia is not None \
        else [datos["paquete"]]
    marcas = ",".join("?" * len(paquetes))
    filas = conn.execute(
        f"""SELECT r.id, r.version_corregida FROM remediaciones r
             WHERE r.activo_id=? AND r.paquete IN ({marcas})
               AND r.estado='abierta'{sin_bajas}{sin_excepcion}
             ORDER BY r.paquete, r.id""", (datos["activo_id"], *paquetes)).fetchall()
    info = nombre_actualizacion(paquetes)
    datos["paquetes"] = paquetes
    datos["nombre"] = info["nombre"]
    datos["ids"] = [int(f["id"]) for f in filas] or [int(remediacion_id)]
    datos["cves"] = int(conn.execute(
        f"""SELECT COUNT(DISTINCT r.cve) FROM remediaciones r
             WHERE r.activo_id=? AND r.paquete IN ({marcas})
               AND r.estado='abierta'{sin_bajas}{sin_excepcion}""",
        (datos["activo_id"], *paquetes)).fetchone()[0] or 0) or 1
    datos["version_objetivo"] = version_objetivo(
        datos.get("so_familia"), [f["version_corregida"] for f in filas])
    return datos


#: Tope de filas de remediacion sobre las que actua UNA peticion de grupo. Sin tope, el
#: perfil de menor privilegio podia hacer crecer la base sin cota con notas de 2.000
#: caracteres por fila (revision de seguridad del 2026-09-08).
#:
#: El valor tiene que quedar POR ENCIMA del maximo real o el boton no sirve para nada:
#: medido sobre la base real el 2026-09-09, la actualizacion mayor tiene 1.358 filas
#: pendientes (un equipo Windows) y hay 8 actualizaciones por encima de 1.000, todas del
#: paquete «windows», de 8.881 en total. Con el tope anterior (1.000) esas ocho pintaban
#: el boton «Ya se actualizó: comprobar las 1.358» y la peticion SIEMPRE respondia con el
#: aviso del tope, y la alternativa que sugeria el mensaje eran 68 paginas de veinte
#: clics. Coste medido de la accion completa: 0,06 s en el modulo y 220 ms por HTTP para
#: un grupo de 797 filas. 2.000 deja margen (47 % sobre el maximo de hoy) sin renunciar a
#: la cota. Mientras exista el tope, las plantillas NO pintan el boton de grupo cuando las
#: filas pendientes lo superan: lo explican en la fila (``webui/templates/remediaciones.html``
#: y ``_remediaciones_activo.html``, con ``limite_accion_grupo`` en el contexto).
LIMITE_ACCION_GRUPO = 2000


def _grupo_acotado(grupo: dict[str, Any]) -> None:
    """Corta la accion de grupo si supera el tope (ver ``LIMITE_ACCION_GRUPO``).

    Se comprueba ANTES de escribir nada: o se hace la accion entera o no se hace ninguna
    parte, para que nadie quede con la mitad de un grupo comprobada y la otra no.
    """
    if len(grupo["ids"]) > LIMITE_ACCION_GRUPO:
        raise ValueError(
            f"La actualización de «{grupo['nombre']}» en {grupo['activo_nombre']} cubre "
            f"{len(grupo['ids'])} filas de remediación y el tope por petición es "
            f"{LIMITE_ACCION_GRUPO}. Actúe desde la ficha del activo, de una en una, o "
            f"espere a que la sincronización con OCS Inventory cierre las ya corregidas.")


def comprobar_grupo(conn: sqlite3.Connection, remediacion_id: int, *, solicitante: str,
                    ip: Optional[str] = None, cerrar: bool = True) -> dict[str, Any]:
    """Comprueba TODAS las filas pendientes de la misma actualizacion (activo y paquetes
    del mismo origen).

    Devuelve el recuento por veredicto y un ``veredicto`` de conjunto para el mensaje:
    «corregida» solo si TODAS lo estan, «sigue_vulnerable» si alguna sigue sin la version
    (que es lo que hay que ver), y «sin_datos» si no se pudo comprobar ninguna.
    ``total`` son filas de remediacion; ``cves`` y ``paquetes`` dicen cuantas
    vulnerabilidades distintas y cuantos paquetes son.
    """
    grupo = _remediaciones_del_grupo(conn, remediacion_id)
    _grupo_acotado(grupo)
    resultados = [comprobar(conn, rid, solicitante=solicitante, ip=ip, cerrar=cerrar)
                  for rid in grupo["ids"]]
    conteo: dict[str, int] = {}
    for r in resultados:
        conteo[r["veredicto"]] = conteo.get(r["veredicto"], 0) + 1
    resueltas = conteo.get("corregida", 0) + conteo.get("desinstalado", 0)
    if conteo.get("sigue_vulnerable"):
        veredicto = "sigue_vulnerable"
    elif resueltas == len(resultados):
        veredicto = "corregida"
    else:
        veredicto = "sin_datos"
    return {
        "activo_nombre": grupo["activo_nombre"],
        "paquete": grupo["paquete"],
        "paquetes": grupo["paquetes"],
        "nombre": grupo["nombre"],
        "cves": grupo["cves"],
        "version_objetivo": grupo["version_objetivo"],
        "total": len(resultados),
        "conteo": conteo,
        "resueltas": resueltas,
        "cerradas": sum(1 for r in resultados if r["cerrada"]),
        "veredicto": veredicto,
        "veredicto_es": VEREDICTO_ES.get(veredicto, veredicto),
        "clave": VEREDICTO_CLAVE.get(veredicto, "neutra"),
        "resultados": resultados,
    }


def _nota_repetida(conn: sqlite3.Connection, grupo: dict[str, Any], texto: str) -> bool:
    """Si esa misma nota ya esta escrita en alguna fila de esta actualizacion.

    Freno a la repeticion (revision de seguridad del 2026-09-09): sin el, el mismo envio
    reenviado N veces (una recarga, un doble clic, un guion) escribia N x 797 notas. Se
    compara el texto YA NORMALIZADO contra las notas del mismo activo y los paquetes de la
    fusion, que es lo que la persona esta viendo como «una nota de esta actualizacion».
    """
    marcas = ",".join("?" * len(grupo["paquetes"]))
    return conn.execute(
        f"""SELECT 1 FROM remediacion_notas n JOIN remediaciones r ON r.id = n.remediacion_id
             WHERE n.activo_id = ? AND r.paquete IN ({marcas}) AND n.texto = ? LIMIT 1""",
        (grupo["activo_id"], *grupo["paquetes"], texto)).fetchone() is not None


def anotar_grupo(conn: sqlite3.Connection, remediacion_id: int, *, autor: str, texto: str,
                 ip: Optional[str] = None) -> dict[str, Any]:
    """Guarda la MISMA nota en todas las filas pendientes de la actualizacion.

    Lo que se documenta («programado para la ventana del sabado, requiere reinicio») vale
    para la actualizacion completa, no para uno de sus veintinueve CVE ni para uno de sus
    cuatro paquetes. Escribirla en cada remediacion es lo que hace que la nota se vea
    despues tanto en la vista agrupada como en la ficha del activo, sin inventar una
    tabla nueva.

    Dos frenos de la revision de seguridad del 2026-09-09:

    * UNA sola entrada de auditoria por accion, con el recuento, el activo y los paquetes,
      en lugar de una por fila: con el perfil «Mantenimiento» un unico envio dejaba 797
      notas, 797 asientos de auditoria y 1,59 MB. El historial no se pierde: cada fila
      sigue teniendo su nota en ``remediacion_notas``, que es donde la leen la ficha del
      activo y la vista agrupada.
    * La MISMA nota sobre el MISMO grupo se rechaza si ya esta escrita, asi que reenviar
      el formulario no multiplica nada.
    """
    texto = normalizar_nota(texto)
    grupo = _remediaciones_del_grupo(conn, remediacion_id)
    _grupo_acotado(grupo)
    if _nota_repetida(conn, grupo, texto):
        raise ValueError(
            f"Esa misma nota ya está guardada en la actualización de «{grupo['nombre']}» "
            f"en {grupo['activo_nombre']}: no se duplica. Si hay algo nuevo que contar, "
            f"escríbalo con sus propias palabras.")
    ids = [anotar(conn, rid, autor=autor, texto=texto, ip=ip, auditar=False)
           for rid in grupo["ids"]]
    paquetes = ", ".join(grupo["paquetes"][:6])
    if len(grupo["paquetes"]) > 6:
        paquetes += f" y {len(grupo['paquetes']) - 6} paquetes más"
    db.audit(conn, autor, "remediacion.nota_grupo", "remediaciones", remediacion_id,
             f"«{grupo['nombre']}» en {grupo['activo_nombre']}: la misma nota en "
             f"{len(ids)} filas de remediación ({grupo['cves']} vulnerabilidades, "
             f"{len(grupo['paquetes'])} paquetes: {paquetes}): {texto[:160]}", ip)
    return {"activo_nombre": grupo["activo_nombre"], "paquete": grupo["paquete"],
            "paquetes": grupo["paquetes"], "nombre": grupo["nombre"], "cves": grupo["cves"],
            "total": len(ids), "notas_ids": ids}

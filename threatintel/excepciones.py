"""Excepciones con vencimiento: aceptación de riesgo con responsable y caducidad (2026-09-10).

Petición del usuario: «falta aceptar un riesgo con responsable, justificación y fecha de
caducidad, que es lo que pide una auditoría y lo que evita que algo quede olvidado». Hasta
hoy una vulnerabilidad solo podía marcarse como falso positivo o mitigada: ninguna de las
dos cosas tiene dueño ni caduca, así que lo que se «aceptaba» se quedaba aceptado para
siempre y sin nadie que respondiera por ello.

Qué hace una excepción vigente:

* **saca** la vulnerabilidad de la cola de trabajo (``remediaciones``) y de las cifras de
  riesgo (``aplicabilidad``), mediante la condición :func:`sql_sin_excepcion`;
* **no la borra ni la oculta**: sigue consultable en ``/excepciones/`` y en la ficha del
  activo, marcada como «riesgo aceptado hasta el 30 de noviembre de 2026»;
* **caduca sola**: la vigencia se CALCULA comparando ``vence_at`` con la fecha de hoy. No
  hay ningún proceso que «cierre» excepciones: si el cron dejara de ejecutarse, la
  vulnerabilidad volvería igualmente a la cola y a las cifras en cuanto pasara la fecha.
  El cálculo está escrito en UN solo sitio, :data:`SQL_VIGENTE` (y su espejo en Python,
  :func:`esta_vencida`, que ``tests/test_excepciones.py`` comprueba que coincide).

Por eso la columna ``estado`` solo guarda dos valores, ``vigente`` y ``revocada``; el
tercer estado que ve la persona, «vencida», es ``vigente`` con la fecha ya pasada.

Alcances admitidos (los tres, porque los tres se expresan con la misma condición y sin
coste añadido: ``aplicabilidad`` y ``remediaciones`` están indexadas por activo y por CVE):

    activo_cve       una vulnerabilidad concreta en un activo concreto
    cve              todas las de un CVE en toda la organización
    activo_paquete   todas las de un paquete en un activo (el caso «esta aplicación
                     heredada no se puede actualizar en este servidor»)

Explotación activa confirmada (KEV): NO se prohíbe, se advierte y se exige confirmación
explícita, medida compensatoria obligatoria y un plazo máximo de 30 días. Prohibirlo
llevaría la decisión fuera de la plataforma (a un correo o a una hoja de cálculo) y se
perdería justo lo que pide la auditoría: quién lo aceptó, por qué y hasta cuándo.

Excepciones PERMANENTES (2026-09-10, tarde)
-------------------------------------------
Petición del usuario: «en excepciones se debe agregar la opción de fecha permanente, ya
que no va a tener una fecha de vencimiento». El diseño de la mañana decía justo lo
contrario («nunca indefinida»); manda la decisión del usuario, pero su preocupación de
fondo —que nada quede olvidado— sigue siendo válida y se resuelve con otro mecanismo.

* Una permanente tiene ``permanente = 1`` y ``vence_at`` a NULL. Nunca se guarda una
  fecha lejana de mentira para simularlo: sería falso en la base y ensuciaría los avisos.
  Un CHECK del esquema impide que las dos columnas se contradigan.
* Está **siempre vigente**: no vence, no entra en el aviso de «vencen pronto» ni en el de
  «vencidas», y sus días restantes no son un número (``dias_restantes`` devuelve ``None``,
  y ``SQL_DIAS_RESTANTES`` devuelve NULL). Un «faltan 999 días» o un cero serían mentira.
* En lugar de caducar, se **revisa**: cada ``excepciones_revision_dias`` días (ajuste
  nuevo, 180 por omisión) desde el registro o desde la última revisión confirmada, entra
  en el correo de administración con su propio texto y la página ofrece «Confirmar la
  revisión», que deja constancia de quién y cuándo y reinicia el plazo. Es un
  RECORDATORIO, no un vencimiento: la excepción sigue vigente aunque nadie conteste, y
  tanto la pantalla como el correo lo dicen con esas palabras.
* Restricciones, con su porqué en :func:`validar` y en ``webui/vistas/excepciones.py``:
  solo la concede ``admin``, nunca se admite sobre una vulnerabilidad con explotación
  activa confirmada (CISA KEV) y la justificación exige más texto que en una temporal.
* No se puede prorrogar (no tiene plazo), sí revocar, y se convierte en temporal y al
  revés con :func:`convertir_en_temporal` y :func:`convertir_en_permanente`.
"""
from __future__ import annotations

import re
import sqlite3
from datetime import date, datetime, timedelta, timezone
from typing import Any, Iterable, Optional

from . import db
from .logging_setup import get_logger

log = get_logger("excepciones")

# --------------------------------------------------------------------------
# Vocabulario
# --------------------------------------------------------------------------
#: Alcances admitidos, en el orden en que se ofrecen en el formulario.
ALCANCES = ("activo_cve", "cve", "activo_paquete")

ALCANCE_ES = {
    "activo_cve": "Una vulnerabilidad en un activo",
    "cve": "Un CVE en toda la organización",
    "activo_paquete": "Un paquete en un activo",
}

#: Qué cubre cada alcance, en una frase para quien no conoce la herramienta.
ALCANCE_AYUDA = {
    "activo_cve": ("Acepta el riesgo de ese CVE solo en ese activo. Es el alcance más "
                   "estrecho y el que se debe usar salvo que haya una razón para otro."),
    "cve": ("Acepta el riesgo de ese CVE en todos los servidores y equipos de cómputo, "
            "incluidos los que se incorporen al inventario mientras esté vigente."),
    "activo_paquete": ("Acepta el riesgo de todas las vulnerabilidades de ese paquete en "
                       "ese activo, también las que aparezcan mientras esté vigente."),
}

#: Estados que se GUARDAN en la base. «vencida» no se guarda: se calcula.
ESTADOS_GUARDADOS = ("vigente", "revocada")

#: Estados que ve la persona (el filtro de la página admite además «por_vencer»).
ESTADOS = ("vigente", "vencida", "revocada")

ESTADO_ES = {
    "vigente": "Vigente",
    "vencida": "Vencida",
    "revocada": "Revocada",
}

#: Clase de la insignia de cada estado. El color solo con significado: ámbar para el
#: riesgo aceptado que sigue en pie (atención), rojo para el que venció y volvió a la
#: cola sin que nadie decidiera nada, gris para el que ya no aplica.
ESTADO_CLAVE = {"vigente": "medio", "vencida": "critico", "revocada": "neutra"}

ESTADO_EXPLICACION = {
    "vigente": ("El riesgo está aceptado y esta vulnerabilidad no aparece en la cola de "
                "trabajo ni en las cifras de riesgo hasta la fecha de vencimiento."),
    "vencida": ("Pasó la fecha de vencimiento: la vulnerabilidad ya volvió sola a la cola "
                "y a las cifras. Hay que corregirla, prorrogar la excepción o revocarla."),
    "revocada": ("Alguien retiró la aceptación del riesgo antes de la fecha: la "
                 "vulnerabilidad volvió a la cola y a las cifras en ese mismo momento."),
}

#: Situaciones que ofrece el filtro de la página. «permanente» y «revision» no son
#: estados: son dos formas de acotar entre las vigentes.
FILTROS_SITUACION = ("vigente", "por_vencer", "vencida", "permanente", "revision",
                     "revocada")

#: Qué significa que una excepción sea permanente, en las palabras que la página y el
#: correo repiten. Se escribe una sola vez para que las dos digan exactamente lo mismo.
PERMANENTE_EXPLICACION = (
    "El riesgo está aceptado sin fecha de vencimiento: esta excepción no caduca nunca y "
    "su vulnerabilidad no volverá sola a la cola de trabajo. Por eso hay que revisarla "
    "cada cierto tiempo y confirmar que sigue siendo válida, o revocarla.")

#: Lo que hay que dejar claro en pantalla y en el correo cuando el plazo de revisión ya
#: pasó: el recordatorio NO caduca la excepción.
REVISION_EXPLICACION = (
    "Pasó el plazo de revisión: nadie ha confirmado que este riesgo se siga aceptando. "
    "La excepción SIGUE VIGENTE y su vulnerabilidad sigue fuera de la cola y de las "
    "cifras aunque nadie conteste; esto es un recordatorio, no un vencimiento.")

#: Ajuste (tabla ``settings``) con los días de antelación del aviso, y su valor por
#: omisión mientras no esté en ``config.DEFAULT_SETTINGS``.
AJUSTE_AVISO_DIAS = "excepciones_aviso_dias"
AVISO_DIAS_DEFECTO = 15

#: Ajuste con cada cuántos días hay que revisar una excepción PERMANENTE, y su valor por
#: omisión. Es la salvaguarda contra el olvido que sustituye al vencimiento: una
#: permanente no caduca, pero pasado este plazo desde el registro o desde la última
#: revisión confirmada entra en el correo de administración hasta que alguien confirme
#: que sigue siendo válida o la revoque. Viene ACTIVADO por omisión, a propósito.
AJUSTE_REVISION_DIAS = "excepciones_revision_dias"
REVISION_DIAS_DEFECTO = 180
#: Rango admitido del ajuste anterior. Por debajo de treinta días el recordatorio sería
#: ruido (llegaría antes de que nada pudiera cambiar) y por encima de dos años dejaría de
#: ser una salvaguarda: una aceptación de riesgo sin mirar durante más de dos años es
#: exactamente el olvido que se quiere evitar.
REVISION_DIAS_MIN = 30
REVISION_DIAS_MAX = 730

#: Cómo se llama en pantalla y en los correos una excepción sin fecha de vencimiento.
#: Está aquí y no en cada plantilla para que las tres pantallas que la nombran (esta
#: página, la ficha del activo y el detalle de la amenaza) digan exactamente lo mismo.
TEXTO_PERMANENTE = "Permanente (sin fecha de vencimiento)"
#: La forma corta, para una insignia dentro de una tabla (``.insignia`` no parte líneas).
TEXTO_PERMANENTE_CORTO = "Permanente"

#: Plazo máximo de una excepción, en días, contados desde hoy. Una aceptación de riesgo a
#: más de un año no es una aceptación: es un abandono con papeles.
MAX_DIAS = 365
#: Plazo máximo cuando hay explotación activa confirmada (CISA KEV).
MAX_DIAS_KEV = 30

#: Longitudes de los campos de texto libre.
MIN_JUSTIFICACION = 20
#: Una excepción permanente no caduca nunca, así que su justificación es lo único que
#: quedará para explicarla dentro de tres años: se le exige el triple de texto que a una
#: temporal. No es burocracia: una temporal se corrige sola el día que vence y esta no.
MIN_JUSTIFICACION_PERMANENTE = 60
MAX_JUSTIFICACION = 2000
MAX_NOMBRE = 120
MAX_CORREO = 160
MAX_COMPENSACION = 1000
MAX_MOTIVO = 500

_RE_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_RE_CORREO = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
_RE_FECHA = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_RE_PAQUETE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:@/-]{0,119}$")

#: Veredicto de ``aplicabilidad`` que significa «este activo está afectado».
AFECTADO = "afectado"

#: Estados de ``threats`` en los que el analista ya cerró la amenaza: no cuentan en
#: ninguna cifra de riesgo del proyecto (mismo criterio que ``ocs._AMENAZA_VIVA``,
#: ``queries`` y ``parches``).
ESTADOS_CERRADOS = ("descartada", "falso_positivo", "mitigada")
ESTADOS_CERRADOS_SQL = "(" + ",".join("'" + e + "'" for e in ESTADOS_CERRADOS) + ")"


class ErrorExcepcion(ValueError):
    """Dato de entrada que no vale, con el mensaje que se le enseña a la persona."""


class AvisoKev(ErrorExcepcion):
    """Hay explotación activa confirmada y todavía no se ha confirmado por escrito.

    Lleva la lista de CVE en KEV para que la pantalla los nombre uno a uno.
    """

    def __init__(self, mensaje: str, cves: Iterable[str] = ()):
        super().__init__(mensaje)
        self.cves = list(cves)


# --------------------------------------------------------------------------
# El cálculo del vencimiento, en UN solo sitio
# --------------------------------------------------------------------------
#: Condición SQL que dice si la excepción ``e`` está vigente AHORA MISMO. Es la única
#: definición de «vigente» del proyecto: la usan la condición que saca las
#: vulnerabilidades de la cola y de las cifras, el listado, el resumen y el aviso.
#:
#: ``date('now')`` es la fecha en UTC. La empresa está en UTC-5, así que una excepción
#: deja de valer hasta cinco horas antes de la medianoche local de su último día. Se
#: acepta a propósito: el error va en la dirección segura (la vulnerabilidad vuelve antes
#: a la cola, nunca después) y evita depender de la zona horaria del servidor.
#:
#: Una excepción PERMANENTE (``permanente = 1``, ``vence_at`` a NULL) está vigente
#: siempre que no esté revocada: no hay fecha que comparar. Va primero en el OR para que
#: SQLite ni siquiera evalúe el ``substr`` sobre un NULL.
SQL_VIGENTE = ("(e.estado = 'vigente' "
               "AND (e.permanente = 1 OR date('now') <= substr(e.vence_at, 1, 10)))")

#: Expresión SQL con el estado efectivo de la excepción ``e`` («vigente», «vencida» o
#: «revocada»), derivada de la anterior. Ninguna consulta debe escribir esto a mano.
#: Una permanente nunca puede dar «vencida»: no vence. «Permanente» NO es un cuarto
#: estado, es una propiedad de la excepción (columna ``permanente``): mezclar las dos
#: cosas obligaría a preguntar «¿está vigente?» en dos sitios distintos.
SQL_ESTADO = ("CASE WHEN e.estado = 'revocada' THEN 'revocada' "
              "WHEN e.permanente = 1 THEN 'vigente' "
              "WHEN date('now') > substr(e.vence_at, 1, 10) THEN 'vencida' "
              "ELSE 'vigente' END")

#: Días que faltan para el vencimiento (negativo si ya venció) y **NULL si es
#: permanente**: una permanente no tiene días restantes, y devolver un número —un cero o
#: un «faltan 999 días»— sería mentira en pantalla y en el correo.
SQL_DIAS_RESTANTES = ("CASE WHEN e.permanente = 1 THEN NULL ELSE "
                      "CAST(julianday(substr(e.vence_at, 1, 10)) "
                      "- julianday(date('now')) AS INTEGER) END")

#: Desde cuándo se cuenta el plazo de revisión de una permanente: desde la última
#: revisión confirmada o, si nunca se ha revisado, desde el día en que se registró.
SQL_BASE_REVISION = "COALESCE(e.revisada_at, e.registrado_at)"

#: Días que lleva una excepción sin revisarse. Vale para cualquiera, pero solo significa
#: algo en las permanentes: las temporales ya tienen su fecha de vencimiento.
SQL_DIAS_SIN_REVISAR = (f"CAST(julianday(date('now')) "
                        f"- julianday(substr({SQL_BASE_REVISION}, 1, 10)) AS INTEGER)")


def sql_pendiente_revision(parametro: str = ":revision") -> str:
    """Condición SQL «esta permanente lleva demasiado tiempo sin revisarse».

    ``parametro`` es el marcador con el que la consulta pasa los días del ajuste. NO es
    un vencimiento: la excepción sigue vigente y sigue tapando su vulnerabilidad; lo
    único que ocurre es que entra en el recordatorio y la página la sube al principio.
    """
    return (f"(e.permanente = 1 AND e.estado = 'vigente' "
            f"AND {SQL_DIAS_SIN_REVISAR} >= {parametro})")


#: La forma de siempre, con el parámetro con nombre que usan ``_filtros`` y el listado.
SQL_PENDIENTE_REVISION = sql_pendiente_revision()


def hoy(ahora: Optional[datetime] = None) -> str:
    """La fecha de hoy en UTC, 'AAAA-MM-DD'. Espejo en Python de ``date('now')``."""
    momento = ahora or datetime.now(timezone.utc)
    if momento.tzinfo is not None:
        momento = momento.astimezone(timezone.utc)
    return momento.date().isoformat()


def esta_vencida(vence_at: Any, *, estado: str = "vigente", permanente: Any = False,
                 ahora: Optional[datetime] = None) -> bool:
    """Espejo en Python de :data:`SQL_VIGENTE`: True si la fecha ya pasó.

    Una excepción revocada no está «vencida»: está revocada, que es otro estado. Y una
    permanente tampoco: no tiene fecha que pasar.
    """
    if (estado or "").strip() == "revocada":
        return False
    if _es_permanente(permanente):
        return False
    return hoy(ahora) > str(vence_at or "")[:10]


def dias_restantes(vence_at: Any, *, permanente: Any = False,
                   ahora: Optional[datetime] = None) -> Optional[int]:
    """Días que faltan para el vencimiento; negativo si ya venció.

    Devuelve ``None`` cuando la excepción es permanente: no faltan días para nada, y un
    número (un cero, o los días hasta una fecha inventada) se acabaría enseñando en
    pantalla como si fuera cierto. Quien lo use tiene que decidir qué escribe cuando no
    hay número, que es justamente lo que se quiere obligar a pensar.
    """
    if _es_permanente(permanente):
        return None
    try:
        fin = date.fromisoformat(str(vence_at or "")[:10])
    except ValueError:
        return 0
    return (fin - date.fromisoformat(hoy(ahora))).days


def estado_efectivo(estado: Any, vence_at: Any, *, permanente: Any = False,
                    ahora: Optional[datetime] = None) -> str:
    """El estado que ve la persona: «vigente», «vencida» o «revocada».

    «Permanente» no es un estado: es una propiedad (:func:`es_permanente`). Una
    permanente no revocada siempre está «vigente».
    """
    guardado = (str(estado or "vigente")).strip()
    if guardado == "revocada":
        return "revocada"
    return ("vencida"
            if esta_vencida(vence_at, estado=guardado, permanente=permanente, ahora=ahora)
            else "vigente")


def _es_permanente(valor: Any) -> bool:
    """Interpreta la columna ``permanente`` y también el «1»/«on»/«sí» de un formulario."""
    if isinstance(valor, str):
        return valor.strip().lower() in ("1", "on", "true", "si", "sí", "permanente")
    return bool(valor)


#: Alias público del anterior: lo usan las vistas para leer una fila de la base.
es_permanente = _es_permanente


def dias_sin_revisar(fila: Any, *, ahora: Optional[datetime] = None) -> int:
    """Espejo en Python de :data:`SQL_DIAS_SIN_REVISAR`.

    ``fila`` es una excepción (diccionario o ``sqlite3.Row``): se cuenta desde la última
    revisión confirmada y, si nunca se revisó, desde el día en que se registró.
    """
    datos = dict(fila) if not isinstance(fila, dict) else fila
    base = str(datos.get("revisada_at") or datos.get("registrado_at") or "")[:10]
    try:
        desde = date.fromisoformat(base)
    except ValueError:
        return 0
    return (date.fromisoformat(hoy(ahora)) - desde).days


def necesita_revision(fila: Any, revision_dias: int,
                      *, ahora: Optional[datetime] = None) -> bool:
    """Si esa permanente lleva ya el plazo entero sin que nadie confirme que sigue valiendo.

    Espejo en Python de :func:`sql_pendiente_revision`. Que devuelva True NO significa
    que la excepción haya caducado: sigue vigente y sigue tapando su vulnerabilidad. Solo
    significa que hay que mirarla.
    """
    datos = dict(fila) if not isinstance(fila, dict) else fila
    if not _es_permanente(datos.get("permanente")):
        return False
    if str(datos.get("estado_guardado") or datos.get("estado") or "vigente") == "revocada":
        return False
    return dias_sin_revisar(datos, ahora=ahora) >= int(revision_dias)


def fecha_maxima(*, kev: bool = False, ahora: Optional[datetime] = None) -> str:
    """La fecha de vencimiento más lejana que se admite hoy, 'AAAA-MM-DD'."""
    tope = MAX_DIAS_KEV if kev else MAX_DIAS
    return (date.fromisoformat(hoy(ahora)) + timedelta(days=tope)).isoformat()


# --------------------------------------------------------------------------
# La condición que saca las vulnerabilidades cubiertas de la cola y de las cifras
# --------------------------------------------------------------------------
def sql_sin_excepcion(*, activo: str = "ap.activo_id", cve: str = "ap.cve",
                      paquete: Optional[str] = "ap.paquete") -> str:
    """Condición SQL «esta fila NO está cubierta por una excepción vigente».

    Se pega con ``AND`` al ``WHERE`` de cualquier consulta que cuente o liste
    vulnerabilidades. ``activo``, ``cve`` y ``paquete`` son los nombres de las columnas en
    esa consulta (por ejemplo ``r.activo_id``, ``r.cve``, ``r.paquete`` para la cola de
    remediación); ``paquete=None`` deja fuera el alcance por paquete, para las consultas
    que no tienen esa columna.

    Se escribe con tres ``NOT IN`` sobre subconsultas NO correlacionadas, y no con un
    ``NOT EXISTS`` correlacionado, a propósito: SQLite materializa cada subconsulta una
    sola vez en un índice temporal, así que el coste no crece con las 179.429 filas de
    ``aplicabilidad`` ni con las 66.326 de ``remediaciones``. Las subconsultas descartan
    los valores nulos (``IS NOT NULL``) porque un solo NULL dentro de un ``NOT IN`` haría
    que la condición no fuese cierta para NINGUNA fila y vaciaría la página entera.
    """
    partes = [
        f"({activo} || char(31) || {cve}) NOT IN ("
        f"SELECT e.activo_id || char(31) || e.cve FROM excepciones e "
        f"WHERE e.alcance = 'activo_cve' AND e.activo_id IS NOT NULL AND e.cve IS NOT NULL "
        f"AND {SQL_VIGENTE})",
        f"{cve} NOT IN ("
        f"SELECT e.cve FROM excepciones e "
        f"WHERE e.alcance = 'cve' AND e.cve IS NOT NULL AND {SQL_VIGENTE})",
    ]
    if paquete:
        partes.append(
            f"({activo} || char(31) || {paquete}) NOT IN ("
            f"SELECT e.activo_id || char(31) || e.paquete FROM excepciones e "
            f"WHERE e.alcance = 'activo_paquete' AND e.activo_id IS NOT NULL "
            f"AND e.paquete IS NOT NULL AND {SQL_VIGENTE})")
    return "(" + " AND ".join(partes) + ")"


#: Filas de ``aplicabilidad ap`` que PODRÍAN estar cubiertas por una excepción vigente:
#: las de un activo nombrado por alguna excepción (alcances «un CVE en un activo» y «un
#: paquete en un activo») y las de un CVE aceptado en toda la organización. Sirve para no
#: recorrer las 179.429 filas de la tabla cuando solo hacen falta unas pocas: las dos
#: subconsultas van por ``idx_aplic_activo`` y por ``idx_aplic_cve``. Es una condición
#: NECESARIA, no suficiente: quien decide sigue siendo
#: :data:`SQL_SIN_EXCEPCION_APLICABILIDAD`.
SQL_CANDIDATAS = (
    f"(ap.activo_id IN (SELECT e.activo_id FROM excepciones e "
    f"WHERE e.alcance IN ('activo_cve','activo_paquete') AND e.activo_id IS NOT NULL "
    f"AND {SQL_VIGENTE}) "
    f"OR ap.cve IN (SELECT e.cve FROM excepciones e WHERE e.alcance = 'cve' "
    f"AND e.cve IS NOT NULL AND {SQL_VIGENTE}))")

#: Las dos formas de siempre, ya escritas: para ``aplicabilidad ap`` (cifras de riesgo) y
#: para ``remediaciones r`` (cola de trabajo).
SQL_SIN_EXCEPCION_APLICABILIDAD = sql_sin_excepcion()
SQL_SIN_EXCEPCION_REMEDIACION = sql_sin_excepcion(activo="r.activo_id", cve="r.cve",
                                                  paquete="r.paquete")


def hay_excepciones(conn: sqlite3.Connection) -> bool:
    """Si hay al menos una excepción vigente. Sirve para no pegar la condición cuando no
    hay ninguna (el caso normal hoy) y dejar las consultas exactamente como estaban."""
    fila = conn.execute(
        f"SELECT 1 FROM excepciones e WHERE {SQL_VIGENTE} LIMIT 1").fetchone()
    return fila is not None


def y_sin_excepcion(conn: sqlite3.Connection, **columnas: Optional[str]) -> str:
    """« AND <condición>» para pegar a un WHERE, o cadena vacía si no hay ninguna vigente.

    Mismo patrón que ``remediacion._y_sin_bajas``: quien llama no tiene que acordarse de
    comprobar nada. Cuesta una consulta por índice sobre una tabla de decenas de filas.
    """
    return f" AND {sql_sin_excepcion(**columnas)}" if hay_excepciones(conn) else ""


# --------------------------------------------------------------------------
# Validación
# --------------------------------------------------------------------------
def _texto(valor: Any, maximo: int) -> str:
    return re.sub(r"\s+", " ", str(valor or "").strip())[:maximo].strip()


def _multilinea(valor: Any, maximo: int) -> str:
    """Recorta y normaliza un texto largo conservando los saltos de línea."""
    texto = str(valor or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    texto = re.sub(r"[ \t]{2,}", " ", texto)
    texto = re.sub(r"\n{3,}", "\n\n", texto)
    return texto[:maximo].strip()


def normalizar_cve(valor: Any) -> str:
    return _texto(valor, 30).upper()


def normalizar_paquete(valor: Any) -> str:
    """Los nombres de paquete se guardan en minúsculas en ``aplicabilidad`` y en
    ``remediaciones``; aquí se normaliza igual para que la comparación sea exacta."""
    return _texto(valor, 120).lower()


def cves_en_kev(conn: sqlite3.Connection, *, alcance: str, activo_id: Optional[int],
                cve: str, paquete: str) -> list[str]:
    """Los CVE del alcance con explotación activa confirmada por CISA (KEV).

    Para un alcance por paquete se miran las vulnerabilidades que ese paquete tiene
    confirmadas hoy en ese activo: aceptar el paquete entero es aceptar también las suyas.
    """
    if alcance in ("activo_cve", "cve"):
        filas = conn.execute(
            "SELECT DISTINCT cve FROM threats WHERE cve = ? AND in_kev = 1", (cve,)).fetchall()
    else:
        filas = conn.execute(
            """SELECT DISTINCT t.cve FROM aplicabilidad ap
                 JOIN threats t ON t.id = ap.threat_id
                WHERE ap.activo_id = ? AND ap.paquete = ? AND ap.veredicto = ?
                  AND t.in_kev = 1 AND t.cve IS NOT NULL""",
            (activo_id, paquete, AFECTADO)).fetchall()
    return sorted({str(f[0]) for f in filas if f[0]})


def _activo(conn: sqlite3.Connection, activo_id: Any) -> sqlite3.Row:
    try:
        numero = int(activo_id)
    except (TypeError, ValueError):
        raise ErrorExcepcion("Elija el activo al que se aplica la excepción.") from None
    fila = conn.execute(
        "SELECT id, nombre, origen, proceso, entorno, presente FROM activos WHERE id = ?",
        (numero,)).fetchone()
    if fila is None:
        raise ErrorExcepcion("Ese activo no existe en el inventario.")
    return fila


def _validar_fecha(valor: Any, *, kev: bool, ahora: Optional[datetime] = None) -> str:
    texto = _texto(valor, 10)
    if not texto:
        raise ErrorExcepcion(
            f"Escriba la fecha de vencimiento, o elija «{TEXTO_PERMANENTE}» si el riesgo "
            f"se acepta sin plazo. Una excepción con plazo no puede quedarse sin fecha.")
    if not _RE_FECHA.match(texto):
        raise ErrorExcepcion("La fecha de vencimiento debe tener el formato año-mes-día, "
                             "por ejemplo 2026-11-30.")
    try:
        fin = date.fromisoformat(texto)
    except ValueError:
        raise ErrorExcepcion("Esa fecha de vencimiento no existe en el calendario.") from None
    if texto <= hoy(ahora):
        raise ErrorExcepcion("La fecha de vencimiento tiene que ser posterior a hoy: una "
                             "excepción que nace vencida no acepta ningún riesgo.")
    tope = fecha_maxima(kev=kev, ahora=ahora)
    if texto > tope:
        limite = MAX_DIAS_KEV if kev else MAX_DIAS
        motivo = (" Con explotación activa confirmada el plazo máximo es más corto"
                  if kev else "")
        raise ErrorExcepcion(f"El plazo máximo es de {limite} días, es decir hasta el {tope}."
                             f"{motivo}. Para mantenerla más tiempo se prorroga, y así queda "
                             f"constancia de cada prórroga.")
    return fin.isoformat()


def validar(conn: sqlite3.Connection, *, alcance: Any, activo_id: Any = None,
            cve: Any = "", paquete: Any = "", justificacion: Any = "",
            responsable_nombre: Any = "", responsable_correo: Any = "",
            compensacion: Any = "", vence_at: Any = "", permanente: Any = False,
            confirmar_kev: bool = False,
            ahora: Optional[datetime] = None) -> dict[str, Any]:
    """Comprueba y normaliza los datos de una excepción. Lanza :class:`ErrorExcepcion`.

    Devuelve el diccionario listo para :func:`crear`, con ``kev`` y ``cves_kev`` ya
    resueltos, y con ``vence_at`` a ``None`` cuando ``permanente`` es cierto.

    Reglas propias de una excepción permanente (2026-09-10), con su porqué:

    * **nunca sobre una vulnerabilidad con explotación activa confirmada (CISA KEV)**.
      Es la única prohibición dura del módulo, y va aquí —en el modelo— y no solo en la
      pantalla, para que ninguna ruta futura pueda saltársela. En una temporal la
      explotación activa se advierte y se admite por treinta días como máximo porque el
      plazo corto es la garantía; sin plazo no queda ninguna garantía, y aceptar para
      siempre un fallo que se está explotando hoy no es aceptar un riesgo: es renunciar.
      Quien de verdad no pueda corregirlo registra una temporal de treinta días y la
      prorroga, que deja constancia cada vez.
    * **justificación de al menos :data:`MIN_JUSTIFICACION_PERMANENTE` caracteres**: una
      temporal se corrige sola el día que vence; esta no, y su texto es lo único que
      leerá quien la audite dentro de tres años.
    * **quién puede concederla** (solo ``admin``) NO se comprueba aquí: los roles son de
      la capa web (``webui/vistas/excepciones.py``, ``ROLES_PERMANENTE``), que es donde
      hay sesión. Este módulo no conoce usuarios, solo el ``actor`` que se le pasa.
    """
    alcance = _texto(alcance, 20)
    if alcance not in ALCANCES:
        raise ErrorExcepcion("Elija a qué se aplica la excepción.")
    es_perm = _es_permanente(permanente)

    fila_activo = None
    activo_final: Optional[int] = None
    cve_final = ""
    paquete_final = ""

    if alcance in ("activo_cve", "activo_paquete"):
        fila_activo = _activo(conn, activo_id)
        activo_final = int(fila_activo["id"])

    if alcance in ("activo_cve", "cve"):
        cve_final = normalizar_cve(cve)
        if not _RE_CVE.match(cve_final):
            raise ErrorExcepcion("Escriba un identificador CVE válido, por ejemplo CVE-2026-20348.")
        conocido = conn.execute(
            "SELECT 1 FROM threats WHERE cve = ? LIMIT 1", (cve_final,)).fetchone()
        if conocido is None:
            visto = conn.execute(
                "SELECT 1 FROM aplicabilidad WHERE cve = ? LIMIT 1", (cve_final,)).fetchone()
            if visto is None:
                raise ErrorExcepcion(f"{cve_final} no figura en el catálogo de amenazas ni en "
                                     f"ninguna evaluación de activos. Compruebe el "
                                     f"identificador antes de aceptar el riesgo.")
        if alcance == "activo_cve":
            afecta = conn.execute(
                "SELECT 1 FROM aplicabilidad WHERE activo_id = ? AND cve = ? LIMIT 1",
                (activo_final, cve_final)).fetchone()
            if afecta is None:
                raise ErrorExcepcion(
                    f"La plataforma no ha evaluado {cve_final} contra «{fila_activo['nombre']}», "
                    f"así que no hay ningún riesgo que aceptar en ese activo. Revise la ficha "
                    f"del activo o acepte el riesgo del CVE en toda la organización.")

    if alcance == "activo_paquete":
        paquete_final = normalizar_paquete(paquete)
        if not paquete_final or not _RE_PAQUETE.match(paquete_final):
            raise ErrorExcepcion("Escriba el nombre del paquete tal como aparece en la ficha "
                                 "del activo, por ejemplo «openssl».")
        existe = conn.execute(
            """SELECT 1 FROM aplicabilidad WHERE activo_id = ? AND paquete = ?
                UNION ALL
               SELECT 1 FROM activo_software WHERE activo_id = ? AND nombre_norm = ?
               LIMIT 1""",
            (activo_final, paquete_final, activo_final, paquete_final)).fetchone()
        if existe is None:
            raise ErrorExcepcion(
                f"En «{fila_activo['nombre']}» no hay ningún paquete llamado "
                f"«{paquete_final}» según OCS Inventory ni ninguna vulnerabilidad evaluada "
                f"con ese nombre. Compruebe el nombre en la ficha del activo.")

    justificacion_final = _multilinea(justificacion, MAX_JUSTIFICACION)
    minimo = MIN_JUSTIFICACION_PERMANENTE if es_perm else MIN_JUSTIFICACION
    if len(justificacion_final) < minimo:
        if es_perm:
            raise ErrorExcepcion(
                f"Una excepción permanente no caduca nunca, así que su justificación "
                f"tiene que sostenerse sola: explique por qué el riesgo se acepta sin "
                f"plazo y qué tendría que cambiar para revocarla, con al menos "
                f"{MIN_JUSTIFICACION_PERMANENTE} caracteres (lleva "
                f"{len(justificacion_final)}).")
        raise ErrorExcepcion(f"Explique por qué se acepta el riesgo, con al menos "
                             f"{MIN_JUSTIFICACION} caracteres. Es lo que leerá la auditoría.")

    nombre_final = _texto(responsable_nombre, MAX_NOMBRE)
    if len(nombre_final) < 5 or " " not in nombre_final:
        raise ErrorExcepcion("Escriba el nombre y el apellido de la persona que acepta el "
                             "riesgo. No vale una cuenta de la plataforma ni un área.")
    correo_final = _texto(responsable_correo, MAX_CORREO).lower()
    if not _RE_CORREO.match(correo_final):
        raise ErrorExcepcion("Escriba un correo electrónico válido de la persona que acepta "
                             "el riesgo, por ejemplo nombre.apellido@ejemplo.local.")

    compensacion_final = _multilinea(compensacion, MAX_COMPENSACION)

    cves_kev = cves_en_kev(conn, alcance=alcance, activo_id=activo_final,
                           cve=cve_final, paquete=paquete_final)
    kev = bool(cves_kev)
    if es_perm and kev:
        raise ErrorExcepcion(_mensaje_kev_permanente(cves_kev))
    vence_final = None if es_perm else _validar_fecha(vence_at, kev=kev, ahora=ahora)

    if kev and not confirmar_kev:
        lista = ", ".join(cves_kev)
        raise AvisoKev(
            f"Explotación activa confirmada por CISA en {lista}. Hay atacantes usando esta "
            f"vulnerabilidad ahora mismo: aceptar el riesgo no la hace desaparecer y solo se "
            f"admite con una medida compensatoria y por un plazo máximo de {MAX_DIAS_KEV} "
            f"días. Marque la casilla de confirmación para registrarla igualmente.", cves_kev)
    if kev and not compensacion_final:
        raise ErrorExcepcion("Con explotación activa confirmada la medida compensatoria es "
                             "obligatoria: escriba qué se ha hecho para contener el riesgo "
                             "mientras la excepción esté vigente.")

    return {"alcance": alcance, "activo_id": activo_final, "cve": cve_final or None,
            "paquete": paquete_final or None, "justificacion": justificacion_final,
            "responsable_nombre": nombre_final, "responsable_correo": correo_final,
            "compensacion": compensacion_final or None, "vence_at": vence_final,
            "permanente": int(es_perm),
            "kev": int(kev), "cves_kev": cves_kev,
            "activo_nombre": fila_activo["nombre"] if fila_activo is not None else None,
            "activo_origen": fila_activo["origen"] if fila_activo is not None else None}


def _mensaje_kev_permanente(cves: Iterable[str]) -> str:
    """El texto del único veto duro del módulo, en un solo sitio.

    Lo usan el alta (:func:`validar`) y la conversión de temporal a permanente
    (:func:`convertir_en_permanente`), que vuelve a mirar la explotación activa EN ESE
    MOMENTO: un CVE puede entrar en el catálogo de CISA meses después de aceptarse el
    riesgo, y entonces la excepción ya no puede volverse permanente.
    """
    lista = ", ".join(cves)
    return (f"Explotación activa confirmada por CISA en {lista}: una vulnerabilidad que "
            f"se está explotando ahora mismo no se acepta de forma permanente en ningún "
            f"caso. Registre una excepción con fecha, de {MAX_DIAS_KEV} días como máximo "
            f"y con una medida compensatoria descrita; si al vencer sigue sin poder "
            f"corregirse, se prorroga y queda constancia de cada prórroga.")


def descripcion(fila: Any) -> str:
    """Qué cubre la excepción, en una frase («CVE-2026-1 en el servidor X»)."""
    datos = dict(fila)
    alcance = datos.get("alcance")
    activo = datos.get("activo_nombre") or (f"el activo {datos.get('activo_id')}"
                                            if datos.get("activo_id") else "")
    if alcance == "cve":
        return f"{datos.get('cve')} en toda la organización"
    if alcance == "activo_paquete":
        return f"el paquete {datos.get('paquete')} en {activo}"
    return f"{datos.get('cve')} en {activo}"


# --------------------------------------------------------------------------
# Escritura
# --------------------------------------------------------------------------
def _auditar(conn: sqlite3.Connection, actor: Optional[str], accion: str,
             excepcion_id: int, detalle: str, ip: Optional[str]) -> None:
    db.audit(conn, actor, accion, "excepciones", excepcion_id, detalle[:900], ip)


def crear(conn: sqlite3.Connection, *, actor: str, ip: Optional[str] = None,
          ahora: Optional[datetime] = None, **datos: Any) -> dict[str, Any]:
    """Registra una excepción ya validada por :func:`validar` (o valida aquí mismo).

    ``actor`` es el usuario de la plataforma que la registra, que NO es el responsable que
    acepta el riesgo: son dos personas distintas y la auditoría necesita las dos.
    """
    if "cves_kev" not in datos:
        datos = validar(conn, ahora=ahora, **datos)
    momento = db.utcnow()
    duplicada = conn.execute(
        """SELECT id, vence_at, permanente, estado FROM excepciones
            WHERE alcance = ? AND COALESCE(activo_id, -1) = COALESCE(?, -1)
              AND COALESCE(cve, '') = COALESCE(?, '') AND COALESCE(paquete, '') = COALESCE(?, '')
              AND estado <> 'revocada'""",
        (datos["alcance"], datos["activo_id"], datos["cve"], datos["paquete"])).fetchone()
    if duplicada is not None:
        estado = estado_efectivo(duplicada["estado"], duplicada["vence_at"],
                                 permanente=duplicada["permanente"], ahora=ahora)
        plazo = ("es permanente, sin fecha de vencimiento" if duplicada["permanente"]
                 else f"vence el {duplicada['vence_at']}")
        raise ErrorExcepcion(
            f"Ya hay una excepción {ESTADO_ES[estado].lower()} para {descripcion(datos)} "
            f"({plazo}). Prorróguela o revóquela: no se pueden "
            f"tener dos excepciones sobre lo mismo.")
    permanente = int(_es_permanente(datos.get("permanente")))
    cursor = conn.execute(
        """INSERT INTO excepciones(alcance, activo_id, cve, paquete, justificacion,
                                   responsable_nombre, responsable_correo, compensacion,
                                   registrado_por, registrado_at, vence_at, vence_at_inicial,
                                   permanente, estado, kev)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'vigente',?)""",
        (datos["alcance"], datos["activo_id"], datos["cve"], datos["paquete"],
         datos["justificacion"], datos["responsable_nombre"], datos["responsable_correo"],
         datos["compensacion"], actor, momento, datos["vence_at"], datos["vence_at"],
         permanente, datos["kev"]))
    excepcion_id = int(cursor.lastrowid)
    _auditar(conn, actor, "excepciones.crear", excepcion_id,
             f"alcance={datos['alcance']} activo_id={datos['activo_id']} cve={datos['cve']} "
             f"paquete={datos['paquete']} "
             f"vence_at={'permanente' if permanente else datos['vence_at']} "
             f"permanente={permanente} "
             f"responsable={datos['responsable_nombre']} <{datos['responsable_correo']}> "
             f"kev={datos['kev']}", ip)
    log.info("excepcion registrada", extra={"id": excepcion_id, "alcance": datos["alcance"],
                                            "vence_at": datos["vence_at"],
                                            "permanente": permanente, "kev": datos["kev"]})
    return obtener(conn, excepcion_id) or {}


def prorrogar(conn: sqlite3.Connection, excepcion_id: int, *, vence_at: Any, motivo: Any,
              actor: str, ip: Optional[str] = None,
              ahora: Optional[datetime] = None) -> dict[str, Any]:
    """Amplía la fecha de vencimiento. La fecha nueva vuelve a pasar por las mismas reglas."""
    fila = obtener(conn, excepcion_id)
    if fila is None:
        raise ErrorExcepcion("Esa excepción no existe.")
    if fila["estado"] == "revocada":
        raise ErrorExcepcion("Esa excepción está revocada: no se puede prorrogar. Registre "
                             "una nueva si hay que volver a aceptar el riesgo.")
    if fila["permanente"]:
        # Prorrogar es «correr la fecha»; sin fecha no hay nada que correr. Lo que sí se
        # puede es ponerle una (convertir_en_temporal) o revocarla.
        raise ErrorExcepcion(
            "Esa excepción es permanente: no tiene fecha de vencimiento, así que no hay "
            "nada que prorrogar. Si hay que ponerle un plazo, use «Convertir en temporal» "
            "y escriba la fecha; si ya no hace falta, revóquela.")
    nueva = _validar_fecha(vence_at, kev=bool(fila["kev"]), ahora=ahora)
    if nueva <= str(fila["vence_at"])[:10]:
        raise ErrorExcepcion(f"La prórroga tiene que ir más allá del {fila['vence_at']}, que es "
                             f"la fecha que ya tiene. Para acortarla, revóquela y registre otra.")
    razon = _multilinea(motivo, MAX_MOTIVO)
    if len(razon) < MIN_JUSTIFICACION:
        raise ErrorExcepcion(f"Explique por qué se prorroga, con al menos {MIN_JUSTIFICACION} "
                             f"caracteres. Una prórroga sin motivo es lo que convierte una "
                             f"excepción en un olvido.")
    anterior = fila["vence_at"]
    conn.execute(
        """UPDATE excepciones SET vence_at = ?, prorrogas = prorrogas + 1, prorrogada_at = ?,
                                  prorrogada_por = ?, prorroga_motivo = ?, avisado_at = NULL
            WHERE id = ?""",
        (nueva, db.utcnow(), actor, razon, int(excepcion_id)))
    _auditar(conn, actor, "excepciones.prorrogar", int(excepcion_id),
             f"vence_at {anterior} -> {nueva} motivo={razon}", ip)
    log.info("excepcion prorrogada", extra={"id": int(excepcion_id), "antes": anterior,
                                            "ahora": nueva})
    return obtener(conn, excepcion_id) or {}


def revocar(conn: sqlite3.Connection, excepcion_id: int, *, motivo: Any, actor: str,
            ip: Optional[str] = None) -> dict[str, Any]:
    """Retira la aceptación del riesgo: la vulnerabilidad vuelve a la cola en el acto."""
    fila = obtener(conn, excepcion_id)
    if fila is None:
        raise ErrorExcepcion("Esa excepción no existe.")
    if fila["estado"] == "revocada":
        raise ErrorExcepcion("Esa excepción ya estaba revocada.")
    razon = _multilinea(motivo, MAX_MOTIVO)
    if len(razon) < MIN_JUSTIFICACION:
        raise ErrorExcepcion(f"Explique por qué se revoca, con al menos {MIN_JUSTIFICACION} "
                             f"caracteres: queda en el registro de auditoría.")
    conn.execute(
        """UPDATE excepciones SET estado = 'revocada', revocada_at = ?, revocada_por = ?,
                                  revocada_motivo = ? WHERE id = ?""",
        (db.utcnow(), actor, razon, int(excepcion_id)))
    _auditar(conn, actor, "excepciones.revocar", int(excepcion_id),
             f"vence_at={'permanente' if fila['permanente'] else fila['vence_at']} "
             f"motivo={razon}", ip)
    log.info("excepcion revocada", extra={"id": int(excepcion_id)})
    return obtener(conn, excepcion_id) or {}


# --------------------------------------------------------------------------
# Excepciones permanentes: revisión periódica y conversiones (2026-09-10)
# --------------------------------------------------------------------------
def confirmar_revision(conn: sqlite3.Connection, excepcion_id: int, *, actor: str,
                       nota: Any = "", ip: Optional[str] = None,
                       ahora: Optional[datetime] = None) -> dict[str, Any]:
    """Deja constancia de que alguien ha mirado la permanente y sigue siendo válida.

    Reinicia el plazo del recordatorio: a partir de hoy vuelven a contar los
    ``excepciones_revision_dias`` del ajuste. NO cambia la vigencia (la excepción estaba
    y sigue vigente) ni la vulnerabilidad que tapa; lo único que hace es callar el
    recordatorio y anotar quién respondió y cuándo.

    La nota es **opcional** a propósito. La evidencia que pide la auditoría es quién y
    cuándo, y eso queda siempre; exigir un texto largo cada seis meses para decir «sigue
    igual» conseguiría que nadie confirmara nunca y que el recordatorio se convirtiera en
    correo de fondo, que es exactamente lo que se quiere evitar. Cuando hay algo que
    contar, la nota se guarda y la página la enseña.
    """
    fila = obtener(conn, excepcion_id)
    if fila is None:
        raise ErrorExcepcion("Esa excepción no existe.")
    if fila["estado"] == "revocada":
        raise ErrorExcepcion("Esa excepción está revocada: no hay nada que revisar.")
    if not fila["permanente"]:
        raise ErrorExcepcion(
            "Solo se revisan las excepciones permanentes: una excepción con fecha ya "
            "tiene su vencimiento, y al llegar la fecha la vulnerabilidad vuelve sola.")
    texto = _multilinea(nota, MAX_MOTIVO)
    momento = (ahora or datetime.now(timezone.utc)).replace(microsecond=0).isoformat(
        ).replace("+00:00", "Z")
    conn.execute(
        """UPDATE excepciones SET revisada_at = ?, revisada_por = ?, revisada_nota = ?,
                                  revisiones = revisiones + 1, revision_avisada_at = NULL
            WHERE id = ?""",
        (momento, actor, texto or None, int(excepcion_id)))
    _auditar(conn, actor, "excepciones.revisar", int(excepcion_id),
             f"revision confirmada; llevaba {dias_sin_revisar(fila, ahora=ahora)} dias sin "
             f"revisarse; nota={texto or '(sin nota)'}", ip)
    log.info("revision de excepcion permanente confirmada",
             extra={"id": int(excepcion_id), "actor": actor})
    return obtener(conn, excepcion_id) or {}


def convertir_en_permanente(conn: sqlite3.Connection, excepcion_id: int, *, motivo: Any,
                            actor: str, ip: Optional[str] = None,
                            ahora: Optional[datetime] = None) -> dict[str, Any]:
    """Quita la fecha de vencimiento: el riesgo pasa a estar aceptado sin plazo.

    Se vuelve a mirar la explotación activa **en este momento** y no el valor guardado
    en la columna ``kev``: un CVE puede entrar en el catálogo de CISA meses después de
    registrarse la excepción, y una vulnerabilidad que se explota hoy no puede quedar
    aceptada para siempre (:func:`_mensaje_kev_permanente`).

    El motivo se exige tan largo como la justificación de una permanente: es la
    justificación de que el riesgo se acepta ya sin plazo, y es lo que leerá la
    auditoría junto a la justificación original, que no se toca.

    La conversión cuenta como revisión (``revisada_at`` de hoy): alguien acaba de mirar
    esta excepción y ha decidido, así que empezar el plazo de revisión desde su fecha de
    registro —que puede ser de hace un año— haría saltar el recordatorio el mismo día.
    """
    fila = obtener(conn, excepcion_id)
    if fila is None:
        raise ErrorExcepcion("Esa excepción no existe.")
    if fila["estado"] == "revocada":
        raise ErrorExcepcion("Esa excepción está revocada: no se puede convertir en "
                             "permanente. Registre una nueva si hay que aceptar el riesgo.")
    if fila["permanente"]:
        raise ErrorExcepcion("Esa excepción ya es permanente.")
    cves_kev = cves_en_kev(conn, alcance=fila["alcance"], activo_id=fila["activo_id"],
                           cve=fila["cve"] or "", paquete=fila["paquete"] or "")
    if cves_kev:
        raise ErrorExcepcion(_mensaje_kev_permanente(cves_kev))
    razon = _multilinea(motivo, MAX_MOTIVO)
    if len(razon) < MIN_JUSTIFICACION_PERMANENTE:
        raise ErrorExcepcion(
            f"Explique por qué el riesgo pasa a aceptarse sin ninguna fecha de "
            f"vencimiento y qué tendría que cambiar para revocarlo, con al menos "
            f"{MIN_JUSTIFICACION_PERMANENTE} caracteres (lleva {len(razon)}). Es lo que "
            f"quedará para justificarla dentro de tres años.")
    anterior = fila["vence_at"]
    momento = (ahora or datetime.now(timezone.utc)).replace(microsecond=0).isoformat(
        ).replace("+00:00", "Z")
    conn.execute(
        """UPDATE excepciones SET permanente = 1, vence_at = NULL, avisado_at = NULL,
                                  revisada_at = ?, revisada_por = ?, revisada_nota = ?,
                                  revision_avisada_at = NULL
            WHERE id = ?""",
        (momento, actor, razon, int(excepcion_id)))
    _auditar(conn, actor, "excepciones.permanente", int(excepcion_id),
             f"convertida en permanente; vence_at {anterior} -> (sin fecha); motivo={razon}", ip)
    log.info("excepcion convertida en permanente",
             extra={"id": int(excepcion_id), "antes": anterior})
    return obtener(conn, excepcion_id) or {}


def convertir_en_temporal(conn: sqlite3.Connection, excepcion_id: int, *, vence_at: Any,
                          motivo: Any, actor: str, ip: Optional[str] = None,
                          ahora: Optional[datetime] = None) -> dict[str, Any]:
    """Le pone fecha de vencimiento a una permanente: vuelve a caducar sola.

    Es el camino de vuelta y el que reduce el riesgo, así que se le pide lo mismo que a
    cualquier cambio con motivo (``MIN_JUSTIFICACION``) y no el texto largo de conceder
    lo permanente. La fecha pasa por las mismas reglas de siempre (posterior a hoy, tope
    de :data:`MAX_DIAS` días, o :data:`MAX_DIAS_KEV` si hay explotación activa).

    ``vence_at_inicial`` conserva la primera fecha que tuvo la excepción si alguna vez la
    tuvo; si nació permanente, esta es su primera fecha y se guarda como tal.
    """
    fila = obtener(conn, excepcion_id)
    if fila is None:
        raise ErrorExcepcion("Esa excepción no existe.")
    if fila["estado"] == "revocada":
        raise ErrorExcepcion("Esa excepción está revocada: no se puede convertir en temporal.")
    if not fila["permanente"]:
        raise ErrorExcepcion("Esa excepción ya tiene fecha de vencimiento. Para cambiarla, "
                             "prorróguela.")
    nueva = _validar_fecha(vence_at, kev=bool(fila["kev"]), ahora=ahora)
    razon = _multilinea(motivo, MAX_MOTIVO)
    if len(razon) < MIN_JUSTIFICACION:
        raise ErrorExcepcion(f"Explique por qué se le pone fecha de vencimiento, con al "
                             f"menos {MIN_JUSTIFICACION} caracteres: queda en el registro "
                             f"de auditoría.")
    conn.execute(
        """UPDATE excepciones SET permanente = 0, vence_at = ?,
                                  vence_at_inicial = COALESCE(vence_at_inicial, ?),
                                  avisado_at = NULL, revision_avisada_at = NULL
            WHERE id = ?""",
        (nueva, nueva, int(excepcion_id)))
    _auditar(conn, actor, "excepciones.temporal", int(excepcion_id),
             f"convertida en temporal; vence_at (sin fecha) -> {nueva}; motivo={razon}", ip)
    log.info("excepcion convertida en temporal",
             extra={"id": int(excepcion_id), "ahora": nueva})
    return obtener(conn, excepcion_id) or {}


def registrar_solicitud(conn: sqlite3.Connection, *, actor: str, texto: str,
                        ip: Optional[str] = None) -> None:
    """Deja constancia de que alguien PIDE una excepción, sin registrarla.

    Los jefes de proceso (perfiles ``redes`` y ``mantenimiento``) pueden solicitarla y
    verla, pero no aceptan el riesgo: la decisión es de ciberseguridad o de la
    administración. La solicitud va al registro de auditoría, se enseña en la propia
    página y desde ahí se registra o se descarta.
    """
    db.audit(conn, actor, "excepciones.solicitud", "excepciones", None, texto[:900], ip)
    log.info("solicitud de excepcion registrada", extra={"actor": actor})


def solicitudes(conn: sqlite3.Connection, *, limite: int = 20, dias: int = 90) -> list[dict]:
    """Las solicitudes recientes, leídas del registro de auditoría."""
    filas = conn.execute(
        """SELECT at, username, detail FROM audit_log
            WHERE action = 'excepciones.solicitud'
              AND at >= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?)
            ORDER BY at DESC LIMIT ?""",
        (f"-{max(1, int(dias))} days", max(1, int(limite)))).fetchall()
    return [dict(f) for f in filas]


# --------------------------------------------------------------------------
# Lectura
# --------------------------------------------------------------------------
_CAMPOS = f"""e.id, e.alcance, e.activo_id, e.cve, e.paquete, e.justificacion,
       e.responsable_nombre, e.responsable_correo, e.compensacion, e.registrado_por,
       e.registrado_at, e.vence_at, e.vence_at_inicial, e.permanente, e.kev, e.prorrogas,
       e.prorrogada_at, e.prorrogada_por, e.prorroga_motivo, e.revocada_at, e.revocada_por,
       e.revocada_motivo, e.avisado_at, e.revisada_at, e.revisada_por, e.revisada_nota,
       e.revisiones, e.revision_avisada_at, e.estado AS estado_guardado,
       {SQL_ESTADO} AS estado, {SQL_DIAS_RESTANTES} AS dias_restantes,
       {SQL_DIAS_SIN_REVISAR} AS dias_sin_revisar,
       a.nombre AS activo_nombre, a.origen AS activo_origen, a.proceso AS activo_proceso,
       a.entorno AS activo_entorno, a.presente AS activo_presente"""

#: Orden de la página: primero lo que exige una decisión y las permanentes AGRUPADAS
#: aparte de las que vencen, que es lo que pidió el usuario. De arriba abajo:
#:
#:   0  vencidas: su vulnerabilidad ya volvió a la cola y nadie ha decidido nada
#:   1  vencen dentro del plazo de aviso
#:   2  permanentes que llevan más del plazo sin revisarse (el recordatorio en pantalla)
#:   3  el resto de las temporales vigentes, por fecha
#:   4  el resto de las permanentes, al día de revisión
#:   5  revocadas
#:
#: Las permanentes van en sus dos grupos y nunca mezcladas con las que vencen. Dentro de
#: cada grupo, por fecha de vencimiento; las permanentes no la tienen, así que caen al
#: desempate por identificador (la más reciente primero).
_ORDEN = (f"CASE WHEN e.estado = 'revocada' THEN 5 "
          f"WHEN e.permanente = 1 AND {SQL_DIAS_SIN_REVISAR} >= :revision THEN 2 "
          f"WHEN e.permanente = 1 THEN 4 "
          f"WHEN date('now') > substr(e.vence_at, 1, 10) THEN 0 "
          f"WHEN julianday(substr(e.vence_at, 1, 10)) - julianday(date('now')) <= :aviso "
          f"THEN 1 ELSE 3 END, e.vence_at ASC, e.id DESC")


def _fila(fila: sqlite3.Row, *, revision_dias: int = REVISION_DIAS_DEFECTO) -> dict[str, Any]:
    datos = dict(fila)
    datos["estado_es"] = ESTADO_ES.get(datos.get("estado", ""), datos.get("estado", ""))
    datos["estado_clave"] = ESTADO_CLAVE.get(datos.get("estado", ""), "neutra")
    datos["alcance_es"] = ALCANCE_ES.get(datos.get("alcance", ""), datos.get("alcance", ""))
    datos["descripcion"] = descripcion(datos)
    datos["permanente"] = bool(datos.get("permanente"))
    # Una permanente NO tiene días restantes: la clave existe y vale None, para que
    # quien la pinte tenga que escribir qué dice cuando no hay número.
    datos["dias_restantes"] = (None if datos["permanente"]
                               else int(datos.get("dias_restantes") or 0))
    datos["dias_sin_revisar"] = int(datos.get("dias_sin_revisar") or 0)
    datos["revision_dias"] = int(revision_dias)
    datos["revision_pendiente"] = bool(
        datos["permanente"] and datos.get("estado") == "vigente"
        and datos["dias_sin_revisar"] >= int(revision_dias))
    datos["revision_en_dias"] = (max(0, int(revision_dias) - datos["dias_sin_revisar"])
                                 if datos["permanente"] else None)
    #: Cómo se nombra la vigencia en una frase, para que las plantillas no repitan el
    #: «Permanente» y la fecha con palabras distintas en cada pantalla.
    datos["vigencia_es"] = TEXTO_PERMANENTE if datos["permanente"] else None
    return datos


def obtener(conn: sqlite3.Connection, excepcion_id: Any,
            *, revision_dias: Optional[int] = None) -> Optional[dict[str, Any]]:
    try:
        numero = int(excepcion_id)
    except (TypeError, ValueError):
        return None
    fila = conn.execute(
        f"""SELECT {_CAMPOS} FROM excepciones e
              LEFT JOIN activos a ON a.id = e.activo_id WHERE e.id = ?""", (numero,)).fetchone()
    if fila is None:
        return None
    dias = int(revision_dias) if revision_dias is not None else ajuste_revision_dias(conn)
    return _fila(fila, revision_dias=dias)


def _filtros(estado: Optional[str], alcance: Optional[str], proceso: Optional[str],
             q: str, origen: Optional[str], activo_id: Optional[int],
             aviso_dias: int,
             revision_dias: int = REVISION_DIAS_DEFECTO) -> tuple[str, dict[str, Any]]:
    """WHERE (con el espacio inicial) y parámetros con nombre para listar y contar."""
    condiciones: list[str] = []
    params: dict[str, Any] = {"aviso": int(aviso_dias), "revision": int(revision_dias)}
    estado = (estado or "").strip()
    if estado == "vigente":
        condiciones.append(SQL_VIGENTE)
    elif estado == "vencida":
        # Una permanente nunca está vencida: la condición la deja fuera sola porque su
        # `vence_at` es NULL, pero se escribe explícito para que se lea de un vistazo.
        condiciones.append("(e.estado = 'vigente' AND e.permanente = 0 "
                           "AND date('now') > substr(e.vence_at, 1, 10))")
    elif estado == "revocada":
        condiciones.append("e.estado = 'revocada'")
    elif estado == "por_vencer":
        condiciones.append(f"({SQL_VIGENTE} AND e.permanente = 0 "
                           f"AND {SQL_DIAS_RESTANTES} <= :aviso)")
    elif estado == "permanente":
        condiciones.append(f"(e.permanente = 1 AND {SQL_VIGENTE})")
    elif estado == "revision":
        condiciones.append(SQL_PENDIENTE_REVISION)
    if alcance in ALCANCES:
        condiciones.append("e.alcance = :alcance")
        params["alcance"] = alcance
    if origen:
        # Una excepción de toda la organización afecta también a las máquinas del perfil,
        # así que se le enseña; las de un activo, solo si ese activo es de su tipo.
        condiciones.append("(e.activo_id IS NULL OR a.origen = :origen)")
        params["origen"] = origen
    if activo_id:
        condiciones.append("e.activo_id = :activo_id")
        params["activo_id"] = int(activo_id)
    if proceso:
        condiciones.append("a.proceso = :proceso")
        params["proceso"] = proceso
    texto = (q or "").strip()
    if texto:
        params["q"] = "%" + texto.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        condiciones.append(
            "(e.cve LIKE :q ESCAPE '\\' OR e.paquete LIKE :q ESCAPE '\\' "
            "OR a.nombre LIKE :q ESCAPE '\\' OR e.responsable_nombre LIKE :q ESCAPE '\\' "
            "OR e.responsable_correo LIKE :q ESCAPE '\\' OR e.justificacion LIKE :q ESCAPE '\\')")
    where = (" WHERE " + " AND ".join(condiciones)) if condiciones else ""
    return where, params


def contar(conn: sqlite3.Connection, *, estado: Optional[str] = None,
           alcance: Optional[str] = None, proceso: Optional[str] = None, q: str = "",
           origen: Optional[str] = None, activo_id: Optional[int] = None,
           aviso_dias: int = AVISO_DIAS_DEFECTO,
           revision_dias: Optional[int] = None) -> int:
    dias = int(revision_dias) if revision_dias is not None else ajuste_revision_dias(conn)
    where, params = _filtros(estado, alcance, proceso, q, origen, activo_id, aviso_dias, dias)
    return int(conn.execute(
        f"""SELECT COUNT(*) FROM excepciones e
              LEFT JOIN activos a ON a.id = e.activo_id{where}""", params).fetchone()[0] or 0)


def listar(conn: sqlite3.Connection, *, estado: Optional[str] = None,
           alcance: Optional[str] = None, proceso: Optional[str] = None, q: str = "",
           origen: Optional[str] = None, activo_id: Optional[int] = None,
           aviso_dias: int = AVISO_DIAS_DEFECTO, revision_dias: Optional[int] = None,
           limite: int = 20, desplazamiento: int = 0) -> list[dict[str, Any]]:
    """Listado para la página, con lo que exige una decisión arriba y las permanentes
    agrupadas aparte de las que vencen (ver :data:`_ORDEN`)."""
    dias = int(revision_dias) if revision_dias is not None else ajuste_revision_dias(conn)
    where, params = _filtros(estado, alcance, proceso, q, origen, activo_id, aviso_dias, dias)
    params["limite"] = max(1, int(limite))
    params["desplazamiento"] = max(0, int(desplazamiento))
    filas = conn.execute(
        f"""SELECT {_CAMPOS} FROM excepciones e
              LEFT JOIN activos a ON a.id = e.activo_id{where}
             ORDER BY {_ORDEN} LIMIT :limite OFFSET :desplazamiento""", params).fetchall()
    return contar_cubiertas(conn, [_fila(f, revision_dias=dias) for f in filas])


def contar_cubiertas(conn: sqlite3.Connection, filas: list[dict]) -> list[dict]:
    """Añade a cada fila ``vulnerabilidades_cubiertas``: los pares (activo, CVE)
    confirmados que la excepción está tapando ahora mismo.

    Se calcula por conjuntos, con tres consultas para toda la página: una por alcance. Con
    una consulta por fila la página crecería con el número de excepciones.
    """
    if not filas:
        return filas
    for fila in filas:
        fila["vulnerabilidades_cubiertas"] = 0
    base = ("FROM aplicabilidad ap JOIN activos a ON a.id = ap.activo_id "
            "WHERE ap.veredicto = ? AND a.presente = 1")
    por_activo_cve = [f for f in filas if f["alcance"] == "activo_cve"]
    if por_activo_cve:
        cond = " OR ".join(["(ap.activo_id = ? AND ap.cve = ?)"] * len(por_activo_cve))
        valores: list[Any] = [AFECTADO]
        for f in por_activo_cve:
            valores += [f["activo_id"], f["cve"]]
        cuenta = {(int(r[0]), str(r[1])): int(r[2]) for r in conn.execute(
            f"SELECT ap.activo_id, ap.cve, COUNT(DISTINCT ap.cve) {base} AND ({cond}) "
            f"GROUP BY ap.activo_id, ap.cve", valores)}
        for f in por_activo_cve:
            f["vulnerabilidades_cubiertas"] = cuenta.get((int(f["activo_id"]), f["cve"]), 0)
    por_cve = [f for f in filas if f["alcance"] == "cve"]
    if por_cve:
        marcas = ",".join("?" * len(por_cve))
        cuenta_cve = {str(r[0]): int(r[1]) for r in conn.execute(
            f"SELECT ap.cve, COUNT(DISTINCT ap.activo_id) {base} AND ap.cve IN ({marcas}) "
            f"GROUP BY ap.cve", [AFECTADO] + [f["cve"] for f in por_cve])}
        for f in por_cve:
            f["vulnerabilidades_cubiertas"] = cuenta_cve.get(f["cve"], 0)
    por_paquete = [f for f in filas if f["alcance"] == "activo_paquete"]
    if por_paquete:
        cond = " OR ".join(["(ap.activo_id = ? AND ap.paquete = ?)"] * len(por_paquete))
        valores = [AFECTADO]
        for f in por_paquete:
            valores += [f["activo_id"], f["paquete"]]
        cuenta_paq = {(int(r[0]), str(r[1])): int(r[2]) for r in conn.execute(
            f"SELECT ap.activo_id, ap.paquete, COUNT(DISTINCT ap.cve) {base} AND ({cond}) "
            f"GROUP BY ap.activo_id, ap.paquete", valores)}
        for f in por_paquete:
            f["vulnerabilidades_cubiertas"] = cuenta_paq.get(
                (int(f["activo_id"]), f["paquete"]), 0)
    return filas


def procesos(conn: sqlite3.Connection, *, origen: Optional[str] = None) -> list[str]:
    """Procesos de negocio con alguna excepción, para el selector de la página."""
    where = " WHERE a.origen = ?" if origen else ""
    params = [origen] if origen else []
    return [r[0] for r in conn.execute(
        f"""SELECT DISTINCT a.proceso FROM excepciones e JOIN activos a ON a.id = e.activo_id
            {where}{' AND' if where else ' WHERE'} COALESCE(a.proceso, '') <> ''
             ORDER BY 1""", params)]


def por_activo(conn: sqlite3.Connection, activo_id: int, *,
               solo_vigentes: bool = True) -> list[dict[str, Any]]:
    """Excepciones que afectan a un activo: las suyas y las de CVE de toda la organización
    que tapan alguna de sus vulnerabilidades confirmadas. Para la ficha del activo."""
    condicion = f" AND {SQL_VIGENTE}" if solo_vigentes else ""
    dias = ajuste_revision_dias(conn)
    filas = conn.execute(
        f"""SELECT {_CAMPOS} FROM excepciones e
              LEFT JOIN activos a ON a.id = e.activo_id
             WHERE (e.activo_id = :activo
                    OR (e.alcance = 'cve' AND e.cve IN (
                          SELECT ap.cve FROM aplicabilidad ap
                           WHERE ap.activo_id = :activo AND ap.veredicto = :afectado))
                   ){condicion}
             ORDER BY {_ORDEN}""",
        {"activo": int(activo_id), "afectado": AFECTADO, "aviso": AVISO_DIAS_DEFECTO,
         "revision": dias}).fetchall()
    return [_fila(f, revision_dias=dias) for f in filas]


def por_cve(conn: sqlite3.Connection, cve: str, *,
            solo_vigentes: bool = True) -> list[dict[str, Any]]:
    """Excepciones que tapan un CVE, en cualquier activo. Para el detalle de la amenaza."""
    condicion = f" AND {SQL_VIGENTE}" if solo_vigentes else ""
    dias = ajuste_revision_dias(conn)
    filas = conn.execute(
        f"""SELECT {_CAMPOS} FROM excepciones e
              LEFT JOIN activos a ON a.id = e.activo_id
             WHERE e.cve = :cve{condicion}
             ORDER BY {_ORDEN}""",
        {"cve": normalizar_cve(cve), "aviso": AVISO_DIAS_DEFECTO,
         "revision": dias}).fetchall()
    return [_fila(f, revision_dias=dias) for f in filas]


def cubre(conn: sqlite3.Connection, *, activo_id: int, cve: str,
          paquete: str = "") -> Optional[dict[str, Any]]:
    """La excepción vigente que tapa esa vulnerabilidad de ese activo, si la hay.

    Es la consulta que necesita una ficha para poner la insignia «riesgo aceptado hasta
    el …» en una fila concreta.
    """
    fila = conn.execute(
        f"""SELECT {_CAMPOS} FROM excepciones e
              LEFT JOIN activos a ON a.id = e.activo_id
             WHERE {SQL_VIGENTE}
               AND ((e.alcance = 'activo_cve' AND e.activo_id = :activo AND e.cve = :cve)
                 OR (e.alcance = 'cve' AND e.cve = :cve)
                 OR (e.alcance = 'activo_paquete' AND e.activo_id = :activo
                     AND e.paquete = :paquete AND :paquete <> ''))
             ORDER BY e.permanente DESC, e.vence_at DESC LIMIT 1""",
        {"activo": int(activo_id), "cve": normalizar_cve(cve),
         "paquete": normalizar_paquete(paquete)}).fetchone()
    # Se prefiere la permanente cuando hay varias que cubren la misma fila: es la que
    # manda de verdad, porque ninguna fecha la va a devolver a la cola.
    return _fila(fila, revision_dias=ajuste_revision_dias(conn)) if fila is not None else None


def ajuste_aviso_dias(conn: sqlite3.Connection = None, *, cfg: Any = None) -> int:
    """Días de antelación del aviso: ajuste ``excepciones_aviso_dias``, por omisión 15."""
    valor = None
    if cfg is not None:
        try:
            valor = cfg.get(AJUSTE_AVISO_DIAS)
        except Exception:  # noqa: BLE001 - un cfg raro no debe tumbar la página
            valor = None
    if valor in (None, "") and conn is not None:
        valor = db.get_setting(conn, AJUSTE_AVISO_DIAS, None)
    try:
        dias = int(float(valor))
    except (TypeError, ValueError):
        dias = AVISO_DIAS_DEFECTO
    return max(1, min(dias, 120))


def ajuste_revision_dias(conn: sqlite3.Connection = None, *, cfg: Any = None) -> int:
    """Cada cuántos días hay que revisar una permanente: ajuste
    ``excepciones_revision_dias``, por omisión 180.

    Es la salvaguarda que sustituye al vencimiento en una excepción sin fecha, así que
    viene activada por omisión y no se puede desactivar poniendo cero: el rango empieza
    en :data:`REVISION_DIAS_MIN`. Un valor corrupto en la tabla de ajustes no tumba nada:
    se cae al valor por omisión, como en :func:`ajuste_aviso_dias`.
    """
    valor = None
    if cfg is not None:
        try:
            valor = cfg.get(AJUSTE_REVISION_DIAS)
        except Exception:  # noqa: BLE001 - un cfg raro no debe tumbar la página
            valor = None
    if valor in (None, "") and conn is not None:
        valor = db.get_setting(conn, AJUSTE_REVISION_DIAS, None)
    try:
        dias = int(float(valor))
    except (TypeError, ValueError):
        dias = REVISION_DIAS_DEFECTO
    return max(REVISION_DIAS_MIN, min(dias, REVISION_DIAS_MAX))


def resumen(conn: sqlite3.Connection, *, origen: Optional[str] = None,
            aviso_dias: Optional[int] = None, revision_dias: Optional[int] = None,
            con_cubiertas: bool = True) -> dict[str, Any]:
    """Cifras de la página: vigentes, por vencer, vencidas, revocadas, permanentes,
    permanentes pendientes de revisión y lo que tapan todas ellas.

    «Por vencer» y «vencidas» NO cuentan las permanentes: no vencen. Las permanentes
    tienen sus dos cifras propias, y ``permanentes_sin_revisar`` son las que llevan más
    de ``excepciones_revision_dias`` días sin que nadie confirme que siguen valiendo
    (siguen vigentes: es un recordatorio, no un vencimiento).

    ``con_cubiertas=False`` omite :func:`vulnerabilidades_cubiertas` y devuelve la clave
    en ``None``. Esa cifra es la única del resumen que recorre ``aplicabilidad`` (179.429
    filas en la base real) y costaba 78 de los 89 milisegundos de ``/salud.json``, que
    Zabbix consulta cada minuto: sin ella la respuesta vuelve a los 11 milisegundos de
    antes. La página de Excepciones sí la pide, porque es su indicador principal
    (pendiente del apartado 12 de ``docs/EXCEPCIONES_2026-09-10.md``, resuelto hoy).
    """
    dias = int(aviso_dias if aviso_dias is not None else ajuste_aviso_dias(conn))
    revision = int(revision_dias if revision_dias is not None
                   else ajuste_revision_dias(conn))
    where, params = _filtros(None, None, None, "", origen, None, dias, revision)
    fila = conn.execute(
        f"""SELECT
              SUM(CASE WHEN {SQL_ESTADO} = 'vigente' THEN 1 ELSE 0 END) AS vigentes,
              SUM(CASE WHEN {SQL_ESTADO} = 'vigente' AND e.permanente = 0
                        AND {SQL_DIAS_RESTANTES} <= :aviso
                       THEN 1 ELSE 0 END) AS por_vencer,
              SUM(CASE WHEN {SQL_ESTADO} = 'vencida' THEN 1 ELSE 0 END) AS vencidas,
              SUM(CASE WHEN {SQL_ESTADO} = 'revocada' THEN 1 ELSE 0 END) AS revocadas,
              SUM(CASE WHEN {SQL_ESTADO} = 'vigente' AND e.kev = 1 THEN 1 ELSE 0 END) AS kev,
              SUM(CASE WHEN {SQL_ESTADO} = 'vigente' AND e.permanente = 1
                       THEN 1 ELSE 0 END) AS permanentes,
              SUM(CASE WHEN {SQL_PENDIENTE_REVISION} THEN 1 ELSE 0 END)
                       AS permanentes_sin_revisar,
              COUNT(*) AS total
            FROM excepciones e LEFT JOIN activos a ON a.id = e.activo_id{where}""",
        params).fetchone()
    datos = {clave: int(fila[clave] or 0) for clave in
             ("vigentes", "por_vencer", "vencidas", "revocadas", "kev", "permanentes",
              "permanentes_sin_revisar", "total")}
    datos["aviso_dias"] = dias
    datos["revision_dias"] = revision
    datos["origen"] = origen
    datos["vulnerabilidades_cubiertas"] = (
        vulnerabilidades_cubiertas(conn, origen=origen) if con_cubiertas else None)
    datos["con_cubiertas"] = bool(con_cubiertas)
    return datos


def vulnerabilidades_cubiertas(conn: sqlite3.Connection, *,
                               origen: Optional[str] = None) -> int:
    """Vulnerabilidades (pares activo-CVE) que HOY desaparecen de las cifras de riesgo
    porque una excepción vigente las cubre. Es una DIFERENCIA exacta, no un conteo de
    filas cubiertas.

    Por qué la diferencia y no el conteo (corrección del 2026-09-10, tarde): una
    vulnerabilidad es un CVE en un activo y puede llegar por VARIOS paquetes de ese
    activo. Si la excepción cubre uno de esos paquetes y el otro sigue pendiente, el par
    (activo, CVE) NO desaparece de ninguna cifra: sigue contando. La versión anterior
    contaba los pares con ALGUNA fila cubierta y decía 1.745 sobre la base real, mientras
    lo que de verdad salía de Amenazas y de Remediación eran 1.742 (tres pares con otro
    paquete pendiente). Dos cifras de lo mismo con tres de diferencia y sin explicación es
    justo lo que este proyecto no admite, así que ahora se mide igual que
    ``queries.resumen_amenazas`` (``vulnerabilidades_aceptadas``) y que
    ``webui.vistas.remediaciones._cifras_riesgo_aceptado``: total menos lo que queda.

    No recorre ``aplicabilidad`` entera. Una vulnerabilidad solo puede desaparecer si
    ALGUNA de sus filas está cubierta, y eso solo les puede pasar a las filas de los
    activos nombrados por una excepción o de un CVE aceptado en toda la organización:
    :data:`SQL_CANDIDATAS` reduce el recorrido a ese conjunto por los índices
    ``idx_aplic_activo`` e ``idx_aplic_cve``, y el ``GROUP BY … HAVING`` decide, pareja a
    pareja, si TODAS sus filas están cubiertas. Medido sobre una copia de la base real el
    2026-09-10 (179.429 filas de ``aplicabilidad``, tres excepciones vigentes, una de
    ellas sobre un CVE presente en 386 activos): **6,5 milisegundos** frente a los 162 de
    recorrer la tabla completa, con el mismo resultado exacto (1.742).

    Mismo filtro que las cifras de riesgo del resto de la plataforma: activos presentes,
    amenazas que no estén descartadas, dadas por falso positivo ni mitigadas, y sin la
    severidad baja cuando el ajuste ``ignore_low_severity`` está activo (que es la regla).
    Así esta cifra y la de Amenazas son necesariamente iguales.
    """
    if not hay_excepciones(conn):
        return 0
    sin_bajas = (" AND (t.severity IS NULL OR t.severity <> 'Low')"
                 if bool(db.get_setting(conn, "ignore_low_severity", True)) else "")
    extra = " AND a.origen = ?" if origen else ""
    params = [AFECTADO] + ([origen] if origen else [])
    return int(conn.execute(
        f"""SELECT COUNT(*) FROM (
              SELECT ap.activo_id, ap.cve
                FROM aplicabilidad ap JOIN activos a ON a.id = ap.activo_id
                LEFT JOIN threats t ON t.id = ap.threat_id
               WHERE ap.veredicto = ? AND a.presente = 1{extra}
                 AND (t.id IS NULL OR t.estado NOT IN {ESTADOS_CERRADOS_SQL}){sin_bajas}
                 AND {SQL_CANDIDATAS}
               GROUP BY ap.activo_id, ap.cve
              HAVING SUM(CASE WHEN {SQL_SIN_EXCEPCION_APLICABILIDAD} THEN 1 ELSE 0 END) = 0)""",
        params).fetchone()[0] or 0)


# --------------------------------------------------------------------------
# Aviso anticipado (ejecución diaria)
# --------------------------------------------------------------------------
#: Tipo de aviso en ``admin_notices``, para no repetir el mismo correo cada día.
TIPO_AVISO = "excepciones"
#: Horas de silencio entre dos avisos de la MISMA excepción y la misma situación.
SILENCIO_HORAS = 24 * 7
#: Cuántas excepciones se detallan en el correo.
MAX_EN_CORREO = 50


def pendientes_de_aviso(conn: sqlite3.Connection, *, aviso_dias: Optional[int] = None,
                        cfg: Any = None) -> dict[str, list[dict]]:
    """Las que vencen pronto y las que ya vencieron sin que nadie decidiera nada.

    Las PERMANENTES quedan fuera de las dos listas: no vencen, así que no pueden estar
    «por vencer» ni «vencidas», y meterlas ahí sería avisar de algo que no va a pasar.
    Su recordatorio es otro (:func:`pendientes_de_revision`) y dice otra cosa. La
    condición ``e.permanente = 0`` está escrita aunque ``SQL_DIAS_RESTANTES`` ya daría
    NULL para ellas (y ``NULL <= 15`` no es cierto): se lee de un vistazo y no depende de
    cómo trate SQLite los nulos en una comparación.
    """
    dias = int(aviso_dias if aviso_dias is not None else ajuste_aviso_dias(conn, cfg=cfg))
    revision = ajuste_revision_dias(conn, cfg=cfg)
    filas = conn.execute(
        f"""SELECT {_CAMPOS} FROM excepciones e
              LEFT JOIN activos a ON a.id = e.activo_id
             WHERE e.estado = 'vigente' AND e.permanente = 0
               AND {SQL_DIAS_RESTANTES} <= :aviso
             ORDER BY {_ORDEN}""", {"aviso": dias, "revision": revision}).fetchall()
    por_vencer, vencidas = [], []
    for cruda in filas:
        fila = _fila(cruda, revision_dias=revision)
        (vencidas if fila["estado"] == "vencida" else por_vencer).append(fila)
    return {"por_vencer": por_vencer, "vencidas": vencidas, "aviso_dias": dias}


def pendientes_de_revision(conn: sqlite3.Connection, *,
                           revision_dias: Optional[int] = None,
                           cfg: Any = None) -> dict[str, Any]:
    """Las permanentes que llevan el plazo entero sin que nadie confirme que siguen valiendo.

    Es la salvaguarda contra el olvido que pidió el usuario cuando decidió que hubiera
    excepciones sin fecha de vencimiento. NO es un vencimiento: estas excepciones están
    vigentes, siguen tapando su vulnerabilidad y lo seguirán haciendo aunque nadie
    conteste nunca. Lo único que ocurre es que entran en el correo de administración y
    suben al principio de la página hasta que alguien confirme la revisión o las revoque.
    """
    dias = int(revision_dias if revision_dias is not None
               else ajuste_revision_dias(conn, cfg=cfg))
    filas = conn.execute(
        f"""SELECT {_CAMPOS} FROM excepciones e
              LEFT JOIN activos a ON a.id = e.activo_id
             WHERE {SQL_PENDIENTE_REVISION}
             ORDER BY {SQL_DIAS_SIN_REVISAR} DESC, e.id DESC""",
        {"revision": dias, "aviso": AVISO_DIAS_DEFECTO}).fetchall()
    return {"revision": [_fila(f, revision_dias=dias) for f in filas],
            "revision_dias": dias}


def _frase_plazo(fila: dict) -> str:
    """Cuánto le queda, en palabras. Una permanente no tiene plazo y lo dice así."""
    if fila.get("permanente"):
        return "permanente: no vence"
    dias = int(fila.get("dias_restantes") or 0)
    if dias < 0:
        return f"venció hace {-dias} día{'s' if dias != -1 else ''}"
    if dias == 0:
        return "vence hoy"
    return f"vence en {dias} día{'s' if dias != 1 else ''}"


def _frase_revision(fila: dict) -> str:
    """Cuánto lleva sin revisarse una permanente, en palabras y con su unidad."""
    dias = int(fila.get("dias_sin_revisar") or 0)
    desde = ("desde la última revisión" if fila.get("revisada_at")
             else "desde que se registró")
    return f"{dias} día{'s' if dias != 1 else ''} {desde}"


def avisar(conn: sqlite3.Connection, *, cfg: Any, mailer: Any = None,
           ahora: Optional[datetime] = None) -> Optional[dict[str, Any]]:
    """Correo de administración con las excepciones que vencen pronto, las vencidas y
    las permanentes que llevan demasiado tiempo sin revisarse.

    Va en la ejecución DIARIA y no en el resumen semanal a propósito: el aviso semanal
    puede llegar hasta seis días tarde, y en ese plazo una excepción de quince días de
    antelación se queda sin margen para renovarse, corregirse o revocarse. Para que no sea
    ruido, cada excepción entra en un correo como mucho una vez por semana en cada
    situación («por vencer» y «vencida»), con el mismo mecanismo de silencio que usa el
    aviso de caducidad del certificado (``admin_notices``).

    Devuelve el aviso enviado o None si no había nada que avisar (o no se pudo enviar).
    """
    datos = pendientes_de_aviso(conn, cfg=cfg)
    por_vencer, vencidas = datos["por_vencer"], datos["vencidas"]
    datos_revision = pendientes_de_revision(conn, cfg=cfg)
    revision = datos_revision["revision"]
    if not por_vencer and not vencidas and not revision:
        return None
    destinatarios = list(getattr(cfg, "admin_to", None) or [])
    if not destinatarios:
        log.warning("excepciones que avisar y sin destinatarios de administracion",
                    extra={"por_vencer": len(por_vencer), "vencidas": len(vencidas),
                           "revision": len(revision)})
        return None
    momento = ahora or datetime.now(timezone.utc)
    limite = (momento - timedelta(hours=SILENCIO_HORAS)).replace(
        microsecond=0).isoformat().replace("+00:00", "Z")
    nuevas = []
    for fila in vencidas + por_vencer:
        clave = f"{fila['id']}|{fila['estado']}|{fila['vence_at']}"
        ya = conn.execute(
            "SELECT 1 FROM admin_notices WHERE kind = ? AND subject_key = ? AND sent_at >= ? LIMIT 1",
            (TIPO_AVISO, clave, limite)).fetchone()
        if ya is None:
            nuevas.append((clave, fila))
    # El recordatorio de revisión lleva en su clave la fecha desde la que se cuenta el
    # plazo: al confirmar la revisión, esa fecha cambia y el recordatorio empieza de
    # cero. Mientras nadie conteste, la clave es la misma y el correo se repite una vez
    # por semana, igual que el resto.
    for fila in revision:
        base = str(fila.get("revisada_at") or fila.get("registrado_at") or "")[:10]
        clave = f"{fila['id']}|revision|{base}"
        ya = conn.execute(
            "SELECT 1 FROM admin_notices WHERE kind = ? AND subject_key = ? AND sent_at >= ? LIMIT 1",
            (TIPO_AVISO, clave, limite)).fetchone()
        if ya is None:
            nuevas.append((clave, fila))
    if not nuevas:
        return None

    from .notify import Mailer, asunto_admin, fecha_larga, render_admin_email
    mailer = mailer or Mailer(cfg)
    hay_vencidas = bool(vencidas)
    revision_dias = datos_revision["revision_dias"]
    # La severidad la marca lo más grave que haya: una vencida ya dejó la vulnerabilidad
    # de vuelta en la cola sin que nadie lo decidiera; una permanente sin revisar no ha
    # roto nada todavía, así que sola no llega a «aviso».
    severidad = ("critical" if hay_vencidas
                 else "warning" if por_vencer else "info")
    partes = []
    if vencidas:
        partes.append(f"{len(vencidas)} aceptación de riesgo vencida" if len(vencidas) == 1
                      else f"{len(vencidas)} aceptaciones de riesgo vencidas")
    if por_vencer:
        partes.append(f"{len(por_vencer)} a punto de vencer" if vencidas else
                      (f"1 aceptación de riesgo vence en los próximos "
                       f"{datos['aviso_dias']} días" if len(por_vencer) == 1 else
                       f"{len(por_vencer)} aceptaciones de riesgo vencen en los próximos "
                       f"{datos['aviso_dias']} días"))
    if revision:
        if vencidas or por_vencer:
            partes.append(f"{len(revision)} permanente{'s' if len(revision) != 1 else ''} "
                          f"sin revisar")
        else:
            partes.append(
                f"1 aceptación de riesgo permanente lleva más de {revision_dias} días sin "
                f"revisarse" if len(revision) == 1 else
                f"{len(revision)} aceptaciones de riesgo permanentes llevan más de "
                f"{revision_dias} días sin revisarse")
    titulo = " y ".join(partes)
    intro = ("Una aceptación de riesgo saca la vulnerabilidad de la cola de trabajo y de las "
             "cifras. Si tiene fecha de vencimiento, al vencer la vulnerabilidad vuelve sola: "
             "vuelve a contar y vuelve a pedir trabajo. Si es permanente, no vence nunca, así "
             "que en su lugar hay que revisarla cada cierto tiempo y confirmar que sigue "
             "siendo válida. Estas son las que hay que mirar.")
    secciones = []
    for nombre, grupo in (("Ya vencidas: la vulnerabilidad volvió a la cola", vencidas),
                          (f"Vencen en los próximos {datos['aviso_dias']} días", por_vencer)):
        if not grupo:
            continue
        recorte = grupo[:MAX_EN_CORREO]
        secciones.append({
            "titulo": nombre,
            "tabla": {
                "cabeceras": ["Qué cubre", "Vence", "Situación", "Responsable",
                              "Explotación activa"],
                "filas": [[fila["descripcion"], fecha_larga(fila["vence_at"]),
                           _frase_plazo(fila),
                           f"{fila['responsable_nombre']} ({fila['responsable_correo']})",
                           "sí (CISA KEV)" if fila["kev"] else "no"]
                          for fila in recorte]}})
        if len(grupo) > len(recorte):
            secciones[-1]["tabla"]["filas"].append(
                [f"y {len(grupo) - len(recorte)} más en la plataforma", "—", "—", "—", "—"])
    if revision:
        recorte = revision[:MAX_EN_CORREO]
        secciones.append({
            "titulo": (f"Permanentes que llevan más de {revision_dias} días aceptadas sin "
                       f"revisarse (siguen vigentes)"),
            "tabla": {
                "cabeceras": ["Qué cubre", "Vence", "Lleva sin revisarse", "Responsable",
                              "Qué hay que hacer"],
                "filas": [[fila["descripcion"], TEXTO_PERMANENTE, _frase_revision(fila),
                           f"{fila['responsable_nombre']} ({fila['responsable_correo']})",
                           (f"lleva {fila['dias_sin_revisar']} días aceptada sin revisarse: "
                            f"confirme que sigue siendo válida o revóquela")]
                          for fila in recorte]}})
        if len(revision) > len(recorte):
            secciones[-1]["tabla"]["filas"].append(
                [f"y {len(revision) - len(recorte)} más en la plataforma",
                 "—", "—", "—", "—"])
    acciones = ["Abrir Excepciones en la plataforma y decidir una por una: corregir, "
                "prorrogar con un motivo nuevo o revocar."]
    if hay_vencidas:
        acciones.insert(0, "Las vencidas ya no protegen nada: su vulnerabilidad vuelve a "
                           "contar en las cifras y a aparecer en la cola de remediación.")
    if revision:
        acciones.append(
            f"Las permanentes de la última tabla NO han caducado ni van a caducar: siguen "
            f"vigentes y su vulnerabilidad sigue fuera de la cola aunque nadie conteste a "
            f"este correo. Lo que hace falta es mirarlas: en la página de Excepciones, "
            f"«Confirmar la revisión» deja constancia de quién y cuándo y reinicia los "
            f"{revision_dias} días; si el riesgo ya no se acepta, revóquela y la "
            f"vulnerabilidad vuelve a la cola en el acto.")
    html = render_admin_email(
        titulo=titulo, intro=intro, severidad=severidad, secciones=secciones,
        acciones=acciones,
        # Se citan las ETIQUETAS VISIBLES de los ajustes y su ruta de menu, no sus claves
        # internas: en Ajustes no se llaman «excepciones_aviso_dias» ni
        # «excepciones_revision_dias» (revision de claridad del 2026-09-15).
        pie=("Este aviso se repite una vez por semana mientras la situación siga igual. La "
             "antelación con la que se avisa se cambia en Administración → Ajustes → Alertas "
             "diarias, en «Días de antelación del aviso de excepciones por vencer»; el plazo "
             "de las permanentes, en «Días entre revisiones de una excepción permanente»."))
    if not mailer.send(subject=asunto_admin(titulo, severidad), html=html, to=destinatarios):
        log.error("no se pudo enviar el aviso de excepciones por vencer")
        return None
    sello = momento.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    for clave, fila in nuevas:
        es_revision = "|revision|" in clave
        conn.execute(
            "INSERT OR IGNORE INTO admin_notices(kind, subject_key, sent_at, detail) VALUES(?,?,?,?)",
            (TIPO_AVISO, clave, sello,
             f"excepcion={fila['id']} estado={fila['estado']} "
             f"{'revision' if es_revision else 'vence_at=' + str(fila['vence_at'])}"))
        # Cada situación tiene su propia marca: `avisado_at` es la del vencimiento y
        # `revision_avisada_at` la del recordatorio de revisión. Con una sola columna,
        # confirmar una revisión borraría la memoria del aviso de vencimiento.
        columna = "revision_avisada_at" if es_revision else "avisado_at"
        conn.execute(f"UPDATE excepciones SET {columna} = ? WHERE id = ?",
                     (sello, fila["id"]))
    log.info("aviso de excepciones enviado",
             extra={"por_vencer": len(por_vencer), "vencidas": len(vencidas),
                    "revision": len(revision), "nuevas": len(nuevas)})
    return {"kind": TIPO_AVISO, "titulo": titulo, "severidad": severidad,
            "por_vencer": len(por_vencer), "vencidas": len(vencidas),
            "revision": len(revision), "avisadas": len(nuevas)}

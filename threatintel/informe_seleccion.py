"""Selección de un informe a medida: periodo, alcance, severidades y apartados (2026-09-10).

Hasta hoy solo existía un informe: el mensual completo de toda la organización que compone
:func:`threatintel.report.construir_documento` y que envía la ejecución programada del
último día del mes. El usuario pidió el 2026-09-10 «poder crear informes personalizados y
tener plantillas de informes preconfiguradas»: elegir el periodo, a qué parte del parque se
refiere, qué severidades entran y qué apartados se escriben.

Este módulo es la **parte de datos** de esa petición y no sabe nada de Word ni de Flask:

* :class:`Seleccion` describe lo que se pide, se construye desde los parámetros de la
  dirección web (todo validado contra listas blancas) y sabe volver a ellos, que es como
  se comparte un informe sin guardar nada en la base;
* :data:`PLANTILLAS` son los puntos de partida preconfigurados;
* las funciones ``estadisticas``, ``amenazas``, ``top_tecnologias``, ``evolucion``,
  ``veredictos``, ``precision`` y ``resumen_activos`` devuelven exactamente lo mismo que
  las de :mod:`threatintel.queries` y :mod:`threatintel.aplicabilidad` que usa el informe
  mensual, pero acotado por la selección en vez de por un mes.

Reglas que se cumplen aquí y no se pueden desactivar desde la dirección web:

* **La severidad Baja no se reporta NUNCA.** No está en :data:`SEVERIDADES`, así que no se
  puede pedir; y si alguien la escribe en la dirección, se descarta al validar.
* **El alcance del perfil manda.** ``origen_perfil`` (el tipo de máquina al que está
  acotado el perfil de la sesión: «servidores» para Redes, «equipos» para Mantenimiento)
  se aplica SIEMPRE por encima de lo que pida la dirección; la vista lo rellena desde
  ``webui.auth.alcance_origen`` y aquí no hay forma de ampliarlo.
* **Todo el SQL va parametrizado** y ningún texto de la persona entra en una consulta ni
  en el nombre de un fichero.

Rendimiento: las consultas de la vista previa son de recuento y se apoyan en los índices
que ya existen (``idx_threats_month``, ``idx_threats_seen``, ``idx_aplic_threat``,
``idx_aplic_activo``). Medido el 2026-09-10 sobre la base real (7.121 amenazas, 717 activos
presentes, 179.429 filas de aplicabilidad): entre 7 y 20 milisegundos por recuento.
"""
from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, replace
from datetime import date, datetime, timedelta, timezone
from typing import Any, Iterable, Mapping, Optional

from . import queries

# --------------------------------------------------------------------------
# Vocabulario
# --------------------------------------------------------------------------
#: Severidades que se pueden pedir en un informe. La Baja no está y no estará: por regla
#: interna del equipo (2026-09-04, reiterada el 2026-09-10) no se reporta en ninguna cifra
#: ni sección, así que tampoco se ofrece.
SEVERIDADES = ("Critical", "High", "Medium")

SEVERIDAD_ES = {"Critical": "crítica", "High": "alta", "Medium": "media"}
SEVERIDAD_ES_PLURAL = {"Critical": "críticas", "High": "altas", "Medium": "medias"}

#: Formas de decir «qué periodo». Cada una usa las columnas que mejor indexadas están:
#: «mes» compara ``threats.month`` (idx_threats_month) y las demás ``first_seen_at``
#: (idx_threats_seen), nunca ``date(first_seen_at)``, que anularía el índice.
CLASES_PERIODO = {
    "mes": "Un mes concreto",
    "trimestre": "Un trimestre",
    "semestre": "Un semestre",
    "anio": "Un año completo",
    "intervalo": "Un intervalo de fechas",
    "dias": "Los últimos días",
}

#: Formas de decir «de qué parte de la organización». «tipo» es el tipo de máquina
#: (servidores o equipos de cómputo), nunca «equipo» a secas.
ALCANCES = {
    "organizacion": "Toda la organización",
    "proceso": "Un proceso de negocio",
    "tipo": "Un tipo de máquina",
    "activo": "Un activo concreto",
    "tecnologia": "Una tecnología",
    "kev": "Solo lo que tiene explotación activa confirmada",
}

#: Tipos de máquina admitidos (columna ``activos.origen``) y su nombre escrito.
TIPOS_MAQUINA = {"servidores": "servidores", "equipos": "equipos de cómputo"}

MESES_ES = ("enero", "febrero", "marzo", "abril", "mayo", "junio", "julio",
            "agosto", "septiembre", "octubre", "noviembre", "diciembre")

_RE_MES = re.compile(r"^\d{4}-(0[1-9]|1[0-2])$")
_RE_FECHA = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_RE_SLUG = re.compile(r"^[a-z0-9][a-z0-9._-]{0,79}$")
#: Calendario fijo (2026-11-17): «AAAA», «AAAA-T1».."AAAA-T4" y «AAAA-S1"/"AAAA-S2".
#: El rango 1930-2099 no es por el calendario sino para que un valor absurdo en la
#: dirección web (un año de siete cifras) no llegue ni a intentar construir una fecha.
_RE_ANIO = re.compile(r"^(19[3-9]\d|20\d{2})$")
_RE_TRIMESTRE = re.compile(r"^(19[3-9]\d|20\d{2})-T([1-4])$")
_RE_SEMESTRE = re.compile(r"^(19[3-9]\d|20\d{2})-S([1-2])$")
#: Caracteres que se admiten en el título, el destinatario y la nota de la portada: letras
#: (con tildes y eñes), cifras, espacios y puntuación corriente. Todo lo demás se quita
#: antes de que el texto llegue al documento; no por el documento, que python-docx escapa,
#: sino para que nadie meta caracteres de control en la auditoría.
_RE_TEXTO_PROHIBIDO = re.compile(r"[\x00-\x1f\x7f]")

#: Tope de días de un intervalo: cinco años. Un informe más largo no cabe en el tiempo de
#: respuesta del servidor web (nginx corta a los 120 segundos) y nadie lo lee.
DIAS_MAXIMO = 1830
#: Tope de la opción «los últimos N días».
DIAS_ULTIMOS_MAXIMO = 366
DIAS_ULTIMOS_DEFECTO = 30


# --------------------------------------------------------------------------
# Apartados
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Apartado:
    """Un apartado del documento: qué es, para quién sirve y cuánto cuesta escribirlo."""
    clave: str
    titulo: str
    descripcion: str
    #: Los apartados numerados llevan «1.», «2.»… en el documento; la portada, el índice
    #: y el anexo no.
    numerado: bool = True
    #: Un apartado «pesado» recorre amenaza a amenaza o activo a activo: es el que decide
    #: cuánto tarda el informe, y la pantalla lo advierte cuando la selección es grande.
    pesado: bool = False


APARTADOS: tuple[Apartado, ...] = (
    Apartado("portada", "Portada",
             "Título, periodo, destinatario, su nota y el cuadro de cifras clave.",
             numerado=False),
    Apartado("indice", "Índice",
             "Índice automático de Word: se actualiza con Ctrl+E y F9 al abrirlo.",
             numerado=False),
    Apartado("resumen_ejecutivo", "Resumen ejecutivo",
             "El párrafo de situación, cómo leer el informe y la actuación requerida "
             "por severidad con su plazo."),
    Apartado("panorama", "Panorama y cifras",
             "Reparto por severidad, procedencia del dato de severidad y evolución "
             "respecto a los periodos anteriores."),
    Apartado("tecnologias", "Tecnologías más afectadas",
             "Las tecnologías del inventario con más amenazas del periodo y el reparto "
             "por aplicabilidad de la versión instalada."),
    Apartado("activos", "Exposición y activos afectados",
             "Servidores y equipos de cómputo con la versión vulnerable confirmada, fin "
             "de soporte y cobertura del inventario real."),
    # 2026-09-15 (revision de claridad, punto 3): estas descripciones llamaban
    # «vulnerabilidades» a lo que el resto de la plataforma llama AMENAZAS. Una
    # vulnerabilidad es un CVE EN UN ACTIVO; lo que lleva ficha y lo que lista el anexo
    # son amenazas del periodo.
    Apartado("prioritarias", "Fichas de las amenazas prioritarias",
             "Una ficha por amenaza que requiere acción, agrupadas por tecnología.",
             pesado=True),
    Apartado("remediacion", "Cola de remediación con la versión a la que actualizar",
             "Qué hay que instalar en cada activo y hasta qué versión, con las "
             "vulnerabilidades que cierra cada actualización.",
             pesado=True),
    Apartado("anexo", "Anexo con el resto de hallazgos",
             "Tabla con las amenazas del periodo que no llevan ficha.",
             numerado=False, pesado=True),
    Apartado("conclusiones", "Conclusiones y recomendaciones",
             "Lectura del periodo, tecnologías prioritarias y recomendaciones."),
    Apartado("precision", "Precisión del filtro",
             "Cuántas amenazas dejó fuera el criterio de alerta y por qué motivo."),
    Apartado("metodologia", "Metodología",
             "Origen de los datos, cómo se clasifica la severidad y cómo se decide la "
             "aplicabilidad por activo."),
)

# --------------------------------------------------------------------------
# Apartados del informe ejecutivo mensual (2026-09-15)
# --------------------------------------------------------------------------
# El usuario pidió: «necesito que a final de mes también se genere un informe ejecutivo
# sobre las amenazas del mes que no exceda las 10 páginas, donde debe ser muy conciso,
# concreto, directo y lo que normalmente le interesa a un gerente: temas de cifras,
# comparación entre meses o años y avances entre meses con detectadas y remediadas».
#
# Es un documento DISTINTO del informe mensual completo, que se conserva intacto (hay una
# prueba que lo compara párrafo a párrafo). Por eso sus apartados son claves propias
# («ej_…») que no se mezclan nunca con las doce del informe a medida: el catálogo que se
# ofrece en el formulario sigue siendo :data:`APARTADOS`, y estos cinco van juntos o no
# van. La estructura es fija a propósito: lo que hace que quepa en diez páginas es
# justamente que nadie pueda añadirle fichas ni anexos.
APARTADOS_EJECUTIVO_DETALLE: tuple[Apartado, ...] = (
    Apartado("ej_portada", "Portada del informe ejecutivo",
             "Mes, alcance y las cuatro cifras que resumen la situación.",
             numerado=False),
    Apartado("ej_cifras", "Las cifras del mes",
             "Cuántas vulnerabilidades hay, en cuántos activos del parque, cuántas se "
             "están explotando ahora mismo y cuánto trabajo queda pendiente."),
    Apartado("ej_comparacion", "Comparación con el mes anterior y con el año pasado",
             "La variación en porcentaje y en número, dicha en palabras: mejoró, "
             "empeoró o se mantiene."),
    Apartado("ej_avance", "Avance mes a mes: detectadas y remediadas",
             "Cuántas vulnerabilidades aparecieron y cuántas se cerraron cada mes, si la "
             "deuda sube o baja y cuánto se tarda en corregir."),
    Apartado("ej_pendiente", "Dónde está el trabajo pendiente",
             "Cuánto queda por hacer, en cuántas máquinas y qué parte es urgente."),
    Apartado("ej_recomendacion", "Qué conviene hacer el mes que viene",
             "Tres o cuatro decisiones concretas, con lo que cambia si se toman."),
)

#: Los apartados del informe ejecutivo, en su orden. Van siempre los cinco más la portada.
APARTADOS_EJECUTIVO: tuple[str, ...] = tuple(a.clave for a in APARTADOS_EJECUTIVO_DETALLE)

#: Clave de la plantilla del informe ejecutivo mensual.
PLANTILLA_EJECUTIVA = "ejecutivo"

#: Orden en que se escriben los apartados en el documento, pase lo que pase con el orden
#: en que los marque la persona: un informe no cambia de estructura según se rellene el
#: formulario. Los del informe ejecutivo van detrás, en su propio bloque: nunca se
#: entremezclan con los del informe a medida (:func:`ordenar_apartados` lo impide).
ORDEN_APARTADOS: tuple[str, ...] = (tuple(a.clave for a in APARTADOS)
                                    + APARTADOS_EJECUTIVO)
APARTADO_POR_CLAVE: dict[str, Apartado] = {
    a.clave: a for a in (APARTADOS + APARTADOS_EJECUTIVO_DETALLE)}

#: Los apartados del informe mensual de siempre, en su orden. Es EXACTAMENTE lo que
#: escribe ``report.construir_documento`` sin argumentos nuevos; la cola de remediación no
#: está porque el informe mensual nunca la ha llevado y no se le va a cambiar el contenido.
APARTADOS_MENSUAL: tuple[str, ...] = (
    "portada", "indice", "resumen_ejecutivo", "panorama", "tecnologias", "activos",
    "prioritarias", "anexo", "conclusiones", "precision", "metodologia")


def ordenar_apartados(claves: Iterable[str]) -> tuple[str, ...]:
    """Las claves conocidas, sin repetir y en el orden del documento.

    Los apartados del informe ejecutivo y los del informe a medida NO se mezclan: si en lo
    pedido hay alguno del ejecutivo se devuelven los del ejecutivo y nada más. Son dos
    documentos distintos, con dos generadores distintos, y una dirección web manipulada
    («?apartado=ej_cifras&apartado=anexo») no puede producir un híbrido.
    """
    pedidas = {str(c) for c in claves}
    if pedidas & set(APARTADOS_EJECUTIVO):
        return tuple(c for c in APARTADOS_EJECUTIVO if c in pedidas)
    return tuple(c for c in ORDEN_APARTADOS if c in pedidas)


def es_ejecutivo(claves: Iterable[str]) -> bool:
    """¿Estos apartados son los del informe ejecutivo mensual?"""
    return bool(set(claves) & set(APARTADOS_EJECUTIVO))


def numeros_de_apartado(claves: Iterable[str]) -> dict[str, int]:
    """Número que le toca a cada apartado numerado de la selección.

    Con los apartados del informe mensual devuelve los números históricos (resumen 1,
    panorama 2, tecnologías 3, activos 4, prioritarias 5, conclusiones 6, precisión 7,
    metodología 8), así que el documento por omisión no cambia ni una cifra.
    """
    numeros: dict[str, int] = {}
    n = 0
    for clave in ordenar_apartados(claves):
        if APARTADO_POR_CLAVE[clave].numerado:
            n += 1
            numeros[clave] = n
    return numeros


# --------------------------------------------------------------------------
# Plantillas preconfiguradas
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Plantilla:
    """Un punto de partida con nombre: qué apartados trae y con qué filtros."""
    clave: str
    nombre: str
    descripcion: str
    #: Para quién se escribe, en una línea. Se usa como ayuda en la pantalla.
    para_quien: str
    apartados: tuple[str, ...]
    periodo: str = "mes"
    alcance: str = "organizacion"
    severidades: tuple[str, ...] = SEVERIDADES
    titulo: str = ""
    #: Alcance que la plantilla necesita que se concrete (un proceso, un activo…). La
    #: pantalla lo pide antes de dejar generar.
    exige: str = ""


PLANTILLAS: tuple[Plantilla, ...] = (
    Plantilla(
        clave="mensual",
        nombre="Informe mensual completo",
        descripcion=("El informe de siempre, palabra por palabra: el mismo documento que "
                     "la ejecución programada envía por correo el último día del mes, con "
                     "todos sus apartados y toda la organización."),
        para_quien="Dirección y Redes; es el informe oficial del mes.",
        apartados=APARTADOS_MENSUAL,
        periodo="mes", alcance="organizacion",
        titulo="Informe mensual de inteligencia de amenazas"),
    Plantilla(
        clave="direccion",
        nombre="Resumen para dirección",
        descripcion=("Cuatro apartados y ninguna ficha técnica: situación, cifras del "
                     "periodo y qué se recomienda hacer. Pensado para leerse entero en "
                     "una reunión."),
        para_quien="Gerencia y comités: decide, no ejecuta.",
        apartados=("portada", "resumen_ejecutivo", "panorama", "conclusiones"),
        periodo="mes", alcance="organizacion",
        titulo="Resumen de ciberseguridad para dirección"),
    Plantilla(
        clave="remediacion",
        nombre="Informe técnico de remediación",
        descripcion=("La cola de trabajo: qué actualizar en cada servidor y equipo de "
                     "cómputo, hasta qué versión y qué vulnerabilidades cierra cada "
                     "actualización. Sin panorama ni evolución histórica."),
        para_quien="Redes y Mantenimiento: ejecutan.",
        apartados=("portada", "indice", "activos", "remediacion", "conclusiones"),
        periodo="mes", alcance="organizacion",
        titulo="Plan de actualizaciones pendientes"),
    Plantilla(
        clave="proceso",
        nombre="Informe por proceso",
        descripcion=("Todo acotado a un proceso: sus activos, sus amenazas "
                     "confirmadas y su cola de actualizaciones. Elija el proceso en el "
                     "formulario."),
        para_quien="El responsable del proceso y quien le da soporte.",
        apartados=("portada", "resumen_ejecutivo", "panorama", "activos", "remediacion",
                   "conclusiones"),
        periodo="mes", alcance="proceso", exige="proceso",
        titulo="Informe de ciberseguridad del proceso"),
    Plantilla(
        clave="kev",
        nombre="Vulnerabilidades con explotación activa",
        descripcion=("Solo las del catálogo KEV de CISA (explotación activa confirmada), "
                     "en lo que va de año: ficha por amenaza, activos afectados y "
                     "qué actualizar. Es lo que se atiende primero."),
        para_quien="Quien decide qué se parchea esta semana.",
        apartados=("portada", "resumen_ejecutivo", "activos", "prioritarias",
                   "remediacion", "conclusiones"),
        periodo="anio", alcance="kev",
        titulo="Vulnerabilidades con explotación activa confirmada"),
    Plantilla(
        clave=PLANTILLA_EJECUTIVA,
        nombre="Informe ejecutivo del mes (diez páginas)",
        descripcion=("Un documento corto para gerencia: las cifras del mes, la "
                     "comparación con el mes anterior y con el mismo mes del año pasado, "
                     "el avance mes a mes entre lo detectado y lo remediado, y tres o "
                     "cuatro recomendaciones. Sin fichas técnicas, sin nombres de "
                     "paquetes y sin órdenes que ejecutar; nunca pasa de diez páginas."),
        para_quien="Gerencia y comités de dirección: quieren la cifra, la tendencia y la "
                   "decisión, no el detalle técnico.",
        apartados=APARTADOS_EJECUTIVO,
        periodo="mes", alcance="organizacion",
        titulo="Informe ejecutivo mensual de ciberseguridad"),
    Plantilla(
        clave="activo",
        nombre="Informe de un activo",
        descripcion=("Todo lo que se sabe de una sola máquina: sus vulnerabilidades "
                     "confirmadas, sus fichas y su cola de actualizaciones. Elija el "
                     "activo en el formulario."),
        para_quien="Quien administra ese servidor o ese equipo de cómputo.",
        apartados=("portada", "resumen_ejecutivo", "activos", "prioritarias",
                   "remediacion", "conclusiones"),
        periodo="anio", alcance="activo", exige="activo",
        titulo="Informe de seguridad del activo"),
)

#: Clave del modo «sin plantilla» (2026-09-10). El usuario pidió «una opción para crear
#: informes completamente personalizados sin depender de una plantilla»: no es una
#: plantilla más con otros apartados, es EMPEZAR DE CERO. Por eso no está en
#: :data:`PLANTILLAS` (la rejilla de puntos de partida) y sus apartados son la tupla
#: vacía: nada viene marcado y la persona elige todo. Sí está en
#: :data:`PLANTILLA_POR_CLAVE` para que ``?plantilla=personalizado`` se valide como
#: cualquier otra clave y para que el nombre del fichero y la auditoría la reconozcan.
PLANTILLA_LIBRE = "personalizado"

PERSONALIZADA = Plantilla(
    clave=PLANTILLA_LIBRE,
    nombre="Informe personalizado (empezar de cero)",
    descripcion=("Sin plantilla y sin nada preseleccionado: usted elige el periodo, el "
                 "alcance, las severidades y, uno a uno, los apartados que quiere que "
                 "lleve el documento. Cualquier combinación vale y la vista previa se "
                 "actualiza sola conforme elige."),
    para_quien="Quien sabe exactamente qué quiere contar y no encuentra su informe entre "
               "las plantillas.",
    apartados=(),
    periodo="mes", alcance="organizacion",
    titulo="Informe de ciberseguridad a medida")

PLANTILLA_POR_CLAVE: dict[str, Plantilla] = {p.clave: p for p in PLANTILLAS}
PLANTILLA_POR_CLAVE[PERSONALIZADA.clave] = PERSONALIZADA
PLANTILLA_DEFECTO = "mensual"


# --------------------------------------------------------------------------
# Utilidades de fecha y texto
# --------------------------------------------------------------------------
def hoy() -> date:
    """La fecha de hoy en UTC, que es la zona en la que se guardan las marcas."""
    return datetime.now(timezone.utc).date()


def fecha_es(valor: date) -> str:
    """'2026-08-01' -> '1 de agosto de 2026'."""
    return f"{valor.day} de {MESES_ES[valor.month - 1]} de {valor.year}"


def mes_es(mes: str) -> str:
    """'2026-08' -> 'agosto de 2026'."""
    if not mes or not _RE_MES.match(str(mes)):
        return str(mes or "")
    anio, m = str(mes).split("-")
    return f"{MESES_ES[int(m) - 1]} de {anio}"


def _fin_de_mes(anio: int, mes: int) -> date:
    """El último día de ``mes`` (1-12), aceptando ``mes`` > 12 para sumar meses sin
    salirse del año (trimestre y semestre lo usan para su último mes)."""
    anio_norm = anio + (mes - 1) // 12
    mes_norm = (mes - 1) % 12 + 1
    siguiente = date(anio_norm + (mes_norm == 12), (mes_norm % 12) + 1, 1)
    return siguiente - timedelta(days=1)


#: «1.er trimestre», no «1.º trimestre»: primero y tercero se apocopan ante un nombre
#: masculino singular (primer, tercer); segundo y cuarto no. Un único origen para esta
#: regla, para que la etiqueta del periodo y las opciones del formulario digan lo mismo.
_ORDINAL_MASC = {1: "1.er", 2: "2.º", 3: "3.er", 4: "4.º"}
_MESES_TRIMESTRE = ("enero-marzo", "abril-junio", "julio-septiembre", "octubre-diciembre")
_MESES_SEMESTRE = ("enero-junio", "julio-diciembre")


def etiqueta_trimestre(anio: int, t: int) -> str:
    return f"{_ORDINAL_MASC[t]} trimestre de {anio} ({_MESES_TRIMESTRE[t - 1]})"


def etiqueta_semestre(anio: int, s: int) -> str:
    return f"{_ORDINAL_MASC[s]} semestre de {anio} ({_MESES_SEMESTRE[s - 1]})"


def _trimestre_valido(valor: str) -> Optional[tuple[int, int]]:
    """'2026-T3' -> (2026, 3), o None si no tiene esa forma exacta."""
    m = _RE_TRIMESTRE.match(str(valor or ""))
    return (int(m.group(1)), int(m.group(2))) if m else None


def _semestre_valido(valor: str) -> Optional[tuple[int, int]]:
    """'2026-S1' -> (2026, 1), o None si no tiene esa forma exacta."""
    m = _RE_SEMESTRE.match(str(valor or ""))
    return (int(m.group(1)), int(m.group(2))) if m else None


def _fecha(valor: Any) -> Optional[date]:
    texto = str(valor or "").strip()
    if not _RE_FECHA.match(texto):
        return None
    try:
        return date.fromisoformat(texto)
    except ValueError:
        return None


def _entero(valor: Any, defecto: int, minimo: int, maximo: int) -> int:
    try:
        n = int(str(valor).strip())
    except (TypeError, ValueError):
        return defecto
    return max(minimo, min(maximo, n))


def _renombrar_alias(sql: str, viejo: str, nuevo: str) -> str:
    """Cambia el alias de tabla de un fragmento SQL escrito por el propio código.

    ``queries.filtro_parque`` devuelve condiciones con el alias ``a`` pegado a paréntesis
    y a funciones («COALESCE(NULLIF(a.proceso,''),'')»), así que un ``replace(" a.")`` se
    dejaba la mitad. Se usa solo con fragmentos internos, nunca con texto de la persona.
    """
    return re.sub(rf"\b{re.escape(viejo)}\.", f"{nuevo}.", sql)


def _verdadero(valor: Any) -> bool:
    """¿La casilla oculta que acompaña a los apartados venía marcada?"""
    return str(valor or "").strip().lower() in ("1", "true", "si", "sí", "on")


def limpiar_texto(valor: Any, *, maximo: int) -> str:
    """El texto de la persona, recortado y sin caracteres de control."""
    texto = _RE_TEXTO_PROHIBIDO.sub(" ", str(valor or ""))
    texto = re.sub(r"\s+", " ", texto).strip()
    return texto[:maximo]


# --------------------------------------------------------------------------
# La selección
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Seleccion:
    """Qué informe se quiere. Inmutable: se construye validada y ya no cambia."""
    plantilla: str = PLANTILLA_DEFECTO
    #: Periodo
    periodo: str = "mes"
    mes: str = ""
    desde: str = ""
    hasta: str = ""
    dias: int = DIAS_ULTIMOS_DEFECTO
    #: Calendario fijo (2026-11-17): «AAAA» para el año completo, «AAAA-T#» (1-4) para
    #: el trimestre y «AAAA-S#» (1-2) para el semestre. Vacío con periodo «anio» sigue
    #: significando «el año en curso hasta hoy», exactamente como antes de que existiera
    #: este campo: no cambia el comportamiento de ningún enlace guardado.
    anio_valor: str = ""
    trimestre: str = ""
    semestre: str = ""
    #: Contenido
    apartados: tuple[str, ...] = APARTADOS_MENSUAL
    severidades: tuple[str, ...] = SEVERIDADES
    #: Alcance
    alcance: str = "organizacion"
    proceso: str = ""
    tipo: str = ""
    activo_id: int = 0
    tecnologia: str = ""
    #: Tipo de máquina al que está acotado el perfil de la sesión. Manda sobre todo lo
    #: demás y no se puede pedir desde la dirección web.
    origen_perfil: str = ""
    #: Portada
    titulo: str = ""
    destinatario: str = ""
    nota: str = ""

    # -- construcción ------------------------------------------------------
    @classmethod
    def desde_parametros(cls, params: Mapping[str, Any], *,
                         meses_disponibles: Iterable[str] = (),
                         origen_perfil: Optional[str] = None) -> "Seleccion":
        """Una selección validada a partir de los parámetros de la dirección web.

        Nada se acepta tal cual: el periodo, el alcance, las severidades y los apartados
        se cotejan con listas blancas, los números se acotan y los textos se recortan. Lo
        que no se entienda cae al valor de la plantilla elegida, de forma que una
        dirección manipulada produce el informe de la plantilla, nunca un error ni una
        consulta rara.
        """
        meses = [m for m in meses_disponibles if _RE_MES.match(str(m))]
        plantilla = PLANTILLA_POR_CLAVE.get(
            str(params.get("plantilla") or "").strip(), PLANTILLA_POR_CLAVE[PLANTILLA_DEFECTO])
        # ¿Vienen parámetros propios o es la primera visita con una plantilla? En la
        # primera visita mandan los valores de la plantilla.
        propios = any(k in params for k in (
            "periodo", "mes", "desde", "hasta", "dias", "alcance", "sev", "apartado",
            "titulo", "destinatario", "nota", "proceso", "tipo", "activo", "tecnologia",
            "anio_valor", "trimestre", "semestre"))

        periodo = str(params.get("periodo") or "").strip()
        if periodo not in CLASES_PERIODO:
            periodo = plantilla.periodo

        mes = str(params.get("mes") or "").strip()
        if not _RE_MES.match(mes):
            mes = meses[0] if meses else hoy().strftime("%Y-%m")

        anio_valor = str(params.get("anio_valor") or "").strip()
        if not _RE_ANIO.match(anio_valor):
            anio_valor = ""

        trimestre = str(params.get("trimestre") or "").strip()
        if _trimestre_valido(trimestre) is None:
            trimestre = ""

        semestre = str(params.get("semestre") or "").strip()
        if _semestre_valido(semestre) is None:
            semestre = ""

        hoy_ = hoy()
        desde = _fecha(params.get("desde"))
        hasta = _fecha(params.get("hasta"))
        if desde is None or hasta is None:
            desde, hasta = hoy_ - timedelta(days=29), hoy_
        if hasta < desde:
            desde, hasta = hasta, desde
        if (hasta - desde).days > DIAS_MAXIMO:
            desde = hasta - timedelta(days=DIAS_MAXIMO)

        dias = _entero(params.get("dias"), DIAS_ULTIMOS_DEFECTO, 1, DIAS_ULTIMOS_MAXIMO)

        alcance = str(params.get("alcance") or "").strip()
        if alcance not in ALCANCES:
            alcance = plantilla.alcance

        severidades = tuple(s for s in SEVERIDADES
                            if s in set(cls._lista(params, "sev")))
        if not severidades:
            severidades = plantilla.severidades if not propios else SEVERIDADES

        # «apartados_enviados» distingue «no me han dicho nada de los apartados» (primera
        # visita: mandan los de la plantilla) de «me los han dicho y no hay ninguno»
        # (la persona los ha desmarcado todos, o ha empezado de cero sin plantilla). Sin
        # esa marca, quitar la última casilla volvería a marcar los once del informe
        # mensual y la vista previa mentiría (2026-09-10).
        apartados = ordenar_apartados(cls._lista(params, "apartado"))
        if not apartados and not _verdadero(params.get("apartados_enviados")):
            apartados = ordenar_apartados(plantilla.apartados)

        # El informe ejecutivo mensual (2026-09-15) NO es configurable: su estructura, sus
        # severidades y su periodo son fijos, y eso es justamente lo que garantiza que no
        # pase de diez páginas ni deje de ser un documento de gerencia. Se fuerzan aquí,
        # después de validar, para que ninguna dirección web manipulada pueda añadirle el
        # anexo, quitarle la comparación ni pedirlo de un intervalo de fechas.
        if plantilla.clave == PLANTILLA_EJECUTIVA:
            apartados = APARTADOS_EJECUTIVO
            severidades = SEVERIDADES
            periodo = "mes"
            alcance = "organizacion"
        elif es_ejecutivo(apartados):
            # Apartados del ejecutivo pedidos desde otra plantilla: se descartan.
            apartados = ordenar_apartados(plantilla.apartados)

        tipo = str(params.get("tipo") or "").strip()
        if tipo not in TIPOS_MAQUINA:
            tipo = ""
        # El alcance del perfil manda siempre: un perfil de Redes no puede pedir un
        # informe de equipos de cómputo por mucho que lo escriba en la dirección.
        propio = str(origen_perfil or "").strip()
        propio = propio if propio in TIPOS_MAQUINA else ""
        if propio:
            tipo = propio

        tecnologia = str(params.get("tecnologia") or "").strip().lower()
        if not _RE_SLUG.match(tecnologia):
            tecnologia = ""

        return cls(
            plantilla=plantilla.clave,
            periodo=periodo, mes=mes,
            desde=desde.isoformat(), hasta=hasta.isoformat(), dias=dias,
            anio_valor=anio_valor, trimestre=trimestre, semestre=semestre,
            apartados=apartados, severidades=severidades,
            alcance=alcance,
            proceso=limpiar_texto(params.get("proceso"), maximo=120),
            tipo=tipo,
            activo_id=_entero(params.get("activo"), 0, 0, 2_000_000_000),
            tecnologia=tecnologia,
            origen_perfil=propio,
            titulo=limpiar_texto(params.get("titulo"), maximo=120) or plantilla.titulo,
            destinatario=limpiar_texto(params.get("destinatario"), maximo=120),
            nota=limpiar_texto(params.get("nota"), maximo=600),
        )

    @staticmethod
    def _lista(params: Mapping[str, Any], clave: str) -> list[str]:
        """Los valores de un parámetro repetido (``?sev=Critical&sev=High``).

        Acepta tanto un ``MultiDict`` de Flask como un diccionario corriente con una
        lista, para que las pruebas no necesiten levantar una petición.
        """
        obtener = getattr(params, "getlist", None)
        if callable(obtener):
            valores = obtener(clave)
        else:
            valor = params.get(clave)
            valores = valor if isinstance(valor, (list, tuple)) else ([valor] if valor else [])
        return [str(v).strip() for v in valores if str(v or "").strip()]

    # -- vuelta a la dirección web ----------------------------------------
    def a_parametros(self) -> dict[str, Any]:
        """Los parámetros con los que se reconstruye esta selección.

        Es el sustituto de guardar plantillas propias en la base: el enlace ES la
        plantilla guardada. Se omite lo que no aplica al periodo o al alcance elegidos
        para que la dirección sea legible.
        """
        p: dict[str, Any] = {"plantilla": self.plantilla, "periodo": self.periodo,
                             "alcance": self.alcance,
                             "sev": list(self.severidades),
                             "apartado": list(self.apartados)}
        if not self.apartados:
            # Sin esta marca, el enlace copiado reconstruiría los apartados de la
            # plantilla en vez de la selección vacía que se está viendo.
            p["apartados_enviados"] = 1
        if self.periodo == "mes":
            p["mes"] = self.mes
        elif self.periodo == "intervalo":
            p["desde"], p["hasta"] = self.desde, self.hasta
        elif self.periodo == "dias":
            p["dias"] = self.dias
        elif self.periodo == "trimestre":
            p["trimestre"] = self.trimestre
        elif self.periodo == "semestre":
            p["semestre"] = self.semestre
        elif self.periodo == "anio" and self.anio_valor:
            p["anio_valor"] = self.anio_valor
        if self.alcance == "proceso" and self.proceso:
            p["proceso"] = self.proceso
        if self.alcance == "tipo" and self.tipo:
            p["tipo"] = self.tipo
        if self.alcance == "activo" and self.activo_id:
            p["activo"] = self.activo_id
        if self.alcance == "tecnologia" and self.tecnologia:
            p["tecnologia"] = self.tecnologia
        for clave, valor in (("titulo", self.titulo), ("destinatario", self.destinatario),
                             ("nota", self.nota)):
            if valor:
                p[clave] = valor
        return p

    # -- periodo -----------------------------------------------------------
    def _anio_elegido(self, hoy_: date) -> int:
        """El año de 'anio': el que se haya elegido, o el actual por omisión.

        Con el mismo valor de siempre (sin elegir ninguno) da EXACTAMENTE el año actual,
        así que un enlace guardado antes de que existiera esta opción sigue funcionando
        igual (2026-11-17).
        """
        if self.anio_valor and _RE_ANIO.match(self.anio_valor):
            return int(self.anio_valor)
        return hoy_.year

    def rango(self) -> tuple[date, date]:
        """Primer y último día del periodo, los dos incluidos."""
        hoy_ = hoy()
        if self.periodo == "mes":
            anio, mes = int(self.mes[:4]), int(self.mes[5:7])
            return date(anio, mes, 1), _fin_de_mes(anio, mes)
        if self.periodo == "trimestre":
            partes = _trimestre_valido(self.trimestre)
            if partes is None:
                return date(hoy_.year, 1, 1), hoy_
            anio, t = partes
            primer_mes = 3 * t - 2
            return date(anio, primer_mes, 1), min(_fin_de_mes(anio, primer_mes + 2), hoy_)
        if self.periodo == "semestre":
            partes = _semestre_valido(self.semestre)
            if partes is None:
                return date(hoy_.year, 1, 1), hoy_
            anio, s = partes
            primer_mes = 6 * s - 5
            return date(anio, primer_mes, 1), min(_fin_de_mes(anio, primer_mes + 5), hoy_)
        if self.periodo == "anio":
            anio = self._anio_elegido(hoy_)
            return date(anio, 1, 1), min(date(anio, 12, 31), hoy_)
        if self.periodo == "intervalo":
            return (_fecha(self.desde) or hoy_, _fecha(self.hasta) or hoy_)
        if self.periodo == "dias":
            return hoy_ - timedelta(days=self.dias - 1), hoy_
        return date(hoy_.year, 1, 1), hoy_

    def etiqueta_periodo(self) -> str:
        """El periodo escrito para una persona."""
        hoy_ = hoy()
        desde, hasta = self.rango()
        if self.periodo == "mes":
            return mes_es(self.mes)
        if self.periodo == "dias":
            return (f"los últimos {self.dias} días "
                    f"(del {fecha_es(desde)} al {fecha_es(hasta)})")
        if self.periodo == "trimestre":
            partes = _trimestre_valido(self.trimestre)
            if partes is not None:
                anio, t = partes
                return f"el {etiqueta_trimestre(anio, t)}"
        if self.periodo == "semestre":
            partes = _semestre_valido(self.semestre)
            if partes is not None:
                anio, s = partes
                return f"el {etiqueta_semestre(anio, s)}"
        if self.periodo == "anio":
            anio = self._anio_elegido(hoy_)
            if anio == hoy_.year:
                return f"el año {anio} hasta el {fecha_es(hasta)}"
            return f"el año {anio} completo"
        return f"del {fecha_es(desde)} al {fecha_es(hasta)}"

    def mes_representativo(self) -> str:
        """El mes «AAAA-MM» con el que se rotula el pie del documento y se archiva.

        Para un periodo que no es un mes se usa el mes del último día: es el criterio con
        el que la organización archiva sus informes.
        """
        if self.periodo == "mes":
            return self.mes
        return self.rango()[1].strftime("%Y-%m")

    # -- alcance -----------------------------------------------------------
    def alcance_pendiente(self) -> str:
        """Qué falta para saber DE QUÉ habla el informe, o cadena vacía si ya se sabe.

        Es la parte de :meth:`completa` que impide siquiera contar: sin el proceso o sin
        el activo elegido, las cifras de la vista previa serían las de toda la
        organización y engañarían. Lo demás (apartados, severidades) no cambia el
        recuento, así que la vista previa sí puede darlo mientras se elige.
        """
        if self.alcance == "proceso" and not self.proceso:
            return "Elija el proceso de negocio del que quiere el informe."
        if self.alcance == "activo" and not self.activo_id:
            return "Elija el activo del que quiere el informe."
        if self.alcance == "tecnologia" and not self.tecnologia:
            return "Elija la tecnología de la que quiere el informe."
        if self.alcance == "tipo" and not self.tipo:
            return "Elija el tipo de máquina: servidores o equipos de cómputo."
        return ""

    def completa(self) -> tuple[bool, str]:
        """¿Se puede generar? (True, '') o (False, 'qué falta') en español."""
        if self.alcance == "proceso" and not self.proceso:
            return False, "Elija el proceso de negocio del que quiere el informe."
        if self.alcance == "activo" and not self.activo_id:
            return False, "Elija el activo del que quiere el informe."
        if self.alcance == "tecnologia" and not self.tecnologia:
            return False, "Elija la tecnología de la que quiere el informe."
        if self.alcance == "tipo" and not self.tipo:
            return False, "Elija el tipo de máquina: servidores o equipos de cómputo."
        if not self.apartados:
            return False, "Marque al menos un apartado para el documento."
        if not self.severidades:
            return False, "Marque al menos una severidad."
        return True, ""

    def es_ejecutivo(self) -> bool:
        """True si lo que se pide es el informe ejecutivo mensual de diez páginas.

        Lo deciden los apartados, no la clave de la plantilla: así la vista y el
        generador miran lo mismo que se va a escribir en el documento.
        """
        return es_ejecutivo(self.apartados)

    def es_mensual_clasico(self) -> bool:
        """True si esto es EXACTAMENTE el informe mensual de siempre.

        En ese caso la generación no pasa por ningún filtro: llama a
        ``report.construir_documento(conn, mes, cfg=cfg)`` sin argumentos nuevos, que es
        el mismo camino que recorre la ejecución programada. Así el documento no puede
        diferir ni en una coma del que se envía por correo.
        """
        return (self.periodo == "mes"
                and self.alcance == "organizacion"
                and not self.origen_perfil
                and tuple(self.severidades) == SEVERIDADES
                and tuple(self.apartados) == ordenar_apartados(APARTADOS_MENSUAL)
                and not self.titulo_personalizado()
                and not self.destinatario and not self.nota)

    def titulo_personalizado(self) -> bool:
        """True si el título no es el del informe mensual de siempre."""
        return bool(self.titulo) and self.titulo != PLANTILLA_POR_CLAVE["mensual"].titulo

    # -- modo: plantilla, plantilla modificada o de cero -------------------
    def sin_plantilla(self) -> bool:
        """True si se pidió expresamente empezar de cero, sin ninguna plantilla."""
        return self.plantilla == PLANTILLA_LIBRE

    def personalizado(self) -> bool:
        """True si lo que hay en pantalla ya NO es la plantilla que dice ser.

        Se comparan las decisiones que definen el documento: qué apartados lleva, qué
        severidades, qué clase de periodo, qué clase de alcance y el título. NO cuentan
        el mes concreto, ni el proceso o el activo elegidos, ni el destinatario ni la
        nota: el informe mensual de agosto sigue siendo el informe mensual, y elegir el
        proceso que la plantilla «por proceso» pide es completarla, no cambiarla.
        """
        if self.sin_plantilla():
            return True
        p = PLANTILLA_POR_CLAVE[self.plantilla]
        return (self.periodo != p.periodo
                or self.alcance != p.alcance
                or tuple(self.severidades) != tuple(p.severidades)
                or tuple(self.apartados) != ordenar_apartados(p.apartados)
                or (self.titulo or "") != (p.titulo or ""))

    def modo(self) -> str:
        """«libre» (de cero), «derivado» (una plantilla ya cambiada) o «plantilla»."""
        if self.sin_plantilla():
            return "libre"
        return "derivado" if self.personalizado() else "plantilla"

    def etiqueta_modo(self) -> str:
        """Lo que se escribe en pantalla para que nadie dude de qué está armando."""
        nombre = PLANTILLA_POR_CLAVE[self.plantilla].nombre
        if self.sin_plantilla():
            return "Informe personalizado, sin plantilla"
        if self.personalizado():
            return f"Informe personalizado a partir de la plantilla «{nombre}»"
        return f"Plantilla «{nombre}», sin cambios"

    # -- SQL ---------------------------------------------------------------
    def where_periodo(self, alias: str = "t") -> tuple[str, list]:
        """Condición del periodo sobre ``threats`` (con « AND » inicial)."""
        if self.periodo == "mes":
            return f" AND {alias}.month = ?", [self.mes]
        desde, hasta = self.rango()
        # Comparación de texto sobre la marca ISO («2026-09-10T12:36:44Z»): usa el índice
        # idx_threats_seen, cosa que date(first_seen_at) no haría. El límite superior es
        # exclusivo y vale el día siguiente, así que el último día entra entero.
        return (f" AND {alias}.first_seen_at >= ? AND {alias}.first_seen_at < ?",
                [desde.isoformat(), (hasta + timedelta(days=1)).isoformat()])

    def where_severidad(self, alias: str = "t") -> tuple[str, list]:
        """Condición de severidad. La Baja jamás entra, se pida lo que se pida."""
        sevs = [s for s in self.severidades if s in SEVERIDADES] or list(SEVERIDADES)
        marcas = ",".join("?" * len(sevs))
        return f" AND {alias}.severity IN ({marcas})", list(sevs)

    def where_alcance(self, alias: str = "t") -> tuple[str, list]:
        """Condición del alcance sobre ``threats`` (con « AND » inicial).

        Para un proceso, un tipo de máquina o un activo el alcance se comprueba con un
        EXISTS contra ``aplicabilidad``: la amenaza entra si algún activo presente del
        ámbito tiene confirmada su versión vulnerable. Para una tecnología, con un EXISTS
        contra ``threat_technologies``. El alcance del perfil se suma siempre.
        """
        if self.alcance == "tecnologia":
            # Alias propios («_alc») en los EXISTS del alcance: la misma condición se pega
            # a consultas que ya usan «tt», «tc», «ap» y «a» para otra cosa, y un alias
            # repetido dentro de la subconsulta taparía el de fuera.
            sql = (f" AND EXISTS (SELECT 1 FROM threat_technologies tt_alc "
                   f"JOIN technologies tc_alc ON tc_alc.id = tt_alc.technology_id "
                   f"WHERE tt_alc.threat_id = {alias}.id AND tc_alc.slug = ?)")
            params: list[Any] = [self.tecnologia]
            extra, p_extra = self._where_parque(alias, proceso=None, origen=self.origen_perfil,
                                                activo_id=0)
            return sql + extra, params + p_extra
        if self.alcance == "kev":
            extra, p_extra = self._where_parque(alias, proceso=None, origen=self.origen_perfil,
                                                activo_id=0)
            return f" AND {alias}.in_kev = 1" + extra, p_extra
        if self.alcance == "proceso":
            return self._where_parque(alias, proceso=self.proceso,
                                      origen=self.origen_perfil, activo_id=0)
        if self.alcance == "tipo":
            return self._where_parque(alias, proceso=None,
                                      origen=self.origen_perfil or self.tipo, activo_id=0)
        if self.alcance == "activo":
            return self._where_parque(alias, proceso=None, origen=self.origen_perfil,
                                      activo_id=self.activo_id)
        return self._where_parque(alias, proceso=None, origen=self.origen_perfil, activo_id=0)

    @staticmethod
    def _where_parque(alias: str, *, proceso: Optional[str], origen: Optional[str],
                      activo_id: int) -> tuple[str, list]:
        """EXISTS contra el parque real, o cadena vacía si no hay nada que acotar.

        El recorte por proceso y por tipo de máquina lo escribe ``queries.filtro_parque``,
        que es el mismo que usan la página de Amenazas y la de Activos: así un informe «de
        Impuestos» cuenta exactamente los activos que cuenta la pantalla de Impuestos.
        """
        extra, params = queries.filtro_parque(proceso or None,
                                              origen if origen in TIPOS_MAQUINA else None)
        if activo_id:
            extra += " AND a.id = ?"
            params = [*params, int(activo_id)]
        if not extra:
            return "", []
        extra = _renombrar_alias(extra, "a", "a_alc")
        return (f" AND EXISTS (SELECT 1 FROM aplicabilidad ap_alc"
                f" JOIN activos a_alc ON a_alc.id = ap_alc.activo_id"
                f" WHERE ap_alc.threat_id = {alias}.id AND ap_alc.veredicto = 'afectado'"
                f" AND a_alc.presente = 1{extra})", list(params))

    def where_activos(self, alias: str = "a") -> tuple[str, list]:
        """Condición del alcance sobre la tabla ``activos`` (con « AND » inicial)."""
        proceso = self.proceso if self.alcance == "proceso" else None
        origen = self.origen_perfil or (self.tipo if self.alcance == "tipo" else None)
        extra, params = queries.filtro_parque(proceso or None,
                                              origen if origen in TIPOS_MAQUINA else None)
        if alias != "a":
            extra = _renombrar_alias(extra, "a", alias)
        if self.alcance == "activo" and self.activo_id:
            extra += f" AND {alias}.id = ?"
            params = [*params, int(self.activo_id)]
        return extra, list(params)

    def where(self, alias: str = "t") -> tuple[str, list]:
        """Toda la selección sobre ``threats``: periodo, severidad y alcance."""
        partes, params = [], []
        for sql, p in (self.where_periodo(alias), self.where_severidad(alias),
                       self.where_alcance(alias)):
            partes.append(sql)
            params.extend(p)
        return "".join(partes), params

    # -- filtros para la cola de remediación -------------------------------
    def filtros_remediacion(self) -> dict[str, Any]:
        """Los argumentos con los que se pide la cola de actualizaciones.

        La cola es la situación de HOY (lo que está pendiente de instalar), no la foto del
        periodo: el periodo no se le aplica, y el documento lo dice con todas las letras.
        """
        severidad = None
        if len(self.severidades) == 1:
            severidad = self.severidades[0].lower()
        return {
            "proceso": self.proceso if self.alcance == "proceso" else None,
            "origen": self.origen_perfil or (self.tipo if self.alcance == "tipo" else None),
            "activo_id": self.activo_id if self.alcance == "activo" else None,
            "severidad": severidad,
        }

    # -- nombre del fichero ------------------------------------------------
    def nombre_fichero(self) -> str:
        """«informe_direccion_2026-08.docx»: solo claves internas y fechas.

        Nunca se construye con el título ni con ningún otro texto de la persona: el nombre
        del fichero viaja en una cabecera HTTP y no se le pone dentro nada que no sea de
        una lista blanca.
        """
        desde, hasta = self.rango()
        if self.periodo == "mes":
            sufijo = self.mes
        elif self.periodo == "anio":
            sufijo = str(hasta.year)
        else:
            sufijo = f"{desde.isoformat()}_{hasta.isoformat()}"
        plantilla = self.plantilla if self.plantilla in PLANTILLA_POR_CLAVE else PLANTILLA_DEFECTO
        return f"informe_{plantilla}_{sufijo}.docx"

    # -- resumen para la auditoría ----------------------------------------
    def resumen_auditoria(self) -> str:
        """Una línea con la plantilla, el periodo, el alcance y los apartados."""
        sevs = ", ".join(SEVERIDAD_ES_PLURAL[s] for s in self.severidades)
        return (f"plantilla «{PLANTILLA_POR_CLAVE[self.plantilla].nombre}»; "
                f"periodo: {self.etiqueta_periodo()}; "
                f"alcance: {self.clave_alcance_texto()}; "
                f"severidades: {sevs}; "
                f"apartados: {', '.join(self.apartados)}")

    def clave_alcance_texto(self) -> str:
        """El alcance en palabras, sin consultar la base (usa las claves internas)."""
        if self.alcance == "proceso":
            return f"proceso de negocio «{self.proceso}»"
        if self.alcance == "tipo":
            return TIPOS_MAQUINA.get(self.tipo, "servidores y equipos de cómputo")
        if self.alcance == "activo":
            return f"activo número {self.activo_id}"
        if self.alcance == "tecnologia":
            return f"tecnología «{self.tecnologia}»"
        if self.alcance == "kev":
            return "solo con explotación activa confirmada (catálogo KEV de CISA)"
        if self.origen_perfil:
            return TIPOS_MAQUINA[self.origen_perfil]
        return "toda la organización"

    def con(self, **cambios: Any) -> "Seleccion":
        """Una copia con algún campo cambiado (las selecciones son inmutables)."""
        return replace(self, **cambios)


# --------------------------------------------------------------------------
# Consultas acotadas por la selección
# --------------------------------------------------------------------------
def estadisticas(conn: sqlite3.Connection, sel: Seleccion) -> dict[str, Any]:
    """Las mismas cifras que ``queries.estadisticas_mes``, acotadas por la selección."""
    where, params = sel.where("t")
    fila = conn.execute(
        f"""SELECT COUNT(*) AS total,
                   SUM(t.severity='Critical') AS criticas,
                   SUM(t.severity='High')     AS altas,
                   SUM(t.severity='Medium')   AS medias,
                   0 AS bajas,
                   SUM(t.in_kev=1)            AS en_kev,
                   SUM(t.cve IS NOT NULL)     AS con_cve,
                   SUM(t.severity_source='nvd')       AS sev_nvd,
                   SUM(t.severity_source='heuristic') AS sev_heuristica,
                   AVG(NULLIF(t.cvss_score,0))        AS cvss_medio,
                   MAX(t.cvss_score)                  AS cvss_max
              FROM threats t WHERE 1=1{where}""", params).fetchone()
    total = int(fila["total"] or 0)
    stats = {k: (fila[k] or 0) for k in fila.keys()}
    stats["total"] = total
    stats["cvss_medio"] = round(float(fila["cvss_medio"]), 1) if fila["cvss_medio"] else None
    stats["cvss_max"] = fila["cvss_max"]
    stats["pct_criticas"] = round(stats["criticas"] * 100.0 / total, 1) if total else 0.0
    stats["pct_altas"] = round(stats["altas"] * 100.0 / total, 1) if total else 0.0
    stats["pct_con_cvss_real"] = round(stats["sev_nvd"] * 100.0 / total, 1) if total else 0.0
    stats["month"] = sel.mes_representativo()
    return stats


def amenazas(conn: sqlite3.Connection, sel: Seleccion, *,
             limite: Optional[int] = None) -> list[dict]:
    """Las amenazas de la selección, en el mismo formato que ``queries.del_mes``.

    Se reutilizan las piezas internas de :mod:`threatintel.queries` (las columnas
    canónicas y la carga en lote de tecnologías y fuentes) a propósito: si el informe a
    medida se construyera su propio diccionario, acabaría divergiendo del mensual en
    cuanto alguien añadiera una columna, y las fichas dirían cosas distintas para la misma
    amenaza. Aquí solo cambia el WHERE.
    """
    where, params = sel.where("t")
    sql = (f"SELECT {queries._THREAT_COLS} FROM threats t WHERE 1=1{where}"
           " ORDER BY t.relevance DESC,"
           " CASE t.severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1"
           " WHEN 'Medium' THEN 2 ELSE 3 END,"
           " COALESCE(t.cvss_score, 0) DESC, t.first_seen_at DESC")
    if limite:
        sql += " LIMIT ?"
        params = [*params, int(limite)]
    filas = conn.execute(sql, params).fetchall()
    return queries._adjuntar_relaciones(conn, [queries._fila_a_view(f) for f in filas])


def top_tecnologias(conn: sqlite3.Connection, sel: Seleccion, limite: int = 20) -> list[dict]:
    """Tecnologías del inventario más afectadas dentro de la selección."""
    where, params = sel.where("t")
    return [dict(r) for r in conn.execute(
        f"""SELECT tc.name, tc.slug, tc.version_installed, tc.criticality,
                   tc.systems_count, tc.exposure,
                   COUNT(DISTINCT tt.threat_id) AS amenazas,
                   SUM(t.severity='Critical') AS criticas,
                   SUM(t.severity='High')     AS altas,
                   SUM(t.severity='Medium')   AS medias,
                   SUM(tt.version_verdict='affected')     AS confirmadas,
                   SUM(tt.version_verdict='not_affected') AS no_aplicables,
                   SUM(tt.version_verdict='unknown')      AS sin_determinar
              FROM threat_technologies tt
              JOIN technologies tc ON tc.id = tt.technology_id
              JOIN threats t       ON t.id  = tt.threat_id
             WHERE 1=1{where}
             GROUP BY tc.id
             ORDER BY criticas DESC, altas DESC, amenazas DESC
             LIMIT ?""", [*params, int(limite)])]


def veredictos(conn: sqlite3.Connection, sel: Seleccion) -> dict[str, int]:
    """Cuántas amenazas de la selección tienen la versión confirmada, descartada o sin
    determinar, contadas como en el informe mensual (una vez por amenaza)."""
    where, params = sel.where("t")
    return {r["v"]: int(r["n"] or 0) for r in conn.execute(
        f"""SELECT tt.version_verdict AS v, COUNT(DISTINCT tt.threat_id) AS n
              FROM threat_technologies tt JOIN threats t ON t.id = tt.threat_id
             WHERE 1=1{where} GROUP BY tt.version_verdict""", params)}


def evolucion(conn: sqlite3.Connection, sel: Seleccion, meses: int = 7) -> list[dict]:
    """Serie por mes con el MISMO alcance y las mismas severidades que el informe.

    Sin el alcance, un informe de un proceso llevaría al lado la evolución de toda la
    organización y las dos cifras del mismo mes no cuadrarían.
    """
    where_sev, p_sev = sel.where_severidad("t")
    where_alc, p_alc = sel.where_alcance("t")
    hasta = sel.rango()[1].strftime("%Y-%m")
    filas = [dict(r) for r in conn.execute(
        f"""SELECT t.month AS month, COUNT(*) AS total,
                   SUM(t.severity='Critical') AS criticas,
                   SUM(t.severity='High')     AS altas,
                   SUM(t.severity='Medium')   AS medias,
                   0 AS bajas,
                   SUM(t.in_kev=1)            AS en_kev,
                   SUM(t.severity_source='nvd') AS sev_nvd,
                   SUM(t.cve IS NOT NULL)     AS con_cve
              FROM threats t WHERE t.month <= ?{where_sev}{where_alc}
             GROUP BY t.month ORDER BY t.month DESC LIMIT ?""",
        [hasta, *p_sev, *p_alc, int(meses)])]
    for fila in filas:
        for clave in ("total", "criticas", "altas", "medias", "bajas", "en_kev",
                      "sev_nvd", "con_cve"):
            fila[clave] = int(fila[clave] or 0)
        fila["cvss_medio"] = None
    return filas


def precision(conn: sqlite3.Connection, sel: Seleccion) -> dict[str, Any]:
    """Cuántas amenazas de la selección dejó fuera el filtro de alertas y por qué.

    Igual que ``report.precision_filtro``, pero sobre el periodo y el alcance elegidos.
    Aquí no se aplica el filtro de severidad: la gracia del apartado es explicar qué se
    descartó, y una de las razones es justamente la severidad.
    """
    where_per, p_per = sel.where_periodo("t")
    where_alc, p_alc = sel.where_alcance("t")
    where = f"{where_per}{where_alc}"
    params = [*p_per, *p_alc]
    motivos = {m: 0 for m in queries.MOTIVOS_EXCLUSION}
    for r in conn.execute(
            f"""SELECT t.alert_skip_reason AS m, COUNT(*) AS n FROM threats t
                 WHERE t.alert_skip_reason IS NOT NULL{where} GROUP BY 1""", params):
        if r["m"] in motivos:
            motivos[r["m"]] = int(r["n"] or 0)
    estados = {e: 0 for e in queries.ESTADOS}
    for r in conn.execute(
            f"SELECT t.estado, COUNT(*) AS n FROM threats t WHERE 1=1{where} GROUP BY 1", params):
        if r["estado"] in estados:
            estados[r["estado"]] = int(r["n"] or 0)
    total = int(conn.execute(
        f"SELECT COUNT(*) FROM threats t WHERE 1=1{where}", params).fetchone()[0] or 0)
    alertadas = int(conn.execute(
        f"SELECT COUNT(*) FROM threats t WHERE t.alerted_at IS NOT NULL{where}",
        params).fetchone()[0] or 0)
    bajas = int(conn.execute(
        f"SELECT COUNT(*) FROM threats t WHERE t.severity='Low'{where}",
        params).fetchone()[0] or 0)
    return {"motivos": motivos, "estados": estados, "total": total, "alertadas": alertadas,
            "excluidas": sum(motivos.values()), "bajas_ignoradas": bajas,
            "cerradas": estados.get("descartada", 0) + estados.get("falso_positivo", 0)}


def _dias_sin_reportar(cfg: Any) -> int:
    """Días sin enviar inventario a partir de los cuales un activo «no reporta».
    Mismo ajuste que usa OCS Inventory (``ocs_stale_days``, 30 por omisión)."""
    try:
        return int(float((cfg.get("ocs_stale_days", 30) if cfg is not None else 30) or 30))
    except (TypeError, ValueError):
        return 30


def resumen_activos(conn: sqlite3.Connection, sel: Seleccion, *, cfg: Any = None,
                    limite: int = 40) -> dict[str, Any]:
    """Lo que necesita el apartado de activos, acotado por la selección.

    Equivale a ``aplicabilidad.resumen_informe`` (que solo sabe de meses y de toda la
    organización) pero respetando el periodo, las severidades y el alcance. Devuelve las
    mismas claves para que el apartado del documento sea el mismo código.
    """
    from . import aplicabilidad

    where, params = sel.where("t")
    where_act, p_act = sel.where_activos("a")
    umbral_dias = _dias_sin_reportar(cfg)
    umbral = (datetime.now(timezone.utc) - timedelta(days=umbral_dias)
              ).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    try:
        parque = conn.execute(
            f"""SELECT COUNT(*) AS total,
                       SUM(a.origen='servidores') AS servidores,
                       SUM(a.origen='equipos') AS equipos,
                       SUM(a.ultimo_inventario IS NULL OR a.ultimo_inventario < ?) AS sin_reportar
                  FROM activos a WHERE a.presente=1{where_act}""",
            [umbral, *p_act]).fetchone()
    except sqlite3.OperationalError:
        return {}
    if not int(parque["total"] or 0):
        return {}

    soft = conn.execute(
        f"""SELECT COUNT(*) AS instalaciones,
                   SUM(s.technology_id IS NOT NULL) AS mapeadas,
                   COUNT(DISTINCT CASE WHEN s.technology_id IS NULL THEN s.nombre_norm END)
                       AS sin_clasificar
              FROM activo_software s JOIN activos a ON a.id=s.activo_id
             WHERE a.presente=1{where_act}""", p_act).fetchone()
    instalaciones = int(soft["instalaciones"] or 0)
    mapeadas = int(soft["mapeadas"] or 0)

    afectados = [dict(r) for r in conn.execute(
        f"""SELECT a.id, a.nombre, a.ip, a.origen, a.so_nombre, a.so_version, a.zona,
                   COUNT(DISTINCT ap.cve) AS cves,
                   COUNT(DISTINCT CASE WHEN t.in_kev=1 THEN ap.cve END) AS kev
              FROM aplicabilidad ap
              JOIN activos a ON a.id=ap.activo_id
              JOIN threats t ON t.id=ap.threat_id
             WHERE ap.veredicto='afectado' AND a.presente=1
               AND t.estado NOT IN ('descartada','falso_positivo'){where}{where_act}
             GROUP BY a.id ORDER BY kev DESC, cves DESC, a.nombre LIMIT ?""",
        [*params, *p_act, int(limite)])]

    totales = conn.execute(
        f"""SELECT COUNT(DISTINCT ap.activo_id) AS activos,
                   {queries.sql_vulnerabilidades()} AS vulnerabilidades,
                   {queries.sql_vulnerabilidades(condicion="t.in_kev=1")} AS vulnerabilidades_kev
              FROM aplicabilidad ap
              JOIN activos a ON a.id=ap.activo_id
              JOIN threats t ON t.id=ap.threat_id
             WHERE ap.veredicto='afectado' AND a.presente=1
               AND t.estado NOT IN ('descartada','falso_positivo'){where}{where_act}""",
        [*params, *p_act]).fetchone()

    corregidas = conn.execute(
        f"""SELECT {queries.sql_vulnerabilidades()} FROM aplicabilidad ap
              JOIN activos a ON a.id=ap.activo_id JOIN threats t ON t.id=ap.threat_id
             WHERE ap.veredicto='no_afectado' AND ap.version_corregida IS NOT NULL
               AND a.presente=1{where}{where_act}""", [*params, *p_act]).fetchone()[0]

    evaluadas = conn.execute(
        f"""SELECT COUNT(*) FROM aplicabilidad_amenaza aa JOIN threats t ON t.id=aa.threat_id
             WHERE 1=1{where}""", params).fetchone()[0]
    con_activos = conn.execute(
        f"""SELECT COUNT(*) FROM aplicabilidad_amenaza aa JOIN threats t ON t.id=aa.threat_id
             WHERE aa.afectados > 0{where}""", params).fetchone()[0]

    # Fin de soporte y hallazgos: no dependen del periodo (son el estado del parque), pero
    # sí del alcance, para que un informe de un proceso no hable de máquinas de otro.
    tabla = aplicabilidad.tabla_fin_soporte(conn)
    fuera: dict[str, dict] = {}
    proximos: dict[str, dict] = {}
    hoy_ = date.today()
    for a in conn.execute(
            f"""SELECT a.id, a.nombre, a.so_nombre, a.so_version, a.so_familia, a.so_ciclo, a.origen
                  FROM activos a WHERE a.presente=1 AND a.so_ciclo IS NOT NULL{where_act}""",
            p_act):
        est = aplicabilidad.estado_soporte(tabla, dict(a), hoy=hoy_)
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
        f"""SELECT h.tipo, COUNT(DISTINCT h.activo_id) AS activos
              FROM hallazgos_activos h JOIN activos a ON a.id=h.activo_id
             WHERE h.resuelto_at IS NULL AND a.presente=1{where_act}
             GROUP BY h.tipo ORDER BY activos DESC""", p_act)]

    return {
        "total": int(parque["total"] or 0),
        "servidores": int(parque["servidores"] or 0),
        "equipos": int(parque["equipos"] or 0),
        "sin_reportar": int(parque["sin_reportar"] or 0),
        "instalaciones": instalaciones,
        "instalaciones_mapeadas": mapeadas,
        "pct_mapeado": round(mapeadas * 100.0 / instalaciones, 1) if instalaciones else 0.0,
        "sin_clasificar": int(soft["sin_clasificar"] or 0),
        "afectados": afectados,
        "activos_afectados": int(totales["activos"] or 0),
        "vulnerabilidades": int(totales["vulnerabilidades"] or 0),
        "vulnerabilidades_kev": int(totales["vulnerabilidades_kev"] or 0),
        "corregidas": int(corregidas or 0),
        "amenazas_evaluadas": int(evaluadas or 0),
        "amenazas_con_activos": int(con_activos or 0),
        "fuera_soporte_sistemas": sorted(fuera.values(), key=lambda x: -x["activos"]),
        "proximos_fin_soporte": sorted(proximos.values(), key=lambda x: x["dias"] or 0),
        "fuera_soporte": sum(v["activos"] for v in fuera.values()),
        "hallazgos_por_tipo": hallazgos,
        "dias_sin_reportar": umbral_dias,
    }


# --------------------------------------------------------------------------
# Vista previa
# --------------------------------------------------------------------------
def vista_previa(conn: sqlite3.Connection, sel: Seleccion) -> dict[str, Any]:
    """Qué entraría en el documento, en cifras, sin construirlo.

    Solo recuentos: es lo que se pinta antes de descargar para que nadie se baje un
    documento vacío ni uno de mil páginas sin saberlo. Medido el 2026-09-10 sobre la base
    real: por debajo de 50 milisegundos en todas las plantillas.
    """
    stats = estadisticas(conn, sel)
    where, params = sel.where("t")
    where_act, p_act = sel.where_activos("a")
    activos_afectados = int(conn.execute(
        f"""SELECT COUNT(DISTINCT ap.activo_id)
              FROM aplicabilidad ap JOIN activos a ON a.id=ap.activo_id
              JOIN threats t ON t.id=ap.threat_id
             WHERE ap.veredicto='afectado' AND a.presente=1
               AND t.estado NOT IN ('descartada','falso_positivo'){where}{where_act}""",
        [*params, *p_act]).fetchone()[0] or 0)
    activos_ambito = int(conn.execute(
        f"SELECT COUNT(*) FROM activos a WHERE a.presente=1{where_act}",
        p_act).fetchone()[0] or 0)
    return {
        "amenazas": stats["total"],
        "criticas": stats["criticas"], "altas": stats["altas"], "medias": stats["medias"],
        "en_kev": stats["en_kev"], "con_cve": stats["con_cve"],
        "activos_afectados": activos_afectados,
        "activos_ambito": activos_ambito,
    }


def actualizaciones_pendientes(conn: sqlite3.Connection, sel: Seleccion) -> int:
    """Cuántas actualizaciones pendientes entrarían en la cola de remediación."""
    from . import remediacion
    filtros = sel.filtros_remediacion()
    try:
        return int(remediacion.contar_actualizaciones(conn, estado="abierta", **filtros))
    except sqlite3.OperationalError:
        return 0


# --------------------------------------------------------------------------
# Esquema del documento y estimación de tamaño (2026-09-10)
# --------------------------------------------------------------------------
def esquema(sel: Seleccion) -> list[dict]:
    """El índice que va a tener el documento: apartados en orden y con su número real.

    Es lo que responde a «previsualizarlo según vaya eligiendo opciones»: al marcar o
    desmarcar una casilla la lista se recompone y los números se corren, exactamente como
    saldrán impresos. La portada, el índice y el anexo no llevan número, igual que en el
    documento (:func:`numeros_de_apartado`).
    """
    numeros = numeros_de_apartado(sel.apartados)
    salida = []
    for clave in sel.apartados:
        apartado = APARTADO_POR_CLAVE[clave]
        salida.append({"clave": clave, "titulo": apartado.titulo,
                       "descripcion": apartado.descripcion,
                       "numero": numeros.get(clave), "pesado": apartado.pesado})
    return salida


#: Páginas que ocupa cada apartado de tamaño fijo. Medido sobre los informes generados el
#: 2026-09-10 con la base real; es una ESTIMACIÓN y así se dice en pantalla.
_PAGINAS_FIJAS = {
    "portada": 1.0, "indice": 1.0, "resumen_ejecutivo": 1.5, "panorama": 1.5,
    "tecnologias": 1.0, "activos": 2.0, "conclusiones": 1.0, "precision": 1.0,
    "metodologia": 1.0,
    # Informe ejecutivo (2026-09-15): medido sobre el documento de septiembre generado con
    # la base real, son ocho páginas en total y ninguna de ellas depende del número de
    # amenazas, porque el documento no lleva ni fichas ni anexo.
    "ej_portada": 1.0, "ej_cifras": 2.0, "ej_comparacion": 1.0, "ej_avance": 2.0,
    "ej_pendiente": 1.0, "ej_recomendacion": 1.0,
}
_PAGINAS_POR_FICHA = 0.35          # una ficha de vulnerabilidad ocupa un tercio de página
_PAGINAS_POR_FILA_ANEXO = 0.035    # unas 28 filas de tabla por página
_PAGINAS_POR_ACTUALIZACION = 0.1   # diez actualizaciones por página en la cola
#: Un .docx de la plataforma pesa unos 45 KB de armazón más kilobyte y medio por página.
_KB_BASE = 45
_KB_POR_PAGINA = 1.5
#: Coste de generación. Los apartados que recorren amenaza a amenaza o activo a activo son
#: los que mandan: el informe mensual completo (120 fichas y 250 filas de anexo) tardó 16
#: segundos el 2026-09-10 y este modelo da 15,3.
_SEGUNDOS_BASE = 0.3
_SEGUNDOS_POR_APARTADO = 0.1
_SEGUNDOS_POR_FICHA = 0.09
_SEGUNDOS_POR_FILA_ANEXO = 0.01
_SEGUNDOS_POR_ACTUALIZACION = 0.004
_SEGUNDOS_APARTADO_ACTIVOS = 0.5
#: Coste del informe ejecutivo mensual completo (2026-09-15, base real).
_SEGUNDOS_EJECUTIVO = 2.0


def estimacion(sel: Seleccion, previa: Mapping[str, Any], *,
               actualizaciones: int = 0, max_fichas: int = 120,
               max_anexo: int = 250) -> dict[str, Any]:
    """Cuánto va a ocupar y cuánto va a tardar el documento, aproximadamente.

    No construye nada: es aritmética sobre los recuentos que ya trae la vista previa, así
    que se puede recalcular en cada cambio del formulario sin coste. Se presenta siempre
    como aproximación («unas 12 páginas»), nunca como una cifra exacta.
    """
    amenazas = int(previa.get("amenazas") or 0)
    fichas = min(amenazas, max_fichas) if "prioritarias" in sel.apartados else 0
    anexo = min(amenazas, max_anexo) if "anexo" in sel.apartados else 0
    cola = min(int(actualizaciones or 0), 2 * max_fichas) if "remediacion" in sel.apartados else 0

    paginas = sum(_PAGINAS_FIJAS.get(c, 0.0) for c in sel.apartados)
    paginas += fichas * _PAGINAS_POR_FICHA
    paginas += anexo * _PAGINAS_POR_FILA_ANEXO
    paginas += cola * _PAGINAS_POR_ACTUALIZACION

    segundos = _SEGUNDOS_BASE + len(sel.apartados) * _SEGUNDOS_POR_APARTADO
    segundos += fichas * _SEGUNDOS_POR_FICHA
    segundos += anexo * _SEGUNDOS_POR_FILA_ANEXO
    segundos += cola * _SEGUNDOS_POR_ACTUALIZACION
    if "activos" in sel.apartados:
        segundos += _SEGUNDOS_APARTADO_ACTIVOS
    if sel.es_ejecutivo():
        # El informe ejecutivo no recorre amenaza a amenaza: son consultas de recuento y
        # la serie mensual. Medido el 2026-09-15 sobre la base real.
        segundos = _SEGUNDOS_EJECUTIVO

    paginas_enteras = max(1, int(round(paginas))) if sel.apartados else 0
    return {
        "paginas": paginas_enteras,
        "kilobytes": int(round(_KB_BASE + paginas_enteras * _KB_POR_PAGINA)) if paginas_enteras else 0,
        "segundos": round(segundos, 1) if sel.apartados else 0.0,
        # El tiempo se escribe aquí y no en la plantilla porque el filtro «numero» de la
        # interfaz redondea a entero y «15,2 segundos» se quedaría en «15».
        "tiempo_es": tiempo_es(segundos) if sel.apartados else "",
        "fichas": fichas,
        "filas_anexo": anexo,
        "actualizaciones": cola,
    }


def tiempo_es(segundos: float) -> str:
    """«menos de un segundo», «unos 16 segundos», «unos 2 minutos»."""
    if segundos < 1:
        return "menos de un segundo"
    if segundos < 60:
        n = int(round(segundos))
        return f"un segundo" if n == 1 else f"unos {n} segundos"
    minutos = int(round(segundos / 60))
    return "un minuto" if minutos == 1 else f"unos {minutos} minutos"


# --------------------------------------------------------------------------
# Selectores de la pantalla
# --------------------------------------------------------------------------
def procesos(conn: sqlite3.Connection, *, origen: Optional[str] = None) -> list[str]:
    """Procesos de negocio que se pueden elegir (los que tienen algo que informar)."""
    try:
        return queries.procesos_del_parque(conn, origen=origen if origen in TIPOS_MAQUINA else None)
    except sqlite3.OperationalError:
        return []


def activos_elegibles(conn: sqlite3.Connection, *, origen: Optional[str] = None,
                      limite: int = 1500) -> list[dict]:
    """Activos presentes con alguna vulnerabilidad confirmada, para el selector.

    Solo esos: ofrecer una máquina de la que no hay nada que contar produce informes
    vacíos. Cada uno trae su tipo escrito para poder agruparlos en la lista.
    """
    extra, params = queries.filtro_parque(None, origen if origen in TIPOS_MAQUINA else None)
    try:
        filas = conn.execute(
            f"""SELECT a.id, a.nombre, a.origen, a.proceso,
                       COUNT(DISTINCT ap.cve) AS cves
                  FROM activos a JOIN aplicabilidad ap ON ap.activo_id = a.id
                 WHERE a.presente=1 AND ap.veredicto='afectado'{extra}
                 GROUP BY a.id ORDER BY a.origen, a.nombre LIMIT ?""",
            [*params, int(limite)]).fetchall()
    except sqlite3.OperationalError:
        return []
    return [{"id": int(f["id"]), "nombre": f["nombre"], "origen": f["origen"],
             "origen_es": TIPOS_MAQUINA.get(f["origen"], f["origen"] or ""),
             "proceso": f["proceso"] or "", "cves": int(f["cves"] or 0)} for f in filas]


def tecnologias_elegibles(conn: sqlite3.Connection, *, limite: int = 400) -> list[dict]:
    """Tecnologías del inventario con amenazas correlacionadas, para el selector."""
    try:
        filas = conn.execute(
            """SELECT tc.slug, tc.name, COUNT(DISTINCT tt.threat_id) AS amenazas
                 FROM technologies tc JOIN threat_technologies tt ON tt.technology_id = tc.id
                WHERE tc.enabled = 1
                GROUP BY tc.id HAVING amenazas > 0
                ORDER BY tc.name LIMIT ?""", (int(limite),)).fetchall()
    except sqlite3.OperationalError:
        return []
    return [{"slug": f["slug"], "nombre": f["name"], "amenazas": int(f["amenazas"] or 0)}
            for f in filas]


def activo(conn: sqlite3.Connection, activo_id: int) -> Optional[dict]:
    """El activo elegido (nombre y tipo), o None si no existe."""
    if not activo_id:
        return None
    try:
        fila = conn.execute(
            "SELECT id, nombre, origen, proceso, presente FROM activos WHERE id = ?",
            (int(activo_id),)).fetchone()
    except sqlite3.OperationalError:
        return None
    return dict(fila) if fila else None


def tecnologia(conn: sqlite3.Connection, slug: str) -> Optional[dict]:
    """La tecnología elegida, o None si el identificador no existe."""
    if not slug:
        return None
    try:
        fila = conn.execute("SELECT slug, name FROM technologies WHERE slug = ?",
                            (slug,)).fetchone()
    except sqlite3.OperationalError:
        return None
    return {"slug": fila["slug"], "nombre": fila["name"]} if fila else None


def etiqueta_alcance(conn: sqlite3.Connection, sel: Seleccion) -> str:
    """El alcance en palabras, con los nombres reales del activo o la tecnología."""
    if sel.alcance == "activo":
        a = activo(conn, sel.activo_id)
        if a:
            tipo = TIPOS_MAQUINA.get(a["origen"], "activo")
            singular = "el servidor" if a["origen"] == "servidores" else "el equipo de cómputo"
            return f"{singular} {a['nombre']}" if tipo else f"el activo {a['nombre']}"
        return "un activo que ya no figura en el inventario"
    if sel.alcance == "tecnologia":
        t = tecnologia(conn, sel.tecnologia)
        return f"la tecnología {t['nombre']}" if t else "una tecnología que ya no existe"
    if sel.alcance == "proceso":
        return f"el proceso de negocio {sel.proceso}"
    if sel.alcance == "tipo":
        return f"los {TIPOS_MAQUINA.get(sel.tipo, 'servidores y equipos de cómputo')}"
    if sel.alcance == "kev":
        base = "las vulnerabilidades con explotación activa confirmada (catálogo KEV de CISA)"
        if sel.origen_perfil:
            return f"{base} en los {TIPOS_MAQUINA[sel.origen_perfil]}"
        return base
    if sel.origen_perfil:
        return f"los {TIPOS_MAQUINA[sel.origen_perfil]}"
    return "toda la organización"

"""Consulta del historico de amenazas.

Solo es posible desde que los datos estan en SQLite: con los JSON monoliticos
no habia forma de buscar ni de ver tendencias.
"""
from __future__ import annotations

from datetime import date

import csv
import inspect
import io
import re

import json

from flask import (Blueprint, Response, abort, current_app, flash, g, jsonify, redirect,
                   render_template, request, url_for)
from openpyxl import Workbook
from openpyxl.styles import Alignment, PatternFill, Font

from threatintel import aplicabilidad, db, excepciones, queries, scoring
# Alias: este modulo ya tiene una vista llamada «remediacion» (endpoint
# amenazas.remediacion, plan de remediacion), así que el modulo threatintel.remediacion
# (el motor que comprueba de verdad contra el inventario) entra con otro nombre.
from threatintel import remediacion as motor_remediacion
from threatintel.matching import CONTEXTO_VULNERABILIDAD
from webui import auth, graficos
from webui.filtros import celda_csv
from webui.vistas.remediaciones import indice_riesgo_aceptado, excepciones_vigentes
from webui.graficos import fmt

bp = Blueprint("amenazas", __name__, url_prefix="/amenazas")

#: Severidades que la interfaz ofrece filtrar. La Baja solo aparece cuando el ajuste
#: ``ignore_low_severity`` esta desactivado: con el activo (lo normal) no cuenta en nada,
#: asi que ofrecerla en el filtro prometia una lista que ninguna cifra respalda
#: (orden del usuario del 2026-09-10). `SEVERIDADES` se conserva como el conjunto de
#: valores VALIDOS, para que un enlace guardado con «sev=Low» no reviente.
SEVERIDADES = ["Critical", "High", "Medium", "Low"]
SEVERIDADES_REPORTADAS = ["Critical", "High", "Medium"]


def severidades_ofrecidas() -> list[str]:
    """Las que se ensenan en el filtro, segun el ajuste de la severidad baja."""
    if bool((getattr(g, "cfg", None) or {}).get("ignore_low_severity", True)):
        return list(SEVERIDADES_REPORTADAS)
    return list(SEVERIDADES)
#: Filas por pagina en los listados largos. El usuario pidio 20 el 2026-09-07
#: («que en cada uno solo muestre de a 20»): una pantalla se recorre de un vistazo.
POR_PAGINA = 20

# Filtro de estado de la lista: 'abiertas' por defecto para que lo descartado
# deje de estorbar; 'todas' y 'cerradas' como atajos, o un estado concreto.
FILTRO_ESTADO = {
    "abiertas": [e for e in queries.ESTADOS if e not in queries.ESTADOS_CERRADOS],
    "cerradas": list(queries.ESTADOS_CERRADOS),
    "todas": None,
}

#: Clave de color de la hoja de estilos por severidad (barras y leyendas).
SEVERIDAD_CLAVE = {"Critical": "critico", "High": "alto", "Medium": "medio", "Low": "bajo"}

#: Cómo se nombra cada tipo de activo en texto corrido (2026-09-08). El usuario
#: protestó porque en la fila «Servidores» se leía «485 equipos»: «equipos» a secas
#: no dice si son servidores o equipos de cómputo, y como el parque tiene 511
#: servidores y 325 equipos de cómputo, la ambigüedad hace dudar de todas las
#: cifras. Cada tipo se llama por su nombre y «activos» queda reservado a las
#: cifras que mezclan los dos tipos; «equipos» a secas no se usa nunca.
NOMBRE_TIPO = {"servidores": "servidores", "equipos": "equipos de cómputo"}
NOMBRE_MEZCLA = "activos"
#: Los mismos nombres en singular: en la revisión renderizada del 2026-09-08 se leía
#: «4 · 1 servidores afectados» en el proceso Fcaeldi, y un descuido de concordancia
#: hace dudar de la cifra igual que un nombre ambiguo.
NOMBRE_TIPO_SINGULAR = {"servidores": "servidor", "equipos": "equipo de cómputo"}
NOMBRE_MEZCLA_SINGULAR = "activo"


def _tipo_es(clave: str | None, cantidad: int) -> str:
    """Nombre del tipo de activo concordado con la cantidad: «1 servidor», «2 servidores».

    ``clave`` es el ``origen`` de la tabla ``activos`` («servidores» o «equipos»); con
    cualquier otro valor (o ``None``) se devuelve el nombre de la mezcla, «activos»,
    que es el único caso en el que la cifra suma los dos tipos.
    """
    if cantidad == 1:
        return NOMBRE_TIPO_SINGULAR.get(clave or "", NOMBRE_MEZCLA_SINGULAR)
    return NOMBRE_TIPO.get(clave or "", NOMBRE_MEZCLA)


def _afectados_es(clave: str | None, afectados: int, presentes: int) -> str:
    """«485 de 511 servidores»: cifra, denominador y unidad, en este orden.

    El nombre del tipo concuerda con el denominador porque es el sustantivo al que
    acompaña («1 de 511 servidores», «1 de 1 servidor»).
    """
    return f"{fmt(afectados)} de {fmt(presentes)} {_tipo_es(clave, presentes)}"


#: Terminos tecnicos que el traductor automatico NO debe traducir, con la forma (o
#: formas) en que los ha traducido mal en textos ya publicados. Son clases de
#: vulnerabilidad y palabras de uso fijo en seguridad: traducidas literalmente, la
#: descripcion deja de entenderse («fijar el uso despues de la compra» por
#: «use-after-free», «codificado duro» por «hardcoded», «lo decree por 1» por «decrement
#: it by 1»). Hallazgo de la revision de claridad del 2026-09-15 sobre LSN-0121-1.
#:
#: Esta tabla NO traduce nada: solo sirve para DETECTAR que un texto ya traducido
#: contiene una de esas vueltas mal dadas y avisar en la ficha de que la traduccion
#: automatica no es fiable para ese texto, ensenando el original en ingles. La
#: correccion de raiz —que el traductor no los traduzca— va en
#: ``threatintel.translate.TERMINOS_PROTEGIDOS``, que no es de esta vista; el informe
#: del 2026-09-15 lleva el cambio exacto.
#:
#: Cada entrada es (termino en ingles, expresiones en espanol que delatan la mala
#: traduccion). Las expresiones se comparan en minusculas y sin distinguir tildes.
TERMINOS_SIN_TRADUCIR = (
    ("use-after-free", ("uso despues de la compra", "uso despues de liberar",
                        "usar despues de libre", "uso despues de gratis",
                        "utilizar despues de libre", "despues de la compra")),
    ("heap overflow", ("desbordamiento del monton", "desbordamiento de monton",
                       "rebosamiento del monton")),
    ("buffer overflow", ("desbordamiento del amortiguador", "desbordamiento de amortiguador",
                         "desbordamiento del parachoques")),
    ("out-of-bounds", ("fuera de los limites del salto", "fuera de limites de la caja",
                       "fuera de juego")),
    ("hardcoded", ("codificado duro", "codificada dura", "duro codificado",
                   "codificado a mano dura")),
    ("race condition", ("condicion de carrera de coches", "condicion de la raza",
                        "condicion racial")),
    ("privilege escalation", ("escalada de privilegio de escalera", "escalamiento de privilegio",
                              "escalera de privilegios")),
    ("fix", ("fijar el", "fijar la", "fijar los", "fijar las", "se fija el flujo",
             "lo decree por", "decree por")),
)

#: Los mismos terminos, solo los nombres, para la nota que los enumera.
TERMINOS_SIN_TRADUCIR_ES = tuple(t for t, _ in TERMINOS_SIN_TRADUCIR)

_SIN_TILDE = str.maketrans("áéíóúüÁÉÍÓÚÜ", "aeiouuAEIOUU")


def terminos_mal_traducidos(texto_es: Any, texto_en: Any = None) -> list[str]:
    """Terminos tecnicos que la traduccion automatica ha vertido mal en ``texto_es``.

    Devuelve los NOMBRES EN INGLES de los terminos detectados, en el orden de
    :data:`TERMINOS_SIN_TRADUCIR`, sin repetir. Vacia si el texto esta bien o no hay
    texto. Cuando se pasa ``texto_en``, un termino solo cuenta si ademas el original lo
    contiene o contiene su raiz: asi una frase espanola que legitimamente diga «fijar la
    fecha» no se marca si el ingles no hablaba de un «fix».

    Comparacion en minusculas y sin tildes, sobre el texto tal cual: no se normaliza la
    puntuacion para no inventar coincidencias.
    """
    texto = str(texto_es or "").lower().translate(_SIN_TILDE)
    if not texto:
        return []
    original = str(texto_en or "").lower()
    salida: list[str] = []
    for termino, senales in TERMINOS_SIN_TRADUCIR:
        if not any(senal in texto for senal in senales):
            continue
        if original:
            raiz = termino.split()[0].split("-")[0]
            if termino not in original and raiz not in original:
                continue
        salida.append(termino)
    return salida


#: Un identificador de confirmacion de git (40 o 7 a 12 caracteres hexadecimales) no es
#: una version: en la tabla «Detalle del CVE segun CVE.org» del nucleo de Linux ocupaba
#: filas enteras con rangos como «affected: 4a1b... hasta 9f0c...», que no dicen a nadie
#: si le afecta. Se descartan y se deja solo lo que tiene forma de version.
_RE_HASH_GIT = re.compile(r"\b[0-9a-f]{7,40}\b")
_RE_VERSION = re.compile(r"\d")


def versiones_legibles(versiones: Any, *, limite: int = 12) -> tuple[list[str], int]:
    """(rangos por version, cuantos rangos por confirmacion de git se han ocultado).

    Un rango se descarta cuando, quitadas las confirmaciones de git, no queda ningun
    numero: es un rango entre dos puntos del repositorio, util para quien mantiene el
    nucleo y ruido para quien decide si actualizar. ``limite`` acota lo que se pinta.
    """
    legibles: list[str] = []
    ocultos = 0
    for bruto in list(versiones or []):
        texto = str(bruto or "").strip()
        if not texto:
            continue
        sin_hash = _RE_HASH_GIT.sub(" ", texto)
        if not _RE_VERSION.search(sin_hash):
            ocultos += 1
            continue
        legibles.append(texto)
    return legibles[:max(0, int(limite))], ocultos


def _detalle_cve_legible(detalle: Any) -> Any:
    """``enrich.detalle_cve`` con las versiones de cada producto ya depuradas.

    Se hace aqui, en la vista, porque ``threatintel/enrich.py`` alimenta ademas al
    informe y a los correos: la limpieza es una decision de presentacion de esta ficha.
    """
    if not isinstance(detalle, dict) or not detalle.get("afectados"):
        return detalle
    salida = dict(detalle)
    productos = []
    ocultos_total = 0
    for producto in detalle.get("afectados") or []:
        p = dict(producto)
        legibles, ocultos = versiones_legibles(p.get("versiones"))
        p["versiones"] = legibles
        p["versiones_ocultas"] = ocultos
        ocultos_total += ocultos
        productos.append(p)
    salida["afectados"] = productos
    salida["versiones_ocultas"] = ocultos_total
    return salida


def _estados_desde(param: str) -> tuple[str, list | None]:
    """(valor del selector, lista de estados para queries.buscar o None=todos)."""
    valor = (param or "abiertas").strip()
    if valor in FILTRO_ESTADO:
        return valor, FILTRO_ESTADO[valor]
    if valor in queries.ESTADOS:
        return valor, [valor]
    return "abiertas", FILTRO_ESTADO["abiertas"]


def _escapar_like(texto: str) -> str:
    return texto.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _patron_like(texto: str) -> str:
    return f"%{_escapar_like(texto)}%"


#: Cuántas coincidencias de cada entidad se muestran en el panel de «Resultados
#: relacionados» de la búsqueda (2026-11-16). La búsqueda global del encabezado solo
#: consulta amenazas (contrato de ``base.html``, ``data-filtro-vivo`` apunta a la zona
#: «resultados» de esta misma página); este panel añade, sin tocar ese contrato, lo que
#: el mismo texto encuentra en Activos y en Tecnologías, con un enlace a la lista
#: completa de cada una. Son solo pistas de a dónde ir: la propia pagina de destino
#: vuelve a aplicar el filtro con sus propias reglas de alcance por perfil.
MAX_COINCIDENCIAS_RELACIONADAS = 5


def _coincidencias_relacionadas(conn, texto: str) -> dict[str, Any]:
    """Activos y tecnologías cuyo nombre (o IP, en activos) contiene ``texto``.

    Se limita a lo que el perfil puede ver (alcance por tipo de máquina de Redes y
    Mantenimiento) para no anunciar un activo que la propia página de Activos le
    ocultaría después.
    """
    like = _patron_like(texto)
    alcance = auth.alcance_origen()
    where_alcance, params_alcance = "", []
    if alcance:
        where_alcance = " AND a.origen=?"
        params_alcance = [alcance]

    activos_total = int(conn.execute(
        f"SELECT COUNT(*) FROM activos a WHERE a.presente=1{where_alcance} "
        "AND (a.nombre LIKE ? ESCAPE '\\' OR a.ip LIKE ? ESCAPE '\\')",
        params_alcance + [like, like]).fetchone()[0] or 0)
    activos = [dict(r) for r in conn.execute(
        f"""SELECT a.id, a.nombre, a.ip, a.origen FROM activos a
             WHERE a.presente=1{where_alcance}
             AND (a.nombre LIKE ? ESCAPE '\\' OR a.ip LIKE ? ESCAPE '\\')
             ORDER BY a.nombre LIMIT ?""",
        params_alcance + [like, like, MAX_COINCIDENCIAS_RELACIONADAS])]

    tecnologias_total = int(conn.execute(
        "SELECT COUNT(*) FROM technologies t WHERE t.name LIKE ? ESCAPE '\\'",
        [like]).fetchone()[0] or 0)
    tecnologias = [dict(r) for r in conn.execute(
        """SELECT t.id, t.slug, t.name FROM technologies t
            WHERE t.name LIKE ? ESCAPE '\\'
            ORDER BY t.name LIMIT ?""",
        [like, MAX_COINCIDENCIAS_RELACIONADAS])]

    return {
        "activos": activos, "activos_total": activos_total,
        "tecnologias": tecnologias, "tecnologias_total": tecnologias_total,
        "hay_algo": bool(activos_total or tecnologias_total),
    }


def _filtros() -> dict:
    """Los filtros de la lista, tal como los entiende ``queries.buscar``.

    ``excluir_bajas`` sale del ajuste ``ignore_low_severity`` y va SIEMPRE, se elija o
    no una severidad en el formulario (revision de claridad del 2026-09-15). Antes, con
    el selector de severidad en «Todas», la cabecera contaba «7.514 amenazas coinciden
    con el filtro actual» mientras la tarjeta de la misma pagina decia «7.293 amenazas
    registradas»: las 221 de diferencia eran de severidad baja y salian con su insignia
    «Baja» en la ultima pagina. Filtrar en `queries.buscar` y no anadir las tres
    severidades a ``severidades`` es lo correcto por dos motivos: una severidad
    desconocida (NULL) no es una baja y debe seguir contando —como en
    ``resumen_amenazas``—, y los «chips» de filtros activos no deben anunciar tres
    severidades que nadie ha elegido.
    """
    return {
        "texto": (request.args.get("q") or "").strip(),
        "severidades": [s for s in request.args.getlist("sev") if s in severidades_ofrecidas()],
        "meses": [m for m in request.args.getlist("mes") if m],
        "tecnologia_slug": (request.args.get("tec") or "").strip() or None,
        "solo_kev": request.args.get("kev") == "1",
        "solo_con_cve": request.args.get("cve") == "1",
        "orden": request.args.get("orden", "relevancia"),
        "estados": _estados_desde(request.args.get("estado"))[1],
        "excluir_bajas": bool((getattr(g, "cfg", None) or {}).get("ignore_low_severity", True)),
    }


@bp.route("/")
@auth.requiere_login
def lista():
    f = _filtros()
    pagina_pedida = max(1, request.args.get("pagina", 1, type=int))

    # «?pagina=99999» devolvia una tabla vacia sin decir por que (hallazgo de la
    # revision del 2026-09-07): si la pagina pedida no existe se ensena la ultima que
    # si existe. La segunda consulta solo ocurre en ese caso, no en el normal.
    pagina = pagina_pedida
    resultados, total = queries.buscar(
        g.db, limite=POR_PAGINA, desplazamiento=(pagina - 1) * POR_PAGINA, **f)
    paginas = max(1, -(-total // POR_PAGINA))
    if pagina > paginas:
        pagina = paginas
        resultados, total = queries.buscar(
            g.db, limite=POR_PAGINA, desplazamiento=(pagina - 1) * POR_PAGINA, **f)

    tecnologias = [dict(r) for r in g.db.execute(
        """SELECT t.slug, t.name FROM technologies t
            WHERE EXISTS (SELECT 1 FROM threat_technologies tt
                           WHERE tt.technology_id = t.id)
            ORDER BY t.name""")]

    # Cifras del apartado (2026-09-07): cuántas amenazas hay y qué cuenta cada
    # número, con el reparto por tipo de activo (servidores y equipos de cómputo) y
    # por proceso de negocio.
    proceso = (request.args.get("proceso") or "").strip()[:80]
    # Alcance por tipo de maquina (2026-09-08): con un perfil acotado (Redes solo ve
    # servidores, Mantenimiento solo equipos de computo) el tipo lo fija el perfil, se
    # pida lo que se pida en la direccion; ni «?origen=» ni un proceso del otro tipo lo
    # amplian, porque el filtro SQL lleva siempre las dos condiciones.
    origen_parque = auth.origen_efectivo(request.args.get("origen")) or ""
    # Regla interna: las bajas no se reportan (ajuste ignore_low_severity, activo). Las
    # cifras, las barras y el selector de procesos usan el mismo criterio.
    incluir_bajas = not bool(g.cfg.get("ignore_low_severity", True))
    cifras = queries.resumen_amenazas(g.db, proceso=proceso or None,
                                      origen=origen_parque or None,
                                      incluir_bajas=incluir_bajas)
    # El denominador de cada cifra de máquinas: sin él, «485 servidores afectados»
    # no se puede juzgar y parece que no cuadra con la página de Activos (queja del
    # 2026-09-08). Se calcula con el mismo recorte que el numerador.
    # El denominador viene del propio resumen (`cifras["presentes"]`), calculado con el
    # mismo recorte y en la misma funcion que el numerador, para que no puedan divergir.
    parque = cifras["presentes"]
    _anotar_tipos(cifras, parque)
    # Los segmentos de las barras y el texto que las explica salen de la MISMA lista: si
    # se escribieran aparte, el párrafo volvería a decir «tres segmentos» mientras la
    # barra pinta cuatro (defecto de la revisión de seguridad del 2026-09-09). Las dos
    # gráficas reparten las mismas vulnerabilidades, así que comparten segmentos.
    segmentos = _segmentos_barra((cifras["por_origen"] or []) + (cifras["por_proceso"] or []),
                                 incluir_bajas=incluir_bajas)
    # Conciliacion con la pagina de Remediacion (2026-09-15). «Vulnerabilidades
    # confirmadas» es lo que la evaluacion de HOY confirma contra el inventario;
    # «pendientes» de Remediacion es eso mas las que siguen en la cola porque su fila de
    # evaluacion desaparecio sin que OCS Inventory confirme ningun cambio. Sin esta
    # cifra, las dos pantallas daban dos numeros distintos de lo mismo y ninguna decia
    # por que. Cuesta unos 160 ms sobre la base real y no entra en ninguna otra cifra.
    pendientes_sin_confirmar = queries.vulnerabilidades_pendientes_sin_confirmar(
        g.db, proceso=proceso or None, origen=origen_parque or None,
        incluir_bajas=incluir_bajas)

    # Resultados relacionados en Activos y Tecnologías (2026-11-16): el mismo texto
    # buscado aquí puede ser el nombre de un activo o de una tecnología, no solo el de
    # una amenaza. Solo se calcula cuando hay texto que buscar, para no pagar dos
    # consultas mas en cada visita sin filtro.
    coincidencias = (_coincidencias_relacionadas(g.db, f["texto"])
                     if f["texto"] else None)

    return render_template(
        "amenazas.html", resultados=resultados, total=total, pagina=pagina,
        por_pagina=POR_PAGINA, paginas=paginas,
        cifras=cifras, proceso=proceso, origen_parque=origen_parque,
        parque=parque, detalle_parque=_detalle_parque(parque),
        afectados_por_tipo=_afectados_por_tipo(cifras, parque),
        total_origen=_fila_total_origen(cifras, parque, origen_parque),
        ambito_es=_ambito_es(proceso, origen_parque),
        procesos_parque=queries.procesos_del_parque(g.db, incluir_bajas=incluir_bajas,
                                                    origen=auth.alcance_origen()),
        # Con alcance fijo el selector solo ofrece el tipo del perfil.
        origenes_parque={k: v for k, v in queries.ORIGEN_AMENAZAS_ES.items()
                         if auth.dentro_del_alcance(k)},
        barras_origen=_barras(cifras["por_origen"], "origen_es", "origen", nota=_nota_origen,
                              segmentos=segmentos),
        barras_proceso=_barras(cifras["por_proceso"], "proceso", "proceso", nota=_nota_proceso,
                               segmentos=segmentos),
        # «críticas, altas y medias» / «críticas, altas, medias y bajas»: el texto de la
        # página, el del recorrido guiado y la descripción accesible de la gráfica se
        # escriben con esta cadena, nunca a mano.
        segmentos_es=_lista_es([nombre.lower() for _, nombre, _ in segmentos]),
        n_segmentos=len(segmentos), n_segmentos_es=CARDINAL_ES.get(len(segmentos),
                                                                   fmt(len(segmentos))),
        args_sin_parque=_args_sin("proceso", "origen", "pagina"),
        pendientes_sin_confirmar=pendientes_sin_confirmar,
        pendientes_remediacion=cifras["vulnerabilidades"] + pendientes_sin_confirmar,
        filtros=f, severidades=severidades_ofrecidas(),
        estado_filtro=_estados_desde(request.args.get("estado"))[0],
        estados=queries.ESTADOS, estado_es=queries.ESTADO_ES,
        meses_disponibles=queries.meses_disponibles(g.db),
        tecnologias=tecnologias, coincidencias=coincidencias,
        recurrentes=queries.cve_recurrentes(g.db, 10) if pagina == 1 else [])


def _args_sin(*excluir: str) -> dict:
    """Los argumentos de la consulta actual sin los indicados y sin los reservados."""
    return {k: v for k, v in request.args.items()
            if k not in excluir and not k.startswith("_") and k not in ("endpoint", "values")}


#: Los pocos numerales que necesita el texto de la página, en palabras: «partida en tres
#: segmentos» se lee mejor que «partida en 3 segmentos» y el proyecto escribe en español.
CARDINAL_ES = {1: "un", 2: "dos", 3: "tres", 4: "cuatro", 5: "cinco"}

#: Segmentos en los que se puede partir una barra de vulnerabilidades, de mayor a menor
#: gravedad: (clave de color de la hoja de estilos, nombre visible, campo del resumen).
#: «Sin severidad conocida» va en neutro (gris «sin dato» de la paleta) porque no es un
#: nivel de gravedad, sino la ausencia del dato; y va al final para no romper el orden.
SEGMENTOS_BARRA = (
    ("critico", "Críticas", "criticas"),
    ("alto", "Altas", "altas"),
    ("medio", "Medias", "medias"),
    ("bajo", "Bajas", "bajas"),
    ("neutro", "Sin severidad conocida", "sin_severidad"),
)


def _segmentos_barra(filas, *, incluir_bajas: bool) -> list[tuple[str, str, str]]:
    """Qué segmentos pinta cada barra en esta petición, en orden de gravedad.

    Críticas, altas y medias siempre. «Bajas» solo cuando el ajuste «Ignorar la severidad
    baja» está desactivado: con el ajuste activo (lo normal) la severidad baja no existe
    en esta página, no se pinta ni se nombra, y `resumen_amenazas` la deja fuera de todas
    las cifras. «Sin severidad conocida» solo cuando de verdad hay alguna vulnerabilidad
    así, en cualquiera de los dos estados del ajuste: una severidad ausente no es una
    severidad baja, no se puede ocultar (contaría en el total y en ningún segmento, como
    ocurría hasta el 2026-09-09) y tampoco tiene sentido anunciar un segmento vacío.

    La decisión es de la gráfica entera, no de cada fila: la leyenda es común, y un
    segmento que apareciera solo en algunas barras haría dudar de las demás.
    """
    hay = {campo: any(int(f.get(campo) or 0) > 0 for f in filas or [])
           for _, _, campo in SEGMENTOS_BARRA}
    salida = []
    for clave, nombre, campo in SEGMENTOS_BARRA:
        if campo == "bajas" and not incluir_bajas:
            continue
        if campo == "sin_severidad" and not hay["sin_severidad"]:
            continue
        salida.append((clave, nombre, campo))
    return salida


def _lista_es(textos) -> str:
    """«críticas, altas y medias»: enumeración en español, con «y» antes del último."""
    partes = [t for t in textos if t]
    if not partes:
        return ""
    if len(partes) == 1:
        return partes[0]
    return f"{', '.join(partes[:-1])} y {partes[-1]}"


def _barras(filas, clave_etiqueta: str, clave_filtro: str, nota=None,
            segmentos=None) -> list[dict]:
    """Filas listas para ``graficos.barras_horizontales``, con su enlace de filtrado.

    Cada barra se parte en los segmentos de :func:`_segmentos_barra` (tres con el ajuste
    «Ignorar la severidad baja» activo: críticas, altas y medias), para que se lea la
    gravedad y no solo el volumen. Los segmentos son excluyentes y COMPLETOS: su suma es
    el total de vulnerabilidades de la fila, que es lo que la gráfica escribe a la derecha
    de la barra. Hasta el 2026-09-09 se pintaban siempre tres y, con el ajuste
    desactivado, la barra perdía las bajas: 1.233 vulnerabilidades de la base real
    contaban en el total y en ninguna parte del dibujo. El enlace acota las cifras de
    esta misma página a ese grupo.
    ``nota`` es la función que escribe la nota de cada barra: la nota no se puede
    redactar aquí porque no dice lo mismo en el reparto por tipo de activo que en el
    de procesos, y el usuario pidió (2026-09-08) que cada una nombre el tipo de
    máquina del que habla en vez del ambiguo «equipos».
    """
    usados = list(segmentos if segmentos is not None else SEGMENTOS_BARRA[:3])
    salida = []
    for f in filas:
        valor = f.get(clave_filtro) or ""
        salida.append({
            "etiqueta": f.get(clave_etiqueta) or "(sin nombre)",
            # El nombre viaja con el segmento para que la leyenda de la gráfica y el
            # texto que la explica salgan de la misma tabla y no puedan discrepar.
            "valores": [(clave, int(f.get(campo) or 0), nombre)
                        for clave, nombre, campo in usados],
            "href": url_for("amenazas.lista", **dict(_args_sin("pagina"), **{clave_filtro: valor})),
            "nota": nota(f) if nota else "",
        })
    return salida


def _parque_presente(conn, *, proceso: str | None = None,
                     origen: str | None = None) -> dict[str, int]:
    """Activos con inventario presente, por tipo: el denominador de estas cifras.

    Desde el 2026-09-08 la vista usa ``cifras["presentes"]``, que lo calcula dentro de
    ``queries.resumen_amenazas`` para que el denominador y el numerador no puedan
    divergir. Esta función se conserva como comprobación independiente de ese dato:
    cuenta lo mismo por otro camino y las pruebas exigen que las dos cifras coincidan.

    El usuario leyó «485 equipos» en la fila de servidores y lo comparó con los 325
    equipos de cómputo de la página de Activos: dos cifras que no tienen nada que ver
    (2026-09-08). Faltaba el denominador, que es lo que permite juzgar la cifra y
    cotejarla: 485 servidores afectados DE 511 presentes. Se cuenta sobre ``activos``
    con ``presente = 1``, la misma tabla y la misma condición que usa
    ``threatintel.ocs.resumen`` para la página de Activos, así que los 511 servidores
    y los 325 equipos de cómputo son literalmente el mismo dato en las dos páginas.

    El recorte por proceso y por tipo se toma de ``queries._filtro_parque``, el mismo
    que usa el resumen: si se escribiera aquí otra vez, al filtrar por un proceso
    saldría «171 de 511», que compara el proceso con todo el parque.
    """
    extra, params = queries.filtro_parque(proceso or None, origen or None)
    fila = conn.execute(
        f"""SELECT COUNT(*) AS total,
                   SUM(a.origen = 'servidores') AS servidores,
                   SUM(a.origen = 'equipos') AS equipos
              FROM activos a
             WHERE a.presente = 1{extra}""", params).fetchone()
    return {"total": int(fila["total"] or 0),
            "servidores": int(fila["servidores"] or 0),
            "equipos": int(fila["equipos"] or 0)}


def _anotar_tipos(cifras: dict, parque: dict) -> None:
    """Añade a cada fila del reparto su unidad, su denominador y el texto que los une.

    Se hace aquí y no en la plantilla porque el nombre de cada tipo de activo es una
    regla del proyecto, no una decisión de maquetación: escrito en la plantilla, la
    siguiente tabla volvería a poner «equipos».
    """
    for fila in cifras.get("por_origen") or []:
        clave = fila.get("origen")
        fila["unidad"] = NOMBRE_TIPO.get(clave, NOMBRE_MEZCLA)
        fila["presentes"] = int(parque.get(clave) or 0)
        fila["afectados_es"] = _afectados_es(clave, int(fila.get("activos") or 0),
                                             fila["presentes"])
    for fila in cifras.get("por_proceso") or []:
        fila["afectados_es"] = _afectados_es(None, int(fila.get("activos") or 0),
                                             int(fila.get("presentes") or 0))


def _nota_origen(fila: dict) -> str:
    """Nota de la barra de un tipo de activo: «485 de 511 servidores afectados».

    El gráfico ya escribe a la izquierda de la nota el total de vulnerabilidades de la
    barra, así que la nota aporta lo que faltaba: cuántas máquinas de ese tipo están
    afectadas y de cuántas hay. Las amenazas distintas no caben aquí y van en la tabla
    de debajo: el módulo de gráficos reserva a la derecha el ancho de la nota más larga
    y con las tres cifras la barra se quedaba en un tercio del gráfico (medido el
    2026-09-04 en el gráfico de tecnologías).
    """
    participio = "afectado" if int(fila.get("presentes") or 0) == 1 else "afectados"
    return f"{fila.get('afectados_es', '')} {participio}".strip()


def _nota_proceso(fila: dict) -> str:
    """Nota de la barra de un proceso: cuántas de sus máquinas están afectadas.

    El usuario lo pidió el 2026-09-08: «si son servidores que diga servidores y no
    equipos». Y toda cifra de máquinas del bloque lleva su denominador, que ahora sí
    viene por grupo desde el resumen (``presentes_servidores`` /
    ``presentes_equipos``): sin él, «33 servidores afectados» de un grupo y «171
    servidores afectados» de otro no se pueden comparar, que es justo lo que se pidió
    poder hacer (revisión del 2026-09-08).

    Cuando el grupo tiene los dos tipos de máquina, la nota los nombra los dos y sigue
    hablando de máquinas, nunca de vulnerabilidades: dos magnitudes distintas en la
    misma columna de notas es la ambigüedad que este bloque viene a quitar.
    """
    servidores = int(fila.get("activos_de_servidores") or 0)
    equipos = int(fila.get("activos_de_equipos") or 0)
    if servidores and equipos:
        return (f"{_afectados_es('servidores', servidores, int(fila.get('presentes_servidores') or 0))}"
                f" y {_afectados_es('equipos', equipos, int(fila.get('presentes_equipos') or 0))}"
                f" afectados")
    if equipos:
        n_pres = int(fila.get("presentes_equipos") or 0)
        return (f"{_afectados_es('equipos', equipos, n_pres)}"
                f" {'afectado' if n_pres == 1 else 'afectados'}")
    if servidores:
        n_pres = int(fila.get("presentes_servidores") or 0)
        return (f"{_afectados_es('servidores', servidores, n_pres)}"
                f" {'afectado' if n_pres == 1 else 'afectados'}")
    activos = int(fila.get("activos") or 0)
    n_pres = int(fila.get("presentes") or 0)
    return (f"{_afectados_es(None, activos, n_pres)}"
            f" {'afectado' if n_pres == 1 else 'afectados'}")


def _fila_total_origen(cifras: dict, parque: dict,
                       origen_parque: str = "") -> dict | None:
    """Fila de total de la tabla por tipo de activo (la pidió el usuario el 2026-09-08).

    Las vulnerabilidades y los activos afectados sí se suman entre filas, porque cada
    activo es de un solo tipo y cada vulnerabilidad pertenece a un solo activo. Las
    amenazas distintas NO: la misma amenaza aparece en servidores y en equipos de
    cómputo, así que sumar las filas daría amenazas que no existen (602 + 963 = 1.565
    frente a las 1.032 reales del 2026-09-08). El total de amenazas distintas es el
    ``COUNT(DISTINCT)`` del resumen (``confirmadas``) y la plantilla avisa de que no es
    la suma cuando difiere; una suma falsa sería peor que no poner el total.
    """
    filas = cifras.get("por_origen") or []
    if not filas:
        return None
    suma_amenazas = sum(int(f.get("amenazas") or 0) for f in filas)
    amenazas = int(cifras.get("confirmadas") or 0)
    activos = sum(int(f.get("activos") or 0) for f in filas)
    presentes = int(parque.get("total") or 0)
    # Con el filtro «Tipo de activo» puesto el total habla de ese tipo y se le llama
    # por su nombre. Sin filtro, se le llama por su nombre solo si el PARQUE del ámbito
    # es de un solo tipo (un proceso de solo servidores: «171 de 175 servidores»); si el
    # parque tiene los dos tipos, la cifra los mezcla y se dice «activos».
    # La clave la decide el filtro y el parque, nunca cuantas filas tenga la tabla:
    # tambien hay una sola fila cuando uno de los dos tipos no tiene ninguna
    # vulnerabilidad viva, y entonces el denominador sigue siendo el parque completo.
    # Rotularlo «485 de 836 servidores» era exactamente la queja del usuario (revision
    # del 2026-09-08).
    tipos_presentes = [t for t in ("servidores", "equipos") if int(parque.get(t) or 0) > 0]
    clave = origen_parque or (tipos_presentes[0] if len(tipos_presentes) == 1 else None)
    return {
        "vulnerabilidades": sum(int(f.get("vulnerabilidades") or 0) for f in filas),
        "activos": activos,
        "presentes": presentes,
        "amenazas": amenazas,
        "suma_amenazas": suma_amenazas,
        "amenazas_es_suma": suma_amenazas == amenazas,
        "unidad": _tipo_es(clave, presentes),
        "tipos_es": " y ".join(f.get("unidad", NOMBRE_MEZCLA) for f in filas),
        "afectados_es": _afectados_es(clave, activos, presentes),
    }


def _detalle_parque(parque: dict) -> list[str]:
    """El parque con cada tipo por su nombre: «511 servidores», «325 equipos de cómputo»."""
    return [f"{fmt(parque[clave])} {_tipo_es(clave, int(parque[clave]))}"
            for clave in ("servidores", "equipos") if parque.get(clave)]


def _afectados_por_tipo(cifras: dict, parque: dict) -> list[str]:
    """Afectados y presentes de cada tipo: «485 de 511 servidores».

    Se recorre el parque y no el reparto para que un tipo sin ningún activo afectado
    también aparezca («0 de 325 equipos de cómputo»): esa cifra informa, y su ausencia
    haría dudar de si falta el dato o no hay ninguno.
    """
    afectados = {f.get("origen"): int(f.get("activos") or 0)
                 for f in cifras.get("por_origen") or []}
    return [_afectados_es(clave, afectados.get(clave, 0), int(parque[clave]))
            for clave in ("servidores", "equipos") if parque.get(clave)]


def _ambito_es(proceso: str, origen: str) -> str:
    """Qué parte del parque describen las cifras, en palabras.

    Con un filtro puesto, las cifras dejan de ser las de todo el parque; si no se dice,
    el lector compara «171 servidores» con los 511 de la página de Activos y concluye
    que las cifras no cuadran (queja del 2026-09-08).
    """
    tipo = NOMBRE_TIPO.get(origen or "", NOMBRE_MEZCLA)
    if proceso and origen:
        return f"los {tipo} del proceso «{proceso}»"
    if proceso:
        return f"los activos del proceso «{proceso}»"
    if origen:
        return f"los {tipo} de toda la organización"
    return "todos los activos de la organización"


def _marcar_activos_aceptados(activos: dict, cve, indice: dict) -> int:
    """Marca con ``riesgo_aceptado`` los activos y paquetes cubiertos por una excepcion.

    Recorre lo que la ficha ya tiene en memoria y cruza contra el indice de excepciones
    vigentes (``webui.vistas.remediaciones.indice_riesgo_aceptado``): ni una consulta mas.
    El activo se marca cuando la excepcion cubre el par (activo, CVE) o el CVE en toda la
    organizacion, y cada paquete cuando la cubre una excepcion de alcance por paquete, que
    es lo que de verdad tapa esa fila. Devuelve cuantos activos quedaron marcados.
    """
    if not indice or not (indice["activo_cve"] or indice["cve"] or indice["activo_paquete"]):
        return 0
    cve = str(cve or "")
    marcados = 0
    for lista in ("afectados",):
        for x in activos.get(lista) or []:
            try:
                activo_id = int(x.get("id") or 0)
            except (TypeError, ValueError):
                continue
            del_activo = (indice["activo_cve"].get((activo_id, cve))
                          or indice["cve"].get(cve))
            paquetes_cubiertos = 0
            for d in x.get("paquetes_detalle") or []:
                por_paquete = indice["activo_paquete"].get(
                    (activo_id, str(d.get("paquete") or "")))
                cubre = del_activo or por_paquete
                if cubre is not None:
                    d["riesgo_aceptado"] = cubre
                    paquetes_cubiertos += 1
            if del_activo is not None:
                x["riesgo_aceptado"] = del_activo
                marcados += 1
            elif paquetes_cubiertos:
                # Solo algunos paquetes: la fila del activo lo dice con su cifra, para no
                # dar a entender que el activo entero esta cubierto.
                x["riesgo_aceptado_paquetes"] = paquetes_cubiertos
                marcados += 1
    return marcados


def _activos_de_amenaza(threat_id: int, *, limite: int = 60) -> dict:
    """El bloque de activos de la ficha, recortado al tipo de maquina del perfil (2026-09-08).

    Sin alcance (administracion, operador SOC, Redes, solo lectura) es
    ``aplicabilidad.activos_de_amenaza`` tal cual. Para Redes y Mantenimiento el recorte
    se hace EN LA CONSULTA, no quitando filas despues: el desglose por sistema operativo
    y las cifras salen solo de las maquinas de su tipo, y un sistema que solo tenian las
    del otro tipo no aparece. Si ``aplicabilidad.activos_de_amenaza`` llega a aceptar
    ``origen`` (una condicion mas en su consulta, que no pertenece a esta vista) se usa
    directamente y la copia local deja de ejecutarse sola.
    """
    origen = auth.alcance_origen()
    if not origen:
        return aplicabilidad.activos_de_amenaza(g.db, threat_id, limite=limite)
    if "origen" in inspect.signature(aplicabilidad.activos_de_amenaza).parameters:
        return aplicabilidad.activos_de_amenaza(g.db, threat_id, limite=limite, origen=origen)
    return _activos_de_amenaza_acotados(g.db, threat_id, origen=origen, limite=limite)


def _activos_de_amenaza_acotados(conn, threat_id: int, *, origen: str, limite: int) -> dict:
    """Misma salida que ``aplicabilidad.activos_de_amenaza`` para UN tipo de maquina.

    Reutiliza los mismos acumuladores del modulo de aplicabilidad (``_acumular_sistema``,
    ``_cerrar_sistema``, ``_cerrar_activo`` y ``detalle_paquete_de_fila``) sobre la misma
    consulta con ``a.origen = ?``: asi las filas por paquete, las versiones y las fuentes
    oficiales son identicas a las de la ficha completa. Los recuentos de la evaluacion
    («ya corregidos», «sin dato») se recalculan para el tipo, porque los guardados en
    ``aplicabilidad_amenaza`` son del parque entero.
    """
    fila = conn.execute("SELECT * FROM aplicabilidad_amenaza WHERE threat_id=?", (threat_id,)).fetchone()
    salida: dict = {"evaluada": fila is not None, "evaluado_at": None, "n_afectados": 0,
                    "n_no_afectados": 0, "n_sin_dato": 0, "afectados": [], "mas": 0,
                    "lineas": [], "incompleta": False, "sistemas": [], "cve": None,
                    "acotado": origen}
    if fila is None:
        return salida
    try:
        detalle = json.loads(fila["detalle"] or "{}")
    except ValueError:
        detalle = {}
    salida.update(evaluado_at=fila["evaluado_at"], lineas=list(detalle.get("lineas") or []),
                  incompleta=bool(detalle.get("incompleta")),
                  errores=list(detalle.get("errores") or []))
    por_activo: dict[int, dict] = {}
    cve_principal = None
    grupos: dict[str, dict] = {}
    for r in conn.execute(
            """SELECT a.id, a.nombre, a.ip, a.origen, a.so_nombre, a.so_version, a.so_familia,
                      a.so_ciclo, a.ecosistema, a.zona, a.entorno, a.proceso,
                      ap.cve, ap.paquete, ap.version_instalada, ap.version_corregida, ap.evidencia,
                      ap.aviso, ap.motor, ap.sin_parche_motivo, ap.referencia
                 FROM aplicabilidad ap JOIN activos a ON a.id = ap.activo_id
                WHERE ap.threat_id=? AND ap.veredicto='afectado' AND a.presente=1 AND a.origen=?
                ORDER BY a.origen, a.nombre, ap.paquete""", (threat_id, origen)):
        cve_principal = cve_principal or r["cve"]
        aplicabilidad._acumular_sistema(grupos, {**dict(r), "activo_id": r["id"]})
        e = por_activo.setdefault(r["id"], {
            "id": r["id"], "nombre": r["nombre"], "ip": r["ip"], "origen": r["origen"],
            "so_nombre": r["so_nombre"], "so_version": r["so_version"], "zona": r["zona"],
            "so_familia": r["so_familia"], "so_ciclo": r["so_ciclo"], "ecosistema": r["ecosistema"],
            "entorno": r["entorno"], "proceso": r["proceso"],
            "sistema": aplicabilidad.nombre_sistema(r["ecosistema"], r["so_nombre"], r["so_ciclo"],
                                                    r["so_familia"]),
            "paquetes": [], "paquetes_detalle": [], "aviso": r["aviso"]})
        e["paquetes"].append(r["paquete"])
        e["paquetes_detalle"].append(aplicabilidad.detalle_paquete_de_fila(r, cve=cve_principal))
    lista = [aplicabilidad._cerrar_activo(a, cve=cve_principal) for a in por_activo.values()]
    salida["afectados"] = lista[:limite] if limite else lista
    salida["mas"] = max(0, len(lista) - limite) if limite else 0
    salida["n_afectados"] = len(lista)
    salida["sistemas"] = [aplicabilidad._cerrar_sistema(gr, cve_principal) for gr in grupos.values()]
    salida["sistemas"].sort(key=lambda gr: (-gr["n_activos"], gr["nombre"]))
    salida["cve"] = cve_principal
    # Recuentos de la evaluacion para este tipo: mismo criterio que
    # aplicabilidad.recalcular_resumenes, acotado con a.origen.
    otros = conn.execute(
        """SELECT COUNT(DISTINCT CASE WHEN ap.veredicto='no_afectado' THEN ap.activo_id END) AS no_af,
                  COUNT(DISTINCT CASE WHEN ap.veredicto='sin_dato' THEN ap.activo_id END) AS sin_dato
             FROM aplicabilidad ap JOIN activos a ON a.id=ap.activo_id
            WHERE ap.threat_id=? AND a.presente=1 AND a.origen=?
              AND ap.activo_id NOT IN (SELECT activo_id FROM aplicabilidad
                                        WHERE threat_id=? AND veredicto='afectado')""",
        (threat_id, origen, threat_id)).fetchone()
    salida["n_no_afectados"] = int(otros["no_af"] or 0)
    salida["n_sin_dato"] = int(otros["sin_dato"] or 0)
    return salida


def _plan_en_alcance(plan: dict) -> dict:
    """El plan de remediacion recortado al tipo de maquina del perfil (2026-09-08).

    ``aplicabilidad.plan_remediacion`` agrupa por sistema y paquete y lista las maquinas
    de cada grupo con su ``origen``, asi que aqui el recorte es exacto: se quitan las del
    otro tipo, se recalculan las cifras de cada grupo y del total y desaparecen los grupos
    que se quedan vacios. Sin alcance se devuelve tal cual.
    """
    origen = auth.alcance_origen()
    if not origen or not plan:
        return plan
    grupos = []
    for grupo in plan.get("grupos") or []:
        maquinas = [m for m in grupo.get("activos") or [] if m.get("origen") == origen]
        if not maquinas:
            continue
        grupos.append(dict(grupo, activos=maquinas, n_activos=len(maquinas),
                           expuestos=sum(1 for m in maquinas
                                         if m.get("entorno") in ("produccion", "contingencia"))))
    return dict(plan, grupos=grupos,
                total_activos=len({m["id"] for gr in grupos for m in gr["activos"]}),
                total_expuestos=len({m["id"] for gr in grupos for m in gr["activos"]
                                     if m.get("entorno") in ("produccion", "contingencia")}),
                cves=sorted({c for gr in grupos for c in gr.get("cves") or []}))


@bp.route("/<int:threat_id>")
@auth.requiere_login
def detalle(threat_id: int):
    """Ficha de una amenaza: estado, prioridad, correlacion, activos afectados y fuentes.

    El bloque de activos trae dos vistas de lo mismo (2026-09-06, a peticion del usuario),
    las dos con el plan POR PAQUETE (revision adversaria del 2026-09-06):

    * ``activos.sistemas``: el desglose por sistema operativo, calculado sobre TODAS las
      filas de la evaluacion, no solo sobre las 60 que caben en la tabla. De cada sistema se
      pinta una fila por paquete afectado (``paquetes_detalle``), con su version instalada,
      su version corregida, la explicacion de la comparacion y la fuente oficial. La version
      que corrige no es la misma en Ubuntu 22.04, en Ubuntu 26.04 y en Debian 13, ni es la
      misma para el sistema base de FreeBSD y para un puerto del mismo servidor.
    * ``activos.afectados``: los equipos concretos, con una fila por paquete instalado
      (``paquetes_detalle``): version instalada, version corregida, explicacion de la
      comparacion, orden con la que verificarlo en el propio equipo, aviso y fuente oficial.
      Solo cuando todos los paquetes de un activo coinciden en instalada y corregida
      (``mismo_plan``) el activo tiene una pareja de versiones propia.
    """
    amenaza = queries.obtener_amenaza(g.db, threat_id)
    if amenaza is None:
        flash("La amenaza no existe.", "error")
        return redirect(url_for("amenazas.lista"))

    otras = []
    if amenaza.get("cve"):
        otras = [a for a in queries.por_cve(g.db, amenaza["cve"])
                 if a["id"] != threat_id]

    # Exposición frente a mención: por debajo de la confianza mínima la
    # coincidencia no prueba que nos afecte y se muestra aparte.
    min_conf = float(g.cfg.get("alert_min_match_confidence", 0.6) or 0)
    tecs_exposicion, tecs_mencion = [], []
    for t in amenaza.get("technologies") or []:
        conf = t.get("confidence")
        conf = 1.0 if conf is None else float(conf)
        (tecs_exposicion if conf >= min_conf else tecs_mencion).append(t)
    # Solo lo que afecta (peticion del usuario del 2026-09-09, repetida tres veces): la
    # tabla no lista las tecnologias cuya version instalada NO es vulnerable. No se pierden:
    # se cuentan en una linea al pie, con su explicacion, porque son la prueba de que la
    # comprobacion se hizo. «Sin determinar» SI se lista: no se puede descartar lo que no
    # se sabe, y esa es la regla de prudencia del proyecto.
    tecs_descartadas = [t for t in tecs_exposicion if t.get("version_verdict") == "not_affected"]
    tecs_exposicion = [t for t in tecs_exposicion if t.get("version_verdict") != "not_affected"]

    # Aplicabilidad por activo (OCS): que equipos tienen de verdad la version vulnerable.
    # El limite acota la tabla de equipos; el desglose por sistema (activos["sistemas"]) se
    # calcula con todas las filas, asi que sus cifras son las reales aunque la tabla se corte.
    activos = _activos_de_amenaza(threat_id, limite=60)
    # Riesgo aceptado (excepciones con vencimiento, 2026-09-10). Los activos cubiertos por
    # una excepcion vigente SIGUEN en esta tabla —la afectacion es un hecho tecnico y la
    # ficha de la amenaza es donde se comprueba—, marcados con la insignia «Riesgo
    # aceptado»: lo que sale de las cifras y de la cola son las cifras de Amenazas, el
    # Panel, Remediacion y el plan de remediacion de esta misma amenaza. Dos consultas
    # para toda la pagina: las excepciones de este CVE (con su responsable y su fecha,
    # para el aviso de arriba) y las vigentes, para marcar tambien las de alcance por
    # paquete, que no llevan CVE. El cruce se hace en Python, nunca una consulta por fila.
    excepciones_cve = (excepciones.por_cve(g.db, amenaza["cve"], solo_vigentes=True)
                       if amenaza.get("cve") else [])
    alcance = auth.alcance_origen()
    if alcance:
        # Un perfil acotado no puede ver el nombre de una maquina del otro tipo: se le
        # ensenan las de su tipo y las de un CVE en toda la organizacion, igual que en la
        # propia pagina de Excepciones (excepciones._filtros con ``origen``).
        excepciones_cve = [e for e in excepciones_cve
                           if not e.get("activo_id") or e.get("activo_origen") == alcance]
    indice_aceptado = indice_riesgo_aceptado(excepciones_vigentes(g.db))
    _marcar_activos_aceptados(activos, amenaza.get("cve"), indice_aceptado)
    extra_alcance, params_alcance = auth.filtro_alcance_sql("a")
    hay_activos = g.db.execute(
        f"SELECT 1 FROM activos a WHERE a.presente=1{extra_alcance} LIMIT 1",
        params_alcance).fetchone() is not None
    # Como se calcula la prioridad: cada componente con su explicacion
    resumen_aplic = g.db.execute("SELECT * FROM aplicabilidad_amenaza WHERE threat_id=?", (threat_id,)).fetchone()
    if resumen_aplic is not None and auth.alcance_origen():
        # Para un perfil acotado (Redes, Mantenimiento) las cifras de activos que alimentan
        # el desglose de prioridad se recalculan con las maquinas de su tipo: la cifra
        # global revelaba cuantos activos del otro tipo estaban afectados (revisión de
        # seguridad del 2026-09-08).
        extra, params = auth.filtro_alcance_sql("a")
        # Se cuentan ACTIVOS distintos, no filas: una fila por paquete inflaba «afectados»
        # (un CVE del nucleo en cinco paquetes del mismo servidor sumaba cinco) y el
        # desglose de prioridad del perfil acotado no cuadraba con el del parque, que
        # ``aplicabilidad.recalcular_resumenes`` calcula por activo (2026-09-09).
        # Un activo con un paquete afectado y otro ya corregido es un activo afectado, no
        # uno corregido: igual que en ``recalcular_resumenes``.
        afectados_en = "SELECT activo_id FROM aplicabilidad WHERE threat_id=? AND veredicto='afectado'"
        acotado = g.db.execute(
            f"""SELECT COUNT(DISTINCT CASE WHEN ap.veredicto='afectado' THEN ap.activo_id END) AS afectados,
                       COUNT(DISTINCT CASE WHEN ap.veredicto='afectado'
                                            AND a.entorno IN ('produccion','contingencia')
                                           THEN ap.activo_id END) AS afectados_expuestos,
                       COUNT(DISTINCT CASE WHEN ap.veredicto='no_afectado'
                                            AND ap.activo_id NOT IN ({afectados_en})
                                           THEN ap.activo_id END) AS no_afectados,
                       COUNT(DISTINCT CASE WHEN ap.veredicto='sin_dato'
                                            AND ap.activo_id NOT IN ({afectados_en})
                                           THEN ap.activo_id END) AS sin_dato
                  FROM aplicabilidad ap JOIN activos a ON a.id = ap.activo_id
                 WHERE ap.threat_id = ? AND a.presente = 1{extra}""",
            [threat_id, threat_id, threat_id, *params]).fetchone()
        resumen_aplic = dict(resumen_aplic)
        for clave in ("afectados", "afectados_expuestos", "no_afectados", "sin_dato"):
            resumen_aplic[clave] = int((acotado[clave] if acotado else 0) or 0)
    desglose = scoring.desglose_relevancia(
        severity=amenaza.get("severity"), cvss_score=amenaza.get("cvss_score"), epss=amenaza.get("epss_score"),
        in_kev=bool(amenaza.get("in_kev")), tecnologias=amenaza.get("technologies") or [],
        min_confianza=min_conf, ignorar_criticidad_baja=bool(g.cfg.get("ignore_low_criticality", True)),
        activos=dict(resumen_aplic) if resumen_aplic else None, cvss_vector=amenaza.get("cvss_vector"))
    # Detalle del CVE segun CVE.org (productos y versiones afectados), desde la cache
    detalle_cve = None
    if amenaza.get("cve"):
        from threatintel import enrich
        try:
            detalle_cve = enrich.detalle_cve(g.db, amenaza["cve"], cfg=g.cfg, permitir_red=True)
        except Exception:  # noqa: BLE001 - la ficha no depende de CVE.org
            detalle_cve = None
    # Los rangos de version que en realidad son confirmaciones de git no se pintan: no
    # dicen a nadie si le afecta y llenaban la tabla (2026-09-15).
    detalle_cve = _detalle_cve_legible(detalle_cve)
    # Traduccion automatica poco fiable (2026-09-15): si el texto en espanol trae una de
    # las vueltas mal dadas conocidas («fijar el uso despues de la compra» por
    # «use-after-free»), la ficha abre el original en ingles y lo advierte, en lugar de
    # presentar como buena una descripcion que no se entiende.
    mal_traducidos = terminos_mal_traducidos(amenaza.get("summary_es"),
                                             amenaza.get("summary_en"))

    return render_template("amenaza_detalle.html", a=amenaza, otras=otras,
                           tecs_exposicion=tecs_exposicion, tecs_mencion=tecs_mencion,
                           tecs_descartadas=tecs_descartadas,
                           min_confianza=min_conf, estados=queries.ESTADOS,
                           estado_es=queries.ESTADO_ES, estados_cerrados=queries.ESTADOS_CERRADOS,
                           activos=activos, hay_activos=hay_activos, desglose=desglose,
                           excepciones_cve=excepciones_cve,
                           mal_traducidos=mal_traducidos,
                           detalle_cve=detalle_cve)


@bp.route("/<int:threat_id>/remediacion")
@auth.requiere_login
def remediacion(threat_id: int):
    """Plan de remediacion: activos con la version vulnerable agrupados por sistema y
    paquete, con la orden que los corrige."""
    from threatintel import ocs
    amenaza = queries.obtener_amenaza(g.db, threat_id)
    if amenaza is None:
        flash("La amenaza no existe.", "error")
        return redirect(url_for("amenazas.lista"))
    # Alcance por tipo de maquina (2026-09-08): Redes y Mantenimiento solo ven las suyas.
    plan = _plan_en_alcance(aplicabilidad.plan_remediacion(g.db, threat_id=threat_id))
    titulo = f"Plan de remediación · {amenaza.get('cve') or (amenaza.get('title_es') or amenaza.get('title_en') or '')[:60]}"
    if request.args.get("formato") == "txt":
        texto = aplicabilidad.plan_remediacion_texto(plan, titulo=titulo)
        return Response(texto, mimetype="text/plain; charset=utf-8",
                        headers={"Content-Disposition": f"attachment; filename=remediacion_{amenaza.get('cve') or threat_id}.txt"})
    return render_template("remediacion.html", plan=plan, amenaza=amenaza, activo=None, titulo=titulo,
                           entorno_es=ocs.ENTORNO_ES)


@bp.route("/<int:threat_id>/estado", methods=["POST"])
@auth.requiere_operacion
@auth.requiere_csrf
def cambiar_estado(threat_id: int):
    """Cambia el estado operativo de una amenaza y, en un falso positivo, puede
    ajustar el inventario para que el caso no se repita.

    Administradores y operador SOC (2026-09-08): operar las amenazas es el trabajo del
    SOC; los perfiles de remediacion y el de solo lectura no cambian estados.

      * ``contexto`` = lista de «slug|alias»: ese alias pasa a exigir contexto
        de vulnerabilidad (deja de correlar noticias que solo lo mencionan).
      * ``desvincular`` = lista de slugs: se quita la correlación de ESTA amenaza
        con esas tecnologías y se recalcula su relevancia.
    """
    amenaza = queries.obtener_amenaza(g.db, threat_id)
    if amenaza is None:
        flash("La amenaza no existe.", "error")
        return redirect(url_for("amenazas.lista"))

    estado = (request.form.get("estado") or "").strip()
    motivo = (request.form.get("motivo") or "").strip()[:500]
    if estado not in queries.ESTADOS:
        flash("Estado no válido.", "error")
        return redirect(url_for("amenazas.detalle", threat_id=threat_id))

    contexto = request.form.getlist("contexto") if estado == "falso_positivo" else []
    desvincular = request.form.getlist("desvincular") if estado == "falso_positivo" else []
    ajustes: list[str] = []
    ruta_db = current_app.config.get("DB_PATH")

    with db.session(ruta_db) as conn:
        if not queries.cambiar_estado(conn, threat_id, estado, usuario=g.usuario, motivo=motivo):
            flash("No se pudo cambiar el estado.", "error")
            return redirect(url_for("amenazas.detalle", threat_id=threat_id))

        for par in contexto:
            slug, _, alias = par.partition("|")
            cur = conn.execute(
                """UPDATE tech_aliases SET context_required=?
                    WHERE technology_id=(SELECT id FROM technologies WHERE slug=?)
                      AND lower(alias)=lower(?) AND is_exclusion=0
                      AND (context_required IS NULL OR context_required IN ('', '[]'))""",
                (json.dumps(list(CONTEXTO_VULNERABILIDAD), ensure_ascii=False), slug, alias))
            if cur.rowcount:
                ajustes.append(f"contexto exigido a «{alias}» ({slug})")

        for slug in desvincular:
            cur = conn.execute(
                """DELETE FROM threat_technologies
                    WHERE threat_id=? AND technology_id=(SELECT id FROM technologies WHERE slug=?)""",
                (threat_id, slug))
            if cur.rowcount:
                ajustes.append(f"desvinculada de {slug}")

        if desvincular:
            fila = conn.execute("SELECT severity, cvss_score, epss_score, in_kev FROM threats WHERE id=?",
                                (threat_id,)).fetchone()
            tecs = [dict(r) for r in conn.execute(
                """SELECT t.criticality, t.exposure, t.systems_count, tt.version_verdict, tt.confidence
                     FROM threat_technologies tt JOIN technologies t ON t.id = tt.technology_id
                    WHERE tt.threat_id=?""", (threat_id,))]
            nueva = scoring.relevancia(
                severity=fila["severity"], cvss_score=fila["cvss_score"], epss=fila["epss_score"],
                in_kev=bool(fila["in_kev"]), tecnologias=tecs,
                min_confianza=float(g.cfg.get("alert_min_match_confidence", 0.6) or 0),
                ignorar_criticidad_baja=bool(g.cfg.get("ignore_low_criticality", True)))
            conn.execute("UPDATE threats SET relevance=? WHERE id=?", (nueva, threat_id))
            ajustes.append(f"relevancia recalculada: {nueva:g}")

        db.audit(conn, g.usuario, "amenaza.estado", "threats", str(threat_id),
                 f"estado={estado}" + (f" motivo={motivo}" if motivo else "")
                 + ("; " + "; ".join(ajustes) if ajustes else ""), request.remote_addr)

    texto = f"Estado cambiado a «{queries.ESTADO_ES.get(estado, estado)}»."
    if ajustes:
        texto += " Ajustes aplicados: " + "; ".join(ajustes) + "."
    if estado in queries.ESTADOS_CERRADOS:
        texto += " La amenaza deja de contar en alertas, resúmenes e informes."
    flash(texto, "exito")
    return redirect(url_for("amenazas.detalle", threat_id=threat_id))


@bp.route("/exportar.csv")
@auth.requiere_login
def exportar():
    f = _filtros()
    resultados, _ = queries.buscar(g.db, limite=5000, desplazamiento=0, **f)

    salida = io.StringIO()
    escritor = csv.writer(salida, delimiter=";")
    escritor.writerow(["cve", "titulo", "severidad", "origen_severidad", "cvss",
                       "epss", "en_kev", "mes", "relevancia", "estado", "motivo_no_alerta",
                       "tecnologias", "veredicto_version", "publicada", "detectada", "fuentes"])
    for a in resultados:
        escritor.writerow([celda_csv(_v) for _v in [
            a["cve"] or "", a["title_es"] or a["title_en"], a["severity"],
            a["severity_source"],
            "" if a["cvss_score"] is None else f"{a['cvss_score']:.1f}",
            "" if a["epss_score"] is None else f"{a['epss_score']:.4f}",
            "si" if a["in_kev"] else "no", a["month"], f"{a['relevance']:.1f}",
            queries.ESTADO_ES.get(a.get("estado") or "nueva", a.get("estado") or ""),
            a.get("alert_skip_reason") or "",
            ", ".join(t["name"] for t in a["technologies"]),
            ", ".join(sorted({t["version_verdict"] for t in a["technologies"]})),
            a["published_at"] or "", a["first_seen_at"],
            ", ".join(s["name"] for s in a["sources"]),
        ]])

    return Response(
        "﻿" + salida.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=amenazas.csv"})


SEVERIDAD_ES = {"Critical": "Crítica", "High": "Alta", "Medium": "Media", "Low": "Baja"}


def _segmentos_severidad(t: dict, *, sin_bajas: bool = True) -> list[tuple]:
    """Segmentos (clave, valor, nombre) de una tecnologia apilada por severidad.

    Con la regla interna de no reportar las bajas (por omision) son exactamente tres:
    criticas, altas y medias. Con la regla desactivada, las bajas se deducen del total
    para que la barra mida las amenazas distintas de la tecnologia (una amenaza sin
    severidad cuenta como baja).
    """
    criticas = int(t.get("criticas") or 0)
    altas = int(t.get("altas") or 0)
    medias = int(t.get("medias") or 0)
    bajas = max(int(t.get("amenazas") or 0) - criticas - altas - medias, 0)
    segmentos = [("critico", criticas, "Críticas"), ("alto", altas, "Altas"),
                 ("medio", medias, "Medias")]
    if not sin_bajas:
        segmentos.append(("bajo", bajas, "Bajas"))
    return segmentos


def _nota_tecnologia(t: dict) -> str:
    """Nota de la fila de una tecnologia en el grafico de Tendencias.

    El grafico apila por severidad, asi que la nota aporta lo que el color no
    dice: cuantas amenazas estan confirmadas por la version instalada («3
    confirmadas») y «sin versión» cuando el inventario no la tiene. Una sola
    cifra, porque la nota va a la derecha de la barra y el modulo de graficos
    reserva para ella el ancho del texto mas largo (con dos cifras las barras
    quedaban en un tercio del grafico, medido el 2026-09-04). El veredicto
    completo (confirmadas, sin determinar, descartadas) va en la tabla de debajo.
    """
    partes = []
    confirmadas = int(t.get("confirmadas") or 0)
    if confirmadas:
        partes.append(f"{fmt(confirmadas)} {'confirmada' if confirmadas == 1 else 'confirmadas'}")
    if not t.get("version_installed"):
        partes.append("sin versión")
    return " · ".join(partes)


def _opciones_linea_cvss(funcion=None) -> dict:
    """Argumentos extra para ``graficos.linea_tiempo`` en el CVSS medio mensual.

    El CVSS va de 0 a 10, asi que el eje Y debe terminar en 10 y no en el 12
    que elige la escala automatica con una media de 9,4 (revision visual del
    2026-09-03). El parametro ``tope`` lo incorpora ``graficos.linea_tiempo``
    en un cambio paralelo: mientras no exista no se pasa nada y la pagina
    sigue funcionando con la escala automatica; en cuanto exista se usa sin
    tocar esta vista ni la plantilla. ``funcion`` permite probarlo con un doble.
    """
    funcion = graficos.linea_tiempo if funcion is None else funcion
    try:
        parametros = inspect.signature(funcion).parameters
    except (TypeError, ValueError):
        return {}
    return {"tope": 10} if "tope" in parametros else {}


# --------------------------------------------------------------------------
# Serie anual de vulnerabilidades e informe del mes (Tendencias, 2026-09-08)
# --------------------------------------------------------------------------
#: Nombres de leyenda de los segmentos por severidad (serie anual y meses del año).
NOMBRES_SEVERIDAD = {"critico": "Críticas", "alto": "Altas", "medio": "Medias", "bajo": "Bajas"}


def _anio_elegido(anios: list[str], pedido: str | None, mes: str | None) -> str | None:
    """Año del que se muestran los doce meses en la serie anual.

    Primero el pedido por la persona («?anio=2025») si es un año con datos; si no, el
    año del mes seleccionado arriba, para que al cambiar de mes el detalle acompañe; y
    en último término el más reciente. Nunca un año sin datos: el selector solo ofrece
    los que existen y una dirección escrita a mano no puede sacar la página de esa lista.
    """
    pedido = (pedido or "").strip()
    if pedido in anios:
        return pedido
    del_mes = (mes or "")[:4]
    if del_mes in anios:
        return del_mes
    return anios[0] if anios else None


def _items_anuales(anual: list[dict], *, sin_bajas: bool, mes: str | None) -> list[dict]:
    """Filas de ``graficos.barras_horizontales`` para la serie anual.

    Una barra por año apilada en críticas, altas y medias (bajas solo con la regla
    interna desactivada), y como nota cuántos meses del año tienen datos: un año con
    tres meses no se compara a ciegas con uno de doce y la barra sola lo ocultaría. El
    enlace de la etiqueta cambia el año del detalle mensual conservando el mes elegido
    arriba (``url_for`` omite ``mes`` cuando vale None).
    """
    salida = []
    for a in anual:
        valores = [("critico", int(a.get("criticas") or 0)),
                   ("alto", int(a.get("altas") or 0)),
                   ("medio", int(a.get("medias") or 0))]
        if not sin_bajas:
            valores.append(("bajo", int(a.get("bajas") or 0)))
        meses = int(a.get("meses") or 0)
        salida.append({
            "etiqueta": str(a["anio"]),
            "valores": valores,
            "href": url_for("amenazas.tendencias", anio=a["anio"], mes=mes),
            "nota": f"{fmt(meses)} {'mes' if meses == 1 else 'meses'} con datos",
        })
    return salida


def _meses_del_anio(evolucion: list[dict], anio: str | None) -> list[dict]:
    """Los doce meses de ``anio``, de enero a diciembre, con las cifras de
    ``queries.evolucion_mensual`` y ceros donde no hay datos.

    ``con_datos`` distingue un mes realmente a cero de uno sin ninguna amenaza
    registrada (por ejemplo, los meses que aún no han llegado): la tabla lo escribe en
    vez de fingir un mes vacío.
    """
    from webui.filtros import MESES
    if not anio:
        return []
    por_mes = {str(e["month"]): e for e in evolucion
               if str(e.get("month") or "").startswith(f"{anio}-")}
    salida = []
    for numero in range(1, 13):
        clave = f"{anio}-{numero:02d}"
        e = por_mes.get(clave) or {}
        salida.append({
            "month": clave,
            "nombre": MESES[numero - 1],
            "total": int(e.get("total") or 0),
            "criticas": int(e.get("criticas") or 0),
            "altas": int(e.get("altas") or 0),
            "medias": int(e.get("medias") or 0),
            "bajas": int(e.get("bajas") or 0),
            "en_kev": int(e.get("en_kev") or 0),
            "con_datos": clave in por_mes,
            # Un mes que aun no ha llegado no es «sin amenazas registradas»: se dice.
            "futuro": clave > date.today().strftime("%Y-%m"),
        })
    return salida


def _series_meses_anio(meses_anio: list[dict], *, sin_bajas: bool) -> tuple[list[str], list[dict]]:
    """Categorías (nombres de los doce meses) y series por severidad para
    ``graficos.barras_apiladas``; mismas claves de color que la serie mensual."""
    categorias = [m["nombre"] for m in meses_anio]
    series = [
        {"clave": "critico", "nombre": "Críticas", "valores": [m["criticas"] for m in meses_anio]},
        {"clave": "alto", "nombre": "Altas", "valores": [m["altas"] for m in meses_anio]},
        {"clave": "medio", "nombre": "Medias", "valores": [m["medias"] for m in meses_anio]},
    ]
    if not sin_bajas:
        series.append({"clave": "bajo", "nombre": "Bajas", "valores": [m["bajas"] for m in meses_anio]})
    return categorias, series


def _url_informe(mes: str | None) -> str | None:
    """Dirección del botón «Descargar el informe de <mes>», o None si no debe verse.

    El botón se muestra solo si hay mes, si el módulo de informes está registrado en
    la aplicación (lo enlaza el coordinador en ``webui/app.py``; sin él, ``url_for``
    lanzaría ``BuildError`` y la página entera caería) y si el perfil de la sesión
    puede generar informes. El permiso se pregunta al propio módulo
    (``informes._puede_generar_informes``) para que no haya dos reglas distintas.
    """
    if not mes or "informes.descargar" not in current_app.view_functions:
        return None
    from webui.vistas import informes
    if not informes._puede_generar_informes():
        return None
    return url_for("informes.descargar", mes=mes)


@bp.route("/tendencias")
@auth.requiere_login
def tendencias():
    """Tendencias: serie mensual, severidad y procedencia del dato, CVSS medio,
    tecnologias por veredicto y CVE recurrentes.

    Los datos de los graficos se preparan aqui como listas y diccionarios
    simples y la plantilla llama a ``graficos.<funcion>(...)`` (seccion 6 de
    docs/DISENO_INTERFAZ_2026-09-03.md). ``evolucion_mensual`` devuelve los
    meses del mas reciente al mas antiguo: la tabla conserva ese orden y los
    graficos lo invierten (cronologico ascendente). Cada grafico se alimenta
    de la misma consulta que la tabla que lo acompana, para que las cifras
    coincidan.

    Las tecnologias se piden ordenadas por numero de amenazas (no por criticas,
    como en el informe y el panel): aqui el grafico apila por veredicto de
    version, asi que el unico criterio de orden que el lector puede ver es la
    longitud de la barra. La tabla sigue el mismo orden y conserva la columna
    «Criticas» para quien quiera ese detalle; la nota de cada barra resume la
    severidad (:func:`_nota_tecnologia`).
    """
    from webui.filtros import MESES, mes_es

    # Regla interna: las bajas no se reportan (ajuste ignore_low_severity, activo): la
    # serie, la dona y la tabla tienen exactamente tres severidades.
    sin_bajas = bool(g.cfg.get("ignore_low_severity", True))
    evolucion = queries.evolucion_mensual(g.db, 24, excluir_bajas=sin_bajas)
    meses = queries.meses_disponibles(g.db)
    pedido = (request.args.get("mes") or "").strip()
    # Solo meses con datos: un «?mes=1999-99» escrito a mano no puede producir un botón de
    # descarga de un informe que no existe (revisión del 2026-09-08).
    mes = pedido if pedido in meses else (meses[0] if meses else None)
    stats = queries.estadisticas_mes(g.db, mes, excluir_bajas=sin_bajas) if mes else None
    # Las tres severidades, como la grafica que las apila: sin este filtro la barra
    # sumaba 1.202 y la tabla de debajo 1.235 en el mismo panel (revision del 2026-09-09).
    top = (queries.top_tecnologias(g.db, mes, 20, orden="amenazas", excluir_bajas=sin_bajas)
           if mes else [])
    recurrentes = queries.cve_recurrentes(g.db, 25)

    ascendente = list(reversed(evolucion))
    abreviar = len(ascendente) > 8

    def etiqueta_mes(month) -> str:
        # Con mas de 8 periodos la etiqueta del eje X va en dos lineas: mes
        # abreviado arriba y ano completo debajo («sep» / «2026»), asi caben
        # todas sin solaparse y el ano se lee entero (peticion del 2026-09-05).
        # Con pocos periodos se escribe el mes completo.
        if not abreviar:
            return mes_es(month)
        try:
            anio, numero = str(month).split("-")[:2]
            return f"{MESES[int(numero) - 1][:3]}\n{anio}"
        except (ValueError, IndexError):
            return str(month)

    serie_categorias = [etiqueta_mes(e["month"]) for e in ascendente]
    serie_severidad = [
        {"clave": "critico", "nombre": "Críticas",
         "valores": [e["criticas"] for e in ascendente]},
        {"clave": "alto", "nombre": "Altas",
         "valores": [e["altas"] for e in ascendente]},
        {"clave": "medio", "nombre": "Medias",
         "valores": [e["medias"] for e in ascendente]},
    ]
    if not sin_bajas:
        serie_severidad.append({"clave": "bajo", "nombre": "Bajas",
                                "valores": [e["bajas"] for e in ascendente]})
    linea_kev = {"clave": "kev", "nombre": "En KEV",
                 "valores": [e["en_kev"] for e in ascendente]}

    dona_severidad = []
    if stats:
        dona_severidad = [
            {"clave": "critico", "nombre": "Críticas", "valor": stats["criticas"]},
            {"clave": "alto", "nombre": "Altas", "valor": stats["altas"]},
            {"clave": "medio", "nombre": "Medias", "valor": stats["medias"]},
        ]
        if not sin_bajas:
            dona_severidad.append({"clave": "bajo", "nombre": "Bajas", "valor": stats["bajas"]})

    # Procedencia de la severidad por mes (los 12 mas recientes, en el mismo
    # orden que la tabla): CVSS oficial de NVD frente a severidad estimada.
    procedencia = []
    for e in evolucion[:12]:
        total = e["total"] or 0
        oficial = min(e["sev_nvd"] or 0, total)
        estimada = total - oficial
        procedencia.append({
            "month": e["month"],
            "total": total,
            "oficial": oficial,
            "estimada": estimada,
            "pct_oficial": round(oficial * 100.0 / total, 1) if total else 0.0,
            "partes": [
                {"clave": "exito", "nombre": "Oficial (NVD)", "valor": oficial},
                {"clave": "neutro", "nombre": "Estimada", "valor": estimada},
            ],
            # Cifras en formato espanol (1.235), como en la tabla adyacente.
            "aria": (f"Procedencia de la severidad en {mes_es(e['month'])}: "
                     f"{fmt(oficial)} con CVSS oficial de NVD y {fmt(estimada)} "
                     f"estimadas de {fmt(total)}"),
        })

    # CVSS medio mensual: solo los meses con alguna puntuacion real, para no
    # dibujar un 0 donde en realidad no hay dato.
    con_cvss = [e for e in ascendente if e.get("cvss_medio") is not None]
    cvss_etiquetas = [etiqueta_mes(e["month"]) for e in con_cvss]
    cvss_series = [{"clave": "acento", "nombre": "CVSS medio",
                    "valores": [e["cvss_medio"] for e in con_cvss]}]
    cvss_opciones = _opciones_linea_cvss()  # tope=10 cuando el modulo lo admita

    # Tecnologias apiladas por severidad, con los mismos cuatro colores que el
    # resto de la plataforma; misma consulta que la tabla. Apilar por veredicto
    # dejaba el grafico de un solo color mientras falten versiones en el
    # inventario (217 «sin determinar» frente a 1 confirmada el 2026-09-05), asi
    # que el veredicto va en la nota («3 confirmadas») y en la tabla.
    tec_items = [{
        "etiqueta": t["name"],
        "valores": _segmentos_severidad(t, sin_bajas=sin_bajas),
        "href": url_for("amenazas.lista", tec=t["slug"], mes=mes),
        "nota": _nota_tecnologia(t),
    } for t in top]

    # Meses en los que aparece cada uno de los 10 CVE mas recurrentes. La barra
    # lleva el color de la severidad mayor del CVE y la nota la escribe (el color
    # nunca va solo) y marca los KEV. Sin leyenda: sumaria meses por color, que no
    # significa nada.
    cve_items = [{
        "etiqueta": r["cve"],
        "valores": [(SEVERIDAD_CLAVE.get(r.get("severidad"), "neutro"), r["meses"], "Meses presentes")],
        "href": url_for("amenazas.lista", q=r["cve"]),
        "nota": " · ".join(p for p in (SEVERIDAD_ES.get(r.get("severidad"), ""),
                                     "explotación activa (KEV)" if r.get("en_kev") else "") if p),
    } for r in recurrentes[:10]]

    # Serie anual de vulnerabilidades (petición del usuario del 2026-09-08): una barra
    # por año y, debajo, los doce meses del año elegido. Los meses salen de la MISMA
    # consulta que la serie mensual (evolucion_mensual), pedida con margen suficiente
    # para cubrir todos los años con datos, así que el total de cada año es la suma
    # exacta de sus doce meses y las dos series no pueden discrepar.
    anual = queries.serie_anual(g.db, excluir_bajas=sin_bajas)
    anios = [a["anio"] for a in anual]
    anio = _anio_elegido(anios, request.args.get("anio"), mes)
    evolucion_toda = (queries.evolucion_mensual(g.db, 12 * (len(anios) + 1), excluir_bajas=sin_bajas)
                      if anios else [])
    meses_anio = _meses_del_anio(evolucion_toda, anio)
    anual_items = _items_anuales(anual, sin_bajas=sin_bajas, mes=mes)
    anio_categorias, anio_series = _series_meses_anio(meses_anio, sin_bajas=sin_bajas)

    return render_template(
        "tendencias.html", sin_bajas=sin_bajas, evolucion=evolucion, meses=meses, mes=mes,
        stats=stats, top=top, recurrentes=recurrentes,
        serie_categorias=serie_categorias, serie_severidad=serie_severidad,
        linea_kev=linea_kev, dona_severidad=dona_severidad,
        procedencia=procedencia, cvss_etiquetas=cvss_etiquetas,
        cvss_series=cvss_series, cvss_opciones=cvss_opciones,
        tec_items=tec_items, cve_items=cve_items,
        anual=anual, anios=anios, anio=anio, meses_anio=meses_anio,
        anual_items=anual_items, anio_categorias=anio_categorias, anio_series=anio_series,
        nombres_severidad=NOMBRES_SEVERIDAD,
        # Botón «Descargar el informe de <mes>» (solo con permiso y módulo registrado).
        url_informe=_url_informe(mes))


#: Activos por página del cuadro de activos afectados (modal y ficha de amenaza): poco,
#: para que la tabla no se extienda sin fin (petición del usuario).
POR_PAGINA_MODAL_ACTIVOS = 10


@bp.route("/activos-afectados/<int:threat_id>")
@auth.requiere_login
def activos_afectados_json(threat_id):
    """Retorna JSON con los activos afectados por una amenaza, con paginación y filtros.

    Incluye la remediación asociada (si existe) para poder comprobarla sin salir de la
    ficha de la amenaza: mismo criterio de union que ``remediaciones`` ya usa
    (``activo_id, cve, paquete``), es la clave UNIQUE de esa tabla. También marca el
    riesgo aceptado (excepciones vigentes) con el mismo índice que usa la ficha
    (``webui.vistas.remediaciones.indice_riesgo_aceptado``), para no repetir ese cruce
    aquí: un activo con el riesgo aceptado SIGUE apareciendo (es un hecho técnico que
    sigue teniendo la versión vulnerable), pero marcado, igual que en el resto de la
    plataforma.

    NO incluye el comando de verificación específico del ecosistema
    (``dpkg --compare-versions`` y equivalentes), que sí trae la ficha de la amenaza
    completa vía ``aplicabilidad.activos_de_amenaza``: pendiente de traerlo también
    aquí si hace falta en el cuadro paginado.
    """
    threat = g.db.execute(
        "SELECT id, cve FROM threats WHERE id = ?", (threat_id,)).fetchone()

    if not threat:
        return jsonify({"error": "Amenaza no encontrada"}), 404

    cve = threat["cve"]
    por_pagina = POR_PAGINA_MODAL_ACTIVOS
    if not cve:
        return jsonify({"activos": [], "total": 0, "pagina": 1, "por_pagina": por_pagina,
                        "max_paginas": 1, "puede_remediar": auth.puede_remediar()})

    pagina = request.args.get("pagina", 1, type=int)
    buscar = request.args.get("buscar", "", type=str).strip()

    query_base = """
        SELECT DISTINCT a.id, a.nombre, a.ip, a.origen as tipo, a.ecosistema, a.so_familia,
               ap.cve, ap.veredicto, ap.paquete, ap.version_instalada, ap.version_corregida,
               ap.motor, ap.evidencia, ap.aviso, ap.referencia, ap.sin_parche_motivo,
               r.id as remediacion_id, r.estado as remediacion_estado
        FROM aplicabilidad ap
        JOIN activos a ON ap.activo_id = a.id
        LEFT JOIN remediaciones r ON r.activo_id = ap.activo_id
                                  AND r.cve = ap.cve AND r.paquete = ap.paquete
        WHERE ap.cve = ? AND ap.veredicto = 'afectado' AND a.presente = 1
    """

    params: list = [cve]
    # Alcance por tipo de máquina (2026-09-08): redes y mantenimiento solo ven lo suyo,
    # igual que el resto de la ficha (webui.vistas.amenazas._plan_en_alcance).
    alcance = auth.alcance_origen()
    if alcance:
        query_base += " AND a.origen = ?"
        params.append(alcance)
    if buscar:
        query_base += " AND (a.nombre LIKE ? OR a.ip LIKE ? OR ap.paquete LIKE ?)"
        buscar_param = f"%{buscar}%"
        params.extend([buscar_param, buscar_param, buscar_param])

    total = g.db.execute(f"SELECT COUNT(*) as cnt FROM ({query_base})", params).fetchone()["cnt"]

    offset = (pagina - 1) * por_pagina
    query_base += " ORDER BY a.nombre LIMIT ? OFFSET ?"
    params.extend([por_pagina, offset])

    activos = g.db.execute(query_base, params).fetchall()

    indice_aceptado = indice_riesgo_aceptado(excepciones_vigentes(g.db))
    cve_str = str(cve or "")

    result = []
    for activo in activos:
        veredicto_clase = "critico" if activo["veredicto"] == "afectado" else "neutro"
        veredicto_es = "Afectado" if activo["veredicto"] == "afectado" else "Sin dato"
        remediacion_estado = activo["remediacion_estado"]
        riesgo_aceptado = (indice_aceptado["activo_cve"].get((activo["id"], cve_str))
                           or indice_aceptado["cve"].get(cve_str)
                           or indice_aceptado["activo_paquete"].get((activo["id"], activo["paquete"] or "")))
        # Mismo cálculo que la ficha completa (texto de la comparación, comando de
        # verificación según el ecosistema, aviso y fuente oficial): una sola fuente de
        # verdad, no se reinventa aquí.
        detalle_paquete = aplicabilidad.detalle_paquete_de_fila(activo, cve=cve_str)
        result.append({
            "id": activo["id"],
            "nombre": activo["nombre"] or "(sin nombre)",
            "tipo": activo["tipo"],
            "ip": activo["ip"],
            "paquete": activo["paquete"],
            "version_instalada": activo["version_instalada"],
            "version_corregida": activo["version_corregida"],
            "veredicto": activo["veredicto"],
            "veredicto_es": veredicto_es,
            "veredicto_clase": veredicto_clase,
            "remediacion_id": activo["remediacion_id"],
            "remediacion_estado": remediacion_estado,
            "remediacion_estado_es": motor_remediacion.ESTADO_ES.get(remediacion_estado, remediacion_estado),
            "remediacion_corregida": remediacion_estado == "corregida",
            "riesgo_aceptado": bool(riesgo_aceptado),
            "riesgo_aceptado_hasta": (riesgo_aceptado or {}).get("vence_at") if riesgo_aceptado else None,
            "riesgo_aceptado_permanente": bool((riesgo_aceptado or {}).get("permanente")) if riesgo_aceptado else False,
            "comparacion_texto": (detalle_paquete.get("comparacion") or {}).get("texto"),
            "verificacion": (detalle_paquete.get("comparacion") or {}).get("verificacion"),
            "referencia": detalle_paquete.get("referencia"),
            "referencia_es": detalle_paquete.get("referencia_es"),
        })

    max_paginas = max(1, (total + por_pagina - 1) // por_pagina)

    return jsonify({
        "activos": result,
        "cve": cve,
        "total": total,
        "pagina": pagina,
        "max_paginas": max_paginas,
        "por_pagina": por_pagina,
        "puede_remediar": auth.puede_remediar(),
    })


@bp.route("/activos-afectados/<int:threat_id>/comprobar/<int:remediacion_id>", methods=["POST"])
@auth.requiere_remediacion
@auth.requiere_csrf
def activos_afectados_comprobar(threat_id, remediacion_id):
    """Comprueba una remediación desde el cuadro de activos afectados, sin salir de la
    ficha de la amenaza. Mismo motor que /remediaciones/<id>/comprobar; solo cambia la
    respuesta, que es JSON para esta zona en vez de una redirección con flash."""
    threat = g.db.execute("SELECT cve FROM threats WHERE id = ?", (threat_id,)).fetchone()
    if not threat:
        return jsonify({"error": "Amenaza no encontrada"}), 404

    fila = g.db.execute(
        "SELECT activo_id, cve FROM remediaciones WHERE id = ?", (remediacion_id,)).fetchone()
    if fila is None:
        return jsonify({"error": "La remediación indicada no existe."}), 404
    if fila["cve"] != threat["cve"]:
        return jsonify({"error": "Esa remediación no corresponde a esta amenaza."}), 400
    if not auth.dentro_del_alcance(_origen_de_activo(fila["activo_id"])):
        abort(404)

    try:
        resultado = motor_remediacion.comprobar(g.db, remediacion_id, solicitante=g.usuario, ip=request.remote_addr)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:  # noqa: BLE001
        current_app.logger.error("fallo la comprobación de la remediación %s desde amenazas",
                                 remediacion_id, exc_info=exc)
        return jsonify({"error": "No se pudo comprobar la remediación por un error interno."}), 500

    return jsonify({
        "veredicto": resultado["veredicto"],
        "veredicto_es": resultado.get("veredicto_es", resultado["veredicto"]),
        "detalle": resultado.get("detalle", ""),
        "cerrada": bool(resultado.get("cerrada")),
        "remediacion_estado": "corregida" if resultado.get("cerrada") else "abierta",
    })


def _origen_de_activo(activo_id: int) -> str | None:
    fila = g.db.execute("SELECT origen FROM activos WHERE id = ?", (activo_id,)).fetchone()
    return fila["origen"] if fila else None


@bp.route("/activos-afectados/<int:threat_id>/excel")
@auth.requiere_login
def activos_afectados_excel(threat_id):
    """Exporta a Excel los activos afectados por una amenaza."""
    threat = g.db.execute(
        "SELECT id, cve, title_es, title_en FROM threats WHERE id = ?", 
        (threat_id,)).fetchone()
    
    if not threat:
        return "Amenaza no encontrada", 404
    
    cve = threat["cve"]
    titulo_amenaza = threat["title_es"] or threat["title_en"] or "(sin título)"
    
    if not cve:
        return "Amenaza sin CVE", 400
    
    query_excel = """
        SELECT DISTINCT a.id, a.nombre, a.ip, a.origen as tipo,
               ap.veredicto, ap.paquete, ap.version_instalada, ap.version_corregida,
               r.estado as remediacion_estado
        FROM aplicabilidad ap
        JOIN activos a ON ap.activo_id = a.id
        LEFT JOIN remediaciones r ON r.activo_id = ap.activo_id
                                  AND r.cve = ap.cve AND r.paquete = ap.paquete
        WHERE ap.cve = ? AND ap.veredicto = 'afectado' AND a.presente = 1
    """
    params_excel: list = [cve]
    # Mismo alcance por tipo de máquina que el cuadro paginado: redes y mantenimiento
    # no pueden exportar lo que no pueden ver.
    alcance = auth.alcance_origen()
    if alcance:
        query_excel += " AND a.origen = ?"
        params_excel.append(alcance)
    query_excel += " ORDER BY a.nombre"
    activos = g.db.execute(query_excel, params_excel).fetchall()

    indice_aceptado = indice_riesgo_aceptado(excepciones_vigentes(g.db))
    cve_str = str(cve or "")

    wb = Workbook()
    ws = wb.active
    ws.title = "Activos Afectados"

    encabezado = PatternFill(start_color="FF1F4E78", end_color="FF1F4E78", fill_type="solid")
    fuente_encabezado = Font(bold=True, color="FFFFFFFF", size=11)

    headers = ["Nombre del activo", "Tipo", "IP", "Paquete",
               "Versión instalada", "Versión que corrige", "Estado de remediación",
               "Riesgo aceptado"]
    for col, header in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col)
        cell.value = header
        cell.fill = encabezado
        cell.font = fuente_encabezado
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)

    for row_idx, activo in enumerate(activos, 2):
        riesgo_aceptado = (indice_aceptado["activo_cve"].get((activo["id"], cve_str))
                           or indice_aceptado["cve"].get(cve_str)
                           or indice_aceptado["activo_paquete"].get((activo["id"], activo["paquete"] or "")))
        ws.cell(row=row_idx, column=1).value = activo["nombre"] or "(sin nombre)"
        ws.cell(row=row_idx, column=2).value = activo["tipo"]
        ws.cell(row=row_idx, column=3).value = activo["ip"] or "-"
        ws.cell(row=row_idx, column=4).value = activo["paquete"] or "-"
        ws.cell(row=row_idx, column=5).value = activo["version_instalada"] or "-"
        ws.cell(row=row_idx, column=6).value = activo["version_corregida"] or "-"
        ws.cell(row=row_idx, column=7).value = motor_remediacion.ESTADO_ES.get(
            activo["remediacion_estado"], "Sin seguimiento")
        ws.cell(row=row_idx, column=8).value = (
            ("Sí (permanente)" if riesgo_aceptado.get("permanente") else "Sí, hasta " + str(riesgo_aceptado.get("vence_at") or ""))
            if riesgo_aceptado else "No")
        for col in range(1, 9):
            cell = ws.cell(row=row_idx, column=col)
            cell.alignment = Alignment(horizontal="left", vertical="center", wrap_text=False)

    ws.column_dimensions["A"].width = 30
    ws.column_dimensions["B"].width = 15
    ws.column_dimensions["C"].width = 18
    ws.column_dimensions["D"].width = 25
    ws.column_dimensions["E"].width = 25
    ws.column_dimensions["F"].width = 25
    ws.column_dimensions["G"].width = 25
    ws.column_dimensions["H"].width = 22

    ws.freeze_panes = "A2"

    output = io.BytesIO()
    wb.save(output)
    output.seek(0)
    
    filename = f"activos_afectados_{cve.replace('/', '_')}.xlsx"
    return Response(
        output.getvalue(),
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename={filename}"})

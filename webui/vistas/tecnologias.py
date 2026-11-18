"""Inventario tecnologico con versiones.

Peticion explicita del usuario: poder registrar las tecnologias CON las
versiones que tiene instaladas, para afinar los hallazgos y evitar falsos
positivos. La version permite decidir si un aviso que dice "afecta a versiones
anteriores a 4.3" nos afecta o no.

Rediseño del 2026-09-03 (sección 6 «Inventario» de docs/DISENO_INTERFAZ_2026-09-03.md):
la vista prepara los datos de los gráficos como listas y diccionarios simples y
la plantilla los pinta con ``graficos.<función>(...)``:

* ``dona`` por criticidad (Crítica, Alta, Media, Baja) con el total en el centro;
* ``barras_apiladas`` por categoría de tecnología (Con versión / Sin versión)
  para ver dónde falta completar el inventario;
* ``barras_horizontales`` de las diez tecnologías con más amenazas (Críticas,
  Altas, Resto) con enlace a su ficha y nota «sin versión»;
* en la ficha, ``dona`` de veredictos (Afectada, No afectada, Sin determinar) y
  ``barras_apiladas`` por mes de sus amenazas por severidad (SQL local
  ``GROUP BY month`` en orden ascendente).

Criticidad, exposición, categoría y veredicto se muestran en español mediante
los diccionarios de este módulo; los valores almacenados no cambian.
"""
from __future__ import annotations

import csv
import io
import json
import sqlite3
from typing import Any, Iterable, Optional

from flask import (Blueprint, Response, current_app, flash, g, redirect,
                   render_template, request, url_for)

from threatintel import db
from webui import auth
from webui.filtros import MESES, celda_csv

bp = Blueprint("tecnologias", __name__, url_prefix="/tecnologias")

CATEGORIAS = ["sistema_operativo", "base_datos", "servidor_web", "red",
              "seguridad", "aplicacion", "escritorio", "desarrollo",
              "comunicaciones", "virtualizacion"]
CRITICIDADES = ["critical", "high", "medium", "low"]
EXPOSICIONES = ["internet", "dmz", "interna"]
MODOS = ["word", "phrase", "regex"]

#: Etiquetas visibles en español (regla 7 de la especificación). Los valores
#: almacenados (``critical``, ``interna``…) no cambian: solo su presentación.
CRITICIDAD_ES = {"critical": "Crítica", "high": "Alta", "medium": "Media", "low": "Baja"}
CRITICIDAD_CLAVE = {"critical": "critico", "high": "alto", "medium": "medio", "low": "bajo"}
EXPOSICION_ES = {"internet": "Internet", "dmz": "Perimetral (DMZ)", "interna": "Red interna",
                 "internal": "Red interna", "local": "Local"}
VEREDICTO_ES = {"affected": "Afectada", "not_affected": "No afectada", "unknown": "Sin determinar"}
VEREDICTO_CLAVE = {"affected": "critico", "not_affected": "exito", "unknown": "neutro"}
MODO_ES = {"word": "Palabra completa", "phrase": "Frase exacta", "regex": "Expresión regular"}
#: Nombres legibles de categoría. El inventario base usa guiones
#: («sistema-operativo») y el formulario guiones bajos («sistema_operativo»);
#: se admiten ambos y cualquier otro valor se humaniza en ``categoria_es``.
CATEGORIA_ES = {
    "sistema-operativo": "Sistema operativo", "sistema_operativo": "Sistema operativo",
    "base-de-datos": "Base de datos", "base_datos": "Base de datos",
    "servidor-web": "Servidor web", "servidor_web": "Servidor web",
    "servidor-aplicaciones": "Servidor de aplicaciones",
    "red": "Red", "seguridad": "Seguridad", "aplicacion": "Aplicación",
    "escritorio": "Escritorio", "desarrollo": "Desarrollo",
    "comunicaciones": "Comunicaciones", "virtualizacion": "Virtualización",
    "colaboracion": "Colaboración", "utilidad": "Utilidad", "navegador": "Navegador",
    "ofimatica": "Ofimática", "monitorizacion": "Monitorización",
    "directorio": "Directorio", "correo": "Correo",
    "gestion-documental": "Gestión documental", "criptografia": "Criptografía",
    "contenedores": "Contenedores", "acceso-remoto": "Acceso remoto",
}

#: Con más de 8 categorías el eje X alterna etiquetas; por encima se muestran
#: las 7 mayores y el resto agrupado en «Otras categorías» (la tabla detalla todas).
MAX_CATEGORIAS_GRAFICO = 8
TOP_TECNOLOGIAS = 10
#: Tecnologias por pagina en la tabla del inventario (2026-09-07): con 198
#: tecnologias la tabla ocupaba una pantalla interminable y la version se edita en
#: linea en cada fila, asi que conviene verlas por tandas.
#: Filas por pagina en los listados largos. El usuario pidio 20 el 2026-09-07
#: («que en cada uno solo muestre de a 20»): una pantalla se recorre de un vistazo.
POR_PAGINA = 20
#: Con más de 8 meses en el eje X se usan etiquetas cortas («sep 26»).
MAX_MESES_ETIQUETA_LARGA = 8


def _pagina_valida(pagina: Any, total: int, por_pagina: int) -> tuple[int, int]:
    """(pagina, paginas) con la pagina acotada al rango real (2026-09-07).

    Una pagina fuera de rango no es un error: se atiende con la primera o con la
    ultima, para que un enlace antiguo o un filtro que reduce el total sigan
    devolviendo una pagina util.
    """
    por_pagina = max(1, int(por_pagina or 1))
    paginas = max(1, -(-int(total or 0) // por_pagina))
    try:
        pagina = int(pagina)
    except (TypeError, ValueError):
        pagina = 1
    return min(max(pagina, 1), paginas), paginas


def _escapar_like(texto: str) -> str:
    """El texto buscado con los comodines de ``LIKE`` neutralizados (2026-09-07).

    Hallazgo del revisor: sin ``ESCAPE``, «%» y «_» eran comodines y buscar «%»
    devolvia el inventario completo. Se escapan como en ``threatintel/remediacion.py``
    y ``threatintel/parches.py``.
    """
    return str(texto or "").replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _patron_like(texto: str) -> str:
    """El texto buscado convertido en patron «%texto%» ya escapado."""
    return f"%{_escapar_like(texto)}%"


#: Argumentos reservados de ``url_for`` (2026-09-07). Un parametro de la direccion
#: llamado como uno de ellos («?_anchor=x», «?endpoint=x», «?_method=POST») no es un
#: filtro de la pagina: si se reenviara a ``url_for(..., **args)`` la llamada
#: recibiria el mismo argumento dos veces y la pagina responderia con un error 500.
_ARGS_RESERVADOS = ("endpoint", "values")


def _args_a_conservar(*excluir: str) -> dict[str, str]:
    """Los argumentos de la direccion que se conservan al cambiar de pagina (los
    filtros), sin los ``excluir`` ni los reservados de ``url_for``."""
    return {k: v for k, v in request.args.items()
            if k not in excluir and k not in _ARGS_RESERVADOS and not k.startswith("_")}

def _mod(nombre: str):
    return __import__(f"threatintel.{nombre}", fromlist=["x"])


# --------------------------------------------------------------------------
# Etiquetas en español
# --------------------------------------------------------------------------
def categoria_es(valor: Any) -> str:
    """'base-de-datos' → 'Base de datos'; un valor desconocido se humaniza."""
    texto = str(valor or "").strip().lower()
    if not texto:
        return "—"
    if texto in CATEGORIA_ES:
        return CATEGORIA_ES[texto]
    return texto.replace("-", " ").replace("_", " ").strip().capitalize() or "—"


def _etiquetar(fila: dict) -> dict:
    """Añade a una fila de ``technologies`` sus etiquetas visibles en español."""
    fila["categoria_es"] = categoria_es(fila.get("category"))
    criticidad = str(fila.get("criticality") or "")
    fila["criticidad_es"] = CRITICIDAD_ES.get(criticidad, criticidad or "—")
    exposicion = str(fila.get("exposure") or "")
    fila["exposicion_es"] = EXPOSICION_ES.get(exposicion, exposicion.capitalize() or "—")
    return fila


def _mes_corto(month: Optional[str], *, corto: bool = False) -> str:
    """'2026-09' → 'septiembre de 2026' (o en dos líneas, con ``corto``) para el eje X.

    Sin abreviaturas, como pide la regla del proyecto y el contrato de ``webui/graficos``
    (revisión de interfaz del 2026-09-09; antes se recortaba a tres letras). Con la
    preposición «de», como en el resto de la plataforma (filtro ``mes_es``): el eje decía
    «marzo 2026» y la tabla de debajo «marzo de 2026» para el mismo mes (revisión de
    claridad del 2026-09-15).
    """
    if not month or "-" not in str(month):
        return str(month or "—")
    anio, mes = str(month).split("-")[:2]
    try:
        nombre = MESES[int(mes) - 1]
    except (ValueError, IndexError):
        return str(month)
    return f"{nombre}\nde {anio}" if corto else f"{nombre} de {anio}"


# --------------------------------------------------------------------------
# Consultas locales (SQL pequeño y documentado)
# --------------------------------------------------------------------------
def _conteo_criticidad(conn: sqlite3.Connection) -> dict[str, int]:
    """Tecnologías por criticidad; cualquier valor no previsto va a ``otras``."""
    conteo = {c: 0 for c in CRITICIDADES}
    conteo["otras"] = 0
    for fila in conn.execute(
            "SELECT criticality, COUNT(*) AS n FROM technologies GROUP BY criticality"):
        clave = fila["criticality"] if fila["criticality"] in conteo else "otras"
        conteo[clave] += int(fila["n"] or 0)
    return conteo


def categorias_del_inventario(conn: sqlite3.Connection) -> list[str]:
    """LA lista de categorías: las que de verdad tiene el inventario, en orden alfabético
    por su nombre visible.

    Por qué (revisión de claridad del 2026-09-15): el formulario «Nueva tecnología»
    ofrecía diez categorías fijas escritas con guion bajo («sistema_operativo») y la
    tabla «Cobertura de versiones por categoría» enseñaba otras diez, las reales, escritas
    con guion («sistema-operativo»). Dos listas distintas de lo mismo en la misma página,
    y elegir una del formulario creaba una categoría nueva que nadie más usaba. Ahora hay
    una sola lista y es la real: 21 categorías en producción.

    :data:`CATEGORIAS` se conserva como respaldo para una base vacía (una instalación
    recién creada no tiene ninguna tecnología todavía, y el formulario no puede quedarse
    sin opciones) y para las pruebas que no usan base.
    """
    try:
        filas = [r[0] for r in conn.execute(
            "SELECT DISTINCT category FROM technologies "
            "WHERE category IS NOT NULL AND category <> ''")]
    except sqlite3.Error:
        filas = []
    if not filas:
        return list(CATEGORIAS)
    return sorted(filas, key=lambda c: categoria_es(c).lower())


def _cobertura_por_categoria(conn: sqlite3.Connection) -> list[dict]:
    """Con y sin versión por categoría, de mayor a menor número de tecnologías
    (mismo criterio de «con versión» que ``health.resumen_sistema``)."""
    filas = []
    for r in conn.execute(
            """SELECT category, COUNT(*) AS total,
                      SUM(CASE WHEN version_installed IS NOT NULL
                                AND version_installed <> '' THEN 1 ELSE 0 END) AS con_version
                 FROM technologies
                GROUP BY category
                ORDER BY total DESC, category"""):
        total = int(r["total"] or 0)
        con = int(r["con_version"] or 0)
        filas.append({"categoria": r["category"], "nombre": categoria_es(r["category"]),
                      "total": total, "con_version": con, "sin_version": max(total - con, 0)})
    return filas


#: Amenazas que esta página cuenta con la regla interna activa (ajuste
#: ``ignore_low_severity``): las mismas que Amenazas, Tendencias y el Panel. Sin este
#: filtro, la columna «Amenazas» de la tabla decía 2.159 para Microsoft Windows y la
#: gráfica de la misma página 2.142 (auditoría de tableros del 2026-09-15, puntos 4 y 5).
SIN_BAJAS_SQL = "(t.severity IS NULL OR t.severity <> 'Low')"


def _top_tecnologias(conn: sqlite3.Connection, limite: int = TOP_TECNOLOGIAS, *,
                     excluir_bajas: bool = True) -> list[dict]:
    """Las tecnologías con más amenazas distintas en todo el histórico, con el
    desglose de críticas y altas (una fila por par amenaza-tecnología, así que
    las sumas por severidad son coherentes con el recuento distinto).

    ``excluir_bajas`` (regla interna, ajuste ``ignore_low_severity``, activo) deja fuera
    la severidad que no se reporta, igual que ``queries.top_tecnologias``: la barra solo
    pinta críticas, altas y medias, así que contar también las demás hacía que el total
    de la barra no fuera el de la columna de la tabla."""
    filtro = f" WHERE {SIN_BAJAS_SQL}" if excluir_bajas else ""
    return [dict(r) for r in conn.execute(
        f"""SELECT tc.id, tc.name, tc.slug, tc.version_installed, tc.criticality,
                  COUNT(DISTINCT tt.threat_id) AS amenazas,
                  SUM(t.severity='Critical') AS criticas,
                  SUM(t.severity='High')     AS altas,
                  SUM(t.severity='Medium')   AS medias
             FROM threat_technologies tt
             JOIN technologies tc ON tc.id = tt.technology_id
             JOIN threats t       ON t.id  = tt.threat_id{filtro}
            GROUP BY tc.id
            ORDER BY amenazas DESC, criticas DESC, tc.name
            LIMIT ?""", (max(1, int(limite)),))]


def _amenazas_distintas(conn: sqlite3.Connection, ids: list[int], *,
                        excluir_bajas: bool = True) -> int:
    """Amenazas DISTINTAS que mencionan alguna de las tecnologías ``ids``.

    Por qué (auditoría de tableros del 2026-09-15, punto 4): el pie de la tabla sumaba la
    columna «Amenazas» y decía 8.363, más que las 7.284 del catálogo entero, porque una
    amenaza que menciona cuatro tecnologías se contaba cuatro veces. Esta es la cifra sin
    repeticiones (6.013 con todo el inventario; 5.820 dejando fuera la severidad que no
    se reporta) y la página escribe las dos con su explicación.

    Con la lista vacía devuelve 0 sin consultar. Los identificadores van como parámetros,
    no interpolados: el inventario tiene 197 tecnologías y el tope de parámetros de SQLite
    es de 32.766, así que no hay riesgo de pasarse ni de inyectar nada.
    """
    if not ids:
        return 0
    marcas = ",".join("?" * len(ids))
    filtro = f" AND {SIN_BAJAS_SQL}" if excluir_bajas else ""
    fila = conn.execute(
        f"""SELECT COUNT(DISTINCT tt.threat_id) FROM threat_technologies tt
              JOIN threats t ON t.id = tt.threat_id
             WHERE tt.technology_id IN ({marcas}){filtro}""", ids).fetchone()
    return int(fila[0] or 0) if fila else 0


def _activos_con_estas_tecnologias(conn: sqlite3.Connection, ids: list[int],
                                   todas: bool) -> int:
    """Activos presentes DISTINTOS que tienen instalada alguna de las tecnologías ``ids``.

    Sustituye a la suma de la columna «Sistemas» del pie de la tabla, que contaba el mismo
    activo una vez por cada tecnología que tiene instalada (22.236 «sistemas» para un
    parque de 730 máquinas) y que además sumaba una columna distinta de la que se ve
    (auditoría de tableros del 2026-09-15, punto 4).

    Dos caminos, elegidos por coste medido sobre las 996.000 filas de
    ``activo_software`` de producción (2026-09-15):

    * sin filtro de búsqueda (``todas``) se pregunta por activo, que corta en cuanto
      encuentra el primer programa clasificado: 6 milisegundos;
    * con filtro se recorre el índice ``idx_actsoft_tec`` de las pocas tecnologías
      seleccionadas: 1 milisegundo. (Cambiar los caminos cuesta 220 y 148 milisegundos
      respectivamente, así que no da igual cuál se use.)
    """
    if todas:
        fila = conn.execute(
            """SELECT COUNT(*) FROM activos a WHERE a.presente=1
                 AND EXISTS (SELECT 1 FROM activo_software s
                              WHERE s.activo_id=a.id AND s.technology_id IS NOT NULL)""").fetchone()
        return int(fila[0] or 0) if fila else 0
    if not ids:
        return 0
    marcas = ",".join("?" * len(ids))
    fila = conn.execute(
        f"""SELECT COUNT(DISTINCT s.activo_id) FROM activo_software s
              JOIN activos a ON a.id = s.activo_id
             WHERE a.presente=1 AND s.technology_id IN ({marcas})""", ids).fetchone()
    return int(fila[0] or 0) if fila else 0


def _evolucion_tecnologia(conn: sqlite3.Connection, tec_id: int, *,
                          excluir_bajas: bool = True) -> list[dict]:
    """Amenazas de una tecnología por mes y severidad, en orden ascendente.

    ``excluir_bajas`` (regla interna, ajuste ``ignore_low_severity``, activo) deja fuera
    la severidad Baja del TOTAL y de la serie. Hasta el 2026-09-15 no lo hacía y la
    ficha de Microsoft Windows daba dos cifras del mismo mes: la barra de septiembre
    medía 726 (críticas + altas + medias, que es lo único que pinta el gráfico) y la
    fila de la tabla de debajo decía 734, con una columna «Bajas» que era la única de
    toda la plataforma que nombraba esa severidad.

    ``sin_severidad`` son las amenazas cuyos avisos no declaran ninguna severidad: no
    son bajas, no se pueden ocultar y por eso se devuelven aparte, de modo que
    ``criticas + altas + medias + sin_severidad == total`` siempre (mismo criterio que
    ``queries.resumen_amenazas``). ``bajas`` se conserva como clave —vale 0 con el
    ajuste activo— porque la plantilla la enseña cuando alguien desactiva el ajuste.
    """
    filtro = " AND (t.severity IS NULL OR t.severity <> 'Low')" if excluir_bajas else ""
    salida = []
    for r in conn.execute(
            f"""SELECT t.month, COUNT(*) AS total,
                      SUM(t.severity='Critical') AS criticas,
                      SUM(t.severity='High')     AS altas,
                      SUM(t.severity='Medium')   AS medias,
                      SUM(t.severity='Low')      AS bajas
                 FROM threat_technologies tt
                 JOIN threats t ON t.id = tt.threat_id
                WHERE tt.technology_id=?{filtro}
                GROUP BY t.month
                ORDER BY t.month ASC""", (tec_id,)):
        total = int(r["total"] or 0)
        criticas, altas, medias = (int(r[k] or 0) for k in ("criticas", "altas", "medias"))
        bajas = int(r["bajas"] or 0)
        salida.append({"month": r["month"], "total": total, "criticas": criticas,
                       "altas": altas, "medias": medias, "bajas": bajas,
                       "sin_severidad": max(total - criticas - altas - medias - bajas, 0)})
    return salida


# --------------------------------------------------------------------------
# Preparación de datos para los gráficos (funciones puras, fáciles de probar)
# --------------------------------------------------------------------------
def _porciones_criticidad(conteo: dict) -> list[dict]:
    porciones = [{"clave": CRITICIDAD_CLAVE[c], "nombre": CRITICIDAD_ES[c],
                  "valor": int(conteo.get(c) or 0)} for c in CRITICIDADES]
    if conteo.get("otras"):
        porciones.append({"clave": "neutro", "nombre": "Sin criticidad", "valor": conteo["otras"]})
    return porciones


def _categorias_apiladas(cobertura: Iterable[dict],
                         maximo: int = MAX_CATEGORIAS_GRAFICO) -> dict[str, Any]:
    """Categorías y series (Con versión / Sin versión) de ``barras_apiladas``.

    Si hay más de ``maximo`` categorías, se dibujan las ``maximo - 1`` mayores
    y el resto se agrupa en «Otras categorías» para que todas las etiquetas del
    eje X sean legibles; ``agrupadas`` dice cuántas se han agrupado y la tabla
    que acompaña al gráfico las detalla todas.
    """
    filas = list(cobertura or [])
    agrupadas = 0
    if len(filas) > max(2, int(maximo)):
        visibles, resto = filas[:maximo - 1], filas[maximo - 1:]
        agrupadas = len(resto)
        visibles = visibles + [{
            "nombre": f"Otras {agrupadas} categorías",
            "con_version": sum(int(f.get("con_version") or 0) for f in resto),
            "sin_version": sum(int(f.get("sin_version") or 0) for f in resto),
            "total": sum(int(f.get("total") or 0) for f in resto),
        }]
    else:
        visibles = filas
    return {
        "categorias": [f["nombre"] for f in visibles],
        "series": [
            {"clave": "exito", "nombre": "Con versión",
             "valores": [int(f.get("con_version") or 0) for f in visibles]},
            {"clave": "medio", "nombre": "Sin versión",
             "valores": [int(f.get("sin_version") or 0) for f in visibles]},
        ],
        "agrupadas": agrupadas,
    }


def _items_top(top: Iterable[dict], *, sin_bajas: bool = True) -> list[dict]:
    """Filas de ``barras_horizontales``: Críticas, Altas y Medias (y Bajas solo si la regla
    interna de no reportarlas está desactivada), con enlace a la ficha (``href`` calculado
    por la vista) y nota «sin versión»."""
    items = []
    for t in top or []:
        criticas = int(t.get("criticas") or 0)
        altas = int(t.get("altas") or 0)
        medias = int(t.get("medias") or 0)
        bajas = max(int(t.get("amenazas") or 0) - criticas - altas - medias, 0)
        valores = [("critico", criticas), ("alto", altas), ("medio", medias)]
        if not sin_bajas:
            valores.append(("bajo", bajas))
        items.append({
            "etiqueta": t.get("name") or "—",
            "valores": valores,
            "href": t.get("href") or "",
            "nota": "" if t.get("version_installed") else "sin versión",
        })
    return items


def _porciones_veredictos(veredictos: dict) -> list[dict]:
    """Afectada (crítico), No afectada (éxito), Sin determinar (neutro)."""
    conteo = {k: 0 for k in VEREDICTO_ES}
    for clave, n in (veredictos or {}).items():
        conteo["unknown" if clave not in conteo else clave] += int(n or 0)
    return [{"clave": VEREDICTO_CLAVE[k], "nombre": VEREDICTO_ES[k], "valor": conteo[k]}
            for k in ("affected", "not_affected", "unknown")]


def _series_evolucion(evolucion: Iterable[dict], *, sin_bajas: bool = True) -> dict[str, Any]:
    """Categorías (meses en orden ascendente) y series por severidad: tres (críticas, altas
    y medias) con la regla interna de no reportar las bajas, que es la situación por omisión.

    Se añade un cuarto segmento, «Sin severidad conocida», SOLO si de verdad hay alguna
    amenaza así: no es una severidad baja, no se puede ocultar y, sin él, la barra medía
    menos que la fila de la tabla de debajo sin que nada lo dijera (mismo criterio que la
    gráfica de vulnerabilidades de la página de Amenazas). Con estos segmentos, el alto de
    cada barra es exactamente el «Total» de su fila.
    """
    filas = list(evolucion or [])
    corto = len(filas) > MAX_MESES_ETIQUETA_LARGA

    def col(clave: str) -> list[int]:
        return [int(f.get(clave) or 0) for f in filas]

    series = [
        {"clave": "critico", "nombre": "Críticas", "valores": col("criticas")},
        {"clave": "alto", "nombre": "Altas", "valores": col("altas")},
        {"clave": "medio", "nombre": "Medias", "valores": col("medias")},
    ]
    if not sin_bajas:
        series.append({"clave": "bajo", "nombre": "Bajas", "valores": col("bajas")})
    sin_severidad = col("sin_severidad")
    if any(sin_severidad):
        series.append({"clave": "neutro", "nombre": "Sin severidad conocida",
                       "valores": sin_severidad})
    return {
        "categorias": [_mes_corto(f.get("month"), corto=corto) for f in filas],
        "series": series,
    }


#: Cuántos activos, como mucho, puede reunir una serie de versiones para que se marque
#: como atípica, y cuántos tiene que reunir otra para que la comparación tenga sentido.
UMBRAL_SERIE_ATIPICA = 0.10
UMBRAL_SERIE_DOMINANTE = 0.50
#: A partir de cuántas series mayores distintas conviviendo en la misma tecnología se
#: avisa de que el reparto está disperso. Medido sobre el inventario real (2026-09-15):
#: 121 de las 166 tecnologías con activos tienen UNA sola serie y 21 tienen dos; con tres
#: o más quedan 24, entre ellas Microsoft Windows (cinco series: 6, 8, 10, 48 y 64) y PHP
#: (tres: 1, 2 y 3), que son justo los casos que la revisión señaló. No es una prueba de
#: error, y por eso el texto pide comprobar en lugar de afirmar.
UMBRAL_SERIES_DISPERSAS = 3


def _serie_mayor(version: Any) -> Optional[str]:
    """La serie a la que pertenece una versión: su primer número («10.0.26100» → «10»).

    Los prefijos de época de Debian («3:1.0.0~rc3-10») no cuentan: la época es una marca
    de empaquetado, no la versión del producto.
    """
    texto = str(version or "").strip()
    if not texto:
        return None
    if ":" in texto:
        texto = texto.split(":", 1)[1]
    numero = ""
    for caracter in texto.lstrip():
        if caracter.isdigit():
            numero += caracter
        elif numero:
            break
        else:
            return None
    return numero or None


def marcar_versiones_atipicas(versiones: Any) -> dict[str, Any]:
    """Marca las versiones instaladas que NO encajan con el patrón de las demás.

    Por qué (revisión de claridad del 2026-09-15): la ficha de Microsoft Windows
    presentaba como buena la versión instalada «6.0.25.33020», y entre las versiones
    reales de OCS Inventory figuraban «48.100.4037» y «64.92.45458», que no son ninguna
    versión de Windows; la de PHP declaraba «1.0». Presentarlas sin marca hace dudar de
    todo el inventario, y además esas versiones son las que se comparan con los avisos.

    Regla, deliberadamente estadística y comprobable (no hay catálogo de versiones por
    producto y no se va a inventar uno): se agrupan los activos por SERIE MAYOR (el
    primer número de la versión). Si una serie reúne al menos la mitad de los activos
    con la tecnología (:data:`UMBRAL_SERIE_DOMINANTE`), cualquier otra serie que no
    llegue a la décima parte (:data:`UMBRAL_SERIE_ATIPICA`) se marca en ámbar como «no
    encaja con el patrón». Si NINGUNA serie llega a la mitad, no se marca ninguna fila
    —no hay patrón con el que comparar— y se devuelve ``dispersa``, para que la página
    avise de que el mapa de nombres probablemente está mezclando programas distintos en
    la misma tecnología.

    Devuelve {"versiones": [...], "serie_dominante": str|None, "activos_dominante": int,
    "instalaciones": int, "activos": int, "series": int, "dispersa": bool,
    "atipicas": int}. Cada versión sale con ``serie``, ``atipica`` y ``motivo`` (texto ya
    redactado en español).

    ``instalaciones`` es la suma de la columna: pares (activo, versión), NO activos. Un
    equipo con dos versiones de la misma tecnología cuenta dos veces, y por eso la ficha
    de Microsoft Windows sumaba 56 con 50 activos (auditoría de tableros del 2026-09-15,
    punto 2). ``activos`` se conserva con el mismo valor por compatibilidad con lo que ya
    llamaba así a esta cifra, pero los textos dicen «instalaciones», que es lo que es.
    """
    filas = []
    for v in list(versiones or []):
        if not isinstance(v, dict):
            continue
        fila = dict(v)
        fila["serie"] = _serie_mayor(fila.get("version"))
        fila["activos"] = int(fila.get("activos") or 0)
        fila["atipica"] = False
        fila["motivo"] = ""
        filas.append(fila)
    total = sum(f["activos"] for f in filas)
    por_serie: dict[Optional[str], int] = {}
    for f in filas:
        por_serie[f["serie"]] = por_serie.get(f["serie"], 0) + f["activos"]
    dominante, activos_dominante = None, 0
    for serie, activos in por_serie.items():
        if serie is not None and activos > activos_dominante:
            dominante, activos_dominante = serie, activos
    hay_patron = bool(total) and activos_dominante >= UMBRAL_SERIE_DOMINANTE * total
    atipicas = 0
    if hay_patron:
        for f in filas:
            propios = por_serie.get(f["serie"], 0)
            if f["serie"] == dominante or propios >= UMBRAL_SERIE_ATIPICA * total:
                continue
            f["atipica"] = True
            f["motivo"] = (
                f"No encaja con el patrón: {propios} de {total} "
                f"{'instalación está' if total == 1 else 'instalaciones están'} en la serie "
                f"{f['serie'] or 'sin número'} y {activos_dominante} en la serie "
                f"{dominante}. Compruebe en Software si es otro programa clasificado "
                f"por error en esta tecnología.")
            atipicas += 1
    n_series = len([x for x in por_serie if x is not None])
    # La versión más extendida: la que la página enseña como referencia al lado de la
    # más antigua, que es la que se compara con los avisos.
    extendida = max(filas, key=lambda f: f["activos"], default=None)
    return {"versiones": filas, "serie_dominante": dominante,
            "activos_dominante": activos_dominante,
            "instalaciones": total, "activos": total,
            "series": n_series,
            "version_extendida": (extendida or {}).get("version"),
            "activos_extendida": int((extendida or {}).get("activos") or 0),
            "sin_patron": bool(filas) and not hay_patron,
            "dispersa": n_series >= UMBRAL_SERIES_DISPERSAS,
            "atipicas": atipicas}


def version_declarada_atipica(declarada: Any, reparto: dict) -> str:
    """Motivo por el que la versión DECLARADA no encaja con lo instalado, o cadena vacía.

    Es la versión con la que se comparan los avisos, así que una versión declarada que no
    se parece a ninguna de las instaladas es un error con consecuencias: la ficha la
    enseñaba en la cabecera como si fuera un dato bueno.
    """
    texto = str(declarada or "").strip()
    if not texto or not (reparto or {}).get("versiones"):
        return ""
    for fila in reparto["versiones"]:
        if str(fila.get("version") or "").strip() == texto and fila.get("motivo"):
            return str(fila["motivo"])
    serie = _serie_mayor(texto)
    dominante = reparto.get("serie_dominante")
    if dominante and serie and serie != dominante:
        return (f"No encaja con el patrón: ninguna instalación tiene esta versión y "
                f"{reparto['activos_dominante']} de {reparto['activos']} instalaciones "
                f"están en la serie {dominante}. Es la versión con la que se comparan los "
                f"avisos: revísela antes de fiarse de los veredictos.")
    if reparto.get("dispersa"):
        return (f"Conviven {reparto['series']} series de versiones distintas en "
                f"{reparto['activos']} "
                f"{'instalación' if reparto['activos'] == 1 else 'instalaciones'}: "
                f"esta es la MÁS ANTIGUA de todas y es la que se compara con los avisos. "
                f"Compruebe en Software que todas esas instalaciones son de verdad este "
                f"producto antes de fiarse de los veredictos.")
    return ""


# --------------------------------------------------------------------------
# Vistas
# --------------------------------------------------------------------------
@bp.route("/")
@auth.requiere_login
def lista():
    """Inventario de tecnologias con la tabla paginada en el servidor (2026-09-07).

    Los graficos y el pie de la tabla siguen hablando de TODO el filtro, no de la
    pagina que se ve: el total, las sumas de alias y amenazas y el numero de
    tecnologias con version salen de una consulta de agregados, no de sumar las filas
    de la pagina (que serian solo 20 de las 197 del inventario).

    Dos cifras del pie NO son sumas y por eso se calculan aparte (auditoria de tableros
    del 2026-09-15, puntos 4 y 5): los ACTIVOS del parque que tienen alguna de las
    tecnologias del filtro (sumar la columna «Sistemas» contaba el mismo activo una vez
    por tecnologia: 22.236 para un parque de 730 maquinas) y las AMENAZAS DISTINTAS que
    las mencionan (sumar la columna daba 8.363, mas que el catalogo entero, porque una
    amenaza que menciona cuatro tecnologias se contaba cuatro veces).
    """
    filtro = (request.args.get("q") or "").strip()
    sin_version = request.args.get("sin_version") == "1"
    # Regla interna: las bajas no se reportan (ajuste ignore_low_severity, activo). La
    # columna «Amenazas», su total, el gráfico y la ficha la aplican a la vez.
    sin_bajas = bool(g.cfg.get("ignore_low_severity", True))
    # La tabla ya usa el alias «t» para technologies, así que las subconsultas que se
    # atan con threats lo llaman «t2»: es el mismo filtro, con otro alias.
    filtro_bajas = f" AND {SIN_BAJAS_SQL.replace('t.severity', 't2.severity')}" if sin_bajas else ""

    where, params = [], []
    if filtro:
        where.append("(t.name LIKE ? ESCAPE '\\' OR t.slug LIKE ? ESCAPE '\\' "
                     "OR t.vendor LIKE ? ESCAPE '\\')")
        params += [_patron_like(filtro)] * 3
    if sin_version:
        where.append("(t.version_installed IS NULL OR t.version_installed = '')")
    sql_where = (" WHERE " + " AND ".join(where)) if where else ""

    # Recuento y sumas del filtro completo, en una sola consulta. La suma de «Sistemas»
    # ya no se calcula: contaba el mismo activo una vez por cada tecnología instalada y
    # ni siquiera sumaba la columna que se ve (auditoría del 2026-09-15, punto 4). En su
    # lugar, el pie enseña los activos reales del parque.
    agregados = g.db.execute(
        f"""SELECT COUNT(*) AS filtradas,
                   SUM(CASE WHEN t.version_installed IS NOT NULL AND t.version_installed <> ''
                            THEN 1 ELSE 0 END) AS con_version_filtradas,
                   COALESCE(SUM((SELECT COUNT(*) FROM tech_aliases a
                                  WHERE a.technology_id=t.id AND a.is_exclusion=0)), 0) AS alias,
                   COALESCE(SUM((SELECT COUNT(DISTINCT tt.threat_id) FROM threat_technologies tt
                                  JOIN threats t2 ON t2.id = tt.threat_id
                                 WHERE tt.technology_id=t.id
                                   {filtro_bajas})), 0) AS amenazas
              FROM technologies t{sql_where}""", params).fetchone()
    total_filtradas = int(agregados["filtradas"] or 0)
    # Identificadores de las tecnologías del filtro: con ellos se calculan las dos cifras
    # del pie que NO se pueden sumar (activos distintos y amenazas distintas).
    ids_filtradas = [int(r[0]) for r in g.db.execute(
        f"SELECT t.id FROM technologies t{sql_where}", params)]
    sumas = {"con_version": int(agregados["con_version_filtradas"] or 0),
             "alias": int(agregados["alias"] or 0),
             "amenazas": int(agregados["amenazas"] or 0),
             "amenazas_distintas": _amenazas_distintas(g.db, ids_filtradas,
                                                       excluir_bajas=sin_bajas),
             "activos": _activos_con_estas_tecnologias(
                 g.db, ids_filtradas, todas=not (filtro or sin_version))}
    pagina, paginas = _pagina_valida(request.args.get("pagina", 1, type=int),
                                     total_filtradas, POR_PAGINA)

    filas = [_etiquetar(dict(r)) for r in g.db.execute(
        f"""SELECT t.*,
                   (SELECT COUNT(*) FROM tech_aliases a
                     WHERE a.technology_id=t.id AND a.is_exclusion=0) AS n_alias,
                   (SELECT COUNT(DISTINCT tt.threat_id) FROM threat_technologies tt
                     JOIN threats t2 ON t2.id = tt.threat_id
                    WHERE tt.technology_id=t.id
                      {filtro_bajas}) AS n_amenazas
              FROM technologies t{sql_where}
             ORDER BY CASE t.criticality WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                      WHEN 'medium' THEN 2 ELSE 3 END, t.name, t.id
             LIMIT ? OFFSET ?""", params + [POR_PAGINA, (pagina - 1) * POR_PAGINA])]

    total = g.db.execute("SELECT COUNT(*) FROM technologies").fetchone()[0]
    con_version = g.db.execute(
        "SELECT COUNT(*) FROM technologies "
        "WHERE version_installed IS NOT NULL AND version_installed <> ''"
    ).fetchone()[0]

    # Gráficos sobre TODO el inventario (no sobre el filtro): responden a
    # «¿cómo está el inventario?», la tabla filtrada responde a la búsqueda.
    conteo_criticidad = _conteo_criticidad(g.db)
    cobertura = _cobertura_por_categoria(g.db)
    apiladas = _categorias_apiladas(cobertura, MAX_CATEGORIAS_GRAFICO)
    top = _top_tecnologias(g.db, TOP_TECNOLOGIAS, excluir_bajas=sin_bajas)
    for t in top:
        t["href"] = url_for("tecnologias.detalle", tec_id=t["id"])
        _etiquetar(t)
    graf = {
        "criticidad": _porciones_criticidad(conteo_criticidad),
        "categorias": apiladas["categorias"], "series": apiladas["series"],
        "agrupadas": apiladas["agrupadas"],
        # Regla interna: las bajas no se reportan (ajuste ignore_low_severity, activo).
        "top": _items_top(top, sin_bajas=sin_bajas),
    }

    args = _args_a_conservar("pagina")
    return render_template(
        "tecnologias.html", filas=filas, filtro=filtro, sin_version=sin_version,
        total_filtradas=total_filtradas, sumas=sumas, pagina=pagina, paginas=paginas,
        por_pagina=POR_PAGINA, args=args,
        resumen={"total": total, "con_version": con_version,
                 "sin_version": total - con_version,
                 "pct": round(con_version * 100 / total, 1) if total else 0.0,
                 "criticidad": conteo_criticidad},
        cobertura=cobertura, top=top, graf=graf, sin_bajas=sin_bajas,
        activos_parque=g.db.execute(
            "SELECT COUNT(*) FROM activos WHERE presente=1").fetchone()[0],
        categorias=categorias_del_inventario(g.db), criticidades=CRITICIDADES,
        exposiciones=EXPOSICIONES,
        categoria_es=categoria_es, criticidades_es=CRITICIDAD_ES,
        exposiciones_es=EXPOSICION_ES)


@bp.route("/<int:tec_id>")
@auth.requiere_login
def detalle(tec_id: int):
    fila = g.db.execute("SELECT * FROM technologies WHERE id=?", (tec_id,)).fetchone()
    if fila is None:
        flash("La tecnologia no existe.", "error")
        return redirect(url_for("tecnologias.lista"))

    alias = [dict(r) for r in g.db.execute(
        "SELECT * FROM tech_aliases WHERE technology_id=? ORDER BY is_exclusion, alias",
        (tec_id,))]
    for a in alias:
        a["modo_es"] = MODO_ES.get(a.get("match_mode"), str(a.get("match_mode") or "—"))

    # Regla interna: las bajas no se reportan (ajuste ignore_low_severity, activo). TODA
    # la ficha usa el mismo filtro (auditoría de tableros del 2026-09-15, punto 3): las
    # tarjetas y la dona decían 2.159 amenazas de Microsoft Windows y la gráfica de
    # debajo apilaba 2.142, porque solo la serie mensual lo aplicaba.
    sin_bajas = bool(g.cfg.get("ignore_low_severity", True))
    filtro_bajas = f" AND {SIN_BAJAS_SQL}" if sin_bajas else ""
    amenazas = [dict(r) for r in g.db.execute(
        f"""SELECT t.id, t.cve, t.title_es, t.title_en, t.severity, t.month,
                  t.cvss_score, t.in_kev, tt.version_verdict, tt.version_evidence
             FROM threat_technologies tt
             JOIN threats t ON t.id = tt.threat_id
            WHERE tt.technology_id=?{filtro_bajas}
            ORDER BY t.month DESC, t.relevance DESC LIMIT 40""", (tec_id,))]

    veredictos = {r["version_verdict"]: r["n"] for r in g.db.execute(
        f"""SELECT tt.version_verdict, COUNT(*) AS n FROM threat_technologies tt
             JOIN threats t ON t.id = tt.threat_id
            WHERE tt.technology_id=?{filtro_bajas} GROUP BY tt.version_verdict""", (tec_id,))}

    evolucion = _evolucion_tecnologia(g.db, tec_id, excluir_bajas=sin_bajas)
    evo = _series_evolucion(evolucion, sin_bajas=sin_bajas)
    graf = {"veredictos": _porciones_veredictos(veredictos),
            "categorias": evo["categorias"], "series": evo["series"]}

    tec = _etiquetar(dict(fila))
    try:
        tec["versiones_ocs_lista"] = json.loads(tec.get("versiones_ocs") or "[]")
    except ValueError:
        tec["versiones_ocs_lista"] = []
    # Versiones que no encajan con el patrón del producto (2026-09-15): se marcan en
    # ámbar con su explicación en lugar de presentarlas como buenas.
    reparto_versiones = marcar_versiones_atipicas(tec["versiones_ocs_lista"])
    tec["versiones_ocs_lista"] = reparto_versiones["versiones"]
    # Cuántas instalaciones hay de verdad detrás de esa tabla (auditoría de tableros del
    # 2026-09-15, punto 2): la cabecera decía «en 56 activos» y la tarjeta de al lado
    # «50 activos», porque 56 no son activos sino pares (activo, versión); y las 29
    # instalaciones sin versión declarada no aparecían por ninguna parte.
    instalaciones = _mod("ocs").resumen_instalaciones(g.db, tec_id)

    return render_template(
        "tecnologia_detalle.html", tec=tec, alias=alias,
        amenazas=amenazas, veredictos=veredictos, sin_bajas=sin_bajas,
        reparto_versiones=reparto_versiones, instalaciones=instalaciones,
        motivo_version_declarada=version_declarada_atipica(
            tec.get("version_installed"), reparto_versiones),
        total_correlaciones=sum(int(n or 0) for n in veredictos.values()),
        evolucion=evolucion, graf=graf,
        categorias=categorias_del_inventario(g.db), criticidades=CRITICIDADES,
        exposiciones=EXPOSICIONES, modos=MODOS,
        categoria_es=categoria_es, criticidades_es=CRITICIDAD_ES,
        exposiciones_es=EXPOSICION_ES, modos_es=MODO_ES)


@bp.route("/nueva", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def nueva():
    campos = _leer_formulario()
    if not campos["name"]:
        flash("El nombre es obligatorio.", "error")
        return redirect(url_for("tecnologias.lista"))

    slug = campos.pop("slug", None) or _slug(campos["name"])

    # El historico importado ya pudo crear esta tecnologia: en ese caso conviene
    # llevar al operador a la ficha existente en lugar de mostrar un error de SQL.
    existente = g.db.execute("SELECT id, name FROM technologies WHERE slug=?",
                             (slug,)).fetchone()
    if existente is not None:
        flash(f"'{existente['name']}' ya existe en el inventario con ese "
              f"identificador. Editela en lugar de crearla de nuevo.", "aviso")
        return redirect(url_for("tecnologias.detalle", tec_id=existente["id"]))

    ahora = db.utcnow()
    try:
        with db.session(current_app.config.get("DB_PATH")) as conn:
            cur = conn.execute(
                """INSERT INTO technologies(slug, name, vendor, category,
                       version_installed, version_latest, criticality, systems_count,
                       exposure, cpe, owner, notes, enabled, created_at, updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (slug, campos["name"], campos["vendor"], campos["category"],
                 campos["version_installed"], campos["version_latest"],
                 campos["criticality"], campos["systems_count"], campos["exposure"],
                 campos["cpe"], campos["owner"], campos["notes"], campos["enabled"],
                 ahora, ahora))
            tec_id = cur.lastrowid
            # Alias por defecto: el propio nombre, con limites de palabra
            conn.execute(
                """INSERT OR IGNORE INTO tech_aliases(technology_id, alias, match_mode,
                       is_exclusion, context_required) VALUES(?,?,?,0,NULL)""",
                (tec_id, campos["name"].lower(),
                 "phrase" if " " in campos["name"] else "word"))
            db.audit(conn, g.usuario, "tecnologia.crear", "technologies", tec_id,
                     f"{campos['name']} version={campos['version_installed']}",
                     request.remote_addr)
        flash(f"Tecnologia '{campos['name']}' anadida.", "exito")
        return redirect(url_for("tecnologias.detalle", tec_id=tec_id))
    except Exception as exc:  # noqa: BLE001
        flash(f"No se pudo crear: {exc}", "error")
        return redirect(url_for("tecnologias.lista"))


@bp.route("/<int:tec_id>/editar", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def editar(tec_id: int):
    campos = _leer_formulario()
    campos.pop("slug", None)
    try:
        with db.session(current_app.config.get("DB_PATH")) as conn:
            conn.execute(
                """UPDATE technologies SET name=?, vendor=?, category=?,
                       version_installed=?, version_latest=?, criticality=?,
                       systems_count=?, exposure=?, cpe=?, owner=?, notes=?,
                       enabled=?, updated_at=? WHERE id=?""",
                (campos["name"], campos["vendor"], campos["category"],
                 campos["version_installed"], campos["version_latest"],
                 campos["criticality"], campos["systems_count"], campos["exposure"],
                 campos["cpe"], campos["owner"], campos["notes"], campos["enabled"],
                 db.utcnow(), tec_id))
            db.audit(conn, g.usuario, "tecnologia.editar", "technologies", tec_id,
                     f"version={campos['version_installed']} "
                     f"criticidad={campos['criticality']}", request.remote_addr)
        flash("Tecnologia actualizada. La version se aplicara en la proxima "
              "recoleccion.", "exito")
    except Exception as exc:  # noqa: BLE001
        flash(f"No se pudo actualizar: {exc}", "error")
    return redirect(url_for("tecnologias.detalle", tec_id=tec_id))


@bp.route("/<int:tec_id>/version", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def version_rapida(tec_id: int):
    """Edicion rapida de version desde el listado, sin abrir el detalle.

    Solo administradores (2026-09-07): escribe ``technologies.version_installed``, y
    de esa version depende el veredicto de aplicabilidad de todo el parque. Era el
    hueco mas serio: el perfil «Solo lectura» podia cambiar el inventario."""
    version = (request.form.get("version_installed") or "").strip() or None
    with db.session(current_app.config.get("DB_PATH")) as conn:
        conn.execute(
            "UPDATE technologies SET version_installed=?, updated_at=? WHERE id=?",
            (version, db.utcnow(), tec_id))
        db.audit(conn, g.usuario, "tecnologia.version", "technologies", tec_id,
                 f"version={version}", request.remote_addr)
    flash("Version registrada.", "exito")
    return redirect(request.referrer or url_for("tecnologias.lista"))


@bp.route("/<int:tec_id>/alias", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def alias_nuevo(tec_id: int):
    alias = (request.form.get("alias") or "").strip().lower()
    modo = request.form.get("match_mode", "word")
    exclusion = 1 if request.form.get("is_exclusion") == "1" else 0
    contexto = (request.form.get("context_required") or "").strip()

    if not alias:
        flash("El alias no puede estar vacio.", "error")
        return redirect(url_for("tecnologias.detalle", tec_id=tec_id))
    if modo not in MODOS:
        modo = "word"
    if modo == "regex":
        import re
        try:
            re.compile(alias)
        except re.error as exc:
            flash(f"La expresion regular no es valida: {exc}", "error")
            return redirect(url_for("tecnologias.detalle", tec_id=tec_id))

    lista_contexto = None
    if contexto:
        terminos = [t.strip().lower() for t in contexto.split(",") if t.strip()]
        lista_contexto = json.dumps(terminos, ensure_ascii=False) if terminos else None

    try:
        with db.session(current_app.config.get("DB_PATH")) as conn:
            conn.execute(
                """INSERT OR REPLACE INTO tech_aliases(technology_id, alias,
                       match_mode, is_exclusion, context_required)
                   VALUES(?,?,?,?,?)""",
                (tec_id, alias, modo, exclusion, lista_contexto))
            db.audit(conn, g.usuario, "tecnologia.alias", "technologies", tec_id,
                     f"alias={alias} modo={modo} exclusion={exclusion}",
                     request.remote_addr)
        flash("Alias de exclusion anadido." if exclusion else "Alias anadido.", "exito")
    except Exception as exc:  # noqa: BLE001
        flash(f"No se pudo anadir el alias: {exc}", "error")
    return redirect(url_for("tecnologias.detalle", tec_id=tec_id))


@bp.route("/<int:tec_id>/alias/<int:alias_id>/borrar", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def alias_borrar(tec_id: int, alias_id: int):
    with db.session(current_app.config.get("DB_PATH")) as conn:
        conn.execute("DELETE FROM tech_aliases WHERE id=? AND technology_id=?",
                     (alias_id, tec_id))
        db.audit(conn, g.usuario, "tecnologia.alias_borrar", "technologies", tec_id,
                 f"alias_id={alias_id}", request.remote_addr)
    flash("Alias eliminado.", "info")
    return redirect(url_for("tecnologias.detalle", tec_id=tec_id))


@bp.route("/<int:tec_id>/borrar", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def borrar(tec_id: int):
    fila = g.db.execute("SELECT name FROM technologies WHERE id=?", (tec_id,)).fetchone()
    with db.session(current_app.config.get("DB_PATH")) as conn:
        conn.execute("DELETE FROM technologies WHERE id=?", (tec_id,))
        db.audit(conn, g.usuario, "tecnologia.borrar", "technologies", tec_id,
                 fila["name"] if fila else None, request.remote_addr)
    flash("Tecnologia eliminada del inventario.", "info")
    return redirect(url_for("tecnologias.lista"))


@bp.route("/sembrar", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def sembrar():
    try:
        with db.session(current_app.config.get("DB_PATH")) as conn:
            r = _mod("matching").seed_inventario(conn, solo_nuevas=True)
            db.audit(conn, g.usuario, "tecnologia.sembrar", "technologies", None,
                     str(r), request.remote_addr)
        flash(f"Inventario base cargado: {r.get('creadas', 0)} tecnologias nuevas, "
              f"{r.get('omitidas', 0)} ya existentes. Complete las versiones.", "exito")
    except Exception as exc:  # noqa: BLE001
        flash(f"No se pudo cargar el inventario base: {exc}", "error")
    return redirect(url_for("tecnologias.lista"))


@bp.route("/exportar.csv")
@auth.requiere_login
def exportar():
    """Exporta el inventario para completar las versiones en hoja de calculo."""
    salida = io.StringIO()
    escritor = csv.writer(salida, delimiter=";")
    escritor.writerow(["slug", "nombre", "fabricante", "categoria",
                       "version_instalada", "version_disponible", "criticidad",
                       "num_sistemas", "exposicion", "responsable", "cpe", "notas"])
    for r in g.db.execute(
            "SELECT * FROM technologies ORDER BY name"):
        escritor.writerow([celda_csv(_v) for _v in [
            r["slug"], r["name"], r["vendor"] or "", r["category"],
            r["version_installed"] or "", r["version_latest"] or "",
            r["criticality"], r["systems_count"] or 0, r["exposure"],
            r["owner"] or "", r["cpe"] or "", (r["notes"] or "").replace("\n", " ")]])

    return Response(
        "﻿" + salida.getvalue(),          # BOM para que Excel respete UTF-8
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition":
                 "attachment; filename=inventario_tecnologico.csv"})


@bp.route("/importar", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def importar():
    """Importa versiones desde el CSV exportado. Solo actualiza, no crea."""
    archivo = request.files.get("archivo")
    if not archivo or not archivo.filename:
        flash("Seleccione un archivo CSV.", "error")
        return redirect(url_for("tecnologias.lista"))

    try:
        contenido = archivo.read().decode("utf-8-sig")
    except UnicodeDecodeError:
        try:
            archivo.seek(0)
            contenido = archivo.read().decode("latin-1")
        except Exception:  # noqa: BLE001
            flash("No se pudo leer el archivo. Guardelo como CSV UTF-8.", "error")
            return redirect(url_for("tecnologias.lista"))

    delimitador = ";" if contenido.count(";") >= contenido.count(",") else ","
    lector = csv.DictReader(io.StringIO(contenido), delimiter=delimitador)

    actualizadas = ignoradas = 0
    errores: list[str] = []

    with db.session(current_app.config.get("DB_PATH")) as conn:
        for n, linea in enumerate(lector, 2):
            slug = (linea.get("slug") or "").strip()
            if not slug:
                ignoradas += 1
                continue
            fila = conn.execute("SELECT id FROM technologies WHERE slug=?",
                                (slug,)).fetchone()
            if fila is None:
                errores.append(f"linea {n}: no existe la tecnologia '{slug}'")
                ignoradas += 1
                continue

            campos, valores = [], []
            for columna, destino in (("version_instalada", "version_installed"),
                                     ("version_disponible", "version_latest"),
                                     ("responsable", "owner"),
                                     ("cpe", "cpe")):
                if columna in linea:
                    campos.append(f"{destino}=?")
                    valores.append((linea.get(columna) or "").strip() or None)

            if "criticidad" in linea:
                valor = (linea.get("criticidad") or "").strip().lower()
                if valor in CRITICIDADES:
                    campos.append("criticality=?")
                    valores.append(valor)
            if "exposicion" in linea:
                valor = (linea.get("exposicion") or "").strip().lower()
                if valor in EXPOSICIONES:
                    campos.append("exposure=?")
                    valores.append(valor)
            if "num_sistemas" in linea:
                try:
                    campos.append("systems_count=?")
                    valores.append(int((linea.get("num_sistemas") or "0").strip() or 0))
                except ValueError:
                    campos.pop()

            if campos:
                campos.append("updated_at=?")
                valores.append(db.utcnow())
                valores.append(fila["id"])
                conn.execute(
                    f"UPDATE technologies SET {', '.join(campos)} WHERE id=?", valores)
                actualizadas += 1

        db.audit(conn, g.usuario, "tecnologia.importar", "technologies", None,
                 f"actualizadas={actualizadas} ignoradas={ignoradas}",
                 request.remote_addr)

    flash(f"Importacion terminada: {actualizadas} tecnologias actualizadas, "
          f"{ignoradas} ignoradas.", "exito" if actualizadas else "aviso")
    for e in errores[:10]:
        flash(e, "aviso")
    return redirect(url_for("tecnologias.lista"))


def _slug(texto: str) -> str:
    import re
    base = re.sub(r"[^a-z0-9]+", "_", texto.lower()).strip("_")
    return base or "tecnologia"


def _leer_formulario() -> dict:
    def limpio(clave: str, defecto: str = "") -> str:
        return (request.form.get(clave) or defecto).strip()

    categoria = limpio("category", "aplicacion")
    criticidad = limpio("criticality", "medium")
    exposicion = limpio("exposure", "interna")

    try:
        sistemas = max(0, int(limpio("systems_count", "0") or 0))
    except ValueError:
        sistemas = 0

    return {
        "slug": limpio("slug") or None,
        "name": limpio("name"),
        "vendor": limpio("vendor") or None,
        "category": categoria if categoria in CATEGORIAS else "aplicacion",
        "version_installed": limpio("version_installed") or None,
        "version_latest": limpio("version_latest") or None,
        "criticality": criticidad if criticidad in CRITICIDADES else "medium",
        "systems_count": sistemas,
        "exposure": exposicion if exposicion in EXPOSICIONES else "interna",
        "cpe": limpio("cpe") or None,
        "owner": limpio("owner") or None,
        "notes": limpio("notes") or None,
        "enabled": 1 if request.form.get("enabled", "1") == "1" else 0,
    }

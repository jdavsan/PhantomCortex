"""Gestion y validacion de las fuentes de consulta.

Cubre la peticion explicita de "validar el tema de fuentes de consulta": cada
fuente se puede probar en vivo desde la interfaz y se ve su historial de salud.
Esto es lo que habria detectado que 10 de 35 fuentes llevaban 33 dias caidas.

Rediseño del 2026-09-03 (sección 6 «Fuentes» de docs/DISENO_INTERFAZ_2026-09-03.md):
la vista prepara los datos de los gráficos como listas y diccionarios simples y
la plantilla los pinta con ``graficos.<función>(...)``:

* ``dona`` del estado de las fuentes ACTIVAS (operativas, degradadas, caídas,
  sin comprobar); las desactivadas se cuentan aparte en el texto;
* ``barras_horizontales`` de las diez fuentes que más amenazas han aportado
  (``COUNT(DISTINCT threat_id)`` en ``threat_sources``), coloreadas por
  categoría con una clave ``cat-N`` estable y leyenda en español;
* en la tabla, una ``chispa`` por fuente con las últimas 15 comprobaciones,
  obtenidas con UNA consulta de ventana (``ROW_NUMBER() OVER``), no una por fila;
  con menos de dos comprobaciones no hay línea que dibujar y se muestra un
  texto («1 comprobación · 4 aceptadas») en su lugar;
* el pie del catálogo muestra las amenazas DISTINTAS con procedencia
  (``COUNT(DISTINCT threat_id)``), no la suma de las aportaciones por fuente,
  que cuenta varias veces una amenaza citada por varias fuentes;
* en el detalle, ``linea_tiempo`` de latencia y de entradas/aceptadas de las
  últimas 60 comprobaciones y ``barra_progreso`` de la tasa de éxito.

Todas las etiquetas visibles van en español y sin abreviaturas; los textos que
salen de la base de datos (nombres de fuentes) los escapa ``graficos.py``.

Permisos (2026-09-08): TODAS las rutas, tambien las de consulta, exigen administrador.
El usuario pidio que «el apartado de fuentes que se encuentra en el menú debe ir en
administración para que no todos los roles lo vean»: las fuentes son configuracion de la
plataforma (direcciones, credenciales de acceso, pruebas en vivo contra Internet), no
informacion operativa, y el resto de perfiles no las necesita para trabajar.
"""
from __future__ import annotations

import sqlite3
from typing import Any, Iterable

from flask import (Blueprint, current_app, flash, g, jsonify, redirect,
                   render_template, request, url_for)

from threatintel import db
from threatintel.collector import TIPOS_RECOLECTABLES as _TIPOS_RECOLECTABLES
from webui import auth
from webui.filtros import _parse
from webui.graficos import fmt

bp = Blueprint("fuentes", __name__, url_prefix="/fuentes")

CATEGORIAS = ["government", "vendor", "news", "blog", "database", "exploits"]
PRIORIDADES = ["critical", "high", "medium", "low"]
TIPOS = ["rss", "kev_json", "nvd_api", "epss_api", "dataset", "html_colcert"]

#: Nombre visible de cada categoría de fuente (regla 7: español, sin abreviaturas).
CATEGORIA_ES = {
    "blog": "Blog", "database": "Base de datos", "exploits": "Exploits",
    "government": "Organismo oficial", "news": "Noticias", "vendor": "Fabricante",
}
#: Clave de color ``cat-N`` ESTABLE por categoría: la misma categoría tiene el
#: mismo color en cualquier página, sin depender del orden de los datos.
CATEGORIA_CLAVE = {
    "blog": "cat-1", "database": "cat-2", "exploits": "cat-3",
    "government": "cat-4", "news": "cat-5", "vendor": "cat-6",
}
PRIORIDAD_ES = {"critical": "Crítica", "high": "Alta", "medium": "Media", "low": "Baja"}
TIPO_ES = {
    "rss": "Canal RSS/Atom", "kev_json": "Catálogo KEV (JSON)",
    "nvd_api": "API de NVD", "epss_api": "API de EPSS",
    "dataset": "Conjunto de datos / API de consulta",
    "html_colcert": "Página HTML de avisos de ColCERT",
}
#: Estado de salud → texto visible y clave de color de la paleta (misma que la
#: dona y la tabla). Se define aquí, con tildes, en lugar de usar el filtro
#: ``estado_es`` de filtros.py, que escribe «Caida».
ESTADO_ES = {"ok": "Operativa", "degradada": "Degradada", "caida": "Caída",
             "sin_datos": "Sin comprobar", "desactivada": "Desactivada"}
ESTADO_CLAVE = {"ok": "exito", "degradada": "medio", "caida": "critico",
                "sin_datos": "neutro", "desactivada": "neutro"}

#: Comprobaciones que se miran en la lista (chispa y tasa) y en el detalle.
VENTANA_CHISPA = 15
VENTANA_DETALLE = 60
TOP_FUENTES = 10
#: Fuentes por pagina en el catalogo (2026-09-07): con 84 fuentes, cada una con su
#: grafico de chispa y sus botones, la tabla completa era una pantalla interminable.
#: Filas por pagina en los listados largos. El usuario pidio 20 el 2026-09-07
#: («que en cada uno solo muestre de a 20»): una pantalla se recorre de un vistazo.
POR_PAGINA = 20


def _pagina_valida(pagina: Any, total: int, por_pagina: int) -> tuple[int, int]:
    """(pagina, paginas) con la pagina acotada al rango real (2026-09-07).

    Una pagina fuera de rango no es un error: se atiende con la primera o con la
    ultima, para que un enlace antiguo siga devolviendo una pagina util.
    """
    por_pagina = max(1, int(por_pagina or 1))
    paginas = max(1, -(-int(total or 0) // por_pagina))
    try:
        pagina = int(pagina)
    except (TypeError, ValueError):
        pagina = 1
    return min(max(pagina, 1), paginas), paginas


#: Argumentos reservados de ``url_for`` (2026-09-07). Un parametro de la direccion
#: llamado como uno de ellos («?_anchor=x», «?endpoint=x», «?_method=POST») no es un
#: filtro de la pagina: si se reenviara a ``url_for(..., **args)`` la llamada
#: recibiria el mismo argumento dos veces y la pagina responderia con un error 500.
_ARGS_RESERVADOS = ("endpoint", "values")


def _args_a_conservar(*excluir: str) -> dict[str, str]:
    """Los argumentos de la direccion que se conservan al cambiar de pagina, sin los
    ``excluir`` ni los reservados de ``url_for``."""
    return {k: v for k, v in request.args.items()
            if k not in excluir and k not in _ARGS_RESERVADOS and not k.startswith("_")}



def _mod(nombre: str):
    return __import__(f"threatintel.{nombre}", fromlist=["x"])


# --------------------------------------------------------------------------
# Consultas locales (SQL pequeño y documentado)
# --------------------------------------------------------------------------
def _historial_reciente(conn: sqlite3.Connection,
                        ventana: int = VENTANA_CHISPA) -> dict[int, list[dict]]:
    """Últimas ``ventana`` comprobaciones de CADA fuente en orden cronológico
    ascendente, con una sola consulta.

    Se numeran las filas por fuente de la más reciente a la más antigua
    (``ROW_NUMBER() OVER (PARTITION BY source_id ORDER BY checked_at DESC)``) y
    se conservan las ``ventana`` primeras: así 78 fuentes no suponen 78
    consultas. El desempate por ``id`` fija el orden cuando dos comprobaciones
    comparten segundo.
    """
    ventana = max(1, int(ventana or VENTANA_CHISPA))
    salida: dict[int, list[dict]] = {}
    for fila in conn.execute(
            """SELECT source_id, checked_at, ok, entries, accepted, latency_ms
                 FROM (SELECT source_id, checked_at, ok, entries, accepted, latency_ms,
                              ROW_NUMBER() OVER (PARTITION BY source_id
                                                 ORDER BY checked_at DESC, id DESC) AS n
                         FROM source_health)
                WHERE n <= ?
                ORDER BY source_id, checked_at ASC, n DESC""", (ventana,)):
        salida.setdefault(fila["source_id"], []).append(dict(fila))
    return salida


#: Amenazas que esta página cuenta cuando la regla interna está activa: las mismas que
#: cuentan Amenazas y Tendencias. Sin este filtro, el pie del catálogo decía «7.514
#: distintas» y las otras dos páginas «7.284» del mismo histórico (auditoría de tableros
#: del 2026-09-15, punto 9). El JOIN con ``threats`` no se puede evitar: ``threat_sources``
#: no guarda la severidad.
_SIN_BAJAS_FUENTES = ("JOIN threats t ON t.id = ts.threat_id "
                      "WHERE (t.severity IS NULL OR t.severity <> 'Low')")


def _filtro_severidad(excluir_bajas: bool, con_where: bool = False) -> str:
    """Trozo de SQL que ata ``threat_sources`` con ``threats`` para dejar fuera la
    severidad que no se reporta; cadena vacía si la regla interna está desactivada."""
    if not excluir_bajas:
        return ""
    return _SIN_BAJAS_FUENTES if not con_where else _SIN_BAJAS_FUENTES.replace("WHERE", "AND")


def _aportacion_por_fuente(conn: sqlite3.Connection, *,
                           excluir_bajas: bool = True) -> dict[int, int]:
    """Amenazas distintas que ha aportado cada fuente (``threat_sources``).

    ``excluir_bajas`` (regla interna, ajuste ``ignore_low_severity``, activo) deja fuera
    la severidad que la organización no reporta, como Amenazas y Tendencias.
    """
    return {r["source_id"]: int(r["n"] or 0) for r in conn.execute(
        "SELECT ts.source_id, COUNT(DISTINCT ts.threat_id) AS n FROM threat_sources ts "
        f"{_filtro_severidad(excluir_bajas)} GROUP BY ts.source_id")}


def _amenazas_distintas(conn: sqlite3.Connection, *, excluir_bajas: bool = True) -> int:
    """Amenazas distintas con procedencia registrada, para el pie del catálogo.

    No es la suma de la columna «Amenazas»: una amenaza citada por tres fuentes
    cuenta una vez para cada fuente pero una sola vez aquí. Con ``excluir_bajas`` cuenta
    exactamente las mismas amenazas que la página de Amenazas.
    """
    fila = conn.execute("SELECT COUNT(DISTINCT ts.threat_id) FROM threat_sources ts "
                        + _filtro_severidad(excluir_bajas)).fetchone()
    return int(fila[0] or 0) if fila else 0


def _top_fuentes(conn: sqlite3.Connection, limite: int = TOP_FUENTES, *,
                 excluir_bajas: bool = True) -> list[dict]:
    """Las fuentes que más amenazas distintas han aportado, de mayor a menor.

    Mismo criterio que la columna «Amenazas» de la tabla y que el pie del catálogo: si
    una de las tres contase la severidad que no se reporta y las otras no, la misma
    página daría dos cifras de la misma fuente.
    """
    return [dict(r) for r in conn.execute(
        f"""SELECT s.id, s.name, s.category, s.kind, s.enabled,
                  COUNT(DISTINCT ts.threat_id) AS amenazas
             FROM threat_sources ts
             JOIN sources s ON s.id = ts.source_id
             {_filtro_severidad(excluir_bajas, con_where=True) or ''}
            GROUP BY s.id
            ORDER BY amenazas DESC, s.name
            LIMIT ?""", (max(1, int(limite)),))]


# --------------------------------------------------------------------------
# Preparación de datos (funciones puras, fáciles de probar)
# --------------------------------------------------------------------------
def _valores_chispa(registros: Iterable[dict]) -> list[int]:
    """Serie de la chispa de una fuente: entradas aceptadas por comprobación.

    Si ninguna comprobación trae el dato de aceptadas, se dibuja 1 = correcta y
    0 = fallo a partir de ``ok`` (la otra variante que admite la especificación).
    Lista vacía si la fuente nunca se ha comprobado.
    """
    registros = list(registros or [])
    if not registros:
        return []
    aceptadas = [r.get("accepted") for r in registros]
    if all(a is None for a in aceptadas):
        return [1 if r.get("ok") else 0 for r in registros]
    return [int(a or 0) for a in aceptadas]


#: Comprobaciones mínimas para dibujar la chispa: con una sola no hay línea y
#: el punto aislado apenas se ve, así que se escribe un texto en su lugar.
MINIMO_PUNTOS_CHISPA = 2


def _texto_chispa(registros: Iterable[dict]) -> str:
    """Texto que sustituye a la chispa cuando hay menos de dos comprobaciones:
    «1 comprobación · 4 aceptadas» (o «· correcta»/«· con fallo» si la
    comprobación no trae el dato de aceptadas). Cadena vacía sin registros."""
    registros = list(registros or [])
    n = len(registros)
    if n == 0:
        return ""
    ultimo = registros[-1]
    aceptadas = ultimo.get("accepted")
    if aceptadas is None:
        detalle = "correcta" if ultimo.get("ok") else "con fallo"
    else:
        aceptadas = int(aceptadas or 0)
        detalle = f"{fmt(aceptadas)} aceptada{'' if aceptadas == 1 else 's'}"
    return f"{fmt(n)} comprobaci{'ón' if n == 1 else 'ones'} · {detalle}"


def _etiquetar(fila: dict) -> dict:
    """Añade a una fila de ``sources`` sus etiquetas en español y su clave de color."""
    categoria = str(fila.get("category") or "")
    fila["categoria_es"] = CATEGORIA_ES.get(categoria, categoria.capitalize() or "—")
    fila["categoria_clave"] = CATEGORIA_CLAVE.get(categoria, "neutro")
    prioridad = str(fila.get("priority") or "")
    fila["prioridad_es"] = PRIORIDAD_ES.get(prioridad, prioridad or "—")
    tipo = str(fila.get("kind") or "")
    fila["tipo_es"] = TIPO_ES.get(tipo, tipo or "—")
    estado = (fila.get("salud") or {}).get("estado") if fila.get("enabled") else "desactivada"
    estado = estado or "sin_datos"
    fila["estado_es"] = ESTADO_ES.get(estado, str(estado).capitalize())
    fila["estado_clave"] = ESTADO_CLAVE.get(estado, "neutro")
    return fila


def _resumen_catalogo(filas: Iterable[dict]) -> dict[str, Any]:
    """Recuento del catálogo: activas por estado de salud y desactivadas aparte.

    Las desactivadas no se consultan, así que no cuentan como «no operativas»;
    la dona reparte solo las activas y el texto menciona las desactivadas.
    """
    resumen = {"total": 0, "activas": 0, "feeds": 0, "apis": 0, "operativas": 0,
               "degradadas": 0, "caidas": 0, "sin_comprobar": 0, "desactivadas": 0,
               "amenazas": 0}
    for f in filas or []:
        resumen["total"] += 1
        resumen["amenazas"] += int(f.get("amenazas") or 0)
        if not f.get("enabled"):
            resumen["desactivadas"] += 1
            continue
        resumen["activas"] += 1
        resumen["feeds" if f.get("kind") in _TIPOS_RECOLECTABLES else "apis"] += 1   # RSS y HTML de ColCERT (v6)
        estado = (f.get("salud") or {}).get("estado")
        clave = {"ok": "operativas", "degradada": "degradadas", "caida": "caidas"}.get(estado)
        resumen[clave or "sin_comprobar"] += 1
    resumen["sin_datos"] = resumen["sin_comprobar"]  # alias histórico de la plantilla
    return resumen


def _porciones_estado(resumen: dict) -> list[dict]:
    """Porciones de la dona de estado: solo fuentes activas, colores semánticos."""
    return [
        {"clave": "exito", "nombre": "Operativas", "valor": resumen.get("operativas", 0)},
        {"clave": "medio", "nombre": "Degradadas", "valor": resumen.get("degradadas", 0)},
        {"clave": "critico", "nombre": "Caídas", "valor": resumen.get("caidas", 0)},
        {"clave": "neutro", "nombre": "Sin comprobar", "valor": resumen.get("sin_comprobar", 0)},
    ]


def _items_top_fuentes(top: Iterable[dict]) -> list[dict]:
    """Filas de ``barras_horizontales``: una barra por fuente, coloreada por su
    categoría (``cat-N`` estable) y con enlace a su ficha (``href`` ya calculado
    por la vista con ``url_for``)."""
    items = []
    for t in top or []:
        categoria = str(t.get("category") or "")
        items.append({
            "etiqueta": t.get("name") or "—",
            "valores": [(CATEGORIA_CLAVE.get(categoria, "neutro"),
                         int(t.get("amenazas") or 0),
                         CATEGORIA_ES.get(categoria, categoria.capitalize() or "Otra"))],
            "href": t.get("href") or "",
            "nota": "" if t.get("enabled", 1) else "desactivada",
        })
    return items


def _etiqueta_hora(valor: Any) -> str:
    """'2026-09-03T13:50:24Z' → '03/09 13:50' (etiqueta corta del eje X, hora local)."""
    dt = _parse(valor)
    if dt is None:
        return "—"
    if dt.tzinfo is not None:
        dt = dt.astimezone()
    return dt.strftime("%d/%m %H:%M")


def _series_detalle(historial: Iterable[dict]) -> dict[str, Any]:
    """Series del detalle a partir del historial en orden cronológico ASCENDENTE.

    Devuelve las etiquetas del eje X, la serie de latencia, las series de
    entradas recibidas/aceptadas, las partes de la barra de éxito (según el
    campo ``ok`` de cada comprobación, el mismo criterio que la columna
    «Resultado» de la tabla) y algunos agregados para el texto.
    """
    registros = list(historial or [])
    latencias = [h.get("latency_ms") for h in registros]
    validas = [float(v) for v in latencias if v is not None]
    correctas = sum(1 for h in registros if h.get("ok"))
    total = len(registros)
    return {
        "etiquetas": [_etiqueta_hora(h.get("checked_at")) for h in registros],
        "latencia": [{"clave": "acento", "nombre": "Latencia", "valores": latencias}],
        "entradas": [
            {"clave": "acento", "nombre": "Entradas recibidas",
             "valores": [h.get("entries") for h in registros]},
            {"clave": "exito", "nombre": "Entradas aceptadas",
             "valores": [h.get("accepted") for h in registros]},
        ],
        "exito": [
            {"clave": "exito", "nombre": "Correctas", "valor": correctas},
            {"clave": "critico", "nombre": "Con fallo", "valor": total - correctas},
        ],
        "total": total, "correctas": correctas, "fallos": total - correctas,
        "tasa": round(correctas * 100.0 / total, 1) if total else None,
        "latencia_media": round(sum(validas) / len(validas)) if validas else None,
        "latencia_maxima": int(max(validas)) if validas else None,
        "entradas_total": sum(int(h.get("entries") or 0) for h in registros),
        "aceptadas_total": sum(int(h.get("accepted") or 0) for h in registros),
    }


# --------------------------------------------------------------------------
# Vistas
# --------------------------------------------------------------------------
@bp.route("/")
@auth.requiere_admin
def lista():
    """Catalogo de fuentes con la tabla paginada en el servidor (2026-09-07).

    Los indicadores, el aviso de caidas y la dona de estado siguen contando TODAS las
    fuentes (84 hoy), no las de la pagina: el recuento del catalogo se hace con una
    consulta ligera de las cuatro columnas que necesita, y solo las fuentes de la
    pagina pedida cargan su historial, su chispa y sus botones.
    """
    try:
        salud = {s["slug"]: s for s in _mod("health").resumen_fuentes(
            g.db, ventana=VENTANA_CHISPA, cfg=g.cfg)}
    except Exception as exc:  # noqa: BLE001
        salud = {}
        flash(f"No se pudo calcular la salud de las fuentes: {exc}", "aviso")

    # Regla interna: las bajas no se reportan (ajuste ignore_low_severity, activo). Las
    # tres cifras de amenazas de esta página (columna, pie y gráfico) la aplican juntas.
    sin_bajas = bool(g.cfg.get("ignore_low_severity", True))
    aportacion = _aportacion_por_fuente(g.db, excluir_bajas=sin_bajas)

    # Recuento del catalogo completo: solo las columnas que mira _resumen_catalogo.
    todas = [dict(r) for r in g.db.execute("SELECT id, slug, enabled, kind FROM sources")]
    for f in todas:
        f["salud"] = salud.get(f["slug"], {})
        f["amenazas"] = aportacion.get(f["id"], 0)
    resumen = _resumen_catalogo(todas)
    resumen["amenazas_distintas"] = _amenazas_distintas(g.db, excluir_bajas=sin_bajas)

    total = len(todas)
    pagina, paginas = _pagina_valida(request.args.get("pagina", 1, type=int), total, POR_PAGINA)
    filas = [dict(r) for r in g.db.execute(
        # El orden termina en «id» a proposito (2026-09-07): un ORDER BY con empates no
        # define un orden total, y con LIMIT/OFFSET una fuente podria salir en dos
        # paginas y otra en ninguna.
        "SELECT * FROM sources ORDER BY enabled DESC, category, name, id LIMIT ? OFFSET ?",
        (POR_PAGINA, (pagina - 1) * POR_PAGINA))]
    historial = _historial_reciente(g.db, VENTANA_CHISPA)
    for f in filas:
        registros = historial.get(f["id"], [])
        f["salud"] = salud.get(f["slug"], {})
        f["chispa"] = _valores_chispa(registros)
        f["chispa_texto"] = _texto_chispa(registros)
        f["amenazas"] = aportacion.get(f["id"], 0)
        _etiquetar(f)

    top = _top_fuentes(g.db, TOP_FUENTES, excluir_bajas=sin_bajas)
    for t in top:
        t["href"] = url_for("fuentes.detalle", source_id=t["id"])
        _etiquetar(t)

    graf = {
        "estado": _porciones_estado(resumen),
        "top": _items_top_fuentes(top),
        "nombres_categorias": {CATEGORIA_CLAVE[c]: CATEGORIA_ES[c] for c in CATEGORIA_CLAVE},
    }
    return render_template("fuentes.html", filas=filas, resumen=resumen, top=top, graf=graf,
                           total=total, pagina=pagina, paginas=paginas, por_pagina=POR_PAGINA,
                           args=_args_a_conservar("pagina"),
                           ventana=VENTANA_CHISPA, minimo_chispa=MINIMO_PUNTOS_CHISPA,
                           categorias=CATEGORIAS, prioridades=PRIORIDADES, tipos=TIPOS,
                           categorias_es=CATEGORIA_ES, prioridades_es=PRIORIDAD_ES,
                           tipos_es=TIPO_ES, sin_bajas=sin_bajas)


@bp.route("/<int:source_id>")
@auth.requiere_admin
def detalle(source_id: int):
    fila = g.db.execute("SELECT * FROM sources WHERE id=?", (source_id,)).fetchone()
    if fila is None:
        flash("La fuente no existe.", "error")
        return redirect(url_for("fuentes.lista"))

    # La tabla muestra lo más reciente primero; los gráficos, en orden cronológico.
    historial = [dict(r) for r in g.db.execute(
        """SELECT * FROM source_health WHERE source_id=?
           ORDER BY checked_at DESC, id DESC LIMIT ?""", (source_id, VENTANA_DETALLE))]
    serie = _series_detalle(reversed(historial))

    # Mismo criterio que la columna «Amenazas» del catálogo (2026-09-15): la ficha de una
    # fuente no puede decir 1.710 donde la lista dice 1.694.
    sin_bajas = bool(g.cfg.get("ignore_low_severity", True))
    aportacion = g.db.execute(
        f"""SELECT COUNT(DISTINCT ts.threat_id) AS amenazas
             FROM threat_sources ts
             {_filtro_severidad(sin_bajas, con_where=True) or ''}
            WHERE ts.source_id=?""", (source_id,)).fetchone()

    fuente = _etiquetar(dict(fila))
    return render_template("fuente_detalle.html", fuente=fuente,
                           historial=historial, serie=serie, ventana=VENTANA_DETALLE,
                           amenazas=aportacion["amenazas"] if aportacion else 0,
                           categorias=CATEGORIAS, prioridades=PRIORIDADES, tipos=TIPOS,
                           categorias_es=CATEGORIA_ES, prioridades_es=PRIORIDAD_ES,
                           tipos_es=TIPO_ES)


@bp.route("/<int:source_id>/probar", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def probar(source_id: int):
    """Prueba en vivo sin guardar amenazas. El boton clave de esta pantalla.

    Solo administradores (2026-09-07): no guarda amenazas ni salud, pero hace que el
    servidor salga a Internet contra la direccion de la fuente y deja constancia en
    la auditoria. El perfil «Solo lectura» consulta, no acciona."""
    try:
        resultado = _mod("sources").probar(g.db, source_id, cfg=g.cfg)
    except Exception as exc:  # noqa: BLE001
        resultado = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    with db.session(current_app.config.get("DB_PATH")) as conn:
        db.audit(conn, g.usuario, "fuente.probar", "sources", source_id,
                 f"ok={resultado.get('ok')} entradas={resultado.get('entries')} "
                 f"error={resultado.get('error')}",
                 request.remote_addr)

    if request.headers.get("Accept", "").startswith("application/json"):
        return jsonify(resultado)

    if resultado.get("ok"):
        flash(f"Fuente operativa: {resultado.get('entries', 0)} entradas en "
              f"{resultado.get('latency_ms', 0)} ms.", "exito")
    else:
        flash(f"La fuente falla: {resultado.get('error')}", "error")
    return redirect(url_for("fuentes.detalle", source_id=source_id))


@bp.route("/probar-todas", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def probar_todas():
    # API4 (consumo de recursos sin limite): esta accion lanza ~55 descargas
    # externas. Se acota a una ejecucion cada 5 minutos, registrada en settings,
    # para que un clic repetido, o una sesion comprometida, no convierta el
    # servidor en un generador de trafico.
    from datetime import datetime, timedelta, timezone
    ultima = db.get_setting(g.db, "ultima_prueba_masiva")
    ahora = datetime.now(timezone.utc)
    if ultima:
        try:
            marca = datetime.fromisoformat(str(ultima).replace("Z", "+00:00"))
            restante = (marca + timedelta(minutes=5) - ahora).total_seconds()
            if restante > 0:
                flash(f"La prueba masiva ya se ejecuto hace poco. Espere "
                      f"{int(restante // 60) + 1} minuto(s) o pruebe fuentes "
                      f"individuales.", "aviso")
                return redirect(url_for("fuentes.lista"))
        except ValueError:
            pass
    with db.session(current_app.config.get("DB_PATH")) as conn:
        db.set_setting(conn, "ultima_prueba_masiva", db.utcnow())

    modulo = _mod("sources")
    filas = g.db.execute("SELECT id, slug, name FROM sources WHERE enabled=1").fetchall()
    ok = fallo = 0
    detalles = []
    for fila in filas:
        try:
            r = modulo.probar(g.db, fila["id"], cfg=g.cfg)
        except Exception as exc:  # noqa: BLE001
            r = {"ok": False, "error": str(exc)}
        if r.get("ok"):
            ok += 1
        else:
            fallo += 1
            detalles.append(f"{fila['name']}: {r.get('error')}")

    with db.session(current_app.config.get("DB_PATH")) as conn:
        db.audit(conn, g.usuario, "fuente.probar_todas", "sources", None,
                 f"ok={ok} fallo={fallo}", request.remote_addr)

    flash(f"Prueba completa: {ok} operativas, {fallo} con fallo.",
          "exito" if fallo == 0 else "aviso")
    for d in detalles[:12]:
        flash(d, "error")
    return redirect(url_for("fuentes.lista"))


@bp.route("/nueva", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def nueva():
    campos = _leer_formulario()
    if not campos.get("name") or not campos.get("url"):
        flash("El nombre y la URL son obligatorios.", "error")
        return redirect(url_for("fuentes.lista"))
    try:
        with db.session(current_app.config.get("DB_PATH")) as conn:
            source_id = _mod("sources").crear(conn, **campos)
            db.audit(conn, g.usuario, "fuente.crear", "sources", source_id,
                     f"{campos.get('name')} <{campos.get('url')}>", request.remote_addr)
        flash(f"Fuente '{campos['name']}' creada. Pruebela antes de activarla.", "exito")
    except Exception as exc:  # noqa: BLE001
        flash(f"No se pudo crear: {exc}", "error")
    return redirect(url_for("fuentes.lista"))


@bp.route("/<int:source_id>/editar", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def editar(source_id: int):
    campos = _leer_formulario()
    try:
        with db.session(current_app.config.get("DB_PATH")) as conn:
            _mod("sources").actualizar(conn, source_id, **campos)
            db.audit(conn, g.usuario, "fuente.editar", "sources", source_id,
                     str(campos), request.remote_addr)
        flash("Fuente actualizada.", "exito")
    except Exception as exc:  # noqa: BLE001
        flash(f"No se pudo actualizar: {exc}", "error")
    return redirect(url_for("fuentes.detalle", source_id=source_id))


@bp.route("/<int:source_id>/activar", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def activar(source_id: int):
    activo = request.form.get("enabled") == "1"
    with db.session(current_app.config.get("DB_PATH")) as conn:
        conn.execute("UPDATE sources SET enabled=?, updated_at=? WHERE id=?",
                     (1 if activo else 0, db.utcnow(), source_id))
        db.audit(conn, g.usuario, "fuente.activar" if activo else "fuente.desactivar",
                 "sources", source_id, None, request.remote_addr)
    flash("Fuente activada." if activo else "Fuente desactivada.", "info")
    return redirect(request.referrer or url_for("fuentes.lista"))


@bp.route("/<int:source_id>/borrar", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def borrar(source_id: int):
    fila = g.db.execute("SELECT name FROM sources WHERE id=?", (source_id,)).fetchone()
    nombre = fila["name"] if fila else source_id
    try:
        with db.session(current_app.config.get("DB_PATH")) as conn:
            _mod("sources").borrar(conn, source_id)
            db.audit(conn, g.usuario, "fuente.borrar", "sources", source_id,
                     str(nombre), request.remote_addr)
        flash(f"Fuente '{nombre}' eliminada.", "info")
    except Exception as exc:  # noqa: BLE001
        flash(f"No se pudo eliminar: {exc}", "error")
    return redirect(url_for("fuentes.lista"))


@bp.route("/sembrar", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def sembrar():
    """Repuebla el catalogo con las fuentes por defecto ya corregidas."""
    try:
        with db.session(current_app.config.get("DB_PATH")) as conn:
            r = _mod("sources").seed(conn, solo_nuevas=True)
            db.audit(conn, g.usuario, "fuente.sembrar", "sources", None, str(r),
                     request.remote_addr)
        flash(f"Catalogo actualizado: {r.get('creadas', 0)} creadas, "
              f"{r.get('omitidas', 0)} ya existentes.", "exito")
    except Exception as exc:  # noqa: BLE001
        flash(f"No se pudo sembrar el catalogo: {exc}", "error")
    return redirect(url_for("fuentes.lista"))


def _leer_formulario() -> dict:
    def limpio(clave: str, defecto: str = "") -> str:
        return (request.form.get(clave) or defecto).strip()

    campos = {
        "name": limpio("name"),
        "url": limpio("url"),
        "kind": limpio("kind", "rss"),
        "category": limpio("category", "news"),
        "priority": limpio("priority", "medium"),
        "notes": limpio("notes") or None,
        "enabled": 1 if request.form.get("enabled") == "1" else 0,
    }
    if limpio("slug"):
        campos["slug"] = limpio("slug")
    try:
        campos["timeout_s"] = max(5, min(120, int(limpio("timeout_s", "30"))))
    except ValueError:
        campos["timeout_s"] = 30

    if campos["kind"] not in TIPOS:
        campos["kind"] = "rss"
    if campos["category"] not in CATEGORIAS:
        campos["category"] = "news"
    if campos["priority"] not in PRIORIDADES:
        campos["priority"] = "medium"
    return campos

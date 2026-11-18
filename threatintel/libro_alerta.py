"""Hoja de calculo de la alerta diaria: un libro con una pestana por vulnerabilidad (v7).

Peticion del usuario (2026-09-06): «si hay 50 vulnerabilidades quiero que se cree un Excel con
varias hojas, donde cada hoja tenga cada una de las vulnerabilidades reportadas, con todos los
detalles que se envían en el correo pero bien ordenados, para poder hacer una gestión interna
mucho más rápida».

Se genera con openpyxl y se adjunta al correo de alerta. Sin datos sensibles fuera de lo que ya
va en el correo.

Como esta hecho y por que
-------------------------
* El correo solo explica en detalle las primeras por relevancia (ajuste ``alert_detalle_top``);
  el libro lleva TODAS, con el mismo contenido que el correo mas los activos completos.
* Los activos afectados NO se toman de ``vista["activos"]``: la ejecucion diaria los adjunta con
  un tope de 10 por amenaza, que sirve para el correo pero no para la hoja. Aqui se leen otra
  vez de la base con el tope del ajuste ``alert_excel_max_activos`` (500 por defecto) y con las
  columnas que el correo no tiene: entorno, proceso de negocio y el motivo por el que falta la
  version que corrige (``aplicabilidad.sin_parche_motivo``). Se lee en UNA consulta para todas
  las amenazas: con 881 activos y decenas de miles de veredictos, una consulta por amenaza se
  notaria.
* Los recuentos (activos afectados y activos en produccion o contingencia) salen de
  ``aplicabilidad_amenaza``, que ya los tiene calculados, no de contar filas.
* Sin formulas ni macros: los enlaces son hiperenlaces de celda y las URL pasan por
  ``notify.url_segura``, de modo que un enlace ``javascript:`` de una fuente RSS no llega al
  libro. Ademas TODA celda se escribe con ``_celda``, que fuerza a texto lo que empieza por
  «=», «+», «-» o «@»: sin eso, un titulo de RSS como «=cmd|' /c calc'!A0» acabaria siendo
  una formula real (y una peticion DDE) en el libro que abre el analista. Las fechas y los
  numeros se escriben como fecha y como numero, no como texto, para que se puedan ordenar y
  filtrar.
"""
from __future__ import annotations

import re
import sqlite3
from datetime import date, datetime
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

from . import notify
from .logging_setup import get_logger
from .paths import DATA_DIR

log = get_logger("libro_alerta")

#: Directorio de los libros de la alerta. Se crea si falta, con los permisos de ``data/``.
DIRECTORIO = DATA_DIR / "informes"

#: Caracteres que Excel no admite en el nombre de una pestana, y tope de longitud.
_PROHIBIDOS_PESTANA = re.compile(r"[:\\/?*\[\]]")
LARGO_PESTANA = 31

HOJA_RESUMEN = "Resumen"
HOJA_CORRECCIONES = "Correcciones pendientes"

#: Nombres que ya ocupan las pestanas fijas: ninguna vulnerabilidad puede quedarse con ellos.
NOMBRES_RESERVADOS = (HOJA_RESUMEN, HOJA_CORRECCIONES)

#: Tope de activos por pestana si el ajuste no dice otra cosa.
MAX_ACTIVOS = 500

_AZUL = "FF1F4E78"
_GRIS = "FFF2F4F7"
_BLANCO = "FFFFFFFF"

_ENTORNO_ES = {"produccion": "Producción", "contingencia": "Contingencia",
               "desarrollo": "Desarrollo", "pruebas": "Pruebas de usuario",
               "soporte": "Soporte y pruebas"}
_ZONA_ES = {"internet": "Expuesta a Internet", "dmz": "Zona perimetral (DMZ)",
            "interna": "Red interna"}
_ORIGEN_ES = {"servidores": "Servidor", "equipos": "Equipo de cómputo"}
_CRITICIDAD_ES = {"critical": "Crítica", "high": "Alta", "medium": "Media", "low": "Baja"}

#: Rotulo unico de la probabilidad de explotacion, con su unidad, en todas las hojas.
ETIQUETA_EPSS = "Probabilidad de explotación en 30 días (EPSS, en porcentaje)"

#: Texto unico de la explotacion activa: la hoja de resumen decia «Sí»/«No» y la ficha
#: «Sí, confirmada por CISA»/«No consta», asi que el mismo dato se leia distinto segun la
#: hoja (revision de claridad del 2026-09-15). «No consta» es lo correcto: que no figure en
#: el catalogo no demuestra que nadie la este explotando.
EXPLOTACION_SI = "Sí, confirmada por CISA"
EXPLOTACION_NO = "No consta"

#: Columnas de la pestana «Resumen»: (cabecera, ancho, formato de numero).
_COLUMNAS_RESUMEN: tuple[tuple[str, int, Optional[str]], ...] = (
    ("Prioridad", 9, "0"),
    ("Identificador", 18, None),
    ("Vulnerabilidad", 60, None),
    ("Severidad", 12, None),
    ("Puntuación CVSS", 15, "0.0"),
    ("Origen de la puntuación", 30, None),
    # Las dos hojas (resumen y ficha) usan EXACTAMENTE el mismo rotulo, la misma unidad y
    # el mismo formato de celda: antes el valor se leia como 0,6 % en una y como 0,00608 en
    # cualquier visor que ignorase el formato (revision de claridad del 2026-09-15).
    (ETIQUETA_EPSS, 20, "0.0%"),
    ("Relevancia para la organización", 16, "0"),
    ("Explotación activa (CISA KEV)", 16, None),
    ("Activos afectados", 14, "#,##0"),
    ("Activos en producción o contingencia", 20, "#,##0"),
    ("Tecnologías afectadas", 38, None),
    ("Fuente", 22, None),
    ("Ficha en la plataforma", 46, None),
)

#: Columnas de la tabla de activos afectados de cada pestana.
_COLUMNAS_ACTIVOS: tuple[tuple[str, int], ...] = (
    ("Activo", 26), ("Dirección", 16), ("Tipo", 18), ("Entorno", 18),
    ("Proceso de negocio", 22), ("Sistema operativo", 26), ("Paquete", 28),
    ("Versión instalada", 22), ("Versión a la que hay que actualizar", 30), ("Aviso", 18),
)

#: Columnas de la pestana de correcciones.
_COLUMNAS_CORRECCIONES: tuple[tuple[str, int, Optional[str]], ...] = (
    ("Vulnerabilidad", 52, None), ("Identificador", 18, None), ("Severidad", 12, None),
    ("Paquete", 26, None), ("Sistema", 22, None), ("Versión que corrige", 26, None),
    ("Aviso", 18, None), ("Días en espera", 13, "#,##0"),
    ("Activos afectados", 14, "#,##0"),
    ("Activos en producción o contingencia", 20, "#,##0"),
    ("Por qué no existía la corrección", 46, None),
)


# --------------------------------------------------------------------------
# Utilidades
# --------------------------------------------------------------------------
def _ajuste(cfg: Any, clave: str, defecto: Any) -> Any:
    if cfg is None:
        return defecto
    obtener = getattr(cfg, "get", None)
    valor = obtener(clave, defecto) if callable(obtener) else getattr(cfg, clave, defecto)
    return defecto if valor in (None, "") else valor


def _entero(valor: Any, defecto: int = 0) -> int:
    try:
        return int(float(valor))
    except (TypeError, ValueError):
        return defecto


def _decimal(valor: Any) -> Optional[float]:
    try:
        return float(valor)
    except (TypeError, ValueError):
        return None


def _texto(valor: Any, largo: int = 2000) -> str:
    texto = str(valor if valor is not None else "").strip()
    texto = texto.replace("\r\n", "\n").replace("\r", "\n")
    return texto if len(texto) <= largo else texto[: largo - 1].rstrip() + "…"


#: Prefijos con los que una hoja de calculo interpreta el contenido de una celda como
#: FORMULA. openpyxl convierte en formula real cualquier cadena que empiece por «=», y Excel
#: y LibreOffice tratan igual lo que empieza por «+», «-» o «@» cuando alguien edita la
#: celda; «=cmd|' /c calc'!A0» es, ademas, la peticion DDE clasica. Los titulos, los paquetes
#: y los avisos llegan de fuentes externas (RSS, avisos de distribucion), asi que todo texto
#: que empiece por uno de estos caracteres se escribe forzado a texto (CWE-1236, inyeccion de
#: formulas en fichero exportado). Hallazgo del revisor del 2026-09-06.
_PREFIJOS_FORMULA = ("=", "+", "-", "@", "\t", "\r", "\n")


def _clave(fila: Any, nombre: str) -> Any:
    """Lee una columna que puede no existir en bases antiguas sin migrar."""
    try:
        return fila[nombre]
    except (IndexError, KeyError):
        return None


def _celda(hoja, fila: int, columna: int, valor: Any = None):
    """Escribe una celda sin que su contenido pueda acabar siendo una formula.

    Toda escritura del libro pasa por aqui. Cuando el texto empieza por uno de los prefijos
    peligrosos se marca como texto (``data_type = "s"``, sin ``<f>`` en el XML) y con el
    prefijo de comilla de Excel, de modo que el analista ve la cadena tal cual y ningun
    programa la evalua."""
    celda = hoja.cell(row=fila, column=columna, value=valor)
    if isinstance(valor, str) and valor[:1] in _PREFIJOS_FORMULA:
        celda.data_type = "s"
        celda.quotePrefix = True
    return celda


def _fecha(valor: Any) -> Optional[datetime]:
    """Fecha y hora sin zona: openpyxl no escribe datetime con ``tzinfo``."""
    if isinstance(valor, datetime):
        dt = valor
    elif isinstance(valor, date):
        return datetime(valor.year, valor.month, valor.day)
    else:
        texto = str(valor or "").strip().replace("Z", "+00:00")
        if not texto:
            return None
        dt = None
        for intento in (texto, texto[:19], texto[:10]):
            try:
                dt = datetime.fromisoformat(intento)
                break
            except ValueError:
                continue
        if dt is None:
            return None
    if dt.tzinfo is not None:
        dt = dt.astimezone().replace(tzinfo=None)
    return dt


def nombre_pestana(identificador: str, usados: Optional[set[str]] = None) -> str:
    """Nombre de pestana valido y unico: 31 caracteres, sin ``: \\ / ? * [ ]``.

    Si el nombre ya esta usado se le anade un sufijo («CVE-2026-1000 (2)»), porque dos
    amenazas distintas pueden compartir identificador (el mismo CVE visto en dos avisos).

    La comparacion NO distingue mayusculas de minusculas y reserva los nombres de las
    pestanas fijas, porque Excel y openpyxl tampoco las distinguen: si aqui se dieran por
    distintos «CVE-2026-2001» y «cve-2026-2001», openpyxl renombraria en silencio y saldrian
    nombres engañosos («CVE-2026-20011», que parece otro CVE) o de 32 caracteres, que algunos
    programas no leen. Hallazgo del revisor del 2026-09-06."""
    limpio = _PROHIBIDOS_PESTANA.sub("-", _texto(identificador, 120))
    limpio = re.sub(r"\s+", " ", limpio).strip().strip("'")
    if not limpio:
        limpio = "Vulnerabilidad"
    base = limpio[:LARGO_PESTANA].rstrip() or "Vulnerabilidad"
    if usados is None:
        return base
    tomados = {n.casefold() for n in usados} | {n.casefold() for n in NOMBRES_RESERVADOS}
    if base.casefold() not in tomados:
        usados.add(base)
        return base
    for n in range(2, 1000):
        sufijo = f" ({n})"
        candidato = (limpio[: LARGO_PESTANA - len(sufijo)].rstrip() or "Vulnerabilidad") + sufijo
        candidato = candidato[:LARGO_PESTANA]
        if candidato.casefold() not in tomados:
            usados.add(candidato)
            return candidato
    usados.add(base)
    return base


def identificador_de(vista: dict, activos: Optional[Sequence[dict]] = None) -> str:
    """CVE si lo hay; si no, el aviso de la distribución (USN-..., DSA-...); si no, el
    identificador interno, para que la pestana siempre tenga un nombre reconocible."""
    cve = _texto(vista.get("cve"), 60)
    if cve:
        return cve
    for activo in activos or []:
        aviso = _texto(activo.get("aviso"), 60)
        if aviso:
            return aviso
    return f"AMENAZA-{vista.get('id')}"


# --------------------------------------------------------------------------
# Lectura de los activos afectados
# --------------------------------------------------------------------------
def _hay_columna(conn: sqlite3.Connection, tabla: str, columna: str) -> bool:
    try:
        return any(r[1] == columna for r in conn.execute(f"PRAGMA table_info({tabla})"))
    except sqlite3.Error:
        return False


def activos_por_amenaza(conn: sqlite3.Connection, ids: Sequence[int], *,
                        limite: int = MAX_ACTIVOS) -> dict[int, dict[str, Any]]:
    """Activos con la version vulnerable instalada, agrupados por amenaza y por activo.

    Una sola consulta para todas las amenazas. Cada activo trae sus paquetes juntos, el
    entorno y el proceso de negocio (que el correo no tiene) y el motivo por el que falta la
    version que corrige. El tope se aplica por amenaza; los recuentos totales salen de
    ``aplicabilidad_amenaza``, no de contar filas."""
    salida: dict[int, dict[str, Any]] = {
        int(i): {"afectados": [], "n_afectados": 0, "n_expuestos": 0,
                 "n_no_afectados": 0, "n_sin_dato": 0, "evaluada": False, "evaluado_at": None}
        for i in ids if i is not None}
    if not salida:
        return salida
    claves = list(salida)
    motivo = "ap.sin_parche_motivo" if _hay_columna(conn, "aplicabilidad", "sin_parche_motivo") else "NULL"
    for lote in (claves[i:i + 800] for i in range(0, len(claves), 800)):
        marcas = ",".join("?" * len(lote))
        for fila in conn.execute(
                f"""SELECT ap.threat_id, a.id AS activo_id, a.nombre, a.ip, a.origen,
                           a.so_nombre, a.so_version, a.zona, a.entorno, a.proceso,
                           ap.paquete, ap.version_instalada, ap.version_corregida,
                           ap.sin_parche_motivo, ap.referencia,
                           ap.aviso, ap.motor, {motivo} AS sin_parche_motivo
                      FROM aplicabilidad ap JOIN activos a ON a.id = ap.activo_id
                     WHERE ap.threat_id IN ({marcas}) AND ap.veredicto = 'afectado'
                       AND a.presente = 1
                     ORDER BY ap.threat_id, a.origen, a.nombre, ap.paquete""", lote):
            entrada = salida.get(int(fila["threat_id"]))
            if entrada is None:
                continue
            lista: list[dict] = entrada["afectados"]
            indice: dict = entrada.setdefault("_indice", {})
            activo = indice.get(fila["activo_id"])
            if activo is None:
                if limite and len(lista) >= limite:
                    continue
                activo = {
                    "id": fila["activo_id"], "nombre": fila["nombre"], "ip": fila["ip"],
                    "origen": fila["origen"], "so_nombre": fila["so_nombre"],
                    "so_version": fila["so_version"], "zona": fila["zona"],
                    "entorno": fila["entorno"], "proceso": fila["proceso"],
                    # Una entrada por paquete: la pareja de versiones es la de ESE paquete.
                    # Guardar solo la de la primera fila hacia que la hoja mostrara la
                    # version de un paquete distinto del que nombraba (revision 2026-09-06).
                    "paquetes": [], "paquetes_detalle": [],
                    "version_instalada": fila["version_instalada"],
                    "version_corregida": fila["version_corregida"], "aviso": fila["aviso"],
                    "motor": fila["motor"], "sin_parche_motivo": fila["sin_parche_motivo"]}
                indice[fila["activo_id"]] = activo
                lista.append(activo)
            if fila["paquete"] and fila["paquete"] not in activo["paquetes"]:
                activo["paquetes"].append(fila["paquete"])
            activo["paquetes_detalle"].append({
                "paquete": fila["paquete"], "instalada": fila["version_instalada"],
                "corregida": fila["version_corregida"],
                "sin_parche_motivo": _clave(fila, "sin_parche_motivo"),
                "aviso": _clave(fila, "aviso"), "referencia": _clave(fila, "referencia"),
            })

        # La ULTIMA version a instalar por paquete, mirando todas las vulnerabilidades
        # abiertas de ese paquete en ese activo y no solo la de esta hoja: la hoja escribia
        # la del aviso, que puede ser mas baja que la que de verdad hay que instalar
        # (peticion del usuario del 2026-09-09).
        from .aplicabilidad import anotar_version_ultima
        for datos in salida.values():
            anotar_version_ultima(conn, datos.get("afectados") or [])

        for fila in conn.execute(
                f"""SELECT threat_id, evaluado_at, afectados, no_afectados, sin_dato,
                           afectados_expuestos
                      FROM aplicabilidad_amenaza WHERE threat_id IN ({marcas})""", lote):
            entrada = salida.get(int(fila["threat_id"]))
            if entrada is None:
                continue
            entrada.update(evaluada=True, evaluado_at=fila["evaluado_at"],
                           n_afectados=_entero(fila["afectados"]),
                           n_no_afectados=_entero(fila["no_afectados"]),
                           n_sin_dato=_entero(fila["sin_dato"]),
                           n_expuestos=_entero(fila["afectados_expuestos"]))
    for entrada in salida.values():
        entrada.pop("_indice", None)
        if not entrada["n_afectados"]:
            entrada["n_afectados"] = len(entrada["afectados"])
    return salida


def _activos_de_la_vista(vista: dict, limite: int) -> dict[str, Any]:
    """Sin conexion (pruebas y llamadas sueltas): se usa lo que traiga la vista."""
    datos = dict(vista.get("activos") or {})
    lista = list(datos.get("afectados") or [])
    return {"afectados": lista[:limite] if limite else lista,
            "n_afectados": _entero(datos.get("n_afectados"), len(lista)),
            "n_expuestos": _entero(datos.get("n_afectados_expuestos")),
            "n_no_afectados": _entero(datos.get("n_no_afectados")),
            "n_sin_dato": _entero(datos.get("n_sin_dato")),
            "evaluada": bool(datos.get("evaluada")),
            "evaluado_at": datos.get("evaluado_at")}


# --------------------------------------------------------------------------
# Escritura: piezas comunes
# --------------------------------------------------------------------------
_BORDE = Border(bottom=Side(style="thin", color="FFD8DCE2"))


def _cabecera(hoja, fila: int, columnas: Iterable[tuple], *, ancho: bool = True) -> None:
    """Fila de cabecera en negrita sobre fondo azul, con los anchos de columna."""
    for indice, columna in enumerate(columnas, start=1):
        celda = _celda(hoja, fila, indice, columna[0])
        celda.font = Font(bold=True, color=_BLANCO, size=10)
        celda.fill = PatternFill("solid", fgColor=_AZUL)
        celda.alignment = Alignment(vertical="center", wrap_text=True)
        if ancho:
            hoja.column_dimensions[get_column_letter(indice)].width = columna[1]
    hoja.row_dimensions[fila].height = 30


def _titulo_bloque(hoja, fila: int, texto: str, ultima_columna: int) -> int:
    """Rotulo de un bloque (fondo gris, negrita) que ocupa el ancho de la hoja."""
    for indice in range(1, ultima_columna + 1):
        celda = _celda(hoja, fila, indice, texto if indice == 1 else None)
        celda.fill = PatternFill("solid", fgColor=_GRIS)
        celda.font = Font(bold=True, size=11, color="FF1F2933")
    hoja.row_dimensions[fila].height = 20
    return fila + 1


def _fila_clave_valor(hoja, fila: int, etiqueta: str, valor: Any, *,
                      formato: Optional[str] = None, enlace: Optional[str] = None,
                      ultima_columna: int = 10) -> int:
    """Etiqueta en la columna A y valor en la B (combinada hasta el final de la hoja)."""
    celda = _celda(hoja, fila, 1, etiqueta)
    celda.font = Font(bold=True, size=10, color="FF4A5563")
    celda.alignment = Alignment(vertical="top", wrap_text=True)
    celda.border = _BORDE
    if ultima_columna > 2:
        hoja.merge_cells(start_row=fila, start_column=2, end_row=fila, end_column=ultima_columna)
    destino = _celda(hoja, fila, 2, valor)
    destino.alignment = Alignment(vertical="top", wrap_text=True)
    if formato:
        destino.number_format = formato
    if enlace:
        destino.hyperlink = enlace
        destino.font = Font(color=_AZUL, underline="single", size=10)
    for indice in range(2, ultima_columna + 1):
        hoja.cell(row=fila, column=indice).border = _BORDE
    texto = str(valor if valor is not None else "")
    lineas = max(texto.count("\n") + 1, (len(texto) // 150) + 1)
    hoja.row_dimensions[fila].height = min(15 * lineas, 240) if lineas > 1 else 16
    return fila + 1


def _valor_numero(hoja, fila: int, columna: int, valor: Optional[float],
                  formato: str) -> None:
    celda = _celda(hoja, fila, columna, valor)
    if valor is not None:
        celda.number_format = formato
    celda.border = _BORDE


# --------------------------------------------------------------------------
# Pestana «Resumen»
# --------------------------------------------------------------------------
def _tecnologias_texto(vista: dict) -> str:
    nombres: list[str] = []
    for tec in vista.get("technologies") or []:
        nombre = _texto(tec.get("name"), 60)
        if nombre and nombre not in nombres:
            nombres.append(nombre)
    if not nombres:
        return ""
    if len(nombres) <= 6:
        return ", ".join(nombres)
    return ", ".join(nombres[:6]) + f" y {len(nombres) - 6} más"


def _fuentes_texto(vista: dict) -> str:
    nombres = [_texto(f.get("name"), 40) for f in (vista.get("sources") or [])]
    nombres = [n for n in nombres if n]
    return ", ".join(nombres[:2]) if nombres else ""


def _hoja_resumen(libro: Workbook, filas: Sequence[dict]) -> None:
    hoja = libro.create_sheet(HOJA_RESUMEN)
    _cabecera(hoja, 1, _COLUMNAS_RESUMEN)
    for numero, datos in enumerate(filas, start=1):
        fila = numero + 1
        vista = datos["vista"]
        valores = (
            (1, numero, "0"),
            (2, datos["identificador"], None),
            (3, _texto(vista.get("title_es") or vista.get("title_en"), 300), None),
            (4, notify.severidad_texto(vista.get("severity")), None),
            (5, _decimal(vista.get("cvss_score")), "0.0"),
            (6, notify.origen_texto(vista.get("severity_source")), None),
            (7, _decimal(vista.get("epss_score")), "0.0%"),
            (8, _entero(round(_decimal(vista.get("relevance")) or 0)), "0"),
            (9, EXPLOTACION_SI if vista.get("in_kev") else EXPLOTACION_NO, None),
            (10, datos["activos"]["n_afectados"], "#,##0"),
            (11, datos["activos"]["n_expuestos"], "#,##0"),
            (12, _tecnologias_texto(vista), None),
            (13, _fuentes_texto(vista), None),
        )
        for columna, valor, formato in valores:
            celda = _celda(hoja, fila, columna, valor)
            if formato and isinstance(valor, (int, float)):
                celda.number_format = formato
            celda.alignment = Alignment(vertical="top", wrap_text=columna in (3, 6, 12))
            celda.border = _BORDE
        enlace = datos["url"]
        celda = _celda(hoja, fila, 14, enlace or "")
        celda.border = _BORDE
        if enlace:
            celda.hyperlink = enlace
            celda.font = Font(color=_AZUL, underline="single", size=10)
    hoja.freeze_panes = "A2"
    if filas:
        hoja.auto_filter.ref = f"A1:{get_column_letter(len(_COLUMNAS_RESUMEN))}{len(filas) + 1}"


# --------------------------------------------------------------------------
# Pestana de una vulnerabilidad
# --------------------------------------------------------------------------
def _hoja_vulnerabilidad(libro: Workbook, datos: dict, *, numero: int, total: int,
                         limite_activos: int, url_activos: str, umbral: float,
                         min_confianza: float) -> None:
    vista = datos["vista"]
    ultima = len(_COLUMNAS_ACTIVOS)
    hoja = libro.create_sheet(datos["pestana"])
    for indice, (_cab, ancho) in enumerate(_COLUMNAS_ACTIVOS, start=1):
        hoja.column_dimensions[get_column_letter(indice)].width = ancho

    fila = 1
    titulo = _celda(hoja, fila, 1,
                    f"{numero}. {datos['identificador']} — "
                    f"{_texto(vista.get('title_es') or vista.get('title_en'), 200)}")
    titulo.font = Font(bold=True, size=13, color="FF1F2933")
    titulo.alignment = Alignment(vertical="center", wrap_text=False)
    hoja.row_dimensions[fila].height = 22
    fila += 1
    sub = _celda(hoja, fila, 1,
                 f"Prioridad {numero} de {total} en la alerta del "
                 f"{notify.fecha_larga(datos['fecha'])}.")
    sub.font = Font(size=10, color="FF63707E")
    fila += 2

    # ------------------------------------------------------------ identificacion
    fila = _titulo_bloque(hoja, fila, "Identificación", ultima)
    fila = _fila_clave_valor(hoja, fila, "Identificador", datos["identificador"],
                             enlace=notify.url_segura(notify.enlace_nvd(vista.get("cve"))) or None,
                             ultima_columna=ultima)
    fila = _fila_clave_valor(hoja, fila, "Vulnerabilidad",
                             _texto(vista.get("title_es") or vista.get("title_en"), 400),
                             ultima_columna=ultima)
    fila = _fila_clave_valor(hoja, fila, "Severidad",
                             notify.severidad_texto(vista.get("severity")), ultima_columna=ultima)
    cvss = _decimal(vista.get("cvss_score"))
    fila = _fila_clave_valor(hoja, fila, "Puntuación CVSS",
                             cvss if cvss is not None else "no disponible",
                             formato="0.0" if cvss is not None else None, ultima_columna=ultima)
    fila = _fila_clave_valor(hoja, fila, "Origen de la puntuación",
                             notify.origen_texto(vista.get("severity_source")), ultima_columna=ultima)
    if vista.get("cvss_vector"):
        fila = _fila_clave_valor(hoja, fila, "Vector CVSS",
                                 _texto(vista.get("cvss_vector"), 120), ultima_columna=ultima)
    epss = _decimal(vista.get("epss_score"))
    fila = _fila_clave_valor(hoja, fila, ETIQUETA_EPSS,
                             epss if epss is not None else "no disponible",
                             formato="0.0%" if epss is not None else None, ultima_columna=ultima)
    fila = _fila_clave_valor(hoja, fila, "Relevancia para la organización",
                             _entero(round(_decimal(vista.get("relevance")) or 0)),
                             formato="0", ultima_columna=ultima)
    fila = _fila_clave_valor(hoja, fila, "Explotación activa (CISA KEV)",
                             EXPLOTACION_SI if vista.get("in_kev") else EXPLOTACION_NO,
                             ultima_columna=ultima)
    if vista.get("in_kev") and vista.get("kev_due_date"):
        fila = _fila_clave_valor(hoja, fila, "Plazo de corrección de CISA",
                                 _fecha(vista.get("kev_due_date")), formato="DD/MM/YYYY",
                                 ultima_columna=ultima)
    fila = _fila_clave_valor(hoja, fila, "Estado de la gestión",
                             datos["estado_es"], ultima_columna=ultima)
    for etiqueta, clave in (("Publicada por la fuente", "published_at"),
                            ("Detectada por el sistema", "first_seen_at"),
                            ("Vista por última vez", "last_seen_at"),
                            ("Incluida en la alerta", "alerted_at")):
        valor = _fecha(vista.get(clave))
        if valor is not None:
            fila = _fila_clave_valor(hoja, fila, etiqueta, valor, formato="DD/MM/YYYY",
                                     ultima_columna=ultima)
    fila += 1

    # ------------------------------------------------- por que esta en la alerta
    fila = _titulo_bloque(hoja, fila, "Por qué está en la alerta", ultima)
    por_que = notify.motivo_alerta(vista, umbral=umbral, min_confianza=min_confianza)
    fila = _fila_clave_valor(hoja, fila, "Motivo",
                             (por_que + ".") if por_que else "Sin motivo registrado.",
                             ultima_columna=ultima)
    fila += 1

    # ------------------------------------------------ descripcion y remediacion
    fila = _titulo_bloque(hoja, fila, "Qué es y qué hacer", ultima)
    fila = _fila_clave_valor(hoja, fila, "Descripción",
                             _texto(vista.get("summary_es") or vista.get("summary_en"), 4000)
                             or "Sin descripción disponible.", ultima_columna=ultima)
    fila = _fila_clave_valor(hoja, fila, "Impacto",
                             _texto(vista.get("impact_es"), 4000) or "Sin redactar.",
                             ultima_columna=ultima)
    fila = _fila_clave_valor(hoja, fila, "Remediación",
                             _texto(vista.get("remediation_es"), 6000) or "Sin redactar.",
                             ultima_columna=ultima)
    fila += 1

    # --------------------------------------------------- tecnologias afectadas
    tecnologias = list(vista.get("technologies") or [])
    if tecnologias:
        fila = _titulo_bloque(hoja, fila, "Tecnologías afectadas del inventario", ultima)
        cabeceras = (("Tecnología", 26), ("Versión instalada", 22), ("Veredicto", 26),
                     ("Fiabilidad de la coincidencia", 26), ("Sistemas", 12),
                     ("Exposición", 22), ("Criticidad", 14))
        _cabecera(hoja, fila, cabeceras, ancho=False)
        fila += 1
        for tec in tecnologias:
            valores = (
                _texto(tec.get("name"), 80),
                _texto(tec.get("version_installed"), 60) or "sin registrar",
                notify.veredicto_texto(tec.get("version_verdict")),
                notify.etiqueta_confianza(tec),
                _entero(tec.get("systems_count")),
                _ZONA_ES.get(str(tec.get("exposure") or "").lower(),
                             _texto(tec.get("exposure"), 30) or "sin determinar"),
                _CRITICIDAD_ES.get(str(tec.get("criticality") or "").lower(),
                                   _texto(tec.get("criticality"), 20) or "sin determinar"))
            for indice, valor in enumerate(valores, start=1):
                celda = _celda(hoja, fila, indice, valor)
                celda.alignment = Alignment(vertical="top", wrap_text=True)
                celda.border = _BORDE
                if indice == 5:
                    celda.number_format = "#,##0"
            fila += 1
        fila += 1

    # ------------------------------------------------------ fuentes y referencias
    fuentes = list(vista.get("sources") or [])
    enlace_nvd = notify.url_segura(notify.enlace_nvd(vista.get("cve")))
    if fuentes or enlace_nvd:
        fila = _titulo_bloque(hoja, fila, "Fuentes y referencias", ultima)
        if enlace_nvd:
            fila = _fila_clave_valor(hoja, fila, "NVD (ficha oficial)", enlace_nvd,
                                     enlace=enlace_nvd, ultima_columna=ultima)
        for fuente in fuentes:
            url = notify.url_segura(fuente.get("url"))
            fila = _fila_clave_valor(hoja, fila, _texto(fuente.get("name"), 40) or "Fuente",
                                     url or "enlace no disponible",
                                     enlace=url or None, ultima_columna=ultima)
        fila += 1

    # -------------------------------------------------------- activos afectados
    activos = datos["activos"]
    fila = _titulo_bloque(hoja, fila, "Activos afectados (OCS Inventory)", ultima)
    # Texto visible: concordancia de singular y plural y numeros en formato español
    # (notify.numero), como pide la regla 3 del proyecto.
    n_afectados = _entero(activos["n_afectados"])
    n_no_afectados = _entero(activos["n_no_afectados"])
    n_sin_dato = _entero(activos["n_sin_dato"])
    resumen = (f"{notify.numero(n_afectados)} activo{'' if n_afectados == 1 else 's'} con la "
               f"versión vulnerable instalada, de los cuales "
               f"{notify.numero(_entero(activos['n_expuestos']))} en producción o "
               f"contingencia.")
    if n_no_afectados:
        resumen += (f" {notify.numero(n_no_afectados)} "
                    + ("ya está corregido." if n_no_afectados == 1 else "ya están corregidos."))
    if n_sin_dato:
        resumen += (f" {notify.numero(n_sin_dato)} "
                    + ("sin dato suficiente para decidir."
                       if n_sin_dato == 1 else "sin datos suficientes para decidir."))
    fila = _fila_clave_valor(hoja, fila, "Situación", resumen, ultima_columna=ultima)
    fila += 1

    lista = activos["afectados"]
    if lista:
        primera_tabla = fila
        _cabecera(hoja, fila, _COLUMNAS_ACTIVOS, ancho=False)
        fila += 1
        for activo in lista:
            # La mas alta pedida por el paquete, no la de este aviso (2026-09-09).
            ultimas = sorted({d.get("version_ultima") for d in (activo.get("paquetes_detalle") or [])
                              if d.get("version_ultima")})
            corregida = _texto(", ".join(ultimas) if ultimas
                               else activo.get("version_corregida"), 80)
            valores = (
                _texto(activo.get("nombre"), 80),
                _texto(activo.get("ip"), 60),
                _ORIGEN_ES.get(str(activo.get("origen") or ""), _texto(activo.get("origen"), 30)),
                _ENTORNO_ES.get(str(activo.get("entorno") or "").lower(),
                                _texto(activo.get("entorno"), 30) or "sin clasificar"),
                _texto(activo.get("proceso"), 60) or "sin asignar",
                " ".join(x for x in (_texto(activo.get("so_nombre"), 60),
                                     _texto(activo.get("so_version"), 30)) if x),
                ", ".join(_texto(p, 60) for p in (activo.get("paquetes") or [])),
                _texto(activo.get("version_instalada"), 80),
                corregida or notify.motivo_sin_parche(activo.get("sin_parche_motivo")),
                _texto(activo.get("aviso"), 60))
            for indice, valor in enumerate(valores, start=1):
                celda = _celda(hoja, fila, indice, valor)
                celda.alignment = Alignment(vertical="top", wrap_text=True)
                celda.border = _BORDE
                if indice == 9 and not corregida:
                    celda.font = Font(color="FF8A6D0B", size=10)
            fila += 1
        hoja.auto_filter.ref = (f"A{primera_tabla}:{get_column_letter(ultima)}{fila - 1}")
        fuera = max(0, activos["n_afectados"] - len(lista))
        if fuera:
            hoja.merge_cells(start_row=fila, start_column=1, end_row=fila, end_column=ultima)
            listados = ("Se lista el primer activo" if len(lista) == 1 else
                        f"Se listan los primeros {notify.numero(len(lista))} activos")
            restantes = ("El restante se consulta" if fuera == 1 else
                         f"Los {notify.numero(fuera)} restantes se consultan")
            aviso = _celda(
                hoja, fila, 1,
                (f"{listados} de {notify.numero(activos['n_afectados'])}. "
                 f"{restantes} en la plataforma"
                 + (f": {url_activos}" if url_activos else "") + "."))
            aviso.font = Font(italic=True, size=10, color="FF63707E")
            aviso.alignment = Alignment(vertical="center", wrap_text=True)
            fila += 1
    else:
        fila = _fila_clave_valor(
            hoja, fila, "Detalle",
            "Ningún activo presente tiene instalada la versión vulnerable.",
            ultima_columna=ultima)


# --------------------------------------------------------------------------
# Pestana «Correcciones pendientes»
# --------------------------------------------------------------------------
def _hoja_correcciones(libro: Workbook, correcciones: Sequence[dict]) -> None:
    hoja = libro.create_sheet(HOJA_CORRECCIONES)
    aviso = _celda(hoja, 1, 1,
                   "Vulnerabilidades que estaban en seguimiento por no existir una versión "
                   "que las corrigiera y para las que la corrección ya se ha publicado: se "
                   "puede programar la actualización.")
    aviso.font = Font(size=10, color="FF63707E")
    aviso.alignment = Alignment(vertical="center", wrap_text=False)
    _cabecera(hoja, 3, _COLUMNAS_CORRECCIONES)
    for indice, correccion in enumerate(correcciones, start=1):
        fila = indice + 3
        valores = (
            _texto(correccion.get("titulo") or correccion.get("title_es")
                   or correccion.get("title_en"), 300),
            _texto(correccion.get("cve"), 60),
            notify.severidad_texto(correccion.get("severidad") or correccion.get("severity")),
            _texto(correccion.get("paquete"), 80),
            _texto(correccion.get("sistema") or correccion.get("ecosistema"), 60),
            _texto(correccion.get("version_corregida"), 80),
            _texto(correccion.get("aviso"), 60),
            _entero(correccion.get("dias_en_espera")),
            _entero(correccion.get("n_activos")),
            _entero(correccion.get("n_activos_expuestos")),
            _texto(correccion.get("motivo_es") or correccion.get("motivo"), 200),
        )
        for columna, valor in enumerate(valores, start=1):
            celda = _celda(hoja, fila, columna, valor)
            formato = _COLUMNAS_CORRECCIONES[columna - 1][2]
            if formato and isinstance(valor, (int, float)):
                celda.number_format = formato
            celda.alignment = Alignment(vertical="top", wrap_text=columna in (1, 11))
            celda.border = _BORDE
    hoja.freeze_panes = "A4"
    if correcciones:
        hoja.auto_filter.ref = (f"A3:{get_column_letter(len(_COLUMNAS_CORRECCIONES))}"
                                f"{len(correcciones) + 3}")


def _correcciones(conn: Optional[sqlite3.Connection], meta: dict) -> list[dict]:
    """Las que trae ``meta["parches_nuevos"]``; si no vienen, se leen sin sellar nada.

    Si el modulo de parches todavia no esta implementado o la tabla no existe, devuelve una
    lista vacia y la pestana no se escribe."""
    dadas = meta.get("parches_nuevos")
    if dadas:
        return [dict(x) for x in dadas]
    if conn is None:
        return []
    try:
        from . import parches
        return [dict(x) for x in (parches.novedades(conn, marcar=False) or [])]
    except Exception as exc:  # noqa: BLE001 - la hoja no puede tumbar la alerta
        log.warning("no se pudieron leer las correcciones nuevas",
                    extra={"error": f"{type(exc).__name__}: {exc}"})
        return []


# --------------------------------------------------------------------------
# Libro aparte solo con las correcciones que ya estan disponibles (v7)
# --------------------------------------------------------------------------
def generar_correcciones(conn: Optional[sqlite3.Connection], correcciones: Optional[Sequence[dict]] = None,
                         *, destino: Optional[Path] = None, cfg: Any = None,
                         meta: Optional[dict] = None) -> Optional[Path]:
    """Libro con UNA sola cosa: las correcciones publicadas desde el correo anterior.

    El usuario lo pidio el 2026-09-06 aparte del libro de vulnerabilidades, «para tener un
    mejor control y visual»: quien programa las actualizaciones abre este y ve solo lo que ya
    se puede aplicar, con el paquete, la version que corrige, el aviso, cuantos dias estuvo en
    espera y cuantos activos afecta. Devuelve la ruta, o None si no hay ninguna correccion
    nueva (en ese dia no se adjunta nada).

    ``correcciones``: lo que devuelve ``threatintel.parches.novedades``. Si no se pasa, se lee
    de ``meta["parches_nuevos"]`` y, en ultimo termino, de la base sin sellar nada."""
    meta = dict(meta or {})
    if correcciones is None:
        correcciones = _correcciones(conn, meta)
    else:
        correcciones = [dict(x) for x in correcciones]
    if not correcciones:
        return None

    hoy = date.today()
    libro = Workbook()
    hoja = libro.active
    hoja.title = "Correcciones disponibles"

    titulo = _celda(hoja, 1, 1, "Correcciones que ya están disponibles")
    titulo.font = Font(size=13, bold=True, color=_AZUL)
    subtitulo = _celda(
        hoja, 2, 1,
        f"Publicadas desde el aviso anterior · {notify.fecha_larga(hoy)} · "
        f"{notify.numero(len(correcciones))} en total. Estas vulnerabilidades estaban "
        "confirmadas en activos de la organización sin que existiera una versión que las "
        "corrigiera; la corrección ya se ha publicado y se puede programar la actualización.")
    subtitulo.font = Font(size=10, color="FF63707E")
    subtitulo.alignment = Alignment(vertical="center", wrap_text=False)

    _cabecera(hoja, 4, _COLUMNAS_CORRECCIONES)
    total_activos = total_expuestos = 0
    for indice, correccion in enumerate(correcciones, start=1):
        fila = indice + 4
        n_activos = _entero(correccion.get("n_activos"))
        n_expuestos = _entero(correccion.get("n_activos_expuestos"))
        total_activos += n_activos
        total_expuestos += n_expuestos
        valores = (
            _texto(correccion.get("titulo") or correccion.get("title_es")
                   or correccion.get("title_en"), 300),
            _texto(correccion.get("cve"), 60),
            notify.severidad_texto(correccion.get("severidad") or correccion.get("severity")),
            _texto(correccion.get("paquete"), 80),
            _texto(correccion.get("sistema") or correccion.get("ecosistema"), 60),
            _texto(correccion.get("version_corregida"), 80),
            _texto(correccion.get("aviso"), 60),
            _entero(correccion.get("dias_en_espera")),
            n_activos,
            n_expuestos,
            _texto(correccion.get("motivo_es") or correccion.get("motivo"), 200),
        )
        for columna, valor in enumerate(valores, start=1):
            celda = _celda(hoja, fila, columna, valor)
            formato = _COLUMNAS_CORRECCIONES[columna - 1][2]
            if formato and isinstance(valor, (int, float)):
                celda.number_format = formato
            celda.alignment = Alignment(vertical="top", wrap_text=columna in (1, 11))
            celda.border = _BORDE

    # Fila de totales: lo primero que mira quien reparte el trabajo.
    fila_total = len(correcciones) + 5
    etiqueta = _celda(hoja, fila_total, 1, "Total")
    etiqueta.font = Font(bold=True)
    for columna, valor in ((9, total_activos), (10, total_expuestos)):
        celda = _celda(hoja, fila_total, columna, valor)
        celda.font = Font(bold=True)
        celda.number_format = "#,##0"

    hoja.freeze_panes = "A5"
    hoja.auto_filter.ref = f"A4:{get_column_letter(len(_COLUMNAS_CORRECCIONES))}{len(correcciones) + 4}"

    ruta = Path(destino) if destino else DIRECTORIO / f"correcciones_disponibles_{hoy.isoformat()}.xlsx"
    if destino is None:
        ruta.parent.mkdir(parents=True, exist_ok=True)
        try:
            ruta.parent.chmod(0o700)
        except OSError:
            pass
    libro.save(ruta)
    try:
        ruta.chmod(0o600)
    except OSError:
        pass
    log.info("libro de correcciones disponibles generado",
             extra={"ruta": str(ruta), "correcciones": len(correcciones)})
    return ruta


# --------------------------------------------------------------------------
# Punto de entrada
# --------------------------------------------------------------------------
def generar(conn: sqlite3.Connection, amenazas: Sequence[dict], *, destino: Optional[Path] = None,
            cfg: Any = None, meta: Optional[dict] = None) -> Optional[Path]:
    """Escribe el libro y devuelve su ruta (o None si no hay nada que escribir).

    Estructura: una pestana «Resumen» con una fila por vulnerabilidad (orden de prioridad,
    identificador, severidad, CVSS, EPSS, relevancia, activos afectados, expuestos,
    tecnologias, fuente y enlace a la plataforma), una pestana «Correcciones pendientes» con
    las correcciones que ya se han publicado, y una pestana por vulnerabilidad con sus datos y
    la tabla de activos afectados. Nombres de pestana validos (31 caracteres, sin
    ``: \\ / ? * [ ]``), cabeceras en negrita, paneles inmovilizados, autofiltro, anchos de
    columna razonables y fechas y numeros escritos como fecha y como numero.

    ``meta``: ``url_base`` (prefijo de la plataforma para los enlaces) y ``parches_nuevos``.
    ``cfg``: ``alert_excel_max_activos`` (tope de activos por pestana), ``alert_min_relevance``
    y ``alert_min_match_confidence`` (para la frase «por qué está en la alerta»)."""
    lista = [dict(a) for a in (amenazas or []) if a]
    if not lista:
        return None
    meta = dict(meta or {})
    limite = max(1, _entero(_ajuste(cfg, "alert_excel_max_activos", MAX_ACTIVOS), MAX_ACTIVOS))
    umbral = _decimal(_ajuste(cfg, "alert_min_relevance", 50)) or 50.0
    min_confianza = _decimal(_ajuste(cfg, "alert_min_match_confidence", 0.6)) or 0.6
    base = str(meta.get("url_base") or "").rstrip("/").removesuffix("/amenazas")
    url_activos = f"{base}/activos/" if base else ""
    hoy = date.today()

    if conn is not None:
        activos = activos_por_amenaza(conn, [a.get("id") for a in lista if a.get("id") is not None],
                                      limite=limite)
    else:
        activos = {}

    from .queries import ESTADO_ES
    usados: set[str] = set()
    filas: list[dict] = []
    for vista in lista:
        datos_activos = activos.get(_entero(vista.get("id"), -1)) if conn is not None else None
        if datos_activos is None:
            datos_activos = _activos_de_la_vista(vista, limite)
        identificador = identificador_de(vista, datos_activos["afectados"])
        url = notify.url_segura(f"{base}/amenazas/{vista['id']}") if base and vista.get("id") is not None else ""
        filas.append({
            "vista": vista, "identificador": identificador,
            "pestana": nombre_pestana(identificador, usados),
            "activos": datos_activos, "url": url, "fecha": hoy,
            "estado_es": ESTADO_ES.get(str(vista.get("estado") or "nueva"),
                                       _texto(vista.get("estado"), 40) or "Nueva")})

    libro = Workbook()
    libro.remove(libro.active)          # openpyxl crea una hoja vacia que no se usa
    libro.properties.title = f"Alerta de vulnerabilidades del {notify.fecha_larga(hoy)}"
    libro.properties.creator = "Sistema de Inteligencia de Amenazas"
    _hoja_resumen(libro, filas)
    correcciones = _correcciones(conn, meta)
    if correcciones:
        _hoja_correcciones(libro, correcciones)
    for numero, datos in enumerate(filas, start=1):
        _hoja_vulnerabilidad(libro, datos, numero=numero, total=len(filas),
                             limite_activos=limite, url_activos=url_activos,
                             umbral=umbral, min_confianza=min_confianza)

    ruta = Path(destino) if destino else DIRECTORIO / f"alerta_{hoy.isoformat()}.xlsx"
    ruta.parent.mkdir(parents=True, exist_ok=True)
    if destino is None:
        # El libro lleva el mapa de activos vulnerables, asi que el directorio propio del
        # modulo se cierra a su dueno. Cuando el llamador indica «destino» NO se toca: no le
        # corresponde a este modulo cambiar los permisos de un directorio ajeno (hallazgo del
        # revisor del 2026-09-06).
        try:
            ruta.parent.chmod(0o700)
        except OSError:
            pass
    libro.save(str(ruta))
    if destino is None:
        # El libro solo lo lee el proceso que envia la alerta; el resto del sistema no
        # necesita el mapa de activos vulnerables.
        try:
            ruta.chmod(0o600)
        except OSError:
            pass
    # «amenazas»: una hoja por amenaza de la alerta. Las vulnerabilidades (un CVE en un
    # activo) se cuentan dentro de cada hoja, en «activos con la version vulnerable», que
    # sale de ``aplicabilidad_amenaza.afectados`` (activos distintos), no de filas de paquete.
    log.info("libro de la alerta generado", extra={
        "ruta": str(ruta), "amenazas": len(filas),
        "pestanas": len(libro.sheetnames), "bytes": ruta.stat().st_size})
    return ruta

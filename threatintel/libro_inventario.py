"""Hojas de calculo de los activos que han dejado de reportar a OCS Inventory.

Peticion del usuario (2026-09-15):

    «necesito ademas un informe para equipos y para servidores que me indique cuantos
    servidores o equipos han dejado de reportar y me los envie en archivos diferentes, uno
    de equipos y otro de servidores, de manera detallada de proceso, hostname, IP y demas».

Que hace y por que asi
----------------------
* **Dos ficheros separados**, uno de servidores y otro de equipos de computo, porque los
  responsables no son los mismos y cada lista se reparte por su lado. Si un grupo no tiene
  ni una maquina sin reportar, **su fichero no se genera**: un adjunto vacio hace perder
  tiempo a quien lo abre.
* **Hoja de calculo (`.xlsx`) y no un CSV ni un PDF**: Redes filtra,
  ordena y reparte esta lista. El `.xlsx` conserva el tipo de cada dato (las fechas se
  ordenan como fechas y los dias como numeros), lleva los anchos de columna, la fila de
  cabecera inmovilizada y el autofiltro puesto, y no tiene el problema de codificacion que
  el CSV arrastra con las tildes en Excel. Un PDF no se puede filtrar.
* **Sin formulas**: toda celda se escribe con :func:`_celda` de ``libro_alerta``, que fuerza
  a texto lo que empieza por «=», «+», «-» o «@». Los nombres de maquina, los grupos y las
  descripciones vienen de OCS Inventory, es decir, de fuera: sin ese filtro, un nombre como
  ``=cmd|' /c calc'!A0`` seria una formula real en el libro que abre el tecnico.
* **Orden de trabajo**: primero las que nunca han reportado, despues las que llevan mas
  dias y, a igualdad de dias, las que arrastran mas vulnerabilidades confirmadas.
* **Fila de totales** al final de la lista y **hoja de resumen** al principio con cuantos
  son, de cuantos, desde cuando se considera que no reportan y que hay que hacer.

Los datos salen de :func:`threatintel.ocs.inventario_sin_reportar_detallado`, que los lee
en dos consultas por conjuntos: aqui no se consulta la base ni una sola vez por fila.
"""
from __future__ import annotations

import unicodedata
from datetime import date, datetime
from pathlib import Path
from typing import Any, Optional

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

from . import notify
from .libro_alerta import _celda, _fecha, _texto
from .logging_setup import get_logger
from .paths import DATA_DIR

log = get_logger("libro_inventario")

#: Directorio donde se dejan los libros cuando no se indica otro.
DIRECTORIO = DATA_DIR / "informes"

_AZUL = "FF1F4E78"
_GRIS = "FFF2F4F7"
_BLANCO = "FFFFFFFF"
_BORDE = Border(bottom=Side(style="thin", color="FFD8DCE2"))

#: Nombre de la hoja de detalle de cada tipo de maquina.
HOJA_RESUMEN = "Resumen"
HOJA_DETALLE = {"servidores": "Servidores sin reportar",
                "equipos": "Equipos de cómputo sin reportar"}

#: Titulo de cada fichero, en singular y en plural, para no decir nunca «equipo» a secas.
TITULO = {"servidores": "Servidores que han dejado de reportar",
          "equipos": "Equipos de cómputo que han dejado de reportar"}
UNIDAD = {"servidores": ("servidor", "servidores"),
          "equipos": ("equipo de cómputo", "equipos de cómputo")}

#: Columnas de la hoja de detalle: (cabecera, ancho, formato de numero).
#: Las cinco primeras son las que pidio el usuario («proceso, hostname, IP y demas»); las
#: demas son las que hacen falta para repartir el trabajo sin volver a la plataforma.
COLUMNAS: tuple[tuple[str, int, Optional[str]], ...] = (
    ("Nombre del activo", 28, None),
    ("Dirección IP", 16, None),
    ("Proceso de negocio", 28, None),
    ("Entorno", 16, None),
    ("Sistema operativo", 30, None),
    ("Versión del sistema operativo", 20, None),
    ("Zona de red", 20, None),
    ("Usuario o responsable", 26, None),
    ("Días sin reportar", 14, "#,##0"),
    ("Fecha del último inventario", 22, "dd/mm/yyyy hh:mm"),
    ("Fecha en que se vio por última vez", 24, "dd/mm/yyyy hh:mm"),
    ("Última conexión registrada", 22, "dd/mm/yyyy hh:mm"),
    ("Vulnerabilidades confirmadas", 18, "#,##0"),
    ("De ellas, con explotación activa confirmada", 20, "#,##0"),
    ("Grupo en OCS Inventory", 24, None),
    ("Identificador en OCS Inventory", 16, "0"),
    ("Qué conviene revisar primero", 62, None),
)

#: Columnas (base 1) que llevan la cifra de la fila de totales.
_COLUMNA_DIAS = 9
_COLUMNA_VULNERABILIDADES = 13
_COLUMNA_KEV = 14
_COLUMNA_NOTA_TOTAL = 10

#: Texto cuando la maquina no ha enviado inventario nunca.
NUNCA = "Nunca ha reportado"


def _plural(n: int, origen: str) -> str:
    """«34 servidores», «1 equipo de cómputo»: la unidad, siempre escrita."""
    singular, plural = UNIDAD.get(origen, ("activo", "activos"))
    return f"{notify.numero(n)} {singular if n == 1 else plural}"


def _sin_tildes(texto: str) -> str:
    """Nombre de fichero legible en cualquier sistema: sin tildes ni eñes ni espacios.

    El fichero viaja por correo y acaba en el escritorio de quien lo recibe; los clientes
    de correo antiguos y los sistemas de ficheros de Windows destrozan las tildes en el
    nombre del adjunto. El TEXTO de dentro si lleva tildes: es lo que se lee.
    """
    plano = unicodedata.normalize("NFKD", str(texto or ""))
    plano = "".join(c for c in plano if not unicodedata.combining(c))
    limpio = "".join(c if c.isalnum() else "_" for c in plano)
    while "__" in limpio:
        limpio = limpio.replace("__", "_")
    return limpio.strip("_")


def nombre_fichero(origen: str, fecha: Optional[date] = None) -> str:
    """«Servidores_sin_reportar_2026-09-15.xlsx»: se entiende al verlo en el escritorio."""
    dia = (fecha or date.today()).isoformat()
    etiqueta = {"servidores": "Servidores", "equipos": "Equipos_de_computo"}.get(
        origen, _sin_tildes(origen).capitalize())
    return f"{etiqueta}_sin_reportar_{dia}.xlsx"


def _cabecera(hoja, fila: int) -> None:
    for indice, (titulo, ancho, _formato) in enumerate(COLUMNAS, start=1):
        celda = _celda(hoja, fila, indice, titulo)
        celda.font = Font(bold=True, color=_BLANCO, size=10)
        celda.fill = PatternFill("solid", fgColor=_AZUL)
        celda.alignment = Alignment(vertical="center", wrap_text=True)
        hoja.column_dimensions[get_column_letter(indice)].width = ancho
    hoja.row_dimensions[fila].height = 32


def _revisar_primero(activo: dict, dias_umbral: int) -> str:
    """La frase que dice al tecnico por donde empezar con ESA maquina."""
    vulnerables = int(activo.get("vulnerabilidades") or 0)
    kev = int(activo.get("kev") or 0)
    dias = activo.get("dias_sin_reportar")
    if activo.get("nunca"):
        base = ("Nunca ha enviado inventario: comprobar si el agente llegó a instalarse, "
                "o si la máquina ya no existe y hay que darla de baja en OCS Inventory.")
    else:
        base = (f"Lleva {notify.numero(int(dias or 0))} días sin enviar inventario (el "
                f"plazo son {notify.numero(dias_umbral)} días): comprobar si está "
                f"encendida, si el agente está detenido o desinstalado, o si cambió de red "
                f"y ya no alcanza al servidor de OCS Inventory.")
    if kev:
        return (base + f" Arrastra {notify.numero(vulnerables)} vulnerabilidades "
                f"confirmadas, {notify.numero(kev)} de ellas con explotación activa "
                f"confirmada: es de las primeras que hay que recuperar.")
    if vulnerables:
        return (base + f" Arrastra {notify.numero(vulnerables)} vulnerabilidades "
                f"confirmadas con datos antiguos: mientras no reporte no se sabe si "
                f"siguen abiertas o ya están corregidas.")
    return base + " No tiene vulnerabilidades confirmadas con el último dato recibido."


def _fila_detalle(hoja, fila: int, activo: dict, dias_umbral: int) -> None:
    ultimo = _fecha(activo.get("ultimo_inventario"))
    valores: list[Any] = [
        _texto(activo.get("nombre"), 120),
        _texto(activo.get("ip"), 60) or "sin dirección registrada",
        _texto(activo.get("proceso"), 120) or "Sin proceso asignado",
        _texto(activo.get("entorno_es"), 40) or "Sin entorno asignado",
        _texto(activo.get("so_nombre"), 120) or "Sin datos de sistema",
        _texto(activo.get("so_version"), 60) or "sin versión registrada",
        _texto(activo.get("zona_es"), 40) or "Red interna",
        _texto(activo.get("usuario"), 120) or "sin usuario registrado",
        int(activo.get("dias_sin_reportar") or 0),
        ultimo if ultimo is not None else NUNCA,
        _fecha(activo.get("visto_at")),
        _fecha(activo.get("ultima_conexion")) or "sin dato",
        int(activo.get("vulnerabilidades") or 0),
        int(activo.get("kev") or 0),
        _texto(activo.get("grupo"), 120) or "sin grupo en OCS Inventory",
        int(activo.get("ocs_id") or 0),
        _revisar_primero(activo, dias_umbral),
    ]
    for columna, valor in enumerate(valores, start=1):
        celda = _celda(hoja, fila, columna, valor)
        formato = COLUMNAS[columna - 1][2]
        if formato and isinstance(valor, (int, float)):
            celda.number_format = formato
        elif formato and isinstance(valor, datetime):
            celda.number_format = formato
        celda.alignment = Alignment(vertical="top", wrap_text=columna == len(COLUMNAS))
        celda.border = _BORDE


def _fila_totales(hoja, fila: int, grupo: dict) -> None:
    """Lo primero que mira quien reparte el trabajo: cuántas son y cuánto arrastran."""
    etiqueta = _celda(hoja, fila, 1, f"Total: {_plural(grupo['sin_reportar'], grupo['origen'])} "
                                    f"sin reportar")
    etiqueta.font = Font(bold=True, size=10)
    nota = _celda(hoja, fila, _COLUMNA_NOTA_TOTAL,
                  "En «Días sin reportar», el máximo de la lista; en las dos columnas de "
                  "vulnerabilidades, la suma.")
    nota.font = Font(italic=True, size=9, color="FF4A5563")
    nota.alignment = Alignment(vertical="center", wrap_text=True)
    for columna, valor in ((_COLUMNA_DIAS, int(grupo.get("dias_maximo") or 0)),
                           (_COLUMNA_VULNERABILIDADES, int(grupo.get("vulnerabilidades") or 0)),
                           (_COLUMNA_KEV, int(grupo.get("kev") or 0))):
        celda = _celda(hoja, fila, columna, valor)
        celda.font = Font(bold=True, size=10)
        celda.number_format = "#,##0"
    for columna in range(1, len(COLUMNAS) + 1):
        hoja.cell(row=fila, column=columna).fill = PatternFill("solid", fgColor=_GRIS)


def _hoja_resumen(libro: Workbook, grupo: dict, datos: dict, *, url_activos: str = "",
                  fecha: Optional[date] = None) -> None:
    """Primera hoja: las cifras en una pantalla y qué hay que hacer con ellas."""
    hoja = libro.create_sheet(HOJA_RESUMEN)
    hoja.column_dimensions["A"].width = 46
    hoja.column_dimensions["B"].width = 74
    origen = grupo["origen"]
    dia = fecha or date.today()

    titulo = _celda(hoja, 1, 1, TITULO.get(origen, "Activos que han dejado de reportar"))
    titulo.font = Font(size=14, bold=True, color=_AZUL)
    subtitulo = _celda(hoja, 2, 1,
                       f"Inventario de OCS Inventory · {notify.fecha_larga(dia)} · "
                       f"Redes")
    subtitulo.font = Font(size=10, color="FF63707E")

    filas: list[tuple[str, Any, Optional[str]]] = [
        ("Cuántos han dejado de reportar",
         f"{_plural(grupo['sin_reportar'], origen)} de {notify.numero(grupo['total'])} "
         f"({notify.decimal(grupo['pct'], 1)} % del total de este tipo)", None),
        ("Desde cuándo se considera que no reportan",
         f"Más de {notify.numero(datos['dias'])} días sin enviar su inventario "
         f"(ajuste «ocs_stale_days» de la plataforma)", None),
        ("Cuántos no han reportado nunca",
         f"{_plural(grupo['nunca'], origen)}", None),
        ("Cuántos días lleva el más antiguo",
         f"{notify.numero(grupo['dias_maximo'])} días", None),
        ("Vulnerabilidades confirmadas que arrastran",
         f"{notify.numero(grupo['vulnerabilidades'])} vulnerabilidades confirmadas, "
         f"{notify.numero(grupo['kev'])} de ellas con explotación activa confirmada", None),
        ("Todo el parque sin reportar",
         f"{notify.numero(datos['total'])} activos de "
         f"{notify.numero(datos['activos_presentes'])} entre servidores y equipos de "
         f"cómputo; este fichero lleva solo los "
         f"{_plural(grupo['sin_reportar'], origen)}", None),
    ]
    fila = 4
    for etiqueta, valor, _formato in filas:
        celda = _celda(hoja, fila, 1, etiqueta)
        celda.font = Font(bold=True, size=10, color="FF4A5563")
        celda.alignment = Alignment(vertical="top", wrap_text=True)
        celda.border = _BORDE
        destino = _celda(hoja, fila, 2, valor)
        destino.alignment = Alignment(vertical="top", wrap_text=True)
        destino.border = _BORDE
        hoja.row_dimensions[fila].height = 30
        fila += 1

    fila += 1
    rotulo = _celda(hoja, fila, 1, "Qué hay que hacer")
    rotulo.font = Font(bold=True, size=11, color="FF1F2933")
    fila += 1
    acciones = (
        "Comprobar si la máquina sigue en uso. Si ya no existe, darla de baja en OCS "
        "Inventory: así deja de contar aquí y de aparecer en los informes.",
        "Si sigue en uso, revisar el agente de OCS Inventory (detenido, desinstalado o "
        "sin alcance al servidor por un cambio de red).",
        "Empezar por las filas de arriba: son las que llevan más tiempo a oscuras y, a "
        "igualdad de días, las que más vulnerabilidades confirmadas arrastran.",
        "Mientras una máquina no reporte, lo que la plataforma sabe de ella es lo último "
        "que recibió: ni sus vulnerabilidades se pueden dar por abiertas ni por cerradas.",
    )
    for indice, accion in enumerate(acciones, start=1):
        celda = _celda(hoja, fila, 1, f"{indice}.")
        celda.font = Font(bold=True, size=10)
        celda.alignment = Alignment(vertical="top")
        destino = _celda(hoja, fila, 2, accion)
        destino.alignment = Alignment(vertical="top", wrap_text=True)
        hoja.row_dimensions[fila].height = 30
        fila += 1

    fila += 1
    nota = _celda(hoja, fila, 1, "Cómo leer la hoja de detalle")
    nota.font = Font(bold=True, size=11, color="FF1F2933")
    fila += 1
    _celda(hoja, fila, 1, "Orden de las filas")
    hoja.cell(row=fila, column=1).font = Font(bold=True, size=10, color="FF4A5563")
    detalle = _celda(hoja, fila, 2,
                     "Primero las que nunca han reportado; después, de más a menos días "
                     "sin reportar y, a igualdad de días, de más a menos vulnerabilidades "
                     "confirmadas.")
    detalle.alignment = Alignment(vertical="top", wrap_text=True)
    hoja.row_dimensions[fila].height = 30
    fila += 1
    _celda(hoja, fila, 1, "Días sin reportar")
    hoja.cell(row=fila, column=1).font = Font(bold=True, size=10, color="FF4A5563")
    detalle = _celda(hoja, fila, 2,
                     "Días transcurridos desde el último inventario recibido. Cuando la "
                     f"máquina no ha reportado nunca («{NUNCA}» en la columna de fecha), "
                     "se cuentan desde que la plataforma la vio por primera vez.")
    detalle.alignment = Alignment(vertical="top", wrap_text=True)
    hoja.row_dimensions[fila].height = 30
    fila += 1

    if url_activos:
        _celda(hoja, fila, 1, "La lista en la plataforma")
        hoja.cell(row=fila, column=1).font = Font(bold=True, size=10, color="FF4A5563")
        enlace = notify.url_segura(url_activos)
        destino = _celda(hoja, fila, 2, enlace)
        if enlace:
            destino.hyperlink = enlace
            destino.font = Font(color=_AZUL, underline="single", size=10)


def _hoja_detalle(libro: Workbook, grupo: dict, datos: dict) -> None:
    hoja = libro.create_sheet(HOJA_DETALLE.get(grupo["origen"], "Sin reportar"))
    _cabecera(hoja, 1)
    for indice, activo in enumerate(grupo["filas"], start=2):
        _fila_detalle(hoja, indice, activo, int(datos.get("dias") or 30))
    ultima = len(grupo["filas"]) + 1
    # Una fila en blanco entre los datos y los totales: quien selecciona la tabla entera y
    # la ordena no se lleva por delante la fila de totales.
    _fila_totales(hoja, ultima + 2, grupo)
    hoja.freeze_panes = "A2"
    if grupo["filas"]:
        hoja.auto_filter.ref = f"A1:{get_column_letter(len(COLUMNAS))}{ultima}"


def generar_grupo(grupo: dict, datos: dict, *, destino: Optional[Path] = None,
                  fecha: Optional[date] = None, url_activos: str = "") -> Optional[Path]:
    """Escribe el fichero de UN tipo de máquina y devuelve su ruta.

    Devuelve ``None`` si ese grupo no tiene ninguna máquina sin reportar: no se genera un
    adjunto vacío, y el correo lo dice con palabras.
    """
    if not grupo.get("filas"):
        log.info("sin fichero: el grupo no tiene activos sin reportar",
                 extra={"origen": grupo.get("origen")})
        return None
    dia = fecha or date.today()
    libro = Workbook()
    libro.remove(libro.active)
    libro.properties.title = (f"{TITULO.get(grupo['origen'], 'Activos sin reportar')} · "
                              f"{notify.fecha_larga(dia)}")
    libro.properties.creator = "Sistema de Inteligencia de Amenazas"
    _hoja_resumen(libro, grupo, datos, url_activos=url_activos, fecha=dia)
    _hoja_detalle(libro, grupo, datos)

    ruta = Path(destino) if destino else DIRECTORIO / nombre_fichero(grupo["origen"], dia)
    ruta.parent.mkdir(parents=True, exist_ok=True)
    if destino is None:
        # El libro lleva el mapa de maquinas a oscuras con sus direcciones: el directorio
        # propio del modulo se cierra a su dueno, igual que el de la alerta diaria. Cuando
        # el llamador indica «destino» no se le tocan los permisos a un directorio ajeno.
        try:
            ruta.parent.chmod(0o700)
        except OSError:
            pass
    libro.save(str(ruta))
    # El fichero lo escribe este modulo, asi que sus permisos si son cosa suya: lleva el
    # nombre, la direccion y las vulnerabilidades de cada maquina a oscuras.
    try:
        ruta.chmod(0o600)
    except OSError:
        pass
    log.info("libro de inventario sin reportar generado", extra={
        "ruta": str(ruta), "origen": grupo["origen"], "filas": len(grupo["filas"]),
        "bytes": ruta.stat().st_size})
    return ruta


def generar(datos: dict, *, directorio: Optional[Path] = None, fecha: Optional[date] = None,
            url_activos: str = "") -> dict[str, Path]:
    """Los dos ficheros, uno por tipo de máquina. Solo los grupos que tienen filas.

    Devuelve ``{"servidores": ruta, "equipos": ruta}`` con las que se hayan escrito.
    """
    dia = fecha or date.today()
    salida: dict[str, Path] = {}
    for grupo in datos.get("grupos") or []:
        destino = (Path(directorio) / nombre_fichero(grupo["origen"], dia)
                   if directorio else None)
        ruta = generar_grupo(grupo, datos, destino=destino, fecha=dia,
                             url_activos=url_activos)
        if ruta is not None:
            salida[grupo["origen"]] = ruta
    return salida


def adjuntos(datos: dict, *, directorio: Optional[Path] = None,
             fecha: Optional[date] = None, url_activos: str = "") -> list[Path]:
    """Las rutas en el orden en que van en el correo: servidores primero."""
    ficheros = generar(datos, directorio=directorio, fecha=fecha, url_activos=url_activos)
    return [ficheros[o] for o in ("servidores", "equipos") if o in ficheros]

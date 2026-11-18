"""Generador del informe mensual en Word.

El informe de agosto de 2026 tenia ~2.039 paginas: detallaba una a una las 2.034
amenazas del mes, de las que 1.684 eran de severidad media. Ademas afirmaba en
sus conclusiones que "se identificaron 2034 vulnerabilidades criticas y altas",
lo que era falso, y estampaba un CVSS inventado en cada ficha.

Estructura nueva, pensada para que la lea la direccion:

  1. Portada con cifras clave
  2. Resumen ejecutivo
  3. Panorama del periodo (con evolucion historica)
  4. Exposicion de la organizacion
  5. Vulnerabilidades prioritarias (fichas de Critical y High)
  6. Anexo: el resto en tabla
  7. Conclusiones y recomendaciones
  8. Nota metodologica

Aqui NO se traduce nada: el texto llega ya traducido de la recoleccion. El
generador anterior aplicaba un segundo diccionario sobre el texto ya traducido y
producia cosas como "cromo" por "chromium".
"""
from __future__ import annotations

import re
import sqlite3
from datetime import datetime
from io import BytesIO
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor


def _decimal_es(valor: Any, cifras: int = 1) -> str:
    """«80,2»: coma decimal y punto de millar, como el resto de la plataforma."""
    try:
        texto = f"{float(valor):,.{max(0, int(cifras))}f}"
    except (TypeError, ValueError):
        return "0,0"
    return texto.replace(",", "\u0000").replace(".", ",").replace("\u0000", ".")


def _hay_clave_nvd(cfg: Any) -> bool:
    """¿Hay una clave de consulta a la base nacional de vulnerabilidades en uso?

    Solo se mira si EXISTE; su valor no sale nunca de aqui. Sirve para no recomendar en el
    informe que se pida una clave cuando ya hay una funcionando (2026-09-15).
    """
    for acceso in ("secrets", "get"):
        try:
            if acceso == "secrets":
                valor = (getattr(cfg, "secrets", None) or {}).get("NIST_NVD_API_KEY")
            else:
                valor = cfg.get("nvd_api_key")
        except Exception:  # noqa: BLE001 - una configuracion de prueba puede no tenerlo
            valor = None
        if valor:
            return True
    return False


def _recortar_palabra(texto: Any, largo: int) -> str:
    """Recorta por palabra y termina en puntos suspensivos si sobraba texto.

    El anexo cortaba con `texto[:72]`, asi que las filas acababan a mitad de palabra y sin
    ninguna senal de que faltara algo (revision de claridad del 2026-09-15).
    """
    limpio = " ".join(str(texto or "").split())
    if len(limpio) <= largo:
        return limpio
    duro = limpio[: largo - 1].rstrip()
    corte = duro.rfind(" ")
    if corte >= (largo - 1) // 2:
        duro = duro[:corte].rstrip(" ,;:.-")
    return duro + "…"


def _numero(valor: Any) -> str:
    """Numero en formato español: 22.807, no 22807 (regla del proyecto).

    El informe se escribia con los numeros crudos de Python. Se aplica a las cifras que
    introdujo el cambio de unidad del 2026-09-09; el resto del documento se deja como
    estaba para no alterar lo que ya se envio a la direccion.
    """
    try:
        return f"{int(valor):,}".replace(",", ".")
    except (TypeError, ValueError):
        return str(valor)

from . import db, queries
from .informe_seleccion import APARTADOS_MENSUAL, numeros_de_apartado
from .logging_setup import get_logger
from .paths import report_file

log = get_logger("report")

AZUL = RGBColor(0x1F, 0x4E, 0x78)
AZUL_CLARO = RGBColor(0x44, 0x72, 0xC4)
GRIS = RGBColor(0x59, 0x59, 0x59)
GRIS_CLARO = RGBColor(0x7F, 0x7F, 0x7F)
NEGRO = RGBColor(0x1F, 0x29, 0x33)

COLOR_SEVERIDAD = {
    "Critical": RGBColor(0xB3, 0x26, 0x1E),
    "High": RGBColor(0xC0, 0x56, 0x21),
    "Medium": RGBColor(0x8A, 0x6D, 0x0B),
    "Low": RGBColor(0x2B, 0x6C, 0xB0),
}

SOMBREADO_SEVERIDAD = {
    "Critical": "FDECEA", "High": "FEF2E7",
    "Medium": "FDF7E3", "Low": "EBF3FB",
}

MESES = ("enero", "febrero", "marzo", "abril", "mayo", "junio", "julio",
         "agosto", "septiembre", "octubre", "noviembre", "diciembre")

ETIQUETA_SEVERIDAD = {"Critical": "Crítica", "High": "Alta",
                      "Medium": "Media", "Low": "Baja"}

ETIQUETA_ORIGEN = {
    "nvd": "CVSS oficial de NVD",
    "vector": "CVSS calculado del vector oficial",
    "kev": "explotación confirmada (CISA KEV)",
    "heuristic": "severidad estimada",
}

ETIQUETA_VEREDICTO = {
    "affected": "versión vulnerable",
    "not_affected": "versión no vulnerable",
    "unknown": "sin determinar",
}

PLAZO = {"Critical": "0-24 horas", "High": "1-7 días",
         "Medium": "7-30 días", "Low": "ventana de mantenimiento"}


# --------------------------------------------------------------------------
# Apartados del documento (2026-09-10)
# --------------------------------------------------------------------------
# El informe a medida (`/informes/`) escribe los mismos apartados que el mensual pero
# solo los que se piden, así que el número de cada uno («1. Resumen ejecutivo») ya no
# puede estar escrito a mano. Cada función de apartado recibe su número, con el HISTÓRICO
# por omisión: sin argumentos nuevos el documento sale letra por letra como siempre, que
# es el que envía la ejecución mensual programada y no se toca.
def _apartados(apartados: Optional[Iterable[str]]) -> tuple[str, ...]:
    """Los apartados del documento; los del informe mensual si no se pide otra cosa."""
    return APARTADOS_MENSUAL if apartados is None else tuple(apartados)


def _incluye(apartados: Optional[Iterable[str]], clave: str) -> bool:
    """¿Lleva el documento ese apartado?"""
    return clave in _apartados(apartados)


def _ref(apartados: Optional[Iterable[str]], clave: str, alternativa: str) -> str:
    """«el apartado 4» cuando ese apartado está en el documento; si no, la alternativa.

    Las referencias cruzadas del informe («Detalle en el apartado 4») no pueden apuntar a
    un apartado que la persona ha desmarcado: en ese caso se dice dónde está el dato de
    verdad, que es la interfaz.
    """
    incluidos = _apartados(apartados)
    if clave not in incluidos:
        return alternativa
    numero = numeros_de_apartado(incluidos).get(clave)
    return f"el apartado {numero}" if numero else alternativa


# --------------------------------------------------------------------------
# Utilidades de formato
# --------------------------------------------------------------------------
def mes_largo(month: str) -> str:
    if not month or "-" not in str(month):
        return str(month or "")
    anio, mes = str(month).split("-")[:2]
    try:
        return f"{MESES[int(mes) - 1]} de {anio}"
    except (ValueError, IndexError):
        return str(month)


def fecha_larga(valor: Any = None) -> str:
    dt = valor if isinstance(valor, datetime) else None
    if dt is None and valor:
        texto = str(valor).strip().replace("Z", "+00:00")
        for intento in (texto, texto[:19], texto[:10]):
            try:
                dt = datetime.fromisoformat(intento)
                break
            except ValueError:
                continue
    dt = dt or datetime.now()
    return f"{dt.day} de {MESES[dt.month - 1]} de {dt.year}"


def cvss_texto(valor: Any) -> str:
    """Nunca inventa un numero. Este era el defecto central del informe viejo."""
    if valor is None or valor == "":
        return "no disponible"
    try:
        return f"{float(valor):.1f}/10.0"
    except (TypeError, ValueError):
        return "no disponible"


def _sombrear(celda, color_hex: str) -> None:
    sombreado = OxmlElement("w:shd")
    sombreado.set(qn("w:val"), "clear")
    sombreado.set(qn("w:color"), "auto")
    sombreado.set(qn("w:fill"), color_hex)
    celda._tc.get_or_add_tcPr().append(sombreado)


def _repetir_cabecera(fila) -> None:
    """Marca la fila como cabecera para que se repita en cada pagina."""
    propiedades = fila._tr.get_or_add_trPr()
    encabezado = OxmlElement("w:tblHeader")
    encabezado.set(qn("w:val"), "true")
    propiedades.append(encabezado)


def _campo(parrafo, instruccion: str) -> None:
    """Inserta un campo de Word (PAGE, NUMPAGES, TOC) via XML."""
    run = parrafo.add_run()
    inicio = OxmlElement("w:fldChar")
    inicio.set(qn("w:fldCharType"), "begin")
    texto = OxmlElement("w:instrText")
    texto.set(qn("xml:space"), "preserve")
    texto.text = instruccion
    separador = OxmlElement("w:fldChar")
    separador.set(qn("w:fldCharType"), "separate")
    fin = OxmlElement("w:fldChar")
    fin.set(qn("w:fldCharType"), "end")
    for elemento in (inicio, texto, separador, fin):
        run._r.append(elemento)


def _barra(valor: int, total: int, ancho: int = 22) -> str:
    """Barra de bloques Unicode: python-docx no dibuja graficos."""
    if not total:
        return ""
    llenos = round(valor * ancho / total)
    return "█" * llenos + "░" * (ancho - llenos)


# --------------------------------------------------------------------------
# Resumen
# --------------------------------------------------------------------------
def construir_resumen(conn: sqlite3.Connection, month: str, *, cfg) -> dict[str, Any]:
    """Cifras del periodo. Lo consume tambien notify.render_monthly_email."""
    excluir_bajas = bool(cfg.get("ignore_low_severity", True))
    stats = queries.estadisticas_mes(conn, month, excluir_bajas=excluir_bajas)
    stats["bajas_ignoradas"] = (conn.execute(
        "SELECT COUNT(*) FROM threats WHERE month=? AND severity='Low'", (month,)).fetchone()[0]
        if excluir_bajas else 0)
    # Con la regla interna activa el informe habla de TRES severidades (criticas, altas y
    # medias) y no pinta filas ni frases de «bajas» a cero (peticion del 2026-09-08).
    stats["excluir_bajas"] = excluir_bajas
    top = queries.top_tecnologias(conn, month, 20, excluir_bajas=excluir_bajas)
    # Un SOLO total para todo el informe (revision de precision del 2026-09-15): la tabla
    # de evolucion se calculaba sin excluir la severidad que no se reporta, asi que el mes
    # en curso aparecia con 1.622 en la columna «Total» mientras la propia fila sumaba
    # 1.532 por severidades y la portada decia 1.532.
    evolucion = queries.evolucion_mensual(conn, 7, excluir_bajas=excluir_bajas)

    veredictos = conn.execute(
        """SELECT tt.version_verdict AS v, COUNT(DISTINCT tt.threat_id) AS n
             FROM threat_technologies tt
             JOIN threats t ON t.id = tt.threat_id
            WHERE t.month = ? GROUP BY tt.version_verdict""", (month,)).fetchall()
    conteo_veredictos = {r["v"]: r["n"] for r in veredictos}

    return {
        **stats,
        "month": month,
        "periodo": mes_largo(month),
        "top_tecnologias": top,
        "evolucion": evolucion,
        "veredictos": conteo_veredictos,
        "confirmadas_afectadas": conteo_veredictos.get("affected", 0),
        "descartadas_version": conteo_veredictos.get("not_affected", 0),
        "sin_determinar": conteo_veredictos.get("unknown", 0),
        "bloques": clasificar_bloques(conn, month, cfg=cfg),
        "precision": precision_filtro(conn, month, bajas_ignoradas=stats["bajas_ignoradas"],
                                     excluir_bajas=excluir_bajas),
        "activos": _resumen_activos(conn, month, cfg=cfg),
    }


def _resumen_activos(conn: sqlite3.Connection, month: str, *, cfg) -> dict[str, Any]:
    """Aplicabilidad por activo (OCS Inventory) del periodo; vacio si no hay activos
    sincronizados o la base es anterior a la v4."""
    try:
        from . import aplicabilidad
        if not conn.execute("SELECT 1 FROM activos WHERE presente=1 LIMIT 1").fetchone():
            return {}
        return aplicabilidad.resumen_informe(conn, month, cfg=cfg, limite=40)
    except sqlite3.OperationalError:
        return {}


# --------------------------------------------------------------------------
# Bloques de lectura y precision del filtro (2026-09-04)
# --------------------------------------------------------------------------
def _tecnologia_principal(amenaza: dict, min_confianza: float,
                          ignorar_baja: bool = False) -> Optional[dict]:
    """Tecnologia de mayor confianza (>= minima); None si solo hay menciones.
    Con ``ignorar_baja`` las de criticidad baja no cuentan."""
    for tec in amenaza.get("technologies") or []:
        if ignorar_baja and str(tec.get("criticality") or "").lower() == "low":
            continue
        conf = tec.get("confidence")
        try:
            conf = 1.0 if conf is None else float(conf)
        except (TypeError, ValueError):
            conf = 1.0
        if conf >= min_confianza:
            return tec
    return None


def bloque_de(amenaza: dict, *, umbral: float, min_confianza: float,
              ignorar_baja: bool = False) -> str:
    """'cerrada' | 'requiere_accion' | 'seguimiento' | 'informativo'.

    Requiere accion: en KEV o relevancia >= umbral (lo alertado con el criterio
    antiguo, por severidad, no cuenta aqui: el bloque describe lo que importa hoy,
    no lo que se envio). Seguimiento:
    correlacionada con el inventario (confianza >= minima) con relevancia >= 25
    o severidad alta/critica. Informativo: el resto. Las descartadas o falsos
    positivos van aparte y no se cuentan como hallazgo vivo.
    """
    if (amenaza.get("estado") or "nueva") in queries.ESTADOS_CERRADOS:
        return "cerrada"
    try:
        relevancia = float(amenaza.get("relevance") or 0)
    except (TypeError, ValueError):
        relevancia = 0.0
    if amenaza.get("in_kev") or relevancia >= umbral:
        return "requiere_accion"
    if _tecnologia_principal(amenaza, min_confianza, ignorar_baja) is not None and (
            relevancia >= 25 or amenaza.get("severity") in ("Critical", "High")):
        return "seguimiento"
    return "informativo"


BLOQUE_ES = {"requiere_accion": "Requiere acción", "seguimiento": "Seguimiento",
             "informativo": "Informativo", "cerrada": "Cerradas por el equipo"}


def clasificar_bloques(conn: sqlite3.Connection, month: str, *, cfg) -> dict[str, Any]:
    """Recuento del periodo por bloque de lectura y ejemplos de cada uno."""
    umbral = float(cfg.get("alert_min_relevance", 50) or 50)
    min_conf = float(cfg.get("alert_min_match_confidence", 0.6) or 0)
    ignorar_baja = bool(cfg.get("ignore_low_criticality", True))
    amenazas = queries.del_mes(conn, month, orden="relevancia",
                               excluir_bajas=bool(cfg.get("ignore_low_severity", True)))
    conteo = {k: 0 for k in BLOQUE_ES}
    for a in amenazas:
        conteo[bloque_de(a, umbral=umbral, min_confianza=min_conf, ignorar_baja=ignorar_baja)] += 1
    total = len(amenazas) or 1
    return {
        "conteo": conteo,
        "porcentaje": {k: round(v * 100.0 / total, 1) for k, v in conteo.items()},
        "umbral": umbral, "min_confianza": min_conf, "total": len(amenazas),
    }


def precision_filtro(conn: sqlite3.Connection, month: str, *,
                     bajas_ignoradas: int = 0,
                     excluir_bajas: bool = False) -> dict[str, Any]:
    """Cuantas amenazas del periodo dejo fuera el filtro de alertas y por que,
    y cuantas cerro el equipo (descartadas / falsos positivos).

    ``excluir_bajas`` hace que este apartado cuente EL MISMO universo que el resto del
    informe: sin el, el total salia 1.622 frente a las 1.532 de la portada y de la tabla
    de severidades, y las tres cifras del mismo mes no cuadraban (revision de precision
    del 2026-09-15). Las de la severidad que no se reporta se devuelven aparte, en
    ``bajas_ignoradas``, para poder decirlo en una frase sin meterlas en la tabla.
    """
    filtro = " AND (severity IS NULL OR severity <> 'Low')" if excluir_bajas else ""
    motivos = {m: 0 for m in queries.MOTIVOS_EXCLUSION}
    for r in conn.execute(
            "SELECT alert_skip_reason AS m, COUNT(*) AS n FROM threats "
            f"WHERE month=? AND alert_skip_reason IS NOT NULL{filtro} GROUP BY 1", (month,)):
        if r["m"] in motivos:
            motivos[r["m"]] = int(r["n"])
    estados = {e: 0 for e in queries.ESTADOS}
    for r in conn.execute(
            f"SELECT estado, COUNT(*) AS n FROM threats WHERE month=?{filtro} GROUP BY 1", (month,)):
        if r["estado"] in estados:
            estados[r["estado"]] = int(r["n"])
    total = conn.execute(
        f"SELECT COUNT(*) FROM threats WHERE month=?{filtro}", (month,)).fetchone()[0] or 0
    alertadas = conn.execute(
        f"SELECT COUNT(*) FROM threats WHERE month=? AND alerted_at IS NOT NULL{filtro}",
        (month,)).fetchone()[0] or 0
    return {"motivos": motivos, "estados": estados, "total": total, "alertadas": alertadas,
            "excluidas": sum(motivos.values()), "bajas_ignoradas": int(bajas_ignoradas or 0),
            "excluye_bajas": bool(excluir_bajas),
            "cerradas": estados.get("descartada", 0) + estados.get("falso_positivo", 0)}


# --------------------------------------------------------------------------
# Documento
# --------------------------------------------------------------------------
def _preparar_documento() -> Document:
    doc = Document()

    normal = doc.styles["Normal"]
    normal.font.name = "Calibri"
    normal.font.size = Pt(10.5)
    normal.paragraph_format.space_after = Pt(6)

    seccion = doc.sections[0]
    seccion.top_margin = Cm(2.2)
    seccion.bottom_margin = Cm(2.0)
    seccion.left_margin = Cm(2.2)
    seccion.right_margin = Cm(2.2)
    return doc


def _insertar_logo(parrafo, logo: Optional[bytes], *, alto_cm: float) -> bool:
    """Inserta ``logo`` (bytes PNG ya normalizados) en ``parrafo``. True si lo insertó.

    Sin logo configurado no hace nada: el documento sale exactamente como antes de que
    existiera esta función, con o sin la fila vacía de más (la llamada decide si la pide).
    """
    if not logo:
        return False
    run = parrafo.add_run()
    run.add_picture(BytesIO(logo), height=Cm(alto_cm))
    return True


def _encabezado_con_logo(doc: Document, logo: Optional[bytes]) -> None:
    """Logo pequeño en la esquina de cada página, a juego con la numeración del pie.

    Sin logo configurado el encabezado queda vacío, como siempre: no se inventa texto
    para no competir con el título de cada apartado.
    """
    if not logo:
        return
    for seccion in doc.sections:
        parrafo = seccion.header.paragraphs[0]
        parrafo.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        _insertar_logo(parrafo, logo, alto_cm=0.9)


def _pie_con_numeracion(doc: Document, month: str) -> None:
    for seccion in doc.sections:
        pie = seccion.footer
        parrafo = pie.paragraphs[0]
        parrafo.alignment = WD_ALIGN_PARAGRAPH.CENTER
        parrafo.text = ""
        run = parrafo.add_run(
            f"Informe de inteligencia de amenazas · {mes_largo(month)} · "
            f"Uso interno · Página ")
        run.font.size = Pt(8)
        run.font.color.rgb = GRIS_CLARO
        _campo(parrafo, "PAGE")
        run2 = parrafo.add_run(" de ")
        run2.font.size = Pt(8)
        run2.font.color.rgb = GRIS_CLARO
        _campo(parrafo, "NUMPAGES")
        for r in parrafo.runs:
            r.font.size = Pt(8)
            r.font.color.rgb = GRIS_CLARO


def _portada(doc: Document, resumen: dict, *, cfg, seleccion: Any = None,
            logo: Optional[bytes] = None) -> None:
    """Portada del documento.

    Sin ``seleccion`` es la de siempre: «INFORME MENSUAL DE INTELIGENCIA DE AMENAZAS» y el
    mes en mayúsculas. Con selección (informe a medida, 2026-09-10) lleva el título que
    haya escrito la persona, el periodo tal como se pidió, a qué parte de la organización
    se refiere, el destinatario y su nota.
    """
    if logo:
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        _insertar_logo(p, logo, alto_cm=2.6)
        doc.add_paragraph()
    else:
        for _ in range(3):
            doc.add_paragraph()

    titulo = doc.add_paragraph()
    titulo.alignment = WD_ALIGN_PARAGRAPH.CENTER
    encabezado = "INFORME MENSUAL\nDE INTELIGENCIA DE AMENAZAS"
    if seleccion is not None and (seleccion.titulo or "").strip():
        encabezado = seleccion.titulo.strip().upper()
    run = titulo.add_run(encabezado)
    run.font.size = Pt(26)
    run.font.bold = True
    run.font.color.rgb = AZUL

    doc.add_paragraph()

    empresa = (cfg.get("empresa_nombre") or "").strip() or "Mi Organización"
    for texto, tamano, color, negrita in (
            (empresa, 16, AZUL_CLARO, True),
            ("Ciberseguridad", 12, GRIS, False)):
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r = p.add_run(texto)
        r.font.size = Pt(tamano)
        r.font.color.rgb = color
        r.font.bold = negrita

    doc.add_paragraph()
    periodo = doc.add_paragraph()
    periodo.alignment = WD_ALIGN_PARAGRAPH.CENTER
    etiqueta = (resumen.get("periodo") or mes_largo(resumen["month"])) if seleccion is not None \
        else mes_largo(resumen["month"])
    r = periodo.add_run(f"PERIODO: {etiqueta.upper()}")
    r.font.size = Pt(15)
    r.font.bold = True
    r.font.color.rgb = NEGRO

    if seleccion is not None:
        for etiqueta_linea, valor in (("Alcance", resumen.get("alcance_es") or ""),
                                      ("Destinatario", seleccion.destinatario or "")):
            if not valor:
                continue
            p = doc.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            r = p.add_run(f"{etiqueta_linea}: {valor}")
            r.font.size = Pt(11)
            r.font.color.rgb = GRIS

    doc.add_paragraph()

    # Cuadro de cifras clave
    tabla = doc.add_table(rows=0, cols=2)
    tabla.style = "Light Grid Accent 1"
    tabla.alignment = WD_TABLE_ALIGNMENT.CENTER

    filas = [
        # Todas las cifras en formato español (2026-09-15).
        ("Vulnerabilidades del periodo", _numero(resumen["total"])),
        ("Severidad crítica",
         f"{_numero(resumen['criticas'])} ({_decimal_es(resumen['pct_criticas'])} %)"),
        ("Severidad alta",
         f"{_numero(resumen['altas'])} ({_decimal_es(resumen['pct_altas'])} %)"),
        ("Con explotación activa confirmada (CISA KEV)", _numero(resumen["en_kev"])),
        # Dos criterios distintos con el mismo nombre (revision de precision 2026-09-15):
        # aqui se cuenta por TECNOLOGIA del inventario (14) y en el apartado de activos por
        # ACTIVO Y PAQUETE (697). Cada uno lleva ahora su nombre completo.
        ("Vulnerabilidades con la versión vulnerable confirmada en el inventario de tecnologías",
         _numero(resumen["confirmadas_afectadas"])),
        ("Con puntuación CVSS oficial (NVD)",
         f"{_numero(resumen['sev_nvd'])} ({_decimal_es(resumen['pct_con_cvss_real'])} %)"),
    ]
    for clave, valor in filas:
        celdas = tabla.add_row().cells
        celdas[0].text = clave
        celdas[1].text = valor
        celdas[0].paragraphs[0].runs[0].font.size = Pt(10)
        p_val = celdas[1].paragraphs[0]
        p_val.runs[0].font.size = Pt(10)
        p_val.runs[0].font.bold = True

    if seleccion is not None and (seleccion.nota or "").strip():
        doc.add_paragraph()
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r = p.add_run(seleccion.nota.strip())
        r.font.size = Pt(10)
        r.font.italic = True
        r.font.color.rgb = NEGRO

    for _ in range(2):
        doc.add_paragraph()

    for texto in (f"Documento generado el {fecha_larga()}",
                  "Clasificación: uso interno",
                  "Sistema Automatizado de Inteligencia de Amenazas"):
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r = p.add_run(texto)
        r.font.size = Pt(9)
        r.font.color.rgb = GRIS_CLARO

    doc.add_page_break()


def _indice(doc: Document) -> None:
    doc.add_heading("Índice", level=1)
    parrafo = doc.add_paragraph()
    _campo(parrafo, r'TOC \o "1-2" \h \z \u')
    nota = doc.add_paragraph()
    r = nota.add_run("Para actualizar el índice en Word: seleccionar todo (Ctrl+E) "
                     "y pulsar F9.")
    r.font.size = Pt(8)
    r.font.italic = True
    r.font.color.rgb = GRIS_CLARO
    doc.add_page_break()


def _resumen_ejecutivo(doc: Document, resumen: dict, *, cfg, conn, numero: int = 1,
                       apartados: Optional[Iterable[str]] = None) -> None:
    doc.add_heading(f"{numero}. Resumen ejecutivo", level=1)

    try:
        from .translate import resumen_ejecutivo as redactar
        texto, motor = redactar(resumen, cfg=cfg, conn=conn)
    except Exception as exc:  # noqa: BLE001 - el informe no debe caerse por esto
        log.warning("no se pudo redactar el resumen ejecutivo",
                    extra={"error": str(exc)})
        texto, motor = "", "plantilla"

    if texto:
        for parrafo in [p.strip() for p in texto.split("\n") if p.strip()]:
            doc.add_paragraph(parrafo)

    total = resumen["total"] or 0
    criticas = resumen["criticas"]
    altas = resumen["altas"]

    bloques = resumen.get("bloques") or {}
    if bloques.get("conteo"):
        doc.add_heading("Cómo leer este informe", level=2)
        conteo = bloques["conteo"]
        # El texto tomaba el total de la portada y los recuentos de otro calculo: si los
        # dos no salen del mismo sitio, el reparto no suma (2026-09-15).
        total = int(bloques.get("total") or total)
        doc.add_paragraph(
            f"De las {_numero(total)} amenazas del periodo, {_numero(conteo['requiere_accion'])} requieren "
            f"acción (alertadas, con explotación activa confirmada o con relevancia igual o "
            f"superior a {int(bloques['umbral'])} para la organización), "
            f"{_numero(conteo['seguimiento'])} quedan en seguimiento (afectan a tecnologías del "
            f"inventario pero con menor relevancia o pendientes de dato oficial), "
            f"{_numero(conteo['informativo'])} son informativas (noticias, campañas o menciones sin "
            f"prueba de exposición) y {_numero(conteo['cerrada'])} fueron descartadas o marcadas como "
            f"falso positivo por el equipo.")
        tabla_b = doc.add_table(rows=1, cols=3)
        tabla_b.style = "Light List Accent 1"
        for i, texto_col in enumerate(("Bloque", "Amenazas", "Porcentaje")):
            tabla_b.rows[0].cells[i].text = texto_col
            tabla_b.rows[0].cells[i].paragraphs[0].runs[0].font.bold = True
            tabla_b.rows[0].cells[i].paragraphs[0].runs[0].font.size = Pt(9)
        for clave in ("requiere_accion", "seguimiento", "informativo", "cerrada"):
            celdas = tabla_b.add_row().cells
            celdas[0].text = BLOQUE_ES[clave]
            celdas[1].text = _numero(conteo.get(clave, 0))
            celdas[2].text = f"{bloques['porcentaje'].get(clave, 0):.1f} %".replace(".", ",")
            for celda in celdas:
                for pp in celda.paragraphs:
                    for rr in pp.runs:
                        rr.font.size = Pt(9.5)
        doc.add_paragraph()

    doc.add_heading("Actuación requerida", level=2)
    tabla = doc.add_table(rows=1, cols=4)
    tabla.style = "Light List Accent 1"
    cabecera = tabla.rows[0].cells
    for i, texto_col in enumerate(("Severidad", "Cantidad", "Plazo", "Estado")):
        cabecera[i].text = texto_col
        cabecera[i].paragraphs[0].runs[0].font.bold = True
        cabecera[i].paragraphs[0].runs[0].font.size = Pt(9)
    _repetir_cabecera(tabla.rows[0])

    for severidad, cantidad in (("Critical", criticas), ("High", altas),
                                ("Medium", resumen["medias"]),
                                ("Low", resumen["bajas"])):
        if not cantidad:
            continue
        celdas = tabla.add_row().cells
        celdas[0].text = ETIQUETA_SEVERIDAD[severidad]
        celdas[1].text = str(cantidad)
        celdas[2].text = PLAZO[severidad]
        con_ficha = (severidad in (cfg.get("report_detail_severities") or [])
                     and _incluye(apartados, "prioritarias"))
        celdas[3].text = (f"Detalladas en {_ref(apartados, 'prioritarias', 'su ficha')}"
                          if con_ficha else
                          "Relación en el anexo A" if _incluye(apartados, "anexo")
                          else "Consulta en la interfaz de la plataforma")
        for celda in celdas:
            for p in celda.paragraphs:
                for r in p.runs:
                    r.font.size = Pt(9.5)
        celdas[0].paragraphs[0].runs[0].font.color.rgb = COLOR_SEVERIDAD[severidad]
        celdas[0].paragraphs[0].runs[0].font.bold = True

    if resumen["en_kev"]:
        p = doc.add_paragraph()
        r = p.add_run(
            f"Atención: {_numero(resumen['en_kev'])} de las amenazas del periodo "
            f"cuentan con explotación activa confirmada en el catálogo KEV de "
            f"CISA y deben tratarse con prioridad absoluta, independientemente "
            f"de su puntuación CVSS.")
        r.font.bold = True
        r.font.color.rgb = COLOR_SEVERIDAD["Critical"]

    act = resumen.get("activos") or {}
    if act.get("total"):
        p = doc.add_paragraph()
        # Total real, no el recorte de la tabla del apartado 4 (2026-09-09).
        n_act = int(act.get("activos_afectados") or len(act.get("afectados") or []))
        r = p.add_run(
            f"Inventario real: {n_act} activo{'s' if n_act != 1 else ''} de {act['total']} "
            f"{'tienen' if n_act != 1 else 'tiene'} instalada la versión vulnerable de alguna amenaza del periodo "
            f"según OCS Inventory; {act.get('fuera_soporte', 0)} está{'n' if act.get('fuera_soporte', 0) != 1 else ''} "
            f"fuera de soporte y {act.get('sin_reportar', 0)} sin reportar. Detalle en "
            f"{_ref(apartados, 'activos', 'la página de Activos de la interfaz')}.")
        r.font.size = Pt(10)

    if motor == "plantilla":
        log.info("resumen ejecutivo generado con plantilla deterministica")


def _panorama(doc: Document, resumen: dict, *, numero: int = 2) -> None:
    doc.add_heading(f"{numero}. Panorama del periodo", level=1)

    total = resumen["total"] or 0
    doc.add_heading(f"{numero}.1 Distribución por severidad", level=2)

    if total:
        tabla = doc.add_table(rows=1, cols=4)
        tabla.style = "Light Grid Accent 1"
        cab = tabla.rows[0].cells
        for i, t in enumerate(("Severidad", "Cantidad", "Porcentaje", "Distribución")):
            cab[i].text = t
            cab[i].paragraphs[0].runs[0].font.bold = True
            cab[i].paragraphs[0].runs[0].font.size = Pt(9)
        _repetir_cabecera(tabla.rows[0])

        pedidas = resumen.get("severidades")   # None en el informe mensual: las cuatro
        for severidad, clave in (("Critical", "criticas"), ("High", "altas"),
                                 ("Medium", "medias"), ("Low", "bajas")):
            if severidad == "Low" and resumen.get("excluir_bajas"):
                continue
            # En un informe a medida solo se pintan las severidades que se pidieron: una
            # fila «Media: 0 (0,0 %)» en un informe de explotación activa no informa de
            # nada y hace dudar de las cifras de al lado (2026-09-10).
            if pedidas is not None and severidad not in pedidas:
                continue
            cantidad = resumen[clave]
            celdas = tabla.add_row().cells
            celdas[0].text = ETIQUETA_SEVERIDAD[severidad]
            celdas[1].text = _numero(cantidad)
            celdas[2].text = f"{_decimal_es(cantidad * 100.0 / total)} %"
            celdas[3].text = _barra(cantidad, total)
            celdas[0].paragraphs[0].runs[0].font.color.rgb = COLOR_SEVERIDAD[severidad]
            celdas[0].paragraphs[0].runs[0].font.bold = True
            celdas[3].paragraphs[0].runs[0].font.name = "Consolas"
            _sombrear(celdas[0], SOMBREADO_SEVERIDAD[severidad])
            for celda in celdas:
                for p in celda.paragraphs:
                    for r in p.runs:
                        r.font.size = Pt(9.5)
    else:
        doc.add_paragraph("No se registraron vulnerabilidades en el periodo.")

    doc.add_heading(f"{numero}.2 Procedencia del dato de severidad", level=2)
    doc.add_paragraph(
        f"De los {_numero(total)} registros del periodo, {_numero(resumen['sev_nvd'])} "
        f"({_decimal_es(resumen['pct_con_cvss_real'])} %) cuentan con puntuación CVSS oficial "
        f"publicada por el NVD. Los {_numero(resumen['sev_heuristica'])} restantes se "
        f"clasificaron mediante estimación a partir de indicios textuales, y en su "
        f"ficha figura «no disponible» en el campo de puntuación. Esta distinción "
        f"se mantiene de forma explícita en todo el informe: una severidad estimada "
        f"no es una puntuación CVSS oficial.")

    evolucion = resumen.get("evolucion") or []
    if len(evolucion) > 1:
        doc.add_heading(f"{numero}.3 Evolución respecto a periodos anteriores", level=2)
        tabla = doc.add_table(rows=1, cols=6)
        tabla.style = "Light Grid Accent 1"
        cab = tabla.rows[0].cells
        for i, t in enumerate(("Periodo", "Total", "Críticas", "Altas", "Medias",
                               "KEV")):
            cab[i].text = t
            cab[i].paragraphs[0].runs[0].font.bold = True
            cab[i].paragraphs[0].runs[0].font.size = Pt(9)
        _repetir_cabecera(tabla.rows[0])

        for fila in evolucion:
            celdas = tabla.add_row().cells
            valores = (mes_largo(fila["month"]), fila["total"], fila["criticas"],
                       fila["altas"], fila["medias"], fila["en_kev"])
            for i, valor in enumerate(valores):
                celdas[i].text = str(valor)
                celdas[i].paragraphs[0].runs[0].font.size = Pt(9)
            if fila["month"] == resumen["month"]:
                for celda in celdas:
                    _sombrear(celda, "EBF3FB")
                    celda.paragraphs[0].runs[0].font.bold = True


def _exposicion(doc: Document, resumen: dict, *, numero: int = 3) -> None:
    doc.add_heading(f"{numero}. Exposición de la organización", level=1)

    top = resumen.get("top_tecnologias") or []
    if not top:
        doc.add_paragraph(
            "No se establecieron correlaciones con el inventario tecnológico "
            "durante el periodo.")
        return

    doc.add_paragraph(
        "La tabla recoge las tecnologías del inventario afectadas por las "
        "vulnerabilidades del periodo. La columna «Versión» indica la versión "
        "registrada en el inventario; cuando está vacía, el sistema no puede "
        "determinar si el aviso aplica y clasifica el hallazgo como «sin "
        "determinar» por prudencia.")

    tabla = doc.add_table(rows=1, cols=7)
    tabla.style = "Light Grid Accent 1"
    cab = tabla.rows[0].cells
    for i, t in enumerate(("Tecnología", "Versión", "Crit.", "Expos.", "Sist.",
                           "Total", "Confirm.")):
        cab[i].text = t
        cab[i].paragraphs[0].runs[0].font.bold = True
        cab[i].paragraphs[0].runs[0].font.size = Pt(8.5)
    _repetir_cabecera(tabla.rows[0])

    for tec in top[:20]:
        celdas = tabla.add_row().cells
        valores = (
            tec["name"],
            tec.get("version_installed") or "—",
            (tec.get("criticality") or "")[:4],
            (tec.get("exposure") or "")[:8],
            str(tec.get("systems_count") or "—"),
            str(tec.get("amenazas") or 0),
            str(tec.get("confirmadas") or 0),
        )
        for i, valor in enumerate(valores):
            celdas[i].text = str(valor)
            celdas[i].paragraphs[0].runs[0].font.size = Pt(8.5)
        if tec.get("confirmadas"):
            celdas[6].paragraphs[0].runs[0].font.bold = True
            celdas[6].paragraphs[0].runs[0].font.color.rgb = COLOR_SEVERIDAD["Critical"]
        if tec.get("exposure") == "internet":
            _sombrear(celdas[3], "FEF2E7")

    doc.add_heading(f"{numero}.1 Aplicabilidad por versión", level=2)
    tabla = doc.add_table(rows=1, cols=3)
    tabla.style = "Light List Accent 1"
    cab = tabla.rows[0].cells
    for i, t in enumerate(("Situación", "Amenazas", "Interpretación")):
        cab[i].text = t
        cab[i].paragraphs[0].runs[0].font.bold = True
        cab[i].paragraphs[0].runs[0].font.size = Pt(9)
    _repetir_cabecera(tabla.rows[0])

    for etiqueta, clave, interpretacion in (
            ("Versión vulnerable", "confirmadas_afectadas",
             "El aviso aplica: requiere actuación"),
            ("Versión no vulnerable", "descartadas_version",
             "Descartado automáticamente: no requiere actuación"),
            ("Sin determinar", "sin_determinar",
             "Falta la versión en el inventario o el aviso no la especifica")):
        celdas = tabla.add_row().cells
        celdas[0].text = etiqueta
        celdas[1].text = str(resumen.get(clave, 0))
        celdas[2].text = interpretacion
        for celda in celdas:
            for p in celda.paragraphs:
                for r in p.runs:
                    r.font.size = Pt(9)

    if resumen.get("sin_determinar", 0) > resumen.get("confirmadas_afectadas", 0):
        p = doc.add_paragraph()
        r = p.add_run(
            "Nota: la mayoría de los hallazgos están «sin determinar» porque el "
            "inventario no tiene registradas las versiones instaladas. "
            "Completarlas permitiría descartar automáticamente los avisos que no "
            "aplican y reducir de forma notable el volumen a revisar.")
        r.font.italic = True
        r.font.size = Pt(9)
        r.font.color.rgb = GRIS


def _ficha(doc: Document, indice: str, amenaza: dict) -> None:
    """Ficha compacta: media pagina, no tres como en el informe anterior."""
    severidad = amenaza.get("severity") or "Medium"
    color = COLOR_SEVERIDAD.get(severidad, GRIS)

    titulo = amenaza.get("title_es") or amenaza.get("title_en") or "Sin título"
    encabezado = doc.add_heading(level=2)
    run = encabezado.add_run(f"{indice}  {amenaza.get('cve') or 'Sin CVE'} — "
                             f"{titulo[:90]}")
    run.font.color.rgb = color
    run.font.size = Pt(12)

    # Bloque de datos en tabla de dos columnas
    tabla = doc.add_table(rows=0, cols=2)
    tabla.style = "Light List"

    origen = ETIQUETA_ORIGEN.get(amenaza.get("severity_source"), "origen no determinado")
    datos: list[tuple[str, str]] = [
        ("Severidad", f"{ETIQUETA_SEVERIDAD.get(severidad, severidad)} "
                      f"({origen})"),
        ("Puntuación CVSS", cvss_texto(amenaza.get("cvss_score"))),
    ]
    estado = amenaza.get("estado") or "nueva"
    if estado != "nueva":
        quien = amenaza.get("estado_por")
        datos.append(("Estado", queries.ESTADO_ES.get(estado, estado)
                      + (f" ({quien})" if quien else "")))
    if amenaza.get("epss_score") is not None:
        datos.append(("Probabilidad EPSS",
                      f"{_decimal_es(amenaza['epss_score'] * 100)} % en 30 días"))
    if amenaza.get("in_kev"):
        plazo = amenaza.get("kev_due_date")
        datos.append(("Explotación activa",
                      "Confirmada en el catálogo CISA KEV"
                      + (f" · plazo {fecha_larga(plazo)}" if plazo else "")))
    if amenaza.get("published_at"):
        datos.append(("Publicación", fecha_larga(amenaza["published_at"])))

    tecnologias = amenaza.get("technologies") or []
    if tecnologias:
        piezas = []
        for t in tecnologias[:6]:
            pieza = t["name"]
            if t.get("version_installed"):
                pieza += f" {t['version_installed']}"
            pieza += f" ({ETIQUETA_VEREDICTO.get(t.get('version_verdict'), 'sin determinar')})"
            piezas.append(pieza)
        if len(tecnologias) > 6:
            piezas.append(f"y {len(tecnologias) - 6} más")
        datos.append(("Tecnologías afectadas", "; ".join(piezas)))

    activos = amenaza.get("activos") or {}
    if activos.get("evaluada"):
        n = int(activos.get("n_afectados") or 0)
        if n:
            nombres = [x["nombre"] + (f" ({x['ip']})" if x.get("ip") else "") for x in activos.get("afectados") or []][:8]
            texto = (f"{n} activo{'s' if n != 1 else ''} con la versión vulnerable instalada según OCS Inventory: "
                     + "; ".join(nombres))
            if n > len(nombres):
                texto += f"; y {n - len(nombres)} más"
            # Desde el 2026-09-06 la pareja de versiones vive en «paquetes_detalle» (una por
            # paquete); el campo del activo solo se rellena cuando todos coinciden. Y desde
            # el 2026-09-09 se escribe la ULTIMA version pedida por el paquete
            # («version_ultima»), no la de este aviso: en produccion el informe decia
            # «actualizar a 6.12.85-1» cuando solo 6.12.105-1 resuelve las nueve versiones
            # pedidas del mismo paquete (peticion del usuario).
            corregidas: set = set()
            acumulan = False
            for x in activos.get("afectados") or []:
                for d in (x.get("paquetes_detalle") or [x]):
                    ultima = d.get("version_ultima")
                    version = ultima or d.get("version_corregida") or d.get("corregida")
                    if version:
                        corregidas.add(version)
                    if d.get("version_ultima_distinta"):
                        acumulan = True
            if corregidas:
                texto += f". Versión a la que hay que actualizar: {', '.join(sorted(corregidas)[:3])}"
                if acumulan:
                    texto += (" (es la última pedida: el mismo paquete acumula varias versiones "
                              "y solo la última las resuelve todas)")
        else:
            texto = "Ningún activo tiene la versión vulnerable instalada"
            if activos.get("n_no_afectados"):
                texto += f" ({activos['n_no_afectados']} ya corregidos)"
            if activos.get("n_sin_dato"):
                texto += f"; {activos['n_sin_dato']} sin dato"
        datos.append(("Activos afectados", texto))

    datos.append(("Prioridad organizativa",
                  f"{amenaza.get('relevance', 0):.0f}/100 · plazo "
                  f"{PLAZO.get(severidad, '—')}"))

    for clave, valor in datos:
        celdas = tabla.add_row().cells
        celdas[0].text = clave
        celdas[1].text = str(valor)
        celdas[0].width = Cm(4.2)
        celdas[0].paragraphs[0].runs[0].font.bold = True
        for celda in celdas:
            for p in celda.paragraphs:
                for r in p.runs:
                    r.font.size = Pt(9)

    descripcion = amenaza.get("summary_es") or amenaza.get("summary_en")
    if descripcion:
        p = doc.add_paragraph()
        r = p.add_run("Descripción. ")
        r.font.bold = True
        r.font.size = Pt(9.5)
        marca = "" if amenaza.get("summary_es") else " [texto original en inglés] "
        r2 = p.add_run(marca + str(descripcion)[:900])
        r2.font.size = Pt(9.5)

    if amenaza.get("impact_es"):
        p = doc.add_paragraph()
        r = p.add_run("Impacto. ")
        r.font.bold = True
        r.font.size = Pt(9.5)
        r2 = p.add_run(str(amenaza["impact_es"])[:800])
        r2.font.size = Pt(9.5)

    if amenaza.get("remediation_es"):
        p = doc.add_paragraph()
        r = p.add_run("Remediación recomendada.")
        r.font.bold = True
        r.font.size = Pt(9.5)
        for linea in str(amenaza["remediation_es"]).splitlines():
            if not linea.strip():
                continue
            pl = doc.add_paragraph(linea.strip())
            pl.paragraph_format.left_indent = Cm(0.6)
            pl.paragraph_format.space_after = Pt(1)
            for r in pl.runs:
                r.font.size = Pt(9)

    fuentes = [s for s in (amenaza.get("sources") or []) if s.get("url")]
    if fuentes:
        p = doc.add_paragraph()
        r = p.add_run("Referencias: ")
        r.font.bold = True
        r.font.size = Pt(8.5)
        r2 = p.add_run(" · ".join(s["url"] for s in fuentes[:3]))
        r2.font.size = Pt(8)
        r2.font.color.rgb = GRIS


def _activos(doc: Document, resumen: dict, *, numero: int = 4) -> None:
    """Activos de la organizacion: aplicabilidad real por activo (OCS Inventory),
    fin de soporte y cobertura del inventario. Solo si hay activos sincronizados."""
    act = resumen.get("activos") or {}
    doc.add_heading(f"{numero}. Activos de la organización", level=1)
    if not act.get("total"):
        doc.add_paragraph(
            "No hay activos sincronizados desde OCS Inventory en este periodo. Cuando la "
            "sincronización esté activa, este apartado detalla qué activos tienen instalada la "
            "versión vulnerable de cada CVE, cuáles quedan fuera de soporte y qué parte del "
            "software está clasificada.")
        return

    # Totales sin el recorte de la tabla (2026-09-09): «activos_afectados» y
    # «vulnerabilidades» los calcula ``aplicabilidad.resumen_informe`` sobre todo el parque;
    # ``len(act['afectados'])`` es solo lo que cabe en la tabla. Un informe antiguo
    # guardado sin esas claves cae a la cifra de la tabla.
    n_activos = int(act.get("activos_afectados") or len(act["afectados"]))
    n_vulns = act.get("vulnerabilidades")
    p = doc.add_paragraph(
        f"El inventario real cuenta con {_numero(act['total'])} activos presentes "
        f"({_numero(act['servidores'])} servidores y {_numero(act['equipos'])} equipos de cómputo). "
        f"De las {_numero(act['amenazas_evaluadas'])} amenazas del periodo evaluadas paquete a paquete, "
        f"{_numero(act['amenazas_con_activos'])} tienen al menos un activo con la versión "
        f"vulnerable instalada. Es el recuento POR ACTIVO Y PAQUETE, y por eso es mayor que "
        f"el de la portada, que cuenta por tecnología del inventario. "
        f"En total {_numero(n_activos)} activo{'s' if n_activos != 1 else ''} "
        f"{'aparecen' if n_activos != 1 else 'aparece'} afectado{'s' if n_activos != 1 else ''}"
        + (f", con {_numero(n_vulns)} vulnerabilidad{'es' if n_vulns != 1 else ''} "
           f"confirmada{'s' if n_vulns != 1 else ''}" if n_vulns is not None else "")
        + f", y {_numero(act['corregidas'])} vulnerabilidades ya llevan la corrección instalada.")
    p.paragraph_format.space_after = Pt(4)
    if n_vulns is not None:
        nota = doc.add_paragraph()
        r = nota.add_run("Una vulnerabilidad es un CVE en un activo; si afecta a varios paquetes de la "
                         "misma máquina cuenta una sola vez. Los paquetes son la trazabilidad de qué "
                         "actualizar, no la unidad de conteo.")
        r.font.size = Pt(8.5)
        r.font.color.rgb = GRIS
        nota.paragraph_format.space_after = Pt(8)

    doc.add_heading(f"{numero}.1 Activos con vulnerabilidades confirmadas "
                    f"(recuento por activo y paquete)", level=2)
    if act["afectados"]:
        tabla = doc.add_table(rows=1, cols=5)
        tabla.style = "Light List Accent 1"
        for i, texto in enumerate(("Activo", "Tipo", "Sistema", "CVE", "En KEV")):
            celda = tabla.rows[0].cells[i]
            celda.text = texto
            celda.paragraphs[0].runs[0].font.bold = True
            celda.paragraphs[0].runs[0].font.size = Pt(9)
        _repetir_cabecera(tabla.rows[0])
        for a in act["afectados"]:
            celdas = tabla.add_row().cells
            celdas[0].text = a["nombre"] + (f"\n{a['ip']}" if a.get("ip") else "")
            celdas[1].text = "Servidor" if a["origen"] == "servidores" else "Equipo de cómputo"
            celdas[2].text = f"{a.get('so_nombre') or '—'} {a.get('so_version') or ''}".strip()
            celdas[3].text = str(a["cves"])
            celdas[4].text = str(a["kev"]) if a["kev"] else "—"
            for celda in celdas:
                for pp in celda.paragraphs:
                    for r in pp.runs:
                        r.font.size = Pt(9)
            if a["kev"]:
                celdas[4].paragraphs[0].runs[0].font.color.rgb = COLOR_SEVERIDAD["Critical"]
                celdas[4].paragraphs[0].runs[0].font.bold = True
        nota = doc.add_paragraph()
        r = nota.add_run("«CVE» cuenta las vulnerabilidades del periodo cuya versión instalada en el activo "
                         "es anterior a la corregida (OSV.dev para Debian y Ubuntu, VuXML para FreeBSD, "
                         "comparación con el aviso para el resto). El detalle por paquete y la evidencia están "
                         "en la ficha de cada activo de la interfaz.")
        r.font.size = Pt(8.5)
        r.font.color.rgb = GRIS
    else:
        doc.add_paragraph("Ningún activo tiene instalada la versión vulnerable de las amenazas del periodo.")

    doc.add_heading(f"{numero}.2 Fin de soporte", level=2)
    fuera = act.get("fuera_soporte_sistemas") or []
    proximos = act.get("proximos_fin_soporte") or []
    if fuera or proximos:
        tabla = doc.add_table(rows=1, cols=4)
        tabla.style = "Light List Accent 1"
        for i, texto in enumerate(("Sistema", "Activos", "Fin de soporte", "Situación")):
            celda = tabla.rows[0].cells[i]
            celda.text = texto
            celda.paragraphs[0].runs[0].font.bold = True
            celda.paragraphs[0].runs[0].font.size = Pt(9)
        _repetir_cabecera(tabla.rows[0])
        for s_ in fuera:
            celdas = tabla.add_row().cells
            celdas[0].text = s_["sistema"]
            celdas[1].text = str(s_["activos"])
            celdas[2].text = fecha_larga(s_["eol"]) if s_.get("eol") else "—"
            celdas[3].text = f"Sin soporte desde hace {abs(int(s_['dias'] or 0))} días"
            celdas[3].paragraphs[0].runs[0].font.color.rgb = COLOR_SEVERIDAD["Critical"]
            for celda in celdas:
                for pp in celda.paragraphs:
                    for r in pp.runs:
                        r.font.size = Pt(9)
        for s_ in proximos:
            celdas = tabla.add_row().cells
            celdas[0].text = s_["sistema"]
            celdas[1].text = str(s_["activos"])
            celdas[2].text = fecha_larga(s_["eol"]) if s_.get("eol") else "—"
            celdas[3].text = f"Quedan {int(s_['dias'] or 0)} días"
            for celda in celdas:
                for pp in celda.paragraphs:
                    for r in pp.runs:
                        r.font.size = Pt(9)
        doc.add_paragraph(
            "Un sistema fuera de soporte no recibe correcciones de seguridad: toda vulnerabilidad nueva "
            "queda abierta aunque no figure en la lista de amenazas. Planificar la migración es la única "
            "medida efectiva.").runs[0].font.size = Pt(9.5)
    else:
        doc.add_paragraph("Todos los sistemas con ciclo conocido están dentro de su periodo de soporte.")

    doc.add_heading(f"{numero}.3 Cobertura del inventario real", level=2)
    hall = {h["tipo"]: h["activos"] for h in act.get("hallazgos_por_tipo") or []}
    # Concordancia y coherencia (2026-09-15): se leia «1 nombres sin clasificar» junto a
    # «100.0 % están clasificadas», que ademas era un redondeo de 99,99 %.
    sin_clasificar = int(act.get("sin_clasificar") or 0)
    pct = float(act.get("pct_mapeado") or 0)
    if sin_clasificar and pct >= 99.95:
        pct_texto = "Prácticamente el 100"
    else:
        pct_texto = _decimal_es(pct)
    frases = [
        f"{pct_texto} % de las {_numero(act['instalaciones'])} instalaciones de software "
        f"están clasificadas en una tecnología del inventario"
        + (f"; queda{'n' if sin_clasificar != 1 else ''} {_numero(sin_clasificar)} "
           f"nombre{'s' if sin_clasificar != 1 else ''} sin clasificar."
           if sin_clasificar else ", sin ningún nombre pendiente de clasificar."),
        f"{_numero(act['sin_reportar'])} activo{'s' if act['sin_reportar'] != 1 else ''} "
        f"lleva{'n' if act['sin_reportar'] != 1 else ''} más de "
        f"{_numero(act.get('dias_sin_reportar') or 30)} días sin enviar inventario: su "
        f"estado real es desconocido.",
    ]
    if hall.get("software_riesgo"):
        n_r = int(hall["software_riesgo"])
        frases.append(f"{_numero(n_r)} activo{'s' if n_r != 1 else ''} con software "
                      f"de riesgo (acceso remoto no gestionado, Java antiguo).")
    if hall.get("sin_edr"):
        n_e = int(hall["sin_edr"])
        frases.append(f"{_numero(n_e)} equipo{'s' if n_e != 1 else ''} de cómputo sin el "
                      f"agente de protección esperado.")
    for frase in frases:
        pf = doc.add_paragraph(frase, style="List Bullet")
        for r in pf.runs:
            r.font.size = Pt(9.5)


def _prioritarias(doc: Document, doc_amenazas: list[dict], *, cfg,
                  total_periodo: int, numero: int = 5,
                  apartados: Optional[Iterable[str]] = None) -> None:
    detalle = cfg.get("report_detail_severities") or ["Critical", "High"]
    doc.add_heading(f"{numero}. Vulnerabilidades prioritarias", level=1)

    etiquetas = ", ".join(ETIQUETA_SEVERIDAD.get(s, s).lower() for s in detalle)
    doc.add_paragraph(
        f"Este apartado detalla las vulnerabilidades que requieren acción: las que "
        f"cuentan con explotación activa confirmada (CISA KEV) o cuya relevancia para la "
        f"organización alcanza el umbral de alerta, de severidad {etiquetas}. Van "
        f"agrupadas por la tecnología del inventario a la que afectan, de mayor a menor "
        f"exposición, y dentro de cada grupo por relevancia. El resto de hallazgos del "
        f"periodo figura {'en el anexo A' if _incluye(apartados, 'anexo') else 'en la interfaz de consulta'}.")

    if not doc_amenazas:
        doc.add_paragraph(
            "No se registraron vulnerabilidades de estas severidades en el periodo.")
        return

    maximo = int(cfg.get("report_max_detail_items", 120) or 120)
    mostradas = doc_amenazas[:maximo]

    if len(doc_amenazas) > maximo:
        p = doc.add_paragraph()
        r = p.add_run(
            f"Se detallan las {maximo} de mayor prioridad de un total de "
            f"{len(doc_amenazas)}. Las restantes figuran "
            f"{'en el anexo A' if _incluye(apartados, 'anexo') else 'en la interfaz de consulta'}.")
        r.font.italic = True
        r.font.size = Pt(9)
        r.font.color.rgb = GRIS

    grupo_actual = None
    for i, amenaza in enumerate(mostradas, 1):
        grupo = amenaza.get("_grupo_tecnologia")
        if grupo and grupo != grupo_actual:
            grupo_actual = grupo
            n_grupo = sum(1 for a in mostradas if a.get("_grupo_tecnologia") == grupo)
            p = doc.add_paragraph()
            r = p.add_run(f"{grupo} · {n_grupo} vulnerabilidad{'es' if n_grupo != 1 else ''}")
            r.font.bold = True
            r.font.size = Pt(11)
            r.font.color.rgb = AZUL
        _ficha(doc, f"5.{i}", amenaza)


def _anexo(doc: Document, amenazas: list[dict], *, titulo: str,
           maximo: int = 250) -> None:
    doc.add_page_break()
    doc.add_heading(titulo, level=1)

    if not amenazas:
        doc.add_paragraph("Sin registros en esta categoría.")
        return

    mostradas = amenazas[:maximo]
    omitidas = len(amenazas) - len(mostradas)

    doc.add_paragraph(
        f"Relación de los hallazgos restantes del periodo, ordenados por "
        f"prioridad organizativa. Se presentan en tabla por volumen; el detalle "
        f"individual y la relación completa están disponibles en la interfaz de "
        f"consulta, con exportación a CSV.")

    if omitidas:
        p = doc.add_paragraph()
        r = p.add_run(
            f"Se listan {'los' if len(mostradas) != 1 else 'el'} {_numero(len(mostradas))} de "
            f"mayor prioridad de un total de {_numero(len(amenazas))}. "
            f"{'Los' if omitidas != 1 else 'El'} {_numero(omitidas)} "
            f"{'restantes se consultan' if omitidas != 1 else 'restante se consulta'} en la "
            f"interfaz para no extender el documento sin aportar valor de decisión.")
        r.font.italic = True
        r.font.size = Pt(9)
        r.font.color.rgb = GRIS

    amenazas = mostradas

    tabla = doc.add_table(rows=1, cols=5)
    tabla.style = "Light Grid Accent 1"
    cab = tabla.rows[0].cells
    for i, t in enumerate(("CVE", "Vulnerabilidad", "Sev.", "CVSS",
                           "Tecnologías")):
        cab[i].text = t
        cab[i].paragraphs[0].runs[0].font.bold = True
        cab[i].paragraphs[0].runs[0].font.size = Pt(8)
    _repetir_cabecera(tabla.rows[0])

    for amenaza in amenazas:
        celdas = tabla.add_row().cells
        # Corte por palabra y con puntos suspensivos (2026-09-15).
        titulo_a = _recortar_palabra(amenaza.get("title_es") or amenaza.get("title_en") or "", 72)
        tecnologias = ", ".join(
            t["name"] for t in (amenaza.get("technologies") or [])[:3]) or "—"
        severidad = amenaza.get("severity") or ""

        valores = (
            amenaza.get("cve") or "—",
            titulo_a,
            ETIQUETA_SEVERIDAD.get(severidad, severidad),
            "—" if amenaza.get("cvss_score") is None
            else f"{amenaza['cvss_score']:.1f}",
            _recortar_palabra(tecnologias, 44),
        )
        for i, valor in enumerate(valores):
            celdas[i].text = str(valor)
            celdas[i].paragraphs[0].runs[0].font.size = Pt(7.5)
        if severidad in COLOR_SEVERIDAD:
            celdas[2].paragraphs[0].runs[0].font.color.rgb = COLOR_SEVERIDAD[severidad]
        if amenaza.get("in_kev"):
            _sombrear(celdas[0], "FDECEA")


def _conclusiones(doc: Document, resumen: dict, *, cfg, numero: int = 6) -> None:
    doc.add_page_break()
    doc.add_heading(f"{numero}. Conclusiones y recomendaciones", level=1)

    total = resumen["total"]
    criticas = resumen["criticas"]
    altas = resumen["altas"]
    medias = resumen["medias"]
    bajas = resumen["bajas"]

    doc.add_heading(f"{numero}.1 Análisis del periodo", level=2)
    # Afirmacion COHERENTE con los datos. El informe anterior decia
    # "se identificaron N vulnerabilidades criticas y altas" usando el total.
    # Estas cifras son AMENAZAS del periodo (avisos del catalogo), no vulnerabilidades:
    # una vulnerabilidad es un CVE en un activo (apartado 4). Llamar «vulnerabilidades» a
    # las dos cosas en el mismo informe dejaba dos numeros distintos de lo mismo, 1.134 y
    # 22.807 (revision de precision del 2026-09-09).
    pedidas = resumen.get("severidades")   # None en el informe mensual: las de siempre
    if pedidas is not None:
        # Informe a medida: se nombran solo las severidades pedidas, para no dejar en el
        # texto un «0 media» de una severidad que el informe ni siquiera cubre.
        nombres = {"Critical": ("crítica", criticas), "High": ("alta", altas),
                   "Medium": ("media", medias)}
        trozos = [f"{_numero(n)} de severidad {etiqueta}"
                  for clave_sev, (etiqueta, n) in nombres.items() if clave_sev in pedidas]
        reparto = (", ".join(trozos[:-1]) + " y " + trozos[-1] if len(trozos) > 1
                   else (trozos[0] if trozos else "sin reparto por severidad"))
        # Sin nombrar la severidad que no se reporta (orden del usuario del 2026-09-10):
        # el informe dice cuáles reporta, no cuál deja fuera.
        reparto += " (son las severidades que se reportan)"
    else:
        reparto = (f"{_numero(criticas)} de severidad crítica, {_numero(altas)} alta y "
                   f"{_numero(medias)} media (son las tres severidades que se reportan)"
                   if resumen.get("excluir_bajas") else
                   f"{_numero(criticas)} de severidad crítica, {_numero(altas)} alta, "
                   f"{_numero(medias)} media y {_numero(bajas)} baja")
    periodo_es = resumen.get("periodo") or mes_largo(resumen["month"])
    # Concordancia con cifras de uno (2026-09-15): se leia «1 amenazas».
    graves = criticas + altas
    doc.add_paragraph(
        f"Durante {periodo_es} se "
        f"{'registraron' if total != 1 else 'registró'} {_numero(total)} "
        f"amenaza{'s' if total != 1 else ''} relacionada{'s' if total != 1 else ''} con el "
        f"inventario tecnológico: {reparto}. "
        f"{'Las de severidad crítica y alta suman' if graves != 1 else 'Una de ellas es de severidad crítica o alta:'} "
        f"{_numero(graves)} amenaza{'s' if graves != 1 else ''}, "
        f"equivalente{'s' if graves != 1 else ''} al "
        f"{_decimal_es(graves * 100.0 / total)} % del total."
        if total else
        f"Durante {periodo_es} no se registraron "
        f"amenazas relacionadas con el inventario tecnológico.")

    # Concordancia de singular y plural en todas las frases con cifra (2026-09-15): antes
    # se leia «1 de ellas tienen», «1 vulnerabilidades cuentan» y «En 1 casos».
    if resumen["en_kev"]:
        n_kev = int(resumen["en_kev"])
        doc.add_paragraph(
            f"{_numero(n_kev)} amenaza{'s' if n_kev != 1 else ''} "
            f"{'cuentan' if n_kev != 1 else 'cuenta'} con explotación activa confirmada por "
            f"CISA. {'Son las que presentan' if n_kev != 1 else 'Es la que presenta'} riesgo "
            f"material inmediato y {'deben' if n_kev != 1 else 'debe'} encabezar la "
            f"planificación de parcheo.")

    if resumen["confirmadas_afectadas"]:
        n_conf = int(resumen["confirmadas_afectadas"])
        doc.add_paragraph(
            f"En {_numero(n_conf)} {'casos' if n_conf != 1 else 'caso'} se ha verificado, "
            f"comparando con el inventario de tecnologías, que la versión registrada está "
            f"dentro del rango vulnerable declarado por el fabricante. Es un recuento por "
            f"TECNOLOGÍA; el recuento equivalente por ACTIVO Y PAQUETE, que es mucho mayor "
            f"porque una misma tecnología está instalada en muchas máquinas, está en el "
            f"apartado de activos.")
    if resumen["descartadas_version"]:
        n_desc = int(resumen["descartadas_version"])
        doc.add_paragraph(
            f"El sistema descartó automáticamente {_numero(n_desc)} "
            f"hallazgo{'s' if n_desc != 1 else ''} al comprobar que la versión instalada no "
            f"es vulnerable, reduciendo el volumen de revisión manual.")

    top = resumen.get("top_tecnologias") or []
    if top:
        doc.add_heading(f"{numero}.2 Tecnologías prioritarias", level=2)
        nombres = ", ".join(t["name"] for t in top[:5])
        doc.add_paragraph(
            f"Las tecnologías con mayor concentración de hallazgos en el periodo "
            f"son: {nombres}.")

        responsables = sorted({t.get("owner") for t in top[:10] if t.get("owner")})
        if responsables:
            doc.add_paragraph(
                f"Responsables designados en el inventario para estas "
                f"tecnologías: {', '.join(responsables)}.")

    doc.add_heading(f"{numero}.3 Recomendaciones", level=2)
    recomendaciones: list[str] = []
    # Concordancia en todas las recomendaciones con cifra (2026-09-15).
    def _amenazas(n: int, adjetivo: str = "") -> str:
        cola = f" {adjetivo}{'s' if n != 1 and adjetivo else ''}" if adjetivo else ""
        return (f"las {_numero(n)} amenazas{cola}" if n != 1
                else f"la amenaza{cola}")

    if resumen["en_kev"]:
        n_kev = int(resumen["en_kev"])
        recomendaciones.append(
            f"Corregir con prioridad absoluta {_amenazas(n_kev)} con explotación activa "
            f"confirmada.")
    if criticas:
        recomendaciones.append(
            f"Aplicar en un plazo de 0 a 24 horas los parches de "
            f"{_amenazas(criticas, 'crítica')}.")
    if altas:
        recomendaciones.append(
            f"Planificar en un plazo de 1 a 7 días la corrección de "
            f"{_amenazas(altas, 'alta')}.")
    if medias:
        recomendaciones.append(
            f"Incorporar {_amenazas(medias, 'de severidad media')} a la próxima ventana de "
            f"mantenimiento (7 a 30 días).")
    if resumen.get("sin_determinar", 0):
        n_sd = int(resumen["sin_determinar"])
        recomendaciones.append(
            f"Completar en el inventario las versiones instaladas: {_numero(n_sd)} "
            f"hallazgo{'s' if n_sd != 1 else ''} "
            f"{'quedaron' if n_sd != 1 else 'quedó'} «sin determinar» por falta de ese dato "
            f"y no {'pudieron' if n_sd != 1 else 'pudo'} descartarse automáticamente.")
    # La recomendacion de pedir una clave solo tiene sentido si NO hay ninguna en uso
    # (revision de precision del 2026-09-15): el informe la repetia con una clave valida
    # configurada y una cobertura del 80,2 % de puntuacion oficial.
    pct_oficial = float(resumen.get("pct_con_cvss_real") or 0)
    if resumen["sev_heuristica"] > resumen["sev_nvd"]:
        if _hay_clave_nvd(cfg):
            recomendaciones.append(
                f"Revisar por qué la cobertura de puntuación oficial se queda en el "
                f"{_decimal_es(pct_oficial)} % pese a estar en uso una clave de consulta "
                f"válida: suele deberse a vulnerabilidades publicadas hace pocas horas, que "
                f"todavía no tienen puntuación asignada.")
        else:
            recomendaciones.append(
                "Solicitar una clave de consulta a la base de datos nacional de "
                "vulnerabilidades para elevar el porcentaje de hallazgos con puntuación "
                "oficial, hoy minoritario.")
    elif pct_oficial < 95.0 and not _hay_clave_nvd(cfg):
        recomendaciones.append(
            f"Solicitar una clave de consulta a la base de datos nacional de "
            f"vulnerabilidades: hoy el {_decimal_es(pct_oficial)} % de los hallazgos llega "
            f"con puntuación oficial y con clave el enriquecimiento va diez veces más rápido.")
    recomendaciones.append(
        "Documentar las actuaciones realizadas y su fecha para poder acreditar "
        "el ciclo de gestión de vulnerabilidades ante auditoría.")

    for i, texto in enumerate(recomendaciones, 1):
        p = doc.add_paragraph(f"{i}. {texto}")
        p.paragraph_format.left_indent = Cm(0.5)


def _precision_filtro(doc: Document, resumen: dict, *, numero: int = 7) -> None:
    """Que dejo fuera el filtro de alertas y por que: transparencia del criterio."""
    doc.add_heading(f"{numero}. Precisión del filtro de alertas", level=1)
    precision = resumen.get("precision") or {}
    total = int(precision.get("total") or 0)
    # Criterio VIGENTE (revision de precision del 2026-09-15): el texto describia el
    # criterio anterior al 8 de septiembre y se contradecia con el parrafo de abajo, que ya
    # hablaba de la afectacion confirmada.
    doc.add_paragraph(
        "La alerta diaria solo incluye lo que requiere acción hoy, y para entrar hacen falta "
        "dos cosas a la vez: que la vulnerabilidad sea relevante (explotación activa "
        "confirmada, o relevancia para la organización igual o superior al umbral, siempre "
        "con identificador de vulnerabilidad o de aviso y con la puntuación oficial cuando "
        "existe) y que al menos un activo del inventario tenga confirmada la versión "
        "vulnerable. Este apartado muestra cuánto dejó fuera ese criterio y por qué, para "
        "que el filtro sea verificable y no una caja negra.")
    if precision.get("bajas_ignoradas"):
        n_bajas = int(precision["bajas_ignoradas"])
        doc.add_paragraph(
            f"Antes de este recuento quedan fuera {_numero(n_bajas)} "
            f"registro{'s' if n_bajas != 1 else ''} de la severidad que, por decisión de "
            f"Ciberseguridad, no se reporta. No están en la tabla ni en "
            f"ninguna otra cifra del informe, que habla siempre del mismo total.")
    if not total:
        doc.add_paragraph("Sin amenazas en el periodo.")
        return

    tabla = doc.add_table(rows=1, cols=3)
    tabla.style = "Light List Accent 1"
    for i, texto_col in enumerate(("Resultado", "Amenazas", "Porcentaje")):
        tabla.rows[0].cells[i].text = texto_col
        tabla.rows[0].cells[i].paragraphs[0].runs[0].font.bold = True
        tabla.rows[0].cells[i].paragraphs[0].runs[0].font.size = Pt(9)
    _repetir_cabecera(tabla.rows[0])

    # La tabla es un REPARTO del total: cada amenaza cae en una sola fila y los
    # porcentajes suman 100 %. Antes sumaban 105,5 % porque las mismas 90 amenazas
    # aparecian en dos filas (la de la severidad que no se reporta y la de su motivo) y
    # porque las filas de «estado» son otra clasificacion distinta, que no se reparte
    # (revision de precision del 2026-09-15).
    alertadas = int(precision.get("alertadas") or 0)
    filas: list[tuple[str, int]] = [("Alertadas", alertadas)]
    contadas = alertadas
    for motivo, n in (precision.get("motivos") or {}).items():
        if n:
            filas.append((f"No alertadas: {queries.MOTIVO_EXCLUSION_ES.get(motivo, motivo)}", int(n)))
            contadas += int(n)
    resto = total - contadas
    if resto > 0:
        filas.append(("Todavía sin decidir: se vuelven a valorar en la siguiente ejecución "
                      "diaria", resto))
        contadas += resto
    for etiqueta, n in filas:
        celdas = tabla.add_row().cells
        celdas[0].text = etiqueta
        celdas[1].text = _numero(n)
        celdas[2].text = f"{_decimal_es(n * 100.0 / total)} %"
        for celda in celdas:
            for pp in celda.paragraphs:
                for rr in pp.runs:
                    rr.font.size = Pt(9.5)
    # Fila de total: sin ella no se podia comprobar que el reparto cuadrara.
    celdas = tabla.add_row().cells
    celdas[0].text = "Total de amenazas del periodo"
    celdas[1].text = _numero(contadas)
    celdas[2].text = f"{_decimal_es(contadas * 100.0 / total)} %"
    for celda in celdas:
        for pp in celda.paragraphs:
            for rr in pp.runs:
                rr.font.size = Pt(9.5)
                rr.font.bold = True

    # Los estados que pone el equipo son otra clasificacion, no un trozo del reparto de
    # arriba: van en una frase aparte para que nadie los sume a la tabla.
    estados = precision.get("estados") or {}
    marcadas = [(queries.ESTADO_ES.get(e, e).lower(), int(estados.get(e) or 0))
                for e in ("descartada", "falso_positivo", "mitigada", "aceptada", "en_analisis")
                if estados.get(e)]
    if marcadas:
        detalle = ", ".join(f"{_numero(n)} como {etiqueta}" for etiqueta, n in marcadas)
        doc.add_paragraph(
            f"Además, y en una clasificación distinta que NO se suma a la tabla anterior, el "
            f"equipo marcó a mano {detalle}. Una misma amenaza puede estar alertada y además "
            f"marcada por el equipo.")

    doc.add_paragraph()
    # El parrafo decia que la explotacion activa «alerta siempre», que dejo de ser cierto
    # el 10 de septiembre de 2026 y contradecia al parrafo de arriba (2026-09-15).
    doc.add_paragraph(
        "Los motivos de exclusión se evalúan en este orden y cada amenaza se queda con el "
        "primero que le aplica: descartada o marcada como falso positivo por el equipo; la "
        "severidad que no se reporta; sin identificador de vulnerabilidad ni de aviso "
        "(noticias y artículos); severidad estimada, a la espera de la puntuación oficial; "
        "versión instalada no vulnerable; comprobado y descartado en el inventario; riesgo "
        "aceptado con una excepción vigente; a la espera de la evaluación contra el "
        "inventario; sin confirmar en ningún activo; relevancia por debajo del umbral. La "
        "explotación activa confirmada no salta el filtro de afectación: si ningún activo "
        "tiene la versión vulnerable, tampoco entra en el correo diario, y así está "
        "configurado en Administración → Ajustes. Lo excluido no se pierde: queda "
        "consultable en la interfaz con su motivo, se vuelve a valorar cada día y entra en "
        "el resumen semanal según el máximo configurado.")
    if precision.get("cerradas"):
        n_cerr = int(precision["cerradas"])
        doc.add_paragraph(
            f"El equipo cerró {_numero(n_cerr)} amenaza{'s' if n_cerr != 1 else ''} del "
            f"periodo como {'descartadas o falsos positivos' if n_cerr != 1 else 'descartada o falso positivo'}; "
            f"cada marca de falso positivo puede ajustar además el inventario para que el "
            f"caso no se repita.")


def _metodologia(doc: Document, resumen: dict, *, cfg, numero: int = 8,
                 apartados: Optional[Iterable[str]] = None) -> None:
    doc.add_page_break()
    doc.add_heading(f"{numero}. Nota metodológica", level=1)

    doc.add_paragraph(
        "Este apartado documenta cómo se obtiene y clasifica la información, para "
        "que el contenido del informe sea verificable y defendible ante una "
        "auditoría.")

    doc.add_heading(f"{numero}.1 Origen de los datos", level=2)
    doc.add_paragraph(
        "La recolección consulta fuentes de inteligencia de amenazas (organismos "
        "públicos, fabricantes, bases de datos de vulnerabilidades y medios "
        "especializados). Cada hallazgo se identifica por su CVE cuando existe, o "
        "por el identificador de aviso del fabricante, de modo que la misma "
        "vulnerabilidad informada por varias fuentes constituye un único registro.")

    doc.add_heading(f"{numero}.2 Clasificación de la severidad", level=2)
    doc.add_paragraph(
        "La severidad se determina por orden de fiabilidad: puntuación CVSS "
        "oficial del NVD; en su defecto, cálculo a partir del vector CVSS "
        "publicado; en su defecto, presencia en el catálogo KEV de CISA; y como "
        "último recurso, estimación a partir de indicios textuales. El origen "
        "aplicado figura en cada ficha.")
    p = doc.add_paragraph()
    r = p.add_run(
        "Cuando la severidad procede de una estimación, el campo de puntuación "
        "CVSS indica «no disponible». Una severidad estimada NO constituye una "
        "puntuación CVSS oficial y no debe presentarse como tal.")
    r.font.bold = True

    doc.add_heading(f"{numero}.3 Correlación con el inventario", level=2)
    doc.add_paragraph(
        "Cada hallazgo se compara con el inventario tecnológico de la "
        "organización mediante coincidencia por palabra completa, con alias y "
        "exclusiones definidos por tecnología. Cuando el aviso especifica un rango "
        "de versiones afectadas y el inventario tiene registrada la versión "
        "instalada, el sistema determina si el aviso aplica. Ante cualquier "
        "ambigüedad se clasifica como «sin determinar», nunca como no aplicable: "
        "en seguridad, un falso negativo es más costoso que un falso positivo.")

    doc.add_heading(f"{numero}.4 Prioridad organizativa", level=2)
    doc.add_paragraph(
        "La prioridad organizativa (0-100) combina la severidad técnica con la "
        "exposición real: criticidad de las tecnologías afectadas, exposición a "
        "Internet, número de sistemas, veredicto de versión, presencia en KEV y "
        f"probabilidad EPSS. Es el criterio de ordenación de "
        f"{_ref(apartados, 'prioritarias', 'las fichas y del listado de la interfaz')}.")

    doc.add_heading(f"{numero}.5 Cobertura del periodo", level=2)
    doc.add_paragraph(
        f"Registros del periodo: {resumen['total']}. Con CVSS oficial: "
        f"{resumen['sev_nvd']} ({resumen['pct_con_cvss_real']} %). Con "
        f"identificador CVE: {resumen['con_cve']}. Con explotación confirmada: "
        f"{resumen['en_kev']}.")


# --------------------------------------------------------------------------
# Punto de entrada
# --------------------------------------------------------------------------
def _metodologia_activos(doc: Document, resumen: dict, *, numero: int = 8) -> None:
    doc.add_heading(f"{numero}.6 Aplicabilidad por activo", level=2)
    doc.add_paragraph(
        "El inventario real se sincroniza a diario desde los dos servidores de OCS Inventory "
        "(servidores y equipos de cómputo) con un usuario de solo lectura. Para cada amenaza con CVE "
        "se compara la versión del paquete instalado en cada activo con la versión que corrige el fallo: "
        "en Debian y Ubuntu con los registros DEBIAN-CVE y UBUNTU-CVE de OSV.dev y las reglas de "
        "comparación de dpkg; en FreeBSD con VuXML (puertos y sistema base por nivel de parche); en Windows "
        "y software de escritorio con las restricciones de versión que enuncia el aviso. El resultado es "
        "«afectado», «no afectado» o «sin dato», siempre con la evidencia (versión instalada frente a "
        "corregida). El fin de soporte procede de endoflife.date. Un activo con la versión vulnerable "
        "confirmada eleva la relevancia de la amenaza; si todos los activos evaluados ya llevan la "
        "corrección, la reduce.")



# --------------------------------------------------------------------------
# Cola de remediación (2026-09-10, informe a medida)
# --------------------------------------------------------------------------
def _remediacion(doc: Document, grupos: list[dict], *, numero: int, total: int,
                 maximo: int) -> None:
    """Qué hay que instalar en cada activo y hasta qué versión.

    Es la cola de trabajo de la página de Remediación puesta en el documento: una fila por
    actualización (activo y origen de paquete), con la versión instalada, la versión
    OBJETIVO (la más alta que piden sus avisos, comparada con las reglas de la
    distribución, nunca por orden de texto) y cuántas vulnerabilidades cierra.

    Advertencia importante que el apartado escribe siempre: la cola es la situación de
    HOY, no la foto del periodo del informe. Una actualización pendiente puede cerrar
    vulnerabilidades de varios meses, así que recortarla por el periodo daría una versión
    objetivo más baja que la que hay que instalar de verdad.
    """
    doc.add_page_break()
    doc.add_heading(f"{numero}. Cola de remediación: qué actualizar y hasta qué versión",
                    level=1)
    doc.add_paragraph(
        "Una fila por actualización pendiente. «Actualizar a» es la versión más alta que "
        "piden los avisos de esa máquina para ese conjunto de paquetes: instalarla cierra "
        "de una vez todas las vulnerabilidades de la fila. La cola refleja la situación "
        "actual del inventario, no solo el periodo del informe, porque la versión que hay "
        "que instalar no depende del mes en que se detectó el problema.")
    if not grupos:
        doc.add_paragraph(
            "No hay actualizaciones pendientes en el alcance de este informe: todo lo "
            "confirmado está corregido o no se ha podido determinar la versión que corrige.")
        return

    if total > len(grupos):
        p = doc.add_paragraph()
        r = p.add_run(
            f"Se detallan las {_numero(len(grupos))} actualizaciones de mayor prioridad de "
            f"un total de {_numero(total)} pendientes en este alcance (tope de "
            f"{_numero(maximo)} filas por documento). La cola completa, con su evidencia, "
            f"está en la página de Remediación de la plataforma.")
        r.font.italic = True
        r.font.size = Pt(9)
        r.font.color.rgb = GRIS

    tabla = doc.add_table(rows=1, cols=7)
    tabla.style = "Light Grid Accent 1"
    cab = tabla.rows[0].cells
    for i, texto in enumerate(("Activo", "Tipo", "Actualización", "Versión instalada",
                               "Actualizar a", "Vulnerab.", "Días")):
        cab[i].text = texto
        cab[i].paragraphs[0].runs[0].font.bold = True
        cab[i].paragraphs[0].runs[0].font.size = Pt(8.5)
    _repetir_cabecera(tabla.rows[0])

    for g in grupos:
        celdas = tabla.add_row().cells
        severidad = g.get("severidad") or ""
        valores = (
            str(g.get("activo_nombre") or "—"),
            "Servidor" if g.get("origen") == "servidores" else "Equipo de cómputo",
            str(g.get("nombre") or g.get("paquete") or "—"),
            str(g.get("version_instalada") or "sin dato"),
            str(g.get("version_objetivo") or "sin versión publicada"),
            _numero(g.get("vulnerabilidades") or 0),
            f"{_numero(g.get('dias') or 0)}" if g.get("dias") is not None else "—",
        )
        for i, valor in enumerate(valores):
            celdas[i].text = valor
            celdas[i].paragraphs[0].runs[0].font.size = Pt(8)
        if not g.get("version_objetivo"):
            celdas[4].paragraphs[0].runs[0].font.color.rgb = GRIS
        if severidad in COLOR_SEVERIDAD:
            celdas[5].paragraphs[0].runs[0].font.color.rgb = COLOR_SEVERIDAD[severidad]
            celdas[5].paragraphs[0].runs[0].font.bold = severidad in ("Critical", "High")
        if g.get("in_kev"):
            _sombrear(celdas[0], "FDECEA")

    nota = doc.add_paragraph()
    r = nota.add_run(
        "«Vulnerab.» son CVE distintos que cierra la actualización, contados una sola vez "
        "aunque afecten a varios paquetes de la misma máquina. «Días» son los que lleva "
        "esperando la detección más antigua de la fila. Una fila sombreada en rojo tiene "
        "al menos una vulnerabilidad con explotación activa confirmada (catálogo KEV de "
        "CISA) y se atiende primero.")
    r.font.size = Pt(8.5)
    r.font.color.rgb = GRIS


def cola_remediacion(conn: sqlite3.Connection, seleccion: Any, *,
                     maximo: int = 250) -> tuple[list[dict], int]:
    """Las actualizaciones pendientes del alcance de la selección y cuántas hay en total.

    Se pide a ``remediacion.pagina_actualizaciones``, el mismo camino que pinta la página
    de Remediación, para que el documento y la pantalla no puedan discrepar. Los CVE
    pintados de cada grupo se recortan a uno (``limite_cves=1``): el documento solo
    necesita las cifras y la versión objetivo, y traer las 25 de cada fila multiplicaba
    por veinte la memoria de la petición.
    """
    from . import remediacion
    filtros = seleccion.filtros_remediacion()
    try:
        pagina = remediacion.pagina_actualizaciones(
            conn, estado="abierta", limite=max(1, int(maximo)), limite_cves=1, **filtros)
    except sqlite3.OperationalError:
        return [], 0
    grupos = pagina.get("grupos") or []
    total = pagina.get("total")
    if total is None:
        try:
            total = remediacion.contar_actualizaciones(conn, estado="abierta", **filtros)
        except sqlite3.OperationalError:
            total = len(grupos)
    return grupos, int(total or 0)


# --------------------------------------------------------------------------
# Resumen de un informe a medida (2026-09-10)
# --------------------------------------------------------------------------
def resumen_a_medida(conn: sqlite3.Connection, seleccion: Any, *, cfg,
                     amenazas: Optional[list[dict]] = None) -> dict[str, Any]:
    """Las mismas cifras que :func:`construir_resumen`, acotadas por la selección.

    Devuelve exactamente las mismas claves para que los apartados del documento sean el
    MISMO código en el informe mensual y en el informe a medida: si aquí faltara una
    clave, el apartado se rompería, y si sobrara, el informe a medida contaría las cosas
    de otra manera que el mensual, que es justo lo que no puede pasar.
    """
    from . import informe_seleccion as isel

    stats = isel.estadisticas(conn, seleccion)
    precision_sel = isel.precision(conn, seleccion)
    # Cuántas bajas se dejaron fuera del periodo: la cifra que el informe usa para decir
    # que no se reportan. Sale de la misma consulta que la precisión del filtro.
    stats["bajas_ignoradas"] = int(precision_sel.get("bajas_ignoradas", 0))
    stats["excluir_bajas"] = True   # la severidad baja no se reporta nunca
    vistas = amenazas if amenazas is not None else isel.amenazas(conn, seleccion)
    conteo_veredictos = isel.veredictos(conn, seleccion)
    return {
        **stats,
        "month": seleccion.mes_representativo(),
        "periodo": seleccion.etiqueta_periodo(),
        # Las severidades del informe: los apartados las usan para no nombrar ni pintar
        # una severidad que la persona dejó fuera. En el informe mensual esta clave NO
        # existe, y entonces los apartados se comportan como siempre.
        "severidades": tuple(seleccion.severidades),
        "alcance_es": isel.etiqueta_alcance(conn, seleccion),
        "top_tecnologias": isel.top_tecnologias(conn, seleccion, 20),
        "evolucion": isel.evolucion(conn, seleccion, 7),
        "veredictos": conteo_veredictos,
        "confirmadas_afectadas": conteo_veredictos.get("affected", 0),
        "descartadas_version": conteo_veredictos.get("not_affected", 0),
        "sin_determinar": conteo_veredictos.get("unknown", 0),
        "bloques": _bloques_de(vistas, cfg=cfg),
        "precision": precision_sel,
        "activos": isel.resumen_activos(conn, seleccion, cfg=cfg, limite=40),
    }


def _bloques_de(vistas: list[dict], *, cfg) -> dict[str, Any]:
    """El recuento por bloque de lectura de una lista ya cargada de amenazas.

    Es ``clasificar_bloques`` sin volver a consultar: el informe a medida ya tiene las
    amenazas en memoria y con la base real esa consulta cuesta más que el propio informe.
    """
    umbral = float(cfg.get("alert_min_relevance", 50) or 50)
    min_conf = float(cfg.get("alert_min_match_confidence", 0.6) or 0)
    ignorar_baja = bool(cfg.get("ignore_low_criticality", True))
    conteo = {k: 0 for k in BLOQUE_ES}
    for a in vistas:
        conteo[bloque_de(a, umbral=umbral, min_confianza=min_conf,
                         ignorar_baja=ignorar_baja)] += 1
    total = len(vistas) or 1
    return {"conteo": conteo,
            "porcentaje": {k: round(v * 100.0 / total, 1) for k, v in conteo.items()},
            "umbral": umbral, "min_confianza": min_conf, "total": len(vistas)}


def construir_documento(conn: sqlite3.Connection, month: str, *, cfg,
                        secciones: Optional[Iterable[str]] = None,
                        filtros: Any = None) -> Document:
    """Compone un informe y devuelve el documento SIN guardarlo.

    Separado de :func:`generar` el 2026-09-08 para que la interfaz web pueda entregar
    el informe de un mes concreto como descarga (:func:`generar_en_memoria`) sin
    escribir en ``reports/`` ni enviar nada por correo. ``generar`` sigue haciendo
    exactamente lo mismo que antes: construir y guardar en disco.

    Desde el 2026-09-10 admite dos argumentos más, para el informe a medida de
    ``/informes/``:

    ``secciones``
        Los apartados que se escriben, por su clave
        (:data:`threatintel.informe_seleccion.APARTADOS`). ``None`` (por omisión) escribe
        los del informe mensual de siempre, en su orden y con su numeración histórica.
    ``filtros``
        Una :class:`threatintel.informe_seleccion.Seleccion` con el periodo, el alcance y
        las severidades. ``None`` (por omisión) es el mes completo de toda la
        organización, es decir el informe mensual tal cual.

    Con los dos a ``None`` el documento es EL MISMO de siempre, camino de código incluido:
    es el que compone la ejecución mensual programada y no se le cambia nada.
    """
    apartados = None if secciones is None else _apartados_pedidos(secciones)
    # El informe ejecutivo mensual (2026-09-15) es OTRO documento, con otro generador: si
    # lo que se pide son sus apartados, se delega y aquí no se escribe nada. Se comprueba
    # antes que cualquier otra cosa para que ni una consulta del informe completo se
    # ejecute de más.
    from .informe_seleccion import es_ejecutivo as _es_ejecutivo
    if apartados is not None and _es_ejecutivo(apartados):
        return construir_documento_ejecutivo(
            conn, month if filtros is None else filtros.mes_representativo(),
            cfg=cfg, filtros=filtros)
    numeros = numeros_de_apartado(_apartados(apartados))
    if filtros is not None:
        month = filtros.mes_representativo()

    detalle = cfg.get("report_detail_severities") or ["Critical", "High"]
    ignorar_crit_baja = bool(cfg.get("ignore_low_criticality", True))
    if filtros is None:
        resumen = construir_resumen(conn, month, cfg=cfg)
        todas = queries.del_mes(conn, month, orden="relevancia",
                                excluir_bajas=bool(cfg.get("ignore_low_severity", True)))
    else:
        from . import informe_seleccion as isel
        todas = isel.amenazas(conn, filtros)
        resumen = resumen_a_medida(conn, filtros, cfg=cfg, amenazas=todas)
    # Las cerradas por el equipo (descartadas, falsos positivos) no son hallazgos
    # vivos: se cuentan en «Precisión del filtro», no se detallan.
    vivas = [a for a in todas if (a.get("estado") or "nueva") not in queries.ESTADOS_CERRADOS]
    min_conf = float(cfg.get("alert_min_match_confidence", 0.6) or 0)
    umbral = float(cfg.get("alert_min_relevance", 50) or 50)
    # Fichas solo para lo que requiere accion (KEV o relevancia >= umbral) y es de
    # una severidad con ficha; una noticia sin CVE de severidad "alta" estimada ya
    # no ocupa media pagina del informe: va al anexo.
    prioritarias = [a for a in vivas
                    if bloque_de(a, umbral=umbral, min_confianza=min_conf,
                                 ignorar_baja=ignorar_crit_baja) == "requiere_accion"
                    and (a.get("in_kev") or a.get("severity") in detalle)]
    ids_prior = {a["id"] for a in prioritarias}
    resto = [a for a in vivas if a["id"] not in ids_prior]
    # Fichas agrupadas por tecnologia principal (la mas expuesta primero) y,
    # dentro de cada grupo, por relevancia.
    orden_tec: dict[str, float] = {}
    for a in prioritarias:
        tec = _tecnologia_principal(a, min_conf, ignorar_crit_baja)
        nombre = tec["name"] if tec else "Sin tecnología del inventario"
        orden_tec[nombre] = max(orden_tec.get(nombre, 0.0), float(a.get("relevance") or 0))
    prioritarias.sort(key=lambda a: (
        _tecnologia_principal(a, min_conf, ignorar_crit_baja) is None,   # las sin tecnología, al final
        -orden_tec[(_tecnologia_principal(a, min_conf, ignorar_crit_baja) or {}).get("name", "Sin tecnología del inventario")],
        (_tecnologia_principal(a, min_conf, ignorar_crit_baja) or {}).get("name", "zzz"),
        -float(a.get("relevance") or 0)))
    for a in prioritarias:
        tec = _tecnologia_principal(a, min_conf, ignorar_crit_baja)
        a["_grupo_tecnologia"] = tec["name"] if tec else "Sin tecnología del inventario"

    maximo = int(cfg.get("report_max_detail_items", 120) or 120)
    if len(prioritarias) > maximo:
        resto = prioritarias[maximo:] + resto
        resto.sort(key=lambda a: -(a.get("relevance") or 0))

    log.info("generando informe", extra={
        "month": month, "total": len(todas), "prioritarias": len(prioritarias),
        "anexo": len(resto), "a_medida": filtros is not None,
        "apartados": ",".join(_apartados(apartados))})

    logo_fila = db.get_logo(conn)
    logo = logo_fila["logo_datos"] if logo_fila else None
    doc = _preparar_documento()
    # Los saltos de página son los mismos que ha tenido siempre el informe mensual: la
    # portada y el índice terminan en salto, el anexo, las conclusiones, la cola de
    # remediación y la metodología empiezan con el suyo, y los demás apartados llevan uno
    # delante cuando no venían ya de un salto. Se lleva la cuenta en vez de escribirlos a
    # mano porque ahora cualquier apartado puede faltar y no puede quedar una página en
    # blanco por medio.
    estado = {"escrito": False, "tras_salto": False}

    def salto_si_hace_falta() -> None:
        if estado["escrito"] and not estado["tras_salto"]:
            doc.add_page_break()

    def anotar(*, termina_en_salto: bool = False) -> None:
        estado["escrito"] = True
        estado["tras_salto"] = termina_en_salto

    if _incluye(apartados, "portada"):
        _portada(doc, resumen, cfg=cfg, seleccion=filtros, logo=logo)
        anotar(termina_en_salto=True)
    if _incluye(apartados, "indice"):
        _indice(doc)
        anotar(termina_en_salto=True)
    if _incluye(apartados, "resumen_ejecutivo"):
        salto_si_hace_falta()
        _resumen_ejecutivo(doc, resumen, cfg=cfg, conn=conn,
                           numero=numeros["resumen_ejecutivo"], apartados=apartados)
        anotar()
    if _incluye(apartados, "panorama"):
        salto_si_hace_falta()
        _panorama(doc, resumen, numero=numeros["panorama"])
        anotar()
    if _incluye(apartados, "tecnologias"):
        salto_si_hace_falta()
        _exposicion(doc, resumen, numero=numeros["tecnologias"])
        anotar()
    if _incluye(apartados, "activos"):
        salto_si_hace_falta()
        _activos(doc, resumen, numero=numeros["activos"])
        anotar()
    if _incluye(apartados, "prioritarias"):
        salto_si_hace_falta()
        try:
            _adjuntar_activos_del_alcance(conn, prioritarias, filtros, limite=8)
        except sqlite3.OperationalError:
            pass
        _prioritarias(doc, prioritarias, cfg=cfg, total_periodo=len(todas),
                      numero=numeros["prioritarias"], apartados=apartados)
        anotar()
    if _incluye(apartados, "remediacion"):
        maximo_cola = int(cfg.get("report_max_detail_items", 120) or 120) * 2
        grupos, total_cola = cola_remediacion(
            conn, filtros if filtros is not None else _seleccion_del_mes(month),
            maximo=maximo_cola)
        _remediacion(doc, grupos, numero=numeros["remediacion"], total=total_cola,
                     maximo=maximo_cola)
        anotar()
    if _incluye(apartados, "anexo"):
        _anexo(doc, resto, titulo="Anexo A. Relación del resto de hallazgos",
               maximo=int(cfg.get("report_max_anexo_items", 250) or 250))
        anotar()
    if _incluye(apartados, "conclusiones"):
        _conclusiones(doc, resumen, cfg=cfg, numero=numeros["conclusiones"])
        anotar()
    if _incluye(apartados, "precision"):
        # En el informe mensual la precisión del filtro va justo detrás de las
        # conclusiones, sin salto: se respeta tal cual. En un informe a medida puede
        # llegar detrás de cualquier apartado, y entonces sí abre página.
        if _apartados(apartados) != APARTADOS_MENSUAL:
            salto_si_hace_falta()
        _precision_filtro(doc, resumen, numero=numeros["precision"])
        anotar()
    if _incluye(apartados, "metodologia"):
        _metodologia(doc, resumen, cfg=cfg, numero=numeros["metodologia"],
                     apartados=apartados)
        _metodologia_activos(doc, resumen, numero=numeros["metodologia"])
        anotar()
    _pie_con_numeracion(doc, month)
    _encabezado_con_logo(doc, logo)
    return doc


def _ids_del_alcance(conn: sqlite3.Connection, seleccion: Any) -> Optional[set[int]]:
    """Los identificadores de los activos presentes del alcance, o None si no hay recorte.

    Son 717 activos en producción: caben de sobra en memoria y evitan una consulta por
    amenaza.
    """
    where, params = seleccion.where_activos("a")
    if not where:
        return None
    try:
        return {int(f[0]) for f in conn.execute(
            f"SELECT a.id FROM activos a WHERE a.presente = 1{where}", params)}
    except sqlite3.OperationalError:
        return None


def _adjuntar_activos_del_alcance(conn: sqlite3.Connection, vistas: list[dict],
                                  seleccion: Any, *, limite: int = 8) -> None:
    """Pone en cada ficha los activos afectados, pero SOLO los del alcance del informe.

    ``aplicabilidad.adjuntar_activos`` lista los activos afectados de toda la
    organización, que es lo correcto en el informe mensual. En un informe de un proceso,
    de un tipo de máquina o de un activo eso sería una fuga: la ficha nombraría máquinas
    que no son del alcance, y con un perfil acotado (Redes, Mantenimiento) nombraría
    máquinas del otro tipo, que ese perfil no puede ver. Aquí se piden todos y se dejan
    los del alcance, recontando la cifra que acompaña a los nombres para que no diga «6
    activos» al lado de una lista de uno. Medido el 2026-09-10 sobre la base real: pedir
    la lista completa en vez de las ocho primeras cuesta 40 milisegundos más en 120
    fichas, porque la consulta ya recorría todas las filas.
    """
    from . import aplicabilidad
    ids = _ids_del_alcance(conn, seleccion) if seleccion is not None else None
    if ids is None:
        aplicabilidad.adjuntar_activos(conn, vistas, limite=limite)
        return
    aplicabilidad.adjuntar_activos(conn, vistas, limite=0)
    for vista in vistas:
        activos = vista.get("activos") or {}
        dentro = [a for a in (activos.get("afectados") or [])
                  if int(a.get("id") or 0) in ids]
        activos["n_afectados"] = len(dentro)
        activos["mas"] = max(0, len(dentro) - limite)
        activos["afectados"] = dentro[:limite]
        # Los recuentos de «ya corregidos» y «sin dato» son de todo el parque y no se
        # pueden recortar sin volver a evaluar: en un informe acotado se omiten antes que
        # dar una cifra de otro ámbito.
        activos["n_no_afectados"] = 0
        activos["n_sin_dato"] = 0
        activos["sistemas"] = []
        vista["activos"] = activos


def _apartados_pedidos(secciones: Iterable[str]) -> tuple[str, ...]:
    """Los apartados pedidos, sin claves desconocidas y en el orden del documento.

    Si no queda ninguno se escriben los del informe mensual: un documento vacío no es un
    informe, y la vista ya avisa antes de llegar aquí.
    """
    from .informe_seleccion import ordenar_apartados
    return ordenar_apartados(secciones) or APARTADOS_MENSUAL


def _seleccion_del_mes(month: str) -> Any:
    """Una selección mínima (un mes, toda la organización) para los apartados que la
    necesitan cuando se pide un informe sin filtros."""
    from .informe_seleccion import Seleccion
    return Seleccion(periodo="mes", mes=month)


def generar_en_memoria(conn: sqlite3.Connection, month: str, *, cfg,
                       secciones: Optional[Iterable[str]] = None,
                       filtros: Any = None) -> bytes:
    """El informe de ``month`` como bytes de un ``.docx``, sin tocar el disco.

    Lo usa el módulo de informes de la interfaz (2026-09-08): el fichero viaja
    directamente al navegador como descarga y no queda copia en ``reports/``, que
    sigue siendo territorio exclusivo de la ejecución mensual programada.
    ``secciones`` y ``filtros`` son los del informe a medida (2026-09-10) y por omisión
    dan el informe mensual completo de siempre.
    """
    import io
    memoria = io.BytesIO()
    construir_documento(conn, month, cfg=cfg, secciones=secciones,
                        filtros=filtros).save(memoria)
    datos = memoria.getvalue()
    log.info("informe generado en memoria", extra={
        "month": month, "kb": round(len(datos) / 1024, 1)})
    return datos


def generar(conn: sqlite3.Connection, month: str, *, cfg,
            destino: Optional[Path] = None) -> Path:
    """Genera el informe mensual, lo guarda y devuelve la ruta del .docx."""
    doc = construir_documento(conn, month, cfg=cfg)

    ruta = Path(destino) if destino else report_file(month)
    ruta.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(ruta))
    try:
        ruta.chmod(0o640)
    except OSError:
        pass

    log.info("informe generado", extra={
        "ruta": str(ruta), "kb": round(ruta.stat().st_size / 1024, 1)})
    return ruta


# ==========================================================================
# Informe ejecutivo mensual (2026-09-15)
# ==========================================================================
# Petición literal del usuario: «necesito que a final de mes también se genere un informe
# ejecutivo sobre las amenazas del mes que no exceda las 10 páginas, donde debe ser muy
# conciso, concreto, directo y lo que normalmente le interesa a un gerente: temas de
# cifras, comparación entre meses o años y avances entre meses con detectadas y
# remediadas».
#
# Es un documento NUEVO Y APARTE: el informe mensual completo (``construir_documento``) no
# cambia ni una coma, porque hay una prueba que lo compara párrafo a párrafo y porque es el
# que se envía por correo el último día del mes. Este otro se genera junto a él.
#
# Cómo se garantizan las diez páginas: la estructura es FIJA y ninguno de sus apartados
# crece con el número de amenazas. No hay fichas, no hay anexo, no hay cola de remediación
# y ninguna tabla lleva una fila por vulnerabilidad: la más larga es la serie de los doce
# últimos meses y el reparto por proceso de negocio, que va recortado a seis filas. Medido
# con septiembre de 2026 sobre la base real: ocho páginas.
#
# Cómo se garantiza que es «para un gerente»: aquí no se escribe ningún identificador de
# vulnerabilidad, ningún nombre de paquete, ninguna versión y ninguna orden que ejecutar.
# Todas las cifras llevan su unidad y su comparación, y cada apartado termina en una frase
# que dice qué significa.
# --------------------------------------------------------------------------

#: Cuántos meses de histórico se leen para la serie y las comparaciones. Trece son los doce
#: que se pintan más el mismo mes del año pasado cuando el mes en curso es enero.
MESES_EJECUTIVO = 13
#: Meses que se pintan en la tabla de avance. Doce caben en una página y son un año entero.
MESES_SERIE_EJECUTIVO = 12
#: Procesos de negocio que se nombran en el apartado de trabajo pendiente.
PROCESOS_EJECUTIVO = 6
#: Días de la ventana de «remediado» que acompaña a las cifras del pendiente.
DIAS_VENTANA_EJECUTIVO = 30


def _plural(n: Any, singular: str, plural: str = "") -> str:
    """«1 activo», «652 activos»: la cifra en formato español con su unidad concordada.

    El informe ejecutivo lo lee una gerencia: «794 vulnerabilidades en 1 activos» se lee
    como un error del sistema y resta credibilidad a todo lo demás.
    """
    try:
        valor = int(n or 0)
    except (TypeError, ValueError):
        valor = 0
    return f"{_numero(valor)} {singular if abs(valor) == 1 else (plural or singular + 's')}"


def _mes_desplazado(month: str, meses: int) -> str:
    """«2026-09» desplazado ``meses`` (negativo hacia atrás): «2026-08», «2025-09»."""
    try:
        anio, mes = int(str(month)[:4]), int(str(month)[5:7])
    except (TypeError, ValueError):
        return ""
    total = anio * 12 + (mes - 1) + int(meses)
    return f"{total // 12:04d}-{total % 12 + 1:02d}"


def _variacion(actual: Any, anterior: Any, *, menos_es_mejor: bool = True) -> dict[str, Any]:
    """La variación entre dos cifras, en número, en porcentaje y EN PALABRAS.

    El usuario pidió que la comparación se dijera «en palabras (mejoró, empeoró, se
    mantiene)»: una gerencia no tiene por qué deducir de un signo menos si eso es bueno o
    malo. ``menos_es_mejor`` invierte el juicio para las magnitudes en las que subir es
    bueno (por ejemplo, las vulnerabilidades remediadas).

    Sin dato anterior (un mes que no existe en el histórico) devuelve ``comparable=False``
    y el documento escribe «no hay dato del periodo anterior» en vez de inventarse un
    100 %.
    """
    try:
        a = int(actual or 0)
    except (TypeError, ValueError):
        a = 0
    if anterior is None:
        return {"comparable": False, "absoluta": 0, "porcentaje": None,
                "palabra": "sin comparación", "texto": "no hay dato del mismo periodo anterior"}
    try:
        b = int(anterior or 0)
    except (TypeError, ValueError):
        b = 0
    diferencia = a - b
    porcentaje = (abs(diferencia) * 100.0 / b) if b else None
    if diferencia == 0:
        palabra = "se mantiene"
    elif (diferencia < 0) == menos_es_mejor:
        palabra = "mejoró"
    else:
        palabra = "empeoró"
    if diferencia == 0:
        texto = "igual que el periodo anterior"
    else:
        signo = "menos" if diferencia < 0 else "más"
        if porcentaje is None:
            texto = f"{_numero(abs(diferencia))} {signo} (el periodo anterior era cero)"
        else:
            texto = (f"{_numero(abs(diferencia))} {signo} "
                     f"({_decimal_es(porcentaje)} %)")
    return {"comparable": True, "absoluta": diferencia, "porcentaje": porcentaje,
            "palabra": palabra, "texto": texto}


def _vulnerabilidades_por_mes(conn: sqlite3.Connection, seleccion: Any,
                              meses: Sequence[str]) -> dict[str, dict[str, int]]:
    """Vulnerabilidades confirmadas y activos afectados de cada uno de esos meses.

    Una vulnerabilidad es un CVE EN UN ACTIVO (``queries.sql_vulnerabilidades``, el único
    punto de verdad del conteo de la plataforma), no una amenaza del catálogo: es la cifra
    que la gerencia entiende como «cuántos problemas reales tenemos». Se piden los tres
    meses de una vez, agrupando por ``threats.month``, para no repetir el mismo recorrido
    tres veces.

    Deja fuera la severidad que no se reporta y el riesgo aceptado con una excepción
    vigente, exactamente igual que ``aplicabilidad.resumen_informe`` y que la página de
    Activos: si no, el informe de gerencia daría una cifra distinta de la pantalla.
    """
    meses = [m for m in meses if m]
    if not meses:
        return {}
    from . import aplicabilidad
    sin_bajas = aplicabilidad._y_sin_bajas(conn)
    sin_excepcion = aplicabilidad._y_sin_excepcion(conn)
    where_act, p_act = seleccion.where_activos("a")
    marcas = ",".join("?" * len(meses))
    try:
        filas = conn.execute(
            f"""SELECT t.month AS mes,
                       COUNT(DISTINCT ap.activo_id) AS activos,
                       {queries.sql_vulnerabilidades()} AS vulnerabilidades,
                       {queries.sql_vulnerabilidades(condicion="t.in_kev=1")} AS kev
                  FROM aplicabilidad ap
                  JOIN activos a ON a.id = ap.activo_id
                  JOIN threats t ON t.id = ap.threat_id
                 WHERE ap.veredicto='afectado' AND a.presente=1
                   AND t.estado NOT IN ('descartada','falso_positivo')
                   AND t.month IN ({marcas}){sin_bajas}{sin_excepcion}{where_act}
                 GROUP BY t.month""", [*meses, *p_act]).fetchall()
    except sqlite3.OperationalError:
        return {}
    return {f["mes"]: {"activos": int(f["activos"] or 0),
                       "vulnerabilidades": int(f["vulnerabilidades"] or 0),
                       "kev": int(f["kev"] or 0)} for f in filas}


def _avance_por_mes(conn: sqlite3.Connection, seleccion: Any, *,
                    meses: int = MESES_SERIE_EJECUTIVO) -> list[dict[str, Any]]:
    """Vulnerabilidades detectadas y remediadas en cada uno de los últimos meses.

    Es el corazón del informe ejecutivo: «cuántas aparecieron y cuántas se cerraron cada
    mes, si la deuda sube o baja, y el tiempo medio en corregir». Se lee de
    ``remediaciones``, que es la tabla que la plataforma usa para la cola de trabajo, con
    la misma unidad que el resto (un CVE en un activo) y con las mismas exclusiones que la
    página de Remediación: sin la severidad que no se reporta y sin el riesgo aceptado.

    Dos recorridos de la tabla, uno por fecha de detección y otro por fecha de corrección,
    y no dos consultas por mes: con 48.000 filas abiertas en producción, veinticuatro
    subconsultas costarían más que todo el documento.
    """
    from . import remediacion
    sin_bajas = remediacion._y_sin_bajas(conn)
    sin_excepcion = remediacion._y_sin_excepcion(conn)
    where_act, p_act = seleccion.where_activos("a")
    union = " JOIN activos a ON a.id = r.activo_id" if where_act else ""
    # El primer mes de la serie: se cuenta desde el día 1 de ese mes.
    mes_final = seleccion.mes_representativo()
    desde = _mes_desplazado(mes_final, -(meses - 1)) + "-01"
    par = "r.activo_id || char(31) || r.cve"
    tiene_cve = "r.cve IS NOT NULL AND r.cve <> ''"
    # Los activos retirados quedan fuera de las dos series, igual que en la gráfica semanal
    # de la página de Remediación: una fila sin activo no es trabajo pendiente ni trabajo
    # hecho, y contarla haría que el informe de gerencia y la pantalla dijeran cifras
    # distintas del mismo mes.
    vivas = " AND r.estado <> 'activo_ausente'"
    try:
        detectadas = {f["mes"]: int(f["n"] or 0) for f in conn.execute(
            f"""SELECT substr(r.detectado_at, 1, 7) AS mes, COUNT(DISTINCT {par}) AS n
                  FROM remediaciones r{union}
                 WHERE r.detectado_at >= ? AND {tiene_cve}{vivas}{sin_bajas}{sin_excepcion}{where_act}
                 GROUP BY 1""", [desde, *p_act])}
        corregidas = {f["mes"]: (int(f["n"] or 0), f["dias"]) for f in conn.execute(
            f"""SELECT substr(r.corregido_at, 1, 7) AS mes, COUNT(DISTINCT {par}) AS n,
                       AVG(julianday(r.corregido_at) - julianday(r.detectado_at)) AS dias
                  FROM remediaciones r{union}
                 WHERE r.estado='corregida' AND r.corregido_at >= ?
                   AND {tiene_cve}{sin_bajas}{sin_excepcion}{where_act}
                 GROUP BY 1""", [desde, *p_act])}
    except sqlite3.OperationalError:
        return []
    # Desde cuándo se lleva la cola de remediación. Sin este dato la tabla pintaría once
    # meses a cero y un cero se lee como «no apareció nada», que sería falso: lo que pasa
    # es que antes de esa fecha no se guardaba la serie (2026-09-15).
    primera = primer_mes_de_remediacion(conn, seleccion)
    salida: list[dict[str, Any]] = []
    for i in range(meses - 1, -1, -1):
        mes = _mes_desplazado(mes_final, -i)
        if primera and mes < str(primera):
            continue          # antes de esa fecha no hay serie, y un cero mentiría
        n_det = detectadas.get(mes, 0)
        n_cor, dias = corregidas.get(mes, (0, None))
        salida.append({
            "mes": mes, "periodo": mes_largo(mes),
            "detectadas": n_det, "remediadas": n_cor, "saldo": n_det - n_cor,
            "dias_medios": None if dias is None else round(float(dias), 1),
        })
    return salida


def primer_mes_de_remediacion(conn: sqlite3.Connection, seleccion: Any) -> str:
    """Primer mes «AAAA-MM» con cola de remediación registrada, o cadena vacía si no hay.

    La plataforma empezó a llevar la cola el 4 de septiembre de 2026: un informe ejecutivo
    de agosto no puede decir «se detectaron 0 y se corrigieron 0», porque no es un cero,
    es una ausencia de dato. Con esta fecha el documento lo explica con todas las letras.
    """
    from . import remediacion
    sin_bajas = remediacion._y_sin_bajas(conn)
    sin_excepcion = remediacion._y_sin_excepcion(conn)
    where_act, p_act = seleccion.where_activos("a")
    union = " JOIN activos a ON a.id = r.activo_id" if where_act else ""
    try:
        fila = conn.execute(
            f"""SELECT MIN(substr(r.detectado_at, 1, 7)) FROM remediaciones r{union}
                 WHERE r.cve IS NOT NULL AND r.cve <> ''{sin_bajas}{sin_excepcion}{where_act}""",
            p_act).fetchone()
    except sqlite3.OperationalError:
        return ""
    return str(fila[0] or "") if fila else ""


def _parque_del_alcance(conn: sqlite3.Connection, seleccion: Any) -> dict[str, int]:
    """Cuántos activos presentes hay en el alcance, y de qué tipo."""
    where_act, p_act = seleccion.where_activos("a")
    try:
        fila = conn.execute(
            f"""SELECT COUNT(*) AS total,
                       SUM(a.origen='servidores') AS servidores,
                       SUM(a.origen='equipos')    AS equipos
                  FROM activos a WHERE a.presente=1{where_act}""", p_act).fetchone()
    except sqlite3.OperationalError:
        return {"total": 0, "servidores": 0, "equipos": 0}
    return {"total": int(fila["total"] or 0),
            "servidores": int(fila["servidores"] or 0),
            "equipos": int(fila["equipos"] or 0)}


def resumen_ejecutivo_mensual(conn: sqlite3.Connection, month: str, *, cfg,
                              seleccion: Any = None) -> dict[str, Any]:
    """Todas las cifras del informe ejecutivo mensual, sin escribir nada.

    Separado del documento a propósito: así las pruebas comprueban las cifras y las
    comparaciones sin abrir un ``.docx``, y la vista previa de ``/informes/`` podría
    enseñarlas el día que se pida.
    """
    from . import informe_seleccion as isel
    from . import remediacion

    sel = seleccion if seleccion is not None else _seleccion_del_mes(month)
    month = sel.mes_representativo()
    origen = getattr(sel, "origen_perfil", "") or ""

    # Serie de amenazas con el MISMO alcance y las mismas severidades que el informe.
    serie_amenazas = {e["month"]: e for e in isel.evolucion(conn, sel, meses=MESES_EJECUTIVO)}
    mes_anterior = _mes_desplazado(month, -1)
    mes_anio = _mes_desplazado(month, -12)
    vulns = _vulnerabilidades_por_mes(conn, sel, [month, mes_anterior, mes_anio])
    vacio = {"activos": 0, "vulnerabilidades": 0, "kev": 0}

    def amenazas_de(mes: str) -> Optional[dict]:
        return serie_amenazas.get(mes)

    def vulns_de(mes: str) -> Optional[dict]:
        if mes not in serie_amenazas and mes not in vulns:
            return None          # ese mes no existe en el histórico
        return vulns.get(mes, vacio)

    actual_amenazas = amenazas_de(month) or {"total": 0, "criticas": 0, "altas": 0,
                                             "medias": 0, "en_kev": 0}
    actual_vulns = vulns.get(month, vacio)
    parque = _parque_del_alcance(conn, sel)
    pendiente = remediacion.resumen(conn, dias=DIAS_VENTANA_EJECUTIVO,
                                    origen=origen or None)
    avance = _avance_por_mes(conn, sel)
    avance_desde = primer_mes_de_remediacion(conn, sel)

    # Las cuatro magnitudes que se comparan. «criticas_altas» se dice junta porque es la
    # que decide el plazo de actuación y una gerencia no separa 9 de 8.
    def compara(clave: str, valor_actual: Any, lectura, *, menos_es_mejor=True) -> dict:
        return {
            "clave": clave,
            "actual": int(valor_actual or 0),
            "mes_anterior": lectura(mes_anterior),
            "anio_anterior": lectura(mes_anio),
        }

    def lectura_amenazas(campo):
        def leer(mes):
            fila = amenazas_de(mes)
            return None if fila is None else int(fila.get(campo) or 0)
        return leer

    def lectura_criticas_altas(mes):
        fila = amenazas_de(mes)
        if fila is None:
            return None
        return int(fila.get("criticas") or 0) + int(fila.get("altas") or 0)

    def lectura_vulns(campo):
        def leer(mes):
            fila = vulns_de(mes)
            return None if fila is None else int(fila.get(campo) or 0)
        return leer

    magnitudes = [
        {"clave": "amenazas",
         "nombre": "Amenazas registradas en el mes",
         "unidad": "amenazas",
         "actual": int(actual_amenazas.get("total") or 0),
         "anterior": lectura_amenazas("total")(mes_anterior),
         "anio": lectura_amenazas("total")(mes_anio)},
        {"clave": "criticas_altas",
         "nombre": "De ellas, de severidad crítica o alta",
         "unidad": "amenazas",
         "actual": (int(actual_amenazas.get("criticas") or 0)
                    + int(actual_amenazas.get("altas") or 0)),
         "anterior": lectura_criticas_altas(mes_anterior),
         "anio": lectura_criticas_altas(mes_anio)},
        {"clave": "vulnerabilidades",
         "nombre": "Vulnerabilidades confirmadas en máquinas de la organización",
         "unidad": "vulnerabilidades",
         "actual": actual_vulns["vulnerabilidades"],
         "anterior": lectura_vulns("vulnerabilidades")(mes_anterior),
         "anio": lectura_vulns("vulnerabilidades")(mes_anio)},
        {"clave": "activos",
         "nombre": "Activos afectados",
         "unidad": "activos",
         "actual": actual_vulns["activos"],
         "anterior": lectura_vulns("activos")(mes_anterior),
         "anio": lectura_vulns("activos")(mes_anio)},
        {"clave": "kev",
         "nombre": "Vulnerabilidades con explotación activa confirmada",
         "unidad": "vulnerabilidades",
         "actual": actual_vulns["kev"],
         "anterior": lectura_vulns("kev")(mes_anterior),
         "anio": lectura_vulns("kev")(mes_anio)},
    ]
    for m in magnitudes:
        m["variacion_mes"] = _variacion(m["actual"], m["anterior"])
        m["variacion_anio"] = _variacion(m["actual"], m["anio"])

    # Avance del mes: lo detectado y lo remediado, y si la deuda sube o baja.
    del_mes = next((f for f in avance if f["mes"] == month), None)
    detectadas_mes = int((del_mes or {}).get("detectadas") or 0)
    remediadas_mes = int((del_mes or {}).get("remediadas") or 0)
    remediadas_total = sum(f["remediadas"] for f in avance)
    detectadas_total = sum(f["detectadas"] for f in avance)
    con_dias = [f["dias_medios"] for f in avance if f["dias_medios"] is not None]
    dias_medios_ano = round(sum(con_dias) / len(con_dias), 1) if con_dias else None

    parque_total = parque["total"] or 0
    return {
        "month": month,
        "periodo": mes_largo(month),
        "mes_anterior": mes_anterior,
        "periodo_anterior": mes_largo(mes_anterior),
        "mes_anio_anterior": mes_anio,
        "periodo_anio_anterior": mes_largo(mes_anio),
        "hay_anio_anterior": amenazas_de(mes_anio) is not None,
        "alcance_es": isel.etiqueta_alcance(conn, sel),
        "amenazas": actual_amenazas,
        "vulnerabilidades": actual_vulns["vulnerabilidades"],
        "vulnerabilidades_kev": actual_vulns["kev"],
        "activos_afectados": actual_vulns["activos"],
        "parque": parque,
        "pct_parque": (round(actual_vulns["activos"] * 100.0 / parque_total, 1)
                       if parque_total else 0.0),
        "magnitudes": magnitudes,
        "avance": avance,
        "detectadas_mes": detectadas_mes,
        "remediadas_mes": remediadas_mes,
        "saldo_mes": detectadas_mes - remediadas_mes,
        "detectadas_ano": detectadas_total,
        "remediadas_ano": remediadas_total,
        "saldo_ano": detectadas_total - remediadas_total,
        "dias_medios_mes": (del_mes or {}).get("dias_medios"),
        "dias_medios_ano": dias_medios_ano,
        "pendiente": pendiente,
        "dias_ventana": DIAS_VENTANA_EJECUTIVO,
        #: Primer mes con cola de remediación registrada («» si nunca se ha registrado).
        "avance_desde": avance_desde,
        "avance_posterior_al_mes": bool(avance_desde and avance_desde > month),
    }


# --------------------------------------------------------------------------
# El documento ejecutivo
# --------------------------------------------------------------------------
#: Tinta del documento ejecutivo: negro puro. El informe completo usa NEGRO (1F2933), que
#: en pantalla parece negro pero es un gris azulado, es decir, un color.
TINTA = RGBColor(0x00, 0x00, 0x00)
#: Gris de las notas y del pie del ejecutivo. Neutro (R=G=B), contraste 7,0:1 sobre blanco.
TINTA_SUAVE = RGBColor(0x59, 0x59, 0x59)
#: Sombreado de las filas de cabecera de tabla del ejecutivo: gris muy claro, el unico
#: «fondo» que sobrevive a una impresion en blanco y negro sin tapar el texto.
SOMBREADO_CABECERA = "D9D9D9"
#: Estilo de tabla del ejecutivo: rejilla negra. «Light Grid Accent 1», el del informe
#: mensual completo, dibuja los bordes con el color de acento (azul).
ESTILO_TABLA_EJECUTIVA = "Table Grid"

#: Atributos de tema que resuelven a un color del tema del documento (accent1, hlink…): se
#: quitan, porque un `w:themeColor="accent1"` pinta azul aunque el `w:val` diga gris.
_ATRIBUTOS_DE_TEMA = tuple(qn(f"w:{n}") for n in (
    "themeColor", "themeTint", "themeShade",
    "themeFill", "themeFillTint", "themeFillShade"))

#: Valores que NO son un color y se dejan tal cual.
_SIN_COLOR = {"auto", "none", "nil", "clear", ""}


def _a_gris(valor: Any) -> str:
    """Devuelve el gris de la misma luminosidad que el color recibido.

    «B3261E» (el rojo de severidad critica) sale «4A4A4A»; «FFFFFF» sigue siendo blanco.
    Se conserva la luminosidad para que lo que se veia oscuro siga viendose oscuro y el
    contraste con el fondo no empeore al quitar el color (2026-09-15).
    """
    texto = str(valor or "").strip().lstrip("#")
    if texto.lower() in _SIN_COLOR:
        return texto
    if len(texto) != 6:
        return "auto"
    try:
        rojo, verde, azul = (int(texto[i:i + 2], 16) for i in (0, 2, 4))
    except ValueError:
        return "auto"
    luz = round(0.299 * rojo + 0.587 * verde + 0.114 * azul)
    return f"{luz:02X}{luz:02X}{luz:02X}"


def _blanco_y_negro_en_xml(raiz) -> int:
    """Pasa a gris todo el color de un arbol de WordprocessingML; devuelve cuantos cambio.

    Actua sobre los tres sitios donde un `.docx` guarda color: el `w:val` de `<w:color>`
    (texto), el `w:fill` de `<w:shd>` (sombreado de celda o de parrafo) y el `w:color` de
    los bordes (`<w:top>`, `<w:tblBorders>`…). Ademas borra los atributos de tema y anula
    el resaltado.
    """
    cambios = 0
    etiqueta_color = qn("w:color")
    etiqueta_resaltado = qn("w:highlight")
    atributo_val = qn("w:val")
    atributo_fill = qn("w:fill")
    for elemento in raiz.iter():
        for atributo in _ATRIBUTOS_DE_TEMA:
            if elemento.get(atributo) is not None:
                del elemento.attrib[atributo]
                cambios += 1
        for atributo in (etiqueta_color, atributo_fill):
            valor = elemento.get(atributo)
            if valor is not None:
                gris = _a_gris(valor)
                if gris != valor:
                    elemento.set(atributo, gris)
                    cambios += 1
        if elemento.tag == etiqueta_color:
            valor = elemento.get(atributo_val)
            if valor is not None:
                gris = _a_gris(valor)
                if gris != valor:
                    elemento.set(atributo_val, gris)
                    cambios += 1
        elif elemento.tag == etiqueta_resaltado:
            if elemento.get(atributo_val) not in (None, "none"):
                elemento.set(atributo_val, "none")
                cambios += 1
    return cambios


#: Color en las partes del paquete que python-docx no expone como arbol (el tema y
#: `stylesWithEffects.xml`). Se trabaja ETIQUETA A ETIQUETA y no sobre el texto entero a
#: proposito: en el tema hay atributos `val` de seis cifras que NO son colores sino
#: porcentajes («<a:satMod val="300000"/>», «<a:tint val="100000"/>»), y convertirlos
#: dejaria el documento con valores invalidos.
_ETIQUETA_XML = re.compile(r"<[^>]+>")
#: Elementos cuyo atributo `val` SI es un color.
_ELEMENTOS_CON_VAL_DE_COLOR = ("srgbClr", "color")
_NOMBRE_DE_ETIQUETA = re.compile(r"<\s*/?\s*(?:\w+:)?(\w+)")
_ATRIBUTO_DE_COLOR = re.compile(r'(?P<antes>[\s:](?:color|fill|lastClr)=")'
                                r'(?P<color>[0-9A-Fa-f]{6})(?P<despues>")')
_VAL_DE_COLOR = re.compile(r'(?P<antes>[\s:]val=")(?P<color>[0-9A-Fa-f]{6})(?P<despues>")')
_TEMA_EN_TEXTO = re.compile(r'\s(?:w:)?theme(?:Color|Tint|Shade|Fill|FillTint|FillShade)'
                            r'="[^"]*"')


def _blanco_y_negro_en_texto(xml: bytes) -> tuple[bytes, int]:
    """Lo mismo, sobre las partes del paquete que no son un arbol de python-docx."""
    texto = xml.decode("utf-8", "replace")
    cuenta = 0

    def a_gris(encontrado) -> str:
        nonlocal cuenta
        gris = _a_gris(encontrado.group("color"))
        if gris.upper() != encontrado.group("color").upper():
            cuenta += 1
        return f'{encontrado.group("antes")}{gris}{encontrado.group("despues")}'

    def por_etiqueta(etiqueta) -> str:
        nonlocal cuenta
        crudo = etiqueta.group(0)
        nuevo = _ATRIBUTO_DE_COLOR.sub(a_gris, crudo)
        nombre = _NOMBRE_DE_ETIQUETA.match(crudo)
        if nombre and nombre.group(1) in _ELEMENTOS_CON_VAL_DE_COLOR:
            nuevo = _VAL_DE_COLOR.sub(a_gris, nuevo)
        nuevo, quitados = _TEMA_EN_TEXTO.subn("", nuevo)
        cuenta += quitados
        return nuevo

    return _ETIQUETA_XML.sub(por_etiqueta, texto).encode("utf-8"), cuenta


#: Relacion del paquete que apunta a la miniatura de vista previa (`thumbnail.jpeg`), la
#: unica pieza en color de la plantilla de python-docx que no es XML. Se quita del
#: ejecutivo: no la ve ningun lector del informe y no se puede pasar a gris sin un
#: codificador de imagen (el proyecto no instala ninguno).
_RELACION_MINIATURA = ("http://schemas.openxmlformats.org/package/2006/"
                       "relationships/metadata/thumbnail")


def _a_blanco_y_negro(doc: Document) -> int:
    """Deja el documento ENTERO sin un solo color: ni texto, ni sombreado, ni borde.

    Es la red de seguridad del informe ejecutivo: aunque manana alguien le anada un
    parrafo en rojo, el documento saldra en blanco y negro igual. Recorre todas las partes
    del paquete (cuerpo, estilos, pie, numeracion, tema) y devuelve cuantos colores ha
    neutralizado, que es lo que mide `tests/test_informe_ejecutivo_bn.py`.

    Solo lo llama `construir_documento_ejecutivo`: el informe mensual completo sigue en
    color, letra por letra, y hay una prueba que lo compara con el de siempre.
    """
    cambios = 0
    paquete = doc.part.package
    for parte in paquete.iter_parts():
        arbol = getattr(parte, "element", None)
        if arbol is not None:
            cambios += _blanco_y_negro_en_xml(arbol)
            continue
        nombre = str(parte.partname)
        if not nombre.endswith(".xml"):
            continue
        try:
            nuevo, cuenta = _blanco_y_negro_en_texto(parte.blob)
        except (AttributeError, ValueError, TypeError):
            continue
        if cuenta:
            parte._blob = nuevo
            cambios += cuenta
    for identificador, relacion in list(paquete.rels.items()):
        if relacion.reltype == _RELACION_MINIATURA:
            del paquete.rels[identificador]
            cambios += 1
    return cambios


def _preparar_documento_ejecutivo() -> Document:
    """El documento del ejecutivo: el de siempre, pero con los estilos en tinta negra.

    Los estilos de la plantilla de Word pintan los titulos en azul de acento. Se cambian
    AQUI, en el documento del ejecutivo, y no en `_preparar_documento`, que es el del
    informe mensual completo y no se toca.
    """
    doc = _preparar_documento()
    for nombre in ("Heading 1", "Heading 2", "Heading 3", "Title", "Subtitle"):
        try:
            estilo = doc.styles[nombre]
        except KeyError:
            continue
        estilo.font.color.rgb = TINTA
        estilo.font.bold = True
    doc.styles["Normal"].font.color.rgb = TINTA
    return doc


def _pie_ejecutivo(doc: Document, month: str) -> None:
    """Pie propio: dice que es el informe ejecutivo, para no confundirlo con el completo."""
    for seccion in doc.sections:
        parrafo = seccion.footer.paragraphs[0]
        parrafo.alignment = WD_ALIGN_PARAGRAPH.CENTER
        parrafo.text = ""
        parrafo.add_run(f"Informe ejecutivo de ciberseguridad · {mes_largo(month)} · "
                        f"Uso interno · Página ")
        _campo(parrafo, "PAGE")
        parrafo.add_run(" de ")
        _campo(parrafo, "NUMPAGES")
        for r in parrafo.runs:
            r.font.size = Pt(8)
            r.font.color.rgb = TINTA_SUAVE


def _tabla_ejecutiva(doc: Document, cabeceras: Sequence[str],
                     anchos: Optional[Sequence[float]] = None):
    """Tabla en blanco y negro: rejilla negra y cabecera en negrita sobre gris muy claro.

    Antes usaba «Light Grid Accent 1», que dibuja los bordes en azul de acento y distingue
    la cabecera SOLO por el color: impresa en blanco y negro, la fila de cabecera se
    confundia con la primera fila de datos. Ahora la cabecera se reconoce por tres cosas
    que no dependen del color: negrita, sombreado gris claro y borde inferior grueso.
    """
    tabla = doc.add_table(rows=1, cols=len(cabeceras))
    tabla.style = ESTILO_TABLA_EJECUTIVA
    tabla.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, texto in enumerate(cabeceras):
        celda = tabla.rows[0].cells[i]
        celda.text = texto
        _sombrear(celda, SOMBREADO_CABECERA)
        for p in celda.paragraphs:
            for r in p.runs:
                r.font.bold = True
                r.font.size = Pt(9)
                r.font.color.rgb = TINTA
    _repetir_cabecera(tabla.rows[0])
    if anchos:
        for fila in tabla.rows:
            for i, ancho in enumerate(anchos):
                if i < len(fila.cells):
                    fila.cells[i].width = Cm(ancho)
    return tabla


def _fila_ejecutiva(tabla, valores: Sequence[str], *, negrita_primera: bool = False,
                    tamano: float = 9.5,
                    versalitas: Optional[Sequence[int]] = None,
                    sombreado: Optional[str] = None) -> None:
    """Fila de datos. `versalitas` son las columnas cuyo texto lleva el juicio escrito.

    Las versalitas (y la negrita) sustituyen al color como forma de destacar: «EMPEORÓ» o
    «LA DEUDA SUBE EN 12» se leen igual en una fotocopia (2026-09-15).
    """
    marcadas = set(versalitas or ())
    celdas = tabla.add_row().cells
    for i, valor in enumerate(valores):
        celdas[i].text = str(valor)
        if sombreado:
            _sombrear(celdas[i], sombreado)
        for p in celdas[i].paragraphs:
            for r in p.runs:
                r.font.size = Pt(tamano)
                r.font.color.rgb = TINTA
                if i in marcadas:
                    r.font.small_caps = True
                    r.font.bold = True
                if i == 0 and negrita_primera:
                    r.font.bold = True


def _parrafo_ejecutivo(doc: Document, texto: str, *, tamano: float = 10.5,
                       cursiva: bool = False, color=None, rotulo: str = "",
                       versalitas: bool = False):
    """Parrafo del ejecutivo. `rotulo` es un encabezado en negrita delante del texto.

    El rotulo es el sustituto escrito del color en los parrafos que antes se distinguian
    por ser azules o grises: «Cómo leer estas cifras.», «Leyenda de la barra.» El color
    por omision es la tinta negra; `color=TINTA_SUAVE` deja el gris neutro de las notas.
    """
    p = doc.add_paragraph()
    if rotulo:
        cabeza = p.add_run(f"{rotulo} ")
        cabeza.font.size = Pt(tamano)
        cabeza.font.bold = True
        cabeza.font.small_caps = versalitas
        # El rotulo es el sustituto del color: va en negro aunque el texto vaya en gris.
        cabeza.font.color.rgb = TINTA
    r = p.add_run(texto)
    r.font.size = Pt(tamano)
    r.font.italic = cursiva
    r.font.color.rgb = color if color is not None else TINTA
    return p


def _ej_portada(doc: Document, datos: dict, *, cfg, seleccion: Any = None) -> None:
    """Portada: el mes, el alcance y las cuatro cifras que resumen la situación.

    Sin logo a propósito: este informe sale entero en blanco y negro para imprimirse y
    reenviarse (orden del usuario, 2026-09-15; ver ``construir_documento_ejecutivo`` y
    ``_a_blanco_y_negro``), y una imagen de marca en color rompería esa regla justo en
    la primera página. El nombre de la organización, al ser texto, sí se muestra.
    """
    doc.add_paragraph()
    doc.add_paragraph()

    titulo = doc.add_paragraph()
    titulo.alignment = WD_ALIGN_PARAGRAPH.CENTER
    encabezado = "INFORME EJECUTIVO\nDE CIBERSEGURIDAD"
    if seleccion is not None and (seleccion.titulo or "").strip() \
            and seleccion.titulo_personalizado():
        encabezado = seleccion.titulo.strip().upper()
    r = titulo.add_run(encabezado)
    r.font.size = Pt(26)
    r.font.bold = True
    # Antes iba en azul de marca. En blanco y negro la jerarquia la marcan el cuerpo de
    # letra y la negrita, que es lo que sobrevive a una impresion sin color (2026-09-15).
    r.font.color.rgb = TINTA

    empresa = (cfg.get("empresa_nombre") or "").strip() or "Mi Organización"
    for texto, tamano, negrita, versalitas in (
            (empresa, 15, True, True),
            ("Ciberseguridad", 11, False, False)):
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = p.add_run(texto)
        run.font.size = Pt(tamano)
        # El nombre de la empresa se distinguia por el azul claro; ahora, por las
        # versalitas y la negrita.
        run.font.color.rgb = TINTA if negrita else TINTA_SUAVE
        run.font.bold = negrita
        run.font.small_caps = versalitas

    periodo = doc.add_paragraph()
    periodo.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = periodo.add_run(f"MES: {datos['periodo'].upper()}")
    r.font.size = Pt(15)
    r.font.bold = True
    r.font.color.rgb = TINTA

    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p.add_run(f"Alcance: {datos['alcance_es']}")
    r.font.size = Pt(10.5)
    r.font.color.rgb = TINTA_SUAVE
    if seleccion is not None and (seleccion.destinatario or "").strip():
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r = p.add_run(f"Destinatario: {seleccion.destinatario.strip()}")
        r.font.size = Pt(10.5)
        r.font.color.rgb = TINTA_SUAVE

    doc.add_paragraph()

    parque = datos["parque"]["total"]
    pendiente = datos["pendiente"]
    tabla = _tabla_ejecutiva(doc, ("La situación en cuatro cifras", "Mes actual",
                                   "Respecto al mes anterior"), anchos=(8.6, 3.4, 4.6))
    por_clave = {m["clave"]: m for m in datos["magnitudes"]}
    for clave, nombre in (
            ("vulnerabilidades", "Vulnerabilidades confirmadas en máquinas de la organización"),
            ("activos", "Activos afectados"),
            ("kev", "Vulnerabilidades con explotación activa confirmada")):
        m = por_clave[clave]
        variacion = m["variacion_mes"]
        # La palabra («mejoró», «empeoró», «se mantiene») es la que dice si la cifra va
        # bien o mal: antes se apoyaba en el color de la fila, ahora va escrita y en
        # versalitas, que se leen igual en una fotocopia (2026-09-15).
        detalle = (f"{variacion['palabra']}: {variacion['texto']}"
                   if variacion["comparable"] else "sin dato del mes anterior")
        valor = _numero(m["actual"])
        if clave == "activos" and parque:
            valor = (f"{_numero(m['actual'])} de {_numero(parque)} "
                     f"({_decimal_es(datos['pct_parque'])} %)")
        _fila_ejecutiva(tabla, (nombre, valor, detalle), negrita_primera=True,
                        versalitas=(2,))
    _fila_ejecutiva(tabla, (
        "Trabajo pendiente hoy (vulnerabilidades por corregir)",
        _numero(pendiente.get("vulnerabilidades_unicas") or 0),
        f"{_numero(pendiente.get('corregidas_periodo') or 0)} corregidas "
        f"en los últimos {_numero(datos['dias_ventana'])} días"), negrita_primera=True)

    doc.add_paragraph()
    _parrafo_ejecutivo(
        doc,
        "Este documento resume el mes en diez páginas o menos: las cifras, cómo han "
        "cambiado respecto al mes anterior y al año pasado, cuánto se ha corregido y qué "
        "conviene decidir. No lleva detalle técnico; el detalle está en el informe "
        "mensual completo y en la plataforma. Está compuesto en blanco y negro a "
        "propósito, porque se imprime y se reenvía: ninguna cifra depende del color, y "
        "lo que antes decía un color («mejoró», «empeoró», «la deuda sube») va escrito "
        "con todas sus letras y en versalitas.",
        tamano=10, cursiva=True, color=TINTA_SUAVE, rotulo="Cómo leer este informe.")

    for texto in (f"Documento generado el {fecha_larga()}",
                  "Clasificación: uso interno"):
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r = p.add_run(texto)
        r.font.size = Pt(9)
        r.font.color.rgb = TINTA_SUAVE
    doc.add_page_break()


def _ej_cifras(doc: Document, datos: dict, *, numero: int = 1) -> None:
    """Las cifras del mes: lo que hay, a cuánto del parque afecta y qué queda por hacer."""
    doc.add_heading(f"{numero}. Las cifras del mes", level=1)
    parque = datos["parque"]
    pendiente = datos["pendiente"]

    _parrafo_ejecutivo(
        doc,
        f"En {datos['periodo']} la plataforma registró "
        f"{_numero(datos['amenazas'].get('total') or 0)} amenazas de seguridad, de las "
        f"que {_numero((datos['amenazas'].get('criticas') or 0) + (datos['amenazas'].get('altas') or 0))} "
        f"son de severidad crítica o alta. Lo que de verdad decide el trabajo no es esa "
        f"cifra, sino cuántas de ellas están confirmadas en máquinas nuestras: "
        f"{_numero(datos['vulnerabilidades'])} vulnerabilidades repartidas en "
        f"{_numero(datos['activos_afectados'])} activos de los {_numero(parque['total'])} "
        f"que hay en el inventario ({_decimal_es(datos['pct_parque'])} % del parque).")

    tabla = _tabla_ejecutiva(doc, ("Qué se mide", "Cifra del mes", "Qué significa"),
                             anchos=(5.4, 3.0, 8.2))
    _fila_ejecutiva(tabla, (
        "Amenazas registradas",
        f"{_numero(datos['amenazas'].get('total') or 0)} amenazas",
        "Avisos de seguridad publicados que afectan a tecnología que tenemos."),
        negrita_primera=True)
    _fila_ejecutiva(tabla, (
        "De severidad crítica o alta",
        f"{_numero((datos['amenazas'].get('criticas') or 0) + (datos['amenazas'].get('altas') or 0))} amenazas",
        "Las que exigen actuar en horas o en pocos días."), negrita_primera=True)
    _fila_ejecutiva(tabla, (
        "Vulnerabilidades confirmadas",
        f"{_numero(datos['vulnerabilidades'])} vulnerabilidades",
        "Cada una es un fallo concreto en una máquina concreta; es la unidad de trabajo."),
        negrita_primera=True)
    _fila_ejecutiva(tabla, (
        "Activos afectados",
        f"{_numero(datos['activos_afectados'])} de {_numero(parque['total'])} activos",
        f"{_decimal_es(datos['pct_parque'])} % del parque: "
        f"{_plural(parque['servidores'], 'servidor', 'servidores')} y "
        f"{_plural(parque['equipos'], 'equipo de cómputo', 'equipos de cómputo')} "
        f"en total."), negrita_primera=True)
    _fila_ejecutiva(tabla, (
        "Con explotación activa confirmada",
        f"{_numero(datos['vulnerabilidades_kev'])} vulnerabilidades",
        "Se están explotando en el mundo real; son las primeras de la cola."),
        negrita_primera=True)
    _fila_ejecutiva(tabla, (
        "Trabajo pendiente hoy",
        f"{_numero(pendiente.get('vulnerabilidades_unicas') or 0)} vulnerabilidades",
        f"Agrupadas en {_numero(pendiente.get('actualizaciones') or 0)} actualizaciones "
        f"por instalar, en {_numero(pendiente.get('activos_con_abiertas') or 0)} activos."),
        negrita_primera=True)

    if pendiente.get("esperando_datos_vulnerabilidades"):
        _parrafo_ejecutivo(
            doc,
            f"Aparte de lo anterior hay "
            f"{_plural(pendiente['esperando_datos_vulnerabilidades'], 'vulnerabilidad', 'vulnerabilidades')} en "
            f"{_plural(pendiente.get('esperando_datos_activos') or 0, 'activo')} que no se "
            f"{'puede' if int(pendiente.get('esperando_datos_activos') or 0) == 1 else 'pueden'} "
            f"ni corregir ni descartar porque "
            f"{'esa máquina no está' if int(pendiente.get('esperando_datos_activos') or 0) == 1 else 'esas máquinas no están'} "
            f"enviando su inventario. No cuentan como trabajo pendiente, pero tampoco "
            f"están resueltas: hace falta que el agente de inventario vuelva a reportar.",
            tamano=10)

    _parrafo_ejecutivo(
        doc,
        "«amenaza» es un aviso publicado y «vulnerabilidad» es ese aviso confirmado en una "
        "máquina nuestra. Una misma amenaza puede producir muchas vulnerabilidades (una "
        "por máquina) o ninguna, si no tenemos la versión afectada. La severidad baja no "
        "se cuenta en ninguna cifra de este informe.",
        tamano=9.5, cursiva=True, color=TINTA_SUAVE, rotulo="Cómo leer estas cifras.")


def _ej_comparacion(doc: Document, datos: dict, *, numero: int = 2) -> None:
    """Mes actual frente al mes anterior y frente al mismo mes del año pasado."""
    doc.add_heading(f"{numero}. Comparación con el mes anterior y con el año pasado",
                    level=1)

    hay_anio = datos["hay_anio_anterior"]
    cabeceras = ["Qué se compara", datos["periodo"].capitalize(),
                 datos["periodo_anterior"].capitalize(), "Variación en el mes"]
    anchos = [5.0, 2.8, 2.8, 6.0]
    if hay_anio:
        cabeceras[3:3] = [datos["periodo_anio_anterior"].capitalize()]
        anchos = [4.2, 2.4, 2.4, 2.4, 5.2]
    tabla = _tabla_ejecutiva(doc, cabeceras, anchos=anchos)
    for m in datos["magnitudes"]:
        variacion = m["variacion_mes"]
        valores = [m["nombre"], _numero(m["actual"]),
                   _numero(m["anterior"]) if m["anterior"] is not None else "sin dato"]
        if hay_anio:
            valores.append(_numero(m["anio"]) if m["anio"] is not None else "sin dato")
        valores.append(f"{variacion['palabra'].capitalize()}: {variacion['texto']}"
                       if variacion["comparable"] else "sin dato del mes anterior")
        # Ultima columna: el juicio escrito, en versalitas y negrita. Es lo que sustituye
        # al color de la fila (verde mejora, rojo empeora) del informe en color.
        _fila_ejecutiva(tabla, valores, negrita_primera=True, tamano=9,
                        versalitas=(len(valores) - 1,))

    por_clave = {m["clave"]: m for m in datos["magnitudes"]}
    vulnerabilidades = por_clave["vulnerabilidades"]
    activos = por_clave["activos"]
    kev = por_clave["kev"]
    frases = []
    if vulnerabilidades["variacion_mes"]["comparable"]:
        frases.append(
            f"Frente a {datos['periodo_anterior']}, el número de vulnerabilidades "
            f"confirmadas {vulnerabilidades['variacion_mes']['palabra']}: "
            f"{vulnerabilidades['variacion_mes']['texto']}.")
    if activos["variacion_mes"]["comparable"]:
        frases.append(
            f"El número de máquinas afectadas "
            f"{activos['variacion_mes']['palabra']} "
            f"({activos['variacion_mes']['texto']}).")
    if kev["variacion_mes"]["comparable"]:
        frases.append(
            f"Lo que se está explotando ahora mismo "
            f"{kev['variacion_mes']['palabra']}: {kev['variacion_mes']['texto']}.")
    if frases:
        _parrafo_ejecutivo(doc, " ".join(frases))

    if hay_anio:
        anuales = [m for m in datos["magnitudes"] if m["variacion_anio"]["comparable"]]
        if anuales:
            _parrafo_ejecutivo(
                doc,
                "Frente al mismo mes del año pasado ("
                + f"{datos['periodo_anio_anterior']}): "
                + "; ".join(f"{m['nombre'].lower()}, {m['variacion_anio']['palabra']} "
                            f"({m['variacion_anio']['texto']})" for m in anuales) + ".")
    else:
        _parrafo_ejecutivo(
            doc,
            f"No hay comparación con {datos['periodo_anio_anterior']}: la plataforma no "
            f"tiene datos de ese mes, porque empezó a registrar después. La comparación "
            f"entre años estará disponible cuando el histórico llegue a doce meses; "
            f"mientras tanto, la referencia válida es el mes anterior.",
            tamano=10, cursiva=True, color=TINTA_SUAVE)

    _parrafo_ejecutivo(
        doc,
        "Que una cifra suba no siempre es malo ni bajar siempre bueno: más amenazas "
        "registradas puede significar que se vigilan más fuentes, y menos activos "
        "afectados puede significar que se corrigió o que una máquina dejó de reportar. "
        "Por eso al lado de cada variación se dice con todas sus letras, en versalitas, si "
        "MEJORÓ, EMPEORÓ o SE MANTIENE según el criterio de riesgo, y el apartado "
        "siguiente enseña el trabajo hecho de verdad.",
        tamano=9.5, cursiva=True, color=TINTA_SUAVE,
        rotulo="Cómo se lee cada variación.")


def _ej_avance(doc: Document, datos: dict, *, numero: int = 3) -> None:
    """Detectadas y remediadas mes a mes: si la deuda sube o baja y cuánto se tarda."""
    doc.add_heading(f"{numero}. Avance mes a mes: detectadas y remediadas", level=1)
    avance = datos["avance"]

    if not avance:
        if datos.get("avance_posterior_al_mes"):
            _parrafo_ejecutivo(
                doc,
                f"Para {datos['periodo']} no hay serie de vulnerabilidades detectadas y "
                f"corregidas: la plataforma empezó a llevar la cola de remediación en "
                f"{mes_largo(datos['avance_desde'])}, después de ese mes. No se escriben "
                f"ceros porque no serían ceros, sería una ausencia de dato. El avance "
                f"se puede leer en los informes ejecutivos de "
                f"{mes_largo(datos['avance_desde'])} en adelante.")
        else:
            _parrafo_ejecutivo(
                doc,
                "Todavía no hay serie de vulnerabilidades detectadas y corregidas: la cola "
                "de remediación empieza a registrarse con la primera sincronización. En "
                "cuanto haya un mes completo, este apartado enseñará el avance.")
        return

    tabla = _tabla_ejecutiva(
        doc, ("Mes", "Detectadas", "Remediadas", "Saldo del mes",
              "Días medios en corregir", "Detectadas frente a remediadas"),
        anchos=(2.6, 2.0, 2.0, 2.2, 2.4, 5.6))
    maximo = max([max(f["detectadas"], f["remediadas"]) for f in avance] or [0])
    for f in avance:
        saldo = f["saldo"]
        texto_saldo = ("la deuda baja en " + _numero(abs(saldo)) if saldo < 0
                       else ("sin cambio" if saldo == 0
                             else "la deuda sube en " + _numero(saldo)))
        dias = ("sin correcciones" if f["dias_medios"] is None
                else f"{_decimal_es(f['dias_medios'])} días")
        barra = (f"D {_barra(f['detectadas'], maximo, ancho=12)}\n"
                 f"R {_barra(f['remediadas'], maximo, ancho=12)}")
        # El saldo va en versalitas: es el juicio del mes («la deuda sube» / «baja»), que
        # en el informe en color se apoyaba en el color de la celda (2026-09-15).
        _fila_ejecutiva(tabla, (f["periodo"].capitalize(), _numero(f["detectadas"]),
                                _numero(f["remediadas"]), texto_saldo, dias, barra),
                        negrita_primera=True, tamano=9, versalitas=(3,))
    _parrafo_ejecutivo(
        doc, "las dos barras de la última columna no llevan color: la de arriba, marcada "
             "con «D», son las vulnerabilidades DETECTADAS y la de abajo, marcada con «R», "
             "las REMEDIADAS. Cada barra se dibuja con bloques llenos (█) sobre una escala "
             "de huecos (░) del mismo largo para todos los meses, así que la barra más "
             "llena de la tabla es el mes con más movimiento. Las cifras exactas están en "
             "las columnas «Detectadas» y «Remediadas» de esa misma fila.",
        tamano=9, cursiva=True, color=TINTA_SUAVE, rotulo="Leyenda de las barras.")

    saldo = datos["saldo_mes"]
    if saldo > 0:
        juicio = (f"la deuda creció en {_numero(saldo)} vulnerabilidades: se detectaron "
                  f"más de las que se cerraron")
    elif saldo < 0:
        juicio = (f"la deuda bajó en {_numero(abs(saldo))} vulnerabilidades: se cerraron "
                  f"más de las que aparecieron")
    else:
        juicio = "la deuda quedó igual: se cerraron tantas como aparecieron"
    dias_mes = datos["dias_medios_mes"]
    _parrafo_ejecutivo(
        doc,
        f"En {datos['periodo']} aparecieron {_numero(datos['detectadas_mes'])} "
        f"vulnerabilidades y se corrigieron {_numero(datos['remediadas_mes'])}, de modo "
        f"que {juicio}. "
        + (f"Lo que se corrigió tardó {_decimal_es(dias_mes)} días de media desde que se "
           f"detectó." if dias_mes is not None
           else "Este mes no se cerró ninguna, así que no hay tiempo medio que dar."))

    if len(avance) == 1:
        _parrafo_ejecutivo(
            doc,
            f"Es el primer mes de la serie: la cola de remediación se empezó a registrar "
            f"en {avance[0]['periodo']}, así que todavía no hay mes anterior con el que "
            f"comparar el avance. Los meses anteriores no se pintan a cero porque no "
            f"serían un cero, sino una ausencia de dato. A partir del mes que viene esta "
            f"tabla compara mes contra mes.",
            tamano=10, cursiva=True, color=TINTA_SUAVE)
        semanas = [s for s in (datos["pendiente"].get("semanas") or [])
                   if not s.get("sin_datos")]
        if semanas:
            _parrafo_ejecutivo(
                doc,
                "Mientras tanto, el avance de las últimas semanas, con las mismas dos "
                "magnitudes:")
            tabla = _tabla_ejecutiva(doc, ("Semana", "Detectadas", "Remediadas"),
                                     anchos=(7.0, 4.8, 4.8))
            for s in semanas:
                _fila_ejecutiva(tabla, (s.get("etiqueta_larga") or s.get("etiqueta") or "",
                                        _numero(s.get("detectadas") or 0),
                                        _numero(s.get("corregidas") or 0)),
                                negrita_primera=True, tamano=9)
    else:
        _parrafo_ejecutivo(
            doc,
            f"En los {_numero(len(avance))} meses de la serie han aparecido "
            f"{_numero(datos['detectadas_ano'])} vulnerabilidades y se han corregido "
            f"{_numero(datos['remediadas_ano'])}"
            + (f", con una media de {_decimal_es(datos['dias_medios_ano'])} días desde la "
               f"detección hasta la corrección." if datos["dias_medios_ano"] is not None
               else "."))


def _ej_pendiente(doc: Document, datos: dict, *, numero: int = 4) -> None:
    """Dónde está el trabajo que queda: cuánto, en cuántas máquinas y de quién es."""
    doc.add_heading(f"{numero}. Dónde está el trabajo pendiente", level=1)
    pendiente = datos["pendiente"]
    vulnerables = int(pendiente.get("vulnerabilidades_unicas") or 0)
    actualizaciones = int(pendiente.get("actualizaciones") or 0)
    sin_version = int(pendiente.get("actualizaciones_sin_version") or 0)
    activos = int(pendiente.get("activos_con_abiertas") or 0)
    parque = datos["parque"]["total"]

    _parrafo_ejecutivo(
        doc,
        f"Hoy quedan {_plural(vulnerables, 'vulnerabilidad', 'vulnerabilidades')} por "
        f"corregir en {_plural(activos, 'activo')}"
        + (f" de los {_numero(parque)} del inventario" if parque else "")
        + f". No son {_numero(vulnerables)} tareas distintas: se agrupan en "
        f"{_plural(actualizaciones, 'actualización', 'actualizaciones')}, porque una sola "
        f"actualización suele cerrar varias vulnerabilidades de la misma máquina."
        + (f" De esas actualizaciones, {_numero(sin_version)} todavía no se pueden hacer: "
           f"el fabricante no ha publicado la versión que corrige."
           if sin_version else ""))

    procesos = [p for p in (pendiente.get("por_proceso") or [])
                if int(p.get("vulnerables") or 0)][:PROCESOS_EJECUTIVO]
    if procesos:
        tabla = _tabla_ejecutiva(
            doc, ("Proceso de negocio", "Vulnerabilidades por corregir",
                  "Activos implicados", f"Corregidas en {datos['dias_ventana']} días"),
            anchos=(6.0, 3.6, 2.8, 4.2))
        for p in procesos:
            _fila_ejecutiva(tabla, (
                p.get("proceso") or "Sin proceso asignado",
                _numero(p.get("vulnerables") or 0),
                _numero(p.get("activos_con_abiertas") or 0),
                _numero(p.get("vulnerables_corregidas") or 0)), negrita_primera=True,
                tamano=9)
        _parrafo_ejecutivo(
            doc,
            (f"El proceso con más trabajo pendiente." if len(procesos) == 1 else
             f"Los {_numero(len(procesos))} procesos con más trabajo pendiente.")
            + " El reparto completo está en la plataforma; aquí interesa saber a qué áreas "
              "hay que pedirles ventana de mantenimiento. La tabla está ordenada de más a "
              "menos trabajo pendiente: la primera fila es la que más pesa.",
            tamano=9.5, cursiva=True, color=TINTA_SUAVE)

    if datos["vulnerabilidades_kev"]:
        _parrafo_ejecutivo(
            doc,
            f"De todo lo anterior, lo urgente son las "
            f"{_numero(datos['vulnerabilidades_kev'])} vulnerabilidades con explotación "
            f"activa confirmada de este mes: se sabe que alguien las está usando para "
            f"atacar, así que van antes que cualquier otra cosa con independencia de su "
            f"puntuación técnica.")


def _ej_recomendacion(doc: Document, datos: dict, *, numero: int = 5) -> None:
    """Tres o cuatro decisiones concretas, con lo que cambia si se toman."""
    doc.add_heading(f"{numero}. Qué conviene hacer el mes que viene", level=1)
    pendiente = datos["pendiente"]
    puntos: list[tuple[str, str]] = []

    if datos["vulnerabilidades_kev"]:
        puntos.append((
            f"Cerrar este mes las {_numero(datos['vulnerabilidades_kev'])} "
            f"vulnerabilidades con explotación activa confirmada.",
            "Es el riesgo que se está materializando hoy en otras organizaciones; "
            "cerrarlas quita de encima la parte del riesgo que ya tiene a alguien "
            "explotándola."))

    saldo = datos["saldo_mes"]
    hay_serie = bool(datos["avance"])
    primer_mes = len(datos["avance"]) <= 1
    if not hay_serie:
        # Sin serie no se puede hablar de ritmo de cierre sin mentir: se recomienda lo
        # único que las cifras sí sostienen, que es atacar la cola pendiente de hoy.
        pendientes = int(pendiente.get("vulnerabilidades_unicas") or 0)
        if pendientes:
            puntos.append((
                f"Reducir la cola de "
                f"{_plural(pendientes, 'vulnerabilidad', 'vulnerabilidades')} pendientes, "
                f"empezando por los procesos con más trabajo acumulado.",
                f"Están agrupadas en "
                f"{_plural(pendiente.get('actualizaciones') or 0, 'actualización', 'actualizaciones')}: "
                f"cada una cierra varias vulnerabilidades de la misma máquina, así que el "
                f"esfuerzo rinde más de lo que la cifra de vulnerabilidades sugiere."))
    elif saldo > 0 and primer_mes:
        # El primer mes de la serie no sirve de ritmo: la cola se llena de golpe con todo
        # lo que ya existía, así que proponer «cerrar tantas como aparecieron» sería
        # proponer un imposible. Se propone fijar el objetivo y medirlo.
        puntos.append((
            f"Fijar un objetivo de cierre para el mes que viene y medirlo contra lo que "
            f"aparezca, empezando por las "
            f"{_plural(saldo, 'vulnerabilidad', 'vulnerabilidades')} que han quedado "
            f"abiertas este mes.",
            f"Este mes se cerraron {_numero(datos['remediadas_mes'])} de las "
            f"{_numero(datos['detectadas_mes'])} que aparecieron, pero es el primer mes "
            f"de la serie y la cola arrancó con todo el trabajo acumulado: sin un objetivo "
            f"escrito no habrá con qué comparar el mes que viene."))
    elif saldo > 0:
        puntos.append((
            f"Fijar un objetivo de cierre mensual por encima de "
            f"{_numero(datos['detectadas_mes'])} vulnerabilidades, que es el ritmo al que "
            f"están apareciendo.",
            f"Este mes se cerraron {_numero(datos['remediadas_mes'])} y la deuda subió en "
            f"{_numero(saldo)}. Sin un objetivo por encima del ritmo de aparición, la cola "
            f"crece sola aunque se trabaje todos los días."))
    else:
        puntos.append((
            "Mantener el ritmo de cierre alcanzado este mes.",
            f"Se cerraron {_numero(datos['remediadas_mes'])} vulnerabilidades frente a "
            f"{_numero(datos['detectadas_mes'])} aparecidas: la cola baja. Mantenerlo es "
            f"lo que hace que el mes que viene se empiece con menos trabajo."))

    procesos = [p for p in (pendiente.get("por_proceso") or [])
                if int(p.get("vulnerables") or 0)]
    if procesos:
        primero = procesos[0]
        puntos.append((
            f"Acordar ventana de mantenimiento con «{primero.get('proceso') or 'el área con más trabajo'}», "
            f"que concentra {_numero(primero.get('vulnerables') or 0)} vulnerabilidades por "
            f"corregir.",
            "Concentrar el esfuerzo donde está la mayor parte del trabajo cierra más "
            "riesgo por hora dedicada que repartirlo por igual entre todas las áreas."))

    esperando = int(pendiente.get("esperando_datos_vulnerabilidades") or 0)
    sin_reportar = int(pendiente.get("esperando_datos_activos") or 0)
    if esperando:
        uno = sin_reportar == 1
        puntos.append((
            ("Recuperar el inventario del activo que no está reportando." if uno else
             f"Recuperar el inventario de los {_numero(sin_reportar)} activos que no están "
             f"reportando."),
            f"Sobre {'esa máquina' if uno else 'esas máquinas'} "
            f"hay {_plural(esperando, 'vulnerabilidad', 'vulnerabilidades')} que no se "
            f"pueden ni corregir ni descartar: mientras no "
            f"{'reporte' if uno else 'reporten'}, no sabemos si "
            f"{'está al día o expuesta' if uno else 'están al día o expuestas'}."))
    elif int(pendiente.get("actualizaciones_sin_version") or 0):
        puntos.append((
            f"Revisar las {_numero(pendiente['actualizaciones_sin_version'])} "
            f"actualizaciones que todavía no tienen versión que instalar.",
            "No se pueden cerrar con un parche: hay que decidir si se acepta el riesgo por "
            "escrito, con responsable y fecha de vencimiento, o si se retira o se aísla la "
            "tecnología afectada."))

    # Tres o cuatro puntos como mucho: si salieran más, manda el orden de riesgo.
    for i, (que, porque) in enumerate(puntos[:4], start=1):
        p = doc.add_paragraph()
        r = p.add_run(f"{i}. {que}")
        r.font.bold = True
        r.font.size = Pt(10.5)
        r.font.color.rgb = TINTA
        # El rotulo en negrita hace de separador entre la decision y su efecto: antes los
        # distinguia el gris del segundo parrafo, que impreso se pierde (2026-09-15).
        _parrafo_ejecutivo(doc, porque, tamano=10, color=TINTA_SUAVE,
                           rotulo="Qué cambia si se hace:")

    _parrafo_ejecutivo(
        doc,
        "Este informe se genera solo con los datos de la plataforma el último día de cada "
        "mes. El detalle técnico de todo lo anterior —qué vulnerabilidad, en qué máquina y "
        "qué hay que instalar— está en el informe mensual completo y en la plataforma; "
        "aquí se ha dejado fuera a propósito.",
        tamano=9.5, cursiva=True, color=TINTA_SUAVE)


def construir_documento_ejecutivo(conn: sqlite3.Connection, month: str, *, cfg,
                                  filtros: Any = None) -> Document:
    """El informe ejecutivo mensual, sin guardarlo. Diez páginas como máximo.

    No comparte una sola línea con :func:`construir_documento`: son dos documentos con dos
    propósitos distintos, y el mensual completo tiene una prueba que lo compara párrafo a
    párrafo con el de siempre.

    Desde el 2026-09-15 sale **entero en blanco y negro** (orden del usuario: se imprime y
    se reenvía). Lo que antes decía el color lo dice ahora la palabra: la variación en
    versalitas («MEJORÓ», «EMPEORÓ»), el saldo de la deuda escrito, la leyenda de las dos
    barras y los rótulos en negrita de las notas. El informe mensual completo NO cambia.
    """
    datos = resumen_ejecutivo_mensual(conn, month, cfg=cfg, seleccion=filtros)
    log.info("generando informe ejecutivo", extra={
        "month": datos["month"], "vulnerabilidades": datos["vulnerabilidades"],
        "activos_afectados": datos["activos_afectados"],
        "meses_de_serie": len(datos["avance"])})

    doc = _preparar_documento_ejecutivo()
    _ej_portada(doc, datos, cfg=cfg, seleccion=filtros)
    _ej_cifras(doc, datos, numero=1)
    _ej_comparacion(doc, datos, numero=2)
    _ej_avance(doc, datos, numero=3)
    _ej_pendiente(doc, datos, numero=4)
    _ej_recomendacion(doc, datos, numero=5)
    _pie_ejecutivo(doc, datos["month"])
    # Ultimo paso, siempre: el documento se imprime y se reenvia en blanco y negro, asi
    # que no puede salir de aqui con un solo color, ni propio ni heredado de la plantilla.
    neutralizados = _a_blanco_y_negro(doc)
    log.info("informe ejecutivo en blanco y negro",
             extra={"month": datos["month"], "colores_neutralizados": neutralizados})
    return doc


def generar_ejecutivo_en_memoria(conn: sqlite3.Connection, month: str, *, cfg,
                                 filtros: Any = None) -> bytes:
    """El informe ejecutivo como bytes de un ``.docx``, sin tocar el disco."""
    import io
    memoria = io.BytesIO()
    construir_documento_ejecutivo(conn, month, cfg=cfg, filtros=filtros).save(memoria)
    datos = memoria.getvalue()
    log.info("informe ejecutivo generado en memoria",
             extra={"month": month, "kb": round(len(datos) / 1024, 1)})
    return datos


def nombre_fichero_ejecutivo(month: str) -> str:
    """«Informe_Ejecutivo_2026_09.docx», al lado del mensual completo."""
    return f"Informe_Ejecutivo_{str(month).replace('-', '_')}.docx"


def generar_ejecutivo(conn: sqlite3.Connection, month: str, *, cfg,
                      destino: Optional[Path] = None) -> Path:
    """Genera el informe ejecutivo mensual, lo guarda y devuelve la ruta del ``.docx``.

    Lo llama la ejecución mensual programada (``bin/ejecucion_mensual.py``) junto al
    informe completo: son dos ficheros y dos documentos, y el completo no cambia.
    """
    doc = construir_documento_ejecutivo(conn, month, cfg=cfg)
    ruta = Path(destino) if destino else report_file(month).parent / nombre_fichero_ejecutivo(month)
    ruta.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(ruta))
    try:
        ruta.chmod(0o640)
    except OSError:
        pass
    log.info("informe ejecutivo generado", extra={
        "ruta": str(ruta), "kb": round(ruta.stat().st_size / 1024, 1)})
    return ruta

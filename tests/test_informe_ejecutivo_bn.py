"""El informe ejecutivo mensual, entero en blanco y negro (2026-09-15).

Orden literal del usuario:

    «solo se debe ajustar el color donde todo debe ser a blanco y negro»

El informe ejecutivo se imprime y se reenvía. En una impresora sin color, dos grises
claros dejan de distinguirse: el color no solo no aporta, engaña. Por eso el documento
sale en tinta negra y grises neutros, y **todo lo que antes decía el color se dice ahora
por escrito**.

Lo que fijan estas pruebas:

* en el paquete ``.docx`` **no queda ni un color**: ni en el texto, ni en el sombreado de
  las celdas, ni en los bordes, ni en los estilos heredados de la plantilla de Word, ni en
  el tema, ni en la miniatura de vista previa;
* el PDF, cuando hay LibreOffice para generarlo, **no tiene un solo píxel de color**;
* la información que transmitía el color sigue estando, escrita: la variación en
  versalitas («MEJORÓ», «EMPEORÓ», «SE MANTIENE»), el saldo de la deuda con todas sus
  letras, la leyenda de las dos barras y los rótulos en negrita de las notas;
* la cabecera de cada tabla se reconoce sin color (negrita y sombreado gris muy claro);
* **el informe mensual completo NO cambia**: sigue en color, y hay una prueba que lo
  comprueba aquí mismo además de la comparación párrafo a párrafo de
  ``tests/test_informes_medida.py``.

Ejecución:
    sudo -n -u si .venv/bin/python -m unittest tests.test_informe_ejecutivo_bn
"""
from __future__ import annotations

import io
import re
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

from docx import Document
from docx.shared import Pt, RGBColor

from threatintel import db, report
from threatintel.paths import BASE_DIR

from tests.test_informe_ejecutivo import MES, ConfiguracionFalsa, _sembrar

#: Cada etiqueta del XML, para mirar el color con su contexto.
_ETIQUETA = re.compile(r"<[^>]+>")
#: Nombre de la etiqueta, sin el prefijo de espacio de nombres.
_NOMBRE = re.compile(r"<\s*/?\s*(?:\w+:)?(\w+)")
#: Atributos que SIEMPRE son un color, sea cual sea la etiqueta.
_ATRIBUTO = re.compile(r'[\s:](?:color|fill|lastClr)="#?([0-9A-Fa-f]{6})"')
#: `val` solo es un color en estas etiquetas: en el tema hay `val` de seis cifras que son
#: PORCENTAJES («<a:satMod val="300000"/>»), no colores, y contarlos sería una falsa alarma.
_ETIQUETAS_CON_VAL_DE_COLOR = ("srgbClr", "color")
_VAL = re.compile(r'[\s:]val="#?([0-9A-Fa-f]{6})"')
#: Atributos que resuelven a un color del tema («accent1» es azul aunque no lo parezca).
_TEMA = re.compile(r'theme(?:Color|Fill)="([^"]+)"')


def _es_color(valor: str) -> bool:
    """¿Es un color de verdad, o un gris (R=G=B), que sí vale en blanco y negro?"""
    v = valor.strip().lstrip("#").upper()
    return not (v[0:2] == v[2:4] == v[4:6])


def colores_del_docx(datos: bytes) -> list[str]:
    """Todos los colores que quedan en un ``.docx``, parte por parte.

    Es la comprobación que pidió el usuario: «verifica que no queda ningún color (por
    ejemplo extrayendo los colores del XML del .docx: w:color, w:fill, w:val de sombreados
    y bordes)». Mira TODAS las partes del paquete, no solo el cuerpo: los estilos de la
    plantilla de Word y el tema pintan igual.
    """
    encontrados: list[str] = []
    with zipfile.ZipFile(io.BytesIO(datos)) as paquete:
        for nombre in paquete.namelist():
            if not nombre.endswith((".xml", ".rels")):
                encontrados.append(f"{nombre}: pieza que no es XML (puede llevar color)")
                continue
            texto = paquete.read(nombre).decode("utf-8", "replace")
            for etiqueta in _ETIQUETA.findall(texto):
                valores = list(_ATRIBUTO.findall(etiqueta))
                marca = _NOMBRE.match(etiqueta)
                if marca and marca.group(1) in _ETIQUETAS_CON_VAL_DE_COLOR:
                    valores.extend(_VAL.findall(etiqueta))
                for valor in valores:
                    if _es_color(valor):
                        encontrados.append(f"{nombre}: {valor}")
                for valor in _TEMA.findall(etiqueta):
                    encontrados.append(f"{nombre}: themeColor={valor}")
    return encontrados


def _texto(doc) -> str:
    partes = [p.text for p in doc.paragraphs]
    for tabla in doc.tables:
        for fila in tabla.rows:
            partes.extend(c.text for c in fila.cells)
    return "\n".join(partes)


def _celdas(doc):
    for tabla in doc.tables:
        for fila in tabla.rows:
            for celda in fila.cells:
                yield celda


def _pixeles_de_color(datos: bytes) -> int:
    """Píxeles con color de la primera página del documento, o -1 si no hay con qué medir.

    Convierte a PDF con LibreOffice y lo rasteriza con ``pdftoppm``; después cuenta los
    píxeles en los que los tres canales no coinciden. Es la comprobación definitiva: mide
    lo que se ve, no lo que dice el XML.
    """
    soffice, pdftoppm = shutil.which("soffice"), shutil.which("pdftoppm")
    if not soffice or not pdftoppm:
        return -1
    with tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data")) as tmp:
        docx = Path(tmp) / "ejecutivo.docx"
        docx.write_bytes(datos)
        try:
            subprocess.run([soffice, "--headless", "--convert-to", "pdf", "--outdir", tmp,
                            str(docx)], check=True, capture_output=True, timeout=180)
            subprocess.run([pdftoppm, "-r", "60", "-f", "1", "-l", "1",
                            str(Path(tmp) / "ejecutivo.pdf"), str(Path(tmp) / "pagina")],
                           check=True, capture_output=True, timeout=120)
        except (subprocess.SubprocessError, OSError):
            return -1
        imagenes = sorted(Path(tmp).glob("pagina-*.ppm"))
        if not imagenes:
            return -1
        crudo = imagenes[0].read_bytes().split(b"\n", 3)[3]
        return sum(1 for i in range(0, len(crudo) - 2, 3)
                   if not (crudo[i] == crudo[i + 1] == crudo[i + 2]))


# ==========================================================================
# 1. La pieza que quita el color
# ==========================================================================
class TestGris(unittest.TestCase):
    """`_a_gris` conserva la luminosidad: lo oscuro sigue oscuro."""

    def test_un_rojo_se_convierte_en_gris(self):
        self.assertEqual(report._a_gris("B3261E"), "4F4F4F")

    def test_el_blanco_sigue_siendo_blanco(self):
        self.assertEqual(report._a_gris("FFFFFF"), "FFFFFF")

    def test_el_negro_sigue_siendo_negro(self):
        self.assertEqual(report._a_gris("000000"), "000000")

    def test_un_gris_no_cambia(self):
        self.assertEqual(report._a_gris("595959"), "595959")

    def test_automatico_se_respeta(self):
        self.assertEqual(report._a_gris("auto"), "auto")

    def test_un_valor_ilegible_no_rompe_el_documento(self):
        self.assertEqual(report._a_gris("azul celeste"), "auto")
        self.assertEqual(report._a_gris(None), "")


class TestNeutralizador(unittest.TestCase):
    """`_a_blanco_y_negro` deja sin color hasta lo que se meta a mano."""

    def test_quita_el_color_del_texto_del_sombreado_y_del_borde(self):
        doc = report._preparar_documento_ejecutivo()
        parrafo = doc.add_paragraph()
        run = parrafo.add_run("Vulnerabilidad crítica")
        run.font.color.rgb = RGBColor(0xB3, 0x26, 0x1E)
        run.font.size = Pt(11)
        tabla = doc.add_table(rows=1, cols=1)
        tabla.style = "Light Grid Accent 1"
        report._sombrear(tabla.rows[0].cells[0], "FDECEA")
        memoria = io.BytesIO()
        doc.save(memoria)
        self.assertTrue(colores_del_docx(memoria.getvalue()),
                        "el documento de partida tenía que tener color")

        cambios = report._a_blanco_y_negro(doc)
        self.assertGreater(cambios, 0)
        memoria = io.BytesIO()
        doc.save(memoria)
        self.assertEqual(colores_del_docx(memoria.getvalue()), [])
        # Y el texto sigue ahí: quitar el color no borra información.
        self.assertIn("Vulnerabilidad crítica", _texto(Document(io.BytesIO(memoria.getvalue()))))

    def test_dos_pasadas_seguidas_no_cambian_nada_mas(self):
        doc = report._preparar_documento_ejecutivo()
        doc.add_paragraph("Sin color")
        report._a_blanco_y_negro(doc)
        self.assertEqual(report._a_blanco_y_negro(doc), 0)


# ==========================================================================
# 2. El documento completo
# ==========================================================================
class TestEjecutivoSinColor(unittest.TestCase):
    """El informe ejecutivo generado con datos, de principio a fin."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.tmp.name) / "ejecutivo_bn.db")
        db.init_db(cls.ruta)
        _sembrar(cls.ruta)
        cls.cfg = ConfiguracionFalsa()
        with db.session(cls.ruta) as conn:
            cls.datos = report.generar_ejecutivo_en_memoria(conn, MES, cfg=cls.cfg)
        cls.doc = Document(io.BytesIO(cls.datos))
        cls.texto = _texto(cls.doc)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    # ---------------------------------------------------------------- color
    def test_no_queda_ningun_color_en_el_paquete(self):
        sobrantes = colores_del_docx(self.datos)
        self.assertEqual(sobrantes, [],
                         f"quedan {len(sobrantes)} elementos con color: {sobrantes[:8]}")

    def test_los_porcentajes_del_tema_siguen_siendo_porcentajes(self):
        """Quitar el color no puede romper el documento.

        En `theme1.xml` hay atributos `val` de seis cifras que NO son colores sino
        porcentajes (`<a:satMod val="300000"/>`, `<a:tint val="100000"/>`). Convertirlos a
        gris dejaba valores inválidos en el tema.
        """
        with zipfile.ZipFile(io.BytesIO(self.datos)) as paquete:
            tema = paquete.read("word/theme/theme1.xml").decode("utf-8")
        porcentajes = re.findall(
            r'<a:(?:alpha|satMod|lumMod|lumOff|tint|shade) val="([^"]+)"', tema)
        self.assertTrue(porcentajes)
        for valor in porcentajes:
            self.assertTrue(valor.isdigit(), f"«{valor}» ya no es un porcentaje")

    def test_todas_las_partes_del_paquete_siguen_siendo_xml_valido(self):
        from xml.etree import ElementTree
        with zipfile.ZipFile(io.BytesIO(self.datos)) as paquete:
            for nombre in paquete.namelist():
                if nombre.endswith((".xml", ".rels")):
                    ElementTree.fromstring(paquete.read(nombre))

    def test_no_queda_ninguna_pieza_que_no_sea_xml(self):
        """La miniatura de vista previa de la plantilla era una imagen en color."""
        with zipfile.ZipFile(io.BytesIO(self.datos)) as paquete:
            sobrantes = [n for n in paquete.namelist()
                         if not n.endswith((".xml", ".rels"))]
        self.assertEqual(sobrantes, [])

    def test_los_titulos_de_apartado_van_en_tinta_negra(self):
        estilo = self.doc.styles["Heading 1"]
        self.assertEqual(str(estilo.font.color.rgb), "000000")
        self.assertTrue(estilo.font.bold)

    def test_las_tablas_son_una_rejilla_negra(self):
        self.assertTrue(self.doc.tables, "el informe tiene tablas")
        for tabla in self.doc.tables:
            self.assertEqual(tabla.style.name, "Table Grid")

    def test_la_cabecera_de_tabla_se_distingue_sin_color(self):
        """Negrita y sombreado gris muy claro: lo único que sobrevive a una fotocopia."""
        for tabla in self.doc.tables:
            primera = tabla.rows[0]
            self.assertIn(report.SOMBREADO_CABECERA, primera.cells[0]._tc.xml,
                          "la cabecera necesita su sombreado gris")
            negritas = [r.font.bold for c in primera.cells
                        for p in c.paragraphs for r in p.runs]
            self.assertTrue(negritas and all(negritas),
                            "la cabecera va en negrita")

    def test_el_pdf_no_tiene_un_solo_pixel_de_color(self):
        pixeles = _pixeles_de_color(self.datos)
        if pixeles < 0:
            self.skipTest("LibreOffice o pdftoppm no están instalados en este servidor")
        self.assertEqual(pixeles, 0, f"{pixeles} píxeles con color en la primera página")

    # ------------------------------------------- lo que decía el color, escrito
    def test_la_portada_avisa_de_que_va_en_blanco_y_negro(self):
        self.assertIn("blanco y negro", self.texto)
        self.assertIn("ninguna cifra depende del color", self.texto)

    def test_la_variacion_va_escrita_y_en_versalitas(self):
        """El rojo de «empeoró» y el verde de «mejoró» son ahora la palabra, en versalitas."""
        palabras = ("mejoró", "empeoró", "se mantiene")
        marcadas = []
        for celda in _celdas(self.doc):
            texto = celda.text.lower()
            if any(p in texto for p in palabras):
                marcadas.extend(r.font.small_caps for p in celda.paragraphs
                                for r in p.runs)
        self.assertTrue(marcadas, "ninguna celda dice si mejoró o empeoró")
        self.assertTrue(all(marcadas), "la palabra tiene que ir en versalitas")

    def test_el_saldo_de_la_deuda_va_escrito_y_en_versalitas(self):
        self.assertTrue(any(f in self.texto for f in
                            ("la deuda sube en", "la deuda baja en", "sin cambio")))
        marcadas = [r.font.small_caps for celda in _celdas(self.doc)
                    if "la deuda" in celda.text.lower()
                    for p in celda.paragraphs for r in p.runs]
        self.assertTrue(marcadas and all(marcadas))

    def test_la_leyenda_dice_que_es_cada_barra(self):
        """La barra no tiene color: la leyenda tiene que decir cuál es cuál."""
        self.assertIn("Leyenda de las barras.", self.texto)
        self.assertIn("no llevan color", self.texto)
        self.assertIn("DETECTADAS", self.texto)
        self.assertIn("REMEDIADAS", self.texto)

    def test_la_comparacion_explica_como_se_lee_la_variacion(self):
        self.assertIn("MEJORÓ, EMPEORÓ o SE MANTIENE", self.texto)

    def test_las_notas_llevan_rotulo_en_negrita(self):
        for rotulo in ("Cómo leer este informe.", "Cómo leer estas cifras.",
                       "Qué cambia si se hace:"):
            self.assertIn(rotulo, self.texto)
        negritas = [r.font.bold for p in self.doc.paragraphs for r in p.runs
                    if r.text.strip() == "Cómo leer estas cifras."]
        self.assertTrue(negritas and all(negritas))

    def test_sigue_diciendo_todo_lo_que_decia_antes(self):
        """Quitar el color no puede quitar información: las cifras siguen enteras."""
        for palabra in ("Vulnerabilidades confirmadas", "Activos afectados",
                        "Detectadas", "Remediadas", "Días medios en corregir",
                        "Qué conviene hacer el mes que viene"):
            self.assertIn(palabra, self.texto)

    # --------------------------------------------------------- estabilidad
    def test_dos_generaciones_seguidas_dan_el_mismo_documento(self):
        with db.session(self.ruta) as conn:
            otra = report.generar_ejecutivo_en_memoria(conn, MES, cfg=self.cfg)
        self.assertEqual(_texto(Document(io.BytesIO(otra))), self.texto)
        self.assertEqual(colores_del_docx(otra), [])

    def test_un_mes_sin_datos_tampoco_tiene_color(self):
        with db.session(self.ruta) as conn:
            vacio = report.generar_ejecutivo_en_memoria(conn, "2026-03", cfg=self.cfg)
        self.assertEqual(colores_del_docx(vacio), [])

    def test_el_informe_mensual_completo_sigue_en_color(self):
        """El cambio es SOLO del ejecutivo: el completo no se ha tocado."""
        with db.session(self.ruta) as conn:
            doc = report.construir_documento(conn, MES, cfg=self.cfg)
        memoria = io.BytesIO()
        doc.save(memoria)
        self.assertTrue(colores_del_docx(memoria.getvalue()),
                        "el informe mensual completo tiene que seguir en color")
        self.assertEqual([t.style.name for t in doc.tables][:1], ["Light Grid Accent 1"])


if __name__ == "__main__":
    unittest.main()

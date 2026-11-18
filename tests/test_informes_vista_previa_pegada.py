"""Vista previa pegada y medida de lectura de la plataforma (2026-09-10).

Queja literal del usuario:

    «No veo lo que pedí del apartado de informes, de previsualizar la construcción de
    informes según lo que yo vaya escogiendo. Ajusta bien las intros de cada apartado,
    que se ajuste porque veo que después de cada título de cada sección está solo a la
    parte izquierda y la idea es que se ajusten a la vista y espacio.»

Lo que había: la vista previa existía y se actualizaba sola, pero empezaba en el píxel
2.574 del documento (medido con el navegador a 1.440 px de ventana), o sea a casi tres
pantallas del formulario, así que quien marcaba un apartado no veía el resultado. Y la
introducción de página estaba atada a 78 caracteres (566 px de los 1.145 disponibles),
mientras que los subtítulos de panel y los textos de ayuda no tenían límite ninguno y
llegaban a 166 caracteres por línea.

Estas pruebas fijan las dos cosas para que no se vuelvan atrás sin querer:

1. la vista previa se pinta en su propia columna, después del formulario en el HTML, con
   la clase que estilo.css pega al desplazamiento, y el botón de generar queda fuera del
   bloque que se desplaza;
2. el esquema del documento lleva los apartados elegidos, en el orden del informe y con
   su numeración real, y se reordena al cambiar la selección;
3. con cero apartados lo dice y no deja generar (ni por la pantalla ni por el POST);
4. la vista previa sigue siendo viva en el modo personalizado y con todas las plantillas;
5. la medida de lectura es un solo token (``--medida-texto``) entre 100 y 120 caracteres,
   que usan la introducción de página, el subtítulo de panel y los textos de ayuda: la
   introducción ya NO está atada a 78 caracteres.

Ejecución:
    sudo -n -u si .venv/bin/python -m unittest tests.test_informes_vista_previa_pegada
"""
from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path

from threatintel import db, informe_seleccion as isel
from threatintel.paths import BASE_DIR

sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "tests"))
import test_informes_medida as base  # noqa: E402

CLAVE = base.CLAVE
ESTILO = (BASE_DIR / "webui" / "static" / "estilo.css").read_text(encoding="utf-8")
PLANTILLAS = BASE_DIR / "webui" / "templates"
INFORMES_HTML = (PLANTILLAS / "informes.html").read_text(encoding="utf-8")
VISTA_PREVIA_HTML = (PLANTILLAS / "_informe_vista_previa.html").read_text(encoding="utf-8")

RE_STYLE = re.compile(r"\sstyle\s*=", re.I)
RE_ON = re.compile(r"\son[a-z]+\s*=", re.I)


def _reglas(selector: str) -> list[str]:
    """Los cuerpos de las reglas CSS cuyo selector es exactamente ``selector``.

    Compara el selector completo (sin comentarios ni espacios de más) para que
    «.columna-informe-resumen» no arrastre «.columna-informe-resumen > .panel».
    """
    limpio = re.sub(r"/\*.*?\*/", " ", ESTILO, flags=re.S)
    cuerpos = []
    for m in re.finditer(r"([^{}]+)\{([^{}]*)\}", limpio):
        partes = [re.sub(r"\s+", " ", p).strip() for p in m.group(1).split(",")]
        if selector in partes:
            cuerpos.append(m.group(2))
    return cuerpos


def _regla(selector: str) -> str:
    cuerpos = _reglas(selector)
    return cuerpos[0] if cuerpos else ""


# ==========================================================================
# 1. La pantalla: dos columnas y vista previa pegada
# ==========================================================================
class BasePantalla(unittest.TestCase):
    """Una base temporal sembrada con los mismos datos del generador de informes."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "informes_previa.db")
        db.init_db(cls.ruta)
        cls.ids = base._sembrar(cls.ruta)
        cls.app = base._app(cls.ruta)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def setUp(self):
        self.cli = self.app.test_client()
        self.cli.post("/login", data={"usuario": "admin@ejemplo.local", "password": CLAVE})

    def html(self, url: str) -> str:
        r = self.cli.get(url)
        self.assertEqual(r.status_code, 200, url)
        return r.get_data(as_text=True)


class TestDisposicionDeLaPantalla(BasePantalla):

    def test_la_vista_previa_va_en_su_columna_y_despues_del_formulario(self):
        """Dos columnas en pantalla ancha; en el HTML, elegir primero y ver después."""
        html = self.html("/informes/")
        self.assertIn('class="disposicion-informe"', html)
        self.assertIn('class="columna-informe-formulario"', html)
        self.assertIn('class="columna-informe-resumen"', html)
        # El orden del documento no cambia: primero lo que se elige, después la vista
        # previa (teclado, lector de pantalla y pantalla estrecha lo recorren así).
        self.assertLess(html.index('class="columna-informe-formulario"'),
                        html.index('class="columna-informe-resumen"'))
        self.assertLess(html.index("Qué informe quiere"),
                        html.index("Vista previa y descarga"))
        # Y la vista previa está DENTRO de la columna pegada, no suelta en la página.
        resto = html[html.index('class="columna-informe-resumen"'):]
        self.assertLess(resto.index("Vista previa y descarga"),
                        resto.index("Meses disponibles"))

    def test_el_boton_de_generar_queda_fuera_del_bloque_que_se_desplaza(self):
        """Con el panel pegado, la acción no se puede esconder al desplazar el esquema."""
        html = self.html("/informes/")
        self.assertIn('class="previa-desplazable"', html)
        self.assertIn("previa-generar", html)
        desplazable = html.index('class="previa-desplazable"')
        generar = html.index("previa-generar")
        boton = html.index("Generar y descargar en Word")
        self.assertLess(desplazable, generar)
        self.assertLess(generar, boton, "el botón tiene que ir en el bloque del pie")

    def test_las_plantillas_tocadas_siguen_sin_estilos_ni_manejadores_en_linea(self):
        for nombre, texto in (("informes.html", INFORMES_HTML),
                              ("_informe_vista_previa.html", VISTA_PREVIA_HTML)):
            with self.subTest(plantilla=nombre):
                self.assertIsNone(RE_STYLE.search(texto), f"{nombre} trae style=")
                for m in RE_ON.finditer(texto):
                    trozo = texto[m.start():m.start() + 30]
                    self.assertNotRegex(trozo, r"\son(click|change|submit|load|input)")

    def test_el_recorrido_guiado_sigue_completo_y_en_orden(self):
        """Mover paneles a una columna no puede romper el recorrido de la pantalla."""
        pasos = [int(n) for n in re.findall(r'data-tour="(\d+)"', self.html("/informes/"))]
        self.assertGreaterEqual(len(pasos), 6)
        self.assertEqual(pasos, sorted(pasos))
        self.assertEqual(len(pasos), len(set(pasos)))


# ==========================================================================
# 2. El esquema del documento
# ==========================================================================
class TestEsquemaDelDocumento(BasePantalla):

    def _esquema(self, html: str) -> list[str]:
        """Los apartados del esquema, en el orden en que se pintan."""
        trozo = html[html.index("Esquema del documento"):]
        trozo = trozo[:trozo.index("Detalle de la selección")]
        return [re.sub(r"\s+", " ", t).strip()
                for t in re.findall(r"<li><strong>(.*?)</strong>", trozo, re.S)]

    def test_pinta_los_apartados_elegidos_en_el_orden_del_documento(self):
        # Se piden desordenados a propósito: el documento manda, no el orden de marcado.
        html = self.html("/informes/?plantilla=mensual&apartados_enviados=1"
                         "&apartado=conclusiones&apartado=portada&apartado=panorama")
        self.assertEqual(self._esquema(html),
                         ["Portada", "1. Panorama y cifras",
                          "2. Conclusiones y recomendaciones"])

    def test_la_numeracion_se_recalcula_al_cambiar_la_seleccion(self):
        """Quitar un apartado renumera los siguientes: es lo que se ve al desmarcar."""
        con_resumen = self._esquema(self.html(
            "/informes/?plantilla=mensual&apartados_enviados=1"
            "&apartado=resumen_ejecutivo&apartado=panorama&apartado=conclusiones"))
        sin_resumen = self._esquema(self.html(
            "/informes/?plantilla=mensual&apartados_enviados=1"
            "&apartado=panorama&apartado=conclusiones"))
        self.assertEqual(con_resumen, ["1. Resumen ejecutivo", "2. Panorama y cifras",
                                       "3. Conclusiones y recomendaciones"])
        self.assertEqual(sin_resumen, ["1. Panorama y cifras",
                                       "2. Conclusiones y recomendaciones"])
        self.assertNotEqual(con_resumen, sin_resumen)

    def test_la_portada_y_el_indice_no_se_numeran(self):
        html = self.html("/informes/?plantilla=mensual&apartados_enviados=1"
                         "&apartado=portada&apartado=indice&apartado=resumen_ejecutivo")
        self.assertEqual(self._esquema(html),
                         ["Portada", "Índice", "1. Resumen ejecutivo"])

    def test_la_lista_no_pinta_ademas_su_propio_numero(self):
        """El número del documento ya va en el texto: dos numeraciones se leen como error."""
        self.assertIn("list-style: none", _regla(".esquema-informe"))

    def test_el_esquema_dice_cuantos_apartados_son_con_su_unidad(self):
        html = self.html("/informes/?plantilla=direccion")
        self.assertRegex(html, r"Los \d+\s+apartados que va a llevar")

    def test_con_cero_apartados_lo_dice_y_no_deja_generar(self):
        html = self.html("/informes/?plantilla=mensual&apartados_enviados=1")
        self.assertIn("Todavía no ha elegido ningún apartado", html)
        self.assertIn("el documento estaría vacío", html)
        self.assertRegex(html, r"<button[^>]*disabled[^>]*>Generar y descargar en Word")
        self.assertIn("Marque al menos un apartado", html)
        self.assertEqual(self._esquema(html), [])

    def test_el_post_tambien_rechaza_una_seleccion_sin_apartados(self):
        """La pantalla no es la única defensa: el servidor vuelve a comprobarlo."""
        csrf = re.search(r'name="csrf" value="([^"]+)"',
                         self.html("/informes/")).group(1)
        r = self.cli.post("/informes/generar",
                          data={"csrf": csrf, "plantilla": "mensual",
                                "apartados_enviados": "1", "periodo": "mes",
                                "mes": "2026-08", "alcance": "todo"},
                          follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        cuerpo = r.get_data(as_text=True)
        self.assertNotIn("wordprocessingml", r.headers.get("Content-Type", ""))
        self.assertIn("apartado", cuerpo.lower())


# ==========================================================================
# 3. La vista previa sigue siendo viva en los dos modos
# ==========================================================================
class TestVistaPreviaViva(BasePantalla):

    def test_viva_en_el_modo_personalizado_y_en_todas_las_plantillas(self):
        # Siete el 2026-09-10 y ocho desde el 2026-09-15, con el informe ejecutivo
        # mensual. La cifra se comprueba contra el catálogo para que añadir una plantilla
        # no deje ninguna sin repasar aquí.
        claves = [p.clave for p in isel.PLANTILLAS] + [isel.PLANTILLA_LIBRE]
        self.assertEqual(len(claves), len(isel.PLANTILLA_POR_CLAVE))
        self.assertGreaterEqual(len(claves), 8)
        for clave in claves:
            with self.subTest(plantilla=clave):
                html = self.html(f"/informes/?plantilla={clave}")
                self.assertIn('data-filtro-vivo="vista-previa-informe"', html)
                self.assertIn('data-vivo-fragmento="/informes/vista-previa"', html)
                self.assertIn('id="vista-previa-informe"', html)
                self.assertIn('class="vista-previa-zona"', html)
                self.assertIn("Esquema del documento", html)

    def test_el_fragmento_trae_la_zona_entera_con_su_bloque_desplazable(self):
        """El motor sustituye la zona completa: si el fragmento no la trae igual, se rompe."""
        for clave in [p.clave for p in isel.PLANTILLAS] + [isel.PLANTILLA_LIBRE]:
            with self.subTest(plantilla=clave):
                r = self.cli.get(f"/informes/vista-previa?plantilla={clave}")
                self.assertEqual(r.status_code, 200)
                frag = r.get_data(as_text=True)
                self.assertIn('id="vista-previa-informe"', frag)
                self.assertIn('class="previa-desplazable"', frag)
                self.assertIn("previa-generar", frag)
                self.assertIn("Esquema del documento", frag)

    def test_el_fragmento_y_la_pagina_pintan_el_mismo_esquema(self):
        consulta = ("plantilla=mensual&apartados_enviados=1&apartado=portada"
                    "&apartado=panorama&apartado=anexo&apartado=conclusiones")
        pagina = self.html(f"/informes/?{consulta}")
        frag = self.cli.get(f"/informes/vista-previa?{consulta}").get_data(as_text=True)
        # El anexo no se numera (es un anexo), las secciones sí: lo mismo en los dos.
        for texto in ("Portada", "1. Panorama y cifras",
                      "Anexo con el resto de hallazgos",
                      "2. Conclusiones y recomendaciones"):
            self.assertIn(texto, pagina)
            self.assertIn(texto, frag)


# ==========================================================================
# 4. Guardián de la medida de lectura (afecta a toda la plataforma)
# ==========================================================================
class TestMedidaDeLectura(unittest.TestCase):
    """Que nadie vuelva a atar la introducción a 78 caracteres sin darse cuenta."""

    def test_hay_un_solo_token_de_medida_y_esta_entre_100_y_120_caracteres(self):
        m = re.search(r"--medida-texto:\s*(\d+)ch", ESTILO)
        self.assertIsNotNone(m, "falta el token --medida-texto en :root")
        self.assertGreaterEqual(int(m.group(1)), 100)
        self.assertLessEqual(int(m.group(1)), 120)

    def test_la_introduccion_de_pagina_ya_no_esta_atada_a_78_caracteres(self):
        regla = _regla(".titulo-pagina p")
        self.assertIn("var(--medida-texto)", regla)
        self.assertNotIn("78ch", regla)
        self.assertNotIn("max-width: 78ch", ESTILO)

    def test_el_subtitulo_de_panel_y_las_ayudas_usan_la_misma_medida(self):
        self.assertIn("var(--medida-texto)", _regla(".panel-cabecera .sub"))
        self.assertIn("var(--medida-texto)", _regla(".ayuda"))

    def test_el_bloque_de_titulo_crece_pero_sin_base_en_pixeles_en_movil(self):
        """A 480 px la cabecera es una columna: una base en píxeles sería alto mínimo."""
        reglas = _reglas(".titulo-pagina > div:first-child")
        self.assertTrue(reglas, "el bloque de título tiene que crecer con el espacio")
        self.assertTrue(any("flex: 1 1 320px" in r for r in reglas))
        indice = ESTILO.index(".titulo-pagina > div:first-child")
        anterior = ESTILO[:indice]
        self.assertIn("@media (min-width: 481px)", anterior[-200:],
                      "la base en píxeles solo vale por encima de 480 px")


class TestColumnaPegada(unittest.TestCase):
    """La disposición de dos columnas y el panel que acompaña al desplazamiento."""

    def test_la_columna_del_resumen_se_pega_bajo_la_barra_superior(self):
        regla = _regla(".columna-informe-resumen")
        self.assertIn("position: sticky", regla)
        self.assertIn("var(--alto-barra)", regla,
                      "el panel pegado tiene que descontar la barra superior")

    def test_el_panel_pegado_limita_su_alto_y_desplaza_solo_su_contenido(self):
        alto = [r for r in _reglas(".columna-informe-resumen > .panel") if "max-height" in r]
        self.assertTrue(alto, "el panel pegado tiene que limitar su alto")
        self.assertTrue(any("100vh" in r for r in alto),
                        "el alto se limita con la altura de la ventana")
        desplazable = [r for r in _reglas(".columna-informe-resumen .previa-desplazable")
                       if "overflow-y" in r]
        self.assertTrue(desplazable, "el esquema largo tiene que desplazarse dentro")
        self.assertTrue(any("auto" in r for r in desplazable))

    def test_solo_hay_dos_columnas_en_pantallas_anchas(self):
        indice = ESTILO.index(".disposicion-informe { grid-template-columns")
        self.assertIn("@media (min-width: 1180px)", ESTILO[:indice][-300:])
        # Y la disposición por omisión (móvil primero) es de una sola columna.
        self.assertIn("display: grid", _regla(".disposicion-informe"))

    def test_la_rejilla_de_apartados_reparte_el_espacio(self):
        regla = _regla(".rejilla.apartados-informe")
        self.assertIn("minmax(240px", regla,
                      "con 340 px la columna del formulario se quedaba en una sola columna")


if __name__ == "__main__":
    unittest.main()

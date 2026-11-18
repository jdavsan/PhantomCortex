#!/usr/bin/env python3
"""Pruebas del módulo de gráficos SVG (webui/graficos.py).

Cubren las exigencias de la sección 5 de docs/DISENO_INTERFAZ_2026-09-03.md:
escapado de datos de terceros, ausencia de ``style=`` y de colores literales
(CSP estricta), estado vacío, suma de porciones, descarte de ``href`` externos,
formato de números en español, longitudes desiguales, márgenes y etiquetas sin
solapes, ``<title>`` en cada elemento de dato y registro como global de Jinja.

Ejecución:
    sudo -n -u si .venv/bin/python -m unittest tests.test_graficos
"""
from __future__ import annotations

import math
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from markupsafe import Markup  # noqa: E402

from webui import graficos as g  # noqa: E402

INF = float("inf")
HOSTIL = '<script>alert(1)</script>'
UMBRALES_CVSS = [(4.0, "bajo"), (7.0, "medio"), (9.0, "alto"), (INF, "critico")]

MESES_6 = ["abr 2026", "may 2026", "jun 2026", "jul 2026", "ago 2026", "sep 2026"]
SERIES_6 = [
    {"clave": "critico", "nombre": "Críticas", "valores": [12, 9, 15, 11, 8, 10]},
    {"clave": "alto", "nombre": "Altas", "valores": [40, 35, 52, 48, 39, 14]},
    {"clave": "medio", "nombre": "Medias", "valores": [900, 1010, 1200, 1250, 1150, 83]},
    {"clave": "bajo", "nombre": "Bajas", "valores": [30, 22, 41, 52, 38, 17]},
]
LINEA_KEV = {"clave": "kev", "nombre": "En KEV", "valores": [3, 5, 2, 6, 4, 1]}

PORCIONES = [
    {"clave": "critico", "nombre": "Críticas", "valor": 10},
    {"clave": "alto", "nombre": "Altas", "valor": 14},
    {"clave": "medio", "nombre": "Medias", "valor": 83},
    {"clave": "bajo", "nombre": "Bajas", "valor": 0},
]

ITEMS = [
    {"etiqueta": "Windows Server", "valores": [("critico", 3), ("alto", 5), ("neutro", 10)],
     "href": "/amenazas/?tec=windows-server", "nota": "sin versión"},
    {"etiqueta": "Cisco IOS XE", "valores": [("critico", 1), ("alto", 2), ("neutro", 4)],
     "href": "/amenazas/?tec=cisco"},
    {"etiqueta": "Fortinet FortiOS", "valores": [("critico", 0), ("alto", 4), ("neutro", 2)]},
]

PASOS = [
    {"titulo": "Recolección", "valor": "52 / 55", "nota": "fuentes operativas",
     "estado": "ok", "href": "/fuentes/"},
    {"titulo": "Correlación", "valor": 124, "nota": "amenazas nuevas", "estado": "atencion"},
    {"titulo": "Enriquecimiento", "valor": "2.054", "nota": "CVE pendientes", "estado": "critico"},
    {"titulo": "Informe mensual", "valor": "—", "estado": "inactivo"},
]


def _todos_los_graficos() -> dict[str, str]:
    """Una salida representativa de cada función, con datos hostiles."""
    hostil_nombre = f"Fuente {HOSTIL} & Cía"
    return {
        "chispa": str(g.chispa([1, 2, None, 4, 3])),
        "barras_apiladas": str(g.barras_apiladas(
            MESES_6 + [HOSTIL], SERIES_6 + [{"clave": "x", "nombre": hostil_nombre, "valores": [1]}],
            linea=LINEA_KEV)),
        "barras_horizontales": str(g.barras_horizontales(
            ITEMS + [{"etiqueta": hostil_nombre, "valores": [("critico", 2)],
                      "href": "javascript:alert(1)", "nota": HOSTIL}])),
        "dona": str(g.dona(PORCIONES + [{"clave": "neutro", "nombre": hostil_nombre, "valor": 1}],
                           centro_valor=108, centro_etiqueta=HOSTIL)),
        "linea_tiempo": str(g.linea_tiempo(
            ["1", "2", HOSTIL], [{"clave": "acento", "nombre": hostil_nombre, "valores": [120, 80, 95]}],
            unidad="ms")),
        "barra_progreso": str(g.barra_progreso(
            [{"clave": "exito", "nombre": hostil_nombre, "valor": 120},
             {"clave": "neutro", "nombre": "Pendientes", "valor": 2054}])),
        "medidor": str(g.medidor(7.5, 10, etiqueta=HOSTIL, umbrales=UMBRALES_CVSS)),
        "flujo": str(g.flujo(PASOS + [{"titulo": hostil_nombre, "valor": HOSTIL, "nota": HOSTIL,
                                        "estado": "ok", "href": "https://evil.invalid/"}])),
    }


# ==========================================================================
# Formato de números
# ==========================================================================
class TestFormato(unittest.TestCase):

    def test_miles_con_punto(self):
        self.assertEqual(g.fmt(1234), "1.234")
        self.assertEqual(g.fmt(1234567), "1.234.567")
        self.assertEqual(g.fmt(999), "999")
        self.assertEqual(g.fmt(0), "0")

    def test_decimales_con_coma(self):
        self.assertEqual(g.fmt(7.5), "7,5")
        self.assertEqual(g.fmt(1234.5), "1.234,5")
        self.assertEqual(g.fmt(0.333), "0,33")
        self.assertEqual(g.fmt(7.0), "7")

    def test_decimales_forzados(self):
        self.assertEqual(g.fmt(7, decimales=1), "7,0")
        self.assertEqual(g.fmt(7.456, decimales=1), "7,5")
        self.assertEqual(g.fmt(1234.5678, decimales=2), "1.234,57")

    def test_none_y_no_numeros(self):
        self.assertEqual(g.fmt(None), "—")
        self.assertEqual(g.fmt(float("nan")), "—")
        self.assertEqual(g.fmt(INF), "—")
        self.assertEqual(g.fmt("texto"), "texto")
        self.assertEqual(g.fmt("7.5"), "7,5")

    def test_negativos_y_booleanos(self):
        self.assertEqual(g.fmt(-3), "-3")
        self.assertEqual(g.fmt(-1234.5), "-1.234,5")
        self.assertEqual(g.fmt(True), "1")


# ==========================================================================
# Seguridad: CSP, escapado, href
# ==========================================================================
class TestSeguridadCSP(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.salidas = _todos_los_graficos()

    def test_devuelven_markup(self):
        for nombre, salida in self.salidas.items():
            with self.subTest(grafico=nombre):
                self.assertTrue(salida.startswith("<"))
        self.assertIsInstance(g.dona(PORCIONES), Markup)
        self.assertIsInstance(g.dona([]), Markup)
        self.assertIsInstance(g.flujo(PASOS), Markup)

    def test_sin_style_ni_manejadores_en_linea(self):
        for nombre, salida in self.salidas.items():
            with self.subTest(grafico=nombre):
                self.assertIsNone(re.search(r'\sstyle\s*=\s*"', salida))
                self.assertIsNone(re.search(r'\son[a-z]+\s*=\s*"', salida, re.I))
                self.assertNotIn("<script", salida)
                self.assertNotIn("<style", salida)
                self.assertNotIn("javascript:", salida)

    def test_sin_colores_literales(self):
        patron = re.compile(r'(fill|stroke)="(?!none"|currentColor"|transparent")')
        for nombre, salida in self.salidas.items():
            with self.subTest(grafico=nombre):
                self.assertIsNone(patron.search(salida), salida[:300])
                self.assertIsNone(re.search(r'="#[0-9a-fA-F]{3,8}"', salida))
                self.assertNotIn("rgb(", salida)
                self.assertNotIn("hsl(", salida)

    def test_sin_recursos_externos(self):
        for nombre, salida in self.salidas.items():
            with self.subTest(grafico=nombre):
                self.assertIsNone(re.search(r'(src|href)="(https?:)?//', salida))
                self.assertNotIn("<link", salida)
                self.assertNotIn("@import", salida)

    def test_escapado_de_script_en_etiquetas(self):
        for nombre, salida in self.salidas.items():
            if nombre == "chispa":
                continue  # la chispa no rotula datos: no hay texto que escapar
            with self.subTest(grafico=nombre):
                self.assertIn("&lt;script&gt;", salida)
                self.assertNotIn(HOSTIL, salida)

    def test_escapado_de_comillas_en_atributos(self):
        salida = str(g.dona(PORCIONES, aria='x" onload="alert(1)'))
        self.assertNotIn('onload="', salida)
        self.assertIn("&#34;", salida)
        salida = str(g.barras_horizontales([{"etiqueta": 'a" style="color:red',
                                             "valores": [("critico", 1)]}]))
        self.assertIsNone(re.search(r'\sstyle\s*=\s*"', salida))

    def test_href_externo_o_javascript_descartado(self):
        for href in ("javascript:alert(1)", "https://evil.invalid/", "//evil.invalid/x",
                     "/\\evil.invalid", "http://x", "data:text/html,a", "/ruta\nmal", ""):
            with self.subTest(href=href):
                bh = str(g.barras_horizontales([{"etiqueta": "T", "valores": [("critico", 1)],
                                                 "href": href}]))
                self.assertNotIn("<a ", bh)
                fl = str(g.flujo([{"titulo": "P", "estado": "ok", "href": href}]))
                self.assertNotIn("<a ", fl)

    def test_href_local_se_conserva_escapado(self):
        bh = str(g.barras_horizontales([{"etiqueta": "T", "valores": [("critico", 1)],
                                         "href": "/amenazas/?tec=x&sev=High"}]))
        self.assertIn('<a href="/amenazas/?tec=x&amp;sev=High">', bh)
        fl = str(g.flujo([{"titulo": "P", "estado": "ok", "href": "/fuentes/"}]))
        self.assertIn('<a href="/fuentes/">P</a>', fl)

    def test_deterministas(self):
        self.assertEqual(_todos_los_graficos(), self.salidas)

    def test_sin_nan_ni_infinito_en_la_salida(self):
        salida = str(g.barras_apiladas(["a", "b"], [{"clave": "alto", "valores": [float("nan"), INF]},
                                                     {"clave": "medio", "valores": [1, 2]}]))
        for prohibido in ("nan", "inf", "NaN", "Infinity"):
            self.assertNotIn(prohibido, salida)


# ==========================================================================
# Estructura común
# ==========================================================================
class TestEstructura(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.salidas = _todos_los_graficos()

    def test_figure_svg_y_tipo(self):
        for nombre, salida in self.salidas.items():
            if nombre == "flujo":
                continue
            with self.subTest(grafico=nombre):
                self.assertRegex(salida, r'^<figure class="grafico-envoltorio grafico-[a-z-]+">')
                self.assertTrue(salida.endswith("</figure>"))
                self.assertIn('role="img"', salida)

    def test_viewbox_bien_formado(self):
        patron = re.compile(r'viewBox="0 0 (\d+(?:\.\d+)?) (\d+(?:\.\d+)?)"')
        for nombre, salida in self.salidas.items():
            if nombre == "flujo":
                continue
            with self.subTest(grafico=nombre):
                m = patron.search(salida)
                self.assertIsNotNone(m, salida[:200])
                self.assertGreater(float(m.group(1)), 0)
                self.assertGreater(float(m.group(2)), 0)

    def test_aria_label_presente_y_no_vacio(self):
        for nombre, salida in self.salidas.items():
            with self.subTest(grafico=nombre):
                m = re.search(r'aria-label="([^"]*)"', salida)
                self.assertIsNotNone(m)
                self.assertTrue(m.group(1).strip())

    def test_aria_personalizado_se_respeta(self):
        self.assertIn('aria-label="Mi gráfico"', str(g.dona(PORCIONES, aria="Mi gráfico")))
        self.assertIn('aria-label="Mi gráfico"', str(g.flujo(PASOS, aria="Mi gráfico")))

    def test_leyenda_opcional(self):
        con = str(g.dona(PORCIONES))
        sin = str(g.dona(PORCIONES, leyenda=False))
        self.assertIn('<ul class="leyenda">', con)
        self.assertNotIn('<ul class="leyenda">', sin)
        self.assertIn('class="leyenda-punto serie-critico"', con)
        self.assertNotIn("leyenda", str(g.barras_apiladas(MESES_6, SERIES_6, leyenda=False)))

    def test_claves_desconocidas_pasan_a_neutro(self):
        salida = str(g.dona([{"clave": "morado", "nombre": "X", "valor": 3},
                             {"clave": "CRITICO", "nombre": "Y", "valor": 1}]))
        self.assertIn("serie-neutro", salida)
        self.assertNotIn("serie-morado", salida)
        self.assertIn("serie-critico", salida)  # se normaliza a minúsculas
        self.assertIn("linea-neutro", str(g.chispa([1, 2, 3], clave="rosa")))

    def test_claves_categoricas_admitidas(self):
        salida = str(g.dona([{"clave": f"cat-{i}", "nombre": f"C{i}", "valor": i} for i in range(1, 9)]))
        for i in range(1, 9):
            self.assertIn(f"serie-cat-{i}", salida)


# ==========================================================================
# Estado vacío y datos irregulares
# ==========================================================================
class TestVacioYRobustez(unittest.TestCase):
    VACIO = '<div class="grafico-vacio">Sin datos suficientes</div>'

    def test_listas_vacias_y_none(self):
        casos = [
            g.chispa([]), g.chispa(None),
            g.barras_apiladas([], []), g.barras_apiladas(None, None), g.barras_apiladas(MESES_6, []),
            g.barras_horizontales([]), g.barras_horizontales(None),
            g.dona([]), g.dona(None),
            g.linea_tiempo([], []), g.linea_tiempo(["a"], None),
            g.barra_progreso([]), g.barra_progreso(None),
            g.medidor(5, None), g.medidor(5, 0), g.medidor(5, -1), g.medidor(5, "x"),
            g.flujo([]), g.flujo(None),
        ]
        for i, salida in enumerate(casos):
            with self.subTest(caso=i):
                self.assertEqual(str(salida), self.VACIO)
                self.assertIsInstance(salida, Markup)

    def test_suma_cero_es_vacio(self):
        self.assertEqual(str(g.dona([{"clave": "critico", "nombre": "C", "valor": 0}])), self.VACIO)
        self.assertEqual(str(g.barras_apiladas(["a"], [{"clave": "alto", "valores": [0]}])), self.VACIO)
        self.assertEqual(str(g.barras_horizontales([{"etiqueta": "t", "valores": [("alto", 0)]}])),
                         self.VACIO)
        self.assertEqual(str(g.barra_progreso([{"clave": "exito", "nombre": "x", "valor": 0}])),
                         self.VACIO)

    def test_negativos_y_basura_como_cero_sin_excepcion(self):
        salida = str(g.barras_apiladas(["a", "b", "c"], [
            {"clave": "critico", "nombre": "C", "valores": [-5, "abc", None]},
            {"clave": "alto", "nombre": "A", "valores": [2, -1, 3]},
        ]))
        self.assertNotIn(self.VACIO, salida)
        self.assertNotIn('<rect class="serie-critico"', salida)  # todas las críticas quedan a 0
        self.assertIn("<b>0</b>", salida)   # leyenda: total de Críticas = 0
        self.assertIn("<b>5</b>", salida)   # Altas = 2 + 0 + 3
        for w in re.findall(r'width="(-?[\d.]+)"', salida):
            self.assertGreaterEqual(float(w), 0)
        for h in re.findall(r'height="(-?[\d.]+)"', salida):
            self.assertGreaterEqual(float(h), 0)

    def test_tipos_inesperados_no_lanzan(self):
        # Cadenas donde se esperan listas, diccionarios sueltos, tuplas cortas...
        g.chispa("abc"); g.barras_apiladas("abc", "def"); g.barras_apiladas(["a"], [1, "x", None])
        g.barras_horizontales([1, "x", {"etiqueta": "t", "valores": [("alto",), 5, None]}])
        g.dona([1, None, {"clave": "alto"}]); g.linea_tiempo("ab", {"valores": "xyz"})
        g.barra_progreso("x"); g.medidor("x", "y"); g.medidor(5, 10, umbrales=[1, (None,), ("a", "b")])
        g.flujo(["a", 1, None, {}])
        g.barras_apiladas(["a"], SERIES_6, ancho="ancho", alto=None)
        g.dona(PORCIONES, tamano=-1, grosor=10_000)
        g.barras_horizontales(ITEMS, max_etiqueta="x", alto_fila=0)

    def test_longitudes_desiguales(self):
        salida = str(g.barras_apiladas(MESES_6, [
            {"clave": "critico", "nombre": "Críticas", "valores": [1, 2]},          # corta
            {"clave": "alto", "nombre": "Altas", "valores": [1, 1, 1, 1, 1, 1, 9, 9]},  # larga
        ], linea={"clave": "kev", "nombre": "En KEV", "valores": [1]}, mostrar_totales=False))
        self.assertEqual(salida.count('class="serie-critico"'), 2)
        self.assertEqual(salida.count('class="serie-alto"'), 6)      # se recorta a 6
        self.assertEqual(salida.count('class="serie-kev punto"'), 6)  # se rellena a 6
        self.assertIn("Altas <b>6</b>", salida)                        # los sobrantes no cuentan
        salida = str(g.linea_tiempo(["a", "b", "c"], [{"clave": "acento", "nombre": "L", "valores": [5]}]))
        self.assertEqual(salida.count("<circle"), 3)


# ==========================================================================
# Chispa
# ==========================================================================
class TestChispa(unittest.TestCase):

    def test_estructura(self):
        salida = str(g.chispa([1, 2, None, 4, 3]))
        self.assertIn('class="grafico-envoltorio grafico-chispa"', salida)
        self.assertIn('viewBox="0 0 120 36"', salida)
        self.assertIn('<path class="area-acento"', salida)
        self.assertIn('<polyline class="linea-acento"', salida)
        self.assertIn('<circle class="serie-acento punto"', salida)
        self.assertNotIn("<ul", salida)
        self.assertNotIn("<text", salida)  # sin ejes

    def test_none_como_cero_toca_la_base(self):
        salida = str(g.chispa([4, None, 4], area=False))
        puntos = re.search(r'points="([^"]+)"', salida).group(1).split()
        ys = [float(p.split(",")[1]) for p in puntos]
        self.assertEqual(ys[0], ys[2])
        self.assertGreater(ys[1], ys[0])  # el 0 está abajo (y mayor)
        self.assertNotIn("<path", salida)

    def test_un_solo_valor_y_todo_cero(self):
        uno = str(g.chispa([7]))
        self.assertNotIn("<polyline", uno)
        self.assertNotIn("<path", uno)
        # un marcador visible (r=3) en el centro, y singular en el aria-label
        self.assertIn('<circle class="serie-acento punto" cx="60" cy="3" r="3">', uno)
        self.assertIn('aria-label="Serie de 1 valor: último 7, máximo 7"', uno)
        self.assertNotIn("1 valores", uno)
        dos = str(g.chispa([7, 8]))
        self.assertIn('r="2.5"', dos)
        self.assertIn("Serie de 2 valores", dos)
        plana = str(g.chispa([0, 0, 0]))
        self.assertIn("<polyline", plana)  # una serie a 0 es un dato, no un vacío

    def test_dimensiones_y_clave(self):
        salida = str(g.chispa([1, 2], ancho=200, alto=50, clave="critico"))
        self.assertIn('viewBox="0 0 200 50"', salida)
        self.assertIn("linea-critico", salida)
        self.assertIn("Serie de 2 valores", salida)


# ==========================================================================
# Barras apiladas
# ==========================================================================
class TestBarrasApiladas(unittest.TestCase):

    def test_cada_barra_con_title(self):
        salida = str(g.barras_apiladas(MESES_6, SERIES_6))
        rects = re.findall(r"<rect[^>]*>(.*?)</rect>", salida)
        self.assertEqual(len(rects), 24)  # 6 meses × 4 series, ninguna a 0
        for contenido in rects:
            self.assertRegex(contenido, r"^<title>.+: [\d.]+ \((<1|\d+) %\)</title>$")
        self.assertIn("<title>sep 2026 · Críticas: 10 (8 %)</title>", salida)

    def test_totales_en_leyenda_y_sobre_barras(self):
        salida = str(g.barras_apiladas(MESES_6, SERIES_6, linea=LINEA_KEV))
        self.assertIn("Críticas <b>65</b>", salida)
        self.assertIn("Altas <b>228</b>", salida)
        self.assertIn("Medias <b>5.593</b>", salida)
        self.assertIn("Bajas <b>200</b>", salida)
        self.assertIn("En KEV <b>21</b>", salida)
        # total sobre la barra de septiembre: 10 + 14 + 83 + 17 = 124
        self.assertIn('text-anchor="middle">124</text>', salida)
        self.assertIn('text-anchor="middle">1.361</text>', salida)
        sin = str(g.barras_apiladas(MESES_6, SERIES_6, mostrar_totales=False))
        self.assertNotIn('class="etiqueta-valor"', sin)

    def test_eje_y_con_rejillas_redondas_y_etiquetas_formateadas(self):
        salida = str(g.barras_apiladas(MESES_6, SERIES_6))
        # máximo 1.361 → tope 1.500 con paso 500 (3 divisiones): el eje 0-1.600
        # de 4×400 desperdiciaba más y 400 no es un paso redondo
        self.assertEqual(salida.count('class="rejilla"'), 3)
        self.assertEqual(salida.count('class="eje-linea"'), 1)
        etiquetas_y = re.findall(r'text-anchor="end">([^<]+)</text>', salida)
        self.assertEqual(etiquetas_y, ["0", "500", "1.000", "1.500"])
        # la rejilla superior coincide con el tope: el total mayor queda por debajo
        y_tope = min(float(y) for y in re.findall(r'class="rejilla"[^>]*y1="([\d.]+)"', salida))
        y_max = min(float(y) for y in re.findall(r'<rect class="serie-[a-z]+" x="[\d.]+" y="([\d.]+)"', salida))
        self.assertGreaterEqual(y_max, y_tope)

    def test_orden_de_apilado_y_geometria(self):
        salida = str(g.barras_apiladas(["m"], [
            {"clave": "critico", "nombre": "C", "valores": [10]},
            {"clave": "alto", "nombre": "A", "valores": [30]},
        ], mostrar_totales=False))
        rc = re.search(r'<rect class="serie-critico" x="([\d.]+)" y="([\d.]+)" width="([\d.]+)" height="([\d.]+)"', salida)
        ra = re.search(r'<rect class="serie-alto" x="([\d.]+)" y="([\d.]+)" width="([\d.]+)" height="([\d.]+)"', salida)
        self.assertEqual(rc.group(1), ra.group(1))                       # misma x
        self.assertGreater(float(rc.group(2)), float(ra.group(2)))       # críticas abajo, altas encima
        self.assertAlmostEqual(float(ra.group(4)) / float(rc.group(4)), 3.0, places=1)
        self.assertLessEqual(float(rc.group(3)), 64)                     # anchura de barra acotada

    def test_linea_superpuesta(self):
        salida = str(g.barras_apiladas(MESES_6, SERIES_6, linea=LINEA_KEV))
        self.assertEqual(salida.count('<polyline class="linea-kev"'), 1)
        self.assertEqual(salida.count('class="serie-kev punto"'), 6)
        self.assertIn("<title>sep 2026 · En KEV: 1</title>", salida)
        # la leyenda marca la línea con una raya (linea-kev), no con el cuadrado de una serie
        self.assertIn('class="leyenda-punto linea-kev"></span>En KEV <b>21</b>', salida)
        self.assertNotIn("leyenda-punto serie-kev", salida)
        sin = str(g.barras_apiladas(MESES_6, SERIES_6))
        self.assertNotIn("kev", sin)
        self.assertNotIn("linea-halo", sin)

    def test_linea_con_halo_bajo_el_trazo(self):
        salida = str(g.barras_apiladas(MESES_6, SERIES_6, linea=LINEA_KEV))
        halo = re.search(r'<polyline class="linea-halo" fill="none" points="([^"]+)"/>', salida)
        self.assertIsNotNone(halo)
        linea = re.search(r'<polyline class="linea-kev" points="([^"]+)">', salida)
        self.assertEqual(halo.group(1), linea.group(1))          # mismo trazado
        self.assertLess(halo.start(), linea.start())              # el halo va debajo
        # el halo se pinta sobre las barras (después de todos los rect) y antes de los puntos
        self.assertGreater(halo.start(), salida.rfind("<rect "))
        self.assertLess(halo.start(), salida.find('class="serie-kev punto"'))
        # con una sola categoría no hay línea ni halo, solo el punto
        uno = str(g.barras_apiladas(["m"], [{"clave": "alto", "valores": [30]}],
                                    linea={"clave": "kev", "nombre": "En KEV", "valores": [2]}))
        self.assertNotIn("<polyline", uno)
        self.assertIn('class="serie-kev punto"', uno)

    def test_linea_pegada_al_eje_rotula_sus_valores(self):
        # KEV 1-6 sobre un eje 0-1.500 (< 5 % del tope): valor sobre cada punto, a 7 px
        salida = str(g.barras_apiladas(MESES_6, SERIES_6, linea=LINEA_KEV))
        rotulos = re.findall(r'<circle class="serie-kev punto" cx="([\d.]+)" cy="([\d.]+)" r="3.5">.*?</circle>'
                             r'<text class="etiqueta-valor etiqueta-linea" x="([\d.]+)" y="([\d.]+)" '
                             r'text-anchor="middle">([^<]+)</text>', salida)
        self.assertEqual([r[4] for r in rotulos], ["3", "5", "2", "6", "4", "1"])
        for cx, cy, x, y, _ in rotulos:
            self.assertEqual(cx, x)
            self.assertAlmostEqual(float(cy) - float(y), 7.0, places=2)
        # los ceros no se rotulan
        con_cero = str(g.barras_apiladas(MESES_6, SERIES_6,
                                         linea={"clave": "kev", "nombre": "En KEV", "valores": [3, 0, 2, 0, 4, 1]}))
        self.assertEqual(con_cero.count("etiqueta-linea"), 4)
        self.assertEqual(con_cero.count('class="serie-kev punto"'), 6)
        # una línea que sí se ve (misma magnitud que las barras) no se rotula
        alta = str(g.barras_apiladas(MESES_6, SERIES_6,
                                     linea={"clave": "kev", "nombre": "En KEV", "valores": [300, 500, 200, 600, 400, 100]}))
        self.assertNotIn("etiqueta-linea", alta)
        self.assertIn("linea-halo", alta)
        # con mostrar_totales=False siguen rotulándose (son etiquetas de la línea, no totales)
        sin_totales = str(g.barras_apiladas(MESES_6, SERIES_6, linea=LINEA_KEV, mostrar_totales=False))
        self.assertEqual(sin_totales.count("etiqueta-linea"), 6)
        self.assertEqual(sin_totales.count('class="etiqueta-valor"'), 0)

    def test_rotulo_de_linea_no_pisa_un_total_a_la_misma_altura(self):
        salida = str(g.barras_apiladas(["a", "b"], [{"clave": "alto", "nombre": "A", "valores": [100, 2]}],
                                       linea={"clave": "kev", "nombre": "K", "valores": [1, 2]}))
        rotulos = re.findall(r'etiqueta-linea" x="[\d.]+" y="[\d.]+" text-anchor="middle">([^<]+)</text>', salida)
        self.assertEqual(rotulos, ["1"])  # en «b» el total (2) está donde iría el rótulo: se omite
        self.assertIn("<title>b · K: 2</title>", salida)  # pero el valor sigue en el tooltip

    def _etiquetas_x(self, salida: str) -> list[tuple[float, str]]:
        # Las etiquetas X son las de text-anchor="middle" con clase eje en la y máxima.
        textos = re.findall(r'<text class="eje" x="([\d.]+)" y="([\d.]+)" text-anchor="middle">([^<]*)</text>', salida)
        y_max = max(float(t[1]) for t in textos)
        return [(float(x), etq) for x, y, etq in textos if float(y) == y_max]

    MESES_24 = [f"{m} 2025" for m in ("ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct", "nov", "dic")] \
        + [f"{m} 2026" for m in ("ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct", "nov", "dic")]

    def test_etiquetas_x_espaciadas_solo_si_no_caben(self):
        series = [{"clave": "medio", "nombre": "Medias", "valores": [1000 + i for i in range(24)]}]
        salida = str(g.barras_apiladas(self.MESES_24, series, linea=LINEA_KEV))
        etiquetas = self._etiquetas_x(salida)
        self.assertLessEqual(len(etiquetas), 12)
        self.assertGreaterEqual(len(etiquetas), 6)
        self.assertEqual(etiquetas[0][1], "ene 2025")   # la primera siempre se muestra
        self.assertEqual(etiquetas[-1][1], "dic 2026")  # y la más reciente también
        # sin solapes: la distancia entre etiquetas consecutivas supera su anchura estimada
        for (x0, e0), (x1, _) in zip(etiquetas, etiquetas[1:]):
            self.assertGreater(x1 - x0, len(e0) * 6.6, (e0, x0, x1))
        # totales sobre barras también espaciados (1.0xx ocupa ~36px, la ranura ~28px)
        totales = re.findall(r'class="etiqueta-valor" x="([\d.]+)"', salida)
        self.assertLess(len(totales), 24)
        # con 6 categorías se muestran todas
        self.assertEqual(len(self._etiquetas_x(str(g.barras_apiladas(MESES_6, SERIES_6)))), 6)

    def test_mas_de_ocho_categorias_no_fuerza_alternancia_si_caben(self):
        # 10 etiquetas «sep 26» (6 caracteres ≈ 40 px) en 1.100 px de ancho caben todas
        meses = [f"{m} 26" for m in ("ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct")]
        series = [{"clave": "medio", "nombre": "Medias", "valores": list(range(10, 20))}]
        etiquetas = self._etiquetas_x(str(g.barras_apiladas(meses, series, ancho=1100)))
        self.assertEqual([e for _, e in etiquetas], meses)
        # con 24 meses de 8 caracteres a 1.100 px (ranura ≈ 43 px < 61 px) se alternan: 12 etiquetas
        largo = str(g.barras_apiladas(self.MESES_24, [{"clave": "medio", "valores": [5] * 24}], ancho=1100))
        etiquetas = self._etiquetas_x(largo)
        self.assertEqual(len(etiquetas), 12)
        self.assertEqual((etiquetas[0][1], etiquetas[-1][1]), ("ene 2025", "dic 2026"))
        # y con muy poco ancho, muy pocas etiquetas pero siempre la primera y la última, sin solapes
        estrecho = str(g.barras_apiladas(self.MESES_24, [{"clave": "medio", "valores": [5] * 24}], ancho=300))
        etiquetas = self._etiquetas_x(estrecho)
        self.assertEqual((etiquetas[0][1], etiquetas[-1][1]), ("ene 2025", "dic 2026"))
        for (x0, e0), (x1, _) in zip(etiquetas, etiquetas[1:]):
            self.assertGreater(x1 - x0, len(e0) * 6.6, (e0, x0, x1))

    def test_etiquetas_de_dos_lineas_mes_y_anio(self):
        """«sep\\n2026»: mes arriba y año completo debajo, en tspans; el margen inferior
        crece una línea y los títulos y el texto accesible van en una sola línea."""
        meses = [f"{m}\n2026" for m in ("ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct", "nov", "dic")]
        series = [{"clave": "medio", "nombre": "Medias", "valores": list(range(10, 22))}]
        salida = str(g.barras_apiladas(meses, series))
        self.assertEqual(salida.count('<tspan x="'), 24)  # 12 etiquetas × 2 líneas, ninguna omitida
        self.assertIn('dy="14">2026</tspan>', salida)
        self.assertIn("<title>sep 2026 · Medias: 18 (100 %)</title>", salida)
        self.assertIn("de ene 2026 a dic 2026", salida)
        self.assertNotIn("ene\n2026 ·", salida)
        una_linea = str(g.barras_apiladas([f"{m} 2026" for m in ("ene", "feb", "mar")], [{"clave": "medio", "valores": [1, 2, 3]}]))
        alto_una = float(re.search(r'viewBox="0 0 [\d.]+ ([\d.]+)"', una_linea).group(1))
        alto_dos = float(re.search(r'viewBox="0 0 [\d.]+ ([\d.]+)"', str(g.barras_apiladas(meses[:3], [{"clave": "medio", "valores": [1, 2, 3]}]))).group(1))
        self.assertEqual(alto_dos, alto_una)  # el alto total se respeta: el margen se gana al área de dibujo
        self.assertIn('<tspan x="', str(g.linea_tiempo(meses, [{"clave": "acento", "nombre": "CVSS", "valores": [7] * 12}])))

    def test_categorico_nunca_omite_nombres(self):
        """Con categorico=True cada categoría lleva su nombre: los largos se reparten por
        palabras en varias líneas y, si ni así caben, se recortan con «…» y título completo."""
        categorias = ["Aplicación", "Utilidad", "Desarrollo", "Sistema operativo", "Colaboración",
                      "Base de datos", "Seguridad", "Otras 14 categorías"]
        series = [{"clave": "exito", "nombre": "Con versión", "valores": [75, 24, 8, 3, 3, 5, 5, 31]},
                  {"clave": "medio", "nombre": "Sin versión", "valores": [17, 1, 3, 8, 5, 1, 1, 8]}]
        salida = str(g.barras_apiladas(categorias, series, ancho=1100, alto=240, categorico=True))
        for nombre in ("Aplicación", "Utilidad", "Desarrollo", "Colaboración", "Seguridad"):
            self.assertIn(f'text-anchor="middle">{nombre}</text>', salida, nombre)
        self.assertIn('text-anchor="middle">Sistema operativo</text>', salida)   # cabe en su ranura (≈132 px)
        self.assertIn(">Otras 14</tspan>", salida)                 # «Otras 14 categorías» no cabe: dos líneas
        self.assertIn(">categorías</tspan>", salida)
        self.assertNotIn("…", salida)
        # muy estrecho: se recorta con «…» pero el nombre completo queda en el título
        estrecho = str(g.barras_apiladas(["Virtualización", "Correo"], [{"clave": "exito", "valores": [1, 2]}],
                                         ancho=160, categorico=True))
        self.assertIn("…", estrecho)
        self.assertIn("<title>Virtualización</title>", estrecho)
        self.assertIn(">Correo</text>", estrecho)
        # sin categorico (serie temporal) el comportamiento anterior no cambia: se espacian
        temporal = str(g.barras_apiladas(self.MESES_24, [{"clave": "medio", "valores": [5] * 24}], ancho=300))
        self.assertLess(len(self._etiquetas_x(temporal)), 24)

    def test_indices_de_etiquetas_primera_y_ultima(self):
        self.assertEqual(g._indices_etiquetas(24, 2), [0, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23])
        self.assertEqual(g._indices_etiquetas(7, 3), [0, 3, 6])
        self.assertEqual(g._indices_etiquetas(6, 4), [0, 5])
        self.assertEqual(g._indices_etiquetas(5, 1), [0, 1, 2, 3, 4])
        self.assertEqual(g._indices_etiquetas(1, 3), [0])
        self.assertEqual(g._indices_etiquetas(0, 1), [])
        self.assertEqual(g._indices_etiquetas(2, 5), [0, 1])  # primera y última aunque el paso sea mayor
        for n in range(1, 40):
            for paso in range(1, 8):
                indices = g._indices_etiquetas(n, paso)
                self.assertEqual(indices[0], 0)
                self.assertEqual(indices[-1], n - 1)
                for a, b in zip(indices, indices[1:]):
                    self.assertGreaterEqual(b - a, min(paso, n - 1), (n, paso, indices))

    def test_margen_izquierdo_crece_con_numeros_largos(self):
        pequeno = str(g.barras_apiladas(["a"], [{"clave": "alto", "valores": [5]}]))
        grande = str(g.barras_apiladas(["a"], [{"clave": "alto", "valores": [1_234_567]}]))
        x_p = float(re.search(r'class="eje-linea" x1="([\d.]+)"', pequeno).group(1))
        x_g = float(re.search(r'class="eje-linea" x1="([\d.]+)"', grande).group(1))
        self.assertGreater(x_g, x_p)
        # la etiqueta más larga cabe: su anchura estimada es menor que el margen
        self.assertIn('text-anchor="end">1.250.000</text>', grande)
        self.assertGreater(x_g - 8, len("1.250.000") * 6.6)

    def test_categorias_hostiles_escapadas_en_eje_y_title(self):
        salida = str(g.barras_apiladas([HOSTIL], [{"clave": "alto", "nombre": "A", "valores": [1]}]))
        self.assertNotIn(HOSTIL, salida)
        self.assertIn("<title>&lt;script&gt;alert(1)&lt;/script&gt; · A: 1 (100 %)</title>", salida)


# ==========================================================================
# Barras horizontales
# ==========================================================================
class TestBarrasHorizontales(unittest.TestCase):

    def test_recorte_con_puntos_suspensivos_y_nombre_completo_en_title(self):
        largo = "Tecnología con un nombre extraordinariamente largo para la etiqueta"
        salida = str(g.barras_horizontales([{"etiqueta": largo, "valores": [("alto", 2)]}], max_etiqueta=20))
        self.assertIn(f"<title>{largo}</title>", salida)
        m = re.search(r"</title>([^<]+)</text>", salida)
        self.assertTrue(m.group(1).endswith("…"))
        self.assertLessEqual(len(m.group(1)), 20)
        corto = str(g.barras_horizontales([{"etiqueta": "Nginx", "valores": [("alto", 2)]}]))
        self.assertIn("<title>Nginx</title>Nginx</text>", corto)

    def test_href_dentro_del_svg(self):
        salida = str(g.barras_horizontales(ITEMS))
        self.assertIn('<a href="/amenazas/?tec=windows-server"><text class="eje"', salida)
        self.assertEqual(salida.count("<a "), 2)  # FortiOS no lleva enlace
        self.assertEqual(salida.count("</a>"), 2)

    def test_cada_segmento_con_title_y_porcentaje_de_la_fila(self):
        salida = str(g.barras_horizontales(ITEMS))
        self.assertIn("<title>Windows Server · Críticas: 3 (17 %)</title>", salida)
        self.assertIn("<title>Windows Server · Altas: 5 (28 %)</title>", salida)
        self.assertIn("<title>Windows Server · Otras: 10 (56 %)</title>", salida)
        rects = re.findall(r"<rect[^>]*>(.*?)</rect>", salida)
        self.assertEqual(len(rects), 8)  # 9 segmentos, uno a 0 se omite
        for r in rects:
            self.assertTrue(r.startswith("<title>"))

    def test_fila_con_un_unico_segmento_sin_porcentaje(self):
        salida = str(g.barras_horizontales([
            {"etiqueta": "CVE-2026-0001", "valores": [("acento", 5, "Meses presentes")]},
            {"etiqueta": "Solo altas", "valores": [("critico", 0), ("alto", 4)]},   # el 0 no cuenta
            {"etiqueta": "Dos", "valores": [("critico", 1), ("alto", 3)]},
        ]))
        self.assertIn("<title>CVE-2026-0001 · Meses presentes: 5</title>", salida)
        self.assertIn("<title>Solo altas · Altas: 4</title>", salida)
        self.assertNotIn("(100 %)", salida)
        self.assertIn("<title>Dos · Críticas: 1 (25 %)</title>", salida)  # con varios sí hay porcentaje
        self.assertIn("<title>Dos · Altas: 3 (75 %)</title>", salida)

    def test_escala_comun_y_alto_por_fila(self):
        salida = str(g.barras_horizontales(ITEMS, ancho=760, alto_fila=28))
        alto = float(re.search(r'viewBox="0 0 [\d.]+ ([\d.]+)"', salida).group(1))
        self.assertEqual(alto, 3 * 28 + 8)
        anchos_fila = {}
        for x, w, titulo in re.findall(r'<rect class="serie-[a-z0-9-]+" x="([\d.]+)" y="[\d.]+" width="([\d.]+)" height="[\d.]+"><title>([^·]+) ·', salida):
            anchos_fila[titulo] = anchos_fila.get(titulo, 0) + float(w)
        # Windows (18) ocupa el doble que Fortinet (6) × 3 = 18 → 3 veces Cisco (7)?  Escala común: proporcional.
        self.assertAlmostEqual(anchos_fila["Windows Server"] / anchos_fila["Fortinet FortiOS"], 18 / 6, places=1)
        self.assertAlmostEqual(anchos_fila["Windows Server"] / anchos_fila["Cisco IOS XE"], 18 / 7, places=1)

    def test_total_y_nota_al_final_de_la_fila(self):
        salida = str(g.barras_horizontales(ITEMS))
        self.assertIn('<text class="etiqueta-valor"', salida)
        self.assertIn('18<tspan class="nota"> · sin versión</tspan></text>', salida)
        self.assertIn(">7</text>", salida)
        sin = str(g.barras_horizontales(ITEMS, mostrar_total=False))
        self.assertNotIn(">18<", sin)
        self.assertIn('<tspan class="nota">sin versión</tspan>', sin)

    def test_leyenda_con_totales_por_clave_y_nombres(self):
        salida = str(g.barras_horizontales(ITEMS))
        self.assertIn("Críticas <b>4</b>", salida)
        self.assertIn("Altas <b>11</b>", salida)
        self.assertIn("Otras <b>16</b>", salida)
        con_nombres = str(g.barras_horizontales(ITEMS, nombres={"neutro": "Resto"}))
        self.assertIn("Resto <b>16</b>", con_nombres)
        self.assertIn("<title>Windows Server · Resto: 10 (56 %)</title>", con_nombres)
        tuplas = str(g.barras_horizontales([{"etiqueta": "T", "valores": [("exito", 3, "Confirmadas"),
                                                                            {"clave": "neutro", "valor": 1, "nombre": "Sin determinar"}]}]))
        self.assertIn("Confirmadas <b>3</b>", tuplas)
        self.assertIn("Sin determinar <b>1</b>", tuplas)

    def test_volumen_real_veinte_tecnologias(self):
        items = [{"etiqueta": f"Tecnología número {i} con nombre largo", "valores": [("critico", i), ("alto", 2 * i), ("neutro", 40 - i)],
                  "href": f"/amenazas/?tec={i}", "nota": "sin versión" if i % 3 else ""} for i in range(1, 21)]
        salida = str(g.barras_horizontales(items))
        self.assertEqual(salida.count("<a "), 20)
        self.assertEqual(salida.count("…</text>"), 20)
        self.assertIn('viewBox="0 0 760 568"', salida)
        # la barra más larga termina antes del margen derecho reservado para el total y la nota
        x_fin = max(float(x) + float(w) for x, w in re.findall(r'<rect[^>]* x="([\d.]+)" y="[\d.]+" width="([\d.]+)"', salida))
        self.assertLess(x_fin + len("60 · sin versión") * 7.2, 760)


# ==========================================================================
# Dona
# ==========================================================================
class TestDona(unittest.TestCase):

    def test_suma_de_porciones_y_porcentajes(self):
        salida = str(g.dona(PORCIONES))
        self.assertIn("total 107", salida)
        self.assertIn("Críticas <b>10</b> (9 %)", salida)
        self.assertIn("Altas <b>14</b> (13 %)", salida)
        self.assertIn("Medias <b>83</b> (78 %)", salida)
        self.assertIn("<title>Medias: 83 (78 %)</title>", salida)

    def test_porcion_cero_omitida_del_dibujo_pero_en_leyenda(self):
        salida = str(g.dona(PORCIONES))
        self.assertEqual(salida.count("<path"), 3)
        self.assertNotIn('<path class="serie-bajo"', salida)
        self.assertIn("Bajas <b>0</b> (0 %)", salida)
        self.assertEqual(salida.count("<li>"), 4)

    def test_porcentajes_suman_cien_por_mayor_resto(self):
        # 33,3 % × 3 redondeado por separado daría 99: el mayor resto reparte el que falta
        tres = str(g.dona([{"clave": "critico", "nombre": "A", "valor": 1},
                           {"clave": "alto", "nombre": "B", "valor": 1},
                           {"clave": "medio", "nombre": "C", "valor": 1}]))
        self.assertEqual(re.findall(r"<b>\d+</b> \((\d+) %\)", tres), ["34", "33", "33"])
        self.assertIn("<title>A: 1 (34 %)</title>", tres)  # el <title> y el aria usan el mismo reparto
        self.assertIn("A 1 (34 %); B 1 (33 %); C 1 (33 %)", tres)
        # 25 + 37,5 + 37,5 redondeado por separado daría 101
        salida = str(g.dona([{"clave": "critico", "nombre": "A", "valor": 2},
                             {"clave": "alto", "nombre": "B", "valor": 3},
                             {"clave": "medio", "nombre": "C", "valor": 3}]))
        self.assertEqual(re.findall(r"<b>\d+</b> \((\d+) %\)", salida), ["25", "38", "37"])
        # el caso de la revisión visual: 3 + 44 + 40 + 12 = 99 → 3 + 45 + 40 + 12
        salida = str(g.dona([{"clave": f"cat-{i}", "nombre": f"P{i}", "valor": v}
                             for i, v in enumerate((7, 106, 96, 30), start=1)]))
        self.assertEqual(sum(int(p) for p in re.findall(r"<b>\d+</b> \((\d+) %\)", salida)), 100)
        for valores in ([1, 1, 1, 1, 1, 1, 1], [5, 5, 6], [1, 2, 4, 8, 16, 32, 64], [999, 1], [3, 44, 40, 12]):
            with self.subTest(valores=valores):
                pcts = g._porcentajes(valores, sum(valores))
                # «<1 %» no es una cifra: cuenta como 0 en la suma
                self.assertEqual(sum(0 if p.startswith("<") else int(p.rstrip(" %")) for p in pcts), 100)

    def test_porcentajes_auxiliar(self):
        self.assertEqual(g._porcentajes([10, 14, 83, 0], 107), ["9 %", "13 %", "78 %", "0 %"])
        self.assertEqual(g._porcentajes([1, 999], 1000), ["<1 %", "100 %"])   # la parte ínfima no es 0
        self.assertEqual(g._porcentajes([7], 72), ["10 %"])                  # con hueco no se fuerza el 100
        self.assertEqual(g._porcentajes([1, 1], 0), ["0 %", "0 %"])
        self.assertEqual(g._porcentajes([], 5), [])

    def test_los_arcos_cierran_el_circulo(self):
        salida = str(g.dona(PORCIONES, tamano=200, grosor=24))
        paths = re.findall(r'd="M([\d.]+) ([\d.]+) A', salida)
        # el primer arco empieza arriba (12 en punto) y el último termina en el mismo punto
        self.assertEqual(paths[0], ("100", "2"))
        ultimo = re.findall(r'd="[^"]*"', salida)[-1]
        self.assertIn("A98 98 0 1 1 100 2", ultimo)  # el último arco vuelve al inicio

    def test_una_sola_porcion_giro_completo(self):
        salida = str(g.dona([{"clave": "exito", "nombre": "Operativas", "valor": 55}]))
        d = re.search(r'd="([^"]+)"', salida).group(1)
        self.assertEqual(d.count("M"), 2)  # dos mitades: un arco de 360° no se pinta
        self.assertIn("Operativas <b>55</b> (100 %)", salida)

    def test_centro(self):
        salida = str(g.dona(PORCIONES, centro_valor=124, centro_etiqueta="amenazas"))
        self.assertIn('<text class="dona-centro" x="100" y="104" text-anchor="middle">124</text>', salida)
        self.assertIn('class="dona-centro-etiqueta"', salida)
        self.assertIn(">amenazas</text>", salida)
        solo_valor = str(g.dona(PORCIONES, centro_valor=1234.5))
        self.assertIn(">1.234,5</text>", solo_valor)
        self.assertNotIn("dona-centro-etiqueta", solo_valor)
        self.assertNotIn("dona-centro", str(g.dona(PORCIONES)))
        texto = str(g.dona(PORCIONES, centro_valor="7,5 %"))
        self.assertIn(">7,5 %</text>", texto)

    def test_tamano_y_grosor(self):
        salida = str(g.dona(PORCIONES, tamano=120, grosor=16))
        self.assertIn('viewBox="0 0 120 120"', salida)
        self.assertIn("A58 58", salida)  # radio exterior = 60 - 2
        self.assertIn("A42 42", salida)  # radio interior = 58 - 16


# ==========================================================================
# Línea de tiempo
# ==========================================================================
class TestLineaTiempo(unittest.TestCase):
    ETQS = [str(i) for i in range(1, 61)]

    def test_estructura_y_unidad(self):
        salida = str(g.linea_tiempo(["a", "b", "c"], [{"clave": "acento", "nombre": "Latencia", "valores": [120, 80, 95]}], unidad="ms"))
        self.assertIn("grafico-linea-tiempo", salida)
        self.assertEqual(salida.count('<polyline class="linea-acento"'), 1)
        self.assertEqual(salida.count('<path class="area-acento"'), 1)
        self.assertEqual(salida.count("<circle"), 3)
        self.assertIn('text-anchor="end">0 ms</text>', salida)
        self.assertIn("<title>b · Latencia: 80 ms</title>", salida)
        self.assertIn("Latencia <b>95 ms</b> (último valor)", salida)
        # máximo 120 → eje 0-125 ms en pasos de 25 (5 divisiones)
        self.assertEqual(salida.count('class="rejilla"'), 5)
        self.assertIn('text-anchor="end">125 ms</text>', salida)

    def test_tope_fijo(self):
        cvss = [{"clave": "acento", "nombre": "CVSS medio", "valores": [6.4, 7.1, 5.9]}]
        salida = str(g.linea_tiempo(["a", "b", "c"], cvss, tope=10))
        etiquetas_y = re.findall(r'text-anchor="end">([^<]+)</text>', salida)
        self.assertEqual(etiquetas_y, ["0", "2", "4", "6", "8", "10"])
        # la rejilla superior está en el tope (10) y el punto de 7,1 queda a 71 % de altura
        y0 = float(re.search(r'class="eje-linea"[^>]*y1="([\d.]+)"', salida).group(1))
        y_tope = min(float(y) for y in re.findall(r'class="rejilla"[^>]*y1="([\d.]+)"', salida))
        cy = float(re.search(r'<circle[^>]*cy="([\d.]+)"[^>]*><title>b · ', salida).group(1))
        self.assertAlmostEqual((y0 - cy) / (y0 - y_tope), 0.71, places=2)
        # sin tope, el eje se ajusta al máximo (7,1 → 0-8)
        auto = str(g.linea_tiempo(["a", "b", "c"], cvss))
        self.assertEqual(re.findall(r'text-anchor="end">([^<]+)</text>', auto), ["0", "2", "4", "6", "8"])
        # topes no válidos → automático; 100 → 0/20/40/60/80/100; 1 → décimas
        for malo in (None, 0, -5, "x", float("nan")):
            self.assertEqual(str(g.linea_tiempo(["a", "b", "c"], cvss, tope=malo)), auto)
        self.assertEqual(re.findall(r'text-anchor="end">([^<]+)</text>',
                                    str(g.linea_tiempo(["a", "b"], [{"clave": "acento", "valores": [40, 55]}], tope=100))),
                         ["0", "20", "40", "60", "80", "100"])
        self.assertEqual(re.findall(r'text-anchor="end">([^<]+)</text>',
                                    str(g.linea_tiempo(["a", "b"], [{"clave": "acento", "valores": [0.4, 0.55]}], tope=1))),
                         ["0", "0,2", "0,4", "0,6", "0,8", "1"])

    def test_tope_fijo_recorta_el_dibujo_pero_no_el_dato(self):
        salida = str(g.linea_tiempo(["a", "b"], [{"clave": "acento", "nombre": "L", "valores": [5, 14]}], tope=10))
        y_tope = min(float(y) for y in re.findall(r'class="rejilla"[^>]*y1="([\d.]+)"', salida))
        cy = float(re.search(r'<circle[^>]*cy="([\d.]+)"[^>]*><title>b · ', salida).group(1))
        self.assertAlmostEqual(cy, y_tope, places=2)          # dibujado en el borde superior
        self.assertIn("<title>b · L: 14</title>", salida)      # con su cifra real
        self.assertIn("máximo 14", salida)                     # también en el aria-label

    def test_varias_series_sin_area(self):
        salida = str(g.linea_tiempo(["a", "b"], [
            {"clave": "acento", "nombre": "Latencia", "valores": [1, 2]},
            {"clave": "secundario", "nombre": "Entradas", "valores": [3, 4]},
        ], area=False))
        self.assertNotIn("<path", salida)
        self.assertIn("linea-acento", salida)
        self.assertIn("linea-secundario", salida)
        self.assertEqual(salida.count("<li>"), 2)

    def test_todo_none_es_vacio_pero_todo_cero_se_dibuja(self):
        self.assertIn("grafico-vacio", str(g.linea_tiempo(["a", "b"], [{"clave": "acento", "valores": [None, None]}])))
        plana = str(g.linea_tiempo(["a", "b"], [{"clave": "acento", "valores": [0, 0]}]))
        self.assertIn("<polyline", plana)

    def test_sesenta_comprobaciones_sin_solapes(self):
        salida = str(g.linea_tiempo(self.ETQS, [{"clave": "acento", "nombre": "Latencia (ms)", "valores": [200 + (i * 37) % 900 for i in range(60)]}], unidad="ms"))
        self.assertEqual(salida.count("<circle"), 60)
        self.assertIn('r="2.5"', salida)
        textos = re.findall(r'<text class="eje" x="([\d.]+)" y="([\d.]+)" text-anchor="middle">([^<]*)</text>', salida)
        y_max = max(float(t[1]) for t in textos)
        xs = [(float(x), e) for x, y, e in textos if float(y) == y_max]
        self.assertLess(len(xs), 60)
        self.assertEqual(xs[-1][1], "60")
        for (x0, e0), (x1, _) in zip(xs, xs[1:]):
            self.assertGreater(x1 - x0, len(e0) * 6.6)

    def test_valor_unico(self):
        salida = str(g.linea_tiempo(["a"], [{"clave": "acento", "valores": [5]}]))
        self.assertIn("<circle", salida)
        self.assertNotIn("<polyline", salida)


# ==========================================================================
# Barra de progreso
# ==========================================================================
class TestBarraProgreso(unittest.TestCase):
    PARTES = [{"clave": "exito", "nombre": "Con CVSS oficial", "valor": 120},
              {"clave": "neutro", "nombre": "Pendientes", "valor": 2054}]

    def test_viewbox_100_y_preserve_aspect_ratio(self):
        salida = str(g.barra_progreso(self.PARTES))
        self.assertIn('viewBox="0 0 100 10"', salida)
        self.assertIn('preserveAspectRatio="none"', salida)
        self.assertIn('<div class="progreso">', salida)
        self.assertIn('class="grafico-envoltorio grafico-progreso"', salida)
        self.assertIn('role="img"', salida)

    def test_anchos_suman_100_y_encadenan(self):
        salida = str(g.barra_progreso(self.PARTES))
        rects = re.findall(r'<rect class="serie-[a-z0-9-]+" x="([\d.]+)" y="0" width="([\d.]+)" height="10">', salida)
        self.assertEqual(len(rects), 2)
        self.assertAlmostEqual(sum(float(w) for _, w in rects), 100, places=1)
        self.assertAlmostEqual(float(rects[1][0]), float(rects[0][1]), places=2)
        self.assertIn("<title>Con CVSS oficial: 120 (6 %)</title>", salida)
        self.assertIn("Pendientes <b>2.054</b> (94 %)", salida)

    def test_total_mayor_que_la_suma_deja_hueco(self):
        salida = str(g.barra_progreso([{"clave": "exito", "nombre": "Con versión", "valor": 7}], total=72))
        w = float(re.search(r'width="([\d.]+)" height', salida).group(1))
        self.assertAlmostEqual(w, 100 * 7 / 72, places=2)
        self.assertIn("Con versión <b>7</b> (10 %)", salida)
        self.assertIn('<li class="leyenda-total">Total <b>72</b></li>', salida)
        # un total menor que la suma no recorta nada
        self.assertNotIn("leyenda-total", str(g.barra_progreso(self.PARTES, total=5)))

    def test_alto_distinto_de_diez(self):
        salida = str(g.barra_progreso(self.PARTES, alto=16))
        self.assertIn('viewBox="0 0 100 16"', salida)
        self.assertIn('<div class="progreso progreso-16">', salida)

    def test_porcentaje_menor_del_uno(self):
        salida = str(g.barra_progreso([{"clave": "exito", "nombre": "A", "valor": 1},
                                       {"clave": "neutro", "nombre": "B", "valor": 999}]))
        self.assertIn("A <b>1</b> (&lt;1 %)", salida)

    def test_porcentajes_suman_cien_por_mayor_resto(self):
        partes = [{"clave": "exito", "nombre": "NVD", "valor": 1},
                  {"clave": "acento", "nombre": "Vector", "valor": 1},
                  {"clave": "kev", "nombre": "KEV", "valor": 1}]
        salida = str(g.barra_progreso(partes))
        self.assertEqual(re.findall(r"<b>\d+</b> \((\d+) %\)", salida), ["34", "33", "33"])
        self.assertIn("<title>NVD: 1 (34 %)</title>", salida)
        self.assertIn("NVD 1 (34 %); Vector 1 (33 %); KEV 1 (33 %)", salida)  # aria-label
        # con hueco (total > suma) las partes suman lo que les corresponde, no 100
        hueco = str(g.barra_progreso(partes, total=6))
        self.assertEqual(re.findall(r"<b>\d+</b> \((\d+) %\)", hueco), ["17", "17", "16"])


# ==========================================================================
# Medidor
# ==========================================================================
class TestMedidor(unittest.TestCase):

    def test_umbrales_cvss(self):
        esperado = {3.9: "bajo", 4.0: "medio", 6.9: "medio", 7.0: "alto", 8.9: "alto", 9.0: "critico", 10: "critico"}
        for valor, clave in esperado.items():
            with self.subTest(valor=valor):
                salida = str(g.medidor(valor, 10, etiqueta="CVSS", umbrales=UMBRALES_CVSS))
                self.assertIn(f'class="serie-{clave} medidor-valor"', salida)
                self.assertIn(f"texto-{clave}", salida)

    def test_umbrales_epss_con_sufijo(self):
        salida = str(g.medidor(63.04, 100, etiqueta="EPSS", sufijo="%",
                               umbrales=[(10, "bajo"), (30, "medio"), (60, "alto"), (INF, "critico")]))
        self.assertIn("serie-critico medidor-valor", salida)
        self.assertIn(">63,0 %</text>", salida)
        self.assertIn("<title>EPSS: 63,0 % de 100</title>", salida)
        self.assertIn('aria-label="Medidor EPSS: 63,0 % de 100 %"', salida)

    def test_none_muestra_raya_y_solo_arco_neutro(self):
        salida = str(g.medidor(None, 10, etiqueta="CVSS", umbrales=UMBRALES_CVSS))
        self.assertIn(">—</text>", salida)
        self.assertIn('class="serie-neutro medidor-fondo"', salida)
        self.assertNotIn("medidor-valor", salida)
        self.assertIn("texto-neutro", salida)
        self.assertIn("sin dato", salida)
        self.assertNotIn("grafico-vacio", salida)
        vacio = str(g.medidor("", 10))  # cadena vacía también es «sin dato»
        self.assertIn(">—</text>", vacio)
        self.assertNotIn("medidor-valor", vacio)
        self.assertIn('aria-label="Medidor: sin dato"', vacio)

    def test_estructura_semicirculo(self):
        salida = str(g.medidor(5, 10, etiqueta="Relevancia", tamano=160, umbrales=UMBRALES_CVSS))
        self.assertIn('class="grafico-envoltorio grafico-medidor"', salida)
        self.assertIn('viewBox="0 0 160 106"', salida)
        fondo = re.search(r'medidor-fondo" d="([^"]+)"', salida).group(1)
        self.assertTrue(fondo.startswith("M4 80 A76 76 0 0 1 156 80"))  # de izquierda a derecha por arriba
        valor = re.search(r'medidor-valor" d="([^"]+)"', salida).group(1)
        self.assertTrue(valor.startswith("M4 80 A76 76 0 0 1 80 4"))     # 50 % llega a las 12
        self.assertIn('class="dona-centro medidor-texto texto-medio" x="80"', salida)
        self.assertIn(">Relevancia</text>", salida)
        self.assertIn('text-anchor="middle">0</text>', salida)
        self.assertIn('text-anchor="middle">10</text>', salida)

    def test_valor_que_supera_el_maximo_se_recorta(self):
        salida = str(g.medidor(15, 10, umbrales=UMBRALES_CVSS))
        valor = re.search(r'medidor-valor" d="([^"]+)"', salida).group(1)
        self.assertIn("A76 76 0 0 1 156 80", valor)  # arco completo, no más
        self.assertIn(">15,0</text>", salida)          # el número se muestra tal cual
        self.assertIn("serie-critico", salida)

    def test_umbrales_por_defecto_y_decimales(self):
        self.assertIn("serie-bajo medidor-valor", str(g.medidor(20, 100)))
        self.assertIn("serie-medio medidor-valor", str(g.medidor(30, 100)))
        self.assertIn("serie-alto medidor-valor", str(g.medidor(60, 100)))
        self.assertIn("serie-critico medidor-valor", str(g.medidor(90, 100)))
        self.assertIn(">7,46</text>", str(g.medidor(7.456, 10, decimales=2)))
        self.assertIn(">7</text>", str(g.medidor(7, 10, decimales=0)))
        self.assertIn(">0,0</text>", str(g.medidor(0, 10)))
        self.assertNotIn("medidor-valor", str(g.medidor(0, 10)))

    def test_etiqueta_hostil_escapada(self):
        salida = str(g.medidor(5, 10, etiqueta=HOSTIL))
        self.assertNotIn(HOSTIL, salida)
        self.assertIn("&lt;script&gt;", salida)


# ==========================================================================
# Flujo
# ==========================================================================
class TestFlujo(unittest.TestCase):

    def test_estados_y_flechas(self):
        salida = str(g.flujo(PASOS))
        self.assertTrue(salida.startswith('<div class="flujo" role="group" aria-label="Diagrama de proceso de 4 pasos">'))
        for estado in ("ok", "atencion", "critico", "inactivo"):
            self.assertIn(f'<div class="flujo-paso {estado}">', salida)
            self.assertIn(f'<span class="punto {estado}" title="', salida)
        self.assertEqual(salida.count('<div class="flujo-flecha" aria-hidden="true">'), 3)
        self.assertEqual(salida.count("<svg"), 3)
        self.assertIn('stroke="currentColor"', salida)
        self.assertIn('fill="none"', salida)

    def test_contenido_de_las_tarjetas(self):
        salida = str(g.flujo(PASOS))
        self.assertIn('<div class="titulo"><span class="punto ok" title="Correcto"></span><a href="/fuentes/">Recolección</a></div>', salida)
        self.assertIn('<div class="valor">52 / 55</div>', salida)
        self.assertIn('<div class="nota">fuentes operativas</div>', salida)
        self.assertIn('<div class="valor">124</div>', salida)  # número formateado
        self.assertIn('title="Requiere atención"', salida)
        # sin nota ni valor no se emiten divs vacíos
        minimo = str(g.flujo([{"titulo": "Solo título", "estado": "ok"}]))
        self.assertNotIn('class="valor"', minimo)
        self.assertNotIn('class="nota"', minimo)

    def test_estado_desconocido_pasa_a_inactivo(self):
        salida = str(g.flujo([{"titulo": "X", "estado": "rarisimo"}, {"titulo": "Y"}, {"titulo": "Z", "estado": "OK"}]))
        self.assertEqual(salida.count('flujo-paso inactivo'), 2)
        self.assertIn('flujo-paso ok', salida)  # se normaliza a minúsculas
        self.assertNotIn("rarisimo", salida)

    def test_compacto(self):
        self.assertTrue(str(g.flujo(PASOS, compacto=True)).startswith('<div class="flujo compacto"'))

    def test_un_solo_paso_sin_flecha(self):
        salida = str(g.flujo(PASOS[:1]))
        self.assertNotIn("flujo-flecha", salida)
        self.assertEqual(salida.count("flujo-paso"), 1)


# ==========================================================================
# Escala del eje Y
# ==========================================================================
class TestEscala(unittest.TestCase):
    PASOS_REDONDOS = (1, 2, 2.5, 5)

    def _mantisa(self, paso: float) -> float:
        return paso / 10 ** math.floor(math.log10(paso))

    def test_ejemplos_de_la_revision(self):
        self.assertEqual(g._escala(24), (25.0, 5.0))       # no 40
        self.assertEqual(g._escala(540), (600.0, 200.0))   # no 800
        self.assertEqual(g._escala(1361), (1500.0, 500.0))
        self.assertEqual(g._escala(5), (5.0, 1.0))
        self.assertEqual(g._escala(100), (100.0, 20.0))
        self.assertEqual(g._escala(7.8), (8.0, 2.0))
        self.assertEqual(g._escala(61), (75.0, 25.0))

    def test_maximos_pequenos_y_no_validos(self):
        for m in (0, -1, 0.4, 1, 2, 3, float("nan"), INF):
            with self.subTest(maximo=m):
                self.assertEqual(g._escala(m), (3.0, 1.0))

    def test_divisiones_entre_tres_y_cinco_con_pasos_redondos_y_enteros(self):
        maximos = [i / 4 for i in range(13, 400)] + [10 ** k * f for k in range(2, 7) for f in (1, 1.3, 2.4, 5.4, 7.7, 9.9)]
        for m in maximos:
            with self.subTest(maximo=m):
                tope, paso = g._escala(m)
                self.assertGreaterEqual(tope, m)
                self.assertGreaterEqual(paso, 1)
                if paso < 25:
                    self.assertEqual(paso, int(paso))  # sin 2,5 en recuentos pequeños
                divisiones = round(tope / paso)
                self.assertAlmostEqual(tope, paso * divisiones)
                self.assertIn(divisiones, (3, 4, 5))
                self.assertTrue(any(abs(self._mantisa(paso) - f) < 1e-9 for f in self.PASOS_REDONDOS), paso)
                self.assertLess(tope - m, paso + 1e-9)  # no sobra más de una división

    def test_ticks(self):
        self.assertEqual(g._ticks(25, 5), [0, 5, 10, 15, 20, 25])
        self.assertEqual(g._ticks(10, 2), [0, 2, 4, 6, 8, 10])
        self.assertEqual([g.fmt(t) for t in g._ticks(1, 0.2)], ["0", "0,2", "0,4", "0,6", "0,8", "1"])

    def test_escala_fija(self):
        self.assertEqual(g._escala_fija(10), (10, 2.0))
        self.assertEqual(g._escala_fija(100), (100, 20.0))
        self.assertEqual(g._escala_fija(6), (6, 2.0))
        self.assertEqual(g._escala_fija(8), (8, 2.0))
        self.assertEqual(g._escala_fija(1), (1, 0.2))
        self.assertEqual(g._escala_fija(12), (12, 3.0))  # sin paso redondo → cuatro divisiones


# ==========================================================================
# Registro como global de Jinja
# ==========================================================================
class TestRegistroJinja(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from threatintel import db
        from threatintel.paths import BASE_DIR
        from webui import auth as _auth
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "graficos.db")
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            _auth.crear_usuario(conn, "pruebas", "PruebaSegura#2026", rol="admin", actor="test")
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def test_modulo_registrado_como_global(self):
        self.assertIs(self.app.jinja_env.globals.get("graficos"), g)

    def test_se_usa_desde_una_plantilla_sin_doble_escapado(self):
        plantilla = self.app.jinja_env.from_string(
            "{{ graficos.fmt(1234) }}|{{ graficos.dona(porciones, centro_valor=107) }}|"
            "{{ graficos.flujo(pasos) }}|{{ graficos.dona([]) }}")
        salida = plantilla.render(porciones=PORCIONES, pasos=PASOS)
        self.assertTrue(salida.startswith("1.234|<figure class=\"grafico-envoltorio grafico-dona\">"))
        self.assertIn('<div class="flujo"', salida)
        self.assertIn('<div class="grafico-vacio">Sin datos suficientes</div>', salida)
        self.assertNotIn("&lt;figure", salida)

    def test_las_paginas_siguen_respondiendo_con_csp_estricta(self):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": "pruebas", "password": "PruebaSegura#2026"})
        resp = cli.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn("unsafe-", resp.headers.get("Content-Security-Policy", ""))


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestUnidadDelTotal(unittest.TestCase):
    """El total de cada barra horizontal puede llevar su unidad («30.827 vulnerabilidades»):
    sin ella, la cifra no decía qué era (queja del usuario del 2026-09-08)."""

    def test_con_unidad_y_sin_unidad(self):
        from webui import graficos
        items = [{"etiqueta": "Servidores", "valores": [("critico", 1000), ("alto", 234)],
                  "nota": "3 de 4 servidores afectados"}]
        con = str(graficos.barras_horizontales(items, unidad="vulnerabilidades"))
        sin = str(graficos.barras_horizontales(items))
        self.assertIn("1.234 vulnerabilidades", con)
        self.assertIn("3 de 4 servidores afectados", con)
        self.assertNotIn("vulnerabilidades", sin)
        self.assertIn(">1.234<", sin.replace("</text>", "<"))

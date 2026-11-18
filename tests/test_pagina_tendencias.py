#!/usr/bin/env python3
"""Pruebas de renderizado de la página Tendencias (/amenazas/tendencias).

Rediseño del 2026-09-03 (sección 6 «Tendencias» de
docs/DISENO_INTERFAZ_2026-09-03.md): la página responde 200 con sesión, los
gráficos SVG están presentes y cumplen la CSP estricta (sin ``style=``, sin
``on*=``, sin ``<script>`` en línea, sin colores literales), las cifras de cada
gráfico coinciden con las de la tabla que lo acompaña (misma consulta), los
datos de terceros llegan escapados al SVG, y con la base vacía no hay
excepciones sino estados vacíos. También cubre la ampliación de
``queries.evolucion_mensual`` (claves nuevas conservando las antiguas) y que
``exportar_json_mes`` sigue funcionando.

Ejecución:
    sudo -n -u si .venv/bin/python -m unittest tests.test_pagina_tendencias
"""
from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threatintel import db, queries  # noqa: E402

USUARIO = "pruebas"
CLAVE = "PruebaSegura#2026"
HOSTIL = "Tecnología <script>alert(1)</script> & Cía"

# Diez meses, como el histórico real (dic 2025 → sep 2026): con más de 8
# periodos el eje X usa etiquetas cortas y alternas.
MESES_10 = ["2025-12", "2026-01", "2026-02", "2026-03", "2026-04",
            "2026-05", "2026-06", "2026-07", "2026-08", "2026-09"]

# Por mes: (críticas, altas, medias, bajas, en_kev, nvd). En septiembre las
# cifras reales aproximadas: 10 críticas, 14 altas, 83 medias, 17 bajas.
PLAN = {
    "2025-12": (2, 1, 3, 0, 1, 2),
    "2026-01": (3, 1, 5, 0, 0, 1),
    "2026-02": (4, 3, 6, 0, 1, 3),
    "2026-03": (5, 4, 8, 1, 0, 4),
    "2026-04": (6, 5, 9, 1, 1, 5),
    "2026-05": (7, 5, 9, 1, 1, 6),
    "2026-06": (6, 4, 10, 2, 2, 7),
    "2026-07": (8, 6, 12, 1, 1, 9),
    "2026-08": (9, 7, 14, 3, 2, 10),
    "2026-09": (10, 14, 83, 17, 1, 18),
}

# CVE recurrentes: (cve, meses en los que aparece)
RECURRENTES = {
    "CVE-2026-31431": MESES_10[3:8],          # 5 meses
    "CVE-2026-43284": MESES_10[4:8],          # 4 meses
    "CVE-2026-20182": ["2026-07", "2026-08", "2026-09"],
    "CVE-2026-2673": ["2026-08", "2026-09"],
}


def _poblar(ruta: str) -> None:
    """Base de pruebas con forma parecida a la real."""
    from webui import auth as _auth
    with db.session(ruta) as conn:
        _auth.crear_usuario(conn, USUARIO, CLAVE, rol="admin", actor="test")
        ahora = db.utcnow()

        # Tecnologías: 20 con amenazas en septiembre (una sin versión y una
        # con nombre hostil) para probar el volumen real del gráfico.
        tecnologias = []
        for i in range(20):
            nombre = HOSTIL if i == 0 else f"Tecnología {i:02d} de prueba"
            version = None if i in (0, 1) else f"{i}.0"
            cur = conn.execute(
                """INSERT INTO technologies(slug,name,category,version_installed,
                       criticality,systems_count,exposure,enabled,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,1,?,?)""",
                (f"tec-{i:02d}", nombre, "aplicacion", version,
                 "critical" if i == 0 else "high", 1, "interna", ahora, ahora))
            tecnologias.append(cur.lastrowid)

        n = 0
        for mes in MESES_10:
            criticas, altas, medias, bajas, en_kev, nvd = PLAN[mes]
            plan_sev = ([("Critical", 9.8)] * criticas + [("High", 7.5)] * altas
                        + [("Medium", 5.0)] * medias + [("Low", 3.1)] * bajas)
            for k, (sev, cvss) in enumerate(plan_sev):
                n += 1
                oficial = k < nvd
                cur = conn.execute(
                    """INSERT INTO threats(fingerprint,cve,title_en,severity,
                           severity_source,cvss_score,in_kev,first_seen_at,
                           last_seen_at,times_seen,month,relevance)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (f"fp-{n:05d}", f"CVE-2026-{n:05d}" if k % 2 == 0 else None,
                     f"Amenaza {n}", sev, "nvd" if oficial else "heuristic",
                     cvss if oficial else None, 1 if k < en_kev else 0,
                     f"{mes}-15 08:00:00", f"{mes}-15 08:00:00", 1, mes, 50.0))
                threat_id = cur.lastrowid
                if mes == "2026-09":
                    # Reparto por tecnología y veredicto: la tecnología i
                    # recibe las amenazas k con k % 20 == i.
                    tec = tecnologias[k % 20]
                    veredicto = ("affected", "unknown", "not_affected")[k % 3]
                    conn.execute(
                        """INSERT INTO threat_technologies(threat_id,technology_id,
                               matched_alias,confidence,version_verdict)
                           VALUES(?,?,?,?,?)""",
                        (threat_id, tec, "alias", 1.0, veredicto))

        # CVE recurrentes: una amenaza por mes con el mismo CVE.
        for cve, meses in RECURRENTES.items():
            for mes in meses:
                n += 1
                conn.execute(
                    """INSERT INTO threats(fingerprint,cve,title_en,severity,
                           severity_source,first_seen_at,last_seen_at,times_seen,
                           month,relevance)
                       VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    (f"fp-{n:05d}", cve, f"Recurrente {cve}", "Medium", "heuristic",
                     f"{mes}-20 08:00:00", f"{mes}-20 08:00:00", 3, mes, 40.0))


def _crear_app(ruta: str):
    from webui.app import crear_app
    return crear_app(db_path=ruta, testing=True)


def _sesion(app):
    cli = app.test_client()
    cli.post("/login", data={"usuario": USUARIO, "password": CLAVE})
    return cli


def _titulos(svg: str) -> list[str]:
    return re.findall(r"<title>([^<]*)</title>", svg)


def _figuras(html: str) -> dict[str, list[str]]:
    """Agrupa los <figure class="grafico-envoltorio grafico-<tipo>"> por tipo."""
    salida: dict[str, list[str]] = {}
    for m in re.finditer(r'<figure class="grafico-envoltorio grafico-([a-z-]+)">(.*?)</figure>',
                         html, re.S):
        salida.setdefault(m.group(1), []).append(m.group(2))
    return salida


# ==========================================================================
# Consulta ampliada
# ==========================================================================
class TestEvolucionMensualAmpliada(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from threatintel.paths import BASE_DIR
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "tendencias_q.db")
        db.init_db(cls.ruta)
        _poblar(cls.ruta)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def test_claves_antiguas_y_nuevas(self):
        with db.session(self.ruta) as conn:
            filas = queries.evolucion_mensual(conn, 24)
        self.assertEqual([f["month"] for f in filas], list(reversed(MESES_10)),
                         "el orden sigue siendo descendente")
        for fila in filas:
            for clave in ("month", "total", "criticas", "altas", "medias", "en_kev",
                          "bajas", "sev_nvd", "con_cve", "cvss_medio"):
                self.assertIn(clave, fila)
        sep = filas[0]
        criticas, altas, medias, bajas, en_kev, nvd = PLAN["2026-09"]
        # Las amenazas recurrentes del mes son de severidad Media.
        recurrentes_sep = sum(1 for m in RECURRENTES.values() if "2026-09" in m)
        self.assertEqual((sep["criticas"], sep["altas"], sep["medias"], sep["bajas"]),
                         (criticas, altas, medias + recurrentes_sep, bajas))
        self.assertEqual(sep["en_kev"], en_kev)
        self.assertEqual(sep["sev_nvd"], nvd)
        self.assertEqual(sep["total"], criticas + altas + medias + bajas + recurrentes_sep)
        self.assertGreater(sep["con_cve"], 0)

    def test_cvss_medio_redondeado_a_un_decimal_y_none_sin_datos(self):
        with db.session(self.ruta) as conn:
            filas = {f["month"]: f for f in queries.evolucion_mensual(conn, 24)}
            stats = queries.estadisticas_mes(conn, "2026-09")
        # Septiembre: 10 críticas a 9.8 y 8 altas a 7.5 con CVSS → media 8,78 → 8,8
        self.assertEqual(filas["2026-09"]["cvss_medio"], 8.8)
        self.assertEqual(filas["2026-09"]["cvss_medio"], stats["cvss_medio"],
                         "la serie y las estadísticas del mes deben coincidir")
        for fila in filas.values():
            medio = fila["cvss_medio"]
            self.assertTrue(medio is None or medio == round(medio, 1))

        with tempfile.TemporaryDirectory(dir=str(Path(self.dir.name))) as d:
            ruta = str(Path(d) / "sin_cvss.db")
            db.init_db(ruta)
            with db.session(ruta) as conn:
                ahora = db.utcnow()
                conn.execute(
                    """INSERT INTO threats(fingerprint,title_en,severity,severity_source,
                           cvss_score,first_seen_at,last_seen_at,month)
                       VALUES('a','t','High','heuristic',0,?,?,'2026-09')""", (ahora, ahora))
                fila = queries.evolucion_mensual(conn, 1)[0]
        self.assertIsNone(fila["cvss_medio"], "un CVSS 0 no es dato: la media es None")
        self.assertEqual(fila["bajas"], 0)

    def test_redondeo_estable_entre_consultas(self):
        """AVG() suma en distinto orden según el índice: 7.5500000001 frente a
        7.5499999999 daban 7,6 y 7,5 para el mismo mes."""
        self.assertEqual(queries._media_1_decimal(7.550000000000001), 7.6)
        self.assertEqual(queries._media_1_decimal(7.549999999999999), 7.6)
        self.assertEqual(queries._media_1_decimal(8.25), 8.3)
        self.assertIsNone(queries._media_1_decimal(None))
        self.assertIsNone(queries._media_1_decimal(0))

    def test_exportar_json_mes_sigue_funcionando(self):
        with db.session(self.ruta) as conn:
            datos = queries.exportar_json_mes(conn, "2026-09")
        self.assertEqual(datos["mes"], "2026-09")
        self.assertEqual(datos["total_mes"], len(datos["amenazas_acumuladas"]))
        self.assertEqual(datos["estadisticas"]["criticas"], PLAN["2026-09"][0])

    def test_limite_de_meses(self):
        with db.session(self.ruta) as conn:
            self.assertEqual(len(queries.evolucion_mensual(conn, 3)), 3)
            self.assertEqual(len(queries.evolucion_mensual(conn, 24)), len(MESES_10))

    def test_top_tecnologias_orden_por_defecto_y_por_amenazas(self):
        """El informe, los correos y el panel siguen recibiendo el orden por
        criticidad; Tendencias pide ``orden="amenazas"`` (revisión visual del
        2026-09-03: el gráfico apila por veredicto y el orden por críticas no
        se leía). Un orden desconocido cae en el de por defecto."""
        with db.session(self.ruta) as conn:
            defecto = queries.top_tecnologias(conn, "2026-09", 20)
            explicito = queries.top_tecnologias(conn, "2026-09", 20, orden="criticidad")
            por_amenazas = queries.top_tecnologias(conn, "2026-09", 20, orden="amenazas")
            desconocido = queries.top_tecnologias(conn, "2026-09", 20, orden="lo-que-sea")
        self.assertEqual([t["slug"] for t in defecto], [t["slug"] for t in explicito])
        self.assertEqual([t["slug"] for t in defecto], [t["slug"] for t in desconocido])
        # Por defecto: primero las que tienen críticas (tecnologías 00-09).
        claves = [(t["criticas"], t["altas"], t["amenazas"]) for t in defecto]
        self.assertEqual(claves, sorted(claves, reverse=True))
        self.assertEqual({t["slug"] for t in defecto[:10]}, {f"tec-{i:02d}" for i in range(10)})
        # Por amenazas: no creciente en total; las 00-03 (7 amenazas) delante.
        totales = [t["amenazas"] for t in por_amenazas]
        self.assertEqual(totales, sorted(totales, reverse=True))
        # (empatadas a 7; el desempate es alfabético por nombre y el nombre
        # hostil «Tecnología <script>…» ordena detrás de «Tecnología 01»).
        self.assertEqual([t["slug"] for t in por_amenazas[:4]],
                         ["tec-01", "tec-02", "tec-03", "tec-00"])
        self.assertEqual(len(por_amenazas), 20)
        # Con el mismo conjunto de tecnologías: solo cambia el orden.
        self.assertEqual({t["slug"] for t in por_amenazas}, {t["slug"] for t in defecto})


# ==========================================================================
# Ayudantes de la vista (sin base de datos)
# ==========================================================================
class TestAyudantesTendencias(unittest.TestCase):

    def test_nota_tecnologia_dice_las_confirmadas(self):
        """La severidad va en los colores de la barra; la nota aporta lo que el color
        no dice: cuántas amenazas están confirmadas por la versión instalada y
        «sin versión» cuando falta en el inventario. Una sola cifra, porque el
        módulo de gráficos reserva a la derecha el ancho del texto más largo
        (revisión visual del 2026-09-03/04)."""
        from webui.vistas.amenazas import _nota_tecnologia as nota
        self.assertEqual(nota({"criticas": 6, "altas": 4, "confirmadas": 3, "version_installed": None}),
                         "3 confirmadas · sin versión")
        self.assertEqual(nota({"criticas": 6, "altas": 4, "confirmadas": 3, "version_installed": "10.0"}),
                         "3 confirmadas")
        self.assertEqual(nota({"criticas": 1, "altas": 3, "confirmadas": 1, "version_installed": "1.0"}),
                         "1 confirmada")
        self.assertEqual(nota({"criticas": 0, "altas": 2, "confirmadas": 0, "version_installed": "1.0"}), "")
        self.assertEqual(nota({"criticas": 2, "confirmadas": 0, "version_installed": None}), "sin versión")
        self.assertEqual(nota({"altas": 1, "confirmadas": 1, "version_installed": None}), "1 confirmada · sin versión")
        self.assertEqual(nota({"criticas": 0, "altas": 0, "version_installed": None}), "sin versión")
        self.assertEqual(nota({"criticas": 0, "altas": 0, "version_installed": "2.0"}), "")
        self.assertEqual(nota({"criticas": None, "confirmadas": None, "version_installed": ""}), "sin versión")
        self.assertEqual(nota({"confirmadas": 1234, "version_installed": "x"}), "1.234 confirmadas")

    def test_opciones_cvss_pasan_tope_10_solo_si_linea_tiempo_lo_admite(self):
        """El CVSS va de 0 a 10: el eje del gráfico debe acabar en 10, no en el
        12 de la escala automática. ``tope`` lo añade el módulo de gráficos en
        paralelo; la vista lo pasa en cuanto exista y no antes (si lo pasara
        sin existir, la plantilla fallaría con TypeError)."""
        import inspect
        from webui import graficos
        from webui.vistas.amenazas import _opciones_linea_cvss as opciones

        def con_tope(etiquetas, series, *, ancho=760, tope=None):
            return ""

        def sin_tope(etiquetas, series, *, ancho=760):
            return ""

        self.assertEqual(opciones(con_tope), {"tope": 10})
        self.assertEqual(opciones(sin_tope), {})
        self.assertEqual(opciones(42), {})  # sin firma inspeccionable: nada
        admite = "tope" in inspect.signature(graficos.linea_tiempo).parameters
        self.assertEqual(opciones(), {"tope": 10} if admite else {})
        if admite:
            # Con el parámetro real, el eje Y termina exactamente en 10.
            svg = str(graficos.linea_tiempo(["ene 26", "feb 26"],
                                            [{"clave": "acento", "nombre": "CVSS medio",
                                              "valores": [9.4, 7.6]}], **opciones()))
            ticks = re.findall(r'text-anchor="end">([^<]*)</text>', svg)
            self.assertEqual(ticks[-1], "10", ticks)
            self.assertNotIn(">12</text>", svg)


# ==========================================================================
# Página con datos
# ==========================================================================
class TestPaginaTendencias(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from threatintel.paths import BASE_DIR
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "tendencias.db")
        db.init_db(cls.ruta)
        _poblar(cls.ruta)
        cls.app = _crear_app(cls.ruta)
        cli = _sesion(cls.app)
        cls.resp = cli.get("/amenazas/tendencias")
        cls.html = cls.resp.data.decode("utf-8")
        cls.figuras = _figuras(cls.html)
        # Adaptación del 2026-09-08: el panel «Serie anual de amenazas» añade
        # una figura de barras horizontales (años) ANTES de la de tecnologías y una
        # segunda de barras apiladas (los doce meses del año) DESPUÉS de la serie
        # mensual. Las tecnologías pasan al índice 1 y los CVE recurrentes al 2; la
        # serie mensual sigue siendo la primera apilada. Se nombran aquí para que las
        # pruebas de abajo no dependan de la posición.
        horizontales = cls.figuras.get("barras-horizontales", [])
        cls.fig_anual, cls.fig_tecnologias, cls.fig_cve = (horizontales + [None, None, None])[:3]
        with db.session(cls.ruta) as conn:
            cls.evolucion = queries.evolucion_mensual(conn, 24, excluir_bajas=True)  # la página excluye las bajas (regla interna)
            cls.stats = queries.estadisticas_mes(conn, "2026-09", excluir_bajas=True)  # la página excluye las bajas
            # La pagina excluye la severidad baja, como la grafica que apila las tres
            # severidades: la tabla de debajo tiene que decir lo mismo (2026-09-09).
            cls.top = queries.top_tecnologias(conn, "2026-09", 20, orden="amenazas",
                                              excluir_bajas=True)
            cls.recurrentes = queries.cve_recurrentes(conn, 25)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    # ---- respuesta y CSP -------------------------------------------------
    def test_responde_200_con_sesion_y_exige_sesion(self):
        self.assertEqual(self.resp.status_code, 200)
        self.assertNotIn("unsafe-", self.resp.headers.get("Content-Security-Policy", ""))
        anonimo = self.app.test_client().get("/amenazas/tendencias")
        self.assertIn(anonimo.status_code, (302, 401, 403))

    def test_graficos_presentes(self):
        self.assertIn('<svg class="grafico"', self.html)
        for tipo in ("barras-apiladas", "dona", "progreso", "linea-tiempo", "barras-horizontales"):
            self.assertIn(tipo, self.figuras, f"falta el gráfico {tipo}")
        # Dos apiladas (serie mensual y meses del año elegido) y tres horizontales
        # (años, tecnologías, CVE recurrentes) desde la serie anual del 2026-09-08.
        self.assertEqual(len(self.figuras["barras-apiladas"]), 2)
        self.assertEqual(len(self.figuras["dona"]), 1)
        self.assertEqual(len(self.figuras["linea-tiempo"]), 1)
        self.assertEqual(len(self.figuras["barras-horizontales"]), 3)
        self.assertEqual(len(self.figuras["progreso"]), len(MESES_10),
                         "una barra de procedencia por mes (hasta 12)")

    def test_sin_style_ni_manejadores_ni_script_en_linea(self):
        self.assertIsNone(re.search(r"\sstyle\s*=", self.html, re.I))
        self.assertIsNone(re.search(r"\son[a-z]+\s*=", self.html, re.I))
        # Solo se admiten <script src="..."> (tema.js y app.js de base.html).
        for m in re.finditer(r"<script\b([^>]*)>", self.html, re.I):
            self.assertIn("src=", m.group(1), f"script en línea: {m.group(0)}")
        self.assertNotIn("<style", self.html.lower())

    def test_sin_colores_literales_ni_recursos_externos_en_svg(self):
        svgs = re.findall(r"<svg.*?</svg>", self.html, re.S)
        self.assertTrue(svgs)
        for svg in svgs:
            for atributo, valor in re.findall(r'\b(fill|stroke)="([^"]*)"', svg):
                self.assertIn(valor, ("none", "currentColor", "transparent"),
                              f"{atributo}={valor!r} es un color literal")
            self.assertIsNone(re.search(r"https?://", svg))
        for svg in re.findall(r'<svg class="grafico"[^>]*>', self.html):
            self.assertIn('role="img"', svg)
            self.assertIn("aria-label=", svg)

    def test_datos_de_terceros_escapados(self):
        self.assertNotIn("<script>alert(1)</script>", self.html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", self.html)
        tec = self.fig_tecnologias
        self.assertIn("Tecnología &lt;script&gt;", tec)
        self.assertIn("&amp; Cía", tec)

    # ---- coherencia gráfico / tabla ----------------------------------------
    def test_serie_mensual_orden_ascendente_y_etiquetas_en_dos_lineas(self):
        svg = self.figuras["barras-apiladas"][0]
        etiquetas = re.findall(r'<text class="eje"[^>]*text-anchor="middle">((?:<tspan[^>]*>[^<]*</tspan>)+)</text>', svg)
        self.assertTrue(etiquetas)
        # Diez periodos → cada etiqueta en dos líneas, mes abreviado y año completo
        # («sep» / «2026»), sin omitir ninguna (petición del 2026-09-05: el año entero).
        lineas = [re.findall(r">([^<]*)</tspan>", e) for e in etiquetas]
        self.assertEqual(len(lineas), 10)
        self.assertEqual(lineas[-1], ["sep", "2026"])
        self.assertIn(["jul", "2026"], lineas)
        self.assertNotIn("septiembre de 2026", svg)
        self.assertNotIn(" 26<", svg)
        # Los <title> de las barras recorren los meses en orden cronológico, con el año completo.
        titulos = _titulos(svg)
        indices = [next((i for i, t in enumerate(titulos) if t.startswith(f"{m} ·")), None)
                   for m in ("dic 2025", "ene 2026", "sep 2026")]
        self.assertTrue(all(i is not None for i in indices))
        self.assertEqual(indices, sorted(indices))

    def test_totales_de_la_leyenda_igualan_a_la_tabla(self):
        svg = self.figuras["barras-apiladas"][0]
        # El marcador de una serie es «serie-<clave>» y el de la línea KEV,
        # desde el 2026-09-04, «linea-<clave>» (una raya en vez de un cuadrado).
        leyenda = dict(re.findall(r'<li><span class="leyenda-punto (?:serie|linea)-[a-z-]+"></span>'
                                  r"([^<]+) <b>([^<]+)</b></li>", svg))
        from webui.filtros import numero
        # Regla interna (2026-09-08): las bajas no se reportan; la leyenda tiene tres
        # severidades y la línea de KEV. Las sumas se comparan con la serie SIN bajas.
        for nombre, clave in (("Críticas", "criticas"), ("Altas", "altas"),
                              ("Medias", "medias"), ("En KEV", "en_kev")):
            self.assertEqual(leyenda[nombre.strip()], numero(sum(e[clave] for e in self.evolucion)),
                             f"leyenda de {nombre} distinta de la suma de la tabla")
        self.assertNotIn("Bajas", leyenda)
        # Y la tabla muestra la fila de septiembre con las mismas cifras.
        sep = self.evolucion[0]
        fila = re.search(r"<tr>\s*<td class=\"nowrap\"><a[^>]*>septiembre de 2026</a></td>(.*?)</tr>",
                         self.html, re.S).group(1)
        celdas = re.findall(r'<td class="num[^"]*">([^<]*)</td>', fila)
        self.assertEqual(celdas[:5], [numero(sep["total"]), numero(sep["criticas"]),
                                      numero(sep["altas"]), numero(sep["medias"]),
                                      numero(sep["en_kev"])])
        self.assertEqual(celdas[5], "8,8", "CVSS medio en formato español")
        self.assertNotIn("<th class=\"num\">Bajas</th>", self.html,
                         "las bajas no se reportan: ni columna ni segmento")

    def test_dona_coincide_con_las_metricas_del_mes(self):
        svg = self.figuras["dona"][0]
        titulos = _titulos(svg)
        self.assertIn(f"Críticas: {self.stats['criticas']} (", "".join(titulos))
        self.assertIn(f"Medias: {self.stats['medias']} (", "".join(titulos))
        self.assertIn(f'<text class="dona-centro" ', svg)
        self.assertIn(f">{self.stats['total']}</text>", svg)
        self.assertIn(f'<div class="valor">{self.stats["total"]}</div>', self.html)

    def test_procedencia_por_mes(self):
        barras = self.figuras["progreso"]
        sep = self.evolucion[0]
        primera = barras[0]  # orden descendente, como la tabla
        self.assertIn('viewBox="0 0 100 10"', primera)
        self.assertIn('preserveAspectRatio="none"', primera)
        self.assertIn(f"Oficial (NVD): {sep['sev_nvd']} (", primera)
        self.assertIn(f"Estimada: {sep['total'] - sep['sev_nvd']} (", primera)
        self.assertIn("septiembre de 2026", primera)  # aria-label descriptivo
        pct = round(sep["sev_nvd"] * 100.0 / sep["total"], 1)
        from webui.graficos import fmt
        self.assertIn(f"{fmt(pct, 1)} %", self.html)
        self.assertIn("Oficial: CVSS publicado por NVD", self.html)

    def test_linea_de_cvss_medio(self):
        svg = self.figuras["linea-tiempo"][0]
        titulos = _titulos(svg)
        self.assertIn("sep 2026 · CVSS medio: 8,8", titulos)   # en el título, el mes y el año en una línea
        self.assertEqual(len([t for t in titulos if "CVSS medio:" in t]),
                         sum(1 for e in self.evolucion if e["cvss_medio"] is not None))
        self.assertIn("<b>8,8</b>", svg)  # último valor en la leyenda

    def test_cvss_medio_eje_termina_en_10(self):
        """Con ``tope=10`` el eje Y del CVSS medio acaba en 10 (el CVSS no pasa
        de ahí); mientras ``graficos.linea_tiempo`` no admita el parámetro, la
        vista no lo pasa y la escala es automática (esta prueba se omite)."""
        import inspect
        from webui import graficos
        if "tope" not in inspect.signature(graficos.linea_tiempo).parameters:
            self.skipTest("graficos.linea_tiempo aún no admite tope=10 (grupo gráficos)")
        svg = self.figuras["linea-tiempo"][0]
        ticks = re.findall(r'text-anchor="end">([^<]*)</text>', svg)
        self.assertEqual(ticks[0], "0")
        self.assertEqual(ticks[-1], "10", ticks)
        self.assertNotIn(">12</text>", svg)

    def test_nota_de_cada_tecnologia_en_el_grafico(self):
        """Junto al total de cada barra va la nota con las críticas (o las
        altas si no hay críticas) y «sin versión» cuando falta en el
        inventario, en el mismo orden que las filas del gráfico y la tabla."""
        from webui.vistas.amenazas import _nota_tecnologia
        svg = self.fig_tecnologias
        filas = re.findall(r'<text class="etiqueta-valor"[^>]*>([^<]*)'
                           r'(?:<tspan class="nota"> · ([^<]*)</tspan>)?</text>', svg)
        self.assertEqual(len(filas), len(self.top))
        from markupsafe import escape
        # Regla interna (2026-09-08): la barra mide criticas + altas + medias (las bajas no se
        # reportan) y el total escribe su unidad: «6 amenazas».
        esperado = [(f"{t['criticas'] + t['altas'] + t['medias']} amenazas",
                     str(escape(_nota_tecnologia(t)))) for t in self.top]
        self.assertEqual(filas, esperado)
        # Con el reparto de la base de pruebas: las tecnologías 00-09 tienen
        # una crítica, las 10-19 una alta, y las 00 y 01 no tienen versión.
        notas = dict(zip((t["slug"] for t in self.top), (n for _, n in filas)))
        # La severidad ya va en los colores: la nota dice cuántas están confirmadas
        # por la versión instalada y «sin versión» cuando falta en el inventario.
        for t in self.top:
            esperado = ([f"{t['confirmadas']} confirmada{'s' if t['confirmadas'] != 1 else ''}"]
                        if t["confirmadas"] else [])
            if not t["version_installed"]:
                esperado.append("sin versión")
            self.assertEqual(notas[t["slug"]], " · ".join(esperado), t["slug"])
        self.assertNotIn("crítica", notas["tec-00"])  # la severidad no se repite en la nota
        # La nota es texto tenue dentro del SVG (clase, nunca style=).
        self.assertIn('<tspan class="nota">', svg)
        self.assertIn("junto a cada barra", self.html)

    def test_tecnologias_por_severidad_con_enlace(self):
        svg = self.fig_tecnologias
        def segmentos(t):
            # tres segmentos: las bajas no se reportan (regla interna, 2026-09-08)
            return {"critico": t["criticas"], "alto": t["altas"], "medio": t["medias"]}
        def total_barra(t):
            return t["criticas"] + t["altas"] + t["medias"]
        self.assertEqual(svg.count("<rect "), sum(sum(1 for v in segmentos(t).values() if v) for t in self.top))
        self.assertNotIn("Bajas", svg)
        for t in self.top:
            self.assertIn(f"/amenazas/?", svg)
            enlace = re.search(rf'<a href="([^"]*tec={t["slug"]}[^"]*)">', svg)
            self.assertIsNotNone(enlace, f"falta el enlace de {t['slug']}")
            self.assertIn("mes=2026-09", enlace.group(1))
            titulos = _titulos(svg)
            if t["criticas"]:
                unidad_c = "amenaza" if t["criticas"] == 1 else "amenazas"   # unidad escrita (2026-09-08)
                self.assertTrue(any(t2.endswith(f"Críticas: {t['criticas']} {unidad_c} ({_pct(t['criticas'], total_barra(t))})")
                                    for t2 in titulos), t["name"])
            if t["altas"]:
                self.assertTrue(any(f"Altas: {t['altas']} " in t2 and "(" in t2 for t2 in titulos))
        # Leyenda con las severidades presentes, mismos colores que el resto de la plataforma.
        totales = {"critico": sum(t["criticas"] for t in self.top), "alto": sum(t["altas"] for t in self.top),
                   "medio": sum(t["medias"] for t in self.top)}
        for clave, nombre in (("critico", "Críticas"), ("alto", "Altas"), ("medio", "Medias")):
            if totales[clave]:
                self.assertIn(f'<span class="leyenda-punto serie-{clave}"></span>{nombre} <b>', svg)
        self.assertNotIn("Sin determinar <b>", svg)   # el veredicto va en la nota y en la tabla
        self.assertIn("sin versión", svg)
        # La tabla debajo lleva la columna «Sin determinar» y criticidad en español.
        self.assertIn("Sin determinar</th>", self.html)
        self.assertIn(">Alta</span>", self.html)
        self.assertNotIn(">high</span>", self.html)

    def test_tecnologias_ordenadas_por_amenazas_en_grafico_y_tabla(self):
        """El criterio de orden debe leerse en el propio gráfico: las barras
        van de más a menos amenazas y la tabla sigue la misma secuencia."""
        svg = self.fig_tecnologias
        nombres_svg = re.findall(r'<text class="eje"[^>]*text-anchor="end"><title>([^<]*)</title>', svg)
        from markupsafe import escape
        self.assertEqual(nombres_svg, [str(escape(t["name"])) for t in self.top])
        totales = [t["amenazas"] for t in self.top]
        self.assertEqual(totales, sorted(totales, reverse=True), "barras de mayor a menor")
        # Filas de la tabla en el mismo orden que las barras.
        tabla = self.html[self.html.find("Tecnologías más afectadas"):self.html.find("CVE recurrentes")]
        slugs_tabla = re.findall(r'<td class="nowrap"><a href="[^"]*tec=(tec-\d\d)[^"]*">', tabla)
        self.assertEqual(slugs_tabla, [t["slug"] for t in self.top])
        self.assertIn("Ordenadas de más a menos", self.html)

    def test_tabla_tecnologias_con_columna_criticidad_propia(self):
        """El nombre y la insignia iban en la misma celda estrecha y «Microsoft
        Windows / Alta» se partía en tres líneas: ahora cada uno tiene su columna
        y ninguna de las dos se parte."""
        self.assertIn(">Criticidad</th>", self.html)
        self.assertRegex(self.html, r'<th>Tecnología</th>\s*<th[^>]*>Criticidad</th>\s*<th>Versión</th>')
        self.assertIsNone(re.search(r'<td[^>]*><a[^>]*>[^<]*</a>\s*<span class="insignia', self.html),
                          "la insignia no debe compartir celda con el enlace")
        self.assertIn('<td class="nowrap"><span class="insignia high">Alta</span></td>', self.html)
        self.assertIn('<td class="nowrap"><span class="insignia critical">Crítica</span></td>', self.html)
        # El nombre hostil sigue escapado en su celda, ahora con nowrap.
        self.assertRegex(self.html, r'<td class="nowrap"><a href="[^"]*tec=tec-00[^"]*">Tecnología &lt;script&gt;')

    def test_ceros_sin_color_semantico(self):
        """Un 0 en rojo o en verde llama la atención sobre nada: los ceros de las
        columnas de severidad y veredicto se pintan tenues; los valores > 0
        conservan su color."""
        self.assertIsNone(re.search(r'class="num txt-[a-z-]+">0</td>', self.html))
        self.assertIn('<td class="num tenue">0</td>', self.html)  # dic 2025 no tiene Bajas
        from webui.filtros import numero
        sep = self.evolucion[0]
        self.assertIn(f'<td class="num txt-critico">{numero(sep["criticas"])}</td>', self.html)
        self.assertNotIn('txt-bajo', self.html, "sin columna de bajas")
        # Tabla de tecnologías: confirmadas > 0 en rojo, descartadas > 0 en verde,
        # y las tecnologías sin críticas con el 0 tenue.
        con_confirmadas = next(t for t in self.top if t["confirmadas"])
        self.assertIn(f'<td class="num txt-critico">{numero(con_confirmadas["confirmadas"])}</td>', self.html)
        con_descartadas = next(t for t in self.top if t["no_aplicables"])
        self.assertIn(f'<td class="num txt-exito">{numero(con_descartadas["no_aplicables"])}</td>', self.html)
        self.assertTrue(any(not t["criticas"] for t in self.top))
        self.assertNotIn('<td class="num txt-exito">0</td>', self.html)
        self.assertNotIn('<td class="num txt-critico">0</td>', self.html)

    def test_cve_recurrentes_meses_presentes(self):
        svg = self.fig_cve
        diez = self.recurrentes[:10]
        self.assertEqual(svg.count("<rect "), len(diez))
        for r in diez:
            # Un único segmento es el 100 % de su fila: el módulo de gráficos
            # puede omitir el porcentaje del <title> (lo hace desde el 2026-09-04).
            self.assertRegex(svg, rf"<title>{re.escape(r['cve'])} · Meses presentes: {r['meses']}"
                                  r"(?: \(100 %\))?</title>")
            enlace = re.search(rf'<a href="([^"]*)">(?:<text[^>]*>)<title>{re.escape(r["cve"])}</title>', svg)
            self.assertIsNotNone(enlace, r["cve"])
            self.assertIn(f"q={r['cve']}", enlace.group(1))
        # El primero es el más recurrente (5 meses) y la tabla lo muestra igual.
        self.assertEqual(diez[0]["cve"], "CVE-2026-31431")
        self.assertEqual(diez[0]["meses"], 5)
        self.assertIn("<strong>5</strong>", self.html)

    # ---- estructura de la página -------------------------------------------
    def test_selector_de_mes_conservado_y_glosario_al_final(self):
        self.assertIn('name="mes" data-autosubmit', self.html)
        self.assertIn('<option value="2026-09" selected>septiembre de 2026</option>', self.html)
        self.assertIn("Cómo leer estos datos", self.html)
        self.assertLess(self.html.rfind('grafico-envoltorio'), self.html.find("Cómo leer estos datos"))

    def test_cambio_de_mes(self):
        cli = _sesion(self.app)
        html = cli.get("/amenazas/tendencias?mes=2026-08").data.decode("utf-8")
        self.assertIn('<option value="2026-08" selected>', html)
        criticas = PLAN["2026-08"][0]
        self.assertIn(f'<div class="valor">{criticas}</div>', html)
        figuras = _figuras(html)
        self.assertIn(f"Críticas: {criticas} (", figuras["dona"][0])
        # Agosto no tiene tecnologías asociadas → estado vacío sin excepción.
        self.assertIn("Sin datos para este periodo.", html)
        # Un mes inexistente tampoco rompe nada.
        self.assertEqual(cli.get("/amenazas/tendencias?mes=2031-01").status_code, 200)

    def test_etiquetas_en_espanol_y_numeros_en_espanol(self):
        for texto in ("Serie mensual", "Severidad del mes", "Procedencia de la severidad",
                      "CVSS</abbr> medio mensual", "Tecnologías más afectadas", "CVE recurrentes",
                      "Críticas", "Altas", "Medias", "Confirmadas", "Descartadas"):
            self.assertIn(texto, self.html)
        self.assertNotIn("Rel.", self.html)
        self.assertIn("8,8", self.html)
        self.assertNotIn(">8.8<", self.html)


def _pct(parte: int, total: int) -> str:
    from webui.graficos import _pct as pct
    return pct(parte, total)


# ==========================================================================
# Procedencia con miles: el aria-label usa el formato español (1.235)
# ==========================================================================
class TestProcedenciaConMiles(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from threatintel.paths import BASE_DIR
        from webui import auth as _auth
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "miles.db")
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            _auth.crear_usuario(conn, USUARIO, CLAVE, rol="admin", actor="test")
            # 1.235 amenazas en un mes, 985 con CVSS oficial (cifras reales
            # de la revisión visual del 2026-09-03).
            conn.executemany(
                """INSERT INTO threats(fingerprint,title_en,severity,severity_source,
                       cvss_score,first_seen_at,last_seen_at,times_seen,month,relevance)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                [(f"fp-m-{k:05d}", f"Amenaza {k}", "Medium",
                  "nvd" if k < 985 else "heuristic", 5.0 if k < 985 else None,
                  "2026-09-10 08:00:00", "2026-09-10 08:00:00", 1, "2026-09", 50.0)
                 for k in range(1235)])
        cls.app = _crear_app(cls.ruta)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def test_aria_de_procedencia_en_formato_espanol(self):
        html = _sesion(self.app).get("/amenazas/tendencias").data.decode("utf-8")
        aria = re.search(r'aria-label="Procedencia de la severidad en septiembre de 2026: ([^"]*)"', html)
        self.assertIsNotNone(aria)
        self.assertEqual(aria.group(1), "985 con CVSS oficial de NVD y 250 estimadas de 1.235")
        self.assertNotIn("de 1235", html)
        # La tabla adyacente y las métricas usan el mismo formato.
        self.assertIn('<div class="valor">1.235</div>', html)
        self.assertIn('<td class="num">1.235</td>', html)


# ==========================================================================
# Página con la base vacía
# ==========================================================================
class TestPaginaTendenciasVacia(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from threatintel.paths import BASE_DIR
        from webui import auth as _auth
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "vacia.db")
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            _auth.crear_usuario(conn, USUARIO, CLAVE, rol="admin", actor="test")
        cls.app = _crear_app(cls.ruta)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def test_sin_datos_responde_con_estados_vacios(self):
        resp = _sesion(self.app).get("/amenazas/tendencias")
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode("utf-8")
        self.assertNotIn('<svg class="grafico"', html)
        self.assertGreaterEqual(html.count('<div class="grafico-vacio">Sin datos suficientes</div>'), 3)
        self.assertIn("Sin datos para este periodo.", html)
        self.assertIn("Sin CVE recurrentes.", html)
        self.assertIn("Todavía no hay amenazas registradas", html)
        self.assertIn('name="mes" data-autosubmit', html)
        self.assertIsNone(re.search(r"\sstyle\s*=", html, re.I))
        self.assertIsNone(re.search(r"\son[a-z]+\s*=", html, re.I))
        self.assertIn("Cómo leer estos datos", html)

    def test_consultas_con_base_vacia(self):
        with db.session(self.ruta) as conn:
            self.assertEqual(queries.evolucion_mensual(conn, 24), [])
            self.assertEqual(queries.meses_disponibles(conn), [])
            self.assertEqual(queries.cve_recurrentes(conn, 10), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)

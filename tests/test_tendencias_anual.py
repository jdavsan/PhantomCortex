"""Serie anual de amenazas y descarga del informe en Tendencias (2026-09-08).

El usuario pidió «crea una opción en tendencias para poder descargar informes del mes
que desee, además en tendencias crea un apartado para poder ver una serie anual de
vulnerabilidades». Estas pruebas fijan:

* ``queries.serie_anual``: un año por fila, del más reciente al más antiguo, con total,
  críticas, altas, medias, bajas, KEV y cuántos meses del año tienen datos; con
  ``excluir_bajas`` (regla interna ignore_low_severity, activa) las bajas no cuentan y el
  total anual coincide exactamente con la suma de los meses de ``evolucion_mensual``;
* el panel «Serie anual de amenazas» de /amenazas/tendencias: barras por año con
  leyenda y unidad «amenazas», selector de año, los doce meses del año elegido (los que
  no tienen amenazas registradas se dicen, no se fingen) y un año inexistente en la
  dirección no rompe la página;
* el botón «Descargar el informe de <mes>» se ve con permiso (administrador) y con el
  módulo de informes registrado, y no se ve para el perfil de solo lectura ni cuando el
  módulo no está registrado (la página no cae por un ``BuildError``);
* el panel nuevo forma parte del recorrido guiado con un número de paso propio.

Ejecución:
    sudo -n -u si .venv/bin/python -m unittest tests.test_tendencias_anual
"""
from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path

from threatintel import db, queries
from threatintel.paths import BASE_DIR

sys.path.insert(0, str(BASE_DIR))
from webui import auth  # noqa: E402
from webui.vistas import amenazas, informes  # noqa: E402

CLAVE = "ClaveSegura#2026"
#: Por mes: (críticas, altas, medias, bajas). Dos años, con huecos (febrero de 2026 sin
#: datos) y bajas repartidas para demostrar que se excluyen.
PLAN = {
    "2025-11": (1, 1, 2, 1),
    "2025-12": (2, 0, 1, 0),
    "2026-01": (0, 1, 1, 3),
    "2026-03": (1, 1, 1, 0),
}


def _sembrar(ruta: str) -> None:
    with db.session(ruta) as conn:
        auth.crear_usuario(conn, "admin@ejemplo.local", CLAVE, rol="admin", actor="t")
        auth.crear_usuario(conn, "lectora@ejemplo.local", CLAVE, rol="ciberseguridad", actor="t")
        n = 0
        for mes, (criticas, altas, medias, bajas) in PLAN.items():
            plan = (["Critical"] * criticas + ["High"] * altas + ["Medium"] * medias + ["Low"] * bajas)
            for sev in plan:
                n += 1
                conn.execute(
                    """INSERT INTO threats(fingerprint,cve,title_en,severity,severity_source,
                           in_kev,first_seen_at,last_seen_at,times_seen,month,relevance)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (f"fp-{n:04d}", f"CVE-2026-{n:04d}", f"Amenaza {n}", sev, "nvd",
                     1 if sev == "Critical" else 0,
                     f"{mes}-10 08:00:00", f"{mes}-10 08:00:00", 1, mes, 50.0))


def _app(ruta: str, *, registrar: bool):
    from webui.app import crear_app
    app = crear_app(db_path=ruta, testing=True)
    if registrar and "informes" not in app.blueprints:
        app.register_blueprint(informes.bp)
    return app


class BaseAnual(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "anual.db")
        db.init_db(cls.ruta)
        _sembrar(cls.ruta)
        cls.app = _app(cls.ruta, registrar=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def _cliente(self, usuario: str, app=None):
        cli = (app or self.app).test_client()
        cli.post("/login", data={"usuario": usuario, "password": CLAVE})
        return cli


class TestSerieAnualConsulta(BaseAnual):

    def test_un_anio_por_fila_sin_bajas(self):
        with db.session(self.ruta) as conn:
            filas = queries.serie_anual(conn, excluir_bajas=True)
        self.assertEqual([f["anio"] for f in filas], ["2026", "2025"], "del más reciente al más antiguo")
        a2025, a2026 = filas[1], filas[0]
        self.assertEqual((a2025["criticas"], a2025["altas"], a2025["medias"], a2025["bajas"]), (3, 1, 3, 0))
        self.assertEqual(a2025["total"], 7, "las bajas no cuentan en el total")
        self.assertEqual(a2025["meses"], 2)
        self.assertEqual(a2025["en_kev"], 3)
        self.assertEqual((a2026["criticas"], a2026["altas"], a2026["medias"], a2026["total"]), (1, 2, 2, 5))
        self.assertEqual(a2026["meses"], 2, "febrero no tiene datos y no cuenta")

    def test_con_bajas_cuando_la_regla_esta_desactivada(self):
        with db.session(self.ruta) as conn:
            filas = {f["anio"]: f for f in queries.serie_anual(conn, excluir_bajas=False)}
        self.assertEqual((filas["2025"]["total"], filas["2025"]["bajas"]), (8, 1))
        self.assertEqual((filas["2026"]["total"], filas["2026"]["bajas"]), (8, 3))

    def test_el_total_anual_es_la_suma_exacta_de_sus_meses(self):
        """La serie anual y la mensual salen de la misma tabla y el mismo criterio: si
        discreparan, el lector no sabría a cuál creer."""
        with db.session(self.ruta) as conn:
            anual = {f["anio"]: f for f in queries.serie_anual(conn, excluir_bajas=True)}
            mensual = queries.evolucion_mensual(conn, 1200, excluir_bajas=True)
        for anio, fila in anual.items():
            del_anio = [m for m in mensual if str(m["month"]).startswith(anio)]
            for clave in ("total", "criticas", "altas", "medias", "en_kev"):
                self.assertEqual(fila[clave], sum(m[clave] for m in del_anio), (anio, clave))
            self.assertEqual(fila["meses"], len(del_anio))

    def test_base_vacia_devuelve_lista_vacia(self):
        with tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data")) as d:
            ruta = str(Path(d) / "vacia.db")
            db.init_db(ruta)
            with db.session(ruta) as conn:
                self.assertEqual(queries.serie_anual(conn, excluir_bajas=True), [])


class TestAuxiliaresDeLaVista(unittest.TestCase):

    def test_anio_elegido_prefiere_el_pedido_luego_el_del_mes_y_nunca_uno_sin_datos(self):
        anios = ["2026", "2025"]
        self.assertEqual(amenazas._anio_elegido(anios, "2025", "2026-03"), "2025")
        self.assertEqual(amenazas._anio_elegido(anios, "1999", "2025-12"), "2025")
        self.assertEqual(amenazas._anio_elegido(anios, None, "2025-11"), "2025")
        self.assertEqual(amenazas._anio_elegido(anios, "", None), "2026")
        self.assertIsNone(amenazas._anio_elegido([], "2026", "2026-01"))

    def test_doce_meses_con_ceros_y_marca_de_sin_datos(self):
        evolucion = [{"month": "2026-03", "total": 3, "criticas": 1, "altas": 1, "medias": 1, "bajas": 0, "en_kev": 1},
                     {"month": "2025-12", "total": 3, "criticas": 2, "altas": 0, "medias": 1, "bajas": 0, "en_kev": 2}]
        meses = amenazas._meses_del_anio(evolucion, "2026")
        self.assertEqual(len(meses), 12)
        self.assertEqual([m["nombre"] for m in meses][:3], ["enero", "febrero", "marzo"])
        self.assertEqual(meses[2]["total"], 3)
        self.assertTrue(meses[2]["con_datos"])
        self.assertFalse(meses[1]["con_datos"])
        self.assertEqual(meses[1]["total"], 0)
        self.assertEqual(amenazas._meses_del_anio(evolucion, None), [])
        categorias, series = amenazas._series_meses_anio(meses, sin_bajas=True)
        self.assertEqual(len(categorias), 12)
        self.assertEqual([s["nombre"] for s in series], ["Críticas", "Altas", "Medias"])
        _, con_bajas = amenazas._series_meses_anio(meses, sin_bajas=False)
        self.assertEqual(con_bajas[-1]["nombre"], "Bajas")


class TestPanelEnLaPagina(BaseAnual):

    def test_panel_con_barras_leyenda_unidad_y_selector(self):
        admin = self._cliente("admin@ejemplo.local")
        r = admin.get("/amenazas/tendencias")
        self.assertEqual(r.status_code, 200)
        html = r.get_data(as_text=True)
        self.assertIn("Serie anual de amenazas", html)
        self.assertIn('id="selector-anio"', html)
        self.assertIn("Año del detalle mensual", html, "etiqueta visible del selector")
        self.assertIn('<option value="2026" selected>', html.replace("  ", " "))
        self.assertIn('<option value="2025" >', html.replace("  ", " "))
        # Barras por año con la unidad escrita y la nota de meses con datos.
        self.assertIn("7 amenazas", html)
        self.assertIn("5 amenazas", html)
        self.assertIn("2 meses con datos", html)
        self.assertIn("Críticas", html)
        # Sin bajas por la regla interna: ni columna ni segmento.
        self.assertNotIn("<th class=\"num\">Bajas</th>", html)
        # El año por defecto es el del mes más reciente y se listan sus doce meses.
        self.assertIn("Los doce meses de 2026", html)
        self.assertIn("febrero de 2026", html)
        self.assertIn("(sin amenazas registradas)", html)
        self.assertIn("diciembre de 2026", html)
        self.assertIn("Total de 2026", html)

    def test_selector_de_anio_cambia_el_detalle_y_un_anio_inexistente_no_rompe(self):
        admin = self._cliente("admin@ejemplo.local")
        html = admin.get("/amenazas/tendencias?anio=2025").get_data(as_text=True)
        self.assertIn("Los doce meses de 2025", html)
        self.assertIn("noviembre de 2025", html)
        self.assertIn('<option value="2025" selected>', html.replace("  ", " "))
        r = admin.get("/amenazas/tendencias?anio=1999")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Los doce meses de 2026", r.get_data(as_text=True))
        # El año sigue al mes elegido cuando no se pide uno explícito.
        html = admin.get("/amenazas/tendencias?mes=2025-12").get_data(as_text=True)
        self.assertIn("Los doce meses de 2025", html)

    def test_boton_de_informe_segun_permiso(self):
        admin = self._cliente("admin@ejemplo.local")
        html = admin.get("/amenazas/tendencias?mes=2026-01").get_data(as_text=True)
        self.assertIn("Descargar el informe de enero de 2026", html)
        self.assertIn('action="/informes/2026-01/descargar"', html)
        self.assertIn('name="csrf"', html)
        lectora = self._cliente("lectora@ejemplo.local")
        html = lectora.get("/amenazas/tendencias?mes=2026-01").get_data(as_text=True)
        self.assertNotIn("Descargar el informe", html)
        self.assertIn("Serie anual de amenazas", html, "la serie sí la ve todo el mundo")

    def test_sin_modulo_registrado_la_pagina_no_cae_y_no_hay_boton(self):
        app = _app(self.ruta, registrar=False)
        if "informes" in app.blueprints:
            self.skipTest("crear_app ya registra el módulo de informes: no hay caso «sin módulo»")
        admin = self._cliente("admin@ejemplo.local", app)
        r = admin.get("/amenazas/tendencias")
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("Descargar el informe", r.get_data(as_text=True))

    def test_csp_estricta_en_la_pagina(self):
        admin = self._cliente("admin@ejemplo.local")
        html = admin.get("/amenazas/tendencias").get_data(as_text=True)
        from html.parser import HTMLParser

        class Recolector(HTMLParser):
            def __init__(self):
                super().__init__()
                self.malos = []

            def handle_starttag(self, tag, attrs):
                for nombre, _ in attrs:
                    n = (nombre or "").lower()
                    if n == "style" or n.startswith("on"):
                        self.malos.append(f"<{tag} {n}>")

        rec = Recolector()
        rec.feed(html)
        self.assertEqual(rec.malos, [])

    def test_recorrido_guiado_incluye_el_panel_nuevo(self):
        texto = (BASE_DIR / "webui" / "templates" / "tendencias.html").read_text(encoding="utf-8")
        pasos = re.findall(r'data-tour="(\d+)" data-tour-titulo="([^"]+)"', texto)
        titulos = [t for _, t in pasos]
        self.assertIn("Serie anual de amenazas", titulos)
        numeros = [int(n) for n, _ in pasos]
        self.assertEqual(sorted(numeros), list(range(1, len(numeros) + 1)), "pasos consecutivos y únicos")

    def test_base_vacia_muestra_estado_vacio(self):
        with tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data")) as d:
            ruta = str(Path(d) / "vacia.db")
            db.init_db(ruta)
            with db.session(ruta) as conn:
                auth.crear_usuario(conn, "admin@ejemplo.local", CLAVE, rol="admin", actor="t")
            app = _app(ruta, registrar=True)
            cli = self._cliente("admin@ejemplo.local", app)
            r = cli.get("/amenazas/tendencias")
            self.assertEqual(r.status_code, 200)
            html = r.get_data(as_text=True)
            self.assertIn("la serie anual se irá llenando", html)
            self.assertNotIn("Descargar el informe", html, "sin mes no hay informe que descargar")


if __name__ == "__main__":
    unittest.main()

"""Recorrido guiado en todas las páginas y regla de color de la sección Activos (2026-09-05;
paleta ampliada a doce colores y gráfica de versiones con color propio el 2026-09-08).

El usuario pidió un recorrido por cada apartado y una paleta profesional: el color
solo cuando significa algo (riesgo, soporte, exposición) y una gama monocroma para los
repartos sin significado propio. Estas pruebas fijan ambas cosas sin levantar la
aplicación: leen las plantillas y la hoja de estilos y prueban las funciones puras."""
from __future__ import annotations

import itertools
import re
import unittest
from pathlib import Path
from unittest import mock

from threatintel.paths import BASE_DIR
from webui import graficos
from webui.vistas import activos

PLANTILLAS = BASE_DIR / "webui" / "templates"
ESTILO = (BASE_DIR / "webui" / "static" / "estilo.css").read_text(encoding="utf-8")
#: Páginas que extienden base.html pero no son un apartado con contenido que explicar.
SIN_RECORRIDO = {"error.html"}


def _plantillas_con_base():
    for ruta in sorted(PLANTILLAS.glob("*.html")):
        texto = ruta.read_text(encoding="utf-8")
        if 'extends "base.html"' in texto and ruta.name not in SIN_RECORRIDO:
            yield ruta.name, texto


class TestRecorridoEnTodasLasPaginas(unittest.TestCase):
    def test_toda_pagina_tiene_al_menos_dos_pasos(self):
        for nombre, texto in _plantillas_con_base():
            pasos = re.findall(r'data-tour="(\d+)"[^>]*data-tour-titulo="([^"]+)"[^>]*data-tour-texto="([^"]+)"', texto)
            with self.subTest(plantilla=nombre):
                self.assertGreaterEqual(len(pasos), 2, f"{nombre} sin recorrido guiado suficiente")
                numeros = [int(n) for n, _, _ in pasos]
                self.assertEqual(len(numeros), len(set(numeros)), "números de paso repetidos")
                self.assertEqual(min(numeros), 1, "el recorrido empieza en el paso 1")
                for _, titulo, cuerpo in pasos:
                    self.assertGreater(len(cuerpo), 40, f"paso «{titulo}» demasiado escueto")

    def test_tendencias_recorre_todos_sus_paneles(self):
        texto = (PLANTILLAS / "tendencias.html").read_text(encoding="utf-8")
        titulos = re.findall(r'data-tour-titulo="([^"]+)"', texto)
        for esperado in ("Tendencias", "Cifras del mes", "Serie mensual", "Severidad del mes",
                         "Tecnologías más afectadas", "CVE recurrentes"):
            self.assertIn(esperado, titulos)

    def test_atributos_en_la_etiqueta_de_apertura_del_panel(self):
        """Nunca en una etiqueta de cierre ni en un hijo: el resaltado debe rodear el panel entero."""
        for nombre, texto in _plantillas_con_base():
            with self.subTest(plantilla=nombre):
                self.assertNotRegex(texto, r"</\w+ data-tour")
                self.assertNotRegex(texto, r'<div class="panel-(cabecera|cuerpo)[^"]*" data-tour=')


def _hex_a_lab(h: str) -> tuple[float, float, float]:
    """sRGB (#rrggbb) a CIE L*a*b* para medir distancia perceptual (dE76)."""
    def lin(c):
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = [lin(int(h[i:i + 2], 16) / 255) for i in (1, 3, 5)]
    x = (0.4124 * r + 0.3576 * g + 0.1805 * b) / 0.95047
    y = 0.2126 * r + 0.7152 * g + 0.0722 * b
    z = (0.0193 * r + 0.1192 * g + 0.9505 * b) / 1.08883

    def f(v):
        return v ** (1 / 3) if v > 0.008856 else 7.787 * v + 16 / 116
    return 116 * f(y) - 16, 500 * (f(x) - f(y)), 200 * (f(y) - f(z))


def _distancia(a: str, b: str) -> float:
    return sum((p - q) ** 2 for p, q in zip(_hex_a_lab(a), _hex_a_lab(b))) ** 0.5


def _paleta(bloque: str) -> dict[str, str]:
    return dict(re.findall(r"--(cat-\d+|neutro): (#[0-9a-f]{6})", bloque))


def _luminancia(h: str) -> float:
    def lin(c):
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = [lin(int(h[i:i + 2], 16) / 255) for i in (1, 3, 5)]
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def _contraste(a: str, b: str) -> float:
    la, lb = _luminancia(a), _luminancia(b)
    return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)


#: Tamaño de la paleta categórica desde el 2026-09-08: doce colores más el gris de «sin datos».
COLORES_CATEGORICOS = 12


class TestReglaDeColorActivos(unittest.TestCase):
    def test_paleta_categorica_en_ambos_temas(self):
        """Doce claves (ocho originales más cat-9..cat-12, añadidas el 2026-09-08 para la gráfica
        de versiones de sistema), cada una definida en los cinco bloques de la hoja de estilos y
        con sus clases de serie, leyenda y barra de progreso."""
        for i in range(1, COLORES_CATEGORICOS + 1):
            self.assertIn(f"cat-{i}", graficos.CLAVES)
            self.assertEqual(len(re.findall(rf"--cat-{i}: #", ESTILO)), 5,
                             "claro, oscuro explícito (dos bloques), oscuro del sistema e impresión")
            for regla in (f".serie-cat-{i} {{", f".linea-cat-{i} {{", f".area-cat-{i} {{",
                          f".leyenda-punto.serie-cat-{i} {{", f".progreso span.serie-cat-{i} {{"):
                self.assertIn(regla, ESTILO, f"falta la regla {regla}")
        self.assertNotIn(f"cat-{COLORES_CATEGORICOS + 1}", graficos.CLAVES)
        self.assertNotIn("tono-", ESTILO, "la gama monocroma se retiró: el usuario quiere colores distintos por categoría")
        self.assertFalse(any(c.startswith("tono-") for c in graficos.CLAVES))

    def test_colores_categoricos_bien_diferenciados(self):
        """Cualquier par de la paleta categórica (y el gris de «sin datos») se distingue a simple
        vista: distancia perceptual dE76 >= 25, en el tema claro y en el oscuro."""
        claro = _paleta(ESTILO[:ESTILO.index(':root[data-tema="claro"]')])
        # Paleta oscura efectiva: el último bloque :root[data-tema="oscuro"] manda en cascada.
        oscuro: dict[str, str] = {}
        pantalla = ESTILO[:ESTILO.index("@media print")]   # la hoja de impresión fuerza la paleta clara
        for bloque in re.findall(r':root\[data-tema="oscuro"\] \{([^}]*)\}', pantalla):
            oscuro.update(_paleta(bloque))
        sistema = _paleta(re.search(r'@media \(prefers-color-scheme: dark\) \{\s*:root:not\(\[data-tema="claro"\]\) \{([^}]*)\}', ESTILO).group(1))
        self.assertEqual(sistema, oscuro, "el oscuro del sistema y el explícito deben coincidir")
        for nombre, paleta in (("claro", claro), ("oscuro", oscuro)):
            self.assertEqual(len(paleta), COLORES_CATEGORICOS + 1, f"paleta {nombre} incompleta: {sorted(paleta)}")
            for (na, a), (nb, b) in itertools.combinations(paleta.items(), 2):
                with self.subTest(tema=nombre, par=f"{na}-{nb}"):
                    self.assertGreaterEqual(_distancia(a, b), 25)

    def test_colores_categoricos_con_contraste_sobre_el_panel(self):
        """Cada color de la paleta (también los cuatro nuevos) se ve sobre el fondo del panel en
        los dos temas: contraste >= 3:1, el mínimo para elementos gráficos (WCAG 1.4.11)."""
        claro = ESTILO[:ESTILO.index(':root[data-tema="claro"]')]
        fondo_claro = re.search(r"--fondo-panel: (#[0-9a-f]{6})", claro).group(1)
        # El tema oscuro explícito se reparte en dos bloques :root[data-tema="oscuro"]; el último manda.
        oscuro = "\n".join(re.findall(r':root\[data-tema="oscuro"\] \{([^}]*)\}', ESTILO[:ESTILO.index("@media print")]))
        fondo_oscuro = re.findall(r"--fondo-panel: (#[0-9a-f]{6})", oscuro)[-1]
        for nombre, bloque, fondo in (("claro", claro, fondo_claro), ("oscuro", oscuro, fondo_oscuro)):
            paleta = _paleta(bloque)
            self.assertEqual(len(paleta), COLORES_CATEGORICOS + 1)
            for clave, color in paleta.items():
                with self.subTest(tema=nombre, clave=clave):
                    self.assertGreaterEqual(_contraste(color, fondo), 3.0)

    def test_familias_con_color_fijo_y_distinto(self):
        claves = [activos.FAMILIA_CLAVE[f] for f in ("ubuntu", "debian", "freebsd", "windows", "centos", "otro")]
        self.assertEqual(len(set(claves)), len(claves), "dos familias no pueden compartir color")
        self.assertTrue(all(c.startswith("cat-") for c in claves))
        self.assertEqual(activos.FAMILIA_CLAVE["desconocido"], "neutro")
        porciones = activos._porciones_familias([
            {"so_familia": "ubuntu", "n": 5}, {"so_familia": "debian", "n": 9},
            {"so_familia": "desconocido", "n": 2}, {"so_familia": "windows", "n": 0}])
        self.assertEqual([p["nombre"] for p in porciones], ["Debian", "Ubuntu", "Sin datos de sistema"])
        self.assertEqual([p["clave"] for p in porciones], ["cat-6", "cat-3", "neutro"])

    def test_entornos_con_color_distinto_en_orden_de_exposicion(self):
        self.assertEqual(activos.ORDEN_ENTORNOS[:2], ["produccion", "contingencia"])
        claves = [activos.CLAVE_ENTORNO[e] for e in activos.ORDEN_ENTORNOS]
        self.assertEqual(len(set(claves)), len(claves))
        self.assertEqual(claves[-1], "neutro")
        for clave in claves:
            self.assertIn(clave, graficos.CLAVES)

    def test_lo_desconocido_va_en_gris_no_en_color_de_marca(self):
        """Familias y entornos sin dato siguen en gris.

        Adaptada el 2026-09-08: la gráfica de versiones ya no codifica el soporte en color (cada
        versión tiene el suyo, petición del usuario), así que un sistema conocido pero sin dato de
        soporte lleva su color categórico y «sin dato de soporte» se lee en la nota.

        Adaptada de nuevo el 2026-09-15 (auditoría de tableros): «Sin datos de sistema» ya no es
        una barra de la gráfica de versiones —no es una versión y competía con Debian 12 dentro
        de un top de versiones—, así que aquí se comprueba que NO aparece entre las barras y que
        esos activos se cuentan aparte, para decirlos en su propia línea."""
        self.assertEqual(activos.FAMILIA_CLAVE["desconocido"], "neutro")
        self.assertEqual(activos.CLAVE_ENTORNO["desconocido"], "neutro")
        sistemas = [
            {"so_nombre": "Kali", "so_familia": "otro", "n": 3, "soporte": {}},
            {"so_nombre": None, "so_familia": None, "so_ciclo": None, "n": 2, "soporte": None},
            {"so_nombre": "Debian 13", "so_familia": "debian", "n": 1,
             "soporte": {"eol": "2030-06-30", "fuera": False, "proximo": False}}]
        with mock.patch.object(activos, "url_for", return_value="/activos/"):
            items = activos._items_sistemas(sistemas)
        self.assertEqual([it["etiqueta"] for it in items], ["Kali", "Debian 13"])
        self.assertEqual(items[0]["valores"], [("cat-1", 3, "Kali")])
        self.assertEqual(items[0]["nota"], "sin dato de soporte")
        self.assertEqual(items[1]["valores"][0][0], "cat-2", "el gris no consume un color de la paleta")
        self.assertNotIn("neutro", [it["valores"][0][0] for it in items])
        self.assertEqual(activos._activos_sin_datos_de_sistema(sistemas), 2)


def _sistemas_de_prueba(n: int) -> list[dict]:
    """n versiones ficticias ordenadas de más a menos activos, como las devuelve _sistemas."""
    return [{"so_nombre": f"Sistema {i + 1}", "so_familia": "otro", "so_ciclo": str(i),
             "n": 100 - i, "soporte": {"eol": "2030-01-01", "fuera": False, "proximo": False}}
            for i in range(n)]


class TestGraficaVersionesConColorPropio(unittest.TestCase):
    """Gráfica «Versiones de sistema con más activos» (2026-09-08). El usuario pidió que en esta
    gráfica «se diferencien y no se repitan los colores»: antes cada barra iba del color de su
    estado de soporte (rojo, ámbar, verde, gris) y varias barras compartían color. Ahora cada
    versión lleva un color categórico distinto y el estado de soporte se escribe en la nota,
    porque el color nunca puede ser la única forma de leer un dato."""

    def _items(self, sistemas):
        with mock.patch.object(activos, "url_for", return_value="/activos/"):
            return activos._items_sistemas(sistemas)

    def test_cada_version_tiene_un_color_distinto_y_conocido(self):
        items = self._items(_sistemas_de_prueba(activos.MAX_VERSIONES_GRAFICA))
        claves = [it["valores"][0][0] for it in items]
        self.assertEqual(len(claves), activos.MAX_VERSIONES_GRAFICA)
        self.assertEqual(len(set(claves)), len(claves), "dos barras comparten color")
        for clave in claves:
            self.assertIn(clave, graficos.CLAVES, "clave sin color en la hoja de estilos: se pintaría en gris")
            self.assertTrue(clave.startswith("cat-"), "ningún color semántico (rojo, ámbar, verde) en esta gráfica")
        self.assertEqual(claves[0], "cat-1", "el orden de colores es estable: la versión con más activos siempre el primero")

    def test_la_leyenda_lista_las_versiones_no_el_soporte(self):
        """El tercer elemento del segmento es el nombre que la leyenda muestra: la versión."""
        items = self._items(_sistemas_de_prueba(3))
        self.assertEqual([it["valores"][0][2] for it in items], ["Sistema 1", "Sistema 2", "Sistema 3"])
        html = str(graficos.barras_horizontales(items, unidad=("activo", "activos")))
        self.assertIn('<span class="leyenda-punto serie-cat-1"></span>Sistema 1', html)
        self.assertNotIn("Fuera de soporte", html)

    def test_la_nota_escribe_el_estado_de_soporte_con_fecha_en_espanol(self):
        """Al perder el color semántico, el texto es la única lectura del soporte: fecha completa
        en español y las cuatro situaciones posibles."""
        self.assertEqual(activos._nota_soporte({"eol": "2025-04-30", "fuera": True, "proximo": False}),
                         "sin soporte desde abril de 2025")
        self.assertEqual(activos._nota_soporte({"eol": "2027-04-10", "fuera": False, "proximo": True}),
                         "fin de soporte en abril de 2027")
        self.assertEqual(activos._nota_soporte({"eol": "2030-01-01", "fuera": False, "proximo": False}),
                         "soporte hasta enero de 2030")
        self.assertEqual(activos._nota_soporte({"eol": None, "fuera": False, "proximo": False, "sin_datos": True}),
                         "sin dato de soporte")
        self.assertEqual(activos._nota_soporte(None), "sin dato de soporte")
        items = self._items([{"so_nombre": "Windows 7 Professional", "so_familia": "windows", "n": 2,
                              "soporte": {"eol": "2020-01-14", "fuera": True, "proximo": False}}])
        self.assertEqual(items[0]["nota"], "sin soporte desde enero de 2020")

    def test_el_numero_de_activos_lleva_la_unidad_escrita(self):
        items = self._items([{"so_nombre": "Ubuntu 22.04", "so_familia": "ubuntu", "n": 184,
                              "soporte": {"eol": "2027-04-01", "fuera": False, "proximo": False}}])
        html = str(graficos.barras_horizontales(items, unidad=("activo", "activos")))
        self.assertIn("184 activos", html)
        self.assertIn('<tspan class="nota"> · soporte hasta abril de 2027</tspan>', html)
        self.assertIn('class="serie-cat-1"', html)

    def test_tope_de_doce_versiones_y_aviso_de_las_que_quedan_fuera(self):
        """Hay tantos colores como barras admitidas: con más versiones que colores se recortan
        las de menos activos y se dice cuántas (y cuántos activos) quedan fuera."""
        sistemas = _sistemas_de_prueba(15)
        items = self._items(sistemas)
        self.assertEqual(len(items), 12)
        self.assertEqual([it["etiqueta"] for it in items][-1], "Sistema 12")
        fuera = activos._versiones_fuera_grafica(sistemas)
        self.assertEqual(fuera, {"versiones": 3, "activos": (100 - 12) + (100 - 13) + (100 - 14)})
        self.assertEqual(activos._versiones_fuera_grafica(_sistemas_de_prueba(5)), {"versiones": 0, "activos": 0})
        self.assertEqual(activos.MAX_VERSIONES_GRAFICA, COLORES_CATEGORICOS)
        plantilla = (PLANTILLAS / "activos.html").read_text(encoding="utf-8")
        self.assertIn("{% if graf.sistemas_fuera.versiones %}", plantilla)
        self.assertIn("quedan fuera", plantilla)
        self.assertNotIn('nombres={"critico": "Fuera de soporte"', plantilla,
                         "la leyenda por estado de soporte se retiró de esta gráfica")
        self.assertIn('unidad=("activo", "activos")', plantilla)

    def test_medias_y_bajas_por_separado(self):
        """Las medias y las bajas nunca se mezclan en un mismo segmento. Y desde el
        2026-09-08, con la regla interna de no reportar las bajas (por omisión), las barras
        tienen exactamente tres segmentos: críticas, altas y medias."""
        from webui.vistas import panel, tecnologias
        fila = {"name": "Apache", "amenazas": 10, "criticas": 2, "altas": 3, "medias": 4, "version_installed": "2.4"}
        self.assertEqual(tecnologias._items_top([fila])[0]["valores"],
                         [("critico", 2), ("alto", 3), ("medio", 4)])
        self.assertEqual(tecnologias._items_top([fila], sin_bajas=False)[0]["valores"],
                         [("critico", 2), ("alto", 3), ("medio", 4), ("bajo", 1)])
        with mock.patch.object(panel, "url_for", return_value="/amenazas/"):
            self.assertEqual(panel._items_tecnologias([dict(fila, slug="apache")], "2026-09")[0]["valores"],
                             [("critico", 2), ("alto", 3), ("medio", 4)])
            self.assertEqual(panel._items_tecnologias([dict(fila, slug="apache")], "2026-09",
                                                      sin_bajas=False)[0]["valores"],
                             [("critico", 2), ("alto", 3), ("medio", 4), ("bajo", 1)])
        for nombre in ("tecnologias.html", "panel.html"):
            self.assertNotIn("Medias y bajas", (PLANTILLAS / nombre).read_text(encoding="utf-8"))

    def test_un_cero_no_se_pinta_de_verde(self):
        """Un indicador a cero no es un éxito que celebrar: va neutro para no distraer."""
        for nombre in ("activos.html", "activo_detalle.html", "software.html", "remediacion.html"):
            texto = (PLANTILLAS / nombre).read_text(encoding="utf-8")
            with self.subTest(plantilla=nombre):
                self.assertNotRegex(texto, r"metrica \{% if [^%]+%\}(critico|alto|medio)\{% else %\}exito")
        panel = (PLANTILLAS / "panel.html").read_text(encoding="utf-8")
        self.assertNotRegex(panel, r"activos\.[a-z_]+ %\}(critico|alto|medio)\{% else %\}exito")


class TestRecorridoCompletoUsuariosNuevos(unittest.TestCase):
    """La invitación al recorrido completo se hace una sola vez por usuario: el estado se
    guarda en la base (no en el navegador) y el menú expone lo que el JavaScript necesita."""

    @classmethod
    def setUpClass(cls):
        import tempfile
        from threatintel import db
        from webui import auth
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "tour.db")
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "nuevo@ejemplo.net", "NuevoSeguro#2026", rol="ciberseguridad", actor="t")
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def _cliente(self):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": "nuevo@ejemplo.net", "password": "NuevoSeguro#2026"})
        return cli

    def test_invitacion_pendiente_y_respuesta_guardada_en_la_base(self):
        from threatintel import db
        cli = self._cliente()
        html = cli.get("/").get_data(as_text=True)
        self.assertIn('data-tour-estado="pendiente"', html)
        self.assertIn('data-tour-url="/tour/respuesta"', html)
        csrf = re.search(r'data-csrf="([^"]+)"', html).group(1)
        r = cli.post("/tour/respuesta", data={"csrf": csrf, "estado": "rechazado"})
        self.assertEqual(r.status_code, 204, r.get_data(as_text=True)[:300])
        with db.session(self.ruta) as conn:
            fila = conn.execute("SELECT tour_estado, tour_at FROM users WHERE username='nuevo@ejemplo.net'").fetchone()
        self.assertEqual(fila["tour_estado"], "rechazado")
        self.assertTrue(fila["tour_at"])
        # En el siguiente acceso, desde cualquier navegador, ya no está pendiente.
        otro = self._cliente()
        html_otro = otro.get("/amenazas/").get_data(as_text=True)
        self.assertIn('data-tour-estado="rechazado"', html_otro)
        csrf_otro = re.search(r'data-csrf="([^"]+)"', html_otro).group(1)   # cada sesión tiene su propio token
        # Un estado desconocido se rechaza; «pendiente» vuelve a invitar.
        self.assertEqual(otro.post("/tour/respuesta", data={"csrf": csrf_otro, "estado": "loquesea"}).status_code, 400)
        self.assertEqual(otro.post("/tour/respuesta", data={"csrf": csrf_otro, "estado": "pendiente"}).status_code, 204)
        self.assertIn('data-tour-estado="pendiente"', otro.get("/").get_data(as_text=True))

    def test_el_javascript_encadena_las_secciones_del_menu(self):
        js = (BASE_DIR / "webui" / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn('aside nav a[href]', js)
        self.assertIn('"Siguiente sección: "', js)
        self.assertIn('data-tour-estado") === "pendiente"', js)
        self.assertNotIn('"¿Primera vez en esta sección?"', js, "el aviso por página se retiró")


if __name__ == "__main__":
    unittest.main()

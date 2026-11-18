"""Páginas Activos, ficha de activo y Software; activos en la ficha de amenaza,
el panel, el inventario, el correo de alerta y el informe mensual (2026-09-04).

Sin red ni MariaDB: lector de OCS simulado y respuestas falsas de OSV.dev,
VuXML y endoflife.date (reutiliza los datos de tests/test_activos_ocs.py).
Comprueba HTTP 200 con sesión, CSP estricta (sin style= ni on*=), permisos de
administrador en las escrituras, CSV, la consulta «¿Le aplica este CVE?», y que
los textos visibles están en español sin abreviaturas."""
from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from threatintel import aplicabilidad as ap
from threatintel import db, notify, ocs, report
from threatintel.paths import BASE_DIR

sys.path.insert(0, str(BASE_DIR / "tests"))
import test_activos_ocs as datos  # noqa: E402

RE_STYLE = re.compile(r"\sstyle\s*=", re.I)
RE_ON = re.compile(r"\son[a-z]+\s*=", re.I)


class Cfg(dict):
    """Config minima para report.generar (usa .get)."""

    def get(self, k, d=None):
        return super().get(k, d)


class TestPaginasActivos(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "paginas.db")
        db.init_db(cls.ruta)
        from webui import auth
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "admin", "AdminSeguro#2026", rol="admin", actor="t")
            auth.crear_usuario(conn, "lector", "LectorSeguro#2026", rol="ciberseguridad", actor="t")
            ahora = db.utcnow()
            for slug, name in (("chrome", "Google Chrome"), ("apache-httpd", "Apache HTTP Server"),
                               ("freebsd", "FreeBSD"), ("postgresql", "PostgreSQL")):
                conn.execute("""INSERT INTO technologies(slug,name,vendor,category,criticality,systems_count,exposure,
                                enabled,created_at,updated_at) VALUES(?,?,'x','aplicacion','high',0,'interna',1,?,?)""",
                             (slug, name, ahora, ahora))
            cls.tid_chrome = conn.execute("SELECT id FROM technologies WHERE slug='chrome'").fetchone()[0]
            conn.execute("""INSERT INTO threats(fingerprint,cve,title_en,summary_en,severity,severity_source,first_seen_at,
                            last_seen_at,month,relevance,estado) VALUES('fp-curl','CVE-2024-11053','curl netrc leak',
                            'curl before 8.11.1 leaks credentials','High','nvd',?,?,?,60.0,'nueva')""",
                         (ahora, ahora, ahora[:7]))
            conn.execute("""INSERT INTO threats(fingerprint,cve,title_en,summary_en,severity,severity_source,first_seen_at,
                            last_seen_at,month,relevance,estado,in_kev) VALUES('fp-chrome','CVE-2026-9999',
                            'Google Chrome type confusion','Google Chrome prior to 152.0.7632.45 allows remote code execution',
                            'Critical','nvd',?,?,?,70.0,'nueva',1)""", (ahora, ahora, ahora[:7]))
            cls.id_curl = conn.execute("SELECT id FROM threats WHERE fingerprint='fp-curl'").fetchone()[0]
            cls.id_chrome = conn.execute("SELECT id FROM threats WHERE fingerprint='fp-chrome'").fetchone()[0]
            conn.execute("INSERT INTO threat_technologies(threat_id,technology_id,matched_alias,confidence,version_verdict) "
                         "VALUES(?,?,'google chrome',1.0,'unknown')", (cls.id_chrome, cls.tid_chrome))
            cls.mes = ahora[:7]
        cfg = datos.Cfg(ocs_risk_software=["tightvnc"], ocs_edr_pattern="sophos", ocs_stale_days=30)
        conn = db.connect(cls.ruta)
        try:
            ocs.sincronizar_origen(conn, "servidores", datos.LectorFalso(datos.HW[:3], [s for s in datos.SW if s[0] <= 3]), cfg=cfg)
            ocs.sincronizar_origen(conn, "equipos", datos.LectorFalso(datos.HW[3:], [s for s in datos.SW if s[0] == 4]), cfg=cfg)
            ocs.sembrar_mapa(conn)
            ocs.aplicar_mapa(conn)
            ocs.actualizar_inventario_desde_ocs(conn)
            ocs.detectar_hallazgos(conn, cfg=cfg)
            ap.actualizar_fin_soporte(conn, forzar=True, fetch=datos.fetch_json_falso)
            ap.hallazgos_fin_soporte(conn)
            osv = ap.ClienteOSV(conn, fetch=datos.fetch_json_falso)
            vux = ap.IndiceVuXML(datos.VUXML)
            for tid in (cls.id_curl, cls.id_chrome):
                am = dict(conn.execute("SELECT * FROM threats WHERE id=?", (tid,)).fetchone())
                ap.evaluar_amenaza(conn, am, osv=osv, vuxml=vux)
            cls.web = conn.execute("SELECT id FROM activos WHERE nombre='srv-web-01'").fetchone()[0]
            cls.pc = conn.execute("SELECT id FROM activos WHERE nombre='pc-ana'").fetchone()[0]
        finally:
            conn.close()
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def _cliente(self, usuario="admin", clave="AdminSeguro#2026"):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": usuario, "password": clave})
        return cli

    def _csrf(self, cli, url):
        return re.search(r'name="csrf" value="([^"]+)"', cli.get(url).get_data(as_text=True)).group(1)

    def _ok(self, cli, url):
        r = cli.get(url)
        html = r.get_data(as_text=True)
        self.assertEqual(r.status_code, 200, url)
        if "text/html" in r.content_type:
            self.assertIsNone(RE_STYLE.search(html), f"style= en {url}")
            self.assertIsNone(RE_ON.search(html), f"on*= en {url}")
        return html

    def test_grafica_versiones_con_color_propio_y_soporte_escrito(self):
        """Gráfica «Versiones de sistema con más activos» (2026-09-08): en la página real cada
        barra lleva un color categórico distinto, el número va con la unidad («activos») y el
        estado de soporte se lee en la nota, no en el color."""
        html = self._ok(self._cliente(), "/activos/")
        panel = html.split("Versiones de sistema con más activos", 1)[1].split("panel-pie", 1)[0]
        claves = re.findall(r'<rect class="serie-(cat-\d+)"', panel)
        self.assertGreaterEqual(len(claves), 2, "la gráfica debería tener al menos dos versiones de prueba")
        self.assertEqual(len(set(claves)), len(claves), f"colores repetidos en la gráfica: {claves}")
        self.assertNotRegex(panel, r'<rect class="serie-(critico|medio|exito|neutro)"')
        self.assertRegex(panel, r'<text class="etiqueta-valor"[^>]*>\d+ activos?<tspan class="nota"> · ')
        self.assertRegex(panel, r"(sin soporte desde|fin de soporte en|soporte hasta) [a-z]+ de \d{4}")  # mes y año (2026-09-08)
        self.assertIn("El color solo distingue una versión de otra", html)

    def test_lista_activos(self):
        cli = self._cliente()
        html = self._ok(cli, "/activos/")
        # 2026-09-15 (revisión de claridad): la tarjeta «Tecnologías con activos» decía
        # «164 / 193» mientras la página de Software decía «166 tecnologías con activos» y
        # la de Inventario tecnológico «197 tecnologías»: tres denominadores para lo
        # mismo. El rótulo dice ahora sobre qué se cuenta, y ese es el texto que se exige.
        for texto in ("Activos de la organización", "srv-web-01", "srv-bsd-01", "pc-ana", "Con vulnerabilidades confirmadas",
                      "Fuera de soporte", "Sin reportar", "Vistas rápidas", "Fin de soporte",
                      "Windows 7 Professional", "Equipo de cómputo", "Servidor",
                      "Tecnologías del inventario instaladas en algún activo"):
            self.assertIn(texto, html)
        self.assertNotIn("Rel.", html)
        # El filtrado es en el navegador: cada fila declara sus vistas en data-vistas y el
        # formulario no recarga (sin botón «Filtrar»); el filtro por tecnología sí es del servidor.
        fila_pc = re.search(r'<tr data-id="\d+" data-nombre="pc-ana"[^>]*>', html).group(0)
        self.assertIn("fin_soporte", fila_pc)
        self.assertIn("software_riesgo", fila_pc)
        self.assertIn('data-entorno="desconocido"', fila_pc)
        fila_db = re.search(r'<tr data-id="\d+" data-nombre="srv-db-01"[^>]*>', html).group(0)
        self.assertNotIn("fin_soporte", fila_db)
        self.assertIn("sin_reportar", fila_db)
        self.assertIn('data-filtro-activos="q"', html)
        self.assertIn('data-vista="fuera_soporte"', html)
        self.assertIn("data-vacio-activos", html)
        self.assertNotIn('type="submit">Filtrar', html.split("tabla-activos")[1])
        html = self._ok(cli, f"/activos/?tec={self.tid_chrome}")
        self.assertIn("con Google Chrome instalado", html)
        self.assertIn("pc-ana", html)
        self.assertNotIn("srv-db-01", html.split("tabla-activos")[1])
        # El selector «Tecnología» del formulario de filtros es visible (ya no un campo
        # oculto) y deja preseleccionada la tecnología que llegó por la URL (2026-11-15:
        # el usuario pidió poder escribir/elegir la tecnología desde el propio formulario,
        # no solo llegar con el id ya resuelto desde la ficha de Tecnología).
        self.assertIn('<label for="tec">Tecnología</label>', html)
        self.assertIn(f'<option value="{self.tid_chrome}" selected>Google Chrome</option>', html)
        # desplegable de vulnerabilidades: JSON por activo
        r = cli.get(f"/activos/{self.web}/vulnerabilidades.json")
        self.assertEqual(r.status_code, 200)
        datos = r.get_json()
        self.assertGreaterEqual(datos["total"], 1)
        self.assertIn("CVE-2024-11053", {v["cve"] for v in datos["vulnerabilidades"]})
        self.assertTrue(datos["vulnerabilidades"][0]["kev"])   # las KEV primero
        self.assertIn("/activos/", datos["url_remediacion"])
        self.assertEqual(r.headers.get("Cache-Control"), "no-store, private")
        self.assertEqual(cli.get("/activos/999999/vulnerabilidades.json").status_code, 404)
        # plan de remediación
        html = self._ok(cli, f"/activos/{self.web}/remediacion")
        self.assertIn("apt-get install --only-upgrade", html)
        self.assertIn("libcurl4", html)
        r = cli.get(f"/activos/{self.web}/remediacion?formato=txt")
        self.assertIn("text/plain", r.content_type)
        self.assertIn("Orden:", r.get_data(as_text=True))
        html = self._ok(cli, f"/amenazas/{self.id_curl}/remediacion")
        self.assertIn("srv-web-01", html)
        self.assertIn("Plan de remediación", html)

    def test_filtro_por_cve(self):
        """Filtro «CVE» de la lista de Activos (2026-11-15, petición del usuario: no
        podía ver qué activos afecta una tecnología o un CVE sin ir uno por uno).

        CVE-2024-11053 (curl) está confirmado como «afectado» en srv-web-01, srv-db-01
        (solo en el paquete libcurl4, pero el activo entero cuenta como afectado, igual
        que en la columna «Afectados» y en la vista rápida «Con vulnerabilidades
        confirmadas») y srv-bsd-01; pc-ana no tiene curl instalado. CVE-2026-9999
        (Google Chrome) está confirmado en srv-web-01 y en pc-ana.
        """
        def cuerpo(html: str) -> str:
            # El cuerpo de LA TABLA DE ACTIVOS, no cualquier otra tabla de la página
            # (hay varias): mismo patrón que
            # test_la_tabla_de_activos_declara_el_ancho_de_todas_sus_columnas, que ya
            # localiza esa tabla por su clase. Sin filas, la tabla ni se pinta (va al
            # «{% else %}» del «vacío»), así que no hay coincidencia.
            tabla = re.search(r'<table[^>]*class="[^"]*tabla-activos[^"]*".*?</table>', html, re.S)
            return tabla.group(0) if tabla else ""

        cli = self._cliente()
        html = self._ok(cli, "/activos/?cve=CVE-2024-11053")
        tabla = cuerpo(html)
        self.assertIn("srv-web-01", tabla)
        self.assertIn("srv-db-01", tabla)
        self.assertIn("srv-bsd-01", tabla)
        self.assertNotIn("pc-ana", tabla)
        self.assertIn("afectados por CVE-2024-11053", html)
        # Normalización igual que en «¿Le aplica este CVE?» (/aplica): minúsculas y
        # espacios de más no cambian el resultado.
        html_minusculas = self._ok(cli, "/activos/?cve=%20cve-2024-11053%20")
        self.assertIn("srv-web-01", cuerpo(html_minusculas))
        # Un CVE que no existe en ningún veredicto de aplicabilidad: lista vacía, sin
        # error (no un 500 ni una pantalla rota).
        html_vacio = self._ok(cli, "/activos/?cve=CVE-2099-0001")
        self.assertIn("0 activos con estos filtros", html_vacio)
        self.assertIn("data-vacio-activos", html_vacio)
        self.assertEqual(cuerpo(html_vacio), "")
        # Otro CVE confirmado (Google Chrome), para no depender de un único caso.
        html_chrome = self._ok(cli, "/activos/?cve=CVE-2026-9999")
        tabla_chrome = cuerpo(html_chrome)
        self.assertIn("srv-web-01", tabla_chrome)
        self.assertIn("pc-ana", tabla_chrome)
        self.assertNotIn("srv-db-01", tabla_chrome)
        # El campo del formulario conserva el valor escrito y «Limpiar filtros» aparece.
        self.assertIn('value="CVE-2026-9999"', html_chrome)
        self.assertIn("Limpiar filtros", html_chrome)
        # Regresión: el filtro por tecnología sigue funcionando igual que antes de
        # añadir el de CVE (no se tocó cómo se lee «tec» en _leer_filtros).
        html_tec = self._ok(cli, f"/activos/?tec={self.tid_chrome}")
        self.assertIn("pc-ana", cuerpo(html_tec))
        self.assertNotIn("srv-db-01", cuerpo(html_tec))
        # Los dos filtros combinados (interseccion): pc-ana tiene Chrome Y el CVE de
        # Chrome, srv-bsd-01 no tiene Chrome aunque sí tenga el CVE de curl.
        html_combinado = self._ok(cli, f"/activos/?tec={self.tid_chrome}&cve=CVE-2026-9999")
        tabla_combinada = cuerpo(html_combinado)
        self.assertIn("pc-ana", tabla_combinada)
        self.assertNotIn("srv-bsd-01", tabla_combinada)

    def test_ficha_activo_y_consulta_cve(self):
        cli = self._cliente()
        html = self._ok(cli, f"/activos/{self.web}")
        # Adaptado el 2026-09-09: la tabla «Amenazas evaluadas para este activo» se
        # retiró (listaba también lo que NO afecta) y la sustituye la de actualizaciones,
        # una entrada por cosa que hay que actualizar. La constancia de lo evaluado queda
        # en una línea de «Hallazgos de política».
        for texto in ("¿Le aplica este CVE?", "Datos del activo", "Actualizaciones pendientes",
                      "Software instalado", "Ubuntu:22.04", "Vulnerabilidades confirmadas",
                      "identificadores CVE en este activo"):
            self.assertIn(texto, html)
        self.assertNotIn("Amenazas evaluadas para este activo", html)
        csrf = self._csrf(cli, f"/activos/{self.web}")
        with mock.patch.object(ap.http, "fetch_json", datos.fetch_json_falso):
            r = cli.post(f"/activos/{self.web}/aplica", data={"csrf": csrf, "cve": "cve-2024-11053"})
        html = r.get_data(as_text=True)
        self.assertEqual(r.status_code, 200)
        self.assertIn("sí le aplica", html)
        self.assertIn("libcurl4", html)
        self.assertIn("7.81.0-1ubuntu1.20", html)
        r = cli.post(f"/activos/{self.web}/aplica", data={"csrf": csrf, "cve": "esto no es un cve"})
        self.assertIn("formato CVE-AAAA-NNNN", r.get_data(as_text=True))
        # software: solo clasificado por defecto; con todo=1 aparece el resto
        html = self._ok(cli, f"/activos/{self.web}")
        self.assertIn("google-chrome-stable", html)
        html_todo = self._ok(cli, f"/activos/{self.web}?todo=1")
        self.assertIn("libcurl4", html_todo)
        # ficha del equipo Windows 7: fuera de soporte y hallazgos
        html = self._ok(cli, f"/activos/{self.pc}")
        self.assertIn("Sistema fuera de soporte", html)
        self.assertIn("Software de riesgo", html)
        self.assertIn("Sin antivirus Sophos", html)
        # 2026-09-08: un activo inexistente responde 404, la MISMA respuesta que un activo
        # fuera del alcance de un perfil acotado (antes redirigía con aviso, y esa diferencia
        # permitía enumerar identificadores del otro tipo de máquina).
        self.assertEqual(cli.get("/activos/999999").status_code, 404)

    def test_software_y_reglas(self):
        cli = self._cliente()
        html = self._ok(cli, "/activos/software")
        for texto in ("Software instalado y mapa de nombres", "Nueva regla", "Software sin clasificar",
                      "Tecnologías con activos", "Reglas del mapa de nombres", "Google Chrome", "Nombre exacto"):
            self.assertIn(texto, html)
        csrf = self._csrf(cli, "/activos/software")
        r = cli.post("/activos/software/regla", data={"csrf": csrf, "patron": "tightvnc", "modo": "prefijo",
                                                      "technology_id": self.tid_chrome}, follow_redirects=True)
        self.assertIn("Regla guardada", r.get_data(as_text=True))
        with db.session(self.ruta) as conn:
            fila = conn.execute("SELECT id FROM tecnologia_ocs WHERE patron='tightvnc' AND modo='prefijo'").fetchone()
            self.assertIsNotNone(fila)
            self.assertEqual(conn.execute("SELECT technology_id FROM activo_software WHERE nombre_norm='tightvnc'").fetchone()[0],
                             self.tid_chrome)
        r = cli.post(f"/activos/software/regla/{fila['id']}/borrar", data={"csrf": csrf}, follow_redirects=True)
        self.assertIn("Regla eliminada", r.get_data(as_text=True))
        with db.session(self.ruta) as conn:
            # sin la regla manual, la clasificacion de respaldo le da su propia tecnologia (no Chrome)
            tid = conn.execute("SELECT technology_id FROM activo_software WHERE nombre_norm='tightvnc'").fetchone()[0]
            self.assertNotEqual(tid, self.tid_chrome)
            self.assertIsNotNone(tid)
        r = cli.post("/activos/software/regla", data={"csrf": csrf, "patron": "(", "modo": "regex",
                                                      "technology_id": self.tid_chrome}, follow_redirects=True)
        self.assertIn("expresión regular no es válida", r.get_data(as_text=True))

    def test_permisos_lector(self):
        cli = self._cliente("lector", "LectorSeguro#2026")
        html = self._ok(cli, "/activos/software")
        self.assertNotIn("Nueva regla", html)
        self.assertNotIn("Sincronizar con OCS ahora", self._ok(cli, "/activos/"))
        csrf = self._csrf(cli, f"/activos/{self.web}")
        r = cli.post("/activos/software/regla", data={"csrf": csrf, "patron": "x", "modo": "exacto",
                                                      "technology_id": self.tid_chrome})
        self.assertIn(r.status_code, (302, 403))
        with db.session(self.ruta) as conn:
            self.assertIsNone(conn.execute("SELECT 1 FROM tecnologia_ocs WHERE patron='x'").fetchone())
        r = cli.post("/activos/sincronizar", data={"csrf": csrf})
        self.assertIn(r.status_code, (302, 403))
        # sin CSRF tampoco
        r = cli.post(f"/activos/{self.web}/aplica", data={"cve": "CVE-2024-11053"})
        self.assertIn(r.status_code, (400, 403))
        # anónimo
        self.assertEqual(self.app.test_client().get("/activos/").status_code, 302)

    def test_tres_columnas_para_tipo_entorno_y_proceso(self):
        """El usuario los pidió separados el 2026-09-07: «necesito saber en una columna
        si es servidor, en otra el entorno si es de desarrollo y en otra a qué proceso
        pertenece»."""
        html = self._ok(self._cliente(), "/activos/")
        for cabecera in (">Tipo</th>", ">Entorno</th>", ">Proceso</th>"):
            self.assertIn(cabecera, html)
        self.assertNotIn("Tipo y entorno", html)
        # y lo que puede faltar se dice con palabras, no con una celda vacía
        self.assertTrue("Sin entorno" in html or "entorno-" in html)

    def test_la_tabla_de_activos_declara_el_ancho_de_todas_sus_columnas(self):
        """«.tabla-activos» es de ancho fijo (table-layout: fixed), así que cada columna
        necesita su porcentaje en el <colgroup> y su regla en estilo.css.

        El 2026-09-07, al separar tipo, entorno y proceso, el <colgroup> se quedó con
        siete columnas para una tabla de nueve: las dos nuevas se quedaron sin anchura y
        el contenido se apiló letra a letra (filas de 1.055 píxeles en lugar de 83).
        Esta prueba cuenta las tres cosas y comprueba que los porcentajes suman 100."""
        import re as _re
        html = self._ok(self._cliente(), "/activos/")
        tabla = _re.search(r'<table[^>]*class="[^"]*tabla-activos[^"]*".*?</table>', html, _re.S)
        self.assertIsNotNone(tabla, "no se encuentra la tabla de activos")
        tabla = tabla.group(0)
        clases = _re.findall(r'<col class="([^"]+)"', tabla)
        cabecera = _re.search(r"<thead>.*?</thead>", tabla, _re.S).group(0)
        n_th = len(_re.findall(r"<th[\s>]", cabecera))   # «<thead» no cuenta
        primera_fila = _re.search(r'<tr data-id="\d+".*?</tr>', tabla, _re.S).group(0)
        n_td = len(_re.findall(r"<td[\s>]", primera_fila))
        self.assertEqual(len(clases), n_th, "una columna del <colgroup> por cada <th>")
        self.assertEqual(n_th, n_td, "una celda por cada encabezado")

        css = (BASE_DIR / "webui" / "static" / "estilo.css").read_text(encoding="utf-8")
        suma = 0
        for clase in clases:
            ancho = _re.search(rf"\.tabla-activos \.{clase} {{ width: ([\d.]+)%; }}", css)
            self.assertIsNotNone(ancho, f"falta el ancho de .{clase} en estilo.css")
            suma += float(ancho.group(1))
        self.assertEqual(round(suma), 100, f"los anchos suman {suma} %, deben sumar 100")

    def test_csv(self):
        cli = self._cliente()
        r = cli.get("/activos/exportar.csv")
        self.assertEqual(r.status_code, 200)
        texto = r.get_data(as_text=True)
        # El entorno y el proceso faltaban en la exportación (petición del 2026-09-07)
        self.assertIn("activo;tipo;entorno;proceso;ip;sistema", texto)
        cabecera, primera = texto.strip().splitlines()[0], texto.strip().splitlines()[1]
        columnas = cabecera.lstrip("\ufeff").split(";")
        valores = primera.split(";")
        self.assertEqual(len(valores), len(columnas), "una fila con tantas celdas como columnas")
        self.assertIn("srv-web-01", texto)
        r = cli.get(f"/activos/{self.web}/exportar.csv")
        self.assertIn("CVE-2024-11053", r.get_data(as_text=True))
        self.assertIn("Afectado", r.get_data(as_text=True))

    def test_integracion_amenaza_panel_inventario(self):
        cli = self._cliente()
        html = self._ok(cli, f"/amenazas/{self.id_curl}")
        self.assertIn("Activos afectados", html)
        # El nombre del activo vive en el cuadro AJAX (2026-11-16), no en el HTML
        # inicial de la ficha.
        datos = cli.get(f"/amenazas/activos-afectados/{self.id_curl}").get_json()
        self.assertIn("srv-web-01", [a["nombre"] for a in datos["activos"]])
        self.assertIn("con la versión vulnerable", html)
        self.assertIn("Cómo se evaluó", html)
        self.assertIn("Cómo se calcula la prioridad", html)
        self.assertIn("Activos reales (OCS Inventory)", html)
        self.assertIn("Plan de remediación", html)
        # Cierra el ciclo con el filtro «CVE» de Activos (2026-11-15): desde la ficha
        # de la amenaza se puede ir directo a la lista de activos que tienen ese CVE
        # exacto confirmado, sin pasar por la tabla de 60 de esta misma página.
        self.assertIn('href="/activos/?cve=CVE-2024-11053">Ver todos los activos afectados</a>', html)
        self.assertNotIn(">Ver activos<", html)
        html = self._ok(cli, "/")
        # Desde el 2026-09-06 el bloque del Panel se titula igual que en el correo de alerta,
        # a petición del usuario, para que lo encuentre en el mismo sitio y con el mismo nombre.
        self.assertIn("Estado de los activos (OCS Inventory)", html)
        # La etiqueta dice ya si cuenta equipos o vulnerabilidades (2026-09-07)
        self.assertIn("Con al menos una vulnerabilidad confirmada", html)
        html = self._ok(cli, f"/tecnologias/{self.tid_chrome}")
        self.assertIn("Versiones instaladas según OCS Inventory", html)
        self.assertIn("Activos con esta tecnología", html)
        html = self._ok(cli, "/tecnologias/")
        self.assertIn(f"/activos/?tec={self.tid_chrome}", html)
        html = self._ok(cli, "/ajustes/")
        self.assertIn("Activos e inventario real (OCS Inventory)", html)

    def test_correo_alerta_con_activos(self):
        from threatintel import queries
        conn = db.connect(self.ruta)
        try:
            vistas = [queries.obtener_amenaza(conn, self.id_curl), queries.obtener_amenaza(conn, self.id_chrome)]
            ap.adjuntar_activos(conn, vistas, limite=10)
        finally:
            conn.close()
        html = notify.render_alert_email(vistas, {"periodo": self.mes})
        self.assertIn("Activos afectados", html)
        self.assertIn("srv-web-01", html)
        self.assertIn("7.81.0-1ubuntu1.20", html)
        # Desde el 2026-09-07 el correo también separa el tipo del entorno
        # («necesito saber en una columna si es servidor, en otra el entorno»).
        for cabecera in (">Tipo</th>", ">Entorno</th>"):
            self.assertIn(cabecera, html)
        self.assertNotIn("Tipo y entorno", html)
        self.assertIn("activos de la organización con la versión vulnerable", html)
        # Revisión de claridad del 2026-09-15: el asunto dice de qué va el correo (fecha
        # en palabras y dos cifras). El recuento de activos afectados sigue en el cuerpo:
        # el asunto se queda corto para que el gestor de correo no lo recorte.
        asunto = notify.asunto_alerta(1, 1, 0, total=2, activos=3)
        self.assertNotIn("activo", asunto)
        self.assertIn("Alerta diaria", asunto)
        self.assertIn("2 vulnerabilidades, 1 crítica", asunto)
        por_que = notify.motivo_alerta(vistas[0], umbral=50)
        self.assertIn("con la versión vulnerable instalada", por_que)

    def test_informe_con_activos(self):
        from docx import Document
        cfg = Cfg(ignore_low_severity=True, ignore_low_criticality=True, alert_min_relevance=50,
                  alert_min_match_confidence=0.6, report_detail_severities=["Critical", "High"],
                  report_max_detail_items=30, report_max_anexo_items=100, translate_engine="none")
        conn = db.connect(self.ruta)
        try:
            resumen = report.construir_resumen(conn, self.mes, cfg=cfg)
            self.assertGreaterEqual(len(resumen["activos"]["afectados"]), 2)
            self.assertTrue(resumen["activos"]["fuera_soporte_sistemas"])
            destino = Path(self.dir.name) / "informe.docx"
            with mock.patch.object(report, "log"):
                report.generar(conn, self.mes, cfg=cfg, destino=destino)
        finally:
            conn.close()
        doc = Document(str(destino))
        textos = "\n".join(p.text for p in doc.paragraphs)
        tablas = "\n".join(c.text for t in doc.tables for f in t.rows for c in f.cells)
        for esperado in ("4. Activos de la organización", "4.1 Activos con vulnerabilidades confirmadas",
                         "4.2 Fin de soporte", "4.3 Cobertura del inventario real", "5. Vulnerabilidades prioritarias",
                         "6. Conclusiones y recomendaciones", "7. Precisión del filtro de alertas",
                         "8. Nota metodológica", "8.6 Aplicabilidad por activo"):
            self.assertIn(esperado, textos, esperado)
        self.assertIn("srv-web-01", tablas)
        self.assertIn("Activos afectados", tablas)          # fila de la ficha
        self.assertIn("Windows 7 Professional", tablas)


if __name__ == "__main__":
    unittest.main()

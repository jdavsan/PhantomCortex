#!/usr/bin/env python3
"""Pruebas de renderizado de Fuentes (/fuentes/, /fuentes/<id>) e Inventario
(/tecnologias/, /tecnologias/<id>) rediseñados el 2026-09-03.

Cubren la sección 6 «Fuentes» e «Inventario» de docs/DISENO_INTERFAZ_2026-09-03.md:

* las cuatro páginas responden 200 con sesión (administrador y solo lectura);
* los gráficos SVG están presentes y cumplen la CSP estricta (sin ``style=``,
  sin ``on*=``, sin ``<script>`` en línea, sin colores literales en
  ``fill``/``stroke``, sin recursos externos);
* las cifras de los gráficos coinciden con las de las tablas y las consultas
  (la dona de criticidad suma el total de tecnologías, la dona de estado solo
  cuenta las fuentes activas, las barras de aportación igualan la columna
  «Amenazas»…);
* la chispa de la tabla de fuentes sale de UNA consulta de ventana y respeta
  las 15 últimas comprobaciones;
* criticidad, exposición y categorías se muestran en español;
* los textos procedentes de la base de datos llegan escapados al SVG;
* formularios y botones (Probar, Activar/Desactivar, Editar, Eliminar,
  Importar CSV, versión rápida, Añadir) siguen en el HTML;
* con una base vacía no hay excepciones y se muestran estados vacíos.

La base de datos es temporal bajo ``data/`` (mismo patrón que
tests/test_pagina_panel.py). Nunca se toca ``data/threat_intel.db``.

Ejecución:
    sudo -n -u si .venv/bin/python -m unittest tests.test_pagina_fuentes_inventario
"""
from __future__ import annotations

import re
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threatintel import db  # noqa: E402
from threatintel.paths import BASE_DIR  # noqa: E402
from webui.graficos import fmt  # noqa: E402
from webui.vistas import fuentes as vista_fuentes  # noqa: E402
from webui.vistas import tecnologias as vista_tec  # noqa: E402

USUARIO, CLAVE = "pruebas", "PruebaSegura#2026"
LECTOR, CLAVE_LECTOR = "lector", "LectorSeguro#2026"
HOSTIL_TEC = 'Tec <script>alert(1)</script>'
HOSTIL_FUENTE = 'Fuente <script>alert("f")</script> & Cía'
MESES = ["2026-07", "2026-08", "2026-09"]

RE_STYLE = re.compile(r"\sstyle\s*=", re.I)
RE_ON = re.compile(r"\son[a-z]+\s*=", re.I)
RE_SCRIPT_INLINE = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>", re.I)
RE_FILL_STROKE = re.compile(r'\b(fill|stroke)="([^"]*)"')

# --- fuentes: (id, slug, nombre, kind, categoría, prioridad, enabled, historial) ---
# El historial va de la comprobación MÁS RECIENTE a la más antigua, como
# tuplas (ok, entradas, aceptadas, latencia_ms). La primera fuente tiene 20
# comprobaciones para probar la ventana de 15 de la chispa.
FUENTES = [
    (1, "s-ok", "Fuente correcta", "rss", "vendor", "high", 1,
     [(1, 5, k % 3, 100 + 10 * k) for k in range(20)]),
    (2, "s-ok2", "Otra fuente correcta", "rss", "news", "medium", 1,
     [(1, 4, 1, 80), (1, 4, 0, 90), (1, 3, 2, 85)]),
    (3, "s-api", "NVD API", "nvd_api", "database", "critical", 1,
     [(1, 5, 0, 300), (1, 5, 0, 310)]),
    (4, "s-caida", HOSTIL_FUENTE, "rss", "blog", "medium", 1,
     [(0, 0, 0, None), (0, 0, 0, None), (0, 0, 0, None)]),
    (5, "s-degradada", "Fuente degradada", "rss", "government", "high", 1,
     [(0, 0, 0, None), (1, 6, 1, 150), (1, 6, 2, 140)]),
    (6, "s-nueva", "Fuente sin comprobar", "rss", "exploits", "low", 1, []),
    (7, "s-off", "Fuente desactivada", "rss", "news", "low", 0,
     [(0, 0, 0, None), (0, 0, 0, None), (0, 0, 0, None)]),
    # una sola comprobación: la chispa no se dibuja (un punto aislado no se ve)
    # y en su lugar sale «1 comprobación · 4 aceptadas»
    (8, "s-una", "Fuente con una comprobación", "rss", "news", "low", 1,
     [(1, 4, 4, 120)]),
]
#: Amenazas distintas con procedencia: todas las amenazas citan la fuente 1.
AMENAZAS_TOTAL = sum((i + 1) + (i + 2) + (2 * i + 3) + i for i in range(len(MESES)))

# --- inventario: (id, slug, nombre, categoría, versión, criticidad, exposición) ---
# Diez categorías distintas (> 8) para probar el agrupado en «Otras categorías»;
# «sistema-operativo» tiene dos tecnologías para ser la mayor y quedar visible.
TECNOLOGIAS = [
    (1, "windows-server", "Windows Server", "sistema-operativo", "2019", "high", "interna"),
    (2, "cisco-ios-xe", "Cisco IOS XE", "red", None, "critical", "internet"),
    (3, "tec-hostil", HOSTIL_TEC, "aplicacion", None, "medium", "dmz"),
    (4, "postgresql", "PostgreSQL", "base-de-datos", "15.4", "high", "interna"),
    (5, "chrome", "Google Chrome", "navegador", None, "low", "interna"),
    (6, "nginx", "Nginx", "servidor-web", None, "medium", "internet"),
    (7, "docker", "Docker", "contenedores", None, "medium", "interna"),
    (8, "openssl", "OpenSSL", "criptografia", "3.0", "high", "interna"),
    (9, "zabbix", "Zabbix", "monitorizacion", None, "medium", "interna"),
    (10, "exchange", "Microsoft Exchange", "correo", None, "high", "dmz"),
    (11, "ubuntu-server", "Ubuntu Server", "sistema-operativo", "22.04", "medium", "interna"),
]


def _iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _sembrar(ruta: str) -> None:
    """Base realista pero pequeña: fuentes en todos los estados, inventario con
    diez categorías, tres meses de amenazas con procedencia y correlaciones."""
    from webui import auth as _auth
    ahora = datetime.now(timezone.utc)
    ts = _iso(ahora)

    with db.session(ruta) as conn:
        _auth.crear_usuario(conn, USUARIO, CLAVE, rol="admin", actor="test")
        _auth.crear_usuario(conn, LECTOR, CLAVE_LECTOR, rol="ciberseguridad", actor="test")

        for sid, slug, nombre, kind, categoria, prioridad, enabled, historial in FUENTES:
            conn.execute(
                """INSERT INTO sources(id,slug,name,url,kind,category,priority,
                       enabled,timeout_s,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,30,?,?)""",
                (sid, slug, nombre, f"https://x.invalid/{slug}", kind, categoria,
                 prioridad, enabled, ts, ts))
            for k, (ok, entradas, aceptadas, latencia) in enumerate(historial):
                conn.execute(
                    """INSERT INTO source_health(source_id,checked_at,ok,http_status,
                           entries,accepted,latency_ms,error)
                       VALUES(?,?,?,?,?,?,?,?)""",
                    (sid, _iso(ahora - timedelta(hours=k + 1)), ok, 200 if ok else 404,
                     entradas, aceptadas, latencia, None if ok else "HTTP 404"))

        for tid, slug, nombre, categoria, version, crit, exposicion in TECNOLOGIAS:
            conn.execute(
                """INSERT INTO technologies(id,slug,name,category,version_installed,
                       criticality,systems_count,exposure,enabled,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,2,?,1,?,?)""",
                (tid, slug, nombre, categoria, version, crit, exposicion, ts, ts))
            conn.execute(
                """INSERT INTO tech_aliases(technology_id,alias,match_mode,is_exclusion)
                   VALUES(?,?,'word',0)""", (tid, slug))

        # Amenazas: por mes i (0..2): críticas i+1, altas i+2, medias 2i+3, bajas i.
        # Procedencia: todas de la fuente 1; las pares también de la 2; las
        # múltiplos de 3 de la 4 (caída); las múltiplos de 5 de la 7 (desactivada).
        # Correlaciones: críticas → Windows Server (la primera de septiembre
        # «afectada»); altas → Cisco; algunas medias → PostgreSQL (no afectada)
        # y la tecnología hostil.
        tid = 0
        for i, mes in enumerate(MESES):
            fecha = _iso(datetime(2026, 7 + i, 1, 12, 0, tzinfo=timezone.utc))
            plan = ([("Critical", 9.8)] * (i + 1) + [("High", 7.5)] * (i + 2)
                    + [("Medium", 5.0)] * (2 * i + 3) + [("Low", 3.1)] * i)
            for j, (sev, cvss) in enumerate(plan):
                tid += 1
                conn.execute(
                    """INSERT INTO threats(id,fingerprint,cve,title_en,title_es,severity,
                           severity_source,cvss_score,in_kev,first_seen_at,last_seen_at,
                           month,relevance)
                       VALUES(?,?,?,?,?,?,'nvd',?,0,?,?,?,?)""",
                    (tid, f"fp-{tid}", f"CVE-2026-{tid:04d}", f"Threat {tid}",
                     f"Amenaza {tid}", sev, cvss, fecha, fecha, mes, 50 + tid))
                fuentes_de = [1] + ([2] if tid % 2 == 0 else []) \
                    + ([4] if tid % 3 == 0 else []) + ([7] if tid % 5 == 0 else [])
                for sid in fuentes_de:
                    conn.execute(
                        "INSERT INTO threat_sources(threat_id,source_id,url,seen_at) "
                        "VALUES(?,?,?,?)", (tid, sid, f"https://x.invalid/{sid}/{tid}", fecha))
                enlace = None
                if sev == "Critical":
                    enlace = (1, "affected" if (mes == "2026-09" and j == 0) else "unknown")
                elif sev == "High":
                    enlace = (2, "unknown")
                elif sev == "Medium" and j % 4 == 0:
                    enlace = (4, "not_affected")
                elif sev == "Medium" and j % 4 == 1:
                    enlace = (3, "unknown")
                if enlace:
                    conn.execute(
                        """INSERT INTO threat_technologies(threat_id,technology_id,
                               matched_alias,confidence,version_verdict)
                           VALUES(?,?,?,1.0,?)""", (tid, enlace[0], "alias", enlace[1]))


class _Base(unittest.TestCase):
    """Infraestructura común: base temporal bajo data/, aplicación en modo prueba
    y las cuatro páginas ya descargadas con sesión de administrador."""

    sembrar = True

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "fuentes_inventario.db")
        db.init_db(cls.ruta)
        if cls.sembrar:
            _sembrar(cls.ruta)
        else:
            from webui import auth as _auth
            with db.session(cls.ruta) as conn:
                _auth.crear_usuario(conn, USUARIO, CLAVE, rol="admin", actor="test")
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)
        cls.conn = db.connect(cls.ruta)
        cls.cli = cls._sesion(USUARIO, CLAVE)
        cls.paginas = {}
        for ruta in ("/fuentes/", "/fuentes/1", "/fuentes/4", "/tecnologias/",
                     "/tecnologias/1", "/tecnologias/3"):
            resp = cls.cli.get(ruta)
            cls.paginas[ruta] = (resp.status_code, resp.data.decode("utf-8", "replace"))

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()
        cls.dir.cleanup()

    @classmethod
    def _sesion(cls, usuario: str, clave: str):
        cli = cls.app.test_client()
        cli.post("/login", data={"usuario": usuario, "password": clave})
        return cli

    def _html(self, ruta: str) -> str:
        estado, html = self.paginas[ruta]
        self.assertEqual(estado, 200, ruta)
        return html

    def _leyenda(self, nombre: str, dentro: str) -> str:
        """Valor <b>…</b> que sigue a un nombre en una leyenda; '' si no está."""
        m = re.search(re.escape(nombre) + r" <b>([^<]+)</b>", dentro)
        return m.group(1) if m else ""

    def _figura(self, html: str, tipo: str, indice: int = 0) -> str:
        figuras = re.findall(r'<figure class="grafico-envoltorio ' + re.escape(tipo) + r'">.*?</figure>',
                             html, re.S)
        self.assertGreater(len(figuras), indice, f"no hay figura {tipo} nº {indice}")
        return figuras[indice]

    def _centro_dona(self, dona: str) -> str:
        m = re.search(r'<text class="dona-centro" [^>]*>([^<]+)</text>', dona)
        self.assertIsNotNone(m, "la dona no lleva valor central")
        return m.group(1)

    def _comprobar_csp(self, html: str, ruta: str) -> None:
        self.assertIsNone(RE_STYLE.search(html), f"hay un atributo style= en {ruta}")
        self.assertIsNone(RE_ON.search(html), f"hay un manejador on*= en {ruta}")
        self.assertIsNone(RE_SCRIPT_INLINE.search(html), f"hay un <script> en línea en {ruta}")
        valores = {v for _, v in RE_FILL_STROKE.findall(html)}
        self.assertTrue(valores <= {"none", "currentColor", "transparent"},
                        f"colores literales en atributos SVG de {ruta}: {valores}")
        externos = [u for u in re.findall(r'(?:src|href)="([^"]+)"', html)
                    if re.match(r"^(https?:)?//", u, re.I)]
        self.assertEqual(externos, [], f"recursos externos en {ruta}: {externos}")


# ==========================================================================
# Comunes a las cuatro páginas
# ==========================================================================
class TestComunes(_Base):

    def test_responden_200_con_sesion(self):
        for ruta, (estado, _) in self.paginas.items():
            self.assertEqual(estado, 200, ruta)

    def test_sin_sesion_redirigen_al_login(self):
        for ruta in ("/fuentes/", "/fuentes/1", "/tecnologias/", "/tecnologias/1"):
            resp = self.app.test_client().get(ruta)
            self.assertIn(resp.status_code, (302, 303), ruta)
            self.assertIn("/login", resp.headers.get("Location", ""))

    def test_csp_estricta_en_todas(self):
        for ruta, (_, html) in self.paginas.items():
            with self.subTest(ruta=ruta):
                self._comprobar_csp(html, ruta)

    def test_accesibilidad_de_los_svg(self):
        for ruta, (_, html) in self.paginas.items():
            for svg in re.findall(r"<svg class=\"grafico\"[^>]*>", html):
                self.assertIn('role="img"', svg, ruta)
                self.assertIn("aria-label=", svg, ruta)

    def test_todo_panel_con_grafico_lleva_h2_y_sub(self):
        for ruta, (_, html) in self.paginas.items():
            cabeceras = re.findall(r'<div class="panel-cabecera">(.*?)</div>\s*<div class="panel-cuerpo">\s*<figure',
                                   html, re.S)
            self.assertGreaterEqual(len(cabeceras), 1, ruta)
            for cab in cabeceras:
                self.assertIn("<h2>", cab, ruta)
                self.assertIn('class="sub"', cab, ruta)

    def test_nombres_de_la_base_llegan_escapados(self):
        for ruta in ("/fuentes/", "/fuentes/4", "/tecnologias/", "/tecnologias/3"):
            html = self._html(ruta)
            self.assertNotIn("<script>alert(1)</script>", html, ruta)
            self.assertNotIn('<script>alert("f")</script>', html, ruta)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", self._html("/tecnologias/"))
        self.assertIn("Fuente &lt;script&gt;alert(&#34;f&#34;)", self._html("/fuentes/"))

    def test_sin_valores_crudos_en_ingles_en_insignias(self):
        for ruta in ("/fuentes/", "/tecnologias/", "/tecnologias/1", "/fuentes/1"):
            html = self._html(ruta)
            for crudo in ("critical", "high", "medium", "low", "vendor", "news", "government"):
                self.assertNotRegex(html, r'<span class="insignia[^"]*">\s*' + crudo + r"\s*</span>",
                                    f"insignia con «{crudo}» sin traducir en {ruta}")

    def test_lector_solo_lectura_ve_las_paginas_sin_acciones_de_administrador(self):
        """Adaptado el 2026-09-08: Fuentes pasa a administración a petición del usuario
        («debe ir en administración para que no todos los roles lo vean»), así que el
        lector recibe 403 en /fuentes/ y en la ficha; sigue viendo Inventario sin
        acciones de administrador."""
        cli = self._sesion(LECTOR, CLAVE_LECTOR)
        for ruta in ("/fuentes/", "/fuentes/1"):
            resp = cli.get(ruta)
            self.assertEqual(resp.status_code, 403, ruta)
            # El 403 se reescribió el 2026-09-15: sigue siendo genérico, pero no culpa a nadie.
            self.assertIn("Esta página no está incluida en su perfil",
                          resp.data.decode("utf-8", "replace"))
        for ruta in ("/tecnologias/", "/tecnologias/1"):
            resp = cli.get(ruta)
            self.assertEqual(resp.status_code, 200, ruta)
            html = resp.data.decode("utf-8", "replace")
            self.assertNotIn("data-confirm=", html, ruta)
            self.assertIn('<svg class="grafico"', html, ruta)

    def setUp(self):
        self.html = self._html("/fuentes/")

    def test_graficos_presentes(self):
        self.assertIn("grafico-dona", self.html)
        self.assertIn("grafico-barras-horizontales", self.html)
        self.assertIn("grafico-chispa", self.html)
        self.assertIn("Estado de las fuentes activas", self.html)
        self.assertIn("Fuentes que más aportan", self.html)
        self.assertIn("Últimas comprobaciones", self.html)

    def test_dona_de_estado_solo_cuenta_activas(self):
        salud = {s["slug"]: s["estado"] for s in
                 __import__("threatintel.health", fromlist=["x"]).resumen_fuentes(self.conn, ventana=15)}
        activas = [f for f in FUENTES if f[6]]
        esperado = {"ok": 0, "degradada": 0, "caida": 0, "sin_datos": 0}
        for f in activas:
            esperado[salud[f[1]]] += 1
        self.assertEqual(esperado, {"ok": 4, "degradada": 1, "caida": 1, "sin_datos": 1})
        dona = self._figura(self.html, "grafico-dona", 0)
        self.assertEqual(self._leyenda("Operativas", dona), "4")
        self.assertEqual(self._leyenda("Degradadas", dona), "1")
        self.assertEqual(self._leyenda("Caídas", dona), "1")
        self.assertEqual(self._leyenda("Sin comprobar", dona), "1")
        self.assertEqual(self._centro_dona(dona), fmt(len(activas)))
        self.assertIn(">activas</text>", dona)
        # las desactivadas van en el texto, no en la dona; con una sola, en singular
        self.assertNotIn("Desactivadas <b>", dona)
        self.assertIn("La fuente desactivada no entra en el gráfico", self.html)
        self.assertNotIn("Las 1 desactivadas", self.html)
        # las métricas superiores dicen lo mismo
        self.assertIn('<div class="valor">7</div>', self.html)
        self.assertRegex(self.html, r'<div class="valor">4</div>\s*<div class="etiqueta">Operativas</div>')

    def test_sin_anglicismo_feed_en_texto_visible(self):
        # «canales RSS/Atom», no «feeds»; el tipo de fuente es «Canal RSS/Atom»
        self.assertIn("canales RSS/Atom", self.html)
        self.assertIn('<option value="rss">Canal RSS/Atom</option>', self.html)
        self.assertNotIn("Feed RSS", self.html)
        self.assertNotRegex(self.html, r"\bfeeds\b")
        self.assertNotRegex(self.html, r"del feed")

    def test_barras_de_aportacion_coinciden_con_threat_sources(self):
        # Adaptado el 2026-09-15 (auditoría de tableros, punto 9): la columna «Amenazas»,
        # el pie del catálogo y este gráfico cuentan las mismas amenazas que Amenazas y
        # Tendencias, es decir sin las severidades que la organización no reporta. Antes
        # esta página decía 7.514 en producción y las otras dos 7.284.
        conteo = {r[0]: r[1] for r in self.conn.execute(
            """SELECT ts.source_id, COUNT(DISTINCT ts.threat_id)
                 FROM threat_sources ts JOIN threats t ON t.id = ts.threat_id
                WHERE (t.severity IS NULL OR t.severity <> 'Low')
                GROUP BY ts.source_id""")}
        fig = self._figura(self.html, "grafico-barras-horizontales", 0)
        # cada barra lleva <title> «Fuente · Categoría: N» con categoría en español
        # (un único segmento es el 100 % de su fila: graficos.py no repite el porcentaje)
        self.assertIn(f"Fuente correcta · Fabricante: {fmt(conteo[1])}</title>", fig)
        self.assertIn(f"Otra fuente correcta · Noticias: {fmt(conteo[2])}", fig)
        self.assertIn(f"Blog: {fmt(conteo[4])}", fig)
        # enlace a la ficha dentro del SVG y nota de la fuente desactivada
        self.assertIn('<a href="/fuentes/1">', fig)
        self.assertIn('<tspan class="nota"> · desactivada</tspan>', fig)
        # leyenda de categorías con nombre en español y color cat-N estable
        self.assertIn('serie-cat-6"></span>Fabricante', fig)
        self.assertIn('serie-cat-5"></span>Noticias', fig)
        self.assertIn('serie-cat-1"></span>Blog', fig)
        self.assertEqual(self._leyenda("Fabricante", fig), fmt(conteo[1]))
        # la columna «Amenazas» del catálogo muestra las mismas cifras
        for sid, n in conteo.items():
            self.assertIn(f'<td class="num">{fmt(n)}</td>', self.html, f"fuente {sid}")
        # el mayor primero
        self.assertLess(fig.find("Fuente correcta"), fig.find("Otra fuente correcta"))

    def test_pie_de_amenazas_cuenta_distintas_no_la_suma(self):
        # Mismo criterio que la columna y que el gráfico (2026-09-15): sin las severidades
        # que no se reportan.
        distintas = self.conn.execute(
            """SELECT COUNT(DISTINCT ts.threat_id) FROM threat_sources ts
                 JOIN threats t ON t.id = ts.threat_id
                WHERE (t.severity IS NULL OR t.severity <> 'Low')""").fetchone()[0]
        suma = sum(r[0] for r in self.conn.execute(
            """SELECT COUNT(DISTINCT ts.threat_id) FROM threat_sources ts
                 JOIN threats t ON t.id = ts.threat_id
                WHERE (t.severity IS NULL OR t.severity <> 'Low')
                GROUP BY ts.source_id"""))
        self.assertGreater(suma, distintas, "el escenario debe tener amenazas citadas por varias fuentes")
        tfoot = re.search(r"<tfoot>.*?</tfoot>", self.html, re.S).group(0)
        self.assertIn(f">{fmt(distintas)} distintas</td>", tfoot)
        self.assertNotIn(f">{fmt(suma)}<", tfoot)
        self.assertNotIn(f">{fmt(suma)} ", tfoot)
        self.assertEqual(vista_fuentes._amenazas_distintas(self.conn), distintas)

    def test_catalogo_compacto_estado_con_fallos_y_error(self):
        # las columnas «Fallos seguidos» y «Último error» ya no existen: van en Estado
        self.assertNotIn("Fallos seguidos</th>", self.html)
        self.assertNotIn("Último error</th>", self.html)
        self.assertEqual(len(re.findall(r"<th[ >]", self.html.split("<tbody>")[0].split("<thead>")[-1])), 8)
        fila_caida = re.search(r'<tr id="s-caida">.*?</tr>', self.html, re.S).group(0)
        self.assertRegex(fila_caida, r"</span>Caída\s*·\s*<span class=\"txt-critico-b\"[^>]*>3 fallos seguidos</span>")
        self.assertIn('<div class="pequeno mono txt-critico" title="Último error: HTTP 404">HTTP 404</div>', fila_caida)
        fila_degradada = re.search(r'<tr id="s-degradada">.*?</tr>', self.html, re.S).group(0)
        self.assertIn(">1 fallo</span>", fila_degradada)
        self.assertNotIn("1 fallo seguido", fila_degradada)
        fila_ok = re.search(r'<tr id="s-ok">.*?</tr>', self.html, re.S).group(0)
        self.assertNotIn("fallo", fila_ok)
        self.assertNotIn("txt-critico", fila_ok)
        # la URL se recorta a 40 caracteres y la completa va en title
        self.assertIn('title="https://x.invalid/s-ok">https://x.invalid/s-ok</div>', fila_ok)
        # «100 %» no se parte: celda nowrap y espacio indivisible (también en el pie)
        self.assertIn('<td class="num nowrap">\n              100&nbsp;%', fila_ok)
        self.assertNotRegex(self.html, r"\d %<")
        # cada fila lleva sus acciones al final
        self.assertEqual(self.html.count('<td class="acciones nowrap">'), len(FUENTES))

    def test_chispa_con_una_sola_comprobacion_se_sustituye_por_texto(self):
        fila = re.search(r'<tr id="s-una">.*?</tr>', self.html, re.S).group(0)
        self.assertNotIn("grafico-chispa", fila)
        self.assertIn('<span class="pequeno suave nowrap">1 comprobación · 4 aceptadas</span>', fila)
        self.assertIn("</span>Operativa", fila)
        self.assertIn("100&nbsp;%", fila)

    def test_chispa_por_fuente_con_ventana_de_15(self):
        # seis fuentes dibujan chispa: todas menos «sin comprobar» y la de una sola comprobación
        self.assertEqual(self.html.count("grafico-chispa"), 6)
        # la fuente 1 tiene 20 comprobaciones: la chispa solo dibuja 15
        fila = re.search(r'<tr id="s-ok">.*?</tr>', self.html, re.S).group(0)
        self.assertIn("Serie de 15 valores", fila)
        # aceptadas de las 15 últimas en orden ascendente: k=14..0 → k % 3 → último 0, máximo 2
        self.assertIn("último 0, máximo 2", fila)
        self.assertIn('viewBox="0 0 90 24"', fila)
        self.assertIn("linea-exito", fila)          # color según el estado (operativa)
        fila_caida = re.search(r'<tr id="s-caida">.*?</tr>', self.html, re.S).group(0)
        self.assertIn("linea-critico", fila_caida)  # caída → crítico
        fila_nueva = re.search(r'<tr id="s-nueva">.*?</tr>', self.html, re.S).group(0)
        self.assertNotIn("grafico-chispa", fila_nueva)
        self.assertIn("Sin comprobar", fila_nueva)

    def test_historial_reciente_una_consulta_con_ventana(self):
        historial = vista_fuentes._historial_reciente(self.conn, 15)
        self.assertEqual(len(historial[1]), 15)
        self.assertEqual(len(historial[2]), 3)
        self.assertNotIn(6, historial)
        fechas = [h["checked_at"] for h in historial[1]]
        self.assertEqual(fechas, sorted(fechas), "orden cronológico ascendente")
        # las 15 conservadas son las MÁS recientes: la más antigua descartada no está
        todas = [r[0] for r in self.conn.execute(
            "SELECT checked_at FROM source_health WHERE source_id=1 ORDER BY checked_at")]
        self.assertEqual(fechas, todas[-15:])

    def test_tabla_en_espanol_y_con_acciones(self):
        self.assertIn('serie-cat-6"></span> Fabricante</span>', self.html)
        self.assertIn("Organismo oficial", self.html)
        self.assertIn("Base de datos", self.html)
        self.assertIn(">Crítica</span>", self.html)      # prioridad de NVD API
        self.assertIn(">Alta</span>", self.html)
        self.assertNotIn(">vendor<", self.html)
        self.assertNotIn(">news<", self.html)
        self.assertEqual(self.html.count(">Probar</button>"), len(FUENTES))
        self.assertEqual(self.html.count("Desactivar\n"), 7)
        self.assertEqual(self.html.count("Activar\n"), 1)
        self.assertIn("Probar todas las activas", self.html)
        self.assertIn("Añadir fuente", self.html)
        self.assertIn('data-toggle="form-nueva"', self.html)
        self.assertIn("<tfoot>", self.html)
        self.assertIn("8 fuentes", self.html)
        # opciones del formulario en español, valores intactos
        self.assertIn('<option value="government">Organismo oficial</option>', self.html)
        self.assertIn('<option value="nvd_api">API de NVD</option>', self.html)
        # estados en español
        self.assertIn("</span>Caída", self.html)
        self.assertNotIn("Caida", self.html)
        self.assertIn("</span>Operativa", self.html)
        self.assertIn("</span>Degradada", self.html)
        self.assertIn(">Desactivada", self.html)

    def test_aviso_de_caidas(self):
        self.assertIn("1 fuente caída.", self.html)
        self.assertIn('role="alert"', self.html)


# ==========================================================================
# Fuentes: detalle
# ==========================================================================
class TestFuenteDetalle(_Base):

    def setUp(self):
        self.html = self._html("/fuentes/1")

    def test_graficos_presentes(self):
        self.assertEqual(self.html.count("grafico-linea-tiempo"), 2)
        self.assertEqual(self.html.count("grafico-progreso"), 1)
        self.assertIn("Tasa de éxito", self.html)
        self.assertIn(">Latencia</h2>", self.html)
        self.assertIn("Entradas recibidas y aceptadas", self.html)

    def test_tasa_de_exito_coincide_con_el_historial(self):
        fig = self._figura(self.html, "grafico-progreso", 0)
        self.assertEqual(self._leyenda("Correctas", fig), "20")
        self.assertEqual(self._leyenda("Con fallo", fig), "0")
        self.assertRegex(self.html, r"20 de 20 comprobaciones correctas\s+\(100 %\)")
        self.assertEqual(self.html.count("insignia ok"), 20)

    def test_lineas_en_orden_cronologico_con_unidad(self):
        lat = self._figura(self.html, "grafico-linea-tiempo", 0)
        # último valor = comprobación más reciente (k=0 → 100 ms); máximo k=19 → 290 ms
        self.assertEqual(self._leyenda("Latencia", lat), "100 ms")
        self.assertIn("Latencia: 290 ms", lat)      # <title> del punto más lento
        self.assertIn(" ms</text>", lat)            # eje Y con unidad
        self.assertIn("Media 195 ms · máxima 290 ms", self.html)
        ent = self._figura(self.html, "grafico-linea-tiempo", 1)
        self.assertEqual(self._leyenda("Entradas recibidas", ent), "5")
        self.assertEqual(self._leyenda("Entradas aceptadas", ent), "0")
        # 20 puntos por serie, etiquetas cortas «dd/mm hh:mm»
        self.assertEqual(ent.count("<circle"), 40)
        self.assertRegex(ent, r'<text class="eje" [^>]*text-anchor="middle">\d{2}/\d{2} \d{2}:\d{2}</text>')
        # el panel a todo el ancho dibuja a 1100 (como el resto de gráficos a todo
        # el ancho) y el de latencia, en dos tercios, a 760: texto de eje parecido
        self.assertIn('viewBox="0 0 1100 ', ent)
        self.assertIn('viewBox="0 0 760 ', lat)

    def test_tasa_de_exito_lleva_los_agregados_de_la_ventana(self):
        panel = re.search(r"<h2>Tasa de éxito</h2>.*?<h2>Latencia</h2>", self.html, re.S).group(0)
        self.assertIn('<dl class="detalle-lista mt-12">', panel)
        self.assertRegex(panel, r"<dt>Comprobaciones</dt>\s*<dd>20 · 20 correctas · 0 con fallo</dd>")
        self.assertRegex(panel, r"<dt>Latencia media</dt>\s*<dd>195 ms</dd>")
        self.assertRegex(panel, r"<dt>Latencia máxima</dt>\s*<dd>290 ms</dd>")
        self.assertRegex(panel, r"<dt>Entradas recibidas</dt>\s*<dd>100</dd>")
        self.assertRegex(panel, r"<dt>Entradas aceptadas</dt>\s*<dd>19 <span class=\"tenue\">\(19 % de las recibidas\)</span></dd>")
        # concordancia en plural con 20 comprobaciones
        self.assertIn("¿Qué parte de las últimas 20 comprobaciones respondió correctamente?", panel)
        self.assertIn("Las últimas 20 comprobaciones, la más reciente primero.", self.html)
        self.assertNotIn("las últimas 60", self.html)   # se habla de las reales, no de la ventana máxima

    def test_concordancia_con_una_sola_comprobacion(self):
        resp = self.cli.get("/fuentes/8")
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode()
        self.assertNotIn("las últimas 1 ", html)
        self.assertNotIn("Las últimas 1 ", html)
        self.assertIn("¿Respondió correctamente la última comprobación?", html)
        self.assertIn("La única comprobación registrada fue correcta", html)
        self.assertIn("(100 %)", html)
        self.assertIn('aria-label="Comprobaciones correctas y con fallo de la última comprobación"', html)
        self.assertIn('aria-label="Latencia en milisegundos de la última comprobación"', html)
        self.assertIn("con el inventario, en la última comprobación.", html)
        self.assertIn("La única comprobación registrada. Los gráficos superiores", html)
        self.assertRegex(html, r"<dt>Comprobaciones</dt>\s*<dd>1 · 1 correcta · 0 con fallo</dd>")
        self.assertIn("Canal RSS/Atom", html)
        # fuente caída sin latencias: los agregados de latencia no inventan un 0
        html4 = self._html("/fuentes/4")
        self.assertRegex(html4, r"<dt>Latencia media</dt>\s*<dd><span class=\"tenue\">sin respuesta</span></dd>")
        self.assertRegex(html4, r"<dt>Comprobaciones</dt>\s*<dd>3 · 0 correctas · 3 con fallo</dd>")

    def test_botones_y_formularios_conservados(self):
        self.assertIn("Probar ahora", self.html)
        self.assertIn(">Desactivar</button>", self.html)
        self.assertIn('action="/fuentes/1/activar"', self.html)
        self.assertIn("Guardar cambios", self.html)
        self.assertIn('formaction="/fuentes/1/borrar"', self.html)
        self.assertIn("Eliminar fuente", self.html)
        self.assertIn("data-confirm=", self.html)
        self.assertIn("Historial de comprobaciones", self.html)
        self.assertIn('<option value="vendor" selected>Fabricante</option>', self.html)
        self.assertIn("Canal RSS/Atom", self.html)
        self.assertNotIn("Feed RSS/Atom", self.html)
        self.assertIn("prioridad alta", self.html)

    def test_fuente_caida_con_latencias_nulas_no_rompe(self):
        html = self._html("/fuentes/4")
        fig = self._figura(html, "grafico-progreso", 0)
        self.assertEqual(self._leyenda("Correctas", fig), "0")
        self.assertEqual(self._leyenda("Con fallo", fig), "3")
        self.assertIn("La fuente falla más de lo que responde", html)
        # sin latencias → estado vacío en el gráfico de latencia, no un SVG roto
        self.assertIn("grafico-vacio", html)
        self.assertIn("Sin datos suficientes", html)
        self.assertEqual(html.count("insignia critical"), 3)
        self.assertIn("Fuente &lt;script&gt;alert(&#34;f&#34;)", html)

    def test_fuente_inexistente_redirige(self):
        resp = self.cli.get("/fuentes/999")
        self.assertIn(resp.status_code, (302, 303))
        self.assertTrue(resp.headers.get("Location", "").endswith("/fuentes/"))


# ==========================================================================
# Inventario: lista
# ==========================================================================
class TestInventarioLista(_Base):

    def setUp(self):
        self.html = self._html("/tecnologias/")

    def test_graficos_presentes(self):
        self.assertIn("grafico-dona", self.html)
        self.assertIn("grafico-barras-apiladas", self.html)
        self.assertIn("grafico-barras-horizontales", self.html)
        self.assertIn("Criticidad del inventario", self.html)
        self.assertIn("Tecnologías con más amenazas", self.html)
        self.assertIn("Cobertura de versiones por categoría", self.html)

    def test_dona_de_criticidad_suma_el_total(self):
        total = self.conn.execute("SELECT COUNT(*) FROM technologies").fetchone()[0]
        conteo = {r[0]: r[1] for r in self.conn.execute(
            "SELECT criticality, COUNT(*) FROM technologies GROUP BY 1")}
        dona = self._figura(self.html, "grafico-dona", 0)
        valores = {n: self._leyenda(n, dona) for n in ("Crítica", "Alta", "Media", "Baja")}
        self.assertEqual(valores, {"Crítica": fmt(conteo["critical"]), "Alta": fmt(conteo["high"]),
                                   "Media": fmt(conteo["medium"]), "Baja": fmt(conteo["low"])})
        self.assertEqual(sum(int(v) for v in valores.values()), total)
        self.assertEqual(self._centro_dona(dona), fmt(total))
        self.assertIn(">tecnologías</text>", dona)
        self.assertIn(f'<div class="valor">{fmt(total)}</div>', self.html)

    def test_barras_apiladas_por_categoria_con_agrupado(self):
        con = self.conn.execute("SELECT COUNT(*) FROM technologies "
                                "WHERE version_installed IS NOT NULL AND version_installed<>''").fetchone()[0]
        total = self.conn.execute("SELECT COUNT(*) FROM technologies").fetchone()[0]
        fig = self._figura(self.html, "grafico-barras-apiladas", 0)
        self.assertEqual(self._leyenda("Con versión", fig), fmt(con))
        self.assertEqual(self._leyenda("Sin versión", fig), fmt(total - con))
        # diez categorías > 8: siete visibles + «Otras categorías», todas legibles
        self.assertIn(">Otras 3 categorías</text>", fig)
        self.assertEqual(len(re.findall(r'<text class="eje" [^>]*text-anchor="middle">', fig)), 8)
        self.assertIn(">Sistema operativo</text>", fig)
        self.assertIn("Sistema operativo · Con versión: 2", fig)
        self.assertLess(fig.find(">Sistema operativo</text>"), fig.find(">Otras 3 categorías</text>"))
        self.assertIn("se suman en la barra «Otras 3 categorías»", self.html)
        # la tabla detalla TODAS las categorías con nombres legibles
        for nombre in ("Sistema operativo", "Base de datos", "Red", "Navegador", "Servidor web",
                       "Contenedores", "Criptografía", "Monitorización", "Correo", "Aplicación"):
            self.assertIn(f'<td class="nowrap">{nombre}</td>', self.html, nombre)
        self.assertIn("Total de 10 categorías", self.html)
        self.assertIn("36,4 % con versión", self.html)
        # Adaptado el 2026-09-15 (revisión de claridad): el formulario «Nueva tecnología»
        # ofrece ahora LAS CATEGORÍAS REALES del inventario, así que «sistema-operativo»
        # aparece como VALOR de una opción. Lo que no puede aparecer es como texto
        # visible: eso es lo que esta prueba vigila.
        antes_de_la_tabla = self.html.split("Tecnologías monitorizadas")[0]
        self.assertNotIn(">sistema-operativo<", antes_de_la_tabla)
        self.assertIn('<option value="sistema-operativo">Sistema operativo</option>',
                      antes_de_la_tabla)

    def test_cobertura_cero_en_tenue_no_en_verde(self):
        tabla = re.search(r"<h2>Cobertura de versiones por categoría</h2>.*?</tfoot>", self.html, re.S).group(0)
        # «Red» (Cisco sin versión): 0 con versión en tenue, 1 sin versión en ámbar
        self.assertRegex(tabla, r'<td class="nowrap">Red</td>\s*<td class="num">1</td>\s*'
                                r'<td class="num tenue">0</td>\s*<td class="num txt-medio">1</td>')
        # «Base de datos» (PostgreSQL con versión): 1 con versión en verde, 0 sin versión en tenue
        self.assertRegex(tabla, r'<td class="nowrap">Base de datos</td>\s*<td class="num">1</td>\s*'
                                r'<td class="num txt-exito">1</td>\s*<td class="num tenue">0</td>')
        self.assertNotIn('<td class="num txt-exito">0</td>', tabla)
        self.assertNotIn('<td class="num txt-medio">0</td>', tabla)
        self.assertIn('<td class="num txt-exito">4</td>', tabla)      # total con versión en el pie

    def test_top_tecnologias_con_enlace_y_nota(self):
        fig = self._figura(self.html, "grafico-barras-horizontales", 0)
        criticas = self.conn.execute(
            "SELECT COUNT(*) FROM threat_technologies tt JOIN threats t ON t.id=tt.threat_id "
            "WHERE tt.technology_id=1 AND t.severity='Critical'").fetchone()[0]
        self.assertEqual(criticas, 6)
        self.assertIn(f"Windows Server · Críticas: {fmt(criticas)}", fig)
        self.assertIn('<a href="/tecnologias/1">', fig)
        self.assertIn('<a href="/tecnologias/2">', fig)
        self.assertIn('<tspan class="nota"> · sin versión</tspan>', fig)
        # Windows Server tiene versión: su fila no lleva la nota
        fila_ws = re.search(r'<a href="/tecnologias/1">.*?</text></a>.*?<text class="etiqueta-valor"[^>]*>(.*?)</text>',
                            fig, re.S).group(1)
        self.assertNotIn("sin versión", fila_ws)
        self.assertEqual(self._leyenda("Críticas", fig), f"{fmt(criticas)} amenazas")  # unidad escrita (2026-09-08)
        self.assertNotIn("Medias y bajas", fig)   # medias y bajas van por separado
        # el más afectado primero: Cisco (altas 2+3+4 = 9) antes que Windows (6)
        self.assertLess(fig.find("Cisco IOS XE"), fig.find("Windows Server"))
        # la tabla debajo lleva las mismas cifras en «Amenazas»
        self.assertIn('<td class="num">9</td>', self.html)
        self.assertIn('<td class="num">6</td>', self.html)

    def test_tabla_en_espanol(self):
        self.assertIn(">Crítica</span>", self.html)
        self.assertIn(">Alta</span>", self.html)
        self.assertIn(">Media</span>", self.html)
        self.assertIn(">Baja</span>", self.html)
        self.assertNotIn(">critical</span>", self.html)
        self.assertNotIn(">high</span>", self.html)
        self.assertIn("Red interna", self.html)
        self.assertIn('<span class="txt-critico-b">Internet</span>', self.html)
        self.assertIn("Perimetral (DMZ)", self.html)
        self.assertNotRegex(self.html, r">\s*interna\s*<")
        self.assertNotRegex(self.html, r">\s*dmz\s*<")
        self.assertIn('<td class="pequeno nowrap">Sistema operativo</td>', self.html)
        self.assertIn('<option value="critical">Crítica</option>', self.html)
        self.assertIn('<option value="interna" selected>Red interna</option>', self.html)
        self.assertIn("36,4 % del inventario", self.html)

    def test_acciones_conservadas(self):
        self.assertIn("Importar CSV", self.html)
        self.assertIn('data-toggle="form-importar"', self.html)
        self.assertIn("Añadir tecnología", self.html)
        self.assertIn("Cargar inventario base", self.html)
        self.assertIn("Exportar CSV", self.html)
        self.assertIn('action="/tecnologias/1/version"', self.html)
        self.assertEqual(self.html.count('name="version_installed"'), len(TECNOLOGIAS) + 1)  # +1 del formulario nuevo
        self.assertEqual(self.html.count('title="Eliminar del inventario">Eliminar</button>'), len(TECNOLOGIAS))
        self.assertIn('data-confirm="¿Eliminar Windows Server del inventario? Se perderán 6 correlaciones', self.html)
        self.assertIn('action="/tecnologias/1/borrar"', self.html)

    def test_filtro_sin_version_mantiene_los_graficos_completos(self):
        resp = self.cli.get("/tecnologias/?sin_version=1")
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode()
        self.assertEqual(html.count('title="Eliminar del inventario">Eliminar</button>'), 7)
        dona = self._figura(html, "grafico-dona", 0)
        self.assertEqual(self._centro_dona(dona), "11")
        self.assertIn("7 tecnologías de 11", html)
        self.assertIn("Solo las tecnologías sin versión registrada", html)
        resp = self.cli.get("/tecnologias/?q=nada-que-coincida")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Ningún resultado para «nada-que-coincida»", resp.data.decode())


# ==========================================================================
# Inventario: detalle
# ==========================================================================
class TestTecnologiaDetalle(_Base):

    def setUp(self):
        self.html = self._html("/tecnologias/1")

    def test_dona_de_veredictos(self):
        veredictos = {r[0]: r[1] for r in self.conn.execute(
            "SELECT version_verdict, COUNT(*) FROM threat_technologies WHERE technology_id=1 GROUP BY 1")}
        self.assertEqual(veredictos, {"affected": 1, "unknown": 5})
        dona = self._figura(self.html, "grafico-dona", 0)
        self.assertEqual(self._leyenda("Afectada", dona), "1")
        self.assertEqual(self._leyenda("No afectada", dona), "0")
        self.assertEqual(self._leyenda("Sin determinar", dona), "5")
        self.assertEqual(self._centro_dona(dona), "6")
        self.assertIn("serie-critico", dona)
        self.assertIn("serie-neutro", dona)
        # Adaptado el 2026-09-15: el rótulo decía «Versión afectada» y contaba AMENAZAS,
        # no versiones; con un cero delante se leía al revés de lo que pasaba.
        self.assertRegex(self.html, r'<div class="valor">1</div>\s*<div class="etiqueta">'
                                    r'Amenaza que afecta a la versión instalada</div>')
        self.assertNotIn(">Versión afectada<", self.html)
        self.assertNotIn(">Versión no afectada<", self.html)

    def test_barras_apiladas_por_mes_ascendentes(self):
        fig = self._figura(self.html, "grafico-barras-apiladas", 0)
        for i, mes in enumerate(MESES):
            etiqueta = vista_tec._mes_corto(mes)
            self.assertIn(f"{etiqueta} · Críticas: {fmt(i + 1)}", fig)
            self.assertIn(f">{etiqueta}</text>", fig)
        self.assertLess(fig.find(">julio de 2026</text>"), fig.find(">septiembre de 2026</text>"))
        self.assertEqual(self._leyenda("Críticas", fig), "6")
        self.assertEqual(self._leyenda("Altas", fig), "0")
        # tabla debajo con los mismos meses y un total
        self.assertIn("julio de 2026", self.html)
        self.assertIn("Total de 3 periodos", self.html)
        self.assertIn('href="/amenazas/?tec=windows-server&amp;mes=2026-09"', self.html)

    def test_ficha_alias_y_acciones_conservadas(self):
        self.assertIn("Ficha del inventario", self.html)
        self.assertIn('formaction="/tecnologias/1/borrar"', self.html)
        self.assertIn("Se perderán 6 correlaciones", self.html)
        self.assertRegex(self.html, r">\s*Eliminar\s*</button>")
        self.assertIn(">Quitar</button>", self.html)
        self.assertIn("Añadir alias", self.html)
        self.assertIn("Palabra completa", self.html)
        self.assertIn('<option value="word">Palabra completa</option>', self.html)
        self.assertIn('<option value="high" selected>Alta</option>', self.html)
        self.assertIn('<option value="interna" selected>Red interna</option>', self.html)
        # categoría real con guion («sistema-operativo») no está en la lista del
        # formulario: se añade como opción seleccionada para no perderla al guardar
        self.assertIn('<option value="sistema-operativo" selected>Sistema operativo</option>', self.html)
        self.assertIn("exposición red interna · criticidad alta", self.html)
        self.assertIn("Amenazas asociadas", self.html)
        self.assertIn(">Afectada</span>", self.html)
        self.assertIn(">Sin determinar</span>", self.html)

    def test_tecnologia_sin_amenazas_muestra_estados_vacios(self):
        resp = self.cli.get("/tecnologias/5")      # Google Chrome: sin correlaciones
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode()
        self.assertGreaterEqual(html.count("grafico-vacio"), 2)
        self.assertIn("Sin amenazas asociadas.", html)
        self.assertIn("Sin versión registrada.", html)
        self.assertIn("Sin amenazas correlacionadas todavía", html)

    def test_tecnologia_hostil_escapada(self):
        html = self._html("/tecnologias/3")
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertIn("Perimetral (DMZ)", html)

    def test_tecnologia_inexistente_redirige(self):
        resp = self.cli.get("/tecnologias/999")
        self.assertIn(resp.status_code, (302, 303))
        self.assertTrue(resp.headers.get("Location", "").endswith("/tecnologias/"))


# ==========================================================================
# Base vacía
# ==========================================================================
class TestVacio(_Base):
    sembrar = False

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

    def test_fuentes_vacias_sin_excepciones(self):
        estado, html = self.paginas["/fuentes/"]
        self.assertEqual(estado, 200)
        self.assertIn("No hay fuentes registradas.", html)
        self.assertIn("grafico-vacio", html)
        self.assertIn("No hay fuentes registradas todavía.", html)
        self.assertIn('<div class="valor">0</div>', html)
        self._comprobar_csp(html, "/fuentes/")

    def test_inventario_vacio_sin_excepciones(self):
        estado, html = self.paginas["/tecnologias/"]
        self.assertEqual(estado, 200)
        self.assertIn("El inventario está vacío.", html)
        self.assertIn("grafico-vacio", html)
        self.assertIn("no hay categorías que mostrar", html)
        self.assertIn("0,0 % del inventario", html)
        self._comprobar_csp(html, "/tecnologias/")

    def test_detalles_inexistentes_redirigen(self):
        for ruta in ("/fuentes/1", "/tecnologias/1"):
            self.assertIn(self.paginas[ruta][0], (302, 303), ruta)


# ==========================================================================
# Funciones puras de las vistas
# ==========================================================================
class TestFuncionesFuentes(unittest.TestCase):

    def test_valores_chispa(self):
        self.assertEqual(vista_fuentes._valores_chispa([]), [])
        self.assertEqual(vista_fuentes._valores_chispa(
            [{"ok": 1, "accepted": 3}, {"ok": 0, "accepted": 0}, {"ok": 1, "accepted": None}]), [3, 0, 0])
        # sin dato de aceptadas en ninguna → 1 = correcta, 0 = fallo
        self.assertEqual(vista_fuentes._valores_chispa(
            [{"ok": 1, "accepted": None}, {"ok": 0, "accepted": None}, {"ok": 1}]), [1, 0, 1])

    def test_texto_chispa(self):
        self.assertEqual(vista_fuentes.MINIMO_PUNTOS_CHISPA, 2)
        self.assertEqual(vista_fuentes._texto_chispa([]), "")
        self.assertEqual(vista_fuentes._texto_chispa([{"ok": 1, "accepted": 4}]), "1 comprobación · 4 aceptadas")
        self.assertEqual(vista_fuentes._texto_chispa([{"ok": 1, "accepted": 1}]), "1 comprobación · 1 aceptada")
        self.assertEqual(vista_fuentes._texto_chispa([{"ok": 1, "accepted": 0}]), "1 comprobación · 0 aceptadas")
        # sin dato de aceptadas se dice si fue correcta o falló
        self.assertEqual(vista_fuentes._texto_chispa([{"ok": 1, "accepted": None}]), "1 comprobación · correcta")
        self.assertEqual(vista_fuentes._texto_chispa([{"ok": 0}]), "1 comprobación · con fallo")
        # con varias, el último registro (el más reciente) da el detalle
        self.assertEqual(vista_fuentes._texto_chispa([{"ok": 1, "accepted": 3}, {"ok": 1, "accepted": 1200}]),
                         "2 comprobaciones · 1.200 aceptadas")

    def test_resumen_catalogo(self):
        filas = [
            {"enabled": 1, "kind": "rss", "salud": {"estado": "ok"}, "amenazas": 10},
            {"enabled": 1, "kind": "nvd_api", "salud": {"estado": "ok"}},
            {"enabled": 1, "kind": "rss", "salud": {"estado": "caida"}},
            {"enabled": 1, "kind": "rss", "salud": {"estado": "degradada"}},
            {"enabled": 1, "kind": "rss", "salud": {}},
            {"enabled": 0, "kind": "rss", "salud": {"estado": "desactivada"}, "amenazas": 2},
        ]
        r = vista_fuentes._resumen_catalogo(filas)
        self.assertEqual((r["total"], r["activas"], r["operativas"], r["degradadas"], r["caidas"],
                          r["sin_comprobar"], r["desactivadas"], r["feeds"], r["apis"], r["amenazas"]),
                         (6, 5, 2, 1, 1, 1, 1, 4, 1, 12))
        self.assertEqual(sum(p["valor"] for p in vista_fuentes._porciones_estado(r)), r["activas"])
        self.assertEqual(vista_fuentes._resumen_catalogo([])["activas"], 0)

    def test_items_top_fuentes_color_estable_por_categoria(self):
        items = vista_fuentes._items_top_fuentes([
            {"name": "A", "category": "vendor", "amenazas": 5, "href": "/fuentes/1", "enabled": 1},
            {"name": "B", "category": "rara", "amenazas": 2, "href": "/fuentes/2", "enabled": 0},
        ])
        self.assertEqual(items[0]["valores"], [("cat-6", 5, "Fabricante")])
        self.assertEqual(items[1]["valores"][0][0], "neutro")
        self.assertEqual(items[1]["nota"], "desactivada")
        self.assertEqual(items[0]["nota"], "")
        self.assertEqual(vista_fuentes._items_top_fuentes([]), [])

    def test_etiqueta_hora_y_series_detalle(self):
        self.assertRegex(vista_fuentes._etiqueta_hora("2026-09-03T13:50:24Z"), r"^\d{2}/\d{2} \d{2}:\d{2}$")
        self.assertEqual(vista_fuentes._etiqueta_hora(None), "—")
        historial = [
            {"checked_at": "2026-09-01T10:00:00Z", "ok": 1, "entries": 5, "accepted": 1, "latency_ms": 100},
            {"checked_at": "2026-09-02T10:00:00Z", "ok": 0, "entries": 0, "accepted": 0, "latency_ms": None},
            {"checked_at": "2026-09-03T10:00:00Z", "ok": 1, "entries": 7, "accepted": 2, "latency_ms": 300},
        ]
        s = vista_fuentes._series_detalle(historial)
        self.assertEqual(len(s["etiquetas"]), 3)
        self.assertEqual(s["latencia"][0]["valores"], [100, None, 300])
        self.assertEqual(s["entradas"][1]["valores"], [1, 0, 2])
        self.assertEqual((s["correctas"], s["fallos"], s["tasa"]), (2, 1, 66.7))
        self.assertEqual((s["latencia_media"], s["latencia_maxima"]), (200, 300))
        self.assertEqual((s["entradas_total"], s["aceptadas_total"]), (12, 3))
        vacio = vista_fuentes._series_detalle([])
        self.assertEqual((vacio["total"], vacio["tasa"], vacio["latencia_media"]), (0, None, None))

    def test_etiquetar(self):
        f = vista_fuentes._etiquetar({"category": "government", "priority": "critical",
                                      "kind": "kev_json", "enabled": 1, "salud": {"estado": "caida"}})
        self.assertEqual((f["categoria_es"], f["categoria_clave"], f["prioridad_es"], f["tipo_es"],
                          f["estado_clave"]), ("Organismo oficial", "cat-4", "Crítica", "Catálogo KEV (JSON)", "critico"))
        self.assertEqual(vista_fuentes._etiquetar({"enabled": 0})["estado_clave"], "neutro")
        self.assertEqual(vista_fuentes._etiquetar({"enabled": 1, "salud": {}})["estado_clave"], "neutro")


class TestFuncionesInventario(unittest.TestCase):

    def test_categoria_es(self):
        self.assertEqual(vista_tec.categoria_es("base-de-datos"), "Base de datos")
        self.assertEqual(vista_tec.categoria_es("sistema_operativo"), "Sistema operativo")
        self.assertEqual(vista_tec.categoria_es("gestion-de-flotas"), "Gestion de flotas")
        self.assertEqual(vista_tec.categoria_es(""), "—")
        self.assertEqual(vista_tec.categoria_es(None), "—")

    def test_etiquetar(self):
        t = vista_tec._etiquetar({"category": "red", "criticality": "critical", "exposure": "internet"})
        self.assertEqual((t["categoria_es"], t["criticidad_es"], t["exposicion_es"]), ("Red", "Crítica", "Internet"))
        t = vista_tec._etiquetar({"category": "x", "criticality": "low", "exposure": "internal"})
        self.assertEqual((t["criticidad_es"], t["exposicion_es"]), ("Baja", "Red interna"))
        self.assertEqual(vista_tec._etiquetar({"exposure": "local"})["exposicion_es"], "Local")

    def test_mes_corto(self):
        # Adaptado el 2026-09-15 (revisión de claridad): el eje decía «marzo 2026» y la
        # tabla de debajo «marzo de 2026» para el mismo mes.
        self.assertEqual(vista_tec._mes_corto("2026-09"), "septiembre de 2026")
        self.assertEqual(vista_tec._mes_corto("2026-09", corto=True), "septiembre\nde 2026")
        self.assertEqual(vista_tec._mes_corto(None), "—")
        self.assertEqual(vista_tec._mes_corto("raro"), "raro")

    def test_categorias_apiladas_agrupa_por_encima_de_ocho(self):
        filas = [{"nombre": f"Categoría {i:02d}", "total": 20 - i, "con_version": 1, "sin_version": 19 - i}
                 for i in range(10)]
        r = vista_tec._categorias_apiladas(filas, 8)
        self.assertEqual(len(r["categorias"]), 8)
        self.assertEqual(r["categorias"][-1], "Otras 3 categorías")
        self.assertEqual(r["agrupadas"], 3)
        self.assertEqual(r["series"][0]["valores"][-1], 3)              # con versión de las 3 agrupadas
        self.assertEqual(r["series"][1]["valores"][-1], 12 + 11 + 10)   # sin versión de las 3 agrupadas
        self.assertEqual(sum(r["series"][0]["valores"]), 10)
        self.assertEqual(sum(r["series"][1]["valores"]), sum(f["sin_version"] for f in filas))
        pocas = vista_tec._categorias_apiladas(filas[:5], 8)
        self.assertEqual((len(pocas["categorias"]), pocas["agrupadas"]), (5, 0))
        self.assertEqual(vista_tec._categorias_apiladas([], 8)["categorias"], [])

    def test_porciones(self):
        crit = vista_tec._porciones_criticidad({"critical": 2, "high": 32, "medium": 29, "low": 9, "otras": 0})
        self.assertEqual([p["nombre"] for p in crit], ["Crítica", "Alta", "Media", "Baja"])
        self.assertEqual([p["clave"] for p in crit], ["critico", "alto", "medio", "bajo"])
        self.assertEqual(sum(p["valor"] for p in crit), 72)
        self.assertEqual(len(vista_tec._porciones_criticidad({"otras": 1})), 5)
        ver = vista_tec._porciones_veredictos({"affected": 1, "unknown": 7444, "raro": 2})
        self.assertEqual([(p["nombre"], p["valor"]) for p in ver],
                         [("Afectada", 1), ("No afectada", 0), ("Sin determinar", 7446)])
        self.assertEqual([p["clave"] for p in ver], ["critico", "exito", "neutro"])

    def test_items_top_y_series_evolucion(self):
        items = vista_tec._items_top([{"name": "A", "amenazas": 10, "criticas": 2, "altas": 3,
                                       "version_installed": None, "href": "/tecnologias/1"}])
        # Regla interna (2026-09-08): por omisión solo tres segmentos; las bajas, solo si se pide.
        self.assertEqual(items[0]["valores"], [("critico", 2), ("alto", 3), ("medio", 0)])
        con_bajas = vista_tec._items_top([{"name": "A", "amenazas": 10, "criticas": 2, "altas": 3,
                                           "medias": 0, "version_installed": None}], sin_bajas=False)
        self.assertEqual(con_bajas[0]["valores"], [("critico", 2), ("alto", 3), ("medio", 0), ("bajo", 5)])
        self.assertEqual(items[0]["nota"], "sin versión")
        evo = [{"month": f"2026-{m:02d}", "total": 3, "criticas": 1, "altas": 1, "medias": 1, "bajas": 0}
               for m in range(1, 10)]
        s = vista_tec._series_evolucion(evo)
        self.assertEqual(s["categorias"][0], "enero\nde 2026")   # > 8 meses → mes y año completo en dos líneas
        self.assertEqual(vista_tec._series_evolucion(evo[:3])["categorias"],
                         ["enero de 2026", "febrero de 2026", "marzo de 2026"])
        self.assertEqual([x["clave"] for x in s["series"]], ["critico", "alto", "medio"])
        self.assertEqual([x["clave"] for x in vista_tec._series_evolucion(evo, sin_bajas=False)["series"]],
                         ["critico", "alto", "medio", "bajo"])


if __name__ == "__main__":
    unittest.main()

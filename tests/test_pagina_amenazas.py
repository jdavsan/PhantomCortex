#!/usr/bin/env python3
"""Pruebas de renderizado de la consulta de amenazas (/amenazas/) y de la
ficha de amenaza (/amenazas/<id>) rediseñadas el 2026-09-03.

Cubren la sección 6 «Amenazas» de docs/DISENO_INTERFAZ_2026-09-03.md:

* la ficha responde 200 con tres medidores (CVSS, EPSS, relevancia) y el
  diagrama de hitos en modo compacto;
* una amenaza sin CVSS ni EPSS muestra «—» en los medidores sin excepción;
* los textos procedentes de la base de datos (título, tecnologías, fuentes)
  llegan escapados, y las URL de terceros pasan por ``url_segura``;
* ambas páginas cumplen la CSP estricta (sin ``style=``, sin ``on*=``, sin
  ``<script>`` en línea, sin colores literales en ``fill``/``stroke``);
* la lista responde 200, conserva filtros, exportación CSV, paginación, CVE
  recurrentes y glosario, con etiquetas y números en español;
* las fechas civiles (plazo CISA KEV a medianoche UTC) no se desplazan un día y
  las fechas RFC 2822 de los RSS (published_at) se muestran; el EPSS no se
  atribuye a NVD; ninguna insignia queda en inglés (revisión visual 2026-09-04).

La base de datos es temporal bajo ``data/`` (mismo patrón que
tests/test_pagina_panel.py). Nunca se toca ``data/threat_intel.db``.

Ejecución:
    sudo -n -u si .venv/bin/python -m unittest tests.test_pagina_amenazas
"""
from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threatintel import db  # noqa: E402
from threatintel.paths import BASE_DIR  # noqa: E402

USUARIO, CLAVE = "pruebas", "PruebaSegura#2026"
LECTOR, CLAVE_LECTOR = "lector", "LectorSeguro#2026"
HOSTIL_TITULO = 'Fallo <script>alert("t")</script> en Moodle'
HOSTIL_TEC = "Tec <script>alert(1)</script> & Cía"
HOSTIL_FUENTE = 'Fuente <script>alert("f")</script>'
CVE_RECURRENTE = "CVE-2026-31431"
URL_JS = "javascript:alert(document.cookie)"
URL_OK = "https://ejemplo.invalid/aviso/31431"
# Resumen con HTML crudo tal como lo entregan algunos feeds (caso real: id 5002).
RESUMEN_HTML = ('<p><span style="font-size: undefined;">Wrap-up with <b>shells</b> '
                '&amp; fixes</span></p><script>alert("s")</script>Ray Dashboard Logs API '
                'Path Traversal (version < 4.3)<span style="font-size: undef')   # truncado

RE_STYLE = re.compile(r"\sstyle\s*=", re.I)
RE_ON = re.compile(r"\son[a-z]+\s*=", re.I)
RE_SCRIPT_INLINE = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>", re.I)
RE_FILL_STROKE = re.compile(r'\b(fill|stroke)="([^"]*)"')

# Identificadores fijos de las amenazas de la ficha.
ID_COMPLETA = 1      # todos los campos: medidores con valor, KEV, alertada
ID_MINIMA = 2        # sin CVE, sin CVSS, sin EPSS, sin alertar, sin inventario
ID_REPETIDA = 3      # mismo CVE que la completa, otro periodo
ID_KEV_REAL = 4      # réplica de la amenaza real 2529: plazo KEV «T00:00:00Z» y RSS RFC 2822
from webui.vistas.amenazas import POR_PAGINA   # el usuario fijó 20 el 2026-09-07

N_RELLENO = 60       # amenazas extra, siempre por encima del tamaño de página


def _sembrar(ruta: str) -> None:
    from webui import auth as _auth
    ts = "2026-09-01T08:00:00Z"
    with db.session(ruta) as conn:
        _auth.crear_usuario(conn, USUARIO, CLAVE, rol="admin", actor="test")
        _auth.crear_usuario(conn, LECTOR, CLAVE_LECTOR, rol="ciberseguridad", actor="test")

        # --- fuentes ---
        for i, (slug, nombre) in enumerate([("s-ok", "Aviso del fabricante"),
                                            ("s-hostil", HOSTIL_FUENTE)], start=1):
            conn.execute(
                """INSERT INTO sources(id,slug,name,url,kind,category,priority,
                       enabled,timeout_s,created_at,updated_at)
                   VALUES(?,?,?,?,'rss','vendor','high',1,30,?,?)""",
                (i, slug, nombre, f"https://x.invalid/{slug}", ts, ts))

        # --- inventario: criticidad y exposición variadas, una sin versión ---
        tecnologias = [
            (1, "moodle", "Moodle", "4.3.1", "critical", "internet", 2),
            (2, "windows-server", "Windows Server", None, "high", "interna", 12),
            (3, "tec-hostil", HOSTIL_TEC, "1.0", "medium", "dmz", 1),
        ]
        for tid, slug, nombre, version, crit, expo, sistemas in tecnologias:
            conn.execute(
                """INSERT INTO technologies(id,slug,name,category,version_installed,
                       criticality,systems_count,exposure,enabled,created_at,updated_at)
                   VALUES(?,?,?,'aplicacion',?,?,?,?,1,?,?)""",
                (tid, slug, nombre, version, crit, sistemas, expo, ts, ts))

        # --- amenaza completa ---
        conn.execute(
            """INSERT INTO threats(id,fingerprint,cve,title_en,title_es,summary_en,summary_es,
                   severity,severity_source,cvss_score,cvss_vector,cvss_version,epss_score,
                   in_kev,kev_due_date,published_at,first_seen_at,last_seen_at,times_seen,
                   impact_es,remediation_es,translation_engine,enriched_at,month,alerted_at,relevance)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (ID_COMPLETA, "fp-completa", CVE_RECURRENTE, "Moodle RCE", HOSTIL_TITULO,
             "Remote code execution in Moodle.", "Ejecución remota de código en Moodle.",
             "Critical", "nvd", 9.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "3.1", 0.83771,
             1, "2026-09-20", "2026-08-30T10:00:00Z", "2026-09-02T08:00:34Z", "2026-09-03T08:01:16Z", 4,
             "Toma de control del servidor de aula virtual.", "Actualizar a Moodle 4.3.5 o posterior.",
             "argos", "2026-09-02T09:00:00Z", "2026-09", "2026-09-02T08:30:00Z", 84.4))
        for tec, veredicto, evidencia in ((1, "affected", "4.3.1 < 4.3.5"),
                                          (2, "unknown", None),
                                          (3, "not_affected", "1.0 no vulnerable")):
            conn.execute(
                """INSERT INTO threat_technologies(threat_id,technology_id,matched_alias,
                       confidence,version_verdict,version_evidence) VALUES(?,?,?,1.0,?,?)""",
                (ID_COMPLETA, tec, "alias", veredicto, evidencia))
        conn.execute("INSERT INTO threat_sources(threat_id,source_id,url,seen_at) VALUES(?,?,?,?)",
                     (ID_COMPLETA, 1, URL_OK, ts))
        conn.execute("INSERT INTO threat_sources(threat_id,source_id,url,seen_at) VALUES(?,?,?,?)",
                     (ID_COMPLETA, 2, URL_JS, ts))

        # --- amenaza mínima: sin CVE, sin puntuaciones, sin alertar, sin inventario ---
        conn.execute(
            """INSERT INTO threats(id,fingerprint,cve,title_en,title_es,severity,severity_source,
                   cvss_score,epss_score,in_kev,first_seen_at,last_seen_at,times_seen,month,
                   alerted_at,relevance)
               VALUES(?,?,NULL,?,NULL,'Low','heuristic',NULL,NULL,0,?,?,1,'2026-09',NULL,0)""",
            (ID_MINIMA, "fp-minima", "Campaign without CVE", "2026-09-03T07:00:00Z", "2026-09-03T07:00:00Z"))

        # --- mismo CVE en otro periodo (recurrente) ---
        conn.execute(
            """INSERT INTO threats(id,fingerprint,cve,title_en,title_es,summary_en,severity,severity_source,
                   cvss_score,in_kev,first_seen_at,last_seen_at,times_seen,month,alerted_at,relevance)
               VALUES(?,?,?,?,?,?,'High','heuristic',NULL,0,?,?,2,'2026-08',?,40.0)""",
            (ID_REPETIDA, "fp-repetida", CVE_RECURRENTE, "Moodle RCE (again)", "Moodle RCE (otra vez)",
             RESUMEN_HTML, "2026-08-10T08:00:00Z", "2026-08-11T08:00:00Z", "2026-08-10T09:00:00Z"))

        # --- réplica de la amenaza real 2529 (revisión visual 2026-09-04) ---
        # kev_due_date es una fecha civil a medianoche UTC: convertida a la zona
        # local (UTC-5) salía «10 de junio». published_at llega tal cual del RSS
        # en RFC 2822 y se mostraba como «-».
        conn.execute(
            """INSERT INTO threats(id,fingerprint,cve,title_en,title_es,severity,severity_source,
                   cvss_score,cvss_version,epss_score,in_kev,kev_due_date,published_at,
                   first_seen_at,last_seen_at,times_seen,month,alerted_at,relevance)
               VALUES(?,?,?,?,?,'Critical','nvd',9.3,'3.1',0.83771,1,?,?,?,?,1,'2026-06',NULL,70.0)""",
            (ID_KEV_REAL, "fp-kev-real", "CVE-2026-50751", "Real KEV threat", "Amenaza KEV real",
             "2026-06-11T00:00:00Z", "Mon, 08 Jun 2026 19:47:39 +0530",
             "2026-06-09 08:00:34", "2026-06-09 08:00:34"))

        # --- relleno para paginar: severidades alternas, algunas en KEV ---
        for i in range(N_RELLENO):
            tid = 10 + i
            sev = ("Critical", "High", "Medium", "Low")[i % 4]
            conn.execute(
                """INSERT INTO threats(id,fingerprint,cve,title_en,title_es,severity,severity_source,
                       cvss_score,epss_score,in_kev,first_seen_at,last_seen_at,times_seen,month,
                       alerted_at,relevance)
                   VALUES(?,?,?,?,?,?,'heuristic',?,?,?,?,?,1,'2026-09',?,?)""",
                (tid, f"fp-{tid}", f"CVE-2026-{tid:05d}" if i % 2 == 0 else None,
                 f"Threat {tid}", f"Amenaza de relleno {tid}", sev,
                 7.5 if i % 3 == 0 else None, 0.123 if i % 5 == 0 else None,
                 1 if i % 10 == 0 else 0, "2026-09-01T08:00:00Z", "2026-09-01T08:00:00Z",
                 "2026-09-01T09:00:00Z", 10 + i % 40))
            if i % 6 == 0:
                conn.execute(
                    """INSERT INTO threat_technologies(threat_id,technology_id,matched_alias,
                           confidence,version_verdict) VALUES(?,2,'alias',1.0,'unknown')""", (tid,))


# Claves internas que nunca deben salir como texto visible: la severidad de la
# amenaza, la criticidad del inventario, el veredicto de versión y el origen de
# la severidad se etiquetan con los filtros severidad_es, veredicto_es y origen_es.
RE_INGLES = re.compile(r">\s*(Critical|High|Medium|Low|critical|high|medium|low|affected|"
                       r"not_affected|unknown|nvd|vector|kev|heuristic)\s*<")


def _sin_ingles(caso: unittest.TestCase, html: str) -> None:
    caso.assertIsNone(RE_INGLES.search(html),
                      f"texto visible en inglés: {RE_INGLES.search(html) and RE_INGLES.search(html).group(0)}")
    caso.assertNotIn("Critica<", html, "severidad sin tilde")


class _BaseAmenazas(unittest.TestCase):
    """Base temporal bajo data/, aplicación en modo prueba, sesión iniciada."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "amenazas.db")
        db.init_db(cls.ruta)
        _sembrar(cls.ruta)
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)
        cls.cli = cls._sesion(USUARIO, CLAVE)
        # Conexión de solo lectura a la MISMA base temporal: las pruebas que comprueban
        # que una cifra de la pantalla coincide con la base necesitan consultarla.
        cls.conn = db.connect(cls.ruta)

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()
        cls.dir.cleanup()

    @classmethod
    def _sesion(cls, usuario: str, clave: str):
        cli = cls.app.test_client()
        cli.post("/login", data={"usuario": usuario, "password": clave})
        return cli

    @classmethod
    def _html(cls, ruta: str) -> str:
        """HTML de una ruta con sesión; falla si no responde 200. Es método de
        clase para poder usarlo desde setUpClass."""
        resp = cls.cli.get(ruta)
        if resp.status_code != 200:
            raise AssertionError(f"{ruta} respondió {resp.status_code}")
        return resp.data.decode("utf-8", "replace")

    @staticmethod
    def _figuras(html: str, tipo: str) -> list[str]:
        return re.findall(r'<figure class="grafico-envoltorio ' + re.escape(tipo) + r'">.*?</figure>',
                          html, re.S)

    def _comprobar_csp(self, html: str) -> None:
        self.assertIsNone(RE_STYLE.search(html), "hay un atributo style=")
        self.assertIsNone(RE_ON.search(html), "hay un manejador on*=")
        self.assertIsNone(RE_SCRIPT_INLINE.search(html), "hay un <script> en línea")
        self.assertNotIn("<style", html.lower())
        valores = {v for _, v in RE_FILL_STROKE.findall(html)}
        self.assertTrue(valores <= {"none", "currentColor", "transparent"},
                        f"colores literales en atributos SVG: {valores}")
        # Ningún recurso externo se carga (los enlaces <a> externos sí se permiten).
        externos = [u for u in re.findall(r'\ssrc="([^"]+)"', html) if re.match(r"^(https?:)?//", u, re.I)]
        self.assertEqual(externos, [], f"recursos externos: {externos}")
        for svg in re.findall(r"<svg.*?</svg>", html, re.S):
            self.assertIsNone(re.search(r"https?://", svg), "URL externa dentro de un SVG")


# ==========================================================================
# Ficha completa
# ==========================================================================
class TestFichaCompleta(_BaseAmenazas):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.html = cls._html(f"/amenazas/{ID_COMPLETA}")
        cls.medidores = cls._figuras(cls.html, "grafico-medidor")

    def test_responde_200_y_exige_sesion(self):
        self.assertIn("Gravedad técnica", self.html)
        anonimo = self.app.test_client().get(f"/amenazas/{ID_COMPLETA}")
        self.assertIn(anonimo.status_code, (302, 303))
        self.assertIn("/login", anonimo.headers.get("Location", ""))
        lector = self._sesion(LECTOR, CLAVE_LECTOR).get(f"/amenazas/{ID_COMPLETA}")
        self.assertEqual(lector.status_code, 200)

    def test_csp_estricta(self):
        self._comprobar_csp(self.html)
        self.assertNotIn("unsafe-", self.cli.get(f"/amenazas/{ID_COMPLETA}")
                         .headers.get("Content-Security-Policy", ""))

    # ------------------------------------------------------------ medidores
    def test_tres_medidores_con_valor_y_color_por_umbral(self):
        self.assertEqual(len(self.medidores), 3, "CVSS, EPSS y relevancia")
        cvss, epss, rel = self.medidores
        # CVSS 9,3 de 10 → crítico (≥ 9)
        self.assertIn('aria-label="Medidor CVSS: 9,3 de 10"', cvss)
        self.assertIn('class="serie-critico medidor-valor"', cvss)
        self.assertIn(">9,3</text>", cvss)
        # EPSS 0,83771 → 83,8 % de 100 % → crítico (≥ 60)
        self.assertIn('aria-label="Medidor EPSS: 83,8 % de 100 %"', epss)
        self.assertIn('class="serie-critico medidor-valor"', epss)
        self.assertIn(">83,8 %</text>", epss)
        # Relevancia 84,4 → 84 entero de 100 → crítico (≥ 75)
        self.assertIn('aria-label="Medidor Relevancia: 84 de 100"', rel)
        self.assertIn('class="serie-critico medidor-valor"', rel)
        self.assertIn(">84</text>", rel)
        self.assertNotIn(">84,4</text>", rel)
        for fig in self.medidores:
            svg = re.search(r'<svg class="grafico"[^>]*>', fig).group(0)
            self.assertIn('role="img"', svg)
            self.assertIn("aria-label=", svg)

    def test_frases_de_lectura_y_origen_de_la_severidad(self):
        self.assertIn("Gravedad técnica crítica", self.html)
        self.assertIn("Probabilidad de explotación muy alta", self.html)
        self.assertIn("Prioridad máxima para la organización", self.html)
        self.assertIn("CVSS oficial (NVD)", self.html)      # origen_es de «nvd»
        self.assertIn("CVSS 3.1", self.html)
        # Los medidores van encima de la ficha: antes de los hitos y de las tecnologías.
        self.assertLess(self.html.find("grafico-medidor"), self.html.find('class="flujo compacto"'))

    def test_epss_no_se_atribuye_a_nvd(self):
        """El EPSS lo publica FIRST: la tarjeta no debe atribuirlo al origen de
        la severidad (NVD), como hacía la primera versión de la ficha."""
        tarjeta = re.search(r'<h2>Probabilidad de explotación</h2>.*?</div>\s*</div>\s*</div>',
                            self.html, re.S).group(0)
        self.assertIn("fuente: <abbr", tarjeta)
        self.assertIn(">FIRST</abbr> EPSS", tarjeta)
        self.assertNotIn("NVD", tarjeta)
        self.assertNotIn("CVSS oficial", tarjeta)
        # La tarjeta de CVSS sí conserva el origen de la severidad.
        self.assertIn("CVSS oficial (NVD)", self.html)

    def test_sin_etiquetas_en_ingles(self):
        _sin_ingles(self, self.html)

    def test_medidores_sin_medias_verdades(self):
        """Un medidor con valor lleva <title> con el valor y el máximo."""
        self.assertIn("<title>CVSS: 9,3 de 10</title>", self.medidores[0])
        self.assertIn("<title>EPSS: 83,8 % de 100</title>", self.medidores[1])
        self.assertIn("<title>Relevancia: 84 de 100</title>", self.medidores[2])

    # ---------------------------------------------------------------- hitos
    def test_flujo_compacto_con_cuatro_hitos(self):
        flujo = re.search(r'<div class="flujo compacto"[^>]*>.*?</div>\s*</div>\s*</div>', self.html, re.S)
        self.assertIsNotNone(flujo)
        self.assertEqual(self.html.count('class="flujo-paso '), 4)
        self.assertIn('class="flujo compacto" role="group"', self.html)
        # primera y última vez vista con fecha en español
        self.assertRegex(self.html, r'Primera vez vista</div><div class="valor">2 de septiembre de 2026</div>')
        self.assertRegex(self.html, r'Última vez vista</div><div class="valor">3 de septiembre de 2026</div>')
        self.assertIn("citada 4 veces", self.html)
        # alertada con fecha y estado correcto
        self.assertRegex(self.html, r'flujo-paso ok"><div class="titulo"><span class="punto ok"[^>]*></span>'
                                    r'Alertada</div><div class="valor">2 de septiembre de 2026</div>')
        # explotación confirmada en estado crítico con plazo CISA
        self.assertRegex(self.html, r'flujo-paso critico"><div class="titulo"><span class="punto critico"[^>]*></span>'
                                    r'Explotación confirmada</div><div class="valor">Sí</div>'
                                    r'<div class="nota">plazo CISA: 20 de septiembre de 2026</div>')
        self.assertNotIn(">pendiente<", self.html)   # «independientemente» contiene la palabra

    # ------------------------------------------------------- orden de lectura
    def test_orden_de_lectura(self):
        posiciones = [self.html.find(marca) for marca in (
            "<h1>",                       # qué es
            "grafico-medidor",            # cuánto importa
            'class="flujo compacto"',     # hitos
            "<h2>Tecnologías afectadas</h2>",
            "<h2>Impacto</h2>",
            "<h2>Remediación recomendada</h2>",
            "<h2>Fuentes</h2>",
        )]
        self.assertTrue(all(p >= 0 for p in posiciones), posiciones)
        self.assertEqual(posiciones, sorted(posiciones), "el orden de la ficha no es el de la especificación")

    def test_todo_panel_lleva_h2_y_sub(self):
        cabeceras = re.findall(r'<div class="panel-cabecera">(.*?)</div>\s*<div class="panel-cuerpo',
                               self.html, re.S)
        self.assertGreaterEqual(len(cabeceras), 7)
        for cab in cabeceras:
            self.assertIn("<h2>", cab)
            self.assertIn('class="sub"', cab)

    # ------------------------------------------------------------- qué es
    def test_cabecera_con_insignias_y_kev(self):
        self.assertIn('<span class="insignia critical"', self.html)
        self.assertIn(">Crítica</span>", self.html)
        self.assertIn('class="insignia kev"', self.html)
        self.assertIn("Explotación activa confirmada.", self.html)
        self.assertIn(f'<span class="mono">{CVE_RECURRENTE}</span>', self.html)
        self.assertIn("vista 4 veces", self.html)
        self.assertIn(f'href="https://nvd.nist.gov/vuln/detail/{CVE_RECURRENTE}"', self.html)
        self.assertRegex(self.html, r'<a class="btn primario" target="_blank" rel="noopener noreferrer"\s+href="https://nvd')

    def test_titulo_hostil_escapado(self):
        self.assertNotIn('<script>alert("t")</script>', self.html)
        self.assertNotIn("<script>alert(1)</script>", self.html)
        self.assertNotIn('<script>alert("f")</script>', self.html)
        self.assertIn("Fallo &lt;script&gt;alert(&#34;t&#34;)&lt;/script&gt; en Moodle", self.html)
        self.assertIn("Tec &lt;script&gt;alert(1)&lt;/script&gt; &amp; Cía", self.html)
        self.assertIn("Fuente &lt;script&gt;alert(&#34;f&#34;)&lt;/script&gt;", self.html)

    # -------------------------------------------------------- tecnologías
    def test_tecnologias_en_espanol_con_chips_de_veredicto(self):
        self.assertIn("<h2>Tecnologías afectadas</h2>", self.html)
        # Adaptado el 2026-09-15 (auditoría de tableros, punto 9): la cabecera decía
        # «3 correlacionadas» y la tabla listaba 2, porque la tercera estaba descartada por
        # versión y va al pie. Ahora el recuento de la cabecera cuenta lo que se lista y lo
        # que no se lista (descartadas y menciones sin prueba) lleva su propio recuento.
        visible = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", self.html))
        self.assertIn("Se listan 2 tecnologías con prueba suficiente: "
                      "1 con versión afectada y 1 sin determinar.", visible)
        self.assertIn("Además, 1 descartada porque la versión registrada no es vulnerable", visible)
        self.assertNotIn("3 correlacionadas", visible)
        # criticidad y exposición en español, nunca la clave interna. «Media» ya no está en
        # la tabla porque era la tecnología descartada: desde el 2026-09-09 la tabla lista
        # solo lo que afecta o lo que no se puede descartar, a petición del usuario.
        for texto in (">Crítica</span>", ">Alta</span>",
                      ">Internet</span>", ">Red interna</span>"):
            self.assertIn(texto, self.html, texto)
        for crudo in (">critical</span>", ">high</span>", ">medium</span>",
                      ">internet</span>", ">interna</span>", ">dmz</span>"):
            self.assertNotIn(crudo, self.html, crudo)
        self.assertIn('<span class="chip afectada"', self.html)
        self.assertIn(">Afectada</span>", self.html)
        self.assertIn(">Sin determinar</span>", self.html)
        # Lo que NO afecta no se lista: se cuenta y se nombra en una sola línea al pie.
        self.assertNotIn('<span class="chip no-afectada"', self.html)
        self.assertNotIn(">No afectada</span>", self.html)
        self.assertIn("cuya versión instalada no es vulnerable según el aviso", self.html)
        self.assertIn("4.3.1 &lt; 4.3.5", self.html)          # evidencia escapada
        self.assertIn("sin registrar", self.html)             # Windows Server sin versión
        self.assertIn('href="/amenazas/?tec=moodle"', self.html)
        self.assertIn("1 con versión afectada", self.html)

    # -------------------------------------------------------- qué hacer
    def test_impacto_y_remediacion(self):
        self.assertIn("Toma de control del servidor de aula virtual.", self.html)
        self.assertIn("Actualizar a Moodle 4.3.5 o posterior.", self.html)
        self.assertIn("Ejecución remota de código en Moodle.", self.html)
        self.assertIn("Ver texto original en inglés", self.html)
        self.assertIn("Traducción automática (argos)", self.html)

    # ----------------------------------------------------------- fuentes
    def test_fuentes_con_url_segura(self):
        self.assertIn(f'href="{URL_OK}" target="_blank" rel="noopener noreferrer"', self.html)
        peligrosos = [h for h in re.findall(r'href="([^"]*)"', self.html)
                      if h.lower().startswith(("javascript:", "data:", "vbscript:"))]
        self.assertEqual(peligrosos, [])
        self.assertIn("enlace omitido por seguridad", self.html)
        self.assertIn("2 referencias externas", self.html)

    def test_mismo_cve_en_otros_periodos(self):
        self.assertIn("<h2>Mismo CVE en otros periodos</h2>", self.html)
        self.assertIn(f'href="/amenazas/{ID_REPETIDA}"', self.html)
        self.assertIn("agosto de 2026", self.html)

    def test_datos_tecnicos_y_numeros_en_espanol(self):
        self.assertIn("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", self.html)
        self.assertIn("fp-completa", self.html)
        self.assertIn("30 de agosto de 2026", self.html)         # publicada
        self.assertNotIn("9.3/10.0", self.html)                  # ya no se usa el formato inglés
        self.assertNotIn(">83.8", self.html)
        self.assertNotIn("Rel.", self.html)


# ==========================================================================
# Ficha mínima: sin CVSS, sin EPSS, sin CVE, sin alertar
# ==========================================================================
class TestFichaSinDatos(_BaseAmenazas):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.html = cls._html(f"/amenazas/{ID_MINIMA}")
        cls.medidores = cls._figuras(cls.html, "grafico-medidor")

    def test_medidores_muestran_guion_sin_excepcion(self):
        self.assertEqual(len(self.medidores), 3)
        cvss, epss, rel = self.medidores
        for fig in (cvss, epss):
            self.assertIn(">—</text>", fig)
            self.assertNotIn("medidor-valor", fig, "sin valor no hay arco de color")
            self.assertIn("sin dato", fig)  # aria-label
        # la relevancia es 0: hay valor (0) pero no arco
        self.assertIn(">0</text>", rel)
        self.assertNotIn("medidor-valor", rel)
        self.assertIn("Sin puntuación oficial", self.html)
        self.assertIn("Sin estimación de explotación", self.html)
        self.assertIn("Prioridad baja para la organización", self.html)
        self.assertIn("severidad estimada", self.html)  # origen_es de «heuristic»

    def test_hitos_pendiente_e_inactivos(self):
        self.assertEqual(self.html.count('class="flujo-paso '), 4)
        self.assertRegex(self.html, r'flujo-paso inactivo"><div class="titulo"><span class="punto inactivo"[^>]*></span>'
                                    r'Alertada</div><div class="valor">pendiente</div>')
        self.assertRegex(self.html, r'flujo-paso inactivo"><div class="titulo"><span class="punto inactivo"[^>]*></span>'
                                    r'Explotación confirmada</div><div class="valor">No</div>'
                                    r'<div class="nota">no consta en CISA KEV</div>')
        self.assertIn("una sola aparición", self.html)

    def test_estados_vacios(self):
        self.assertIn("Sin CVE", self.html)
        self.assertIn("Sin correlación con el inventario.", self.html)
        self.assertIn("Sin referencias registradas.", self.html)
        self.assertIn("Sin análisis de impacto ni remediación registrado.", self.html)
        self.assertIn("Sin resumen registrado.", self.html)
        self.assertNotIn("Mismo CVE en otros periodos", self.html)
        self.assertNotIn("nvd.nist.gov", self.html)
        self.assertIn(">Baja</span>", self.html)

    def test_csp_tambien_sin_datos(self):
        self._comprobar_csp(self.html)

    def test_publicada_nula_conserva_el_fallback(self):
        self.assertIn('<dt>Publicada</dt><dd><span class="tenue">sin fecha de publicación</span></dd>', self.html)
        _sin_ingles(self, self.html)

    def test_resumen_con_html_de_la_fuente_se_limpia(self):
        """El HTML crudo del feed no se muestra como código ni como marcado."""
        html = self._html(f"/amenazas/{ID_REPETIDA}")
        self.assertIn("Wrap-up with shells &amp; fixes", html)
        # la etiqueta truncada del final se recorta; un «<» legítimo se conserva
        self.assertIn("Path Traversal (version &lt; 4.3)…", html)
        self.assertNotIn("font-size", html)
        self.assertNotIn("&lt;p&gt;", html)
        self.assertNotIn("&lt;span", html)
        self.assertNotIn("<b>shells</b>", html)
        self.assertNotIn('alert("s")', html)
        self.assertIn("Texto original en inglés: todavía sin traducir.", html)
        self._comprobar_csp(html)

    def test_amenaza_inexistente_redirige_a_la_lista(self):
        resp = self.cli.get("/amenazas/999999")
        self.assertIn(resp.status_code, (302, 303))
        self.assertTrue(resp.headers.get("Location", "").endswith("/amenazas/"))


# ==========================================================================
# Fechas reales: plazo KEV civil y publicación RFC 2822 (amenaza 2529)
# ==========================================================================
class TestFichaFechasReales(_BaseAmenazas):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.html = cls._html(f"/amenazas/{ID_KEV_REAL}")

    def test_plazo_cisa_no_se_desplaza_un_dia(self):
        """kev_due_date='2026-06-11T00:00:00Z' es una fecha de calendario: debe
        leerse «11 de junio», no «10 de junio» (medianoche UTC en UTC-5)."""
        self.assertIn("Plazo de corrección fijado por CISA: 11 de junio de 2026.", self.html)
        self.assertIn('<div class="nota">plazo CISA: 11 de junio de 2026</div>', self.html)
        self.assertNotIn("10 de junio de 2026", self.html)

    def test_publicada_rfc_2822_se_muestra(self):
        """published_at='Mon, 08 Jun 2026 19:47:39 +0530' (formato RSS) ya no sale como «-»."""
        self.assertIn("<dt>Publicada</dt><dd>8 de junio de 2026</dd>", self.html)
        self.assertNotIn("<dt>Publicada</dt><dd>-</dd>", self.html)
        self.assertNotIn("sin fecha de publicación", self.html)

    def test_detectada_sin_zona_horaria(self):
        # first_seen_at real sin «Z» ni «T»: '2026-06-09 08:00:34'
        self.assertIn("Detectada el 9 de junio de 2026 · periodo junio de 2026", self.html)

    def test_csp_y_sin_ingles(self):
        self._comprobar_csp(self.html)
        _sin_ingles(self, self.html)
        self.assertIn('<span class="insignia critical"', self.html)
        self.assertIn(">Crítica</span>", self.html)


# ==========================================================================
# Lista
# ==========================================================================
class TestLista(_BaseAmenazas):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.html = cls._html("/amenazas/")

    def test_responde_200_con_filtros_y_glosario(self):
        self.assertIn("Consulta de amenazas", self.html)
        self.assertIn("<h2>Filtros</h2>", self.html)
        for campo in ('name="q"', 'name="mes"', 'name="sev"', 'name="tec"', 'name="orden"',
                      'name="kev"', 'name="cve"'):
            self.assertIn(campo, self.html, campo)
        self.assertIn('<option value="2026-09"', self.html)
        self.assertIn('<option value="moodle"', self.html)
        self.assertIn("Cómo leer estos datos", self.html)
        self.assertGreater(self.html.find("Cómo leer estos datos"), self.html.find("<h2>Resultados</h2>"))
        self.assertNotIn("Filtros activos:", self.html)

    def test_csp_estricta(self):
        self._comprobar_csp(self.html)

    def test_exportar_csv_y_tendencias(self):
        self.assertIn('href="/amenazas/exportar.csv"', self.html)
        self.assertIn(">Exportar CSV</a>", self.html)
        self.assertIn('href="/amenazas/tendencias"', self.html)
        resp = self.cli.get("/amenazas/exportar.csv?sev=Critical")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/csv", resp.headers.get("Content-Type", ""))

    def test_tabla_paginada_y_total(self):
        # Adaptado el 2026-09-15 (revisión de claridad): con el ajuste «Ignorar la
        # severidad baja» activo, la LISTA tampoco cuenta ni enseña las bajas, así que el
        # total ya no es «todas las sembradas» sino «todas menos las bajas». Antes decía
        # 7.514 en la cabecera y 7.293 en la tarjeta de la misma página.
        bajas = self.conn.execute(
            "SELECT COUNT(*) FROM threats WHERE severity='Low' AND estado NOT IN "
            "('descartada','falso_positivo')").fetchone()[0]
        self.assertGreater(bajas, 0, "el sembrado tiene amenazas de severidad baja")
        total = 4 + N_RELLENO - bajas
        self.assertIn(f"{total} amenazas coinciden", self.html)
        paginas = max(1, -(-total // POR_PAGINA))
        self.assertIn(f"página 1 de {paginas}, {POR_PAGINA} por página", self.html)
        self.assertIn(f"Página 1 de {paginas}", self.html)
        # Desde el 2026-09-07 esta página usa el mismo componente que el resto de los
        # listados («_paginacion.html»), que nombra lo que se lista en la etiqueta
        # accesible en lugar de decir «resultados».
        self.assertIn('aria-label="Paginación de las amenazas"', self.html)
        # El ancla «#resultados» devuelve a la tabla al cambiar de página, en lugar de
        # al principio del documento.
        self.assertIn('href="/amenazas/?pagina=2#resultados"', self.html)
        self.assertIn('aria-current="page"', self.html)
        self.assertIn(">Primera<", self.html)
        self.assertIn(">Última<", self.html)
        self.assertEqual(len(re.findall(r'<a href="/amenazas/\d+">', self.html)), POR_PAGINA)
        ultima = self._html(f"/amenazas/?pagina={paginas}")
        self.assertEqual(len(re.findall(r'<a href="/amenazas/\d+">', ultima)),
                         (total % POR_PAGINA) or POR_PAGINA)
        # Y en ninguna página aparece una insignia «Baja» (2026-09-15).
        self.assertNotIn(">Baja</span>", ultima)
        self.assertNotIn("CVE presentes en varios periodos", ultima,
                         "los recurrentes solo en la primera página")

    def test_sin_etiquetas_en_ingles_y_veredicto_por_filtro(self):
        _sin_ingles(self, self.html)
        # Opciones y chips de severidad salen del filtro severidad_es, con tilde.
        self.assertRegex(self.html, r'<option value="Critical"\s*>\s*Crítica\s*</option>')
        # La severidad Baja ya no se ofrece en el filtro: con el ajuste activo no cuenta
        # en nada, así que ofrecerla prometía una lista sin respaldo (2026-09-10).
        self.assertNotRegex(self.html, r'<option value="Low"\s*>\s*Baja\s*</option>')
        # El veredicto del chip de tecnología usa veredicto_es.
        self.assertIn("Moodle 4.3.1 · versión afectada", self.html)
        self.assertIn("Windows Server · sin determinar", self.html)
        self.assertNotIn("veredicto sin determinar", self.html)
        # La fecha RFC 2822 y la civil no rompen la lista de la amenaza real.
        fila = re.search(rf'<tr>\s*<td>\s*<a href="/amenazas/{ID_KEV_REAL}">(.*?)</tr>', self.html, re.S)
        if fila is None:
            fila = re.search(rf'<tr>\s*<td>\s*<a href="/amenazas/{ID_KEV_REAL}">(.*?)</tr>',
                             self._html("/amenazas/?pagina=2"), re.S)
        self.assertIsNotNone(fila)
        self.assertIn("junio de 2026", fila.group(0))
        self.assertIn("9 de junio de 2026", fila.group(0))

    def test_cabeceras_en_espanol_con_titulos_explicativos(self):
        for th in ("<th>Amenaza</th>", ">Severidad</th>", ">CVSS</th>", ">EPSS</th>",
                   ">Relevancia</th>", ">Tecnologías</th>", ">Periodo</th>"):
            self.assertIn(th, self.html, th)
        self.assertRegex(self.html, r'<th class="num" title="[^"]*Relevancia[^"]*">Relevancia</th>')
        self.assertNotIn("Rel.", self.html)

    def test_fila_completa_en_formato_espanol(self):
        fila = re.search(rf'<tr>\s*<td>\s*<a href="/amenazas/{ID_COMPLETA}">(.*?)</tr>', self.html, re.S).group(0)
        self.assertIn("Fallo &lt;script&gt;alert(&#34;t&#34;)&lt;/script&gt; en Moodle", fila)
        self.assertNotIn("<script>", fila)
        self.assertIn('<span class="insignia critical">Crítica</span>', fila)
        self.assertIn('class="insignia kev"', fila)
        self.assertIn("CVSS oficial (NVD)", fila)
        self.assertIn("9,3", fila)
        self.assertNotIn("9.3", fila)
        self.assertIn("83,8 %", fila)
        self.assertIn('class="txt-critico-b">84</span>', fila)
        self.assertIn('<span class="chip afectada"', fila)
        self.assertIn('<span class="chip no-afectada"', fila)
        self.assertIn("Moodle 4.3.1", fila)
        self.assertIn("vista 4 veces", fila)
        self.assertIn("2 fuentes", fila)
        self.assertIn("septiembre de 2026", fila)
        self.assertIn(f"{CVE_RECURRENTE}", fila)

    def test_fila_sin_datos_dice_no_disponible(self):
        """Una fila sin CVSS, sin EPSS y sin correlación lo dice, no deja huecos.

        Reescrito el 2026-09-15 (revisión de claridad). La amenaza mínima del sembrado es
        de severidad BAJA y hasta hoy salía en la lista con su insignia «Baja»: eso es
        justo lo que la regla del equipo prohíbe y lo que la revisión encontró en
        producción (221 bajas en la última página). Ahora se comprueban las dos cosas: que
        esa fila NO está en ninguna página, y que una fila sin datos de una severidad que
        sí se reporta escribe «no disponible» en lugar de dejar el hueco.
        """
        paginas = max(1, -(-(4 + N_RELLENO) // POR_PAGINA))
        html_paginas = [self._html(f"/amenazas/?pagina={p}") for p in range(1, paginas + 1)]
        for pagina, html in enumerate(html_paginas, start=1):
            self.assertIsNone(re.search(rf'<a href="/amenazas/{ID_MINIMA}">', html),
                              f"la amenaza de severidad baja aparece en la página {pagina}")
            self.assertNotIn(">Baja</span>", html, f"insignia «Baja» en la página {pagina}")
        # Una de relleno sin CVSS ni EPSS (i=1: severidad Alta, sin CVE): mismo caso, con
        # una severidad que sí se reporta.
        sin_datos = self.conn.execute(
            "SELECT id FROM threats WHERE severity <> 'Low' AND cvss_score IS NULL "
            "AND epss_score IS NULL AND cve IS NULL ORDER BY id LIMIT 1").fetchone()[0]
        patron = rf'<tr>\s*<td>\s*<a href="/amenazas/{sin_datos}">(.*?)</tr>'
        fila = None
        for html in html_paginas:
            fila = re.search(patron, html, re.S)
            if fila:
                break
        self.assertIsNotNone(fila, "la amenaza sin datos no aparece en ninguna página")
        fila = fila.group(0)
        self.assertEqual(fila.count("no disponible"), 2)
        self.assertIn("sin CVE", fila)
        self.assertIn("sin correlación", fila)

    def test_cve_recurrentes(self):
        self.assertIn("CVE presentes en varios periodos", self.html)
        self.assertIn(f'href="/amenazas/?q={CVE_RECURRENTE}"', self.html)
        self.assertIn("<strong>2</strong>", self.html)     # dos periodos
        self.assertIn(">Ver avisos</a>", self.html)
        self.assertIn(">Periodos</th>", self.html)

    def test_filtro_por_severidad_y_chips_de_filtros_activos(self):
        html = self._html("/amenazas/?sev=Critical&kev=1")
        self.assertIn("Filtros activos:", html)
        self.assertIn('<span class="chip">Severidad: Crítica</span>', html)
        self.assertIn('<span class="chip">Solo KEV</span>', html)
        self.assertIn(">Quitar filtros</a>", html)
        self.assertIn('<option value="Critical" selected>', html)
        self.assertIn('href="/amenazas/exportar.csv?sev=Critical&amp;kev=1"', html)
        # Solo las insignias de severidad: la columna «Estado» (2026-09-04) también usa insignias.
        filas = re.findall(r'<td class="nowrap">\s*<span class="insignia (critical|high|medium|low)">', html)
        self.assertTrue(filas)
        self.assertTrue(all(f == "critical" for f in filas), filas)
        # Acotado al panel de «Resultados» (hasta el siguiente <h2>): el orden de los demás
        # paneles de la página puede cambiar sin que esta prueba dependa de cuántas filas
        # <tr> traigan antes o después (2026-11-16, tras mover «CVE recurrentes» debajo de
        # los resultados). La primera fila es la cabecera de la tabla.
        tabla_resultados = html.split("<h2>Resultados</h2>")[1].split("<h2>")[0]
        self.assertTrue(all("insignia kev" in tr
                            for tr in re.findall(r"<tr>.*?</tr>", tabla_resultados, re.S)[1:]))

    def test_filtro_por_texto_tecnologia_y_mes(self):
        html = self._html(f"/amenazas/?q={CVE_RECURRENTE}&tec=moodle&mes=2026-09")
        self.assertIn("1 amenaza coincide", html)
        self.assertIn('<span class="chip">Tecnología: Moodle</span>', html)
        self.assertIn('<span class="chip">Periodo: septiembre de 2026</span>', html)
        self.assertIn(f'<span class="chip">Texto: «{CVE_RECURRENTE}»</span>', html)
        self.assertIn(f'<a href="/amenazas/{ID_COMPLETA}">', html)
        self.assertNotIn("Página 1 de", html)

    def test_sin_resultados_estado_vacio(self):
        html = self._html("/amenazas/?q=no-existe-nada-asi")
        self.assertIn("0 amenazas coinciden", html)
        self.assertIn("Ningún resultado con estos filtros.", html)
        self.assertIn('class="vacio"', html)
        # Acotado al propio panel de «Resultados» (hasta el siguiente <h2>): con «CVE
        # recurrentes» debajo de los resultados (2026-11-16), ese panel sí trae su propio
        # <tbody> con filas reales, y no es lo que esta prueba quiere comprobar.
        self.assertNotIn("<tbody>", html.split("<h2>Resultados</h2>")[1].split("<h2>")[0])

    def test_parametros_hostiles_no_rompen(self):
        html = self._html('/amenazas/?q=%3Cscript%3Ealert(9)%3C/script%3E&tec=%3Cb%3Ex&sev=Raro&mes=&pagina=0')
        self.assertNotIn("<script>alert(9)</script>", html)
        self.assertIn("&lt;script&gt;alert(9)&lt;/script&gt;", html)
        self.assertNotIn("<b>x", html)
        self._comprobar_csp(html)


# ==========================================================================
# Barras con la severidad baja incluida (revisión de seguridad del 2026-09-09)
# ==========================================================================
ID_BAJA = 900        # amenaza de severidad Baja confirmada en un servidor
ID_ALTA = 901        # amenaza de severidad Alta confirmada en el mismo servidor


class TestBarrasConSeveridadBajaIncluida(_BaseAmenazas):
    """Con el ajuste «Ignorar la severidad baja» desactivado, la barra pinta el cuarto
    segmento y sigue cumpliendo la CSP estricta.

    Hasta el 2026-09-09 las barras de esta página pintaban siempre tres segmentos
    (críticas, altas y medias) mientras el total contaba también las bajas: en la base real
    eran 1.233 vulnerabilidades que estaban en el total y en ninguna parte del dibujo.
    Aquí se comprueba lo que ve el lector: cuatro segmentos con nombre en la leyenda, el
    color por clase de la hoja de estilos (nunca literal en el SVG, que la CSP prohíbe) y
    el total de la barra igual a la suma de sus segmentos.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        with db.session(cls.ruta) as conn:
            # Un servidor presente con una vulnerabilidad alta y otra baja.
            conn.execute(
                """INSERT INTO activos(id, ocs_id, nombre, origen, so_familia, presente,
                                       proceso, entorno, primera_vez_at, visto_at)
                   VALUES(90, 900, 'srv-baja-01', 'servidores', 'debian', 1, 'Pila',
                          'produccion', ?, ?)""", ("2026-09-01T08:00:00Z",) * 2)
            for tid, sev, cve in ((ID_ALTA, "High", "CVE-2026-70001"),
                                  (ID_BAJA, "Low", "CVE-2026-70002")):
                conn.execute(
                    """INSERT INTO threats(id, fingerprint, cve, title_en, title_es, severity,
                            severity_source, in_kev, first_seen_at, last_seen_at, times_seen,
                            month, relevance)
                       VALUES(?,?,?,?,?,?,'nvd',0,?,?,1,'2026-09',50.0)""",
                    (tid, f"fp-{tid}", cve, f"Threat {tid}", f"Amenaza {tid}", sev,
                     "2026-09-01T08:00:00Z", "2026-09-01T08:00:00Z"))
                conn.execute(
                    """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete,
                            version_instalada, version_corregida, veredicto, motor, evaluado_at)
                       VALUES(90,?,?,'paq','1.0','1.1','afectado','osv',?)""",
                    (tid, cve, "2026-09-01T09:00:00Z"))
            # El ajuste se desactiva en la propia base temporal: la vista lo lee en cada
            # petición (config.load sobre la misma conexión).
            db.set_setting(conn, "ignore_low_severity", False)
        cls.html = cls._html("/amenazas/")
        cls.grafico = cls.html[cls.html.index("Vulnerabilidades por tipo de activo"):
                               cls.html.index('id="resultados"')]

    def test_la_leyenda_nombra_los_cuatro_segmentos(self):
        leyenda = re.search(r'<ul class="leyenda">(.*?)</ul>', self.grafico, re.S)
        self.assertIsNotNone(leyenda, "la gráfica de barras tiene que llevar leyenda")
        claves = [(clave, nombre.strip()) for clave, nombre in re.findall(
            r'leyenda-punto serie-([a-z-]+)"></span>([^<]*)', leyenda.group(1))]
        self.assertEqual(claves, [("critico", "Críticas"), ("alto", "Altas"),
                                  ("medio", "Medias"), ("bajo", "Bajas")])

    def test_el_total_de_la_barra_es_la_suma_de_sus_segmentos(self):
        total = re.search(r'class="etiqueta-valor"[^>]*>(\d+) vulnerabilidades', self.grafico)
        self.assertIsNotNone(total)
        self.assertEqual(int(total.group(1)), 2,
                         "una alta y una baja: la barra mide las dos, no solo la alta")
        segmentos = re.findall(r'class="serie-(critico|alto|medio|bajo)"', self.grafico)
        self.assertEqual(sorted(segmentos), ["alto", "bajo"],
                         "se dibujan los segmentos con valor, cada uno con su clase de color")

    def test_el_texto_explica_que_las_bajas_cuentan(self):
        # Sobre el texto corrido con los espacios normalizados: las frases de la plantilla
        # llevan saltos de línea y no se pueden buscar tal cual.
        texto = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", self.grafico))
        self.assertIn("partida en cuatro segmentos", texto)
        self.assertIn("críticas, altas, medias y bajas", texto)
        self.assertIn("«Ignorar la severidad baja» está desactivado", texto)
        self.assertIn("1 de las 2 vulnerabilidades de este ámbito es baja", texto)
        self.assertNotIn("no se reportan", texto)

    def test_csp_estricta_con_el_cuarto_segmento(self):
        self._comprobar_csp(self.html)
        _sin_ingles(self, self.html)


# ==========================================================================
# Resultados relacionados en Activos y Tecnologías (2026-11-16): el mismo
# texto buscado en Amenazas puede ser el nombre de un activo o de una
# tecnología del inventario, no solo el de un aviso de seguridad.
# ==========================================================================
NOMBRE_ACTIVO_BUSQUEDA = "equipo-busqueda-91"


class TestResultadosRelacionados(_BaseAmenazas):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        with db.session(cls.ruta) as conn:
            conn.execute(
                """INSERT INTO activos(id, ocs_id, nombre, ip, origen, so_familia, presente,
                                       primera_vez_at, visto_at)
                   VALUES(91, 910, ?, '203.0.113.50', 'equipos', 'windows', 1, ?, ?)""",
                (NOMBRE_ACTIVO_BUSQUEDA, "2026-09-01T08:00:00Z", "2026-09-01T08:00:00Z"))

    def test_busqueda_de_tecnologia_muestra_el_panel_relacionado(self):
        # «Moodle» es el nombre de una tecnología del inventario sembrado por _sembrar()
        # (technologies.id=1) y también aparece en el título de la amenaza completa: las
        # dos cosas son ciertas a la vez, que es justo el caso que motiva el panel.
        html = self._html("/amenazas/?q=Moodle&estado=todas")
        self.assertIn("Resultados relacionados con", html)
        self.assertIn("Tecnologías (1)", re.sub(r"\s+", " ", html))
        self.assertIn("/tecnologias/1", html)
        self._comprobar_csp(html)

    def test_busqueda_de_activo_muestra_el_panel_relacionado(self):
        html = self._html(f"/amenazas/?q={NOMBRE_ACTIVO_BUSQUEDA}&estado=todas")
        self.assertIn("Resultados relacionados con", html)
        self.assertIn(NOMBRE_ACTIVO_BUSQUEDA, html)
        self.assertIn("/activos/91", html)
        self._comprobar_csp(html)

    def test_busqueda_sin_coincidencias_no_pinta_el_panel_vacio(self):
        html = self._html("/amenazas/?q=texto-sin-ninguna-coincidencia-posible&estado=todas")
        self.assertNotIn("Resultados relacionados con", html)

    def test_sin_texto_de_busqueda_no_consulta_ni_pinta_el_panel(self):
        html = self._html("/amenazas/")
        self.assertNotIn("Resultados relacionados con", html)


if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""Pruebas de renderizado del panel (/) rediseñado el 2026-09-03.

Cubren la sección 6 «Panel» de docs/DISENO_INTERFAZ_2026-09-03.md:

* la página responde 200 con sesión (administrador y solo lectura);
* los gráficos SVG están presentes y cumplen la CSP estricta (sin ``style=``,
  sin ``on*=``, sin ``<script>`` en línea, sin colores literales en
  ``fill``/``stroke``);
* las cifras de los gráficos coinciden con las de las tablas y las consultas
  (misma fuente de datos);
* los textos procedentes de la base de datos llegan escapados al SVG;
* el diagrama de flujo aplica los umbrales de estado;
* con una base vacía no hay excepciones y se muestran estados vacíos.

La base de datos es temporal bajo ``data/`` (mismo patrón que
``TestSeguridadInterfaz`` en tests/test_regresiones.py). Nunca se toca
``data/threat_intel.db``.

Ejecución:
    sudo -n -u si .venv/bin/python -m unittest tests.test_pagina_panel
"""
from __future__ import annotations

import re
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threatintel import db, queries  # noqa: E402
from threatintel.paths import BASE_DIR  # noqa: E402
from webui.graficos import fmt  # noqa: E402
from webui.vistas import panel as vista  # noqa: E402

USUARIO, CLAVE = "pruebas", "PruebaSegura#2026"
LECTOR, CLAVE_LECTOR = "lector", "LectorSeguro#2026"
HOSTIL_TEC = 'Tec <script>alert(1)</script>'
HOSTIL_FUENTE = 'Fuente <script>alert("f")</script> & Cía'
MES_ACTUAL = "2026-09"
MESES = ["2026-04", "2026-05", "2026-06", "2026-07", "2026-08", MES_ACTUAL]

RE_STYLE = re.compile(r"\sstyle\s*=", re.I)
RE_ON = re.compile(r"\son[a-z]+\s*=", re.I)
RE_SCRIPT_INLINE = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>", re.I)
RE_FILL_STROKE = re.compile(r'\b(fill|stroke)="([^"]*)"')


def _iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _sembrar(ruta: str) -> None:
    """Base realista pero pequeña: 6 meses, fuentes en todos los estados,
    tecnologías con y sin versión, ejecuciones diaria y mensual."""
    from webui import auth as _auth
    ahora = datetime.now(timezone.utc)
    ts = _iso(ahora)

    with db.session(ruta) as conn:
        _auth.crear_usuario(conn, USUARIO, CLAVE, rol="admin", actor="test")
        _auth.crear_usuario(conn, LECTOR, CLAVE_LECTOR, rol="ciberseguridad", actor="test")

        # --- fuentes: (slug, nombre, kind, enabled, historial de ok) ---
        fuentes = [
            ("s-ok", "Fuente correcta", "rss", 1, [1, 1, 1]),
            ("s-ok2", "Otra fuente correcta", "rss", 1, [1, 1, 1]),
            ("s-api", "NVD API", "nvd_api", 1, [1, 1]),
            ("s-caida", HOSTIL_FUENTE, "rss", 1, [0, 0, 0]),
            ("s-degradada", "Fuente degradada", "rss", 1, [0, 1, 1]),
            ("s-nueva", "Fuente sin comprobar", "rss", 1, []),
            ("s-off", "Fuente desactivada", "rss", 0, [0, 0, 0]),
        ]
        for i, (slug, nombre, kind, enabled, historial) in enumerate(fuentes, start=1):
            conn.execute(
                """INSERT INTO sources(id,slug,name,url,kind,category,priority,
                       enabled,timeout_s,created_at,updated_at)
                   VALUES(?,?,?,?,?,'news','medium',?,30,?,?)""",
                (i, slug, nombre, f"https://x.invalid/{slug}", kind, enabled, ts, ts))
            # el más reciente va primero en la lista; se inserta con hora decreciente
            for k, ok in enumerate(historial):
                conn.execute(
                    """INSERT INTO source_health(source_id,checked_at,ok,http_status,
                           entries,accepted,latency_ms,error)
                       VALUES(?,?,?,?,?,?,?,?)""",
                    (i, _iso(ahora - timedelta(hours=k + 1)), ok, 200 if ok else 404,
                     5 if ok else 0, 2 if ok else 0, 120, None if ok else "HTTP 404"))

        # --- inventario ---
        tecnologias = [
            (1, "windows-server", "Windows Server", "2019", "high"),
            (2, "cisco-ios-xe", "Cisco IOS XE", None, "critical"),
            (3, "tec-hostil", HOSTIL_TEC, None, "medium"),
        ]
        for tid, slug, nombre, version, crit in tecnologias:
            conn.execute(
                """INSERT INTO technologies(id,slug,name,category,version_installed,
                       criticality,systems_count,exposure,enabled,created_at,updated_at)
                   VALUES(?,?,?,'aplicacion',?,?,3,'interna',1,?,?)""",
                (tid, slug, nombre, version, crit, ts, ts))

        # --- amenazas: por mes i (0..5): críticas i+1, altas 2i+2, medias 5i+5, bajas i ---
        tid = 0
        for i, mes in enumerate(MESES):
            fecha = _iso(datetime(2026, 4 + i, 1, 12, 0, tzinfo=timezone.utc))
            plan = ([("Critical", True)] + [("Critical", False)] * i
                    + [("High", False)] * (2 * i + 2)
                    + [("Medium", False)] * (5 * i + 5)
                    + [("Low", False)] * i)
            for j, (sev, kev) in enumerate(plan):
                tid += 1
                es_actual = mes == MES_ACTUAL
                # procedencia del mes actual: 4 nvd, 2 vector, 1 kev, resto heurística
                if es_actual and j < 4:
                    origen = "nvd"
                elif es_actual and j < 6:
                    origen = "vector"
                elif es_actual and j == 6:
                    origen = "kev"
                else:
                    origen = "heuristic"
                cve = f"CVE-2026-{tid:04d}" if j % 3 != 2 else None
                enriquecido = fecha if (cve and origen in ("nvd", "vector")) else None
                # pendientes de alertar del mes actual: 1 crítica y 3 altas
                if es_actual and sev in ("Critical", "High") and j in (1, 8, 9, 10):
                    alertada = None
                elif es_actual and j == 0:
                    alertada = _iso(ahora - timedelta(minutes=30))   # en las últimas 24 h
                else:
                    alertada = fecha
                conn.execute(
                    """INSERT INTO threats(id,fingerprint,cve,title_en,title_es,severity,
                           severity_source,cvss_score,in_kev,first_seen_at,last_seen_at,
                           month,alerted_at,relevance,enriched_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (tid, f"fp-{tid}", cve, f"Threat {tid}", f"Amenaza {tid}", sev, origen,
                     9.8 if sev == "Critical" else None, 1 if kev else 0, fecha, fecha,
                     mes, alertada, 50 + (tid % 50), enriquecido))

        # --- correlaciones del mes actual ---
        actuales = [dict(r) for r in conn.execute(
            "SELECT id, severity FROM threats WHERE month=? ORDER BY id", (MES_ACTUAL,))]
        criticas = [t["id"] for t in actuales if t["severity"] == "Critical"]
        altas = [t["id"] for t in actuales if t["severity"] == "High"]
        medias = [t["id"] for t in actuales if t["severity"] == "Medium"]
        enlaces = ([(1, t, "affected") for t in criticas[:3]]
                   + [(1, t, "unknown") for t in altas[:2]]
                   + [(1, medias[0], "unknown")]
                   + [(2, criticas[0], "unknown"), (2, altas[2], "unknown")]
                   + [(3, altas[3], "unknown")])
        for tec, amenaza, veredicto in enlaces:
            conn.execute(
                """INSERT OR IGNORE INTO threat_technologies(threat_id,technology_id,
                       matched_alias,confidence,version_verdict)
                   VALUES(?,?,?,1.0,?)""", (amenaza, tec, "alias", veredicto))

        # --- ejecuciones ---
        conn.execute(
            """INSERT INTO executions(kind,started_at,finished_at,status,sources_ok,
                   sources_failed,threats_new,threats_alerted)
               VALUES('daily',?,?,'success',4,1,12,3)""",
            (_iso(ahora - timedelta(hours=1)), _iso(ahora - timedelta(minutes=55))))
        conn.execute(
            """INSERT INTO executions(kind,started_at,finished_at,status,sources_ok,
                   sources_failed,threats_new,threats_alerted)
               VALUES('daily',?,?,'partial',3,2,7,1)""",
            (_iso(ahora - timedelta(days=1)), _iso(ahora - timedelta(days=1, minutes=-5))))
        conn.execute(
            """INSERT INTO executions(kind,started_at,finished_at,status,sources_ok,
                   sources_failed,threats_new,threats_alerted)
               VALUES('monthly','2026-08-31T22:00:00Z','2026-08-31T22:03:00Z','success',0,0,0,0)""")


class _BasePanel(unittest.TestCase):
    """Infraestructura común: base temporal bajo data/, aplicación en modo prueba."""

    sembrar = True

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "panel.db")
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
        cli = cls._sesion(USUARIO, CLAVE)
        resp = cli.get("/")
        cls.status = resp.status_code
        cls.html = resp.data.decode("utf-8", "replace")

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()
        cls.dir.cleanup()

    @classmethod
    def _sesion(cls, usuario: str, clave: str):
        cli = cls.app.test_client()
        cli.post("/login", data={"usuario": usuario, "password": clave})
        return cli

    def _leyenda(self, nombre: str, dentro: str = "") -> str:
        """Valor <b>…</b> que sigue a un nombre en una leyenda; '' si no está.
        ``dentro`` acota la búsqueda a un fragmento (p. ej. una figura)."""
        m = re.search(re.escape(nombre) + r" <b>([^<]+)</b>", dentro or self.html)
        return m.group(1) if m else ""

    def _figura(self, tipo: str, indice: int = 0) -> str:
        """HTML de la figura n-ésima de un tipo (grafico-dona, grafico-progreso…)."""
        figuras = re.findall(r'<figure class="grafico-envoltorio ' + re.escape(tipo) + r'">.*?</figure>',
                             self.html, re.S)
        self.assertGreater(len(figuras), indice, f"no hay figura {tipo} nº {indice}")
        return figuras[indice]


# ==========================================================================
# Panel con datos
# ==========================================================================
class TestPanelConDatos(_BasePanel):

    # ---------------------------------------------------------- respuesta
    def test_responde_200_con_sesion(self):
        self.assertEqual(self.status, 200)
        self.assertIn("Panel de estado", self.html)
        self.assertIn("Proceso de inteligencia", self.html)

    def test_lector_solo_lectura_tambien_ve_el_panel(self):
        cli = self._sesion(LECTOR, CLAVE_LECTOR)
        resp = cli.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode("utf-8", "replace")
        self.assertIn("Proceso de inteligencia", html)
        # el lector no recibe enlaces a Credenciales (ruta de administrador)
        self.assertNotIn('href="/credenciales/"', html)

    def test_sin_sesion_redirige_al_login(self):
        resp = self.app.test_client().get("/")
        self.assertIn(resp.status_code, (302, 303))
        self.assertIn("/login", resp.headers.get("Location", ""))

    # ---------------------------------------------------------------- CSP
    def test_sin_estilos_en_linea_ni_manejadores(self):
        self.assertIsNone(RE_STYLE.search(self.html), "hay un atributo style=")
        self.assertIsNone(RE_ON.search(self.html), "hay un manejador on*=")
        self.assertIsNone(RE_SCRIPT_INLINE.search(self.html), "hay un <script> en línea")

    def test_fill_y_stroke_solo_valores_permitidos(self):
        valores = {v for _, v in RE_FILL_STROKE.findall(self.html)}
        self.assertTrue(valores, "no se encontró ningún fill/stroke (¿hay SVG?)")
        self.assertTrue(valores <= {"none", "currentColor", "transparent"},
                        f"colores literales en atributos SVG: {valores}")

    def test_sin_recursos_externos(self):
        externos = [u for u in re.findall(r'(?:src|href)="([^"]+)"', self.html)
                    if re.match(r"^(https?:)?//", u, re.I)]
        self.assertEqual(externos, [], f"recursos externos: {externos}")

    # ----------------------------------------------------------- gráficos
    def test_graficos_presentes(self):
        self.assertGreaterEqual(self.html.count('<svg class="grafico"'), 8,
                                "4 chispas + barras apiladas + dona + barras horizontales + dona de fuentes")
        # tres barras de calidad del dato + la del disco
        self.assertGreaterEqual(self.html.count("grafico-progreso"), 3)
        self.assertEqual(self.html.count('class="flujo-paso '), 5)
        for tipo in ("grafico-chispa", "grafico-barras-apiladas", "grafico-dona",
                     "grafico-barras-horizontales", "grafico-progreso"):
            self.assertIn(tipo, self.html)
        # accesibilidad: cada svg de gráfico lleva role e aria-label
        for svg in re.findall(r"<svg class=\"grafico\"[^>]*>", self.html):
            self.assertIn('role="img"', svg)
            self.assertIn("aria-label=", svg)

    def test_todo_panel_lleva_h2_y_sub(self):
        cabeceras = re.findall(r'<div class="panel-cabecera">(.*?)</div>\s*<div class="panel-cuerpo',
                               self.html, re.S)
        self.assertGreaterEqual(len(cabeceras), 8)
        for cab in cabeceras:
            self.assertIn("<h2>", cab)
            self.assertIn('class="sub"', cab)

    # ------------------------------------------------- coherencia de cifras
    def test_dona_del_mes_coincide_con_estadisticas(self):
        stats = queries.estadisticas_mes(self.conn, MES_ACTUAL, excluir_bajas=True)
        dona = self._figura("grafico-dona", 0)
        centro = re.search(r'<text class="dona-centro" [^>]*>([^<]+)</text>', dona)
        self.assertIsNotNone(centro)
        self.assertEqual(centro.group(1), fmt(stats["total"]))
        # Regla interna (2026-09-08): las bajas no se reportan, la dona tiene TRES porciones.
        for nombre, clave in (("Críticas", "criticas"), ("Altas", "altas"),
                              ("Medias", "medias")):
            self.assertEqual(self._leyenda(nombre, dona), fmt(stats[clave]), nombre)
        self.assertNotIn("Bajas", dona)
        # la métrica muestra el mismo total que el centro de la dona
        self.assertIn(f'<div class="valor">{fmt(stats["total"])}</div>', self.html)
        self.assertIn(f'<div class="valor">{fmt(stats["criticas"])}</div>', self.html)
        self.assertIn(f'<div class="valor">{fmt(stats["en_kev"])}</div>', self.html)

    def test_barras_apiladas_coinciden_con_la_tabla_de_evolucion(self):
        evolucion = queries.evolucion_mensual(self.conn, 6, excluir_bajas=True)
        self.assertEqual(len(evolucion), 6)
        for fila in evolucion:
            etiqueta = vista._mes_corto(fila["month"]).replace("\n", " ")   # en el <title> va en una línea
            self.assertIn(f"{etiqueta} · Críticas: {fmt(fila['criticas'])}", self.html,
                          "cada barra lleva <title> con el valor del mes")
            # Adaptado el 2026-09-15 (auditoría de tableros, punto 12): la línea ya no se
            # llama «En KEV» a secas, porque en la leyenda parecía un cuarto grupo que se
            # suma a las tres severidades y no lo es: son las mismas amenazas.
            self.assertIn(f"{etiqueta} · Con explotación confirmada (ya contadas arriba): "
                          f"{fmt(fila['en_kev'])}", self.html)
            # la tabla debajo muestra el mismo mes con el mismo total
            self.assertIn(f"<td class=\"num\">{fmt(fila['total'])}</td>", self.html)
        # orden cronológico ascendente en el eje X
        self.assertLess(self.html.find(">abril</tspan>"), self.html.find(">septiembre</tspan>"))  # mes arriba, año debajo
        self.assertIn("de los últimos 6 meses", self.html)
        apiladas = self._figura("grafico-barras-apiladas")
        self.assertEqual(self._leyenda("Críticas", apiladas), fmt(sum(f["criticas"] for f in evolucion)))
        self.assertEqual(self._leyenda("Con explotación confirmada (ya contadas arriba)", apiladas),
                         fmt(sum(f["en_kev"] for f in evolucion)))
        # Y la página dice que esa leyenda suma los seis meses y que la línea no se suma.
        self.assertIn(f"suma de los {fmt(len(evolucion))} meses", self.html)
        self.assertIn("<strong>no se suma</strong>", self.html)

    def test_procedencia_coincide_con_la_base(self):
        # Adaptado el 2026-09-15 (revisión de claridad): la barra de procedencia deja
        # fuera la severidad baja, igual que la tarjeta «Amenazas del periodo». Antes la
        # misma pantalla daba dos totales del mismo mes (1.622 y 1.532 en producción) y
        # dos porcentajes del mismo dato (77 % y 80 %).
        conteo = {r[0]: r[1] for r in self.conn.execute(
            "SELECT severity_source, COUNT(*) FROM threats WHERE month=? "
            "AND (severity IS NULL OR severity <> 'Low') GROUP BY 1", (MES_ACTUAL,))}
        fig = self._figura("grafico-progreso", 0)
        self.assertEqual(self._leyenda("CVSS oficial (NVD)", fig), fmt(conteo.get("nvd", 0)))
        self.assertEqual(self._leyenda("CVSS calculado del vector", fig), fmt(conteo.get("vector", 0)))
        self.assertEqual(self._leyenda("Severidad tomada del catálogo KEV", fig), fmt(conteo.get("kev", 0)))
        self.assertEqual(self._leyenda("Severidad estimada", fig), fmt(conteo.get("heuristic", 0)))
        self.assertEqual(conteo.get("nvd"), 4)
        # La barra suma exactamente el total de la tarjeta, y su porcentaje de CVSS
        # oficial es el MISMO que el del paso «Enriquecimiento» del flujo.
        stats = queries.estadisticas_mes(self.conn, MES_ACTUAL, excluir_bajas=True)
        self.assertEqual(sum(conteo.values()), stats["total"])
        self.assertIn(f"{fmt(int(round(stats['pct_con_cvss_real'])))} % del mes con CVSS oficial",
                      self.html)

    def test_enriquecimiento_e_inventario(self):
        # Adaptado el 2026-09-15 (auditoría de tableros, punto 11): el bloque cuenta las
        # AMENAZAS CON CVE que la plataforma reporta, con el mismo criterio que el resto
        # (sin la severidad que no se reporta ni las amenazas cerradas). En producción
        # pasó de «4.515 CVE» a «4.402 amenazas con CVE», que es lo que dice Amenazas.
        pendientes = self.conn.execute(
            """SELECT COUNT(*) FROM threats WHERE cve IS NOT NULL AND enriched_at IS NULL
                 AND (severity IS NULL OR severity <> 'Low')
                 AND (estado IS NULL OR estado NOT IN ('descartada', 'falso_positivo'))""").fetchone()[0]
        enr = self._figura("grafico-progreso", 1)
        self.assertEqual(self._leyenda("Pendientes de consultar", enr), fmt(pendientes))
        inv = self._figura("grafico-progreso", 2)
        self.assertEqual(self._leyenda("Con versión registrada", inv), "1")
        self.assertEqual(self._leyenda("Sin versión", inv), "2")
        self.assertIn("1 de 3 tecnologías con versión", self.html)

    def test_pendientes_de_alertar_total_y_filas(self):
        # Desde el 2026-09-05 el indicador usa el criterio real de la alerta diaria
        # (relevancia o KEV, con activos afectados cuando se ha podido comprobar).
        from threatintel import config
        cfg = config.load(self.conn)
        clasificacion = queries.clasificar_pendientes(self.conn, cfg=cfg, persistir=False)
        total = len(clasificacion["alertar"])
        self.assertIn(f'<div class="valor">{fmt(total)}</div>', self.html)
        self.assertIn("superan el criterio de la alerta diaria", self.html)
        excluidas = sum(clasificacion["conteo"].values())
        self.assertIn(f"{fmt(excluidas)} excluidas por el filtro", self.html)
        antiguo = self.conn.execute(
            "SELECT COUNT(*) FROM threats WHERE alerted_at IS NULL AND severity IN ('Critical','High')").fetchone()[0]
        self.assertEqual(antiguo, 4)              # la base de prueba no cambia

    # ----------------------------------------------------------- tecnologías
    def test_tecnologias_con_enlace_filtrado_y_nota_sin_version(self):
        self.assertIn('href="/amenazas/?tec=cisco-ios-xe&amp;mes=2026-09"', self.html)
        self.assertIn("sin versión", self.html)
        # Windows Server tiene versión: su fila no lleva la nota
        fila = re.search(r'<text class="etiqueta-valor"[^>]*>[^<]*(<tspan[^>]*>[^<]*</tspan>)?</text>',
                         self.html)
        self.assertIsNotNone(fila)
        top = queries.top_tecnologias(self.conn, MES_ACTUAL, 8)
        primera = top[0]
        self.assertIn(f"{primera['name']} · Críticas: {fmt(primera['criticas'])}", self.html)
        # la tabla debajo muestra la criticidad en español, no «critical»
        self.assertIn(">Crítica</span>", self.html)
        self.assertNotIn(">critical</span>", self.html)

    def test_nombres_de_la_base_llegan_escapados(self):
        self.assertNotIn("<script>alert(1)</script>", self.html)
        self.assertNotIn('<script>alert("f")</script>', self.html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", self.html)
        self.assertIn("Fuente &lt;script&gt;alert(&#34;f&#34;)", self.html)

    # --------------------------------------------------------------- fuentes
    def test_dona_de_fuentes_solo_cuenta_activas(self):
        dona = self._figura("grafico-dona", 1)
        self.assertEqual(self._leyenda("Operativas", dona), "3")
        self.assertEqual(self._leyenda("Degradadas", dona), "1")
        self.assertEqual(self._leyenda("Caídas", dona), "1")
        self.assertEqual(self._leyenda("Sin comprobar", dona), "1")
        self.assertIn('<text class="dona-centro" x="100" y="104" text-anchor="middle">6</text>', dona)
        self.assertNotIn("Fuente desactivada", self.html)
        self.assertIn("1 desactivadas de las 7 registradas", self.html)
        # lista de no operativas con enlace al detalle de la fuente caída (id 4)
        self.assertIn('href="/fuentes/4"', self.html)
        self.assertRegex(self.html, r"Sin comprobar\s*</td>")

    # ----------------------------------------------------------------- flujo
    def test_flujo_valores_y_estados(self):
        # Recolección: 3 operativas de 6 activas, 1 caída (16,7 % < 20 %) → atención
        self.assertIn('<div class="valor">3 / 6</div>', self.html)
        recoleccion = re.search(r'<div class="flujo-paso (\w+)"><div class="titulo">'
                                r'<span class="punto \w+"[^>]*></span><a href="/fuentes/">Recolección</a>',
                                self.html)
        self.assertIsNotNone(recoleccion)
        self.assertEqual(recoleccion.group(1), "atencion")
        # Correlación: 12 nuevas en la última diaria (correcta) → ok
        self.assertRegex(self.html, r'flujo-paso ok"><div class="titulo">.*?Correlación</a></div>'
                                    r'<div class="valor">12</div>')
        # Alerta: 1 alertada en 24 h, última diaria hoy → ok
        self.assertRegex(self.html, r'flujo-paso ok"><div class="titulo">.*?Alerta</div>'
                                    r'<div class="valor">1</div>')
        # Informe mensual generado el 31 de agosto de 2026. Adaptado el 2026-09-15: era
        # la única fecha del Panel en formato numérico («30/09/2026»).
        self.assertIn('<div class="valor">31 de agosto</div>', self.html)
        self.assertIn("último informe generado el 31 de agosto de 2026", self.html)
        self.assertNotRegex(self.html, r"previsto el \d{2}/\d{2}/\d{4}")

    # ------------------------------------------------------------ ejecuciones
    def test_ejecuciones_en_espanol_con_alertadas(self):
        self.assertIn("<th class=\"num\">Alertadas</th>", self.html)
        self.assertIn("Recolección diaria", self.html)
        self.assertIn("Informe mensual", self.html)
        self.assertIn(">Correcta</span>", self.html)
        self.assertIn(">Parcial</span>", self.html)
        self.assertIn("· 1 con fallo", self.html)
        self.assertNotIn("<td>daily</td>", self.html)

    # ------------------------------------------------------------ formato
    def test_numeros_en_formato_espanol(self):
        # los porcentajes de las métricas usan coma decimal
        self.assertRegex(self.html, r"\d+,\d % del total|\d+ % del total")
        self.assertNotRegex(self.html, r"\d+\.\d % del total")

    def test_glosario_al_final(self):
        self.assertIn("Cómo leer estos datos", self.html)
        self.assertGreater(self.html.find("Cómo leer estos datos"), self.html.find("Últimas ejecuciones"))


# ==========================================================================
# Base vacía
# ==========================================================================
class TestPanelVacio(_BasePanel):
    sembrar = False

    def test_responde_200_sin_datos(self):
        self.assertEqual(self.status, 200)
        self.assertIn("Sin amenazas registradas todavía.", self.html)

    def test_estados_vacios_y_flujo_inactivo(self):
        self.assertIn("grafico-vacio", self.html)
        self.assertEqual(self.html.count('class="flujo-paso inactivo"'), 5)
        self.assertIn("nunca generado", self.html)
        self.assertIn("No hay fuentes registradas.", self.html)
        self.assertIn("No hay nada pendiente de alertar.", self.html)

    def test_csp_tambien_en_vacio(self):
        self.assertIsNone(RE_STYLE.search(self.html))
        self.assertIsNone(RE_ON.search(self.html))
        self.assertIsNone(RE_SCRIPT_INLINE.search(self.html))


# ==========================================================================
# Funciones puras de la vista
# ==========================================================================
class TestUmbralesFlujo(unittest.TestCase):

    def test_recoleccion(self):
        self.assertEqual(vista._estado_recoleccion(0, 0), "inactivo")
        self.assertEqual(vista._estado_recoleccion(0, 55), "ok")
        self.assertEqual(vista._estado_recoleccion(3, 55), "atencion")   # 5,5 %
        self.assertEqual(vista._estado_recoleccion(10, 55), "atencion")  # 18 %
        self.assertEqual(vista._estado_recoleccion(11, 55), "critico")   # 20 %
        self.assertEqual(vista._estado_recoleccion(30, 55), "critico")

    def test_correlacion(self):
        self.assertEqual(vista._estado_correlacion(None), "inactivo")
        self.assertEqual(vista._estado_correlacion({"status": "success"}), "ok")
        self.assertEqual(vista._estado_correlacion({"status": "partial"}), "atencion")
        self.assertEqual(vista._estado_correlacion({"status": "failed"}), "critico")

    def test_enriquecimiento(self):
        self.assertEqual(vista._estado_enriquecimiento(0, 0), "inactivo")
        self.assertEqual(vista._estado_enriquecimiento(500, 3054), "ok")
        self.assertEqual(vista._estado_enriquecimiento(2054, 3054), "atencion")

    def test_alerta(self):
        self.assertEqual(vista._estado_alerta(None), "inactivo")
        self.assertEqual(vista._estado_alerta(0), "ok")
        self.assertEqual(vista._estado_alerta(1), "ok")
        self.assertEqual(vista._estado_alerta(2), "atencion")
        self.assertEqual(vista._estado_alerta(3), "critico")

    def test_informe(self):
        self.assertEqual(vista._estado_informe(None), "inactivo")
        self.assertEqual(vista._estado_informe(3), "ok")
        self.assertEqual(vista._estado_informe(40), "atencion")

    def test_dias_desde(self):
        ahora = datetime(2026, 9, 3, 15, 0, tzinfo=timezone.utc)
        self.assertEqual(vista._dias_desde("2026-09-03T01:00:00Z", ahora), 0)
        self.assertEqual(vista._dias_desde("2026-09-02T23:59:00Z", ahora), 1)
        self.assertEqual(vista._dias_desde("2026-08-31T22:00:00Z", ahora), 3)
        self.assertIsNone(vista._dias_desde(None, ahora))
        self.assertIsNone(vista._dias_desde("no es fecha", ahora))


class TestPreparacionDeDatos(unittest.TestCase):

    def test_mes_corto(self):
        self.assertEqual(vista._mes_corto("2026-09"), "septiembre\n2026")   # dos líneas: mes y año completo
        self.assertEqual(vista._mes_corto("2025-12"), "diciembre\n2025")
        self.assertEqual(vista._mes_corto(None), "—")
        self.assertEqual(vista._mes_corto("raro"), "raro")

    def test_series_evolucion_deriva_bajas_si_faltan(self):
        evo = [{"month": "2026-08", "total": 100, "criticas": 10, "altas": 20, "medias": 60, "en_kev": 3},
               {"month": "2026-09", "total": 50, "criticas": 5, "altas": 10, "medias": 30,
                "en_kev": 1, "bajas": 5}]
        s = vista._series_evolucion(evo, sin_bajas=False)
        self.assertEqual(s["categorias"], ["agosto\n2026", "septiembre\n2026"])
        self.assertEqual(s["bajas"], [10, 5])
        self.assertEqual([x["clave"] for x in s["series"]], ["critico", "alto", "medio", "bajo"])
        # con la regla interna (por omisión) la serie tiene exactamente tres segmentos
        s3 = vista._series_evolucion(evo)
        self.assertEqual([x["clave"] for x in s3["series"]], ["critico", "alto", "medio"])
        self.assertEqual(s["linea"]["valores"], [3, 1])
        self.assertEqual(s["chispas"]["total"], [100, 50])

    def test_series_evolucion_vacia(self):
        s = vista._series_evolucion([])
        self.assertEqual(s["categorias"], [])
        self.assertEqual(s["chispas"]["criticas"], [])

    def test_resumen_fuentes_ignora_desactivadas(self):
        fuentes = [
            {"enabled": 1, "kind": "rss", "estado": "ok"},
            {"enabled": 1, "kind": "nvd_api", "estado": "ok"},
            {"enabled": 1, "kind": "rss", "estado": "caida"},
            {"enabled": 1, "kind": "rss", "estado": "degradada"},
            {"enabled": 1, "kind": "rss", "estado": "sin_datos"},
            {"enabled": 0, "kind": "rss", "estado": "desactivada"},
        ]
        r = vista._resumen_fuentes_activas(fuentes)
        self.assertEqual((r["activas"], r["operativas"], r["caidas"], r["degradadas"],
                          r["sin_comprobar"], r["desactivadas"], r["total"]), (5, 2, 1, 1, 1, 1, 6))
        self.assertEqual((r["feeds"], r["apis"]), (4, 1))
        self.assertEqual(len(r["no_operativas"]), 3)
        self.assertEqual(vista._resumen_fuentes_activas([])["activas"], 0)

    def test_partes_disco_por_ocupacion(self):
        self.assertEqual(vista._partes_disco(None), [])
        holgado = vista._partes_disco({"total_gb": 100.0, "libre_gb": 60.0, "usado_pct": 40.0})
        self.assertEqual(holgado[0]["clave"], "acento")
        self.assertEqual((holgado[0]["valor"], holgado[1]["valor"]), (40.0, 60.0))
        self.assertEqual((holgado[0]["nombre"], holgado[1]["nombre"]), ("Usado (GB)", "Libre (GB)"))
        self.assertEqual(vista._partes_disco({"total_gb": 100.0, "libre_gb": 20.0, "usado_pct": 80.0})[0]["clave"], "medio")
        self.assertEqual(vista._partes_disco({"total_gb": 100.0, "libre_gb": 5.0, "usado_pct": 95.0})[0]["clave"], "critico")
        self.assertEqual(vista._partes_disco({"total_gb": 10.0, "libre_gb": 1.5, "usado_pct": 85.0})[0]["clave"], "critico")

    def test_partes_procedencia_y_enriquecimiento(self):
        partes = vista._partes_procedencia({"nvd": 18, "vector": 0, "kev": 0, "heuristic": 106, "otros": 0})
        self.assertEqual([p["valor"] for p in partes], [18, 0, 0, 106])
        self.assertEqual(len(vista._partes_procedencia({"otros": 2})), 5)
        enr = vista._partes_enriquecimiento({"con_cve": 3054, "con_cvss_oficial": 988,
                                             "consultadas_sin_cvss": 12, "pendientes": 2054})
        self.assertEqual([p["valor"] for p in enr], [988, 12, 2054])
        self.assertEqual(len(vista._partes_enriquecimiento({"con_cvss_oficial": 1, "pendientes": 0})), 2)

    def test_etiquetar_ejecuciones(self):
        filas = vista._etiquetar_ejecuciones([{"kind": "daily", "status": "success"},
                                              {"kind": "raro", "status": "extraño"}])
        self.assertEqual((filas[0]["tipo_es"], filas[0]["estado_es"], filas[0]["estado_clase"]),
                         ("Recolección diaria", "Correcta", "ok"))
        self.assertEqual((filas[1]["tipo_es"], filas[1]["estado_es"], filas[1]["estado_clase"]),
                         ("raro", "extraño", "neutra"))


if __name__ == "__main__":
    unittest.main()

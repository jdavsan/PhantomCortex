#!/usr/bin/env python3
"""Pruebas de regresion de los defectos encontrados en la auditoria.

Cada prueba corresponde a un hallazgo concreto y documentado. El sistema
anterior no tenia ninguna prueba automatizada, y todos los defectos de datos
estaban en cuatro funciones: el matching de tecnologias, la estimacion de
severidad, la extraccion de CVE y el filtro temporal.

Ejecucion:
    .venv/bin/python -m unittest discover -s tests -v
    .venv/bin/python tests/test_regresiones.py
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threatintel import db, identity, scoring, versions  # noqa: E402
from threatintel import matching, translate, notify       # noqa: E402
from threatintel.config import split_emails               # noqa: E402


# ==========================================================================
# P1-5: falsos positivos por coincidencia de subcadena
# ==========================================================================
class TestFalsosPositivosMatching(unittest.TestCase):
    """'edge' casaba dentro de 'knowledge' (117 casos en agosto de 2026) y
    'java' dentro de 'javascript' (14 casos)."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        cls.ruta = str(Path(cls.dir.name) / "prueba.db")
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            matching.seed_inventario(conn, solo_nuevas=True)
        cls.conn = db.connect(cls.ruta)
        cls.inv = matching.compilar_inventario(cls.conn)

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()
        cls.dir.cleanup()

    def _nombres(self, texto: str) -> set[str]:
        return {c.name for c in matching.encontrar(texto, self.inv, titulo=texto)}

    def test_edge_no_casa_dentro_de_knowledge(self):
        texto = ("China Is Training Military AI With Knowledge Extracted From "
                 "American Models")
        self.assertNotIn("Microsoft Edge", self._nombres(texto))

    def test_edge_no_casa_dentro_de_acknowledge(self):
        self.assertNotIn("Microsoft Edge",
                         self._nombres("Acknowledged issue in the reporting module"))

    def test_java_no_casa_dentro_de_javascript(self):
        texto = ("Shai-Hulud Supply Chain Attack Compromises Keyv and Hundreds "
                 "of npm Packages via JavaScript")
        self.assertNotIn("Java", self._nombres(texto))

    def test_edge_si_casa_cuando_es_de_verdad(self):
        self.assertIn("Microsoft Edge",
                      self._nombres("Microsoft Edge zero-day exploited in the wild"))

    def test_java_si_casa_cuando_es_de_verdad(self):
        self.assertIn("Java",
                      self._nombres("Critical Java deserialization flaw in Apache Struts"))

    def test_tecnologias_reales_se_detectan(self):
        casos = [
            ("Unauthenticated SQL injection in Moodle 4.3", "Moodle"),
            ("PostgreSQL 15 privilege escalation", "PostgreSQL"),
            ("Critical GitLab GraphQL vulnerability", "GitLab"),
            ("pfSense CE 2.7 command injection", "pfSense"),
        ]
        for texto, esperada in casos:
            with self.subTest(texto=texto):
                self.assertIn(esperada, self._nombres(texto))


# ==========================================================================
# P1-12: la fecha de publicacion no debe formar parte de la identidad
# ==========================================================================
class TestIdentidadYDeduplicacion(unittest.TestCase):
    """Los feeds republican la misma entrada con fecha nueva cada dia. Con
    md5(titulo + fecha) el sistema guardaba 11.007 registros para 5.638
    amenazas reales, y re-alertaba el mismo aviso hasta 5 dias seguidos."""

    def test_misma_amenaza_distinta_fecha_misma_huella(self):
        a = identity.fingerprint(month="2026-03",
                                 titulo="DSA-6157-1 chromium - security update")
        b = identity.fingerprint(
            month="2026-03",
            titulo="[Actualizado] DSA-6157-1 chromium - security update")
        self.assertEqual(a, b)

    def test_avisos_distintos_del_mismo_paquete_no_se_fusionan(self):
        a = identity.fingerprint(month="2026-03",
                                 titulo="DSA-6157-1 chromium - security update")
        b = identity.fingerprint(month="2026-03",
                                 titulo="DSA-6151-1 chromium - security update")
        self.assertNotEqual(a, b)

    def test_mismo_cve_de_fuentes_distintas_misma_huella(self):
        a = identity.fingerprint(month="2026-08", cve="CVE-2026-53224",
                                 titulo="Bleeping: RCE en Apache")
        b = identity.fingerprint(month="2026-08", cve="cve-2026-53224",
                                 titulo="THN: Apache RCE bug")
        self.assertEqual(a, b)

    def test_url_generica_no_se_usa_como_identidad(self):
        """El recolector antiguo hacia link = entry.get('link', source['url']),
        asi que las entradas sin enlace heredaban la URL de la fuente."""
        for generica in ("https://cybersecuritynews.com/feed/",
                         "https://www.cisa.gov/cybersecurity-advisories/all.xml",
                         "https://ejemplo.com/"):
            with self.subTest(url=generica):
                self.assertIsNone(identity.normalizar_url(generica))

    def test_url_de_articulo_si_identifica(self):
        self.assertIsNotNone(identity.normalizar_url(
            "https://lists.debian.org/debian-security-announce/2026/msg00066.html"))

    def test_extraer_cve(self):
        self.assertEqual(
            identity.extraer_cve("DSA-6480-1", "Fixes CVE-2026-53224 and more"),
            "CVE-2026-53224")
        self.assertIsNone(identity.extraer_cve("sin identificador"))

    def test_extraer_id_aviso(self):
        casos = [("DSA-6157-1 chromium", "DSA-6157-1"),
                 ("USN-8643-1: Linux kernel", "USN-8643-1"),
                 ("RHSA-2026:1234 kernel", "RHSA-2026:1234"),
                 ("sin aviso", None)]
        for texto, esperado in casos:
            with self.subTest(texto=texto):
                self.assertEqual(identity.extraer_id_aviso(texto), esperado)


# ==========================================================================
# P1-1: la puntuacion CVSS era inventada
# ==========================================================================
class TestSeveridadYCvss(unittest.TestCase):
    """estimate_severity() devolvia las constantes 9.0 / 7.5 / 5.0 y el informe
    las presentaba como CVSS oficial ante la direccion."""

    def test_vector_cvss31_coincide_con_el_valor_oficial(self):
        casos = [
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
            ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ]
        for vector, esperado in casos:
            with self.subTest(vector=vector):
                self.assertEqual(scoring.de_vector(vector)[0], esperado)

    def test_vector_no_calculable_no_inventa_valor(self):
        for vector in ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                       "basura", "", None):
            with self.subTest(vector=vector):
                self.assertIsNone(scoring.de_vector(vector)[0])

    def test_heuristica_no_devuelve_puntuacion(self):
        """Cuando el origen es heuristico, cvss_score debe quedar en None."""
        resultado = scoring.decidir(titulo="Reflected XSS vulnerability in plugin")
        self.assertEqual(resultado["severity_source"], "heuristic")
        self.assertIsNone(resultado["cvss_score"])

    def test_nvd_tiene_precedencia_sobre_el_vector(self):
        resultado = scoring.decidir(
            nvd_score=9.8,
            vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(resultado["severity_source"], "nvd")
        self.assertEqual(resultado["cvss_score"], 9.8)

    def test_kev_eleva_el_suelo_de_severidad(self):
        resultado = scoring.decidir(titulo="Minor information leak vulnerability",
                                    in_kev=True)
        self.assertLessEqual(scoring.orden_severidad(resultado["severity"]),
                             scoring.orden_severidad("High"))

    def test_noticia_no_tecnica_no_escala(self):
        """Un articulo sobre el fenomeno del ransomware no es una vulnerabilidad
        critica. El sistema anterior marcaba Critical cualquier texto con la
        palabra 'ransomware'."""
        for titulo in ("Ransomware gang arrested by Europol",
                       "The rise of ransomware: a 2026 market report",
                       "Webinar: how to defend against zero-day attacks",
                       "Top 10 security predictions for 2027"):
            with self.subTest(titulo=titulo):
                severidad, _ = scoring.heuristica(titulo)
                self.assertEqual(severidad, "Low")

    def test_vulnerabilidad_real_si_escala(self):
        casos = [("Unauthenticated RCE in Apache Struts", "Critical"),
                 ("Actively exploited zero-day in Chrome", "Critical"),
                 ("SQL injection in Moodle allows exfiltration", "High"),
                 ("Reflected XSS vulnerability in plugin", "Medium")]
        for titulo, esperada in casos:
            with self.subTest(titulo=titulo):
                self.assertEqual(scoring.heuristica(titulo)[0], esperada)

    def test_relevancia_baja_si_la_version_no_esta_afectada(self):
        base = {"criticality": "critical", "exposure": "internet",
                "systems_count": 4}
        afectada = scoring.relevancia(
            severity="Critical", cvss_score=9.8, in_kev=True,
            tecnologias=[{**base, "version_verdict": "affected"}])
        no_afectada = scoring.relevancia(
            severity="Critical", cvss_score=9.8, in_kev=True,
            tecnologias=[{**base, "version_verdict": "not_affected"}])
        self.assertGreater(afectada, no_afectada * 2)


# ==========================================================================
# Version: prudencia ante la ambiguedad
# ==========================================================================
class TestVersiones(unittest.TestCase):

    def test_extrae_restricciones_habituales(self):
        for texto in ("affects versions prior to 4.3",
                      "all versions before 4.3 are vulnerable",
                      "up to and including 4.2",
                      "4.2 and earlier",
                      "fixed in 4.3"):
            with self.subTest(texto=texto):
                self.assertTrue(versions.extraer_restricciones(texto),
                                f"sin restricciones en: {texto}")

    def test_sin_version_instalada_es_sin_determinar(self):
        restricciones = versions.extraer_restricciones("prior to 4.3")
        veredicto, _ = versions.evaluar(None, restricciones)
        self.assertEqual(veredicto, "unknown")

    def test_sin_restricciones_es_sin_determinar(self):
        veredicto, _ = versions.evaluar("4.5", [])
        self.assertEqual(veredicto, "unknown")

    def test_version_posterior_no_afectada(self):
        restricciones = versions.extraer_restricciones("versions prior to 4.3")
        veredicto, _ = versions.evaluar("4.5", restricciones)
        self.assertEqual(veredicto, "not_affected")

    def test_version_anterior_afectada(self):
        restricciones = versions.extraer_restricciones("versions prior to 4.3")
        veredicto, _ = versions.evaluar("4.1", restricciones)
        self.assertEqual(veredicto, "affected")


# ==========================================================================
# P1-8: dos traductores que se destruian entre si
# ==========================================================================
class TestTraduccion(unittest.TestCase):
    """'chromium' se convertia en 'cromo' y 'Patch Tuesday' en 'Patch Martes'."""

    def test_terminos_de_producto_quedan_protegidos(self):
        for termino in ("Chromium", "Patch Tuesday", "Microsoft Edge",
                        "Apache HTTP Server", "Moodle", "PostgreSQL"):
            with self.subTest(termino=termino):
                protegido, mapa = translate.proteger(f"A flaw in {termino} allows RCE")
                self.assertIn(termino, mapa.values())
                self.assertNotIn(termino, protegido)

    def test_cve_y_versiones_quedan_protegidos(self):
        texto = "CVE-2026-53224 affects Apache HTTP Server 2.4.58 and earlier"
        _, mapa = translate.proteger(texto)
        valores = " ".join(mapa.values())
        self.assertIn("CVE-2026-53224", valores)
        self.assertIn("2.4.58", valores)

    def test_restaurar_recupera_el_original(self):
        texto = "Chromium 4.3 flaw CVE-2026-1234"
        protegido, mapa = translate.proteger(texto)
        self.assertEqual(translate.restaurar(protegido, mapa), texto)

    def test_restaurar_no_deja_marcadores_huerfanos(self):
        protegido, mapa = translate.proteger("Chromium buffer overflow")
        # Simular que el traductor pierde un marcador
        recuperado = translate.restaurar(protegido, {})
        self.assertNotIn(translate.MARCADOR_INICIO, recuperado)

    def test_detecta_espanol(self):
        self.assertTrue(translate.parece_espanol(
            "Una vulnerabilidad crítica permite la ejecución de código remoto"))
        self.assertFalse(translate.parece_espanol(
            "A critical vulnerability allows remote code execution"))

    def test_limpiar_html(self):
        self.assertEqual(
            translate.limpiar_html("<p>Hola <b>mundo</b></p>&amp;fin"),
            "Hola mundo &fin")
        self.assertEqual(
            translate.limpiar_html("<script>alert(1)</script>texto"), "texto")


# ==========================================================================
# P0-2, P0-3, P0-6: destinatarios de correo
# ==========================================================================
class TestDestinatarios(unittest.TestCase):
    """El sistema anterior pasaba 'a@x,b@y' como una sola direccion de sobre."""

    def test_trocea_varios_separadores(self):
        self.assertEqual(split_emails("a@x.com, b@y.com;c@z.com"),
                         ["a@x.com", "b@y.com", "c@z.com"])

    def test_descarta_valores_no_validos(self):
        self.assertEqual(split_emails("basura, ok@dom.com"), ["ok@dom.com"])

    def test_lista_vacia_si_no_hay_nada(self):
        for valor in ("", None, "   ", ",,,"):
            with self.subTest(valor=valor):
                self.assertEqual(split_emails(valor), [])

    def test_elimina_duplicados(self):
        self.assertEqual(split_emails("a@x.com, A@X.COM"), ["a@x.com"])


# ==========================================================================
# P2-12: HTML de correo sin escapar
# ==========================================================================
class TestSeguridadCorreo(unittest.TestCase):

    def _amenaza(self, **extra):
        base = {
            "id": 1, "fingerprint": "x", "cve": None,
            "title_en": "t", "title_es": "t", "summary_en": None,
            "summary_es": None, "severity": "High",
            "severity_source": "heuristic", "cvss_score": None,
            "cvss_vector": None, "cvss_version": None, "epss_score": None,
            "in_kev": False, "kev_due_date": None, "published_at": None,
            "first_seen_at": "2026-09-02T10:00:00Z",
            "last_seen_at": "2026-09-02T10:00:00Z", "times_seen": 1,
            "impact_es": None, "remediation_es": None, "month": "2026-09",
            "relevance": 50.0, "technologies": [], "sources": [],
        }
        base.update(extra)
        return base

    def test_script_en_el_titulo_queda_escapado(self):
        html = notify.render_alert_email(
            [self._amenaza(title_es="<script>alert(1)</script>")], {})
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_img_con_onerror_queda_escapado(self):
        html = notify.render_alert_email(
            [self._amenaza(summary_es="<img src=x onerror=alert(2)>")], {})
        self.assertNotIn("<img", html.lower())

    def test_esquema_javascript_se_descarta(self):
        html = notify.render_alert_email(
            [self._amenaza(sources=[{"name": "X", "slug": "x",
                                     "url": "javascript:alert(3)"}])], {})
        self.assertNotIn("javascript:", html.lower())

    def test_url_legitima_se_conserva(self):
        html = notify.render_alert_email(
            [self._amenaza(sources=[{"name": "X", "slug": "x",
                                     "url": "https://example.com/aviso"}])], {})
        self.assertIn("https://example.com/aviso", html)

    def test_cvss_ausente_se_declara_no_disponible(self):
        html = notify.render_alert_email([self._amenaza(cvss_score=None)], {})
        self.assertIn("no disponible", html)

    def test_url_segura(self):
        for peligrosa in ("javascript:alert(1)", "JaVaScRiPt:alert(1)",
                          "data:text/html;base64,x", "//evil.com", ""):
            with self.subTest(url=peligrosa):
                self.assertEqual(notify.url_segura(peligrosa), "")
        self.assertEqual(notify.url_segura("https://ok.com/a"), "https://ok.com/a")


# ==========================================================================
# Robustez con base de datos vacia (division por cero del sistema anterior)
# ==========================================================================
class TestBaseDeDatosVacia(unittest.TestCase):
    """El generador anterior hacia len(criticas)/total*100 sin proteger total=0."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.ruta = str(Path(self.dir.name) / "vacia.db")
        db.init_db(self.ruta)

    def tearDown(self):
        self.dir.cleanup()

    def test_estadisticas_sin_datos_no_revienta(self):
        from threatintel import queries
        with db.connect(self.ruta) as conn:
            stats = queries.estadisticas_mes(conn, "2026-09")
        self.assertEqual(stats["total"], 0)
        self.assertEqual(stats["pct_criticas"], 0.0)

    def test_consultas_vacias_devuelven_listas(self):
        from threatintel import queries
        with db.connect(self.ruta) as conn:
            self.assertEqual(queries.del_mes(conn, "2026-09"), [])
            self.assertEqual(queries.pendientes_de_alerta(conn), [])
            self.assertEqual(queries.buscar(conn, texto="x"), ([], 0))
            self.assertEqual(queries.meses_disponibles(conn), [])

    def test_alerta_con_lista_vacia(self):
        html = notify.render_alert_email([], {})
        self.assertIn("Alerta", html)


if __name__ == "__main__":
    unittest.main(verbosity=2)


# ==========================================================================
# Defectos encontrados en la revision de seguridad del 2026-09-03
# ==========================================================================
class TestSeguridadInterfaz(unittest.TestCase):
    """Dos defectos reales detectados al auditar la interfaz recien escrita."""

    @classmethod
    def setUpClass(cls):
        import shutil
        from threatintel.paths import BASE_DIR
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "iface.db")
        db.init_db(cls.ruta)
        from webui import auth as _auth
        with db.session(cls.ruta) as conn:
            _auth.crear_usuario(conn, "pruebas", "PruebaSegura#2026",
                                rol="admin", actor="test")
            ahora = db.utcnow()
            conn.execute(
                """INSERT INTO sources(slug,name,url,kind,category,priority,
                       enabled,timeout_s,created_at,updated_at)
                   VALUES('s1','Fuente','https://x.invalid/f','rss','news',
                          'low',1,30,?,?)""", (ahora, ahora))
            conn.execute(
                """INSERT INTO threats(fingerprint,title_en,severity,
                       severity_source,first_seen_at,last_seen_at,month)
                   VALUES('hh','t','High','heuristic',?,?,'2026-09')""",
                (ahora, ahora))
            # URL maliciosa procedente de una fuente de terceros
            conn.execute(
                """INSERT INTO threat_sources(threat_id,source_id,url,seen_at)
                   VALUES(1,1,'javascript:alert(document.cookie)',?)""", (ahora,))

        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def _sesion(self):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": "pruebas",
                                 "password": "PruebaSegura#2026"})
        return cli

    def test_no_hay_redireccion_abierta(self):
        """'//evil.com/' empieza por barra y pasaba el filtro startswith('/'),
        pero el navegador lo trata como dominio externo."""
        import re as _re
        for destino in ("//evil.com/", "https://evil.com/", "/\\evil.com",
                        "http://evil.com", "javascript:alert(1)"):
            with self.subTest(destino=destino):
                cli = self.app.test_client()
                resp = cli.post(f"/login?siguiente={destino}",
                                data={"usuario": "pruebas",
                                      "password": "PruebaSegura#2026"})
                destino_real = resp.headers.get("Location", "")
                self.assertFalse(
                    _re.match(r"^(https?:)?//", destino_real, _re.I),
                    f"redireccion externa permitida: {destino_real}")

    def test_redireccion_local_legitima_se_respeta(self):
        cli = self.app.test_client()
        resp = cli.post("/login?siguiente=/amenazas/",
                        data={"usuario": "pruebas", "password": "PruebaSegura#2026"})
        self.assertEqual(resp.headers.get("Location"), "/amenazas/")

    def test_esquema_javascript_no_llega_al_href(self):
        """La URL de una amenaza viene de una fuente RSS: contenido de terceros.
        El autoescape de Jinja2 escapa caracteres pero no valida el esquema."""
        import re as _re
        cli = self._sesion()
        cuerpo = cli.get("/amenazas/1").data.decode("utf-8", "replace")
        peligrosos = [h for h in _re.findall(r'href="([^"]*)"', cuerpo)
                      if h.lower().startswith(("javascript:", "data:", "vbscript:"))]
        self.assertEqual(peligrosos, [], f"href peligroso: {peligrosos}")

    def test_filtro_url_segura(self):
        from webui.filtros import url_segura
        for peligrosa in ("javascript:alert(1)", "JaVaScRiPt:alert(1)",
                          "data:text/html,x", "vbscript:x", "//evil.com", ""):
            with self.subTest(url=peligrosa):
                self.assertEqual(url_segura(peligrosa), "")
        self.assertEqual(url_segura("https://ok.com/a"), "https://ok.com/a")

    def test_salud_json_exige_token_o_sesion(self):
        resp = self.app.test_client().get("/salud.json")
        self.assertEqual(resp.status_code, 403)

    def test_todas_las_rutas_post_exigen_csrf(self):
        import re as _re
        cli = self._sesion()
        rutas = {_re.sub(r"<[^>]+>", "1", str(r))
                 for r in self.app.url_map.iter_rules() if "POST" in r.methods}
        for ruta in sorted(rutas - {"/login"}):
            with self.subTest(ruta=ruta):
                self.assertEqual(cli.post(ruta, data={}).status_code, 400,
                                 f"{ruta} acepta POST sin token CSRF")


# ==========================================================================
# Revision OWASP Top 10:2025 y API Security Top 10:2023 del 2026-09-03
# ==========================================================================
class TestOwasp2025(unittest.TestCase):
    """Cuatro defectos confirmados con prueba ejecutada y corregidos."""

    def test_a01_ssrf_destinos_internos_prohibidos(self):
        """A01:2025 (SSRF). 'Probar fuente' alcanzaba http://127.0.0.1:11434
        (la API de Ollama) y la propia interfaz."""
        from threatintel.http import DestinoProhibido, validar_destino
        for url in ("http://127.0.0.1:11434/", "http://localhost/",
                    "http://169.254.169.254/latest/", "http://10.10.11.1/",
                    "http://[::1]:11434/", "http://192.168.1.1/",
                    "file:///etc/passwd", "gopher://127.0.0.1/",
                    "http://metadata.google.internal/"):
            with self.subTest(url=url):
                with self.assertRaises(DestinoProhibido):
                    validar_destino(url)

    def test_a01_ssrf_fetch_devuelve_error_sin_tocar_la_red(self):
        from threatintel import http as h
        r = h.fetch_feed("http://127.0.0.1:11434/api/tags", timeout=3, retries=0)
        self.assertFalse(r.ok)
        self.assertEqual(r.error, "destino_prohibido")
        self.assertIsNone(r.status, "no debio llegar a hacer la peticion")

    def test_a06_respuesta_acotada_a_15mb(self):
        """A06:2025 / API4. Un feed sin fin consumio 4,2 GB de RAM en 107 s."""
        from threatintel import http as h

        class RespuestaFalsa:
            headers = {}
            def __init__(self, tam): self._tam = tam
            def iter_content(self, chunk_size):
                enviado = 0
                while enviado < self._tam:
                    yield b"A" * chunk_size; enviado += chunk_size
            def close(self): pass

        contenido, excedido = h._leer_acotado(RespuestaFalsa(h.MAX_BYTES_RESPUESTA * 3),
                                              h.MAX_BYTES_RESPUESTA)
        self.assertTrue(excedido)
        self.assertEqual(contenido, b"")
        contenido, excedido = h._leer_acotado(RespuestaFalsa(1024 * 1024), h.MAX_BYTES_RESPUESTA)
        self.assertFalse(excedido)
        self.assertEqual(len(contenido), 1024 * 1024)

    def test_a06_content_length_excesivo_no_se_lee(self):
        from threatintel import http as h

        class R:
            headers = {"Content-Length": str(h.MAX_BYTES_RESPUESTA + 1)}
            def iter_content(self, chunk_size): raise AssertionError("no debio leer el cuerpo")
            def close(self): pass
        _, excedido = h._leer_acotado(R(), h.MAX_BYTES_RESPUESTA)
        self.assertTrue(excedido)

    def test_a05_inyeccion_csv_neutralizada(self):
        """A05:2025. Celdas que empiezan por = + - @ se ejecutan como formula en
        Excel. Un titulo de feed `=cmd|'/c calc'!A0` llegaba tal cual al CSV."""
        from webui.filtros import celda_csv
        for peligrosa in ("=cmd|'/c calc'!A0", "+cmd|'/c calc'!A0",
                          "@SUM(1+1)*cmd", '=HYPERLINK("http://evil","x")',
                          "-2+3+cmd", "\tcmd", "\rcmd"):
            with self.subTest(celda=peligrosa):
                self.assertTrue(celda_csv(peligrosa).startswith("'"),
                                f"no neutralizada: {peligrosa!r}")
        # Lo legitimo no se toca
        for inocua in ("texto normal", "-3", "-3.5", "CVE-2026-1", "", None):
            with self.subTest(celda=inocua):
                self.assertFalse(celda_csv(inocua).startswith("'"))

    def test_a07_login_sin_oraculo_temporal(self):
        """A07:2025. Un usuario inexistente respondia en 0,1 ms y uno real en
        188 ms: enumeracion de cuentas por tiempo (ratio 1.700x)."""
        import statistics, time
        from webui import auth
        with tempfile.TemporaryDirectory() as d:
            ruta = str(Path(d) / "t.db")
            db.init_db(ruta)
            with db.session(ruta) as conn:
                auth.crear_usuario(conn, "real", "ContrasenaReal#2026", actor="t")

            def medir(usuario, n=5):
                t = []
                for _ in range(n):
                    with db.connect(ruta) as conn:
                        a = time.perf_counter()
                        auth.autenticar(conn, usuario, "incorrecta")
                        t.append(time.perf_counter() - a)
                return statistics.median(t)

            existe, no_existe = medir("real"), medir("nadie")
            ratio = max(existe, no_existe) / max(min(existe, no_existe), 1e-6)
            self.assertLess(ratio, 2.0, f"tiempos distinguibles: {existe:.4f}s vs {no_existe:.4f}s")


class TestSesionYCsp(unittest.TestCase):
    """Cookie de sesion opaca (A07:2025) y CSP sin 'unsafe-inline' (A02:2025)."""

    @classmethod
    def setUpClass(cls):
        from threatintel.paths import BASE_DIR
        from webui import auth as _auth
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "s.db")
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            _auth.crear_usuario(conn, "pruebas", "PruebaSegura#2026", rol="admin", actor="t")
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def _login(self):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": "pruebas", "password": "PruebaSegura#2026"})
        return cli

    def _token(self, cli):
        """Token opaco de la cookie de sesión. Adaptado el 2026-09-08: la cookie ya no es
        la firmada de Flask con una carga Base64 que decodificar, sino un token aleatorio
        sin ningún dato (webui/sesion_servidor.py)."""
        galleta = cli.get_cookie("session")
        return galleta.value if galleta else ""

    def test_cookie_solo_contiene_identificador_opaco(self):
        """Antes la cookie llevaba usuario, rol, csrf e inicio, legibles por
        cualquiera que la capturase (solo estaba firmada, no cifrada). Desde el
        2026-09-08 es solo un token de 43 caracteres; tests/test_cookie_opaca.py lo
        comprueba en detalle."""
        from webui import sesion_servidor
        token = self._token(self._login())
        self.assertTrue(sesion_servidor.token_valido(token), f"cookie inesperada: {token!r}")
        for prohibida in ("usuario", "rol", "csrf", "inicio", "username", "role", "sid", "{"):
            self.assertNotIn(prohibida, token)

    def test_sid_se_guarda_como_hash(self):
        from webui import auth as _auth
        cli = self._login()
        token = self._token(cli)
        with db.connect(self.ruta) as conn:
            fila = conn.execute("SELECT sid_hash FROM web_sessions WHERE sid_hash=?",
                                (_auth._hash_sid(token),)).fetchone()
            en_claro = conn.execute("SELECT 1 FROM web_sessions WHERE sid_hash=?", (token,)).fetchone()
        self.assertIsNotNone(fila, "la fila se busca por el hash del token")
        self.assertIsNone(en_claro, "el token en claro no está en la base")
        self.assertEqual(len(fila["sid_hash"]), 64)

    def test_cambiar_password_revoca_todas_las_sesiones(self):
        from webui import auth as _auth
        a, b = self._login(), self._login()
        with db.session(self.ruta) as conn:
            _auth.cambiar_password(conn, "pruebas", "OtraClaveSegura#2026", actor="t")
        self.assertEqual(a.get("/").status_code, 302)
        self.assertEqual(b.get("/").status_code, 302)
        with db.session(self.ruta) as conn:      # restaurar para el resto de pruebas
            # Adaptado el 2026-09-08: el historial de contraseñas (rotación de credenciales)
            # impide volver a la anterior con cambiar_password, así que se repone el hash
            # directamente y se vacía el historial de esta cuenta de pruebas.
            conn.execute("UPDATE users SET password_hash=? WHERE username='pruebas'",
                         (_auth.hash_password("PruebaSegura#2026"),))
            conn.execute("DELETE FROM password_historial WHERE username='pruebas'")

    def test_logout_borra_la_sesion_en_servidor(self):
        # Se comprueba la fila de ESTA sesion por su hash: otras pruebas de la
        # clase dejan sesiones abiertas en la misma base y contarlas todas daba
        # un falso fallo (3 != 0) aunque el logout funcionase.
        import re as _re
        from webui import auth as _auth
        cli = self._login()
        sid_hash = _auth._hash_sid(self._token(cli))
        tok = _re.search(r'name="csrf" value="([^"]+)"', cli.get("/").data.decode()).group(1)
        with db.connect(self.ruta) as conn:
            self.assertIsNotNone(conn.execute(
                "SELECT 1 FROM web_sessions WHERE sid_hash=?", (sid_hash,)).fetchone())
        cli.post("/logout", data={"csrf": tok})
        with db.connect(self.ruta) as conn:
            self.assertIsNone(conn.execute(
                "SELECT 1 FROM web_sessions WHERE sid_hash=?", (sid_hash,)).fetchone())
        self.assertEqual(cli.get("/").status_code, 302)

    def test_sesion_caducada_en_servidor_se_rechaza(self):
        cli = self._login()
        with db.session(self.ruta) as conn:
            conn.execute("UPDATE web_sessions SET expires_at='2000-01-01T00:00:00Z'")
        self.assertEqual(cli.get("/").status_code, 302)

    def test_csp_sin_unsafe_inline(self):
        resp = self._login().get("/")
        csp = resp.headers.get("Content-Security-Policy", "")
        self.assertIn("default-src 'none'", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertNotIn("unsafe-eval", csp)
        self.assertIn("frame-ancestors 'none'", csp)

    def test_html_sin_codigo_en_linea(self):
        """Con la CSP estricta, cualquier onclick= o style= dejaria de funcionar:
        su ausencia en el HTML servido es lo que garantiza que la interfaz sigue
        operativa y que un XSS no puede apoyarse en ellos."""
        import re as _re
        cli = self._login()
        for ruta in ("/", "/fuentes/", "/tecnologias/", "/amenazas/", "/ajustes/", "/credenciales/"):
            with self.subTest(ruta=ruta):
                html = cli.get(ruta).data.decode()
                self.assertEqual(_re.findall(r"\son\w+=\"", html), [], f"manejador en linea en {ruta}")
                self.assertEqual(_re.findall(r"\sstyle=\"", html), [], f"style= en linea en {ruta}")
                self.assertNotIn("<script>", html)

    def test_paginas_autenticadas_no_cacheables(self):
        resp = self._login().get("/")
        self.assertIn("no-store", resp.headers.get("Cache-Control", ""))


class TestClaveNvd(unittest.TestCase):
    """Gestion de la clave de API de NVD desde la interfaz.

    Ninguna prueba escribe en config/credentials.env: `config.update_secret` se
    sustituye por un registrador. Ninguna hace red: `http.fetch_json` se simula.
    """

    @classmethod
    def setUpClass(cls):
        from threatintel.paths import BASE_DIR
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "nvd.db")
        db.init_db(cls.ruta)
        from webui import auth as _auth
        with db.session(cls.ruta) as conn:
            _auth.crear_usuario(conn, "pruebas", "PruebaSegura#2026",
                                rol="admin", actor="test")
            ahora = db.utcnow()
            for i, cve in enumerate(("CVE-2026-0001", "CVE-2026-0002", None)):
                conn.execute(
                    """INSERT INTO threats(fingerprint,title_en,severity,cve,
                           severity_source,first_seen_at,last_seen_at,month)
                       VALUES(?, 't', 'High', ?, 'heuristic', ?, ?, '2026-09')""",
                    (f"fp{i}", cve, ahora, ahora))
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def setUp(self):
        from threatintel import config as _config, enrich as _enrich
        self._config, self._enrich = _config, _enrich
        self.escritos = []
        self._update_secret = _config.update_secret
        _config.update_secret = lambda k, v, **kw: self.escritos.append((k, v))
        self._validar = _enrich.validar_clave_nvd
        self._fetch = _enrich.http.fetch_json

    def tearDown(self):
        self._config.update_secret = self._update_secret
        self._enrich.validar_clave_nvd = self._validar
        self._enrich.http.fetch_json = self._fetch

    # ------------------------------------------------------------ utilidades
    def _sesion(self):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": "pruebas", "password": "PruebaSegura#2026"})
        return cli

    def _csrf(self, cli):
        import re as _re
        html = cli.get("/credenciales/").get_data(as_text=True)
        return _re.search(r'name="csrf" value="([^"]+)"', html).group(1)

    def _cfg(self, clave):
        from types import SimpleNamespace
        return SimpleNamespace(nvd_api_key=clave, get=lambda k, d=None: d)

    UUID_OK = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"  # distinto del placeholder del formulario

    # ------------------------------------------------------- validacion pura
    def test_sin_clave_informa_limite_publico(self):
        ok, msg = self._enrich.validar_clave_nvd(self._cfg(None))
        self.assertFalse(ok); self.assertIn("público", msg)

    def test_formato_invalido_no_llega_a_la_red(self):
        def prohibido(*a, **k): raise AssertionError("no debe hacer red")
        self._enrich.http.fetch_json = prohibido
        ok, msg = self._enrich.validar_clave_nvd(self._cfg("OPabcdefghijklmnopqrs"))
        self.assertFalse(ok); self.assertIn("21 caracteres", msg)

    def test_404_con_clave_significa_clave_invalida(self):
        from types import SimpleNamespace
        self._enrich.http.fetch_json = lambda *a, **k: SimpleNamespace(
            ok=False, status=404, error="HTTP 404", data=None)
        ok, msg = self._enrich.validar_clave_nvd(self._cfg(self.UUID_OK))
        self.assertFalse(ok); self.assertIn("404", msg); self.assertIn("activación", msg)

    def test_200_con_clave_es_valida_y_envia_cabecera(self):
        from types import SimpleNamespace
        visto = {}
        def falso(url, **k):
            visto.update(k); return SimpleNamespace(ok=True, status=200, error=None, data={})
        self._enrich.http.fetch_json = falso
        ok, msg = self._enrich.validar_clave_nvd(self._cfg(None), clave=self.UUID_OK)
        self.assertTrue(ok)
        self.assertEqual(visto["api_key_header"], {"apiKey": self.UUID_OK})

    def test_estado_distingue_situaciones(self):
        with db.connect(self.ruta) as conn:
            e = self._enrich.estado_clave_nvd(conn, self._cfg(None))
            self.assertEqual(e["situacion"], "ausente"); self.assertIsNone(e["mascara"])
            self.assertEqual(e["pendientes"], 2)  # solo las amenazas con CVE
            e = self._enrich.estado_clave_nvd(conn, self._cfg("OPabcdefghijklmnopqrs"))
            self.assertEqual(e["situacion"], "formato_invalido"); self.assertFalse(e["utilizable"])
            self.assertNotIn("OPabcdefghijklmnopqrs", str(e))  # nunca en claro
            e = self._enrich.estado_clave_nvd(conn, self._cfg(self.UUID_OK))
            self.assertEqual(e["situacion"], "sin_verificar")

    # ----------------------------------------------------------- interfaz web
    def test_ui_formato_invalido_no_se_guarda(self):
        cli = self._sesion()
        r = cli.post("/credenciales/nvd/guardar",
                     data={"csrf": self._csrf(cli), "clave": "OPabcdefghijklmnopqrs",
                           "verificar": "1"}, follow_redirects=True)
        self.assertIn("No se ha guardado", r.get_data(as_text=True))
        self.assertEqual(self.escritos, [])

    def test_ui_rechazada_por_nvd_no_se_guarda_y_queda_auditada(self):
        self._enrich.validar_clave_nvd = lambda cfg, clave=None: (False, "NVD no reconoce la clave (HTTP 404)")
        cli = self._sesion()
        r = cli.post("/credenciales/nvd/guardar",
                     data={"csrf": self._csrf(cli), "clave": self.UUID_OK, "verificar": "1"},
                     follow_redirects=True)
        self.assertIn("no se ha guardado", r.get_data(as_text=True))
        self.assertEqual(self.escritos, [])
        with db.connect(self.ruta) as conn:
            n = conn.execute("SELECT COUNT(*) FROM audit_log WHERE action='nvd.guardar_rechazada'").fetchone()[0]
        self.assertEqual(n, 1)

    def test_ui_valida_se_guarda_registra_y_no_muestra_la_clave(self):
        self._enrich.validar_clave_nvd = lambda cfg, clave=None: (True, "clave válida")
        cli = self._sesion()
        r = cli.post("/credenciales/nvd/guardar",
                     data={"csrf": self._csrf(cli), "clave": self.UUID_OK, "verificar": "1"},
                     follow_redirects=True)
        html = r.get_data(as_text=True)
        self.assertIn("guardada", html)
        self.assertEqual(self.escritos, [("NIST_NVD_API_KEY", self.UUID_OK)])
        self.assertNotIn(self.UUID_OK, html)  # la clave nunca vuelve al navegador
        with db.connect(self.ruta) as conn:
            self.assertIs(db.get_setting(conn, "nvd_key_last_check_ok"), True)
            detalle = conn.execute("SELECT detail FROM audit_log WHERE action='nvd.guardar'").fetchone()[0]
        self.assertNotIn(self.UUID_OK, detalle)  # tampoco en la auditoria

    def test_ui_requiere_csrf_y_admin(self):
        cli = self._sesion()
        r = cli.post("/credenciales/nvd/guardar", data={"clave": self.UUID_OK})
        self.assertIn(r.status_code, (400, 403))
        anonimo = self.app.test_client()
        r = anonimo.post("/credenciales/nvd/quitar", data={})
        self.assertIn(r.status_code, (302, 401, 403))
        self.assertEqual(self.escritos, [])

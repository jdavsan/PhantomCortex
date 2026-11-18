"""Correo de alerta e informe mensual tras el filtro de precisión (2026-09-04):
«Por qué está aquí», etiquetas de confianza, menciones aparte, pie «Filtro de
hoy», asunto con el número que requiere acción, bloques del informe y sección
«Precisión del filtro». Base temporal bajo data/; sin envío de correo."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from threatintel import db, notify, report
from threatintel.paths import BASE_DIR


class Cfg(dict):
    pass


def _vista(**extra):
    base = {
        "id": 1, "title_en": "Critical RCE in Postgres", "title_es": "RCE crítica en Postgres",
        "cve": "CVE-2026-1000", "severity": "Critical", "severity_source": "nvd", "cvss_score": 9.8,
        "epss_score": 0.42, "in_kev": False, "kev_due_date": None, "relevance": 78.0,
        "summary_es": "Descripción", "impact_es": None, "remediation_es": None,
        "technologies": [
            {"name": "PostgreSQL", "slug": "postgresql", "version_installed": "15.2", "criticality": "critical",
             "systems_count": 3, "exposure": "internet", "confidence": 1.0, "version_verdict": "affected",
             "version_evidence": None},
            {"name": "Microsoft Windows", "slug": "windows", "version_installed": None, "criticality": "high",
             "systems_count": 0, "exposure": "interna", "confidence": 0.4, "version_verdict": "unknown",
             "version_evidence": None},
        ],
        "sources": [{"name": "NVD", "slug": "nvd", "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-1000"}],
    }
    base.update(extra)
    return base


class TestCorreoDeAlerta(unittest.TestCase):
    def test_por_que_confianza_y_menciones(self):
        html = notify.render_alert_email([_vista()], {"filtro": {
            "excluidas": {"relevancia_baja": 3, "sin_identificador": 2, "heuristica_en_espera": 0,
                          "no_afectada": 0, "estado_cerrado": 1},
            "umbral_relevancia": 50, "min_confianza": 0.6}, "url_interfaz": "http://10.0.0.1:9090/amenazas/"})
        self.assertIn("Por qué está aquí", html)
        self.assertIn("la versión instalada de PostgreSQL es vulnerable", html)
        self.assertIn("coincidencia exacta", html)
        self.assertIn("Menciones", html)                    # Windows con 0,4 va como mención
        self.assertIn("Relevancia", html)
        self.assertNotIn("Rel.", html)
        self.assertIn("1 amenaza que requiere acción", html)

    def test_sin_filtro_no_hay_pie_y_kev_manda(self):
        html = notify.render_alert_email([_vista(in_kev=True, relevance=30.0)])
        self.assertNotIn("Filtro de hoy", html)
        self.assertIn("xplotación activa confirmada por CISA (KEV)", html)

    def test_motivo_alerta_frases(self):
        self.assertTrue(notify.motivo_alerta(_vista()).startswith("Relevancia 78"))
        sin_tecs = _vista(technologies=[], relevance=55.0)
        self.assertEqual(notify.motivo_alerta(sin_tecs), "Relevancia 55 para la organización")
        mencion = _vista(technologies=[_vista()["technologies"][1]], relevance=20.0)
        self.assertEqual(notify.motivo_alerta(mencion), "Relevancia 20")

    def test_asunto_dice_de_que_va_el_correo(self):
        """Revisión de claridad del 2026-09-15: un solo prefijo, la fecha en palabras y dos
        cifras que dicen de qué va el correo.

        Sustituye a la petición del 2026-09-07 («que diga alertamiento diario y la fecha y
        ya»): con aquel asunto, en la bandeja no se distinguía un día con siete críticas de
        otro sin novedades y había que abrirlos todos. Se mantiene el asunto corto —dos
        cifras, no cinco— para que el gestor de correo no lo recorte."""
        from datetime import datetime
        fecha = datetime(2026, 9, 7)
        asunto = notify.asunto_alerta(2, 5, 1, fecha=fecha, total=7, activos=454)
        self.assertEqual(
            asunto,
            "[Inteligencia de Amenazas] Alerta diaria · 7 de septiembre de 2026 · "
            "7 vulnerabilidades, 2 críticas")
        # Un solo prefijo en todo el sistema y la fecha en palabras, no en cifras.
        self.assertNotIn("[SOC]", asunto)
        self.assertNotIn("07/09/2026", asunto)
        # Los días sin novedades lo dicen en el propio asunto.
        self.assertIn("sin novedades que requieran acción",
                      notify.asunto_alerta(fecha=fecha))


class TestInformeMensual(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "informe.db")
        db.init_db(cls.ruta)
        cls.cfg = Cfg(alert_min_relevance=50, alert_min_match_confidence=0.6,
                      report_detail_severities=["Critical", "High"], report_max_detail_items=30,
                      report_max_anexo_items=50, translate_engine="none", ollama_url="",
                      webui_host="10.0.0.1", webui_port=9090)
        with db.session(cls.ruta) as conn:
            ahora = db.utcnow()
            conn.execute("""INSERT INTO technologies(slug,name,vendor,category,criticality,systems_count,
                            exposure,enabled,created_at,updated_at) VALUES('postgresql','PostgreSQL','x','bd',
                            'critical',3,'internet',1,?,?)""", (ahora, ahora))
            tid = conn.execute("SELECT id FROM technologies").fetchone()[0]
            filas = [
                ("accion", "CVE-2026-1", "Critical", "nvd", 80.0, 0, "2026-08-02T10:00:00Z", "nueva", None, 1.0),
                ("kev", "CVE-2026-2", "High", "nvd", 30.0, 1, None, "nueva", None, 1.0),
                ("seguimiento", "CVE-2026-3", "High", "heuristic", 30.0, 0, None, "nueva", "relevancia_baja", 0.9),
                ("informativa", None, "Medium", "heuristic", 10.0, 0, None, "nueva", "sin_identificador", None),
                ("falso positivo", "CVE-2026-4", "High", "nvd", 70.0, 0, None, "falso_positivo", None, 1.0),
            ]
            for titulo, cve, sev, origen, rel, kev, alertada, estado, skip, conf in filas:
                conn.execute("""INSERT INTO threats(fingerprint,cve,title_en,severity,severity_source,in_kev,
                                first_seen_at,last_seen_at,month,relevance,alerted_at,estado,alert_skip_reason)
                                VALUES(?,?,?,?,?,?,'2026-08-01T00:00:00Z','2026-08-01T00:00:00Z','2026-08',?,?,?,?)""",
                             (f"fp-{titulo}", cve, titulo, sev, origen, kev, rel, alertada, estado, skip))
                if conf is not None:
                    th = conn.execute("SELECT id FROM threats WHERE title_en=?", (titulo,)).fetchone()[0]
                    conn.execute("INSERT INTO threat_technologies(threat_id,technology_id,matched_alias,confidence,"
                                 "version_verdict) VALUES(?,?,'postgres',?,'unknown')", (th, tid, conf))

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def test_bloques_y_precision(self):
        with db.connect(self.ruta) as conn:
            res = report.construir_resumen(conn, "2026-08", cfg=self.cfg)
        self.assertEqual(res["bloques"]["conteo"],
                         {"requiere_accion": 2, "seguimiento": 1, "informativo": 1, "cerrada": 1})
        self.assertEqual(res["precision"]["motivos"]["relevancia_baja"], 1)
        self.assertEqual(res["precision"]["motivos"]["sin_identificador"], 1)
        self.assertEqual(res["precision"]["cerradas"], 1)
        self.assertEqual(res["precision"]["alertadas"], 1)

    def test_documento_con_secciones_nuevas_y_sin_cerradas(self):
        from docx import Document
        destino = Path(self.dir.name) / "informe.docx"
        with db.connect(self.ruta) as conn:
            ruta = report.generar(conn, "2026-08", cfg=self.cfg, destino=destino)
        doc = Document(str(ruta))
        texto = "\n".join(p.text for p in doc.paragraphs)
        for esperado in ("Cómo leer este informe", "7. Precisión del filtro de alertas",
                         "8. Nota metodológica", "PostgreSQL · "):
            self.assertIn(esperado, texto, esperado)
        self.assertIn("accion", texto)
        self.assertNotIn("— falso positivo", texto)   # no hay ficha de la cerrada
        celdas = "\n".join(c.text for t in doc.tables for r in t.rows for c in r.cells)
        self.assertIn("Requiere acción", celdas)
        # Revisión de precisión del 2026-09-15: la tabla de precisión es un REPARTO del
        # total y ahora lleva su fila de total; los estados que pone el equipo son otra
        # clasificación y se cuentan en una frase aparte, porque sumarlos a la tabla hacía
        # que los porcentajes pasaran del 100 %.
        self.assertIn("No alertadas: relevancia por debajo del umbral", celdas)
        self.assertIn("Total de amenazas del periodo", celdas)
        self.assertNotIn("Marcadas por el equipo: falso positivo", celdas)
        self.assertIn("el equipo marcó a mano", texto)

    def test_severidad_baja_fuera_del_informe(self):
        with db.session(self.ruta) as conn:
            conn.execute("""INSERT INTO threats(fingerprint,cve,title_en,severity,severity_source,first_seen_at,
                            last_seen_at,month,relevance) VALUES('fp-baja','CVE-2026-9','ruido bajo','Low','nvd',
                            '2026-08-01T00:00:00Z','2026-08-01T00:00:00Z','2026-08',20.0)""")
        try:
            with db.connect(self.ruta) as conn:
                res = report.construir_resumen(conn, "2026-08", cfg=self.cfg)
                sin = report.construir_resumen(conn, "2026-08", cfg=Cfg(self.cfg, ignore_low_severity=False))
            self.assertEqual(res["total"], 5)                 # la Baja no cuenta
            self.assertEqual(res["bajas"], 0)
            self.assertEqual(res["bajas_ignoradas"], 1)
            self.assertEqual(res["precision"]["bajas_ignoradas"], 1)
            self.assertEqual(sum(res["bloques"]["conteo"].values()), 5)
            self.assertEqual(sin["total"], 6)
        finally:
            with db.session(self.ruta) as conn:
                conn.execute("DELETE FROM threats WHERE fingerprint='fp-baja'")

    def test_correo_mensual_con_bloques(self):
        with db.connect(self.ruta) as conn:
            res = report.construir_resumen(conn, "2026-08", cfg=self.cfg)
        html = notify.render_monthly_email(res)
        self.assertIn("Cómo se reparte el periodo", html)
        self.assertIn("Requiere acción", html)
        self.assertIn("Cerradas por el equipo", html)


if __name__ == "__main__":
    unittest.main()

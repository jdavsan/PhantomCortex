"""Gestión de estados y falso positivo desde la interfaz (2026-09-04).

Cambio de estado con auditoría, ajustes del inventario al marcar un falso
positivo (contexto en el alias, desvincular tecnología y recalcular
relevancia), permisos y CSRF, filtro de estados en la lista («abiertas» por
defecto), columna de estado, CSV y motivo de no alerta en la ficha. Base
temporal bajo data/."""
from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path

from threatintel import db
from threatintel.paths import BASE_DIR


class TestEstadosAmenaza(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "estados.db")
        db.init_db(cls.ruta)
        from webui import auth as _auth
        with db.session(cls.ruta) as conn:
            _auth.crear_usuario(conn, "admin", "AdminSeguro#2026", rol="admin", actor="test")
            _auth.crear_usuario(conn, "lector", "LectorSeguro#2026", rol="ciberseguridad", actor="test")
            # Cambiar el estado de una amenaza es de administración y ciberseguridad
            # (auth.ROLES_OPERACION); «redes» no está en ese conjunto.
            _auth.crear_usuario(conn, "redes", "RedesSeguro#2026", rol="redes", actor="test")
            ahora = db.utcnow()
            conn.execute("""INSERT INTO technologies(slug,name,vendor,category,criticality,systems_count,
                            exposure,enabled,created_at,updated_at) VALUES('windows','Microsoft Windows','Microsoft',
                            'sistema-operativo','high',50,'interna',1,?,?)""", (ahora, ahora))
            conn.execute("""INSERT INTO technologies(slug,name,vendor,category,criticality,systems_count,
                            exposure,enabled,created_at,updated_at) VALUES('postgresql','PostgreSQL','x',
                            'base-de-datos','critical',3,'internet',1,?,?)""", (ahora, ahora))
            cls.tid_win = conn.execute("SELECT id FROM technologies WHERE slug='windows'").fetchone()[0]
            cls.tid_pg = conn.execute("SELECT id FROM technologies WHERE slug='postgresql'").fetchone()[0]
            conn.execute("INSERT INTO tech_aliases(technology_id, alias, match_mode, is_exclusion) VALUES(?, 'windows', 'word', 0)",
                         (cls.tid_win,))
            for titulo, sev, rel, estado, skip in (
                    ("Malware para Windows", "High", 40.0, "nueva", "relevancia_baja"),
                    ("RCE en PostgreSQL", "Critical", 80.0, "nueva", None),
                    ("Ya descartada", "High", 60.0, "descartada", None)):
                conn.execute("""INSERT INTO threats(fingerprint,cve,title_en,severity,severity_source,first_seen_at,
                                last_seen_at,month,relevance,estado,alert_skip_reason)
                                VALUES(?,'CVE-2026-1','%s','%s','nvd','2026-09-01T00:00:00Z','2026-09-01T00:00:00Z',
                                '2026-09',?,?,?)""" % (titulo, sev), (f"fp-{titulo}", rel, estado, skip))
            cls.id_win = conn.execute("SELECT id FROM threats WHERE title_en='Malware para Windows'").fetchone()[0]
            cls.id_pg = conn.execute("SELECT id FROM threats WHERE title_en='RCE en PostgreSQL'").fetchone()[0]
            conn.execute("INSERT INTO threat_technologies(threat_id,technology_id,matched_alias,confidence,version_verdict) "
                         "VALUES(?,?,'windows',0.4,'unknown')", (cls.id_win, cls.tid_win))
            conn.execute("INSERT INTO threat_technologies(threat_id,technology_id,matched_alias,confidence,version_verdict) "
                         "VALUES(?,?,'postgresql',1.0,'affected')", (cls.id_pg, cls.tid_pg))
            conn.execute("INSERT INTO threat_technologies(threat_id,technology_id,matched_alias,confidence,version_verdict) "
                         "VALUES(?,?,'windows',0.4,'unknown')", (cls.id_pg, cls.tid_win))
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def setUp(self):
        """Cada prueba parte del mismo estado: las de escritura no contaminan a las demás."""
        with db.session(self.ruta) as conn:
            conn.execute("UPDATE threats SET estado='nueva', estado_at=NULL, estado_por=NULL, estado_motivo=NULL "
                         "WHERE title_en IN ('Malware para Windows', 'RCE en PostgreSQL')")
            conn.execute("UPDATE threats SET relevance=40.0 WHERE id=?", (self.id_win,))
            conn.execute("DELETE FROM threat_technologies WHERE threat_id IN (?, ?)", (self.id_win, self.id_pg))
            conn.execute("INSERT INTO threat_technologies(threat_id,technology_id,matched_alias,confidence,version_verdict) "
                         "VALUES(?,?,'windows',0.4,'unknown')", (self.id_win, self.tid_win))
            conn.execute("INSERT INTO threat_technologies(threat_id,technology_id,matched_alias,confidence,version_verdict) "
                         "VALUES(?,?,'postgresql',1.0,'affected')", (self.id_pg, self.tid_pg))
            conn.execute("INSERT INTO threat_technologies(threat_id,technology_id,matched_alias,confidence,version_verdict) "
                         "VALUES(?,?,'windows',0.4,'unknown')", (self.id_pg, self.tid_win))
            conn.execute("UPDATE tech_aliases SET context_required=NULL WHERE technology_id=?", (self.tid_win,))

    def _sesion(self, usuario="admin", password="AdminSeguro#2026"):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": usuario, "password": password})
        return cli

    def _csrf(self, cli, ruta):
        html = cli.get(ruta).get_data(as_text=True)
        return re.search(r'name="csrf" value="([^"]+)"', html).group(1)

    # ---------------------------------------------------------------- ficha
    def test_ficha_muestra_gestion_motivo_y_menciones(self):
        cli = self._sesion()
        html = cli.get(f"/amenazas/{self.id_win}").get_data(as_text=True)
        self.assertIn("Gestión", html)
        self.assertIn("No se alertó: relevancia por debajo del umbral", html)
        # Adaptado el 2026-09-15 (auditoría de tableros, punto 9): la nota lleva ahora su
        # propio recuento, porque esas menciones no aparecen en la tabla de arriba.
        self.assertIn("1 mención sin prueba de exposición", html)      # windows con 0,4
        self.assertIn("Guardar estado", html)
        html_pg = cli.get(f"/amenazas/{self.id_pg}").get_data(as_text=True)
        self.assertIn("confianza 1", html_pg)                         # PostgreSQL en la tabla
        self.assertIn("Microsoft Windows («windows»)", html_pg)      # Windows como mención
        # el lector (ciberseguridad) SÍ ve el formulario: puede operar amenazas
        lector = self._sesion("lector", "LectorSeguro#2026")
        self.assertIn("Guardar estado", lector.get(f"/amenazas/{self.id_win}").get_data(as_text=True))
        # «redes» no está en ROLES_OPERACION y no lo ve
        redes = self._sesion("redes", "RedesSeguro#2026")
        self.assertNotIn("Guardar estado", redes.get(f"/amenazas/{self.id_win}").get_data(as_text=True))

    def test_permisos_y_csrf(self):
        redes = self._sesion("redes", "RedesSeguro#2026")
        r = redes.post(f"/amenazas/{self.id_win}/estado", data={"estado": "mitigada", "csrf": "x"})
        self.assertIn(r.status_code, (302, 403))
        admin = self._sesion()
        r = admin.post(f"/amenazas/{self.id_win}/estado", data={"estado": "mitigada"})
        self.assertIn(r.status_code, (400, 403))
        with db.connect(self.ruta) as conn:
            estado = conn.execute("SELECT estado FROM threats WHERE id=?", (self.id_win,)).fetchone()[0]
        self.assertEqual(estado, "nueva")

    def test_cambio_de_estado_con_auditoria(self):
        cli = self._sesion()
        csrf = self._csrf(cli, f"/amenazas/{self.id_pg}")
        r = cli.post(f"/amenazas/{self.id_pg}/estado",
                     data={"csrf": csrf, "estado": "en_analisis", "motivo": "Revisando parche"},
                     follow_redirects=True)
        html = r.get_data(as_text=True)
        self.assertIn("En análisis", html)
        self.assertIn("Motivo: Revisando parche", html)
        with db.connect(self.ruta) as conn:
            fila = conn.execute("SELECT estado, estado_por, estado_motivo FROM threats WHERE id=?",
                                (self.id_pg,)).fetchone()
            audit = conn.execute("SELECT COUNT(*) FROM audit_log WHERE action='amenaza.estado'").fetchone()[0]
        self.assertEqual(tuple(fila), ("en_analisis", "admin", "Revisando parche"))
        self.assertGreaterEqual(audit, 1)
        r = cli.post(f"/amenazas/{self.id_pg}/estado", data={"csrf": csrf, "estado": "inventado"},
                     follow_redirects=True)
        self.assertIn("Estado no válido", r.get_data(as_text=True))

    def test_falso_positivo_ajusta_alias_y_desvincula(self):
        cli = self._sesion()
        csrf = self._csrf(cli, f"/amenazas/{self.id_win}")
        with db.connect(self.ruta) as conn:
            rel_antes = conn.execute("SELECT relevance FROM threats WHERE id=?", (self.id_win,)).fetchone()[0]
        r = cli.post(f"/amenazas/{self.id_win}/estado",
                     data={"csrf": csrf, "estado": "falso_positivo", "motivo": "noticia de malware",
                           "contexto": ["windows|windows"], "desvincular": ["windows"]},
                     follow_redirects=True)
        html = r.get_data(as_text=True)
        self.assertIn("Falso positivo", html)
        self.assertIn("contexto exigido a «windows»", html)
        self.assertIn("desvinculada de windows", html)
        with db.connect(self.ruta) as conn:
            contexto = conn.execute("SELECT context_required FROM tech_aliases WHERE technology_id=? AND alias='windows'",
                                    (self.tid_win,)).fetchone()[0]
            quedan = conn.execute("SELECT COUNT(*) FROM threat_technologies WHERE threat_id=?", (self.id_win,)).fetchone()[0]
            rel = conn.execute("SELECT relevance FROM threats WHERE id=?", (self.id_win,)).fetchone()[0]
        self.assertIn("vulnerability", contexto)
        self.assertEqual(quedan, 0)
        self.assertNotEqual(rel, rel_antes)

    # ---------------------------------------------------------------- lista y CSV
    def test_lista_oculta_cerradas_por_defecto_y_filtra(self):
        cli = self._sesion()
        html = cli.get("/amenazas/").get_data(as_text=True)
        self.assertNotIn("Ya descartada", html)
        self.assertIn("RCE en PostgreSQL", html)
        self.assertIn('<th title="Estado operativo', html)
        html_todas = cli.get("/amenazas/?estado=todas").get_data(as_text=True)
        self.assertIn("Ya descartada", html_todas)
        html_cerradas = cli.get("/amenazas/?estado=cerradas").get_data(as_text=True)
        self.assertIn("Ya descartada", html_cerradas)
        self.assertNotIn("RCE en PostgreSQL", html_cerradas)
        html_uno = cli.get("/amenazas/?estado=descartada").get_data(as_text=True)
        self.assertIn("Ya descartada", html_uno)
        html_raro = cli.get("/amenazas/?estado=lo-que-sea").get_data(as_text=True)
        self.assertNotIn("Ya descartada", html_raro)        # valor desconocido → abiertas

    def test_csv_con_estado(self):
        cli = self._sesion()
        csv = cli.get("/amenazas/exportar.csv?estado=todas").get_data(as_text=True)
        self.assertIn(";estado;motivo_no_alerta;", csv)
        self.assertIn("Descartada", csv)
        self.assertNotIn("\nstyle=", csv)

    def test_sin_estilos_en_linea(self):
        cli = self._sesion()
        for ruta in ("/amenazas/", f"/amenazas/{self.id_pg}"):
            html = cli.get(ruta).get_data(as_text=True)
            self.assertEqual(len(re.findall(r'\sstyle="|\son[a-z]+="', html)), 0, ruta)


if __name__ == "__main__":
    unittest.main()

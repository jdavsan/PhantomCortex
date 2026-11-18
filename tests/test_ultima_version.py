"""La remediación indica SIEMPRE la última versión a la que hay que actualizar (2026-09-09).

Petición literal del usuario: «se descubre vulnerabilidad en kernel donde se debe actualizar
a la versión 1.1.0 pero el día de mañana hay otra vulnerabilidad en el kernel y dice que se
debe actualizar a la versión 1.2.0, pero luego vuelve a salir otra que dice que se debe
actualizar a la 1.3.0, entonces se debe contar como una sola y que al abrirla se vea la cola
o trazabilidad de las vulnerabilidades pero que la remediación indique sí o sí la última
versión a la que se debe actualizar».

Medido en producción antes del cambio: el correo y el libro de la alerta escribían la versión
de ESE aviso. En el servidor SRV-EJEMPLO-511 el paquete `linux-tools-common` acumulaba
veintinueve vulnerabilidades con siete versiones pedidas, de 6.8.0-117.117 a 6.8.0-139.139, y
la alerta decía «actualizar a 6.8.0-117.117». Había 1.456 pares (activo, paquete) así.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from threatintel import aplicabilidad, db, libro_alerta, notify
from threatintel.paths import BASE_DIR

sys.path.insert(0, str(BASE_DIR))


def _activo(conn, ocs_id, nombre, familia="debian", ecosistema="Debian:13"):
    conn.execute(
        """INSERT INTO activos(ocs_id, nombre, origen, so_familia, ecosistema, so_nombre,
                               presente, entorno, primera_vez_at, visto_at)
           VALUES(?,?,'servidores',?,?,'Debian GNU/Linux',1,'produccion',?,?)""",
        (ocs_id, nombre, familia, ecosistema, db.utcnow(), db.utcnow()))
    return conn.execute("SELECT id FROM activos WHERE nombre=?", (nombre,)).fetchone()[0]


def _amenaza(conn, fp, cve, severidad="High"):
    conn.execute(
        """INSERT INTO threats(fingerprint, cve, title_en, title_es, severity, severity_source,
                               first_seen_at, last_seen_at, month, relevance, estado)
           VALUES(?,?,?,?,?,'nvd',?,?,?,70.0,'nueva')""",
        (fp, cve, f"Aviso {cve}", f"Aviso {cve}", severidad, db.utcnow(), db.utcnow(),
         db.utcnow()[:7]))
    return conn.execute("SELECT id FROM threats WHERE fingerprint=?", (fp,)).fetchone()[0]


class TestUltimaVersion(unittest.TestCase):
    """Tres vulnerabilidades del mismo paquete que piden 1.1.0, 1.2.0 y 1.3.0."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "ultima_version.db")
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            cls.activo = _activo(conn, 90, "srv-nucleo")
            cls.otro = _activo(conn, 91, "srv-sin-cola")
            cls.ids = []
            for numero, (cve, version, severidad) in enumerate((
                    ("CVE-2026-1001", "1.1.0", "Medium"),
                    ("CVE-2026-1002", "1.2.0", "High"),
                    ("CVE-2026-1003", "1.3.0", "Critical")), start=1):
                amenaza = _amenaza(conn, f"fp-{numero}", cve, severidad)
                cls.ids.append(amenaza)
                conn.execute(
                    """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete,
                            version_instalada, version_corregida, veredicto, motor, evaluado_at,
                            evidencia, aviso)
                       VALUES(?,?,?,'nucleo','1.0.0',?,'afectado','osv',?,?,?)""",
                    (cls.activo, amenaza, cve, version, db.utcnow(),
                     f"nucleo 1.0.0 es anterior a la corrección {version}", f"AVISO-{numero}"))
            # Otro paquete del mismo activo con su propia versión: no se mezcla.
            otra = _amenaza(conn, "fp-otro", "CVE-2026-2001")
            conn.execute(
                """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete,
                        version_instalada, version_corregida, veredicto, motor, evaluado_at)
                   VALUES(?,?,'CVE-2026-2001','biblioteca','2.0.0','2.0.1','afectado','osv',?)""",
                (cls.activo, otra, db.utcnow()))
            cls.otra_amenaza = otra
        with db.session(cls.ruta) as conn:
            # Las vistas de amenaza leen el resumen por amenaza, no las filas sueltas.
            for tid in cls.ids + [cls.otra_amenaza]:
                conn.execute(
                    """INSERT INTO aplicabilidad_amenaza(threat_id, evaluado_at, afectados,
                            no_afectados, sin_dato, afectados_expuestos)
                       VALUES(?,?,1,0,0,1)""", (tid, db.utcnow()))
            aplicabilidad.recalcular_resumenes(conn, recalcular_relevancia=False)
        cls.conn = db.connect(cls.ruta)

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()
        cls.dir.cleanup()

    def test_la_ultima_version_es_la_mas_alta_de_las_pedidas(self):
        mapa = aplicabilidad.versiones_pedidas_por_paquete(
            self.conn, [(self.activo, "nucleo"), (self.activo, "biblioteca")])
        nucleo = mapa[(self.activo, "nucleo")]
        self.assertEqual(nucleo["version_objetivo"], "1.3.0",
                         "instalar la 1.3.0 resuelve las tres, la 1.1.0 no")
        self.assertEqual(nucleo["versiones_pedidas"], 3)
        self.assertEqual(nucleo["vulnerabilidades"], 3)
        self.assertEqual(mapa[(self.activo, "biblioteca")]["version_objetivo"], "2.0.1",
                         "cada paquete tiene su propia versión: no se mezclan")

    def test_no_se_cuenta_como_tres_actualizaciones(self):
        from threatintel import remediacion
        remediacion.sincronizar(self.conn)
        pagina = remediacion.pagina_actualizaciones(self.conn, estado="abierta",
                                                    activo_id=self.activo, limite=50)
        grupos = pagina["grupos"]
        nucleo = [g for g in grupos if "nucleo" in str(dict(g).get("nombre") or dict(g).get("paquete"))]
        self.assertEqual(len(nucleo), 1, "una sola actualización, no tres")
        g = dict(nucleo[0])
        self.assertEqual(g["version_objetivo"], "1.3.0", "la remediación indica la última versión")
        self.assertEqual(g["vulnerabilidades"], 3, "y dice cuántas vulnerabilidades resuelve")
        self.assertEqual(g["versiones_pedidas"], 3)
        cola = [dict(v)["version"] for v in (g.get("versiones") or [])]
        self.assertEqual(cola[0], "1.3.0", "la cola empieza por la que hay que instalar")
        self.assertEqual(sorted(cola), ["1.1.0", "1.2.0", "1.3.0"],
                         "y la trazabilidad conserva las tres versiones pedidas")

    def test_el_correo_de_la_primera_ya_pide_la_ultima(self):
        vistas = [{"id": self.ids[0], "cve": "CVE-2026-1001", "title_es": "Aviso CVE-2026-1001",
                   "severity": "Medium", "relevance": 70.0, "tecs_exposicion": []}]
        aplicabilidad.adjuntar_activos(self.conn, vistas, limite=10)
        detalle = vistas[0]["activos"]["afectados"][0]["paquetes_detalle"][0]
        self.assertEqual(detalle["version_corregida"], "1.1.0", "el aviso pedía la 1.1.0")
        self.assertEqual(detalle["version_ultima"], "1.3.0")
        self.assertTrue(detalle["version_ultima_distinta"])
        html = notify.render_alert_email(vistas, {"detalle_top": 3})
        self.assertIn("1.3.0", html)
        self.assertIn("Es la última versión pedida", html)
        self.assertIn("3 versiones pedidas", html)

    def test_el_libro_escribe_la_ultima_version(self):
        datos = libro_alerta.activos_por_amenaza(self.conn, [self.ids[0]], limite=10)
        detalle = datos[self.ids[0]]["afectados"][0]["paquetes_detalle"][0]
        self.assertEqual(detalle["version_ultima"], "1.3.0")
        self.assertTrue(detalle["version_ultima_distinta"])

    def test_el_sistema_operativo_tambien_pide_la_ultima(self):
        datos = aplicabilidad.activos_de_amenaza(self.conn, self.ids[0], limite=10)
        sistema = datos["sistemas"][0]
        detalle = [d for d in sistema["paquetes_detalle"] if d["paquete"] == "nucleo"][0]
        self.assertEqual(detalle["version_ultima"], "1.3.0")
        self.assertTrue(detalle["version_ultima_distinta"])

    def test_un_paquete_sin_cola_no_dice_nada_raro(self):
        datos = aplicabilidad.activos_de_amenaza(self.conn, self.otra_amenaza, limite=10)
        detalle = datos["afectados"][0]["paquetes_detalle"][0]
        self.assertEqual(detalle["paquete"], "biblioteca")
        self.assertEqual(detalle["version_ultima"], "2.0.1")
        self.assertFalse(detalle["version_ultima_distinta"],
                         "con una sola versión pedida no hay nada que explicar")
        html = notify.render_alert_email(
            [{"id": self.otra_amenaza, "cve": "CVE-2026-2001", "title_es": "Aviso",
              "severity": "High", "relevance": 70.0, "tecs_exposicion": [],
              "activos": datos}], {"detalle_top": 3})
        self.assertNotIn("Es la última versión pedida", html)

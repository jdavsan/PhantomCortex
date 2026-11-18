"""Criterio de alerta por relevancia (2026-09-04) y resumen semanal.

Cubre `queries.motivo_exclusion` / `clasificar_pendientes` / `pendientes_de_alerta`
(firma nueva y antigua), la persistencia de `alert_skip_reason`, el resumen
semanal (`digest`) y que `--comparar` no escribe ni envía. Base temporal bajo
data/; ninguna prueba toca la base real ni envía correo.

Nota del 2026-09-08: el criterio de afectación real («solo se alerta lo que afecta a
alguna máquina», ajuste `alert_solo_con_activos_afectados`) no cambia lo que se espera
aquí porque esta base temporal no tiene inventario: sin ningún activo con presente=1 el
filtro se abstiene a propósito, para que un fallo de sincronización de OCS no deje el
correo vacío. Ese criterio se prueba, con inventario y con todas sus salvaguardas, en
tests/test_criterio_afectados.py.
"""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from threatintel import db, digest, queries
from threatintel.paths import BASE_DIR


class Cfg(dict):
    """Configuración mínima con la interfaz `.get` que usan las funciones."""
    alert_to = ["equipo@example.invalid"]
    alert_cc: list = []


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "alertas.db")
        db.init_db(cls.ruta)
        cls.ahora = datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc)
        cls.cfg = Cfg(alert_min_relevance=50, alert_require_identifier=True,
                      alert_defer_heuristic_hours=24, alert_min_match_confidence=0.6,
                      alert_only_affected_versions=False, alert_min_severity="High",
                      digest_max_items=60, webui_host="10.0.0.1", webui_port=9090)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def setUp(self):
        with db.session(self.ruta) as conn:
            conn.execute("DELETE FROM threat_technologies")
            conn.execute("DELETE FROM threats")
            conn.execute("DELETE FROM tech_aliases")
            conn.execute("DELETE FROM technologies")

    # ------------------------------------------------------------ utilidades
    def _tec(self, conn, slug="postgres", *, criticality="critical", exposure="internet") -> int:
        ahora = db.utcnow()
        conn.execute(
            """INSERT INTO technologies(slug,name,vendor,category,criticality,systems_count,
                   exposure,enabled,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,1,?,?)""",
            (slug, slug.title(), "x", "base-de-datos", criticality, 3, exposure, ahora, ahora))
        return conn.execute("SELECT id FROM technologies WHERE slug=?", (slug,)).fetchone()[0]

    def _amenaza(self, conn, titulo, *, cve=None, severity="High", origen="heuristic",
                 relevance=60.0, kev=0, hace_horas=48, estado="nueva", tecs=()) -> int:
        visto = _iso(self.ahora - timedelta(hours=hace_horas))
        conn.execute(
            """INSERT INTO threats(fingerprint,cve,title_en,severity,severity_source,in_kev,
                   first_seen_at,last_seen_at,month,relevance,estado)
               VALUES(?,?,?,?,?,?,?,?,'2026-09',?,?)""",
            (f"fp-{titulo}", cve, titulo, severity, origen, kev, visto, visto, relevance, estado))
        tid = conn.execute("SELECT id FROM threats WHERE title_en=?", (titulo,)).fetchone()[0]
        for tec_id, veredicto, conf in tecs:
            conn.execute(
                """INSERT INTO threat_technologies(threat_id,technology_id,matched_alias,
                       confidence,version_verdict) VALUES(?,?,?,?,?)""",
                (tid, tec_id, "alias", conf, veredicto))
        return tid

    def _motivos(self):
        with db.connect(self.ruta) as conn:
            res = queries.clasificar_pendientes(conn, cfg=self.cfg, ahora=self.ahora,
                                                persistir=False)
        por_titulo = {v["title_en"]: None for v in res["alertar"]}
        with db.connect(self.ruta) as conn:
            titulos = {r[0]: r[1] for r in conn.execute("SELECT id, title_en FROM threats")}
        for motivo, ids in res["excluidas"].items():
            for i in ids:
                por_titulo[titulos[i]] = motivo
        return por_titulo, res


class TestMotivosDeExclusion(_Base):
    def test_orden_y_excepciones_kev(self):
        with db.session(self.ruta) as conn:
            self._amenaza(conn, "alerta clara", cve="CVE-2026-1", origen="nvd", relevance=72)
            self._amenaza(conn, "noticia sin cve", relevance=90)                      # sin identificador
            self._amenaza(conn, "kev sin cve ni relevancia", kev=1, relevance=5)      # KEV alerta siempre
            self._amenaza(conn, "kev descartada", kev=1, cve="CVE-2026-9", estado="falso_positivo")
            self._amenaza(conn, "estimada reciente", cve="CVE-2026-2", relevance=80, hace_horas=3)
            self._amenaza(conn, "estimada madura", cve="CVE-2026-3", relevance=80, hace_horas=30)
            self._amenaza(conn, "aviso oficial reciente DSA-6479-1 roundcube", origen="heuristic",
                          relevance=70, hace_horas=1)                                 # id de aviso: no espera
            self._amenaza(conn, "poco relevante", cve="CVE-2026-4", origen="nvd", relevance=31)
        motivos, res = self._motivos()
        self.assertIsNone(motivos["alerta clara"])
        self.assertEqual(motivos["noticia sin cve"], "sin_identificador")
        self.assertIsNone(motivos["kev sin cve ni relevancia"])
        self.assertEqual(motivos["kev descartada"], "estado_cerrado")
        self.assertEqual(motivos["estimada reciente"], "heuristica_en_espera")
        self.assertIsNone(motivos["estimada madura"])
        self.assertIsNone(motivos["aviso oficial reciente DSA-6479-1 roundcube"])
        self.assertEqual(motivos["poco relevante"], "relevancia_baja")
        # las que alertan van por relevancia descendente
        self.assertEqual([v["title_en"] for v in res["alertar"]][:2],
                         ["estimada madura", "alerta clara"])
        self.assertEqual(set(res["conteo"]), set(queries.MOTIVOS_EXCLUSION))

    def test_no_afectada_solo_si_se_pide(self):
        with db.session(self.ruta) as conn:
            t = self._tec(conn)
            self._amenaza(conn, "version no vulnerable", cve="CVE-2026-5", origen="nvd",
                          relevance=70, tecs=[(t, "not_affected", 1.0)])
        motivos, _ = self._motivos()
        self.assertIsNone(motivos["version no vulnerable"])
        cfg = Cfg(self.cfg, alert_only_affected_versions=True)
        with db.connect(self.ruta) as conn:
            res = queries.clasificar_pendientes(conn, cfg=cfg, ahora=self.ahora, persistir=False)
        self.assertEqual(res["conteo"]["no_afectada"], 1)

    def test_umbral_configurable_y_espera_cero(self):
        with db.session(self.ruta) as conn:
            self._amenaza(conn, "relevancia 45", cve="CVE-2026-6", origen="nvd", relevance=45)
            self._amenaza(conn, "estimada de hoy", cve="CVE-2026-7", relevance=80, hace_horas=1)
        cfg = Cfg(self.cfg, alert_min_relevance=40, alert_defer_heuristic_hours=0)
        with db.connect(self.ruta) as conn:
            res = queries.clasificar_pendientes(conn, cfg=cfg, ahora=self.ahora, persistir=False)
        self.assertEqual({v["title_en"] for v in res["alertar"]}, {"relevancia 45", "estimada de hoy"})

    def test_severidad_baja_no_se_tiene_en_cuenta_salvo_kev(self):
        with db.session(self.ruta) as conn:
            self._amenaza(conn, "baja relevante", cve="CVE-2026-40", severity="Low", origen="nvd", relevance=90)
            self._amenaza(conn, "baja en kev", cve="CVE-2026-41", severity="Low", origen="nvd", relevance=5, kev=1)
        motivos, _ = self._motivos()
        self.assertEqual(motivos["baja relevante"], "severidad_baja")
        self.assertIsNone(motivos["baja en kev"])
        cfg = Cfg(self.cfg, ignore_low_severity=False)
        with db.connect(self.ruta) as conn:
            res = queries.clasificar_pendientes(conn, cfg=cfg, ahora=self.ahora, persistir=False)
        self.assertIn("baja relevante", {v["title_en"] for v in res["alertar"]})

    def test_criticidad_baja_no_suma_relevancia(self):
        from threatintel import scoring
        tec = {"criticality": "low", "exposure": "internet", "systems_count": 10,
               "version_verdict": "affected", "confidence": 1.0}
        con = scoring.relevancia(severity="High", cvss_score=8.0, tecnologias=[tec])
        sin = scoring.relevancia(severity="High", cvss_score=8.0, tecnologias=[tec],
                                 ignorar_criticidad_baja=True)
        self.assertGreater(con, sin)
        self.assertEqual(sin, scoring.relevancia(severity="High", cvss_score=8.0, tecnologias=[]))

    def test_base_vacia(self):
        with db.connect(self.ruta) as conn:
            res = queries.clasificar_pendientes(conn, cfg=self.cfg, ahora=self.ahora)
        self.assertEqual(res["alertar"], [])
        self.assertEqual(sum(res["conteo"].values()), 0)


class TestPersistenciaYFirmas(_Base):
    def test_alert_skip_reason_se_escribe_y_se_limpia(self):
        with db.session(self.ruta) as conn:
            self._amenaza(conn, "espera", cve="CVE-2026-8", relevance=80, hace_horas=3)
        with db.connect(self.ruta) as conn:
            queries.clasificar_pendientes(conn, cfg=self.cfg, ahora=self.ahora, persistir=True)
            fila = conn.execute("SELECT alert_skip_reason, alert_skip_at FROM threats").fetchone()
        self.assertEqual(fila[0], "heuristica_en_espera")
        self.assertIsNotNone(fila[1])
        # 30 horas despues ya no espera: pasa y el motivo se borra
        with db.connect(self.ruta) as conn:
            res = queries.clasificar_pendientes(conn, cfg=self.cfg,
                                                ahora=self.ahora + timedelta(hours=30), persistir=True)
            fila = conn.execute("SELECT alert_skip_reason FROM threats").fetchone()
        self.assertEqual(len(res["alertar"]), 1)
        self.assertIsNone(fila[0])

    def test_firma_antigua_sigue_funcionando_y_excluye_cerradas(self):
        with db.session(self.ruta) as conn:
            self._amenaza(conn, "alta antigua", severity="High", relevance=10)
            self._amenaza(conn, "media", severity="Medium", relevance=10)
            self._amenaza(conn, "alta cerrada", severity="High", relevance=10, estado="descartada")
        with db.connect(self.ruta) as conn:
            viejo = queries.pendientes_de_alerta(conn, min_severidad="High")
            nuevo = queries.pendientes_de_alerta(conn, cfg=self.cfg)
        self.assertEqual([v["title_en"] for v in viejo], ["alta antigua"])
        self.assertEqual(nuevo, [])   # sin identificador

    def test_cambiar_estado(self):
        with db.session(self.ruta) as conn:
            tid = self._amenaza(conn, "gestionada", cve="CVE-2026-10")
            self.assertTrue(queries.cambiar_estado(conn, tid, "falso_positivo",
                                                   usuario="soc", motivo="ruido"))
            self.assertFalse(queries.cambiar_estado(conn, tid, "inventado", usuario="soc"))
            fila = conn.execute("SELECT estado, estado_por, estado_motivo FROM threats WHERE id=?",
                                (tid,)).fetchone()
        self.assertEqual(tuple(fila), ("falso_positivo", "soc", "ruido"))


class TestResumenSemanal(_Base):
    def test_recopilar_render_y_marcar(self):
        with db.session(self.ruta) as conn:
            t = self._tec(conn, "postgres")
            self._amenaza(conn, "seguimiento por tecnologia", cve="CVE-2026-20", origen="nvd",
                          relevance=35, hace_horas=24, tecs=[(t, "unknown", 0.9)])
            self._amenaza(conn, "solo mencion debil", cve="CVE-2026-21", origen="nvd",
                          relevance=35, hace_horas=24, tecs=[(t, "unknown", 0.4)])
            self._amenaza(conn, "informativa media", severity="Medium", relevance=10, hace_horas=24)
            self._amenaza(conn, "baja que no entra", severity="Low", relevance=2, hace_horas=24)
            self._amenaza(conn, "vieja fuera de ventana", cve="CVE-2026-22", relevance=40,
                          hace_horas=24 * 9)
            conn.execute("UPDATE threats SET alert_skip_reason='relevancia_baja' "
                         "WHERE title_en='solo mencion debil'")
            alertada = self._amenaza(conn, "alertada esta semana", cve="CVE-2026-23",
                                     origen="nvd", relevance=80, hace_horas=24)
            conn.execute("UPDATE threats SET alerted_at=? WHERE id=?",
                         (_iso(self.ahora - timedelta(hours=20)), alertada))
        with db.connect(self.ruta) as conn:
            datos = digest.recopilar(conn, cfg=self.cfg, ahora=self.ahora)
        self.assertEqual(datos["seguimiento_total"], 1)
        self.assertEqual(datos["seguimiento"][0]["tecnologia"]["name"], "Postgres")
        informativas = {v["title_en"] for v in datos["informativo"]}
        self.assertIn("informativa media", informativas)
        self.assertIn("solo mencion debil", informativas)     # mención débil no es seguimiento
        self.assertNotIn("baja que no entra", informativas)
        self.assertNotIn("vieja fuera de ventana", informativas)
        self.assertEqual(datos["descartadas_total"], 1)
        self.assertEqual(len(datos["alertadas"]), 1)
        self.assertFalse(datos["vacio"])

        html = digest.render(datos)
        for texto in ("Seguimiento", "Informativo", "Postgres", "relevancia inferior a 50",
                      "alertada esta semana"):
            self.assertIn(texto, html)
        self.assertNotIn("None", html.replace("none", ""))
        self.assertTrue(digest.asunto(datos["desde"]).startswith("[SOC] Resumen semanal"))

        with db.connect(self.ruta) as conn:
            n = digest.marcar_incluidas(conn, datos["ids_incluidas"])
            quedan = queries.no_alertadas_desde(conn, _iso(self.ahora - timedelta(days=7)),
                                                excluir_bajas=True)
        self.assertEqual(n, len(datos["ids_incluidas"]))
        # Las incluidas no se repiten; la Baja tampoco aparece: no se tiene en cuenta
        self.assertEqual([v["title_en"] for v in quedan], [])

    def test_resumen_vacio(self):
        with db.connect(self.ruta) as conn:
            datos = digest.recopilar(conn, cfg=self.cfg, ahora=self.ahora)
        self.assertTrue(datos["vacio"])


class TestComparacionNoEscribe(_Base):
    def test_comparar_criterios(self):
        spec = importlib.util.spec_from_file_location(
            "ejecucion_diaria", BASE_DIR / "bin" / "ejecucion_diaria.py")
        modulo = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(modulo)
        with db.session(self.ruta) as conn:
            self._amenaza(conn, "alta antigua sin cve", severity="High", relevance=10)
            self._amenaza(conn, "kev", cve="CVE-2026-30", kev=1, relevance=20)
        with db.connect(self.ruta) as conn:
            antes = conn.execute("SELECT alerted_at, alert_skip_reason FROM threats").fetchall()
            resultado = modulo.comparar_criterios(conn, self.cfg)
            despues = conn.execute("SELECT alerted_at, alert_skip_reason FROM threats").fetchall()
        self.assertEqual(resultado["antiguo"], 2)
        self.assertEqual(resultado["nuevo"], 1)
        self.assertEqual(resultado["kev_nuevo"], 1)
        self.assertEqual([tuple(r) for r in antes], [tuple(r) for r in despues])


if __name__ == "__main__":
    unittest.main()

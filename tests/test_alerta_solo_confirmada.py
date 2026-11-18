"""Sin afectación confirmada no se alerta: evaluar antes de decidir (2026-09-10).

Petición del usuario, sobre el correo de ese día: «en el correo de alertamiento de hoy veo
que no hay activos afectados según la vulnerabilidad, esa alerta sobre esas
vulnerabilidades que no me afectan ningún activo no tiene sentido, repito, me debe alertar
lo que realmente me esté afectando, de lo contrario no».

Medido en producción ese día: 35 amenazas alertadas y 4 sin ningún activo afectado
confirmado. Las cuatro NUNCA se habían evaluado —el cupo de reparto de
``applicability_max_threats_per_run`` (150) se lo llevaron las 923 amenazas nuevas del
día— y el filtro se abstenía a propósito para no callar nada por un fallo propio, así que
pasaban con el aviso «Afectación todavía sin evaluar».

Lo que vigilan estas pruebas:

* la ejecución diaria EVALÚA DIRIGIDO (``aplicabilidad.evaluar_dirigido``, sin el cupo de
  reparto) las candidatas a alertar que no tienen evaluación utilizable, ANTES de aplicar
  el filtro, y eso cambia la decisión cuando corresponde: si al evaluarlas resulta que sí
  afectan, se alertan; si resulta que no, se callan con el motivo exacto;
* lo que sigue sin evaluación después de eso NO se alerta y queda con el motivo nuevo
  ``sin_evaluar_todavia``, con su texto en la ficha, en el pie del correo y en el resumen
  semanal;
* la explotación activa confirmada tampoco alerta sin afectación confirmada, porque
  ``alert_kev_sin_activos`` pasa a valer False por omisión; y sí alerta si se activa;
* si algo se queda sin evaluar, se emite un aviso de administración: un fallo técnico no
  puede callar una vulnerabilidad en silencio;
* y el correo no puede contener ninguna frase de «afectación sin evaluar».

Sin red (OSV.dev simulado) y sin enviar correo (Mailer falso). Base temporal bajo data/.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from threatintel import aplicabilidad, db, digest, notify, queries
from threatintel.paths import BASE_DIR


class Cfg(dict):
    """Ajustes con la interfaz ``.get`` y los destinatarios que usan los avisos."""
    alert_to = ["equipo@example.invalid"]
    alert_cc: list = []
    admin_to = ["administracion@example.invalid"]

    def get(self, clave, defecto=None):
        return super().get(clave, defecto)


class MailerFalso:
    """Sustituto de ``notify.Mailer``: guarda los envíos y no manda nada."""

    def __init__(self, acepta: bool = True):
        self.acepta = acepta
        self.enviados: list[dict] = []

    def send(self, *, subject, html, to, cc=None, **_):
        self.enviados.append({"asunto": subject, "html": html, "to": list(to)})
        return self.acepta


#: Registro de OSV.dev simulado: la versión instalada del servidor (1.0) es vulnerable y
#: la corrección es la 2.0. Solo responde al CVE «que sí afecta».
REGISTRO = {
    "id": "UBUNTU-CVE-2026-4001",
    "affected": [{"package": {"ecosystem": "Ubuntu:22.04", "name": "openssl"},
                  "ranges": [{"type": "ECOSYSTEM",
                              "events": [{"introduced": "0"}, {"fixed": "2.0"}]}],
                  "ecosystem_specific": {"binaries": [{"binary_name": "openssl",
                                                       "binary_version": "2.0"}]}}],
}


class JsonFalso:
    def __init__(self, ok, status, data, error="", ms=5):
        self.ok, self.status, self.data, self.error, self.ms = ok, status, data, error, ms


def _fetch(url, **_kw):
    """OSV.dev simulado: solo conoce el CVE que de verdad afecta al servidor."""
    if url.endswith("UBUNTU-CVE-2026-4001"):
        return JsonFalso(True, 200, REGISTRO)
    return JsonFalso(False, 404, None, "http_404")


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class Base(unittest.TestCase):
    """Un servidor Ubuntu con openssl 1.0 instalado y cuatro amenazas sin evaluar."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "solo_confirmada.db")
        db.init_db(cls.ruta)
        cls.ahora = datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)
        cls.cfg = Cfg(alert_min_relevance=50, alert_require_identifier=True,
                      alert_defer_heuristic_hours=24, alert_min_match_confidence=0.6,
                      alert_only_affected_versions=False, alert_skip_without_assets=True,
                      applicability_enabled=True, alert_solo_con_activos_afectados=True,
                      alert_kev_sin_activos=False, ignore_low_severity=True,
                      applicability_max_osv_per_run=50, osv_cache_hours=168)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def setUp(self):
        with db.session(self.ruta) as conn:
            for tabla in ("aplicabilidad", "aplicabilidad_amenaza", "threats", "activos",
                          "activo_software", "osv_cache", "admin_notices", "remediaciones"):
                conn.execute(f"DELETE FROM {tabla}")
            ahora = db.utcnow()
            conn.execute(
                """INSERT INTO activos(id, origen, ocs_id, nombre, so_familia, so_version,
                       ecosistema, so_ciclo, zona, entorno, proceso, presente,
                       primera_vez_at, visto_at)
                   VALUES(1,'servidores',10,'SRV-CONTABILIDAD','ubuntu','22.04',
                          'Ubuntu:22.04','22.04','interna','produccion','Contabilidad',1,?,?)""",
                (ahora, ahora))
            conn.execute(
                """INSERT INTO activo_software(activo_id, nombre, nombre_norm, version)
                   VALUES(1,'openssl','openssl','1.0')""")

    # ------------------------------------------------------------------ ayudas
    def _amenaza(self, conn, ident: int, cve: str, *, severity="Critical", kev=0,
                 relevance=70.0, hace_horas=48) -> int:
        visto = _iso(self.ahora - timedelta(hours=hace_horas))
        conn.execute(
            """INSERT INTO threats(id, fingerprint, cve, title_en, title_es, severity,
                   severity_source, in_kev, first_seen_at, last_seen_at, month, relevance,
                   estado)
               VALUES(?,?,?,?,?,?, 'nvd', ?, ?, ?, '2026-09', ?, 'nueva')""",
            (ident, f"fp-{ident}", cve, f"Fallo {cve}", f"Fallo {cve}", severity, kev,
             visto, visto, relevance))
        return ident

    def _evaluacion(self, conn, threat_id, *, afectados=0, no_afectados=0, incompleta=0):
        conn.execute(
            """INSERT INTO aplicabilidad_amenaza(threat_id, evaluado_at, afectados,
                   no_afectados, sin_dato, detalle)
               VALUES(?,?,?,?,0,?)""",
            (threat_id, db.utcnow(), afectados, no_afectados,
             json.dumps({"incompleta": incompleta})))

    def _clasificar(self, cfg=None):
        with db.connect(self.ruta) as conn:
            res = queries.clasificar_pendientes(conn, cfg=cfg or self.cfg, ahora=self.ahora,
                                                persistir=False)
        motivos = {v["id"]: None for v in res["alertar"]}
        for motivo, ids in res["excluidas"].items():
            for i in ids:
                motivos[i] = motivo
        return motivos, res

    def _evaluar_dirigido(self, conn, cfg=None):
        """La evaluación dirigida como la hace la ejecución diaria, con OSV simulado."""
        cfg = cfg or self.cfg
        candidatas = queries.candidatas_sin_evaluacion(conn, cfg=cfg)
        osv = aplicabilidad.ClienteOSV(conn, cfg=cfg, fetch=_fetch)
        resultado = aplicabilidad.evaluar_dirigido(
            conn, [c["id"] for c in candidatas], cfg=cfg, osv=osv, recalcular=False)
        return candidatas, resultado


# ==========================================================================
class TestSinConfirmarNoSeAlerta(Base):
    def test_una_amenaza_sin_evaluar_no_se_alerta_y_queda_con_su_motivo(self):
        with db.session(self.ruta) as conn:
            self._amenaza(conn, 1, "CVE-2026-4001")
        motivos, res = self._clasificar()
        self.assertEqual(motivos[1], "sin_evaluar_todavia")
        self.assertEqual(res["alertar"], [])
        self.assertEqual(res["conteo"]["sin_evaluar_todavia"], 1)

    def test_el_motivo_se_persiste_y_se_limpia_cuando_deja_de_aplicar(self):
        with db.session(self.ruta) as conn:
            self._amenaza(conn, 1, "CVE-2026-4001")
        with db.connect(self.ruta) as conn:
            queries.clasificar_pendientes(conn, cfg=self.cfg, ahora=self.ahora, persistir=True)
            self.assertEqual(
                conn.execute("SELECT alert_skip_reason FROM threats WHERE id=1").fetchone()[0],
                "sin_evaluar_todavia")
        with db.session(self.ruta) as conn:
            self._evaluacion(conn, 1, afectados=1)
            conn.execute(
                """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete,
                       version_instalada, version_corregida, veredicto, motor, evaluado_at)
                   VALUES(1,1,'CVE-2026-4001','openssl','1.0','2.0','afectado','osv',?)""",
                (db.utcnow(),))
        with db.connect(self.ruta) as conn:
            res = queries.clasificar_pendientes(conn, cfg=self.cfg, ahora=self.ahora,
                                                persistir=True)
            self.assertEqual(len(res["alertar"]), 1)
            self.assertIsNone(
                conn.execute("SELECT alert_skip_reason FROM threats WHERE id=1").fetchone()[0])

    def test_el_texto_del_motivo_existe_en_los_tres_sitios(self):
        self.assertIn("sin_evaluar_todavia", queries.MOTIVOS_EXCLUSION)
        for tabla in (queries.MOTIVO_EXCLUSION_ES, notify.MOTIVOS_FILTRO_ES,
                      digest.FRASES_MOTIVO):
            self.assertIn("sin_evaluar_todavia", tabla)
            self.assertNotIn("_", tabla["sin_evaluar_todavia"].replace("{", "").replace("}", ""))
        frase = digest.frase_motivo("sin_evaluar_todavia", 4)
        self.assertIn("a la espera de la evaluación", frase)
        self.assertNotIn("sin_evaluar", frase)

    def test_lo_que_ya_se_evaluo_y_no_afecta_conserva_su_motivo_exacto(self):
        """«No nos afecta» y «no se sabe» no son lo mismo y no comparten motivo."""
        with db.session(self.ruta) as conn:
            self._amenaza(conn, 1, "CVE-2026-4002")
            self._evaluacion(conn, 1, afectados=0, no_afectados=1)
        motivos, _ = self._clasificar()
        self.assertEqual(motivos[1], "sin_activos_afectados")

    def test_el_correo_no_puede_llevar_ninguna_afectacion_sin_evaluar(self):
        with db.session(self.ruta) as conn:
            self._amenaza(conn, 1, "CVE-2026-4001")
            self._amenaza(conn, 2, "CVE-2026-4002")
            self._evaluacion(conn, 2, afectados=1)
            conn.execute(
                """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete,
                       version_instalada, version_corregida, veredicto, motor, evaluado_at)
                   VALUES(1,2,'CVE-2026-4002','openssl','1.0','2.0','afectado','osv',?)""",
                (db.utcnow(),))
        _motivos, res = self._clasificar()
        with db.connect(self.ruta) as conn:
            aplicabilidad.adjuntar_activos(conn, res["alertar"], limite=10)
        html = notify.render_alert_email(res["alertar"], {"detalle_top": 3})
        self.assertNotIn("Afectación todavía sin evaluar", html)
        self.assertNotIn("sin haber confirmado", html)
        # Y la cabecera cuadra: todas las del correo tienen activos confirmados.
        self.assertIn("de este correo", html)
        self.assertIn("La única</strong> amenaza de este correo tiene", html)


class TestEvaluarAntesDeDecidir(Base):
    def test_la_evaluacion_dirigida_cambia_la_decision_cuando_corresponde(self):
        """Las dos mitades del caso real del 2026-09-10: la que sí afecta acaba en el
        correo (335 activos en producción) y la que no, se calla con el motivo exacto."""
        with db.session(self.ruta) as conn:
            self._amenaza(conn, 1, "CVE-2026-4001")     # OSV dice que openssl 1.0 es vulnerable
            self._amenaza(conn, 2, "CVE-2026-4002")     # OSV no la conoce: no afecta
        antes, _res = self._clasificar()
        self.assertEqual(antes[1], "sin_evaluar_todavia")
        self.assertEqual(antes[2], "sin_evaluar_todavia")
        with db.session(self.ruta) as conn:
            candidatas, resultado = self._evaluar_dirigido(conn)
        self.assertEqual([c["id"] for c in candidatas], [1, 2])
        self.assertEqual(resultado["evaluadas"], 2)
        self.assertEqual(resultado["con_afectados"], 1)
        self.assertEqual(resultado["activos_afectados"], 1)
        self.assertEqual(resultado["sin_evaluar"], [])
        despues, res = self._clasificar()
        self.assertIsNone(despues[1], "al evaluarla resulta que sí nos afecta: se alerta")
        # Ya evaluada y sin ningún activo confirmado: el motivo es el preciso, no «no se
        # sabe». Es «sin_activos_confirmados» y no «sin_activos_afectados» porque las
        # bases de la distribución no listan ese CVE para nuestro ecosistema: no hay
        # evidencia positiva de que los activos ya lleven la corrección.
        self.assertEqual(despues[2], "sin_activos_confirmados")
        self.assertEqual([v["id"] for v in res["alertar"]], [1])

    def test_no_se_piden_las_que_no_se_pueden_o_no_hace_falta_evaluar(self):
        with db.session(self.ruta) as conn:
            self._amenaza(conn, 1, "CVE-2026-4001")                       # candidata
            self._amenaza(conn, 2, "CVE-2026-4002", relevance=10.0)       # irrelevante
            self._amenaza(conn, 3, "CVE-2026-4003", severity="Low", relevance=90.0)
            self._amenaza(conn, 4, "CVE-2026-4004")
            self._evaluacion(conn, 4, afectados=0, no_afectados=1)        # ya evaluada
            self._amenaza(conn, 5, "CVE-2026-4005", relevance=10.0, kev=1)  # KEV: siempre
            self._amenaza(conn, 6, "CVE-2026-4006")
            self._evaluacion(conn, 6, incompleta=1)                       # a medias: se repite
            conn.execute("UPDATE threats SET cve=NULL WHERE id=3")        # sin CVE: no evaluable
        with db.connect(self.ruta) as conn:
            ids = [c["id"] for c in queries.candidatas_sin_evaluacion(conn, cfg=self.cfg)]
        self.assertEqual(ids, [5, 1, 6], "explotación activa primero, después por relevancia")

    def test_la_evaluacion_dirigida_no_gasta_el_cupo_de_reparto(self):
        """El cupo de ``applicability_max_threats_per_run`` es de la cola general; la
        evaluación dirigida no lo usa, porque el día del incidente era justo ese cupo el
        que dejó sin evaluar las cuatro críticas."""
        cfg = Cfg(self.cfg, applicability_max_threats_per_run=1)
        with db.session(self.ruta) as conn:
            self._amenaza(conn, 1, "CVE-2026-4001")
            self._amenaza(conn, 2, "CVE-2026-4002")
            candidatas, resultado = self._evaluar_dirigido(conn, cfg=cfg)
        self.assertEqual(len(candidatas), 2)
        self.assertEqual(resultado["evaluadas"], 2)

    def test_el_tope_de_seguridad_acota_el_trabajo_y_lo_dice(self):
        with db.session(self.ruta) as conn:
            for i in (1, 2, 3):
                self._amenaza(conn, i, f"CVE-2026-400{i}")
            osv = aplicabilidad.ClienteOSV(conn, cfg=self.cfg, fetch=_fetch)
            resultado = aplicabilidad.evaluar_dirigido(
                conn, [1, 2, 3], cfg=self.cfg, osv=osv, limite=1, recalcular=False)
        self.assertEqual(resultado["evaluadas"], 1)
        self.assertEqual([p["motivo"] for p in resultado["sin_evaluar"]],
                         ["tope_dirigido", "tope_dirigido"])
        self.assertEqual(aplicabilidad.LIMITE_EVALUACION_DIRIGIDA, 250)

    def test_sin_cve_no_se_evalua_y_se_dice_por_que(self):
        with db.session(self.ruta) as conn:
            self._amenaza(conn, 1, "CVE-2026-4001")
            conn.execute("UPDATE threats SET cve=NULL WHERE id=1")
            osv = aplicabilidad.ClienteOSV(conn, cfg=self.cfg, fetch=_fetch)
            resultado = aplicabilidad.evaluar_dirigido(conn, [1], cfg=self.cfg, osv=osv,
                                                       recalcular=False)
        self.assertEqual(resultado["evaluadas"], 0)
        self.assertEqual(resultado["sin_evaluar"], [{"id": 1, "motivo": "sin_cve", "cve": None}])

    def test_con_la_evaluacion_desactivada_no_se_toca_nada(self):
        cfg = Cfg(self.cfg, applicability_enabled=False)
        with db.session(self.ruta) as conn:
            self._amenaza(conn, 1, "CVE-2026-4001")
            resultado = aplicabilidad.evaluar_dirigido(conn, [1], cfg=cfg, recalcular=False)
        self.assertTrue(resultado["omitido"])
        self.assertEqual(resultado["evaluadas"], 0)
        # Y el filtro no se aplica: sin motor que confirme nada, se alerta como antes.
        motivos, _ = self._clasificar(cfg)
        self.assertIsNone(motivos[1])

    def test_sin_inventario_el_filtro_sigue_absteniendose(self):
        """La única abstención que queda: sin un solo activo con presente=1, «no afecta a
        ninguna máquina» no significa nada y callar dejaría el correo vacío en silencio."""
        with db.session(self.ruta) as conn:
            conn.execute("UPDATE activos SET presente=0")
            self._amenaza(conn, 1, "CVE-2026-4001")
        motivos, _ = self._clasificar()
        self.assertIsNone(motivos[1])


class TestExplotacionActiva(Base):
    def test_una_kev_sin_afectacion_confirmada_no_se_alerta_por_omision(self):
        with db.session(self.ruta) as conn:
            self._amenaza(conn, 1, "CVE-2026-4002", kev=1, relevance=90.0)
            self._evaluacion(conn, 1, afectados=0, no_afectados=0)
        motivos, res = self._clasificar()
        self.assertEqual(motivos[1], "sin_activos_confirmados")
        self.assertEqual(res["alertar"], [])

    def test_la_misma_kev_se_alerta_si_el_ajuste_se_activa(self):
        with db.session(self.ruta) as conn:
            self._amenaza(conn, 1, "CVE-2026-4002", kev=1, relevance=90.0)
            self._evaluacion(conn, 1, afectados=0, no_afectados=0)
        cfg = Cfg(self.cfg, alert_kev_sin_activos=True)
        motivos, res = self._clasificar(cfg)
        self.assertIsNone(motivos[1])
        self.assertTrue(res["alertar"][0]["kev_sin_activos_confirmados"])
        html = notify.render_alert_email(res["alertar"], {"detalle_top": 3})
        self.assertIn("afectación NO confirmada", html)

    def test_una_kev_confirmada_se_alerta_siempre(self):
        with db.session(self.ruta) as conn:
            self._amenaza(conn, 1, "CVE-2026-4001", kev=1)
            self._evaluacion(conn, 1, afectados=1)
            conn.execute(
                """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete,
                       version_instalada, version_corregida, veredicto, motor, evaluado_at)
                   VALUES(1,1,'CVE-2026-4001','openssl','1.0','2.0','afectado','osv',?)""",
                (db.utcnow(),))
        motivos, _ = self._clasificar()
        self.assertIsNone(motivos[1])


class TestAvisoDeAdministracion(Base):
    def test_se_avisa_de_lo_que_no_se_pudo_evaluar(self):
        with db.session(self.ruta) as conn:
            self._amenaza(conn, 1, "CVE-2026-4009", kev=1)
            self._evaluacion(conn, 1, incompleta=1)
            candidatas = queries.candidatas_sin_evaluacion(conn, cfg=self.cfg)
            mailer = MailerFalso()
            aviso = aplicabilidad.avisar_sin_evaluar(
                conn, cfg=self.cfg, mailer=mailer,
                pendientes=[{**candidatas[0], "motivo": "incompleta"}], ahora=self.ahora)
        self.assertIsNotNone(aviso)
        self.assertEqual((aviso["pendientes"], aviso["kev"], aviso["severidad"]),
                         (1, 1, "critical"))
        self.assertEqual(len(mailer.enviados), 1)
        html = mailer.enviados[0]["html"]
        self.assertIn("CVE-2026-4009", html)
        self.assertIn("no se pudo completar", html)
        # Revisión de claridad del 2026-09-15: un solo prefijo para todo el sistema
        # («[Inteligencia de Amenazas]») y «Acción requerida» con tilde y sin gritar.
        self.assertIn("Acción requerida", mailer.enviados[0]["asunto"])
        self.assertTrue(mailer.enviados[0]["asunto"].startswith("[Inteligencia de Amenazas]"))
        self.assertEqual(mailer.enviados[0]["to"], ["administracion@example.invalid"])

    def test_el_mismo_aviso_no_se_repite_el_mismo_dia(self):
        with db.session(self.ruta) as conn:
            self._amenaza(conn, 1, "CVE-2026-4009")
            pendientes = [{"id": 1, "cve": "CVE-2026-4009", "severity": "Critical",
                           "relevance": 70.0, "motivo": "incompleta"}]
            primero = aplicabilidad.avisar_sin_evaluar(
                conn, cfg=self.cfg, mailer=MailerFalso(), pendientes=pendientes,
                ahora=self.ahora)
            mailer = MailerFalso()
            segundo = aplicabilidad.avisar_sin_evaluar(
                conn, cfg=self.cfg, mailer=mailer, pendientes=pendientes,
                ahora=self.ahora + timedelta(hours=2))
            # Al día siguiente vuelve a avisar: si sigue sin poder comprobarse, hay que
            # decirlo otra vez.
            tercero = aplicabilidad.avisar_sin_evaluar(
                conn, cfg=self.cfg, mailer=MailerFalso(), pendientes=pendientes,
                ahora=self.ahora + timedelta(hours=25))
        self.assertIsNotNone(primero)
        self.assertIsNone(segundo)
        self.assertEqual(mailer.enviados, [])
        self.assertIsNotNone(tercero)

    def test_sin_destinatarios_no_se_marca_nada_y_se_reintenta(self):
        class SinAdmin(Cfg):
            admin_to: list = []
        with db.session(self.ruta) as conn:
            self._amenaza(conn, 1, "CVE-2026-4009")
            pendientes = [{"id": 1, "cve": "CVE-2026-4009", "motivo": "incompleta"}]
            self.assertIsNone(aplicabilidad.avisar_sin_evaluar(
                conn, cfg=SinAdmin(self.cfg), mailer=MailerFalso(), pendientes=pendientes))
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM admin_notices").fetchone()[0], 0)
            # Y con un servidor de correo que rechaza el envío, tampoco.
            self.assertIsNone(aplicabilidad.avisar_sin_evaluar(
                conn, cfg=self.cfg, mailer=MailerFalso(acepta=False), pendientes=pendientes))
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM admin_notices").fetchone()[0], 0)

    def test_sin_nada_pendiente_no_se_envia_ningun_correo(self):
        with db.session(self.ruta) as conn:
            mailer = MailerFalso()
            self.assertIsNone(aplicabilidad.avisar_sin_evaluar(
                conn, cfg=self.cfg, mailer=mailer, pendientes=[]))
        self.assertEqual(mailer.enviados, [])


if __name__ == "__main__":
    unittest.main()

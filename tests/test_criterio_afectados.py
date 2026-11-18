"""Criterio de afectación real: solo se alerta lo que afecta a alguna máquina (2026-09-08).

El usuario protestó el 8 de septiembre de 2026 porque el correo de ese día alertó de
CVE-2026-75650 (Crítica, relevancia 63,1) sin un solo activo afectado: «solo me debe
alertar lo que me afecta». Aquí se comprueba el motivo de exclusión nuevo
(`sin_activos_confirmados`), sus salvaguardas y la excepción de la explotación activa
confirmada (KEV).

REVISIÓN DEL 2026-09-10: el usuario volvió a protestar por el correo de ese día («en el
correo de alertamiento de hoy veo que no hay activos afectados según la vulnerabilidad…
me debe alertar lo que realmente me esté afectando, de lo contrario no»). Las cuatro
amenazas que se colaron no estaban confirmadas: NUNCA se habían evaluado, y el filtro se
abstenía a propósito para no callar nada por un fallo propio. La regla cambia:

* la ejecución diaria EVALÚA DIRIGIDO las candidatas sin evaluación antes de decidir
  (``aplicabilidad.evaluar_dirigido``), así que la decisión se toma con datos;
* lo que después de eso siga sin evaluación o con la evaluación incompleta NO se alerta y
  queda con el motivo nuevo ``sin_evaluar_todavia``;
* la explotación activa confirmada tampoco alerta sin afectación confirmada
  (``alert_kev_sin_activos`` pasa a valer False por omisión);
* la única abstención que queda es «no hay inventario»: sin un solo activo con presente=1
  el criterio no significa nada;
* y para que un fallo técnico no calle nada en silencio, lo que no se pudo evaluar sale en
  un aviso de administración (``aplicabilidad.avisar_sin_evaluar``).

Las cinco pruebas de ``TestSalvaguardas`` que exigían lo contrario se han reescrito abajo
con la regla nueva, conservando el caso que reproducían: lo que antes se comprobaba como
«se alerta igual» ahora se comprueba como «no se alerta, pero queda registrado, se
reevalúa y se avisa a administración».

Ninguna prueba toca la base real ni envía correo: base temporal bajo data/.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from threatintel import db, queries
from threatintel.paths import BASE_DIR


class Cfg(dict):
    """Configuración mínima con la interfaz `.get` que usan las funciones."""
    alert_to = ["equipo@example.invalid"]
    alert_cc: list = []


class _CfgConAdmin(Cfg):
    """Igual, con destinatarios de administración: los del aviso de lo no evaluado."""
    admin_to = ["administracion@example.invalid"]


class _MailerFalso:
    """Sustituto de ``notify.Mailer``: guarda los envíos y no manda nada."""

    def __init__(self, acepta: bool = True):
        self.acepta = acepta
        self.enviados: list = []

    def send(self, *, subject, html, to, cc=None, **_):
        self.enviados.append({"asunto": subject, "html": html, "to": list(to)})
        return self.acepta


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "afectados.db")
        db.init_db(cls.ruta)
        cls.ahora = datetime(2026, 9, 8, 12, 0, tzinfo=timezone.utc)
        cls.cfg = Cfg(alert_min_relevance=50, alert_require_identifier=True,
                      alert_defer_heuristic_hours=24, alert_min_match_confidence=0.6,
                      alert_only_affected_versions=False, alert_min_severity="High",
                      alert_skip_without_assets=True, applicability_enabled=True,
                      alert_solo_con_activos_afectados=True, alert_kev_sin_activos=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def setUp(self):
        with db.session(self.ruta) as conn:
            conn.execute("DELETE FROM aplicabilidad")
            conn.execute("DELETE FROM aplicabilidad_amenaza")
            conn.execute("DELETE FROM activos")
            conn.execute("DELETE FROM threats")

    # ------------------------------------------------------------ utilidades
    def _activo(self, conn, nombre, *, origen="servidores", presente=1, ocs_id=None) -> int:
        ahora = db.utcnow()
        conn.execute(
            """INSERT INTO activos(origen, ocs_id, nombre, so_familia, presente,
                   primera_vez_at, visto_at, entorno)
               VALUES(?,?,?,?,?,?,?,'produccion')""",
            (origen, ocs_id if ocs_id is not None else abs(hash(nombre)) % 100000,
             nombre, "ubuntu", presente, ahora, ahora))
        return conn.execute("SELECT id FROM activos WHERE nombre=?", (nombre,)).fetchone()[0]

    def _amenaza(self, conn, titulo, *, cve=None, severity="High", relevance=70.0,
                 kev=0, estado="nueva", hace_horas=48) -> int:
        visto = _iso(self.ahora - timedelta(hours=hace_horas))
        conn.execute(
            """INSERT INTO threats(fingerprint,cve,title_en,severity,severity_source,in_kev,
                   first_seen_at,last_seen_at,month,relevance,estado)
               VALUES(?,?,?,?,'nvd',?,?,?,'2026-09',?,?)""",
            (f"fp-{titulo}", cve or f"CVE-2026-{abs(hash(titulo)) % 9999}", titulo,
             severity, kev, visto, visto, relevance, estado))
        return conn.execute("SELECT id FROM threats WHERE title_en=?", (titulo,)).fetchone()[0]

    def _veredicto(self, conn, activo_id, threat_id, veredicto, *, paquete="openssl") -> None:
        cve = conn.execute("SELECT cve FROM threats WHERE id=?", (threat_id,)).fetchone()[0]
        conn.execute(
            """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete, version_instalada,
                   version_corregida, veredicto, motor, evaluado_at)
               VALUES(?,?,?,?,'1.0','1.1',?, 'osv', ?)""",
            (activo_id, threat_id, cve, paquete, veredicto, db.utcnow()))

    def _evaluacion(self, conn, threat_id, *, afectados=0, no_afectados=0, sin_dato=0,
                    incompleta=0, distro_no_afectada=0, tecnologias_solo_so=0) -> None:
        """Fila de `aplicabilidad_amenaza`: es lo que lee el filtro para saber si la
        evaluación quedó completa y si hay evidencia positiva de no afectación."""
        conn.execute(
            """INSERT INTO aplicabilidad_amenaza(threat_id, evaluado_at, afectados,
                   no_afectados, sin_dato, detalle)
               VALUES(?,?,?,?,?,?)""",
            (threat_id, db.utcnow(), afectados, no_afectados, sin_dato,
             json.dumps({"incompleta": incompleta, "distro_no_afectada": distro_no_afectada,
                         "tecnologias_solo_so": tecnologias_solo_so})))

    def _clasificar(self, cfg=None, **kwargs):
        """Devuelve ({título: motivo o None}, resultado) sin escribir en la base."""
        with db.connect(self.ruta) as conn:
            res = queries.clasificar_pendientes(conn, cfg=cfg or self.cfg, ahora=self.ahora,
                                                persistir=False, **kwargs)
            titulos = {r[0]: r[1] for r in conn.execute("SELECT id, title_en FROM threats")}
        motivos = {v["title_en"]: None for v in res["alertar"]}
        for motivo, ids in res["excluidas"].items():
            for i in ids:
                motivos[titulos[i]] = motivo
        return motivos, res


class TestSoloLoQueAfecta(_Base):
    def test_con_activo_afectado_se_alerta(self):
        with db.session(self.ruta) as conn:
            activo = self._activo(conn, "srv-web-01")
            tid = self._amenaza(conn, "afecta a un servidor", cve="CVE-2026-1001")
            self._veredicto(conn, activo, tid, "afectado")
            self._evaluacion(conn, tid, afectados=1)
        motivos, res = self._clasificar()
        self.assertIsNone(motivos["afecta a un servidor"])
        self.assertEqual(res["alertar"][0]["activos_afectados_presentes"], 1)
        self.assertEqual(res["conteo"]["sin_activos_confirmados"], 0)

    def test_sin_activos_afectados_no_se_alerta(self):
        """El caso de CVE-2026-75650: relevancia alta, cero activos afectados."""
        with db.session(self.ruta) as conn:
            self._activo(conn, "srv-web-01")
            tid = self._amenaza(conn, "critica que no nos toca", cve="CVE-2026-75650",
                                severity="Critical", relevance=63.1)
            self._evaluacion(conn, tid)
        motivos, res = self._clasificar()
        self.assertEqual(motivos["critica que no nos toca"], "sin_activos_confirmados")
        self.assertEqual(res["alertar"], [])

    def test_veredicto_no_afectado_o_sin_dato_no_bastan(self):
        """Solo 'afectado' cuenta: tener el paquete pero corregido, o sin poder
        compararlo, no es afectación confirmada."""
        with db.session(self.ruta) as conn:
            a1 = self._activo(conn, "srv-app-01")
            a2 = self._activo(conn, "pc-contabilidad-01", origen="equipos")
            t1 = self._amenaza(conn, "ya corregida en los activos", cve="CVE-2026-1002")
            t2 = self._amenaza(conn, "version no comparable", cve="CVE-2026-1003")
            self._veredicto(conn, a1, t1, "no_afectado")
            self._veredicto(conn, a2, t2, "sin_dato")
            self._evaluacion(conn, t1, no_afectados=1)
            self._evaluacion(conn, t2, sin_dato=1)
        motivos, _ = self._clasificar()
        # Con evidencia positiva de no afectación gana el motivo más informativo
        # que ya existía (4b); con 'sin_dato' se cae en el criterio nuevo.
        self.assertEqual(motivos["ya corregida en los activos"], "sin_activos_afectados")
        self.assertEqual(motivos["version no comparable"], "sin_activos_confirmados")

    def test_activo_ausente_no_cuenta(self):
        """Un activo dado de baja en OCS (presente=0) no justifica una alerta: ya no
        existe nada que corregir. Hay otro activo presente para que el inventario
        siga siendo utilizable y el filtro no se abstenga."""
        with db.session(self.ruta) as conn:
            self._activo(conn, "srv-vivo-01")
            baja = self._activo(conn, "srv-retirado-01", presente=0)
            tid = self._amenaza(conn, "solo en un activo retirado", cve="CVE-2026-1004")
            self._veredicto(conn, baja, tid, "afectado")
            self._evaluacion(conn, tid, afectados=1)
        motivos, _ = self._clasificar()
        self.assertEqual(motivos["solo en un activo retirado"], "sin_activos_confirmados")

    def test_amenaza_cerrada_no_se_alerta_aunque_afecte(self):
        """Descartada o falso positivo (queries.ESTADOS_CERRADOS) manda sobre todo lo
        demás: el equipo ya decidió. «Mitigada» no es un estado cerrado, así que sigue
        alertándose mientras la evaluación siga confirmando activos afectados."""
        with db.session(self.ruta) as conn:
            activo = self._activo(conn, "srv-web-02")
            for titulo, estado in (("descartada con activos", "descartada"),
                                   ("falso positivo con activos", "falso_positivo"),
                                   ("mitigada con activos", "mitigada")):
                tid = self._amenaza(conn, titulo, estado=estado)
                self._veredicto(conn, activo, tid, "afectado", paquete=titulo[:10])
                self._evaluacion(conn, tid, afectados=1)
        motivos, res = self._clasificar()
        self.assertEqual([v["title_en"] for v in res["alertar"]], ["mitigada con activos"])
        for titulo in ("descartada con activos", "falso positivo con activos"):
            self.assertEqual(motivos[titulo], "estado_cerrado")

    def test_afectacion_de_otra_amenaza_no_vale(self):
        with db.session(self.ruta) as conn:
            activo = self._activo(conn, "srv-web-03")
            afecta = self._amenaza(conn, "esta si afecta", cve="CVE-2026-1005")
            otra = self._amenaza(conn, "esta no afecta", cve="CVE-2026-1006")
            self._veredicto(conn, activo, afecta, "afectado")
            self._evaluacion(conn, afecta, afectados=1)
            self._evaluacion(conn, otra)
        motivos, _ = self._clasificar()
        self.assertIsNone(motivos["esta si afecta"])
        self.assertEqual(motivos["esta no afecta"], "sin_activos_confirmados")

    def test_el_motivo_se_persiste_y_se_borra_al_confirmarse(self):
        """La exclusión no es definitiva: en cuanto la evaluación confirma un activo,
        la amenaza vuelve a alertarse y el motivo se limpia."""
        with db.session(self.ruta) as conn:
            activo = self._activo(conn, "srv-web-04")
            tid = self._amenaza(conn, "confirmada al dia siguiente", cve="CVE-2026-1007")
            self._evaluacion(conn, tid)
        with db.connect(self.ruta) as conn:
            queries.clasificar_pendientes(conn, cfg=self.cfg, ahora=self.ahora, persistir=True)
            fila = conn.execute("SELECT alert_skip_reason, alert_skip_at, alerted_at "
                                "FROM threats WHERE id=?", (tid,)).fetchone()
        self.assertEqual(fila[0], "sin_activos_confirmados")
        self.assertIsNotNone(fila[1])
        self.assertIsNone(fila[2])          # sigue pendiente, no se pierde
        with db.session(self.ruta) as conn:
            self._veredicto(conn, activo, tid, "afectado")
            conn.execute("UPDATE aplicabilidad_amenaza SET afectados=1 WHERE threat_id=?", (tid,))
        with db.connect(self.ruta) as conn:
            res = queries.clasificar_pendientes(conn, cfg=self.cfg,
                                                ahora=self.ahora + timedelta(days=1),
                                                persistir=True)
            fila = conn.execute("SELECT alert_skip_reason FROM threats WHERE id=?", (tid,)).fetchone()
        self.assertEqual([v["id"] for v in res["alertar"]], [tid])
        self.assertIsNone(fila[0])

    def test_todos_los_motivos_en_el_conteo(self):
        motivos, res = self._clasificar()
        self.assertEqual(set(res["conteo"]), set(queries.MOTIVOS_EXCLUSION))
        self.assertIn("sin_activos_confirmados", queries.MOTIVOS_EXCLUSION)
        self.assertIn("sin afectación confirmada",
                      queries.MOTIVO_EXCLUSION_ES["sin_activos_confirmados"])


class TestExplotacionActivaKev(_Base):
    def test_kev_sin_activos_se_alerta_y_queda_avisada(self):
        """Decisión del 2026-09-08: una vulnerabilidad que se está explotando hoy y no
        aparece en el inventario puede ser un fallo de nuestra evaluación, no una
        ausencia real de riesgo. Se alerta, marcada para que el correo lo diga."""
        with db.session(self.ruta) as conn:
            self._activo(conn, "srv-web-05")
            tid = self._amenaza(conn, "kev sin confirmar", cve="CVE-2026-2001",
                                kev=1, relevance=10.0)
            self._evaluacion(conn, tid)
        motivos, res = self._clasificar()
        self.assertIsNone(motivos["kev sin confirmar"])
        self.assertTrue(res["alertar"][0]["kev_sin_activos_confirmados"])

    def test_kev_con_activos_no_lleva_el_aviso(self):
        with db.session(self.ruta) as conn:
            activo = self._activo(conn, "srv-web-06")
            tid = self._amenaza(conn, "kev confirmada", cve="CVE-2026-2002", kev=1)
            self._veredicto(conn, activo, tid, "afectado")
            self._evaluacion(conn, tid, afectados=1)
        _, res = self._clasificar()
        self.assertFalse(res["alertar"][0].get("kev_sin_activos_confirmados"))

    def test_la_excepcion_kev_se_puede_apagar(self):
        with db.session(self.ruta) as conn:
            self._activo(conn, "srv-web-07")
            tid = self._amenaza(conn, "kev sin confirmar", cve="CVE-2026-2003", kev=1)
            self._evaluacion(conn, tid)
        cfg = Cfg(self.cfg, alert_kev_sin_activos=False)
        motivos, res = self._clasificar(cfg)
        self.assertEqual(motivos["kev sin confirmar"], "sin_activos_confirmados")
        self.assertEqual(res["alertar"], [])

    def test_kev_con_evidencia_de_no_afectacion_sigue_excluida(self):
        """La evidencia positiva (4b) es más fuerte que la falta de confirmación: si
        consta que los activos ya llevan la corrección, ni una KEV alerta."""
        with db.session(self.ruta) as conn:
            activo = self._activo(conn, "srv-web-08")
            tid = self._amenaza(conn, "kev ya corregida", cve="CVE-2026-2004", kev=1)
            self._veredicto(conn, activo, tid, "no_afectado")
            self._evaluacion(conn, tid, no_afectados=1)
        motivos, _ = self._clasificar()
        self.assertEqual(motivos["kev ya corregida"], "sin_activos_afectados")


class TestAjustesCableados(unittest.TestCase):
    """Los dos interruptores tienen que existir en los tres sitios: valor por omisión,
    página de ajustes y filtro. Un ajuste que solo esté en el código no se puede
    apagar cuando hace falta, y uno que solo esté en la página no hace nada."""

    def test_valores_por_omision(self):
        """El criterio de afectación real viene activado; la excepción de la explotación
        activa, DESACTIVADA desde el 2026-09-10 (orden del usuario: sin afectación
        confirmada no se alerta, ni siquiera una KEV). El ajuste se conserva porque la
        decisión es reversible."""
        from threatintel import config
        self.assertIs(config.DEFAULT_SETTINGS["alert_solo_con_activos_afectados"], True)
        self.assertIs(config.DEFAULT_SETTINGS["alert_kev_sin_activos"], False)

    def test_editables_desde_la_pagina_de_ajustes(self):
        from webui.vistas import ajustes
        claves = {c: tipo for _, items in ajustes.GRUPOS for c, _, tipo, _ in items}
        for clave in ("alert_solo_con_activos_afectados", "alert_kev_sin_activos"):
            self.assertEqual(claves.get(clave), "bool", clave)

    def test_la_ayuda_de_las_alertas_no_dice_equipos_a_secas(self):
        """Vocabulario del proyecto: «equipos» a secas no distingue servidores de
        equipos de cómputo y el usuario protestó justo por eso. Se vigila el grupo
        «Alertas diarias», que es donde vive este cambio; los textos del grupo de
        OCS los mantiene el trabajo de inventario y se revisan aparte."""
        import re
        from webui.vistas import ajustes
        grupo = next(items for nombre, items in ajustes.GRUPOS if nombre == "Alertas diarias")
        prohibido = re.compile(r"\b[Ee]quipos\b(?!\s+de\s+(?:c[oó]mputo|usuario))")
        for clave, etiqueta, _, ayuda in grupo:
            for texto in (etiqueta, ayuda):
                self.assertIsNone(prohibido.search(texto),
                                  f"«equipos» a secas en el ajuste {clave}: {texto}")

    def test_el_motivo_nuevo_se_explica_sin_abreviaturas(self):
        """El texto del motivo lo leen la ficha, el correo y el informe: tiene que
        decir a qué tipo de máquina se refiere."""
        texto = queries.MOTIVO_EXCLUSION_ES["sin_activos_confirmados"]
        self.assertIn("servidor", texto)
        self.assertIn("equipo de cómputo", texto)
        self.assertIn("OCS Inventory", texto)


class TestSalvaguardas(_Base):
    def test_ajuste_apagado_restaura_el_comportamiento_anterior(self):
        with db.session(self.ruta) as conn:
            self._activo(conn, "srv-web-09")
            self._amenaza(conn, "relevante sin activos", cve="CVE-2026-3001", relevance=63.1)
        cfg = Cfg(self.cfg, alert_solo_con_activos_afectados=False)
        motivos, res = self._clasificar(cfg)
        self.assertIsNone(motivos["relevante sin activos"])
        self.assertEqual(res["conteo"]["sin_activos_confirmados"], 0)
        # y el argumento explícito manda sobre el ajuste (lo usa --comparar)
        motivos, _ = self._clasificar(solo_con_activos=False)
        self.assertIsNone(motivos["relevante sin activos"])

    def test_sin_inventario_el_filtro_se_abstiene(self):
        """Sin activos sincronizados, «no afecta a ninguna máquina» no significa nada:
        callar la alerta dejaría el correo vacío por un fallo de sincronización."""
        with db.session(self.ruta) as conn:
            self._amenaza(conn, "relevante sin inventario", cve="CVE-2026-3002")
        motivos, _ = self._clasificar()
        self.assertIsNone(motivos["relevante sin inventario"])
        # con un inventario que existe pero todo dado de baja, tampoco se aplica
        with db.session(self.ruta) as conn:
            self._activo(conn, "srv-retirado-02", presente=0)
        motivos, _ = self._clasificar()
        self.assertIsNone(motivos["relevante sin inventario"])

    def test_evaluacion_incompleta_no_se_alerta_pero_queda_registrada(self):
        """Si la evaluación falló (OSV o VuXML no respondieron), el cero de activos
        afectados no es un dato. Hasta el 2026-09-09 eso bastaba para alertar; desde el
        2026-09-10 no se alerta —el usuario no quiere en el correo lo que no está
        confirmado— y queda con el motivo «a la espera de la evaluación», que se reintenta
        cada día y sale en el aviso de administración."""
        with db.session(self.ruta) as conn:
            self._activo(conn, "srv-web-10")
            tid = self._amenaza(conn, "evaluacion a medias", cve="CVE-2026-3003")
            self._evaluacion(conn, tid, incompleta=1)
        motivos, res = self._clasificar()
        self.assertEqual(motivos["evaluacion a medias"], "sin_evaluar_todavia")
        self.assertEqual(res["conteo"]["sin_activos_confirmados"], 0,
                         "no es «no nos afecta»: es que no se sabe")

    def test_amenaza_con_cve_todavia_sin_evaluar_no_se_alerta(self):
        """El caso exacto del correo del 2026-09-10: la amenaza tiene CVE y relevancia
        alta, pero el motor no había llegado a ella (el cupo de reparto se lo llevaron las
        923 amenazas nuevas del día). Sin fila en `aplicabilidad_amenaza` no se sabe si
        nos afecta, así que NO se alerta y queda con «sin_evaluar_todavia»; la ejecución
        diaria la evalúa dirigida antes de decidir y, si no puede, avisa a
        administración."""
        with db.session(self.ruta) as conn:
            self._activo(conn, "srv-web-12")
            self._amenaza(conn, "con cve sin evaluar", cve="CVE-2026-3005", relevance=63.1)
        motivos, res = self._clasificar()
        self.assertEqual(motivos["con cve sin evaluar"], "sin_evaluar_todavia")
        self.assertEqual(res["conteo"]["sin_activos_confirmados"], 0)
        self.assertEqual(len(res["excluidas"]["sin_evaluar_todavia"]), 1)

    def test_lo_irrelevante_sin_evaluar_sigue_siendo_irrelevante(self):
        """El motivo nuevo es solo para las CANDIDATAS a alertar. Una amenaza sin evaluar
        cuya relevancia no llega al umbral no se habría alertado nunca, así que su motivo
        sigue siendo «relevancia_baja»: medido sobre la base real el 2026-09-10, sin esta
        condición el motivo nuevo se llevaba 241 amenazas irrelevantes y el resumen
        semanal habría dicho «241 a la espera de la evaluación»."""
        with db.session(self.ruta) as conn:
            self._activo(conn, "srv-web-18")
            self._amenaza(conn, "irrelevante sin evaluar", cve="CVE-2026-3008", relevance=12.0)
        motivos, res = self._clasificar()
        self.assertEqual(motivos["irrelevante sin evaluar"], "relevancia_baja")
        self.assertEqual(res["conteo"]["sin_evaluar_todavia"], 0)

    def test_un_fallo_de_la_evaluacion_no_calla_nada_en_silencio(self):
        """El mismo caso a escala: se borra la evaluación entera, como el día que falló la
        fase de aplicabilidad. Hasta el 2026-09-09 las tres se alertaban «por si acaso»;
        desde el 2026-09-10 no se alertan (el usuario no quiere en el correo lo que no
        está confirmado), pero el fallo NO queda en silencio: las tres son candidatas a
        alertar sin evaluación, la ejecución diaria las evalúa dirigidas y, si no puede,
        emite un aviso de administración con la lista y el motivo."""
        from threatintel import aplicabilidad
        with db.session(self.ruta) as conn:
            activo = self._activo(conn, "srv-web-13")
            for i in range(3):
                tid = self._amenaza(conn, f"relevante {i}", cve=f"CVE-2026-31{i:02d}",
                                    relevance=63.1)
                self._veredicto(conn, activo, tid, "afectado", paquete=f"paq{i}")
                self._evaluacion(conn, tid, afectados=1)
        motivos, _ = self._clasificar()
        self.assertEqual([m for m in motivos.values() if m], [])
        with db.session(self.ruta) as conn:                 # el día que falló la fase
            conn.execute("DELETE FROM aplicabilidad")
            conn.execute("DELETE FROM aplicabilidad_amenaza")
        motivos, res = self._clasificar()
        self.assertEqual(len(res["alertar"]), 0)
        self.assertEqual(len(res["excluidas"]["sin_evaluar_todavia"]), 3)
        # Las tres son exactamente las que la ejecución diaria evalúa antes de decidir…
        with db.connect(self.ruta) as conn:
            candidatas = queries.candidatas_sin_evaluacion(conn, cfg=self.cfg)
            self.assertEqual(len(candidatas), 3)
            # …y si no se pudieran evaluar, el aviso de administración lo dice.
            mailer = _MailerFalso()
            aviso = aplicabilidad.avisar_sin_evaluar(
                conn, cfg=_CfgConAdmin(self.cfg),
                pendientes=[{**c, "motivo": "incompleta"} for c in candidatas],
                mailer=mailer)
        self.assertIsNotNone(aviso)
        self.assertEqual(aviso["pendientes"], 3)
        self.assertEqual(len(mailer.enviados), 1)
        self.assertIn("NO ha podido comprobar", mailer.enviados[0]["html"])
        self.assertIn("ACCION REQUERIDA" if aviso["severidad"] == "critical" else "Aviso",
                      mailer.enviados[0]["asunto"])

    def test_amenaza_sin_cve_tampoco_se_alerta_sin_confirmar(self):
        """`aplicabilidad` solo evalúa amenazas con CVE, así que un aviso de proveedor sin
        CVE (DSA, USN, RHSA, SUSE-SU) no se puede confirmar contra el inventario. Hasta el
        2026-09-09 eso lo exceptuaba del filtro; desde el 2026-09-10 no: sin confirmación
        no se alerta, y queda con «sin_evaluar_todavia» —consultable, en el resumen
        semanal y en el aviso de administración— hasta que llegue con CVE o alguien lo
        revise a mano. Medido sobre la base real ese día: ninguna de las 35 amenazas
        alertadas venía sin CVE, así que el cambio no quita nada que hoy se reporte."""
        with db.session(self.ruta) as conn:
            self._activo(conn, "srv-web-14")
            visto = _iso(self.ahora - timedelta(hours=48))
            conn.execute(
                """INSERT INTO threats(fingerprint,cve,title_en,summary_en,severity,
                       severity_source,in_kev,first_seen_at,last_seen_at,month,relevance,estado)
                   VALUES('fp-dsa', NULL, 'aviso de proveedor sin cve',
                          'DSA-5555-1 actualización de seguridad de openssl', 'High',
                          'vendor', 0, ?, ?, '2026-09', 63.1, 'nueva')""", (visto, visto))
            tid = conn.execute("SELECT id FROM threats WHERE fingerprint='fp-dsa'").fetchone()[0]
            self._evaluacion(conn, tid)          # evaluada y con cero activos afectados
        motivos, res = self._clasificar()
        self.assertEqual(motivos["aviso de proveedor sin cve"], "sin_evaluar_todavia")
        # Y no aparece entre las candidatas de la evaluación dirigida: sin CVE no hay nada
        # que evaluar, así que pedirla sería gastar el cupo de OSV.dev en balde.
        with db.connect(self.ruta) as conn:
            self.assertEqual(queries.candidatas_sin_evaluacion(conn, cfg=self.cfg), [])

    def test_la_afectacion_se_cuenta_por_cve_y_no_solo_por_amenaza(self):
        """La fila de `aplicabilidad` es única por (activo, cve, paquete) y su
        `threat_id` lo sobrescribe la última amenaza evaluada. El mismo CVE llega por
        dos fuentes en 139 casos de producción, así que una de las hermanas se quedaba
        con cero activos propios y se callaba una vulnerabilidad confirmada de verdad
        (CVE-2026-50508, amenazas 5668 y 2607)."""
        with db.session(self.ruta) as conn:
            activo = self._activo(conn, "srv-web-15")
            hermana = self._amenaza(conn, "misma cve por otra fuente", cve="CVE-2026-50508")
            propia = self._amenaza(conn, "misma cve fuente original", cve="CVE-2026-50508",
                                   relevance=51.0)
            self._veredicto(conn, activo, propia, "afectado")
            self._evaluacion(conn, hermana)
            self._evaluacion(conn, propia, afectados=1)
        motivos, res = self._clasificar()
        self.assertIsNone(motivos["misma cve fuente original"])
        self.assertIsNone(motivos["misma cve por otra fuente"],
                          "la hermana cuenta los activos de su CVE, no solo los suyos")
        for vista in res["alertar"]:
            self.assertEqual(vista["activos_afectados_presentes"], 1)

    def test_el_correo_ya_no_puede_llevar_una_afectacion_sin_evaluar(self):
        """Hasta el 2026-09-09 la amenaza que se alertaba por abstención llevaba en el
        correo el bloque «Afectación todavía sin evaluar», que es justo lo que el usuario
        rechazó el 2026-09-10 («se alerta por su relevancia sin haber confirmado todavía
        que nos afecte»). Ahora esa amenaza no entra en el correo, así que el bloque no
        puede aparecer: se retiró de la plantilla y esta prueba lo vigila."""
        from threatintel import notify
        with db.session(self.ruta) as conn:
            self._activo(conn, "srv-web-16")
            self._amenaza(conn, "relevante sin evaluar", cve="CVE-2026-3006", relevance=63.1)
            activo = self._activo(conn, "srv-web-17")
            tid = self._amenaza(conn, "relevante confirmada", cve="CVE-2026-3007", relevance=63.1)
            self._veredicto(conn, activo, tid, "afectado")
            self._evaluacion(conn, tid, afectados=1)
        _motivos, res = self._clasificar()
        self.assertEqual([v["title_en"] for v in res["alertar"]], ["relevante confirmada"])
        self.assertIn("relevante sin evaluar",
                      [t for t in _motivos if _motivos[t] == "sin_evaluar_todavia"])
        html = notify.render_alert_email(res["alertar"], {"detalle_top": 5})
        self.assertNotIn("Afectación todavía sin evaluar", html)
        self.assertNotIn("sin haber confirmado", html)

    def test_aplicabilidad_desactivada_no_silencia(self):
        """Con la evaluación por activo apagada en ajustes nadie confirmaría nada
        nunca: el filtro no puede aplicarse o no se alertaría jamás."""
        with db.session(self.ruta) as conn:
            self._activo(conn, "srv-web-11")
            self._amenaza(conn, "sin motor de aplicabilidad", cve="CVE-2026-3004")
        cfg = Cfg(self.cfg, applicability_enabled=False)
        motivos, _ = self._clasificar(cfg)
        self.assertIsNone(motivos["sin motor de aplicabilidad"])


class TestTodoMotivoTieneFraseEnLosTresSitios(unittest.TestCase):
    """Guardián: el motivo nuevo salió en crudo en el resumen semanal («196 por
    «sin_activos_confirmados».», con guiones bajos y sin tildes, en un correo que lee el
    usuario) porque se añadió a `queries.MOTIVOS_EXCLUSION` y no a las tres tablas de
    texto. Esta prueba recorre los motivos y falla si a alguno le falta su frase en
    cualquiera de los tres sitios donde se lee: la ficha de la amenaza, el pie del correo
    diario y el resumen semanal (revisión del 2026-09-08).
    """

    def test_los_tres_diccionarios_cubren_todos_los_motivos(self):
        from threatintel import digest, notify
        for motivo in queries.MOTIVOS_EXCLUSION:
            with self.subTest(motivo=motivo):
                self.assertIn(motivo, queries.MOTIVO_EXCLUSION_ES,
                              "falta la explicación de la ficha y de los listados")
                self.assertIn(motivo, notify.MOTIVOS_FILTRO_ES,
                              "falta la frase del pie del correo diario")
                self.assertIn(motivo, digest.FRASES_MOTIVO,
                              "falta la frase del resumen semanal")

    def test_ninguna_frase_deja_ver_el_identificador_crudo(self):
        from threatintel import digest, notify
        for motivo in queries.MOTIVOS_EXCLUSION:
            for donde, tabla in (("ficha", queries.MOTIVO_EXCLUSION_ES),
                                 ("correo diario", notify.MOTIVOS_FILTRO_ES),
                                 ("resumen semanal", digest.FRASES_MOTIVO)):
                with self.subTest(motivo=motivo, donde=donde):
                    texto = tabla[motivo]
                    self.assertNotIn("_", texto.replace("{", "").replace("}", ""),
                                     "el texto visible no puede llevar guiones bajos")

    def test_las_dos_tablas_de_nombres_de_tipo_de_maquina_coinciden(self):
        """El usuario veía tres nombres para la misma cosa: «equipos de usuario» en
        Activos, «equipos de cómputo» en Amenazas y «equipos» a secas en el Panel. Ahora
        `ocs.ORIGEN_PLURAL_ES` es la fuente de verdad y esta prueba impide que las dos
        tablas vuelvan a divergir."""
        from threatintel import ocs
        self.assertEqual(ocs.ORIGEN_PLURAL_ES, queries.ORIGEN_AMENAZAS_ES)
        self.assertEqual(ocs.ORIGEN_ES["equipos"], "Equipo de cómputo")
        for texto in list(ocs.ORIGEN_ES.values()) + list(ocs.ORIGEN_PLURAL_ES.values()):
            self.assertNotIn("usuario", texto.lower())


if __name__ == "__main__":
    unittest.main()

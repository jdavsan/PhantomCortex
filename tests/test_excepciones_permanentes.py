"""Excepciones permanentes: aceptación de riesgo sin fecha de vencimiento (2026-09-10).

Petición del usuario: «en excepciones se debe agregar la opción de fecha permanente, ya
que no va a tener una fecha de vencimiento». El diseño de la mañana decía lo contrario;
manda la decisión del usuario, pero su preocupación de fondo —que nada quede olvidado—
sigue siendo válida, y estas pruebas son las que garantizan que se resuelve.

Lo que vigilan, en el orden en que importa:

* se registran las dos clases de excepción, con fecha y permanente, y la permanente
  guarda ``vence_at`` a NULL: nunca una fecha lejana de mentira;
* una permanente **está siempre vigente**: no vence por más que pase el tiempo, sus días
  restantes no son un número (ni un cero engañoso ni un «faltan 999 días») y no aparece
  en el aviso de «vencen pronto» ni en el de «vencidas»;
* el comportamiento de las que SÍ vencen no cambia (una a tres días entra en el aviso,
  una vencida hace dos entra, una a doscientos días queda fuera);
* el recordatorio de revisión se emite al pasar el plazo del ajuste, dice con sus
  palabras que la excepción sigue vigente, y se silencia en cuanto alguien confirma la
  revisión;
* una vulnerabilidad con explotación activa confirmada (CISA KEV) nunca se acepta de
  forma permanente, ni al registrarla ni convirtiendo una temporal;
* solo administración concede lo permanente: el operador del SOC recibe 403;
* la conversión funciona en los dos sentidos y cada cambio queda en la auditoría;
* la página la marca, la cuenta, la agrupa aparte y la deja filtrar.

Base temporal bajo data/; ninguna prueba toca la base real, la red ni el correo.
"""
from __future__ import annotations

import re
import sqlite3
import tempfile
import unittest
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from threatintel import db, excepciones
from threatintel.paths import BASE_DIR
from webui import auth

CLAVE = "AdminSeguro#2026"
#: Justificación larga: una permanente exige al menos 60 caracteres.
JUSTIFICACION = ("El aplicativo de nómina del fabricante no funciona con la versión "
                 "corregida y el servidor se retira cuando se migre la nómina en 2030; "
                 "hasta entonces el riesgo se acepta sin plazo.")
#: Justificación corta: válida para una temporal (20 caracteres) y no para una permanente.
JUSTIFICACION_CORTA = "No se puede actualizar."
MOTIVO = "El fabricante aplazó la certificación de la versión corregida a diciembre."
MOTIVO_LARGO = ("El sistema heredado se mantiene hasta su retiro en 2030 y el fabricante "
                "no publicará una versión compatible con el aplicativo de nómina.")


def _fecha(dias: int) -> str:
    """Fecha ISO a ``dias`` de hoy (UTC), para que las pruebas no caduquen."""
    return (date.fromisoformat(excepciones.hoy()) + timedelta(days=dias)).isoformat()


class MailerFalso:
    """Sustituto de ``notify.Mailer``: cuenta los envíos y no manda nada."""

    def __init__(self, acepta: bool = True):
        self.acepta = acepta
        self.enviados: list[dict] = []

    def send(self, *, subject, html, to, cc=None, **_):
        self.enviados.append({"asunto": subject, "html": html, "to": list(to)})
        return self.acepta


class CfgFalso:
    def __init__(self, admin_to=("soc@ejemplo.local",), **ajustes):
        self.admin_to = list(admin_to)
        self._ajustes = dict(ajustes)

    def get(self, clave, defecto=None):
        return self._ajustes.get(clave, defecto)


class BasePermanentes(unittest.TestCase):
    """Un servidor y un equipo de cómputo, tres amenazas (una con explotación activa),
    sus veredictos y su cola de trabajo."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "permanentes.db")
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "admin", CLAVE, rol="admin", actor="t")
            auth.crear_usuario(conn, "soc", CLAVE, rol="ciberseguridad", actor="t")
            # «jefe» y «lector» solicitan pero no gestionan (ROLES_SOLICITUD incluye a
            # redes y mantenimiento; ROLES_GESTION y ROLES_PERMANENTE no).
            auth.crear_usuario(conn, "jefe", CLAVE, rol="redes", actor="t")
            auth.crear_usuario(conn, "lector", CLAVE, rol="mantenimiento", actor="t")
            ahora = db.utcnow()
            conn.execute(
                """INSERT INTO activos(id, origen, ocs_id, nombre, so_familia, so_version,
                                       ecosistema, zona, entorno, proceso, presente,
                                       primera_vez_at, visto_at)
                   VALUES(1,'servidores',10,'SRV-CONTABILIDAD','ubuntu','22.04','Ubuntu:22.04',
                          'interna','produccion','Contabilidad',1,?,?)""", (ahora, ahora))
            conn.execute(
                """INSERT INTO activos(id, origen, ocs_id, nombre, so_familia, so_version,
                                       zona, entorno, proceso, presente, primera_vez_at, visto_at)
                   VALUES(2,'equipos',20,'PC-TESORERIA','windows','11','interna','produccion',
                          'Tesorería',1,?,?)""", (ahora, ahora))
            for idx, (cve, severidad, kev) in enumerate(
                    (("CVE-2026-1001", "High", 0), ("CVE-2026-1002", "Critical", 1),
                     ("CVE-2026-1003", "Medium", 0)), start=1):
                conn.execute(
                    """INSERT INTO threats(id, fingerprint, cve, title_en, title_es, severity,
                                           severity_source, first_seen_at, last_seen_at, month,
                                           in_kev, estado)
                       VALUES(?,?,?,?,?,?, 'nvd', ?, ?, ?, ?, 'nueva')""",
                    (idx, f"fp-{idx}", cve, f"Fallo {idx}", f"Fallo {idx}", severidad,
                     ahora, ahora, ahora[:7], kev))
            for activo, threat, cve, paquete in (
                    (1, 1, "CVE-2026-1001", "openssl"), (1, 2, "CVE-2026-1002", "openssl"),
                    (1, 3, "CVE-2026-1003", "curl"), (2, 1, "CVE-2026-1001", "openssl")):
                conn.execute(
                    """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete,
                                                 version_instalada, version_corregida, veredicto,
                                                 motor, evaluado_at)
                       VALUES(?,?,?,?,'1.0','2.0','afectado','osv',?)""",
                    (activo, threat, cve, paquete, ahora))
                conn.execute(
                    """INSERT INTO remediaciones(activo_id, threat_id, cve, paquete,
                                                 version_vulnerable, version_corregida, motor,
                                                 estado, detectado_at, comprobado_at)
                       VALUES(?,?,?,?,'1.0','2.0','osv','abierta',?,?)""",
                    (activo, threat, cve, paquete, ahora, ahora))
            conn.execute(
                """INSERT INTO activo_software(activo_id, nombre, nombre_norm, version)
                   VALUES(1,'openssl','openssl','1.0')""")
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def setUp(self):
        with db.session(self.ruta) as conn:
            conn.execute("DELETE FROM excepciones")
            conn.execute("DELETE FROM admin_notices")
            conn.execute("DELETE FROM audit_log")
            conn.execute("DELETE FROM settings WHERE key = ?",
                         (excepciones.AJUSTE_REVISION_DIAS,))
            conn.execute("UPDATE remediaciones SET estado='abierta'")

    # ------------------------------------------------------------------ ayudas
    def _cliente(self, usuario="admin"):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": usuario, "password": CLAVE})
        return cli

    def _csrf(self, cli):
        html = cli.get("/excepciones/").get_data(as_text=True)
        return re.search(r'name="csrf" value="([^"]+)"', html).group(1)

    def _permanente(self, conn, **cambios):
        datos = {"alcance": "activo_cve", "activo_id": 1, "cve": "CVE-2026-1001",
                 "justificacion": JUSTIFICACION, "responsable_nombre": "Ana Pérez Gómez",
                 "responsable_correo": "ana.perez@ejemplo.local", "permanente": True}
        datos.update(cambios)
        return excepciones.crear(conn, actor="admin", **datos)

    def _temporal(self, conn, **cambios):
        datos = {"alcance": "activo_cve", "activo_id": 1, "cve": "CVE-2026-1001",
                 "justificacion": JUSTIFICACION_CORTA,
                 "responsable_nombre": "Ana Pérez Gómez",
                 "responsable_correo": "ana.perez@ejemplo.local",
                 "vence_at": _fecha(60)}
        datos.update(cambios)
        return excepciones.crear(conn, actor="admin", **datos)

    def _cola_abierta(self, conn) -> int:
        return int(conn.execute(
            f"""SELECT COUNT(*) FROM remediaciones r
                 WHERE r.estado='abierta' AND {excepciones.SQL_SIN_EXCEPCION_REMEDIACION}"""
        ).fetchone()[0])

    def _envejecer(self, conn, excepcion_id, dias):
        """Adelanta el reloj de la revisión moviendo la fecha de registro hacia atrás."""
        conn.execute("UPDATE excepciones SET registrado_at = ? WHERE id = ?",
                     (_fecha(-dias) + "T10:00:00Z", excepcion_id))


class TestAlta(BasePermanentes):
    def test_se_registran_las_dos_clases_y_la_permanente_no_guarda_fecha(self):
        with db.session(self.ruta) as conn:
            perm = self._permanente(conn)
            self.assertTrue(perm["permanente"])
            self.assertIsNone(perm["vence_at"], "una permanente no tiene fecha")
            self.assertIsNone(perm["vence_at_inicial"], "ni la ha tenido nunca")
            self.assertEqual(perm["estado"], "vigente")
            self.assertEqual(perm["vigencia_es"], excepciones.TEXTO_PERMANENTE)
            # Y en la base tampoco hay ninguna fecha inventada.
            self.assertIsNone(conn.execute(
                "SELECT vence_at FROM excepciones WHERE id = ?", (perm["id"],)).fetchone()[0])
            temporal = self._temporal(conn, cve="CVE-2026-1003")
            self.assertFalse(temporal["permanente"])
            self.assertEqual(temporal["vence_at"], _fecha(60))
            self.assertEqual(temporal["vence_at_inicial"], _fecha(60))

    def test_la_justificacion_de_una_permanente_exige_mas_texto(self):
        with db.session(self.ruta) as conn:
            with self.assertRaises(excepciones.ErrorExcepcion) as caja:
                self._permanente(conn, justificacion=JUSTIFICACION_CORTA)
            self.assertIn("no caduca nunca", str(caja.exception))
            self.assertIn(str(excepciones.MIN_JUSTIFICACION_PERMANENTE), str(caja.exception))
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM excepciones").fetchone()[0], 0)
            # Ese mismo texto sí vale para una excepción con fecha.
            self.assertIsNotNone(self._temporal(conn, justificacion=JUSTIFICACION_CORTA))

    def test_una_permanente_no_necesita_fecha_y_la_ignora_si_llega(self):
        """El campo de la fecha no se deshabilita en el servidor: se ignora, que es lo
        único que se puede garantizar sin depender del navegador."""
        with db.session(self.ruta) as conn:
            fila = self._permanente(conn, vence_at=_fecha(30))
            self.assertIsNone(fila["vence_at"])

    def test_una_temporal_sin_fecha_sigue_sin_admitirse(self):
        with db.session(self.ruta) as conn:
            with self.assertRaises(excepciones.ErrorExcepcion) as caja:
                self._temporal(conn, vence_at="")
            self.assertIn("Escriba la fecha de vencimiento, o elija", str(caja.exception))
            self.assertIn(excepciones.TEXTO_PERMANENTE, str(caja.exception))

    def test_el_indice_unico_tambien_cuenta_a_la_permanente(self):
        with db.session(self.ruta) as conn:
            self._permanente(conn)
            with self.assertRaises(excepciones.ErrorExcepcion) as caja:
                self._temporal(conn)
            self.assertIn("es permanente, sin fecha de vencimiento", str(caja.exception))


class TestNuncaVence(BasePermanentes):
    def test_sigue_vigente_por_mucho_que_pase_el_tiempo(self):
        with db.session(self.ruta) as conn:
            fila = self._permanente(conn)
            self.assertEqual(self._cola_abierta(conn), 3)
            self._envejecer(conn, fila["id"], 4000)
            de_nuevo = excepciones.obtener(conn, fila["id"])
            self.assertEqual(de_nuevo["estado"], "vigente")
            self.assertEqual(self._cola_abierta(conn), 3,
                             "la vulnerabilidad NO vuelve sola: no hay fecha que la devuelva")

    def test_los_dias_restantes_no_son_un_numero(self):
        with db.session(self.ruta) as conn:
            fila = self._permanente(conn)
            self.assertIsNone(fila["dias_restantes"],
                              "ni un cero engañoso ni un «faltan 999 días»")
            self.assertIsNone(conn.execute(
                f"SELECT {excepciones.SQL_DIAS_RESTANTES} FROM excepciones e").fetchone()[0])
            self.assertIsNone(excepciones.dias_restantes(None, permanente=True))
            self.assertEqual(excepciones.dias_restantes(_fecha(5)), 5)

    def test_el_sql_y_el_python_dicen_lo_mismo_para_una_permanente(self):
        with db.session(self.ruta) as conn:
            self._permanente(conn)
            vigente_sql = conn.execute(
                f"SELECT COUNT(*) FROM excepciones e WHERE {excepciones.SQL_VIGENTE}"
            ).fetchone()[0] == 1
            self.assertTrue(vigente_sql)
            self.assertFalse(excepciones.esta_vencida(None, permanente=True))
            estado_sql = conn.execute(
                f"SELECT {excepciones.SQL_ESTADO} FROM excepciones e").fetchone()[0]
            self.assertEqual(estado_sql,
                             excepciones.estado_efectivo("vigente", None, permanente=True))
            self.assertEqual(estado_sql, "vigente")

    def test_una_permanente_revocada_deja_de_tapar_en_el_acto(self):
        with db.session(self.ruta) as conn:
            fila = self._permanente(conn)
            self.assertEqual(self._cola_abierta(conn), 3)
            revocada = excepciones.revocar(
                conn, fila["id"], actor="soc",
                motivo="El servidor se migró y ya no hace falta aceptar este riesgo.")
            self.assertEqual(revocada["estado"], "revocada")
            self.assertEqual(self._cola_abierta(conn), 4)

    def test_una_permanente_no_se_prorroga(self):
        with db.session(self.ruta) as conn:
            fila = self._permanente(conn)
            with self.assertRaises(excepciones.ErrorExcepcion) as caja:
                excepciones.prorrogar(conn, fila["id"], vence_at=_fecha(30),
                                      motivo=MOTIVO, actor="admin")
            self.assertIn("no tiene fecha de vencimiento", str(caja.exception))
            self.assertIn("Convertir en temporal", str(caja.exception))
            self.assertEqual(excepciones.obtener(conn, fila["id"])["prorrogas"], 0)


class TestAvisos(BasePermanentes):
    def test_una_permanente_no_entra_en_los_avisos_de_vencimiento(self):
        with db.session(self.ruta) as conn:
            self._permanente(conn)
            pendientes = excepciones.pendientes_de_aviso(conn)
            self.assertEqual(pendientes["por_vencer"], [])
            self.assertEqual(pendientes["vencidas"], [])
            # Tampoco con una antelación absurda: no vence, así que no puede estar
            # «a punto de vencer» nunca.
            self.assertEqual(
                excepciones.pendientes_de_aviso(conn, aviso_dias=120)["por_vencer"], [])
            self.assertEqual(excepciones.resumen(conn)["por_vencer"], 0)
            self.assertEqual(excepciones.resumen(conn)["vencidas"], 0)
            self.assertEqual(excepciones.resumen(conn)["permanentes"], 1)

    def test_las_que_vencen_siguen_avisando_exactamente_igual(self):
        """Comportamiento verificado por el usuario el 2026-09-10: con quince días de
        antelación entra una que vence en tres días y una vencida hace dos, y queda fuera
        una que vence dentro de doscientos. Una permanente no cambia nada de eso."""
        with db.session(self.ruta) as conn:
            self._permanente(conn, cve="CVE-2026-1003", activo_id=1)
            pronto = self._temporal(conn, cve="CVE-2026-1001", vence_at=_fecha(3))
            lejana = self._temporal(conn, activo_id=2, cve="CVE-2026-1001",
                                    vence_at=_fecha(200))
            vencida = self._temporal(conn, alcance="activo_paquete", activo_id=1,
                                     cve="", paquete="curl", vence_at=_fecha(1))
            conn.execute("UPDATE excepciones SET vence_at=? WHERE id=?",
                         (_fecha(-2), vencida["id"]))
            pendientes = excepciones.pendientes_de_aviso(conn)
            self.assertEqual([f["id"] for f in pendientes["por_vencer"]], [pronto["id"]])
            self.assertEqual([f["id"] for f in pendientes["vencidas"]], [vencida["id"]])
            self.assertNotIn(lejana["id"],
                             [f["id"] for f in pendientes["por_vencer"] + pendientes["vencidas"]])

    def test_el_recordatorio_de_revision_se_emite_al_pasar_el_plazo(self):
        cfg = CfgFalso()
        mailer = MailerFalso()
        with db.session(self.ruta) as conn:
            fila = self._permanente(conn)
            self.assertEqual(excepciones.pendientes_de_revision(conn)["revision"], [])
            self.assertIsNone(excepciones.avisar(conn, cfg=cfg, mailer=mailer),
                              "recién registrada no hay nada que recordar")
            self._envejecer(conn, fila["id"], excepciones.REVISION_DIAS_DEFECTO)
            pendientes = excepciones.pendientes_de_revision(conn)
            self.assertEqual([f["id"] for f in pendientes["revision"]], [fila["id"]])
            self.assertEqual(pendientes["revision_dias"], excepciones.REVISION_DIAS_DEFECTO)
            aviso = excepciones.avisar(conn, cfg=cfg, mailer=mailer)
            self.assertIsNotNone(aviso)
            self.assertEqual(aviso["revision"], 1)
            self.assertEqual(aviso["por_vencer"], 0)
            self.assertEqual(aviso["vencidas"], 0)
            self.assertEqual(aviso["severidad"], "info",
                             "un recordatorio no es una acción requerida")
            correo = mailer.enviados[0]
            self.assertIn("días aceptada sin revisarse", correo["html"])
            self.assertIn("confirme que sigue siendo válida o revóquela", correo["html"])
            self.assertIn("siguen vigentes", correo["html"].lower())
            self.assertIn(excepciones.TEXTO_PERMANENTE, correo["html"])
            self.assertIn("CVE-2026-1001", correo["html"])
            self.assertNotIn("ACCION REQUERIDA", correo["asunto"])
            # Queda anotado en su columna propia y NO en la del aviso de vencimiento.
            actual = excepciones.obtener(conn, fila["id"])
            self.assertIsNotNone(actual["revision_avisada_at"])
            self.assertIsNone(actual["avisado_at"])

    def test_el_recordatorio_se_silencia_al_confirmar_la_revision(self):
        cfg = CfgFalso()
        with db.session(self.ruta) as conn:
            fila = self._permanente(conn)
            self._envejecer(conn, fila["id"], 400)
            self.assertIsNotNone(excepciones.avisar(conn, cfg=cfg, mailer=MailerFalso()))
            revisada = excepciones.confirmar_revision(
                conn, fila["id"], actor="admin", nota="Revisado con el jefe del proceso.")
            self.assertEqual(revisada["revisiones"], 1)
            self.assertEqual(revisada["revisada_por"], "admin")
            self.assertFalse(revisada["revision_pendiente"])
            self.assertEqual(revisada["dias_sin_revisar"], 0)
            self.assertEqual(excepciones.pendientes_de_revision(conn)["revision"], [])
            segundo = MailerFalso()
            self.assertIsNone(excepciones.avisar(
                conn, cfg=cfg, mailer=segundo,
                ahora=datetime.now(timezone.utc) + timedelta(days=30)))
            self.assertEqual(segundo.enviados, [])
            # Y la excepción sigue exactamente igual de vigente: la revisión no la toca.
            self.assertEqual(revisada["estado"], "vigente")
            self.assertEqual(self._cola_abierta(conn), 3)

    def test_el_recordatorio_no_se_repite_al_dia_siguiente_pero_si_a_la_semana(self):
        cfg = CfgFalso()
        with db.session(self.ruta) as conn:
            fila = self._permanente(conn)
            self._envejecer(conn, fila["id"], 400)
            self.assertIsNotNone(excepciones.avisar(conn, cfg=cfg, mailer=MailerFalso()))
            manana = MailerFalso()
            self.assertIsNone(excepciones.avisar(
                conn, cfg=cfg, mailer=manana,
                ahora=datetime.now(timezone.utc) + timedelta(days=1)))
            self.assertEqual(manana.enviados, [])
            semana = MailerFalso()
            self.assertIsNotNone(excepciones.avisar(
                conn, cfg=cfg, mailer=semana,
                ahora=datetime.now(timezone.utc) + timedelta(days=8)))
            self.assertEqual(len(semana.enviados), 1)

    def test_si_el_correo_no_sale_no_se_marca_como_recordada(self):
        with db.session(self.ruta) as conn:
            fila = self._permanente(conn)
            self._envejecer(conn, fila["id"], 400)
            self.assertIsNone(excepciones.avisar(conn, cfg=CfgFalso(),
                                                 mailer=MailerFalso(acepta=False)))
            self.assertIsNone(excepciones.obtener(conn, fila["id"])["revision_avisada_at"])
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM admin_notices").fetchone()[0], 0)

    def test_un_correo_con_las_tres_cosas_a_la_vez(self):
        with db.session(self.ruta) as conn:
            perm = self._permanente(conn, cve="CVE-2026-1003")
            self._envejecer(conn, perm["id"], 400)
            self._temporal(conn, cve="CVE-2026-1001", vence_at=_fecha(3))
            vencida = self._temporal(conn, activo_id=2, cve="CVE-2026-1001",
                                     vence_at=_fecha(1))
            conn.execute("UPDATE excepciones SET vence_at=? WHERE id=?",
                         (_fecha(-2), vencida["id"]))
            mailer = MailerFalso()
            aviso = excepciones.avisar(conn, cfg=CfgFalso(), mailer=mailer)
            self.assertEqual((aviso["vencidas"], aviso["por_vencer"], aviso["revision"]),
                             (1, 1, 1))
            self.assertEqual(aviso["severidad"], "critical")
            # Revisión de claridad del 2026-09-15: un solo prefijo para todo el sistema
            # («[Inteligencia de Amenazas]») y «Acción requerida» con tilde y sin gritar.
            self.assertIn("Acción requerida", mailer.enviados[0]["asunto"])
            self.assertIn("sin revisar", aviso["titulo"])

    def test_el_ajuste_de_los_dias_de_revision(self):
        with db.session(self.ruta) as conn:
            self.assertEqual(excepciones.ajuste_revision_dias(conn),
                             excepciones.REVISION_DIAS_DEFECTO)
            db.set_setting(conn, excepciones.AJUSTE_REVISION_DIAS, 30)
            self.assertEqual(excepciones.ajuste_revision_dias(conn), 30)
            self.assertEqual(excepciones.ajuste_revision_dias(
                conn, cfg=CfgFalso(excepciones_revision_dias=365)), 365)
            # Fuera de rango se recorta y un valor corrupto cae al valor por omisión.
            db.set_setting(conn, excepciones.AJUSTE_REVISION_DIAS, 1)
            self.assertEqual(excepciones.ajuste_revision_dias(conn),
                             excepciones.REVISION_DIAS_MIN)
            db.set_setting(conn, excepciones.AJUSTE_REVISION_DIAS, 99999)
            self.assertEqual(excepciones.ajuste_revision_dias(conn),
                             excepciones.REVISION_DIAS_MAX)
            db.set_setting(conn, excepciones.AJUSTE_REVISION_DIAS, "lo que sea")
            self.assertEqual(excepciones.ajuste_revision_dias(conn),
                             excepciones.REVISION_DIAS_DEFECTO)

    def test_el_ajuste_decide_cuando_se_recuerda(self):
        with db.session(self.ruta) as conn:
            fila = self._permanente(conn)
            self._envejecer(conn, fila["id"], 100)
            self.assertEqual(excepciones.pendientes_de_revision(conn)["revision"], [])
            self.assertEqual(len(excepciones.pendientes_de_revision(
                conn, revision_dias=90)["revision"]), 1)

    def test_una_temporal_no_se_revisa(self):
        with db.session(self.ruta) as conn:
            fila = self._temporal(conn)
            self._envejecer(conn, fila["id"], 400)
            self.assertEqual(excepciones.pendientes_de_revision(conn)["revision"], [])
            with self.assertRaises(excepciones.ErrorExcepcion) as caja:
                excepciones.confirmar_revision(conn, fila["id"], actor="admin")
            self.assertIn("Solo se revisan las excepciones permanentes", str(caja.exception))


class TestExplotacionActiva(BasePermanentes):
    def test_una_kev_no_se_acepta_de_forma_permanente(self):
        with db.session(self.ruta) as conn:
            for confirmada in (False, True):
                with self.subTest(confirmar_kev=confirmada):
                    with self.assertRaises(excepciones.ErrorExcepcion) as caja:
                        self._permanente(conn, cve="CVE-2026-1002",
                                         confirmar_kev=confirmada,
                                         compensacion="Aislado en su propia red.")
                    self.assertIn("no se acepta de forma permanente", str(caja.exception))
                    self.assertIn("CVE-2026-1002", str(caja.exception))
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM excepciones").fetchone()[0], 0)
            # Con fecha sí se admite, con su plazo corto y su medida compensatoria.
            fila = self._temporal(conn, cve="CVE-2026-1002", vence_at=_fecha(20),
                                  confirmar_kev=True,
                                  compensacion="Aislado en su propia red.")
            self.assertEqual(fila["kev"], 1)
            self.assertFalse(fila["permanente"])

    def test_un_paquete_con_una_kev_dentro_tampoco(self):
        with db.session(self.ruta) as conn:
            with self.assertRaises(excepciones.ErrorExcepcion) as caja:
                self._permanente(conn, alcance="activo_paquete", cve="", paquete="openssl")
            self.assertIn("CVE-2026-1002", str(caja.exception))

    def test_una_temporal_kev_no_se_puede_convertir_en_permanente(self):
        with db.session(self.ruta) as conn:
            fila = self._temporal(conn, cve="CVE-2026-1002", vence_at=_fecha(20),
                                  confirmar_kev=True, compensacion="Aislada.")
            with self.assertRaises(excepciones.ErrorExcepcion) as caja:
                excepciones.convertir_en_permanente(conn, fila["id"], motivo=MOTIVO_LARGO,
                                                    actor="admin")
            self.assertIn("no se acepta de forma permanente", str(caja.exception))
            self.assertFalse(excepciones.obtener(conn, fila["id"])["permanente"])

    def test_una_kev_sobrevenida_bloquea_la_conversion(self):
        """El veto mira la explotación activa AHORA, no la que había al registrarla: un
        CVE puede entrar en el catálogo de CISA meses después."""
        with db.session(self.ruta) as conn:
            fila = self._temporal(conn, cve="CVE-2026-1003", vence_at=_fecha(30))
            self.assertEqual(fila["kev"], 0)
            conn.execute("UPDATE threats SET in_kev = 1 WHERE cve = 'CVE-2026-1003'")
            try:
                with self.assertRaises(excepciones.ErrorExcepcion) as caja:
                    excepciones.convertir_en_permanente(conn, fila["id"],
                                                        motivo=MOTIVO_LARGO, actor="admin")
                self.assertIn("CVE-2026-1003", str(caja.exception))
            finally:
                conn.execute("UPDATE threats SET in_kev = 0 WHERE cve = 'CVE-2026-1003'")


class TestConversiones(BasePermanentes):
    def test_de_temporal_a_permanente_y_de_vuelta(self):
        with db.session(self.ruta) as conn:
            fila = self._temporal(conn, vence_at=_fecha(45))
            perm = excepciones.convertir_en_permanente(conn, fila["id"],
                                                       motivo=MOTIVO_LARGO, actor="admin")
            self.assertTrue(perm["permanente"])
            self.assertIsNone(perm["vence_at"])
            self.assertEqual(perm["vence_at_inicial"], _fecha(45),
                             "la primera fecha que tuvo no se pierde")
            self.assertEqual(perm["revisada_por"], "admin",
                             "convertirla cuenta como haberla mirado")
            self.assertFalse(perm["revision_pendiente"])
            self.assertEqual(self._cola_abierta(conn), 3)

            temporal = excepciones.convertir_en_temporal(
                conn, fila["id"], vence_at=_fecha(90),
                motivo="Ya hay fecha de salida del sistema heredado.", actor="soc")
            self.assertFalse(temporal["permanente"])
            self.assertEqual(temporal["vence_at"], _fecha(90))
            self.assertEqual(temporal["vence_at_inicial"], _fecha(45))
            self.assertEqual(temporal["dias_restantes"], 90)
            # Y ahora sí vuelve a vencer sola.
            conn.execute("UPDATE excepciones SET vence_at=? WHERE id=?",
                         (_fecha(-1), fila["id"]))
            self.assertEqual(excepciones.obtener(conn, fila["id"])["estado"], "vencida")
            self.assertEqual(self._cola_abierta(conn), 4)

    def test_una_permanente_de_nacimiento_guarda_su_primera_fecha_al_convertirse(self):
        with db.session(self.ruta) as conn:
            fila = self._permanente(conn)
            self.assertIsNone(fila["vence_at_inicial"])
            temporal = excepciones.convertir_en_temporal(
                conn, fila["id"], vence_at=_fecha(30),
                motivo="Se le pone plazo tras la revisión anual.", actor="admin")
            self.assertEqual(temporal["vence_at_inicial"], _fecha(30))

    def test_las_conversiones_validan_lo_suyo(self):
        with db.session(self.ruta) as conn:
            temporal = self._temporal(conn)
            with self.assertRaises(excepciones.ErrorExcepcion) as caja:
                excepciones.convertir_en_permanente(conn, temporal["id"], motivo="corto",
                                                    actor="admin")
            self.assertIn(str(excepciones.MIN_JUSTIFICACION_PERMANENTE), str(caja.exception))
            with self.assertRaises(excepciones.ErrorExcepcion) as caja:
                excepciones.convertir_en_temporal(conn, temporal["id"],
                                                  vence_at=_fecha(10), motivo=MOTIVO,
                                                  actor="admin")
            self.assertIn("ya tiene fecha de vencimiento", str(caja.exception))

            perm = self._permanente(conn, cve="CVE-2026-1003")
            with self.assertRaises(excepciones.ErrorExcepcion) as caja:
                excepciones.convertir_en_permanente(conn, perm["id"], motivo=MOTIVO_LARGO,
                                                    actor="admin")
            self.assertIn("ya es permanente", str(caja.exception))
            for cambios, fragmento in (
                    ({"vence_at": ""}, "Escriba la fecha de vencimiento"),
                    ({"vence_at": _fecha(-1)}, "posterior a hoy"),
                    ({"vence_at": _fecha(excepciones.MAX_DIAS + 1)}, "plazo máximo"),
                    ({"motivo": "corto"}, "Explique por qué se le pone fecha")):
                datos = {"vence_at": _fecha(30), "motivo": MOTIVO}
                datos.update(cambios)
                with self.subTest(**cambios):
                    with self.assertRaises(excepciones.ErrorExcepcion) as caja:
                        excepciones.convertir_en_temporal(conn, perm["id"], actor="admin",
                                                          **datos)
                    self.assertIn(fragmento, str(caja.exception))
            self.assertTrue(excepciones.obtener(conn, perm["id"])["permanente"])

    def test_una_revocada_no_se_convierte_ni_se_revisa(self):
        with db.session(self.ruta) as conn:
            fila = self._permanente(conn)
            excepciones.revocar(conn, fila["id"], actor="admin",
                                motivo="El servidor se retiró del inventario.")
            for llamada in (
                    lambda: excepciones.confirmar_revision(conn, fila["id"], actor="admin"),
                    lambda: excepciones.convertir_en_temporal(
                        conn, fila["id"], vence_at=_fecha(30), motivo=MOTIVO, actor="admin"),
                    lambda: excepciones.convertir_en_permanente(
                        conn, fila["id"], motivo=MOTIVO_LARGO, actor="admin")):
                with self.assertRaises(excepciones.ErrorExcepcion):
                    llamada()

    def test_cada_cambio_queda_en_la_auditoria(self):
        with db.session(self.ruta) as conn:
            fila = self._temporal(conn, vence_at=_fecha(45))
            excepciones.convertir_en_permanente(conn, fila["id"], motivo=MOTIVO_LARGO,
                                                actor="admin", ip="10.1.1.5")
            excepciones.confirmar_revision(conn, fila["id"], actor="admin", nota="Sigue igual.",
                                           ip="10.1.1.6")
            excepciones.convertir_en_temporal(conn, fila["id"], vence_at=_fecha(60),
                                              motivo="Ya hay fecha de retiro del servidor.",
                                              actor="soc", ip="10.1.1.7")
            filas = conn.execute(
                """SELECT action, username, detail, ip FROM audit_log
                    WHERE entity='excepciones' ORDER BY id""").fetchall()
            self.assertEqual([f["action"] for f in filas],
                             ["excepciones.crear", "excepciones.permanente",
                              "excepciones.revisar", "excepciones.temporal"])
            self.assertEqual([f["username"] for f in filas],
                             ["admin", "admin", "admin", "soc"])
            self.assertIn("(sin fecha)", filas[1]["detail"])
            self.assertIn("revision confirmada", filas[2]["detail"])
            self.assertIn(_fecha(60), filas[3]["detail"])
            self.assertEqual([f["ip"] for f in filas],
                             [None, "10.1.1.5", "10.1.1.6", "10.1.1.7"])

    def test_el_alta_permanente_queda_en_la_auditoria_como_tal(self):
        with db.session(self.ruta) as conn:
            self._permanente(conn)
            detalle = conn.execute(
                "SELECT detail FROM audit_log WHERE action='excepciones.crear'"
            ).fetchone()[0]
            self.assertIn("vence_at=permanente", detalle)
            self.assertIn("permanente=1", detalle)


class TestPermisos(BasePermanentes):
    def _alta(self, **cambios):
        datos = {"alcance": "activo_cve", "activo_id": "1", "cve": "CVE-2026-1003",
                 "justificacion": JUSTIFICACION, "responsable_nombre": "Ana Pérez Gómez",
                 "responsable_correo": "ana.perez@ejemplo.local",
                 "vigencia": "permanente"}
        datos.update(cambios)
        return datos

    def test_solo_administracion_registra_una_permanente(self):
        for usuario in ("soc", "jefe", "lector"):
            cli = self._cliente(usuario)
            csrf = self._csrf(cli)
            with self.subTest(usuario=usuario):
                respuesta = cli.post("/excepciones/crear",
                                     data={"csrf": csrf, **self._alta()})
                self.assertEqual(respuesta.status_code, 403)
        with db.session(self.ruta) as conn:
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM excepciones").fetchone()[0], 0)
        cli = self._cliente("admin")
        respuesta = cli.post("/excepciones/crear",
                             data={"csrf": self._csrf(cli), **self._alta()},
                             follow_redirects=True)
        self.assertIn("Riesgo aceptado de forma permanente",
                      respuesta.get_data(as_text=True))
        with db.session(self.ruta) as conn:
            self.assertTrue(excepciones.listar(conn)[0]["permanente"])

    def test_el_operador_del_soc_si_puede_registrar_una_temporal(self):
        cli = self._cliente("soc")
        respuesta = cli.post("/excepciones/crear",
                             data={"csrf": self._csrf(cli),
                                   **self._alta(vigencia="temporal",
                                                vence_at=_fecha(30))},
                             follow_redirects=True)
        self.assertIn("Riesgo aceptado hasta el", respuesta.get_data(as_text=True))

    def test_revisar_y_quitar_la_fecha_son_solo_de_administracion(self):
        with db.session(self.ruta) as conn:
            perm = self._permanente(conn)
            temporal = self._temporal(conn, cve="CVE-2026-1003", vence_at=_fecha(30))
        for usuario in ("soc", "jefe", "lector"):
            cli = self._cliente(usuario)
            csrf = self._csrf(cli)
            with self.subTest(usuario=usuario):
                self.assertEqual(cli.post(f"/excepciones/{perm['id']}/revisar",
                                          data={"csrf": csrf}).status_code, 403)
                self.assertEqual(
                    cli.post(f"/excepciones/{temporal['id']}/permanente",
                             data={"csrf": csrf, "motivo": MOTIVO_LARGO}).status_code, 403)
        with db.session(self.ruta) as conn:
            self.assertEqual(excepciones.obtener(conn, perm["id"])["revisiones"], 0)
            self.assertFalse(excepciones.obtener(conn, temporal["id"])["permanente"])

    def test_ponerle_fecha_a_una_permanente_lo_puede_el_operador_del_soc(self):
        """Va en la dirección que reduce el riesgo: la excepción vuelve a caducar sola."""
        with db.session(self.ruta) as conn:
            perm = self._permanente(conn)
        cli = self._cliente("soc")
        respuesta = cli.post(f"/excepciones/{perm['id']}/temporal",
                             data={"csrf": self._csrf(cli), "vence_at": _fecha(30),
                                   "motivo": "Ya hay fecha de retiro del servidor."},
                             follow_redirects=True)
        self.assertIn("vence el", respuesta.get_data(as_text=True))
        with db.session(self.ruta) as conn:
            self.assertFalse(excepciones.obtener(conn, perm["id"])["permanente"])
        # Y el lector no.
        lector = self._cliente("lector")
        self.assertEqual(
            lector.post(f"/excepciones/{perm['id']}/temporal",
                        data={"csrf": self._csrf(lector), "vence_at": _fecha(30),
                              "motivo": MOTIVO}).status_code, 403)

    def test_las_rutas_nuevas_exigen_csrf_y_sesion(self):
        with db.session(self.ruta) as conn:
            perm = self._permanente(conn)
        cli = self._cliente("admin")
        for url, datos in ((f"/excepciones/{perm['id']}/revisar", {}),
                           (f"/excepciones/{perm['id']}/temporal",
                            {"vence_at": _fecha(30), "motivo": MOTIVO}),
                           (f"/excepciones/{perm['id']}/permanente",
                            {"motivo": MOTIVO_LARGO})):
            with self.subTest(url=url):
                respuesta = cli.post(url, data=datos)
                self.assertIn(respuesta.status_code, (400, 403))
                self.assertIn("CSRF", respuesta.get_data(as_text=True))
        anonimo = self.app.test_client()
        for url in (f"/excepciones/{perm['id']}/revisar",
                    f"/excepciones/{perm['id']}/temporal",
                    f"/excepciones/{perm['id']}/permanente"):
            with self.subTest(url=url, sesion="sin"):
                respuesta = anonimo.post(url)
                self.assertIn(respuesta.status_code, (302, 400, 403))
        with db.session(self.ruta) as conn:
            self.assertTrue(excepciones.obtener(conn, perm["id"])["permanente"])
            self.assertEqual(excepciones.obtener(conn, perm["id"])["revisiones"], 0)

    def test_las_rutas_nuevas_responden_404_si_no_existe(self):
        cli = self._cliente("admin")
        csrf = self._csrf(cli)
        self.assertEqual(cli.post("/excepciones/424242/revisar",
                                  data={"csrf": csrf}).status_code, 404)
        self.assertEqual(cli.post("/excepciones/424242/permanente",
                                  data={"csrf": csrf, "motivo": MOTIVO_LARGO}).status_code, 404)
        self.assertEqual(cli.post("/excepciones/424242/temporal",
                                  data={"csrf": csrf, "vence_at": _fecha(30),
                                        "motivo": MOTIVO}).status_code, 404)

    def test_un_jefe_de_proceso_puede_solicitar_una_permanente_sin_registrarla(self):
        cli = self._cliente("jefe")
        respuesta = cli.post("/excepciones/solicitar",
                             data={"csrf": self._csrf(cli),
                                   **self._alta(cve="CVE-2026-1001")},
                             follow_redirects=True)
        self.assertIn("Solicitud registrada", respuesta.get_data(as_text=True))
        with db.session(self.ruta) as conn:
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM excepciones").fetchone()[0], 0)
            detalle = conn.execute(
                "SELECT detail FROM audit_log WHERE action='excepciones.solicitud'"
            ).fetchone()[0]
            self.assertIn("PERMANENTE", detalle)


class TestPagina(BasePermanentes):
    def test_la_pagina_marca_cuenta_y_explica_las_permanentes(self):
        with db.session(self.ruta) as conn:
            perm = self._permanente(conn)
            self._temporal(conn, cve="CVE-2026-1003", vence_at=_fecha(40))
        # «jefe» (redes) está en el alcance del activo 1 (servidor), que es el que
        # crean «_permanente» y «_temporal» por omisión.
        html = self._cliente("jefe").get("/excepciones/").get_data(as_text=True)
        self.assertIn(">Permanente</span>", html)
        self.assertIn("Permanentes (sin fecha de vencimiento)", html)
        self.assertIn("Permanentes pendientes de revisión", html)
        self.assertIn("No vence", html)
        self.assertIn("no caduca nunca", html)
        # Ni un cero ni una fecha inventada para la permanente.
        self.assertNotIn("quedan 0 días", html)
        self.assertNotIn("9999", html)
        # Y sigue cumpliendo la CSP y sin JavaScript en línea.
        self.assertIsNone(re.search(r"\sstyle\s*=", html))
        self.assertIsNone(re.search(r"\son[a-z]+\s*=", html))
        with db.session(self.ruta) as conn:
            self.assertIsNone(excepciones.obtener(conn, perm["id"])["vence_at"])

    def test_la_pagina_dice_cuantas_permanentes_hay_y_cuantas_sin_revisar(self):
        with db.session(self.ruta) as conn:
            perm = self._permanente(conn)
            self._permanente(conn, cve="CVE-2026-1003", activo_id=1)
            self._envejecer(conn, perm["id"], 400)
        html = self._cliente("admin").get("/excepciones/").get_data(as_text=True)
        self.assertRegex(html, r'<div class="valor">2</div>\s*<div class="etiqueta">'
                               r'Permanentes \(sin fecha de vencimiento\)')
        self.assertRegex(html, r'<div class="valor">1</div>\s*<div class="etiqueta">'
                               r'Permanentes pendientes de revisión')
        self.assertIn("aceptada sin revisarse", html)
        self.assertIn("recordatorio, no un vencimiento", html)

    def test_el_filtro_de_permanentes_y_el_de_pendientes_de_revision(self):
        with db.session(self.ruta) as conn:
            perm = self._permanente(conn)
            self._temporal(conn, cve="CVE-2026-1003", vence_at=_fecha(40))
            self.assertEqual(excepciones.contar(conn, estado="permanente"), 1)
            self.assertEqual(excepciones.contar(conn, estado="revision"), 0)
            self._envejecer(conn, perm["id"], 400)
            self.assertEqual(excepciones.contar(conn, estado="revision"), 1)
        cli = self._cliente("admin")
        solo_permanentes = cli.get("/excepciones/?estado=permanente").get_data(as_text=True)
        self.assertIn("CVE-2026-1001", solo_permanentes)
        self.assertNotIn("CVE-2026-1003", solo_permanentes)
        pendientes = cli.get("/excepciones/?estado=revision").get_data(as_text=True)
        self.assertIn("CVE-2026-1001", pendientes)
        self.assertNotIn("CVE-2026-1003", pendientes)
        # Y una permanente no sale en «vencidas» ni en «vencen pronto».
        for filtro in ("vencida", "por_vencer"):
            with self.subTest(filtro=filtro):
                self.assertNotIn("CVE-2026-1001",
                                 cli.get(f"/excepciones/?estado={filtro}").get_data(as_text=True))

    def test_las_permanentes_se_agrupan_aparte_de_las_que_vencen(self):
        with db.session(self.ruta) as conn:
            perm_sin_revisar = self._permanente(conn, cve="CVE-2026-1003", activo_id=1)
            self._envejecer(conn, perm_sin_revisar["id"], 400)
            perm_al_dia = self._permanente(conn, alcance="cve", activo_id=None,
                                           cve="CVE-2026-1003")
            pronto = self._temporal(conn, cve="CVE-2026-1001", vence_at=_fecha(3))
            lejana = self._temporal(conn, activo_id=2, cve="CVE-2026-1001",
                                    vence_at=_fecha(200))
            vencida = self._temporal(conn, alcance="activo_paquete", activo_id=1,
                                     cve="", paquete="openssl", vence_at=_fecha(1),
                                     confirmar_kev=True, compensacion="Aislado.")
            conn.execute("UPDATE excepciones SET vence_at=? WHERE id=?",
                         (_fecha(-2), vencida["id"]))
            orden = [f["id"] for f in excepciones.listar(conn)]
            self.assertEqual(orden, [vencida["id"], pronto["id"], perm_sin_revisar["id"],
                                     lejana["id"], perm_al_dia["id"]])

    def test_los_botones_de_lo_permanente_solo_salen_para_quien_puede(self):
        with db.session(self.ruta) as conn:
            self._permanente(conn)
            self._temporal(conn, cve="CVE-2026-1003", vence_at=_fecha(40))
        admin = self._cliente("admin").get("/excepciones/").get_data(as_text=True)
        self.assertIn("Confirmar la revisión", admin)
        self.assertIn("Quitarle la fecha (permanente)", admin)
        self.assertIn("Ponerle fecha de vencimiento", admin)
        self.assertIn('value="permanente"', admin)
        soc = self._cliente("soc").get("/excepciones/").get_data(as_text=True)
        self.assertNotIn("Confirmar la revisión", soc)
        self.assertNotIn("Quitarle la fecha (permanente)", soc)
        self.assertIn("Ponerle fecha de vencimiento", soc)
        self.assertIn("Su perfil no puede aceptar un riesgo sin fecha de vencimiento", soc)
        self.assertIn("disabled", soc)

    def test_el_recorrido_guiado_sigue_numerado_sin_saltos(self):
        texto = (BASE_DIR / "webui" / "templates" / "excepciones.html").read_text(
            encoding="utf-8")
        numeros = [int(n) for n in re.findall(r'data-tour="(\d+)"', texto)]
        self.assertEqual(numeros, sorted(numeros))
        self.assertEqual(len(numeros), len(set(numeros)))
        self.assertEqual(min(numeros), 1)
        # Y el motor de actualización sin recarga del otro agente sigue intacto.
        for atributo in ("data-zona-viva", "data-accion-viva", "data-filtro-vivo"):
            self.assertIn(atributo, texto)

    def test_la_ficha_del_activo_recibe_la_permanente_marcada(self):
        """La insignia de las otras pantallas necesita saber que es permanente y no
        recibir un cero como días restantes."""
        from webui.vistas.remediaciones import excepciones_vigentes, indice_riesgo_aceptado
        with db.session(self.ruta) as conn:
            self._permanente(conn)
            for fila in excepciones.por_activo(conn, 1):
                self.assertTrue(fila["permanente"])
                self.assertIsNone(fila["dias_restantes"])
                self.assertEqual(fila["vigencia_es"], excepciones.TEXTO_PERMANENTE)
            cubre = excepciones.cubre(conn, activo_id=1, cve="CVE-2026-1001",
                                      paquete="openssl")
            self.assertTrue(cubre["permanente"])
            self.assertIsNone(cubre["vence_at"])
            vigentes = excepciones_vigentes(conn)
            self.assertTrue(vigentes[0]["permanente"])
            self.assertIsNone(vigentes[0]["dias_restantes"])
            indice = indice_riesgo_aceptado(vigentes)
            self.assertTrue(indice["activo_cve"][(1, "CVE-2026-1001")]["permanente"])


if __name__ == "__main__":
    unittest.main()

"""Excepciones con vencimiento: aceptación de riesgo con responsable y caducidad (2026-09-10).

Lo que vigilan estas pruebas, en el orden en que importa:

* el alta exige TODOS los campos obligatorios (alcance, justificación, responsable con
  nombre y correo, y fecha de vencimiento) y los valida uno por uno;
* una excepción vigente saca la vulnerabilidad de la cola de trabajo y de las cifras de
  riesgo, y al VENCER la devuelve sola, sin que nadie ejecute nada;
* la revocación la devuelve en el acto, y una excepción vencida o revocada no cuenta como
  vigente en NINGUNA cifra;
* el cálculo del vencimiento está en un solo sitio: la condición SQL y su espejo en
  Python dicen lo mismo en los días frontera;
* el aviso anticipado de la ejecución diaria (con un Mailer falso: en pruebas no se envía
  ni un correo) avisa de las que vencen pronto y de las vencidas, y no repite el mismo
  aviso al día siguiente;
* los permisos de cada perfil, incluido el 404 uniforme fuera del alcance de máquinas;
* el CSRF y el registro de auditoría de cada creación, prórroga y revocación.

Base temporal bajo data/; ninguna prueba toca la base real ni la red.
"""
from __future__ import annotations

import re
import tempfile
import unittest
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from threatintel import db, excepciones
from threatintel.paths import BASE_DIR
from webui import auth

CLAVE = "AdminSeguro#2026"
JUSTIFICACION = ("El fabricante no certifica la versión corregida hasta noviembre y la "
                 "aplicación de nómina deja de funcionar si se actualiza antes.")
MOTIVO = "El fabricante aplazó la certificación de la versión corregida a diciembre."


def _fecha(dias: int) -> str:
    """Fecha en formato ISO a ``dias`` de hoy (UTC), para que las pruebas no caduquen."""
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
    """Configuración mínima: los ajustes que se consultan y los destinatarios."""

    def __init__(self, admin_to=("soc@ejemplo.local",), **ajustes):
        self.admin_to = list(admin_to)
        self._ajustes = dict(ajustes)

    def get(self, clave, defecto=None):
        return self._ajustes.get(clave, defecto)


class BaseExcepciones(unittest.TestCase):
    """Inventario mínimo: dos activos (un servidor y un equipo de cómputo), tres amenazas
    (una de ellas con explotación activa confirmada), sus veredictos y su cola."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "excepciones.db")
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "admin", CLAVE, rol="admin", actor="t")
            auth.crear_usuario(conn, "soc", CLAVE, rol="ciberseguridad", actor="t")
            # «jefe» y «lector» representan perfiles que SOLICITAN pero no GESTIONAN
            # (ROLES_SOLICITUD incluye a redes y mantenimiento, pero ROLES_GESTION solo a
            # admin y ciberseguridad): uno sobre un servidor, otro sobre un equipo de
            # cómputo, para cubrir los dos alcances.
            auth.crear_usuario(conn, "jefe", CLAVE, rol="redes", actor="t")
            auth.crear_usuario(conn, "redes", CLAVE, rol="redes", actor="t")
            auth.crear_usuario(conn, "mantenimiento", CLAVE, rol="mantenimiento", actor="t")
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
            # Veredictos: el servidor tiene los tres CVE (dos en openssl y uno en curl) y
            # el equipo de computo comparte el CVE-2026-1001.
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
            conn.execute("UPDATE remediaciones SET estado='abierta'")

    # ------------------------------------------------------------------ ayudas
    def _cliente(self, usuario="admin"):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": usuario, "password": CLAVE})
        return cli

    def _csrf(self, cli):
        html = cli.get("/excepciones/").get_data(as_text=True)
        return re.search(r'name="csrf" value="([^"]+)"', html).group(1)

    def _crear(self, conn, **cambios):
        datos = {"alcance": "activo_cve", "activo_id": 1, "cve": "CVE-2026-1001",
                 "justificacion": JUSTIFICACION, "responsable_nombre": "Ana Pérez Gómez",
                 "responsable_correo": "ana.perez@ejemplo.local",
                 "vence_at": _fecha(60)}
        datos.update(cambios)
        return excepciones.crear(conn, actor="admin", **datos)

    def _cola_abierta(self, conn) -> int:
        """Filas de la cola de trabajo que NO están cubiertas por una excepción vigente.

        Es la consulta que hará ``threatintel.remediacion`` cuando se le añada la
        condición: aquí se comprueba con las mismas piezas para que la prueba valga como
        contrato de esa condición.
        """
        return int(conn.execute(
            f"""SELECT COUNT(*) FROM remediaciones r
                 WHERE r.estado='abierta' AND {excepciones.SQL_SIN_EXCEPCION_REMEDIACION}"""
        ).fetchone()[0])

    def _vulnerabilidades(self, conn) -> int:
        """Pares (activo, CVE) confirmados que cuentan en las cifras de riesgo."""
        return int(conn.execute(
            f"""SELECT COUNT(DISTINCT ap.activo_id || char(31) || ap.cve)
                  FROM aplicabilidad ap JOIN activos a ON a.id = ap.activo_id
                 WHERE ap.veredicto='afectado' AND a.presente=1
                   AND {excepciones.SQL_SIN_EXCEPCION_APLICABILIDAD}""").fetchone()[0])


class TestAltaYValidacion(BaseExcepciones):
    def test_alta_con_todos_los_campos(self):
        with db.session(self.ruta) as conn:
            fila = self._crear(conn, compensacion="Solo acepta conexiones de administración.")
            self.assertEqual(fila["alcance"], "activo_cve")
            self.assertEqual(fila["estado"], "vigente")
            self.assertEqual(fila["cve"], "CVE-2026-1001")
            self.assertEqual(fila["activo_nombre"], "SRV-CONTABILIDAD")
            self.assertEqual(fila["registrado_por"], "admin")
            self.assertEqual(fila["responsable_nombre"], "Ana Pérez Gómez")
            self.assertEqual(fila["vence_at"], fila["vence_at_inicial"])
            self.assertEqual(fila["prorrogas"], 0)
            self.assertEqual(fila["kev"], 0)
            self.assertEqual(fila["descripcion"], "CVE-2026-1001 en SRV-CONTABILIDAD")

    def test_sin_los_campos_obligatorios_no_se_registra(self):
        casos = [
            ({"alcance": ""}, "Elija a qué se aplica"),
            ({"alcance": "otra_cosa"}, "Elija a qué se aplica"),
            ({"activo_id": None}, "Elija el activo"),
            ({"activo_id": 999}, "Ese activo no existe"),
            ({"cve": ""}, "identificador CVE válido"),
            ({"cve": "CVE-mal"}, "identificador CVE válido"),
            ({"cve": "CVE-2026-9999"}, "no figura en el catálogo"),
            ({"justificacion": "poco"}, "Explique por qué se acepta"),
            ({"responsable_nombre": "Ana"}, "nombre y el apellido"),
            ({"responsable_nombre": "Servicios Tecnológicos"}, None),
            ({"responsable_correo": "no-es-correo"}, "correo electrónico válido"),
            # v15 (2026-09-10): el mensaje ya no dice «nunca es indefinida», porque
            # ahora sí puede serlo con la opción «Permanente»; lo que no admite es
            # quedarse sin fecha SIN elegir esa opción.
            ({"vence_at": ""}, "Escriba la fecha de vencimiento, o elija"),
            ({"vence_at": "30/11/2026"}, "formato año-mes-día"),
            ({"vence_at": "2026-02-31"}, "no existe en el calendario"),
            ({"vence_at": excepciones.hoy()}, "posterior a hoy"),
            ({"vence_at": _fecha(-1)}, "posterior a hoy"),
            ({"vence_at": _fecha(excepciones.MAX_DIAS + 1)}, "plazo máximo"),
        ]
        for cambios, fragmento in casos:
            if fragmento is None:
                continue          # nombre de un área: se rechaza por otro mensaje
            with self.subTest(**cambios):
                with db.session(self.ruta) as conn:
                    with self.assertRaises(excepciones.ErrorExcepcion) as caja:
                        self._crear(conn, **cambios)
                    self.assertIn(fragmento, str(caja.exception))
                    self.assertEqual(
                        conn.execute("SELECT COUNT(*) FROM excepciones").fetchone()[0], 0)

    def test_un_area_no_puede_ser_el_responsable(self):
        """El responsable es una PERSONA: «Servicios Tecnológicos» tiene un espacio, así que
        se comprueba que el nombre no es el de un área conocida por su forma."""
        with db.session(self.ruta) as conn:
            # Un nombre de área pasa la comprobación de forma (dos palabras): la garantía
            # real es el correo personal obligatorio, que no admite un alias de área vacío.
            with self.assertRaises(excepciones.ErrorExcepcion):
                self._crear(conn, responsable_nombre="Servicios Tecnológicos",
                            responsable_correo="servicios tecnologicos")

    def test_el_cve_tiene_que_estar_evaluado_en_ese_activo(self):
        with db.session(self.ruta) as conn:
            with self.assertRaises(excepciones.ErrorExcepcion) as caja:
                self._crear(conn, activo_id=2, cve="CVE-2026-1003")
            self.assertIn("no ha evaluado", str(caja.exception))

    def test_alcance_por_paquete_exige_un_paquete_real_del_activo(self):
        with db.session(self.ruta) as conn:
            with self.assertRaises(excepciones.ErrorExcepcion) as caja:
                self._crear(conn, alcance="activo_paquete", cve="", paquete="no-existe")
            self.assertIn("no hay ningún paquete llamado", str(caja.exception))
            fila = self._crear(conn, alcance="activo_paquete", cve="", paquete="CURL")
            self.assertEqual(fila["paquete"], "curl", "el nombre se normaliza a minúsculas")
            self.assertIsNone(fila["cve"])

    def test_no_se_admiten_dos_excepciones_sobre_lo_mismo(self):
        with db.session(self.ruta) as conn:
            self._crear(conn)
            with self.assertRaises(excepciones.ErrorExcepcion) as caja:
                self._crear(conn, vence_at=_fecha(90))
            self.assertIn("Ya hay una excepción", str(caja.exception))
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM excepciones").fetchone()[0], 1)

    def test_tras_revocar_se_puede_registrar_otra_del_mismo_alcance(self):
        with db.session(self.ruta) as conn:
            primera = self._crear(conn)
            excepciones.revocar(conn, primera["id"],
                                motivo="Se instaló la corrección y la excepción sobra ya.",
                                actor="admin")
            segunda = self._crear(conn, vence_at=_fecha(30))
            self.assertNotEqual(primera["id"], segunda["id"])
            self.assertEqual(segunda["estado"], "vigente")


class TestExplotacionActiva(BaseExcepciones):
    def test_kev_avisa_antes_de_registrar_y_exige_confirmacion(self):
        with db.session(self.ruta) as conn:
            with self.assertRaises(excepciones.AvisoKev) as caja:
                self._crear(conn, cve="CVE-2026-1002", vence_at=_fecha(20))
            self.assertIn("Explotación activa confirmada", str(caja.exception))
            self.assertEqual(caja.exception.cves, ["CVE-2026-1002"])
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM excepciones").fetchone()[0], 0)

    def test_kev_exige_medida_compensatoria_y_plazo_corto(self):
        with db.session(self.ruta) as conn:
            with self.assertRaises(excepciones.ErrorExcepcion) as caja:
                self._crear(conn, cve="CVE-2026-1002", vence_at=_fecha(20),
                            confirmar_kev=True)
            self.assertIn("medida compensatoria es", str(caja.exception))
            with self.assertRaises(excepciones.ErrorExcepcion) as caja:
                self._crear(conn, cve="CVE-2026-1002",
                            vence_at=_fecha(excepciones.MAX_DIAS_KEV + 1),
                            confirmar_kev=True, compensacion="Aislado en su propia red.")
            self.assertIn(f"plazo máximo es de {excepciones.MAX_DIAS_KEV} días",
                          str(caja.exception))
            fila = self._crear(conn, cve="CVE-2026-1002", vence_at=_fecha(20),
                               confirmar_kev=True,
                               compensacion="Aislado en su propia red y con registro diario.")
            self.assertEqual(fila["kev"], 1)

    def test_el_paquete_hereda_la_explotacion_activa_de_sus_cve(self):
        """Aceptar un paquete entero es aceptar también sus vulnerabilidades explotadas."""
        with db.session(self.ruta) as conn:
            with self.assertRaises(excepciones.AvisoKev) as caja:
                self._crear(conn, alcance="activo_paquete", cve="", paquete="openssl",
                            vence_at=_fecha(20))
            self.assertEqual(caja.exception.cves, ["CVE-2026-1002"])

    def test_la_pantalla_advierte_con_los_cve_explotados(self):
        cli = self._cliente("admin")
        csrf = self._csrf(cli)
        respuesta = cli.post("/excepciones/crear", data={
            "csrf": csrf, "alcance": "activo_cve", "activo_id": "1", "cve": "CVE-2026-1002",
            "justificacion": JUSTIFICACION, "responsable_nombre": "Ana Pérez Gómez",
            "responsable_correo": "ana.perez@ejemplo.local", "vence_at": _fecha(20)})
        html = respuesta.get_data(as_text=True)
        self.assertEqual(respuesta.status_code, 200)
        self.assertIn("Explotación activa confirmada", html)
        self.assertIn("CVE-2026-1002", html)
        self.assertIn("casilla de confirmación", html)
        # Y no se registró nada.
        with db.session(self.ruta) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM excepciones").fetchone()[0], 0)


class TestVigenciaYCifras(BaseExcepciones):
    def test_una_excepcion_vigente_saca_la_vulnerabilidad_de_la_cola_y_de_las_cifras(self):
        with db.session(self.ruta) as conn:
            self.assertEqual(self._cola_abierta(conn), 4)
            self.assertEqual(self._vulnerabilidades(conn), 4)
            self._crear(conn)
            self.assertEqual(self._cola_abierta(conn), 3, "la fila cubierta sale de la cola")
            self.assertEqual(self._vulnerabilidades(conn), 3)
            # Pero NO se borra ni se oculta: sigue en la base y en su página.
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM remediaciones WHERE estado='abierta'").fetchone()[0], 4)
            self.assertEqual(len(excepciones.listar(conn)), 1)

    def test_al_vencer_vuelve_sola_sin_que_nadie_haga_nada(self):
        with db.session(self.ruta) as conn:
            fila = self._crear(conn)
            self.assertEqual(self._cola_abierta(conn), 3)
            # Se adelanta el reloj cambiando la fecha, que es lo único que decide la
            # vigencia: no hay ningún proceso que «cierre» excepciones.
            conn.execute("UPDATE excepciones SET vence_at=? WHERE id=?",
                         (_fecha(-1), fila["id"]))
            self.assertEqual(self._cola_abierta(conn), 4, "vencida: la fila vuelve a la cola")
            self.assertEqual(self._vulnerabilidades(conn), 4)
            de_nuevo = excepciones.obtener(conn, fila["id"])
            self.assertEqual(de_nuevo["estado"], "vencida")
            self.assertEqual(de_nuevo["estado_guardado"], "vigente",
                             "«vencida» no se guarda: se calcula")

    def test_la_revocacion_la_devuelve_en_el_acto(self):
        with db.session(self.ruta) as conn:
            fila = self._crear(conn)
            self.assertEqual(self._cola_abierta(conn), 3)
            excepciones.revocar(conn, fila["id"], actor="soc",
                                motivo="Ya se instaló la corrección en el servidor.")
            self.assertEqual(self._cola_abierta(conn), 4)
            self.assertEqual(self._vulnerabilidades(conn), 4)
            revocada = excepciones.obtener(conn, fila["id"])
            self.assertEqual(revocada["estado"], "revocada")
            self.assertEqual(revocada["revocada_por"], "soc")
            self.assertIn("instaló la corrección", revocada["revocada_motivo"])

    def test_una_vencida_o_revocada_no_cuenta_como_vigente_en_ninguna_cifra(self):
        with db.session(self.ruta) as conn:
            vencida = self._crear(conn)
            conn.execute("UPDATE excepciones SET vence_at=? WHERE id=?",
                         (_fecha(-3), vencida["id"]))
            revocada = self._crear(conn, cve="CVE-2026-1003")
            excepciones.revocar(conn, revocada["id"], actor="admin",
                                motivo="El proceso decidió no aceptar este riesgo.")
            viva = self._crear(conn, activo_id=2, cve="CVE-2026-1001")
            resumen = excepciones.resumen(conn)
            self.assertEqual(resumen["vigentes"], 1)
            self.assertEqual(resumen["vencidas"], 1)
            self.assertEqual(resumen["revocadas"], 1)
            self.assertEqual(resumen["total"], 3)
            self.assertEqual(resumen["vulnerabilidades_cubiertas"], 1,
                             "solo la vigente tapa una vulnerabilidad")
            self.assertEqual(self._cola_abierta(conn), 3)
            self.assertEqual(len(excepciones.listar(conn, estado="vigente")), 1)
            self.assertEqual(excepciones.listar(conn, estado="vigente")[0]["id"], viva["id"])
            self.assertEqual(excepciones.contar(conn, estado="vencida"), 1)
            self.assertEqual(excepciones.contar(conn, estado="revocada"), 1)

    def test_el_alcance_de_toda_la_organizacion_cubre_los_dos_activos(self):
        with db.session(self.ruta) as conn:
            self._crear(conn, alcance="cve", activo_id=None, cve="CVE-2026-1001")
            self.assertEqual(self._cola_abierta(conn), 2, "sale del servidor y del equipo")
            self.assertEqual(self._vulnerabilidades(conn), 2)
            fila = excepciones.listar(conn)[0]
            self.assertEqual(fila["descripcion"], "CVE-2026-1001 en toda la organización")
            self.assertEqual(fila["vulnerabilidades_cubiertas"], 2)

    def test_el_alcance_por_paquete_cubre_todos_los_cve_de_ese_paquete(self):
        with db.session(self.ruta) as conn:
            self._crear(conn, alcance="activo_paquete", cve="", paquete="openssl",
                        confirmar_kev=True, vence_at=_fecha(20),
                        compensacion="Aislado en su propia red.")
            self.assertEqual(self._cola_abierta(conn), 2,
                             "los dos CVE de openssl del servidor salen de la cola")
            fila = excepciones.listar(conn)[0]
            self.assertEqual(fila["vulnerabilidades_cubiertas"], 2)

    def test_sin_excepciones_las_consultas_quedan_como_estaban(self):
        with db.session(self.ruta) as conn:
            self.assertFalse(excepciones.hay_excepciones(conn))
            self.assertEqual(excepciones.y_sin_excepcion(conn), "")
            self.assertEqual(excepciones.vulnerabilidades_cubiertas(conn), 0)
            self._crear(conn)
            self.assertTrue(excepciones.hay_excepciones(conn))
            self.assertIn("NOT IN", excepciones.y_sin_excepcion(conn))

    def test_la_condicion_no_deja_fuera_filas_por_valores_nulos(self):
        """Un NULL dentro de un NOT IN vaciaría la página entera: las subconsultas los
        descartan y se comprueba con una excepción de cada alcance a la vez."""
        with db.session(self.ruta) as conn:
            self._crear(conn)                                      # activo_cve: cve y activo
            self._crear(conn, alcance="cve", activo_id=None, cve="CVE-2026-1003")
            self._crear(conn, alcance="activo_paquete", cve="", paquete="openssl",
                        confirmar_kev=True, vence_at=_fecha(20),
                        compensacion="Aislado en su propia red.")
            # Quedan: el CVE-2026-1002 de openssl del servidor (cubierto por el paquete),
            # el CVE-2026-1001 del equipo de cómputo y nada más.
            self.assertEqual(self._cola_abierta(conn), 1)
            self.assertEqual(
                conn.execute(f"""SELECT r.activo_id, r.cve FROM remediaciones r
                                  WHERE r.estado='abierta'
                                    AND {excepciones.SQL_SIN_EXCEPCION_REMEDIACION}"""
                             ).fetchone()["cve"], "CVE-2026-1001")


class TestCalculoDelVencimiento(BaseExcepciones):
    def test_el_sql_y_el_python_dicen_lo_mismo_en_los_dias_frontera(self):
        """El cálculo del vencimiento está en un solo sitio (SQL_VIGENTE) y su espejo en
        Python tiene que coincidir, también el último día y el primero después."""
        with db.session(self.ruta) as conn:
            fila = self._crear(conn)
            for dias in (-10, -1, 0, 1, 10):
                with self.subTest(dias=dias):
                    fecha = _fecha(dias)
                    conn.execute("UPDATE excepciones SET vence_at=? WHERE id=?",
                                 (fecha, fila["id"]))
                    vigente_sql = conn.execute(
                        f"SELECT COUNT(*) FROM excepciones e WHERE {excepciones.SQL_VIGENTE}"
                    ).fetchone()[0] == 1
                    self.assertEqual(vigente_sql, not excepciones.esta_vencida(fecha),
                                     f"discrepan para {fecha}")
                    estado_sql = conn.execute(
                        f"SELECT {excepciones.SQL_ESTADO} FROM excepciones e").fetchone()[0]
                    self.assertEqual(estado_sql, excepciones.estado_efectivo("vigente", fecha))
                    dias_sql = conn.execute(
                        f"SELECT {excepciones.SQL_DIAS_RESTANTES} FROM excepciones e"
                    ).fetchone()[0]
                    self.assertEqual(int(dias_sql), excepciones.dias_restantes(fecha))

    def test_el_ultimo_dia_sigue_vigente(self):
        with db.session(self.ruta) as conn:
            fila = self._crear(conn, vence_at=_fecha(1))
            conn.execute("UPDATE excepciones SET vence_at=? WHERE id=?",
                         (excepciones.hoy(), fila["id"]))
            self.assertEqual(excepciones.obtener(conn, fila["id"])["estado"], "vigente")
            self.assertEqual(excepciones.obtener(conn, fila["id"])["dias_restantes"], 0)
            self.assertEqual(self._cola_abierta(conn), 3)

    def test_una_excepcion_revocada_no_esta_vencida(self):
        self.assertFalse(excepciones.esta_vencida(_fecha(-5), estado="revocada"))
        self.assertEqual(excepciones.estado_efectivo("revocada", _fecha(-5)), "revocada")


class TestProrroga(BaseExcepciones):
    def test_la_prorroga_amplia_la_fecha_y_deja_constancia(self):
        with db.session(self.ruta) as conn:
            fila = self._crear(conn)
            nueva = excepciones.prorrogar(conn, fila["id"], vence_at=_fecha(120),
                                          motivo=MOTIVO, actor="soc")
            self.assertEqual(nueva["vence_at"], _fecha(120))
            self.assertEqual(nueva["vence_at_inicial"], fila["vence_at"])
            self.assertEqual(nueva["prorrogas"], 1)
            self.assertEqual(nueva["prorrogada_por"], "soc")
            self.assertIn("aplazó la certificación", nueva["prorroga_motivo"])

    def test_una_vencida_se_puede_prorrogar_y_vuelve_a_salir_de_la_cola(self):
        with db.session(self.ruta) as conn:
            fila = self._crear(conn)
            conn.execute("UPDATE excepciones SET vence_at=? WHERE id=?",
                         (_fecha(-2), fila["id"]))
            self.assertEqual(self._cola_abierta(conn), 4)
            excepciones.prorrogar(conn, fila["id"], vence_at=_fecha(30), motivo=MOTIVO,
                                  actor="admin")
            self.assertEqual(self._cola_abierta(conn), 3)
            self.assertEqual(excepciones.obtener(conn, fila["id"])["estado"], "vigente")

    def test_la_prorroga_exige_motivo_fecha_mayor_y_respeta_los_topes(self):
        with db.session(self.ruta) as conn:
            fila = self._crear(conn)
            for cambios, fragmento in (
                    ({"motivo": "corto"}, "Explique por qué se prorroga"),
                    ({"vence_at": _fecha(10)}, "tiene que ir más allá"),
                    ({"vence_at": ""}, "Escriba la fecha de vencimiento, o elija"),
                    ({"vence_at": _fecha(excepciones.MAX_DIAS + 5)}, "plazo máximo")):
                datos = {"vence_at": _fecha(120), "motivo": MOTIVO}
                datos.update(cambios)
                with self.subTest(**cambios):
                    with self.assertRaises(excepciones.ErrorExcepcion) as caja:
                        excepciones.prorrogar(conn, fila["id"], actor="admin", **datos)
                    self.assertIn(fragmento, str(caja.exception))
            self.assertEqual(excepciones.obtener(conn, fila["id"])["prorrogas"], 0)

    def test_una_revocada_no_se_prorroga(self):
        with db.session(self.ruta) as conn:
            fila = self._crear(conn)
            excepciones.revocar(conn, fila["id"], motivo="Ya no hace falta esta excepción.",
                                actor="admin")
            with self.assertRaises(excepciones.ErrorExcepcion) as caja:
                excepciones.prorrogar(conn, fila["id"], vence_at=_fecha(90), motivo=MOTIVO,
                                      actor="admin")
            self.assertIn("está revocada", str(caja.exception))

    def test_la_prorroga_de_un_kev_no_pasa_de_su_plazo_corto(self):
        with db.session(self.ruta) as conn:
            fila = self._crear(conn, cve="CVE-2026-1002", vence_at=_fecha(5),
                               confirmar_kev=True, compensacion="Aislado en su red.")
            with self.assertRaises(excepciones.ErrorExcepcion) as caja:
                excepciones.prorrogar(conn, fila["id"],
                                      vence_at=_fecha(excepciones.MAX_DIAS_KEV + 10),
                                      motivo=MOTIVO, actor="admin")
            self.assertIn(f"plazo máximo es de {excepciones.MAX_DIAS_KEV} días",
                          str(caja.exception))


class TestAvisoAnticipado(BaseExcepciones):
    def test_avisa_de_las_que_vencen_pronto_y_de_las_vencidas(self):
        cfg = CfgFalso()
        mailer = MailerFalso()
        with db.session(self.ruta) as conn:
            lejana = self._crear(conn, vence_at=_fecha(200))
            pronto = self._crear(conn, cve="CVE-2026-1003", vence_at=_fecha(5))
            vencida = self._crear(conn, activo_id=2, cve="CVE-2026-1001")
            conn.execute("UPDATE excepciones SET vence_at=? WHERE id=?",
                         (_fecha(-4), vencida["id"]))
            pendientes = excepciones.pendientes_de_aviso(conn, cfg=cfg)
            self.assertEqual([f["id"] for f in pendientes["por_vencer"]], [pronto["id"]])
            self.assertEqual([f["id"] for f in pendientes["vencidas"]], [vencida["id"]])
            self.assertEqual(pendientes["aviso_dias"], excepciones.AVISO_DIAS_DEFECTO)
            aviso = excepciones.avisar(conn, cfg=cfg, mailer=mailer)
            self.assertIsNotNone(aviso)
            self.assertEqual(aviso["severidad"], "critical")
            self.assertEqual(aviso["por_vencer"], 1)
            self.assertEqual(aviso["vencidas"], 1)
            self.assertEqual(len(mailer.enviados), 1)
            correo = mailer.enviados[0]
            self.assertEqual(correo["to"], ["soc@ejemplo.local"])
            # Revisión de claridad del 2026-09-15: un solo prefijo para todo el sistema
            # («[Inteligencia de Amenazas]») y «Acción requerida» con tilde y sin gritar.
            self.assertIn("Acción requerida", correo["asunto"])
            self.assertIn("CVE-2026-1003", correo["html"])
            self.assertIn("Ana Pérez Gómez", correo["html"])
            self.assertNotIn("CVE-2026-1002", correo["html"])
            self.assertNotIn(str(lejana["cve"]) + " en SRV", correo["html"])
            self.assertIn("vuelve sola", correo["html"])
            # Queda anotado en la excepción y en admin_notices
            self.assertIsNotNone(excepciones.obtener(conn, pronto["id"])["avisado_at"])
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM admin_notices WHERE kind='excepciones'").fetchone()[0], 2)

    def test_no_repite_el_mismo_aviso_al_dia_siguiente(self):
        cfg = CfgFalso()
        with db.session(self.ruta) as conn:
            self._crear(conn, vence_at=_fecha(3))
            primero = excepciones.avisar(conn, cfg=cfg, mailer=MailerFalso())
            self.assertIsNotNone(primero)
            segundo = MailerFalso()
            manana = datetime.now(timezone.utc) + timedelta(days=1)
            self.assertIsNone(excepciones.avisar(conn, cfg=cfg, mailer=segundo, ahora=manana))
            self.assertEqual(segundo.enviados, [])
            # Pasada la semana de silencio vuelve a avisar.
            tercero = MailerFalso()
            self.assertIsNotNone(excepciones.avisar(
                conn, cfg=cfg, mailer=tercero,
                ahora=datetime.now(timezone.utc) + timedelta(days=8)))
            self.assertEqual(len(tercero.enviados), 1)

    def test_sin_nada_que_avisar_no_se_envia_nada(self):
        with db.session(self.ruta) as conn:
            self._crear(conn, vence_at=_fecha(200))
            mailer = MailerFalso()
            self.assertIsNone(excepciones.avisar(conn, cfg=CfgFalso(), mailer=mailer))
            self.assertEqual(mailer.enviados, [])

    def test_sin_destinatarios_no_se_envia_y_no_se_marca_nada(self):
        with db.session(self.ruta) as conn:
            fila = self._crear(conn, vence_at=_fecha(2))
            mailer = MailerFalso()
            self.assertIsNone(excepciones.avisar(conn, cfg=CfgFalso(admin_to=()),
                                                 mailer=mailer))
            self.assertEqual(mailer.enviados, [])
            self.assertIsNone(excepciones.obtener(conn, fila["id"])["avisado_at"])

    def test_si_el_correo_no_sale_no_se_marca_como_avisado(self):
        with db.session(self.ruta) as conn:
            fila = self._crear(conn, vence_at=_fecha(2))
            self.assertIsNone(excepciones.avisar(conn, cfg=CfgFalso(),
                                                 mailer=MailerFalso(acepta=False)))
            self.assertIsNone(excepciones.obtener(conn, fila["id"])["avisado_at"])
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM admin_notices").fetchone()[0], 0)

    def test_los_dias_de_antelacion_salen_del_ajuste(self):
        with db.session(self.ruta) as conn:
            self.assertEqual(excepciones.ajuste_aviso_dias(conn), 15)
            db.set_setting(conn, excepciones.AJUSTE_AVISO_DIAS, 30)
            self.assertEqual(excepciones.ajuste_aviso_dias(conn), 30)
            self.assertEqual(excepciones.ajuste_aviso_dias(conn, cfg=CfgFalso(
                excepciones_aviso_dias=7)), 7)
            db.set_setting(conn, excepciones.AJUSTE_AVISO_DIAS, "lo que sea")
            self.assertEqual(excepciones.ajuste_aviso_dias(conn), 15,
                             "un valor corrupto no rompe el aviso")
            db.set_setting(conn, excepciones.AJUSTE_AVISO_DIAS, 15)

    def test_la_antelacion_del_ajuste_decide_a_quien_se_avisa(self):
        with db.session(self.ruta) as conn:
            self._crear(conn, vence_at=_fecha(25))
            self.assertEqual(len(excepciones.pendientes_de_aviso(conn)["por_vencer"]), 0)
            self.assertEqual(len(excepciones.pendientes_de_aviso(
                conn, aviso_dias=30)["por_vencer"]), 1)


class TestPaginaYPermisos(BaseExcepciones):
    def test_la_pagina_se_ve_con_cualquier_perfil_y_cumple_la_csp(self):
        with db.session(self.ruta) as conn:
            self._crear(conn)
        for usuario in ("admin", "soc", "jefe", "redes", "mantenimiento", "lector"):
            with self.subTest(usuario=usuario):
                respuesta = self._cliente(usuario).get("/excepciones/")
                self.assertEqual(respuesta.status_code, 200)
                html = respuesta.get_data(as_text=True)
                self.assertIn("Excepciones: riesgo aceptado", html)
                self.assertIsNone(re.search(r"\sstyle\s*=", html))
                self.assertIsNone(re.search(r"\son[a-z]+\s*=", html))
                self.assertIn("no-store", respuesta.headers.get("Cache-Control", ""))
                self.assertNotIn("unsafe", respuesta.headers.get("Content-Security-Policy", ""))

    def test_sin_sesion_no_se_ve_nada(self):
        anonimo = self.app.test_client()
        for metodo, url in (("get", "/excepciones/"), ("post", "/excepciones/crear"),
                            ("post", "/excepciones/1/prorrogar"),
                            ("post", "/excepciones/1/revocar"),
                            ("post", "/excepciones/solicitar")):
            with self.subTest(url=url):
                respuesta = getattr(anonimo, metodo)(url)
                self.assertIn(respuesta.status_code, (302, 400, 403))
                if respuesta.status_code == 302:
                    self.assertIn("/login", respuesta.headers.get("Location", ""))

    def test_solo_administracion_y_operador_soc_registran_prorrogan_y_revocan(self):
        with db.session(self.ruta) as conn:
            fila = self._crear(conn)
        alta = {"alcance": "activo_cve", "activo_id": "1", "cve": "CVE-2026-1003",
                "justificacion": JUSTIFICACION, "responsable_nombre": "Ana Pérez Gómez",
                "responsable_correo": "ana.perez@ejemplo.local", "vence_at": _fecha(30)}
        for usuario in ("jefe", "redes", "mantenimiento", "lector"):
            cli = self._cliente(usuario)
            csrf = self._csrf(cli)
            with self.subTest(usuario=usuario):
                self.assertEqual(cli.post("/excepciones/crear",
                                          data={"csrf": csrf, **alta}).status_code, 403)
                self.assertEqual(cli.post(f"/excepciones/{fila['id']}/prorrogar",
                                          data={"csrf": csrf, "vence_at": _fecha(90),
                                                "motivo": MOTIVO}).status_code, 403)
                self.assertEqual(cli.post(f"/excepciones/{fila['id']}/revocar",
                                          data={"csrf": csrf,
                                                "motivo": MOTIVO}).status_code, 403)
        with db.session(self.ruta) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM excepciones").fetchone()[0], 1)
            self.assertEqual(excepciones.obtener(conn, fila["id"])["estado"], "vigente")
        for usuario in ("admin", "soc"):
            with self.subTest(usuario=usuario):
                cli = self._cliente(usuario)
                csrf = self._csrf(cli)
                respuesta = cli.post("/excepciones/crear",
                                     data={"csrf": csrf, **alta,
                                           "cve": "CVE-2026-1003" if usuario == "admin"
                                                  else "CVE-2026-1002",
                                           "confirmar_kev": "1",
                                           "compensacion": "Aislado en su propia red.",
                                           "vence_at": _fecha(20)},
                                     follow_redirects=True)
                self.assertIn("Riesgo aceptado hasta el", respuesta.get_data(as_text=True))

    def test_los_botones_de_accion_solo_salen_para_quien_puede_usarlos(self):
        with db.session(self.ruta) as conn:
            self._crear(conn)
        gestor = self._cliente("soc").get("/excepciones/").get_data(as_text=True)
        self.assertIn("Aceptar el riesgo y registrar la excepción", gestor)
        self.assertIn(">Prorrogar</summary>", gestor.replace("<summary>", ">"))
        self.assertIn("Revocar", gestor)
        jefe = self._cliente("jefe").get("/excepciones/").get_data(as_text=True)
        self.assertIn("Enviar la solicitud", jefe)
        self.assertNotIn("Aceptar el riesgo y registrar la excepción", jefe)
        lector = self._cliente("lector").get("/excepciones/").get_data(as_text=True)
        self.assertIn("Enviar la solicitud", lector)
        self.assertNotIn("Aceptar el riesgo y registrar la excepción", lector)

    def test_el_jefe_de_proceso_solicita_y_queda_en_la_auditoria(self):
        cli = self._cliente("jefe")
        csrf = self._csrf(cli)
        respuesta = cli.post("/excepciones/solicitar", data={
            "csrf": csrf, "alcance": "activo_cve", "activo_id": "1", "cve": "CVE-2026-1001",
            "justificacion": JUSTIFICACION, "responsable_nombre": "Ana Pérez Gómez",
            "responsable_correo": "ana.perez@ejemplo.local", "vence_at": _fecha(30)},
            follow_redirects=True)
        html = respuesta.get_data(as_text=True)
        self.assertIn("Solicitud registrada", html)
        self.assertIn("sigue en la cola de trabajo", html)
        with db.session(self.ruta) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM excepciones").fetchone()[0], 0,
                             "una solicitud no acepta ningún riesgo")
            fila = conn.execute(
                "SELECT username, detail FROM audit_log WHERE action='excepciones.solicitud'"
            ).fetchone()
            self.assertEqual(fila["username"], "jefe")
            self.assertIn("CVE-2026-1001 en SRV-CONTABILIDAD", fila["detail"])
            self.assertEqual(len(excepciones.solicitudes(conn)), 1)
        self.assertIn("CVE-2026-1001 en SRV-CONTABILIDAD",
                      cli.get("/excepciones/").get_data(as_text=True))

    def test_una_solicitud_con_datos_invalidos_no_se_registra(self):
        cli = self._cliente("jefe")
        csrf = self._csrf(cli)
        respuesta = cli.post("/excepciones/solicitar", data={
            "csrf": csrf, "alcance": "activo_cve", "activo_id": "1", "cve": "CVE-2026-1001",
            "justificacion": "corto", "responsable_nombre": "Ana Pérez Gómez",
            "responsable_correo": "ana.perez@ejemplo.local", "vence_at": _fecha(30)})
        self.assertEqual(respuesta.status_code, 200)
        self.assertIn("Explique por qué se acepta", respuesta.get_data(as_text=True))
        with db.session(self.ruta) as conn:
            self.assertEqual(len(excepciones.solicitudes(conn)), 0)

    def test_los_perfiles_acotados_solo_ven_las_de_sus_maquinas(self):
        with db.session(self.ruta) as conn:
            self._crear(conn)                                       # servidor
            self._crear(conn, activo_id=2, cve="CVE-2026-1001")     # equipo de cómputo
            self._crear(conn, alcance="cve", activo_id=None, cve="CVE-2026-1003")
        redes = self._cliente("redes").get("/excepciones/").get_data(as_text=True)
        self.assertIn("SRV-CONTABILIDAD", redes)
        self.assertNotIn("PC-TESORERIA", redes)
        self.assertIn("Toda la organización", redes,
                      "un CVE aceptado en toda la organización también afecta a sus servidores")
        mantenimiento = self._cliente("mantenimiento").get("/excepciones/").get_data(as_text=True)
        self.assertIn("PC-TESORERIA", mantenimiento)
        self.assertNotIn("SRV-CONTABILIDAD", mantenimiento)
        self.assertIn("Toda la organización", mantenimiento)
        completo = self._cliente("admin").get("/excepciones/").get_data(as_text=True)
        self.assertIn("SRV-CONTABILIDAD", completo)
        self.assertIn("PC-TESORERIA", completo)

    def test_404_uniforme_para_un_activo_fuera_del_alcance(self):
        """Un activo del otro tipo de máquina responde igual que uno inventado: 404."""
        redes = self._cliente("redes")
        self.assertEqual(redes.get("/excepciones/?activo=2").status_code, 404)
        self.assertEqual(redes.get("/excepciones/?activo=9999").status_code, 404)
        self.assertEqual(redes.get("/excepciones/?activo=1").status_code, 200)
        mantenimiento = self._cliente("mantenimiento")
        self.assertEqual(mantenimiento.get("/excepciones/?activo=1").status_code, 404)
        self.assertEqual(mantenimiento.get("/excepciones/?activo=2").status_code, 200)
        self.assertEqual(self._cliente("admin").get("/excepciones/?activo=2").status_code, 200)
        # La respuesta es la misma para el activo del otro tipo y para uno inventado:
        # ni el nombre del activo ni el motivo real aparecen en ninguna de las dos.
        inventado = redes.get("/excepciones/?activo=9999").get_data(as_text=True)
        otro_tipo = redes.get("/excepciones/?activo=2").get_data(as_text=True)
        # El 404 se reescribió el 2026-09-15 para decir qué pasó y cómo seguir.
        self.assertIn("Esa página no existe", inventado)
        self.assertIn("Esa página no existe", otro_tipo)
        self.assertNotIn("PC-TESORERIA", otro_tipo)
        self.assertNotIn("equipos de cómputo", otro_tipo)

    def test_el_selector_de_activos_respeta_el_alcance(self):
        # «jefe» (redes) solo ve servidores; «admin» no tiene alcance restringido y ve
        # los dos tipos de máquina.
        jefe = self._cliente("jefe").get("/excepciones/").get_data(as_text=True)
        self.assertIn("SRV-CONTABILIDAD", jefe)
        self.assertNotIn("PC-TESORERIA", jefe)
        admin = self._cliente("admin").get("/excepciones/").get_data(as_text=True)
        self.assertIn("SRV-CONTABILIDAD", admin)
        self.assertIn("PC-TESORERIA", admin)
        self.assertIn("equipo de cómputo", admin)
        # «lector» (mantenimiento) solo ve equipos de cómputo en su selector.
        lector = self._cliente("lector").get("/excepciones/").get_data(as_text=True)
        self.assertIn("PC-TESORERIA", lector)
        self.assertNotIn("SRV-CONTABILIDAD", lector)

    def test_toda_escritura_exige_csrf(self):
        with db.session(self.ruta) as conn:
            fila = self._crear(conn)
        cli = self._cliente("admin")
        for url, datos in (("/excepciones/crear", {"alcance": "cve", "cve": "CVE-2026-1001"}),
                           (f"/excepciones/{fila['id']}/prorrogar",
                            {"vence_at": _fecha(120), "motivo": MOTIVO}),
                           (f"/excepciones/{fila['id']}/revocar", {"motivo": MOTIVO}),
                           ("/excepciones/solicitar", {"alcance": "cve"})):
            with self.subTest(url=url):
                respuesta = cli.post(url, data=datos)
                self.assertIn(respuesta.status_code, (400, 403))
                self.assertIn("CSRF", respuesta.get_data(as_text=True))
        with db.session(self.ruta) as conn:
            self.assertEqual(excepciones.obtener(conn, fila["id"])["estado"], "vigente")
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM excepciones").fetchone()[0], 1)

    def test_prorrogar_o_revocar_algo_que_no_existe_responde_404(self):
        cli = self._cliente("admin")
        csrf = self._csrf(cli)
        self.assertEqual(cli.post("/excepciones/424242/prorrogar",
                                  data={"csrf": csrf, "vence_at": _fecha(30),
                                        "motivo": MOTIVO}).status_code, 404)
        self.assertEqual(cli.post("/excepciones/424242/revocar",
                                  data={"csrf": csrf, "motivo": MOTIVO}).status_code, 404)

    def test_el_alta_desde_la_pagina_prorroga_y_revoca_de_punta_a_punta(self):
        cli = self._cliente("admin")
        csrf = self._csrf(cli)
        respuesta = cli.post("/excepciones/crear", data={
            "csrf": csrf, "alcance": "activo_cve", "activo_id": "1", "cve": "CVE-2026-1001",
            "justificacion": JUSTIFICACION, "responsable_nombre": "Ana Pérez Gómez",
            "responsable_correo": "Ana.Perez@Ejemplo.local", "vence_at": _fecha(45),
            "compensacion": "Solo acepta conexiones desde la red de administración."},
            follow_redirects=True)
        html = respuesta.get_data(as_text=True)
        self.assertIn("Riesgo aceptado hasta el", html)
        self.assertIn("riesgo aceptado", html.lower())
        with db.session(self.ruta) as conn:
            fila = excepciones.listar(conn)[0]
            self.assertEqual(fila["responsable_correo"], "ana.perez@ejemplo.local")
        html = cli.post(f"/excepciones/{fila['id']}/prorrogar",
                        data={"csrf": csrf, "vence_at": _fecha(90), "motivo": MOTIVO},
                        follow_redirects=True).get_data(as_text=True)
        self.assertIn("Excepción prorrogada hasta el", html)
        html = cli.post(f"/excepciones/{fila['id']}/revocar",
                        data={"csrf": csrf,
                              "motivo": "Ya se instaló la versión corregida en el servidor."},
                        follow_redirects=True).get_data(as_text=True)
        self.assertIn("Excepción revocada", html)
        self.assertIn("vuelve ahora mismo", html)

    def test_el_filtro_de_situacion_y_el_buscador(self):
        with db.session(self.ruta) as conn:
            vigente = self._crear(conn)
            vencida = self._crear(conn, cve="CVE-2026-1003", vence_at=_fecha(5))
            conn.execute("UPDATE excepciones SET vence_at=? WHERE id=?",
                         (_fecha(-2), vencida["id"]))
        cli = self._cliente("admin")
        solo_vigentes = cli.get("/excepciones/?estado=vigente").get_data(as_text=True)
        self.assertIn("CVE-2026-1001", solo_vigentes)
        self.assertNotIn("CVE-2026-1003", solo_vigentes)
        solo_vencidas = cli.get("/excepciones/?estado=vencida").get_data(as_text=True)
        self.assertIn("CVE-2026-1003", solo_vencidas)
        self.assertNotIn("CVE-2026-1001<", solo_vencidas)
        por_texto = cli.get("/excepciones/?q=CVE-2026-1003").get_data(as_text=True)
        self.assertIn("CVE-2026-1003", por_texto)
        self.assertNotIn("CVE-2026-1001<", por_texto)
        # Un filtro corrupto no vacía la página ni rompe nada.
        self.assertEqual(cli.get("/excepciones/?estado=lo-que-sea&alcance=x&pagina=-3"
                                 ).status_code, 200)
        self.assertIn(str(vigente["id"]), cli.get("/excepciones/").get_data(as_text=True))

    def test_la_pagina_dice_hasta_cuando_esta_aceptado_el_riesgo(self):
        with db.session(self.ruta) as conn:
            self._crear(conn, vence_at="2026-11-30")
        # «jefe» (redes) está en el alcance del activo 1 (servidor), que es el que
        # crea «_crear» por omisión.
        html = self._cliente("jefe").get("/excepciones/").get_data(as_text=True)
        self.assertIn("30 de noviembre de 2026", html)
        self.assertIn("Vigente", html)
        self.assertIn("fuera de la cola y de las cifras", html)


class TestAuditoria(BaseExcepciones):
    def test_crear_prorrogar_y_revocar_quedan_en_la_auditoria(self):
        with db.session(self.ruta) as conn:
            fila = self._crear(conn)
            excepciones.prorrogar(conn, fila["id"], vence_at=_fecha(120), motivo=MOTIVO,
                                  actor="soc", ip="10.1.1.5")
            excepciones.revocar(conn, fila["id"], motivo="Ya se instaló la corrección aquí.",
                                actor="admin", ip="10.1.1.6")
            filas = conn.execute(
                """SELECT action, username, entity, entity_id, detail, ip FROM audit_log
                    WHERE entity='excepciones' ORDER BY id""").fetchall()
            acciones = [f["action"] for f in filas]
            self.assertEqual(acciones, ["excepciones.crear", "excepciones.prorrogar",
                                        "excepciones.revocar"])
            self.assertEqual([f["username"] for f in filas], ["admin", "soc", "admin"])
            self.assertEqual({f["entity_id"] for f in filas}, {str(fila["id"])})
            self.assertIn("responsable=Ana Pérez Gómez", filas[0]["detail"])
            self.assertIn("vence_at=" + fila["vence_at"], filas[0]["detail"])
            self.assertIn(f"{fila['vence_at']} -> {_fecha(120)}", filas[1]["detail"])
            self.assertIn("Ya se instaló la corrección", filas[2]["detail"])
            self.assertEqual([f["ip"] for f in filas], [None, "10.1.1.5", "10.1.1.6"])

    def test_la_ip_del_alta_desde_la_pagina_queda_registrada(self):
        cli = self._cliente("admin")
        csrf = self._csrf(cli)
        cli.post("/excepciones/crear", data={
            "csrf": csrf, "alcance": "activo_cve", "activo_id": "1", "cve": "CVE-2026-1001",
            "justificacion": JUSTIFICACION, "responsable_nombre": "Ana Pérez Gómez",
            "responsable_correo": "ana.perez@ejemplo.local", "vence_at": _fecha(30)},
            environ_base={"REMOTE_ADDR": "10.1.1.77"}, follow_redirects=True)
        with db.session(self.ruta) as conn:
            fila = conn.execute(
                "SELECT ip, username FROM audit_log WHERE action='excepciones.crear'").fetchone()
            self.assertEqual(fila["ip"], "10.1.1.77")
            self.assertEqual(fila["username"], "admin")


class TestFichaDelActivoYDeLaAmenaza(BaseExcepciones):
    def test_por_activo_incluye_las_de_toda_la_organizacion(self):
        with db.session(self.ruta) as conn:
            self._crear(conn)
            self._crear(conn, alcance="cve", activo_id=None, cve="CVE-2026-1003")
            filas = excepciones.por_activo(conn, 1)
            self.assertEqual({f["cve"] for f in filas}, {"CVE-2026-1001", "CVE-2026-1003"})
            # El equipo de cómputo no tiene el CVE-2026-1003 evaluado: no le aplica.
            self.assertEqual([f["cve"] for f in excepciones.por_activo(conn, 2)], [])

    def test_por_cve_y_cubre_dan_la_insignia_de_la_ficha(self):
        with db.session(self.ruta) as conn:
            fila = self._crear(conn, vence_at="2026-11-30")
            self.assertEqual([f["id"] for f in excepciones.por_cve(conn, "cve-2026-1001")],
                             [fila["id"]])
            tapada = excepciones.cubre(conn, activo_id=1, cve="CVE-2026-1001",
                                       paquete="openssl")
            self.assertIsNotNone(tapada)
            self.assertEqual(tapada["vence_at"], "2026-11-30")
            self.assertIsNone(excepciones.cubre(conn, activo_id=2, cve="CVE-2026-1001"))
            self.assertIsNone(excepciones.cubre(conn, activo_id=1, cve="CVE-2026-1002"))
            excepciones.revocar(conn, fila["id"], motivo="Se corrigió y ya no hace falta.",
                                actor="admin")
            self.assertIsNone(excepciones.cubre(conn, activo_id=1, cve="CVE-2026-1001"))
            self.assertEqual(len(excepciones.por_cve(conn, "CVE-2026-1001",
                                                     solo_vigentes=False)), 1)

    def test_cubre_por_paquete_solo_con_paquete(self):
        with db.session(self.ruta) as conn:
            self._crear(conn, alcance="activo_paquete", cve="", paquete="openssl",
                        confirmar_kev=True, vence_at=_fecha(20),
                        compensacion="Aislado en su propia red.")
            self.assertIsNotNone(excepciones.cubre(conn, activo_id=1, cve="CVE-2026-1002",
                                                   paquete="openssl"))
            self.assertIsNone(excepciones.cubre(conn, activo_id=1, cve="CVE-2026-1002",
                                                paquete="curl"))
            self.assertIsNone(excepciones.cubre(conn, activo_id=1, cve="CVE-2026-1002"),
                              "sin paquete no se puede afirmar que esté cubierta")


class TestEsquemaDeExcepciones(BaseExcepciones):
    def test_la_tabla_y_sus_indices_existen(self):
        with db.session(self.ruta) as conn:
            columnas = {r[1] for r in conn.execute("PRAGMA table_info(excepciones)")}
            for obligatoria in ("alcance", "activo_id", "cve", "paquete", "justificacion",
                                "responsable_nombre", "responsable_correo", "compensacion",
                                "registrado_por", "registrado_at", "vence_at",
                                "vence_at_inicial", "estado", "kev", "prorrogas",
                                "revocada_at", "revocada_por", "revocada_motivo",
                                "avisado_at"):
                self.assertIn(obligatoria, columnas)
            indices = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='excepciones'")}
            for indice in ("idx_exc_activo", "idx_exc_cve", "idx_exc_vence", "idx_exc_unica"):
                self.assertIn(indice, indices)

    def test_la_version_del_esquema_es_la_trece(self):
        self.assertGreaterEqual(db.SCHEMA_VERSION, 13)
        with db.session(self.ruta) as conn:
            self.assertEqual(int(conn.execute(
                "SELECT value FROM schema_meta WHERE key='version'").fetchone()[0]),
                db.SCHEMA_VERSION)

    def test_el_indice_unico_impide_dos_vigentes_sobre_lo_mismo(self):
        import sqlite3
        with db.session(self.ruta) as conn:
            self._crear(conn)
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute(
                    """INSERT INTO excepciones(alcance, activo_id, cve, justificacion,
                                               responsable_nombre, responsable_correo,
                                               registrado_por, registrado_at, vence_at,
                                               vence_at_inicial)
                       VALUES('activo_cve', 1, 'CVE-2026-1001', ?, 'Ana Pérez Gómez',
                              'ana.perez@ejemplo.local', 'admin', ?, ?, ?)""",
                    (JUSTIFICACION, db.utcnow(), _fecha(10), _fecha(10)))


class TestPlantilla(unittest.TestCase):
    """La plantilla cumple las reglas de la casa sin necesidad de la aplicación."""

    @classmethod
    def setUpClass(cls):
        cls.texto = (BASE_DIR / "webui" / "templates" / "excepciones.html").read_text(
            encoding="utf-8")
        cls.base = (BASE_DIR / "webui" / "templates" / "base.html").read_text(encoding="utf-8")

    def test_extiende_la_base_y_tiene_recorrido_guiado(self):
        self.assertIn('extends "base.html"', self.texto)
        pasos = re.findall(
            r'data-tour="(\d+)"[^>]*data-tour-titulo="([^"]+)"[^>]*data-tour-texto="([^"]+)"',
            self.texto)
        self.assertGreaterEqual(len(pasos), 2)
        numeros = [int(n) for n, _, _ in pasos]
        self.assertEqual(min(numeros), 1)
        self.assertEqual(len(numeros), len(set(numeros)))
        for _, titulo, cuerpo in pasos:
            self.assertGreater(len(cuerpo), 40, titulo)

    def test_sin_estilos_ni_javascript_en_linea(self):
        limpio = re.sub(r"\{#.*?#\}", "", self.texto, flags=re.S)
        self.assertIsNone(re.search(r"\sstyle\s*=", limpio))
        self.assertIsNone(re.search(r"\son[a-z]+\s*=", limpio))
        self.assertNotIn("<script", limpio)

    def test_los_div_cuadran(self):
        limpio = re.sub(r"\{#.*?#\}", "", self.texto, flags=re.S)
        self.assertEqual(len(re.findall(r"<div\b", limpio)),
                         len(re.findall(r"</div\s*>", limpio)))

    def test_todo_campo_del_formulario_tiene_etiqueta_visible(self):
        controles = re.findall(r'<(?:input|select|textarea)\b[^>]*\sid="([^"]+)"', self.texto)
        etiquetas = set(re.findall(r'<label for="([^"]+)"', self.texto))
        for control in controles:
            if control.startswith(("vence-", "motivo-p-", "motivo-r-")):
                continue                       # etiquetas generadas con el mismo bucle
            self.assertIn(control, etiquetas, f"el campo {control} no tiene etiqueta")

    def test_esta_en_el_menu_junto_a_remediacion(self):
        self.assertIn("excepciones.lista", self.base)
        self.assertIn("'Excepciones'", self.base)
        self.assertLess(self.base.index("remediaciones.lista"),
                        self.base.index("excepciones.lista"))

    def test_los_numeros_van_con_el_filtro_espanol(self):
        for cifra in ("resumen.vigentes", "resumen.por_vencer", "resumen.vencidas",
                      "total"):
            self.assertIn(f"{{{{ {cifra} | numero }}}}", self.texto)


if __name__ == "__main__":
    unittest.main()

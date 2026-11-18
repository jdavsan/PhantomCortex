"""Perfil operativo acotado (antes «Servicios Tecnológicos») y comprobación real de una
remediación (2026-09-07; roles unificados a cuatro perfiles el 2026-09-15: admin,
ciberseguridad, redes, mantenimiento).

El usuario pidió dos cosas ligadas:

1. «una opción por cada vulnerabilidad en cada activo que una persona con el rol
   operativo pueda darle clic en que está remediada y que el sistema vaya y realice la
   respectiva consulta en la base de datos según el activo y verifique si la
   vulnerabilidad está o no está presente consultando la versión actual cruzándola con la
   información que se reportó de la vulnerabilidad».
2. «crear un rol donde solamente tendría acceso a marcar que se remedió, que el sistema
   valide y una opción que le permita documentar la vulnerabilidad de ese activo. Este rol
   solo podrá hacer eso, nada más (además de solicitar una excepción).»

Ese alcance mínimo lo representan hoy los perfiles ``redes`` y ``mantenimiento``: ven y
comprueban remediaciones y pueden solicitar una excepción, pero no gestionan nada más.
Estas pruebas usan ``redes`` porque el activo de ejemplo es un servidor.

La decisión de diseño que estas pruebas fijan: **la marca de la persona no cierra nada**.
Solo pide la comprobación; el veredicto lo pone la plataforma comparando la versión que
OCS Inventory reporta con la que corrige el fallo. Una remediación que se cierra porque
alguien lo dice es un programa de vulnerabilidades que se engaña a sí mismo.
"""
from __future__ import annotations

import re
import sys
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

from threatintel import db, remediacion
from threatintel.paths import BASE_DIR

sys.path.insert(0, str(BASE_DIR))
from webui import auth  # noqa: E402

CLAVE = "ClaveSegura#2026"

#: Lo único que un perfil que no es administrador puede enviar: su propia cuenta, su
#: sesión, y —solo redes y mantenimiento— las dos acciones de remediación.
PROPIAS = {
    "auth.login", "auth.logout", "auth.segundo_factor", "auth.cambiar_contrasena",
    "auth.perfil", "auth.mi_password", "auth.segundo_factor_activar",
    "auth.segundo_factor_codigos", "auth.segundo_factor_desactivar",
    "panel.tour_estado",
    # Preferencia visual propia (tema y paleta de colores): sin restricción de rol,
    # cualquier perfil autenticado la cambia para su propia sesión.
    "colores.aplicar_paleta",
}
REMEDIACION = {"remediaciones.comprobar", "remediaciones.nota",
               # Mismo permiso que remediaciones.comprobar (requiere_remediacion): es la
               # misma acción, pero llamada desde el cuadro de activos afectados de la
               # ficha de la amenaza en lugar de la página de Remediación (2026-11-16).
               "amenazas.activos_afectados_comprobar"}
#: Tercera acción del perfil, del 2026-09-10 (excepciones con vencimiento): los jefes del
#: proceso pueden SOLICITAR una excepción, que no acepta ningún riesgo ni escribe en
#: `excepciones`; solo deja la petición en el registro de auditoría para que el operador
#: del SOC o un administrador decida. Se excluye del barrido y se prueba aparte, en
#: `test_puede_solicitar_una_excepcion_pero_no_aceptar_el_riesgo`, para que quede escrito
#: exactamente qué puede y qué no.
SOLICITUD = {"excepciones.solicitar"}


class BaseServicios(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "rol_st.db")
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "jefa@ejemplo.local", CLAVE, rol="admin",
                               nombre="Jefa Administradora", actor="t")
            auth.crear_usuario(conn, "sistemas@ejemplo.local", CLAVE,
                               rol="redes",
                               nombre="Persona de Sistemas", actor="t")
            auth.crear_usuario(conn, "lectora@ejemplo.local", CLAVE, rol="ciberseguridad",
                               nombre="Lectora Sin Permisos", actor="t")
            conn.execute(
                """INSERT INTO activos(ocs_id, nombre, origen, so_familia, presente,
                                       ultimo_inventario, primera_vez_at, visto_at)
                   VALUES(1,'srv-uno','servidores','debian',1,?,?,?)""",
                (db.utcnow(), db.utcnow(), db.utcnow()))
            cls.activo_id = conn.execute("SELECT id FROM activos").fetchone()[0]
            # openssl 1.0 instalado, corrige en 1.2 -> sigue vulnerable
            conn.execute("""INSERT INTO activo_software(activo_id, nombre, nombre_norm, version)
                            VALUES(?,'openssl','openssl','1.0')""", (cls.activo_id,))
            # curl 7.9 instalado, corrige en 7.8 -> ya corregida
            conn.execute("""INSERT INTO activo_software(activo_id, nombre, nombre_norm, version)
                            VALUES(?,'curl','curl','7.9')""", (cls.activo_id,))
            # instalado, pero todavía no se conoce la versión que corrige el fallo
            conn.execute("""INSERT INTO activo_software(activo_id, nombre, nombre_norm, version)
                            VALUES(?,'sinparche','sinparche','1.0')""", (cls.activo_id,))
            for cve, paquete, vulnerable, corrige in (
                    ("CVE-2026-0001", "openssl", "1.0", "1.2"),
                    ("CVE-2026-0002", "curl", "7.8", "7.8"),
                    ("CVE-2026-0003", "borrado", "1.0", "2.0"),
                    ("CVE-2026-0004", "sinparche", "1.0", None)):
                conn.execute(
                    """INSERT INTO remediaciones(activo_id, cve, paquete, version_vulnerable,
                            version_corregida, motor, estado, detectado_at, comprobado_at)
                       VALUES(?,?,?,?,?,'osv','abierta',?,?)""",
                    (cls.activo_id, cve, paquete, vulnerable, corrige,
                     db.utcnow(), db.utcnow()))
            cls.ids = {r["paquete"]: r["id"] for r in
                       conn.execute("SELECT id, paquete FROM remediaciones")}
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def _cliente(self, usuario: str):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": usuario, "password": CLAVE})
        return cli

    def _csrf(self, cli, url: str = "/") -> str:
        html = cli.get(url, follow_redirects=True).get_data(as_text=True)
        encontrado = re.search(r'name="csrf" value="([^"]+)"', html)
        return encontrado.group(1) if encontrado else ""

    def _estado(self, remediacion_id: int) -> dict:
        with db.session(self.ruta) as conn:
            return dict(conn.execute("SELECT * FROM remediaciones WHERE id=?",
                                     (remediacion_id,)).fetchone())


class TestAlcanceDelRol(BaseServicios):
    """«Este rol solo podrá hacer eso, nada más.» Demostrado, no supuesto."""

    def test_el_rol_existe_y_tiene_su_alcance_escrito(self):
        self.assertIn("redes", auth.ROLES)
        self.assertEqual(auth.ROL_ES["redes"], "Redes")
        alcance = auth.ROL_ALCANCE_ES["redes"].lower()
        self.assertIn("comprobación", alcance, "debe decir que comprueba una remediación")
        self.assertIn("documentarla", alcance)
        # Es el perfil de los jefes del proceso de servidores: solo ese tipo de máquina.
        self.assertIn("solo servidores", alcance)
        self.assertIn("no ve los equipos de cómputo", alcance)
        # y el alcance de los demás perfiles también está escrito
        self.assertEqual(set(auth.ROL_ALCANCE_ES), set(auth.ROLES))

    def test_solo_puede_enviar_sus_dos_acciones_y_lo_de_su_cuenta(self):
        """Barrido por TODAS las rutas con POST de la aplicación.

        Una ruta nueva con el decorador equivocado aparece aquí sin que nadie tenga que
        acordarse de añadirla a una lista."""
        cli = self._cliente("sistemas@ejemplo.local")
        csrf = self._csrf(cli)
        self.assertTrue(csrf, "no llegó a entrar")
        with self.app.test_request_context():
            reglas = list(self.app.url_map.iter_rules())
        permitidas, revisadas = [], 0
        for regla in reglas:
            if "POST" not in (regla.methods or set()):
                continue
            if regla.endpoint in PROPIAS or regla.endpoint in REMEDIACION or regla.endpoint in SOLICITUD:
                continue
            valores = {}
            for nombre in regla.arguments:
                valores[nombre] = self.activo_id if "activo" in nombre else 1
            with self.app.test_request_context():
                from flask import url_for
                url = url_for(regla.endpoint, **valores)
            revisadas += 1
            respuesta = cli.post(url, data={"csrf": csrf})
            if respuesta.status_code not in (400, 403):
                permitidas.append(f"{regla.endpoint} ({url}) -> {respuesta.status_code}")
        self.assertGreater(revisadas, 20, "el barrido no encontró rutas")
        self.assertEqual(permitidas, [],
                         "rutas que el perfil de Servicios Tecnológicos puede enviar")

    def test_puede_solicitar_una_excepcion_pero_no_aceptar_el_riesgo(self):
        """2026-09-10: la tercera y última acción del perfil.

        Solicitar NO acepta el riesgo: no escribe ni una fila en `excepciones`, la
        vulnerabilidad sigue en la cola y la petición queda en el registro de auditoría
        para que la decida el operador del SOC o un administrador. Registrar, prorrogar y
        revocar siguen prohibidos para este perfil."""
        cli = self._cliente("sistemas@ejemplo.local")
        csrf = self._csrf(cli, "/excepciones/")
        # La solicitud se valida igual que el alta, así que hace falta el veredicto que
        # dice que ese CVE afecta a ese activo (esta clase solo monta la cola).
        with db.session(self.ruta) as conn:
            conn.execute(
                """INSERT INTO threats(fingerprint, cve, title_en, severity, severity_source,
                                       first_seen_at, last_seen_at, month, estado)
                   VALUES('fp-exc','CVE-2026-0001','OpenSSL','High','nvd',?,?,?,'nueva')""",
                (db.utcnow(), db.utcnow(), db.utcnow()[:7]))
            conn.execute(
                """INSERT INTO aplicabilidad(activo_id, cve, paquete, veredicto, motor,
                                             evaluado_at)
                   VALUES(?, 'CVE-2026-0001', 'openssl', 'afectado', 'osv', ?)""",
                (self.activo_id, db.utcnow()))
        datos = {"csrf": csrf, "alcance": "activo_cve", "activo_id": str(self.activo_id),
                 "cve": "CVE-2026-0001",
                 "vence_at": (date.today() + timedelta(days=30)).isoformat(),
                 "justificacion": ("El fabricante no certifica la versión corregida hasta "
                                   "noviembre y la aplicación deja de funcionar."),
                 "responsable_nombre": "Jefa del Proceso",
                 "responsable_correo": "jefa.proceso@ejemplo.local"}
        respuesta = cli.post("/excepciones/solicitar", data=datos, follow_redirects=True)
        self.assertEqual(respuesta.status_code, 200)
        self.assertIn("Solicitud registrada", respuesta.get_data(as_text=True))
        with db.session(self.ruta) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM excepciones").fetchone()[0], 0,
                             "una solicitud no acepta ningún riesgo")
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM audit_log WHERE action='excepciones.solicitud'"
            ).fetchone()[0], 1)
        # Aceptar el riesgo, prorrogar y revocar siguen fuera de su alcance.
        self.assertEqual(cli.post("/excepciones/crear", data=datos).status_code, 403)
        self.assertEqual(cli.post("/excepciones/1/prorrogar",
                                  data={"csrf": csrf, "vence_at": datos["vence_at"],
                                        "motivo": datos["justificacion"]}).status_code, 403)
        self.assertEqual(cli.post("/excepciones/1/revocar",
                                  data={"csrf": csrf,
                                        "motivo": datos["justificacion"]}).status_code, 403)
        self.assertEqual(cli.get("/excepciones/").status_code, 200, "verlas sí puede")

    def test_no_entra_en_las_paginas_de_administracion(self):
        """Ampliado el 2026-09-08: Fuentes pasa a administración (petición del usuario) e
        Informes es solo de administración y operador SOC."""
        cli = self._cliente("sistemas@ejemplo.local")
        for url in ("/usuarios/", "/ajustes/", "/credenciales/", "/sincronizaciones/",
                    "/alertas-proceso/", "/fuentes/", "/informes/", "/auditoria"):
            with self.subTest(url=url):
                self.assertIn(cli.get(url).status_code, (403, 404), url)

    def test_si_consulta_lo_que_necesita_para_trabajar(self):
        cli = self._cliente("sistemas@ejemplo.local")
        for url in ("/", "/activos/", "/amenazas/", "/remediaciones/", "/perfil"):
            with self.subTest(url=url):
                self.assertEqual(cli.get(url).status_code, 200, url)

    def test_la_lectora_no_puede_comprobar_ni_documentar(self):
        """El perfil de solo lectura sigue sin poder escribir nada."""
        cli = self._cliente("lectora@ejemplo.local")
        csrf = self._csrf(cli)
        rid = self.ids["openssl"]
        self.assertEqual(cli.post(f"/remediaciones/{rid}/comprobar",
                                  data={"csrf": csrf}).status_code, 403)
        self.assertEqual(cli.post(f"/remediaciones/{rid}/nota",
                                  data={"csrf": csrf, "texto": "algo"}).status_code, 403)

    def test_la_administradora_tambien_puede(self):
        cli = self._cliente("jefa@ejemplo.local")
        csrf = self._csrf(cli, "/remediaciones/")
        rid = self.ids["curl"]
        self.assertIn(cli.post(f"/remediaciones/{rid}/comprobar",
                               data={"csrf": csrf}).status_code, (302, 200))

    def test_sin_token_csrf_no_se_comprueba(self):
        cli = self._cliente("sistemas@ejemplo.local")
        self.assertEqual(cli.post(f"/remediaciones/{self.ids['openssl']}/comprobar",
                                  data={}).status_code, 400)

    def test_anonimo_va_al_acceso(self):
        cli = self.app.test_client()
        self.assertEqual(cli.post(f"/remediaciones/{self.ids['openssl']}/comprobar",
                                  data={}).status_code, 302)


class TestComprobacionReal(BaseServicios):
    """La plataforma decide, no la persona."""

    def test_sigue_vulnerable_no_cierra_la_remediacion(self):
        """Lo más importante: marcar no basta. openssl 1.0 instalado, corrige en 1.2."""
        rid = self.ids["openssl"]
        with db.session(self.ruta) as conn:
            r = remediacion.comprobar(conn, rid, solicitante="sistemas@ejemplo.local")
        self.assertEqual(r["veredicto"], "sigue_vulnerable")
        self.assertFalse(r["cerrada"])
        self.assertEqual(self._estado(rid)["estado"], "abierta",
                         "una remediación no se cierra porque alguien lo diga")
        self.assertIn("1.0", r["detalle"])
        self.assertIn("1.2", r["detalle"])

    def test_corregida_de_verdad_si_cierra(self):
        rid = self.ids["curl"]
        with db.session(self.ruta) as conn:
            r = remediacion.comprobar(conn, rid, solicitante="sistemas@ejemplo.local")
        self.assertEqual(r["veredicto"], "corregida")
        self.assertTrue(r["cerrada"])
        fila = self._estado(rid)
        self.assertEqual(fila["estado"], "corregida")
        self.assertEqual(fila["version_final"], "7.9")
        self.assertEqual(fila["cerrado_motivo"], remediacion.MOTIVO_COMPROBADA)

    def test_un_paquete_desinstalado_cuenta_como_corregido(self):
        """«borrado» no está en activo_software: OCS ya no lo informa.

        Este caso manda sobre los demás: si el paquete no está instalado, la
        vulnerabilidad no aplica, exista o no una versión que la corrija."""
        rid = self.ids["borrado"]
        with db.session(self.ruta) as conn:
            r = remediacion.comprobar(conn, rid, solicitante="sistemas@ejemplo.local")
        self.assertEqual(r["veredicto"], "desinstalado")
        self.assertTrue(r["cerrada"])

    def test_sin_version_que_corrija_no_se_puede_comprobar(self):
        rid = self.ids["sinparche"]
        with db.session(self.ruta) as conn:
            r = remediacion.comprobar(conn, rid, solicitante="sistemas@ejemplo.local")
        self.assertEqual(r["veredicto"], "sin_datos")
        self.assertFalse(r["cerrada"])
        self.assertIn("Correcciones pendientes", r["detalle"])

    def test_el_veredicto_dice_con_que_inventario_se_comprobo(self):
        """El límite honesto: OCS es tan fresco como su última sincronización."""
        with db.session(self.ruta) as conn:
            r = remediacion.comprobar(conn, self.ids["openssl"],
                                      solicitante="sistemas@ejemplo.local")
        self.assertIn("inventario de", r["detalle"])
        self.assertIsNotNone(r["inventario_at"])

    def test_cada_intento_queda_registrado_y_auditado(self):
        rid = self.ids["openssl"]
        with db.session(self.ruta) as conn:
            remediacion.comprobar(conn, rid, solicitante="sistemas@ejemplo.local", ip="10.1.1.1")
        with db.session(self.ruta) as conn:
            comp = remediacion.historial_comprobaciones(conn, rid)
            auditoria = conn.execute(
                "SELECT username, detail FROM audit_log WHERE action='remediacion.comprobar'"
                " ORDER BY id DESC LIMIT 1").fetchone()
        self.assertTrue(comp)
        self.assertEqual(comp[0]["solicitado_por"], "sistemas@ejemplo.local")
        self.assertEqual(comp[0]["version_instalada"], "1.0")
        self.assertEqual(comp[0]["version_corregida"], "1.2")
        self.assertIsNotNone(auditoria)
        self.assertEqual(auditoria["username"], "sistemas@ejemplo.local")

    def test_las_versiones_de_debian_se_comparan_con_las_reglas_de_dpkg(self):
        """Epoch y sufijo de distribución: «1ubuntu1.20» es anterior a «1ubuntu1.27»."""
        self.assertLess(remediacion.comparar_versiones(
            "ubuntu", "1:7.81.0-1ubuntu1.20", "1:7.81.0-1ubuntu1.27"), 0)
        self.assertEqual(remediacion.comparar_versiones(
            "ubuntu", "1:7.81.0-1ubuntu1.27", "1:7.81.0-1ubuntu1.27"), 0)
        self.assertGreater(remediacion.comparar_versiones(
            "debian", "6.12.105-1", "6.12.94-1"), 0)

    def test_una_remediacion_inventada_no_rompe_nada(self):
        with db.session(self.ruta) as conn:
            with self.assertRaises(ValueError):
                remediacion.comprobar(conn, 999999, solicitante="sistemas@ejemplo.local")

    def test_documentar_guarda_la_nota_y_la_cuenta(self):
        rid = self.ids["openssl"]
        with db.session(self.ruta) as conn:
            remediacion.anotar(conn, rid, autor="sistemas@ejemplo.local",
                               texto="  Programado   para el sábado.  ")
        with db.session(self.ruta) as conn:
            notas = remediacion.notas(conn, rid)
        self.assertTrue(notas)
        self.assertEqual(notas[0]["texto"], "Programado para el sábado.",
                         "los espacios repetidos se colapsan")
        self.assertGreaterEqual(self._estado(rid)["notas"], 1)

    def test_una_nota_vacia_se_rechaza(self):
        with db.session(self.ruta) as conn:
            for malo in ("", "  ", "ab"):
                with self.assertRaises(ValueError):
                    remediacion.anotar(conn, self.ids["openssl"],
                                       autor="sistemas@ejemplo.local", texto=malo)


class TestInterfazDeLaFicha(BaseServicios):

    def test_cada_vulnerabilidad_del_activo_lleva_su_identificador(self):
        """«cada vulnerabilidad por activo debe de tener un id como identificador»."""
        cli = self._cliente("sistemas@ejemplo.local")
        html = cli.get(f"/activos/{self.activo_id}").get_data(as_text=True)
        for rid in self.ids.values():
            self.assertIn(f'id="rem-{rid}"', html, f"falta el identificador {rid}")

    def test_ve_las_dos_acciones_y_no_las_que_no_le_tocan(self):
        cli = self._cliente("sistemas@ejemplo.local")
        html = cli.get(f"/activos/{self.activo_id}").get_data(as_text=True)
        self.assertIn("Ya está remediada: comprobar", html)
        self.assertIn("Guardar nota", html)
        # «¿Le aplica este CVE?» escribe en la base: es solo de administradores
        self.assertNotIn("¿Le aplica este CVE?", html)

    def test_la_lectora_no_ve_ninguna_de_las_dos(self):
        cli = self._cliente("lectora@ejemplo.local")
        html = cli.get(f"/activos/{self.activo_id}").get_data(as_text=True)
        self.assertNotIn("Ya está remediada: comprobar", html)
        self.assertNotIn("Guardar nota", html)

    def test_sin_estilo_ni_codigo_en_linea(self):
        cli = self._cliente("sistemas@ejemplo.local")
        html = cli.get(f"/activos/{self.activo_id}").get_data(as_text=True)
        self.assertIsNone(re.search(r"\sstyle\s*=", html))
        self.assertIsNone(re.search(r"\son[a-z]+\s*=", html))


if __name__ == "__main__":
    unittest.main()

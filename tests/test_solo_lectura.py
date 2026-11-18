"""Control de acceso de quien NO administra la plataforma (petición del usuario del
2026-09-07: «hay usuarios de solo lectura que pueden editar cosas»; roles unificados a
cuatro perfiles el 2026-09-15: admin, ciberseguridad, redes, mantenimiento).

Se encontraron tres rutas que escribían en la base y llevaban `@requiere_login` en vez de
`@requiere_admin` (A01:2025, control de acceso roto):

* `POST /tecnologias/<id>/version` — escribía `technologies.version_installed`, y de esa
  versión depende el veredicto de aplicabilidad de todo el parque. El hueco más serio.
* `POST /activos/<id>/aplica` — parece una consulta («¿Le aplica este CVE?»), pero llama a
  `aplicabilidad.responder_cve`, que evalúa la amenaza y escribe la fila de `aplicabilidad`.
  Es administración u operación (``auth.requiere_operacion``: admin o ciberseguridad), no
  de cualquiera.
* `POST /fuentes/<id>/probar` — no guarda amenazas, pero hace que el servidor salga a
  Internet contra la fuente y deja constancia en la auditoría. Es solo de administración.

Desde que ciberseguridad pasó a ser un perfil operativo con permisos reales (evalúa CVE,
cambia el estado de una amenaza, gestiona excepciones: ``auth.ROLES_OPERACION``), ya no
existe un rol que no escriba absolutamente nada. La prueba principal recorre el mapa de
rutas de la aplicación y exige que cada ruta que acepta POST rechace a ``ciberseguridad``,
salvo la lista corta de acciones sobre su propia cuenta y las que están dentro de su
ámbito operativo real. Así, una ruta nueva que alguien añada mañana con el decorador
equivocado hace fallar la suite.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from threatintel import db
from threatintel.paths import BASE_DIR

sys.path.insert(0, str(BASE_DIR))
from webui import auth  # noqa: E402

CLAVE = "ClaveSegura#2026"

#: Lo único que cualquier perfil autenticado puede enviar sobre su propia cuenta y
#: sesión. Cualquier otra ruta con POST tiene que rechazar a quien no administra.
PROPIAS = {
    "auth.login", "auth.logout", "auth.segundo_factor", "auth.cambiar_contrasena",
    "auth.perfil", "auth.mi_password", "auth.segundo_factor_activar",
    "auth.segundo_factor_codigos", "auth.segundo_factor_desactivar",
    # Respuesta a la invitación del recorrido guiado: es una preferencia de la persona,
    # se guarda en su propia ficha y no toca ningún dato de la organización.
    "panel.tour_estado",
    # Preferencia visual propia (tema y paleta de colores): sin restricción de rol.
    "colores.aplicar_paleta",
}

#: El ámbito operativo real de «ciberseguridad» (``auth.ROLES_OPERACION`` y
#: ``auth.ROLES_SOLICITUD``): decide el estado de una amenaza, evalúa un CVE contra un
#: activo y participa en el flujo de excepciones. No es administración de la
#: plataforma (usuarios, ajustes, credenciales, fuentes, inventario tecnológico), que
#: sigue siendo exclusiva de ``admin`` y es lo que esta prueba protege de verdad.
OPERACION_CIBERSEGURIDAD = {
    "activos.aplica", "amenazas.cambiar_estado",
    "excepciones.crear", "excepciones.solicitar", "excepciones.prorrogar",
    "excepciones.revocar", "excepciones.convertir_temporal",
}


class TestSoloLectura(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "solo_lectura.db")
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "jefa@ejemplo.local", CLAVE, rol="admin",
                               nombre="Jefa Administradora", actor="t")
            auth.crear_usuario(conn, "lectora@ejemplo.local", CLAVE, rol="ciberseguridad",
                               nombre="Lectora Sin Permisos", actor="t")
            # Datos mínimos para que las rutas con identificador existan
            conn.execute("""INSERT INTO technologies(name, slug, category, criticality,
                                exposure, enabled, created_at, updated_at)
                            VALUES('Curl','curl','biblioteca','high','interna',1,?,?)""",
                         (db.utcnow(), db.utcnow()))
            cls.tec_id = conn.execute("SELECT id FROM technologies WHERE slug='curl'").fetchone()[0]
            conn.execute("""INSERT INTO sources(name, slug, url, kind, category, enabled,
                                                created_at, updated_at)
                            VALUES('Prueba','prueba','https://example.invalid/rss','rss','vendor',1,?,?)""",
                         (db.utcnow(), db.utcnow()))
            cls.fuente_id = conn.execute("SELECT id FROM sources WHERE name='Prueba'").fetchone()[0]
            conn.execute("""INSERT INTO activos(ocs_id, nombre, origen, so_familia, presente,
                                                primera_vez_at, visto_at)
                            VALUES(1,'srv-uno','servidores','ubuntu',1,?,?)""",
                         (db.utcnow(), db.utcnow()))
            cls.activo_id = conn.execute("SELECT id FROM activos WHERE nombre='srv-uno'").fetchone()[0]
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
        import re
        html = cli.get(url, follow_redirects=True).get_data(as_text=True)
        encontrado = re.search(r'name="csrf" value="([^"]+)"', html)
        return encontrado.group(1) if encontrado else ""

    def _valores(self, regla) -> dict:
        """Un valor plausible para cada parte variable de la dirección."""
        valores = {}
        for nombre in regla.arguments:
            if "activo" in nombre:
                valores[nombre] = self.activo_id
            elif "source" in nombre or "fuente" in nombre:
                valores[nombre] = self.fuente_id
            elif "tec" in nombre:
                valores[nombre] = self.tec_id
            else:
                valores[nombre] = 1
        return valores

    # ------------------------------------------------------------------ el barrido
    def test_ninguna_ruta_con_post_acepta_a_un_usuario_de_solo_lectura(self):
        """Recorre TODAS las rutas con POST de la aplicación.

        Se exige 403 (o el 400 del token CSRF, que también es un rechazo) en todas
        menos las de la propia cuenta. Una ruta nueva con el decorador equivocado
        aparece aquí sin que nadie tenga que acordarse de añadirla."""
        lectora = self._cliente("lectora@ejemplo.local")
        csrf = self._csrf(lectora)
        self.assertTrue(csrf, "la lectora no llegó a entrar")

        revisadas, permitidas = 0, []
        with self.app.test_request_context():
            reglas = list(self.app.url_map.iter_rules())
        for regla in reglas:
            if ("POST" not in (regla.methods or set()) or regla.endpoint in PROPIAS
                    or regla.endpoint in OPERACION_CIBERSEGURIDAD):
                continue
            with self.app.test_request_context():
                from flask import url_for
                url = url_for(regla.endpoint, **self._valores(regla))
            revisadas += 1
            respuesta = lectora.post(url, data={"csrf": csrf})
            if respuesta.status_code not in (400, 403):
                permitidas.append(f"{regla.endpoint} ({url}) -> {respuesta.status_code}")
        self.assertGreater(revisadas, 20, "el barrido no encontró rutas: revise el mapa")
        self.assertEqual(permitidas, [],
                         "rutas que un usuario de solo lectura puede enviar")

    # --------------------------------------------- los tres huecos, uno por uno
    def test_no_puede_cambiar_la_version_del_inventario(self):
        lectora = self._cliente("lectora@ejemplo.local")
        antes = self._version()
        r = lectora.post(f"/tecnologias/{self.tec_id}/version",
                         data={"csrf": self._csrf(lectora), "version_installed": "9.9.9"})
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self._version(), antes, "la versión del inventario cambió")

    def test_no_puede_evaluar_un_cve_contra_un_activo(self):
        """Evaluar un CVE es de administración y ciberseguridad (``requiere_operacion``),
        no de cualquiera: el perfil de prueba aquí es «redes», que no está en ese
        conjunto (a diferencia de la «lectora», que SÍ es ciberseguridad y sí puede)."""
        with db.session(self.ruta) as conn:
            auth.crear_usuario(conn, "redes-aplica@ejemplo.local", CLAVE, rol="redes",
                               nombre="Redes", actor="t")
        redes = self._cliente("redes-aplica@ejemplo.local")
        r = redes.post(f"/activos/{self.activo_id}/aplica",
                       data={"csrf": self._csrf(redes), "cve": "CVE-2026-1234"})
        self.assertEqual(r.status_code, 403)
        with db.session(self.ruta) as conn:
            filas = conn.execute("SELECT COUNT(*) FROM aplicabilidad").fetchone()[0]
        self.assertEqual(filas, 0, "se escribió una fila de aplicabilidad")

    def test_no_puede_lanzar_la_prueba_de_una_fuente(self):
        lectora = self._cliente("lectora@ejemplo.local")
        r = lectora.post(f"/fuentes/{self.fuente_id}/probar",
                         data={"csrf": self._csrf(lectora)})
        self.assertEqual(r.status_code, 403)
        # Desde el 2026-09-08 tampoco consulta Fuentes: es una página de administración.
        self.assertEqual(lectora.get("/fuentes/").status_code, 403)

    def test_los_perfiles_nuevos_tampoco_escriben_fuera_de_su_alcance(self):
        """Redes, Mantenimiento y operador SOC (2026-09-08) no son administradores a
        medias: ninguno toca el inventario ni las fuentes. Su alcance completo lo fija
        tests/test_roles_alcance.py; aquí se comprueban las tres rutas que estaban
        abiertas al perfil de consulta."""
        with db.session(self.ruta) as conn:
            for rol in ("redes", "mantenimiento", "ciberseguridad"):
                auth.crear_usuario(conn, f"{rol}@ejemplo.local", CLAVE, rol=rol,
                                   nombre=f"Persona de {rol}", actor="t")
        antes = self._version()
        for rol in ("redes", "mantenimiento", "ciberseguridad"):
            cli = self._cliente(f"{rol}@ejemplo.local")
            csrf = self._csrf(cli)
            for url, datos in (
                    (f"/tecnologias/{self.tec_id}/version", {"version_installed": "9.9.9"}),
                    (f"/fuentes/{self.fuente_id}/probar", {})):
                with self.subTest(rol=rol, url=url):
                    self.assertEqual(cli.post(url, data=dict(datos, csrf=csrf)).status_code, 403, url)
            if rol != "ciberseguridad":
                # Evaluar un CVE contra un activo escribe en «aplicabilidad»: es de
                # administración y operador SOC, no de los perfiles de remediación.
                with self.subTest(rol=rol, url="aplica"):
                    self.assertEqual(cli.post(f"/activos/{self.activo_id}/aplica",
                                              data={"csrf": csrf, "cve": "CVE-2026-1234"}).status_code, 403)
        self.assertEqual(self._version(), antes)

    # --------------------------------------------- la administradora sí puede
    def test_el_perfil_de_servicios_tecnologicos_tampoco_toca_el_inventario(self):
        """El perfil operativo acotado (``redes``/``mantenimiento``) solo comprueba y
        documenta remediaciones: no es un administrador a medias. Su alcance completo lo
        fija tests/test_rol_servicios_tecnologicos.py; aquí se comprueba que no se le
        colara ninguna de las tres rutas que estaban abiertas al perfil de consulta."""
        with db.session(self.ruta) as conn:
            auth.crear_usuario(conn, "sistemas@ejemplo.local", CLAVE,
                               rol="redes", nombre="De Sistemas", actor="t")
        cli = self._cliente("sistemas@ejemplo.local")
        csrf = self._csrf(cli)
        antes = self._version()
        for url, datos in (
                (f"/tecnologias/{self.tec_id}/version", {"version_installed": "9.9.9"}),
                (f"/activos/{self.activo_id}/aplica", {"cve": "CVE-2026-1234"}),
                (f"/fuentes/{self.fuente_id}/probar", {})):
            with self.subTest(url=url):
                r = cli.post(url, data=dict(datos, csrf=csrf))
                self.assertEqual(r.status_code, 403, url)
        self.assertEqual(self._version(), antes)

    def test_la_administradora_si_puede_cambiar_la_version(self):
        """El cierre no debe habérselas quitado a quien sí tiene permiso."""
        jefa = self._cliente("jefa@ejemplo.local")
        r = jefa.post(f"/tecnologias/{self.tec_id}/version",
                      data={"csrf": self._csrf(jefa), "version_installed": "8.5.0"})
        self.assertIn(r.status_code, (302, 200))
        self.assertEqual(self._version(), "8.5.0")

    # --------------------------------------------- la interfaz no ofrece lo que no puede
    def test_la_interfaz_no_ensena_a_la_lectora_lo_que_no_puede_hacer(self):
        """Un botón que devuelve 403 al pulsarlo es un error de interfaz: el perfil de
        consulta no debe verlo. La información sigue estando, como texto."""
        lectora = self._cliente("lectora@ejemplo.local")
        # Se busca la ACCIÓN exacta del formulario, no un trozo de dirección: «/aplica»
        # a secas también casa con el «syft /ruta/aplicacion» del ejemplo de SBOM.
        form_version = f'action="/tecnologias/{self.tec_id}/version"'
        form_aplica = f'action="/activos/{self.activo_id}/aplica"'
        form_probar = f'action="/fuentes/{self.fuente_id}/probar"'

        inventario = lectora.get("/tecnologias/").get_data(as_text=True)
        self.assertNotIn(form_version, inventario, "la lectora ve el formulario de versión")
        self.assertIn("Curl", inventario, "pero sí ve la tecnología")

        # «¿Le aplica este CVE?» sí es del ámbito de ciberseguridad
        # (auth.puede_operar_amenazas, ROLES_OPERACION = admin + ciberseguridad).
        ficha = lectora.get(f"/activos/{self.activo_id}").get_data(as_text=True)
        self.assertIn("¿Le aplica este CVE?", ficha)
        self.assertIn(form_aplica, ficha)
        # Adaptado el 2026-09-09: la ficha ya no lista los veredictos uno a uno (listaba
        # también lo que NO afecta). La lectora sigue viendo lo que hay que actualizar y
        # la constancia de lo que se evaluó, que es lo que necesita para consultar.
        self.assertIn("Actualizaciones pendientes", ficha,
                      "la lectora sí debe ver lo que hay que actualizar")
        self.assertIn("identificadores CVE en este activo", ficha,
                      "y la constancia de que la comprobación se hizo")

        # Adaptado el 2026-09-08: Fuentes pasa a administración a petición del usuario
        # («debe ir en administración para que no todos los roles lo vean»), así que la
        # lectora ya no ve la ficha: recibe 403 y el menú no le ofrece el enlace.
        respuesta_fuente = lectora.get(f"/fuentes/{self.fuente_id}")
        self.assertEqual(respuesta_fuente.status_code, 403)
        fuente = respuesta_fuente.get_data(as_text=True)
        self.assertNotIn("Probar ahora", fuente)
        self.assertNotIn(form_probar, fuente)
        self.assertNotIn("example.invalid", fuente, "el 403 no debe filtrar datos de la fuente")
        self.assertNotIn('href="/fuentes/"', ficha, "el menú de la lectora no enlaza a Fuentes")

        # y la administradora sí los ve
        jefa = self._cliente("jefa@ejemplo.local")
        self.assertIn(form_version, jefa.get("/tecnologias/").get_data(as_text=True))
        ficha_jefa = jefa.get(f"/activos/{self.activo_id}").get_data(as_text=True)
        self.assertIn("¿Le aplica este CVE?", ficha_jefa)
        self.assertIn(form_aplica, ficha_jefa)
        fuente_jefa = jefa.get(f"/fuentes/{self.fuente_id}").get_data(as_text=True)
        self.assertIn("Probar ahora", fuente_jefa)
        self.assertIn(form_probar, fuente_jefa)

    # ------------------------------------------------------------------ ayuda
    def _version(self):
        with db.session(self.ruta) as conn:
            return conn.execute("SELECT version_installed FROM technologies WHERE id=?",
                                (self.tec_id,)).fetchone()[0]


if __name__ == "__main__":
    unittest.main()

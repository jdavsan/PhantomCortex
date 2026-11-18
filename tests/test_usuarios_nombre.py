"""Nombre de la persona y edición completa del usuario (petición del 2026-09-07).

El usuario pidió que la interfaz muestre el nombre de la persona y no el correo, que
en Usuarios se pueda escribir ese nombre y editar el usuario completo (incluida una
contraseña nueva) y que desaparezcan los diálogos del navegador.

Aquí se comprueba lo que depende de webui/vistas/usuarios.py y de la plantilla
webui/templates/usuarios.html:
  * alta con el nombre de la persona y rechazo cuando el campo llega vacío o con
    caracteres que no son de un nombre;
  * edición completa (nombre, perfil, estado y contraseña nueva con repetición) en un
    formulario propio y no en línea, con la política del proyecto, revocación de
    sesiones y must_change;
  * la tabla muestra el nombre como identidad principal, el correo debajo y una nota
    que invita a completar el nombre donde falta;
  * la auditoría guarda el valor anterior y el nuevo, nunca contraseñas;
  * permisos (un lector no puede), token CSRF obligatorio y HTML sin style= ni on*=.

Sin red y con base temporal bajo data/."""
from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path

from threatintel import db
from threatintel.paths import BASE_DIR
from webui import auth

CLAVE_JEFA = "JefaSegura#2026"
CLAVE_OTROS = "OtraSegura#2026"


class TestUsuariosNombre(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "usuarios_nombre.db")
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            uid = auth.crear_usuario(conn, "jefa@ejemplo.local", CLAVE_JEFA, rol="admin", actor="t")
            conn.execute("UPDATE users SET nombre=? WHERE id=?", ("Jimena Torres Castro", uid))
            for correo in ("ana.perez@ejemplo.local", "lector@ejemplo.local",
                           "clave@ejemplo.local", "estado@ejemplo.local"):
                auth.crear_usuario(conn, correo, CLAVE_OTROS, rol="ciberseguridad", actor="t")
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    # ---- utilidades -----------------------------------------------------------------
    def _cliente(self, usuario="jefa@ejemplo.local", clave=CLAVE_JEFA):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": usuario, "password": clave})
        return cli

    def _csrf(self, cli, url="/usuarios/"):
        html = cli.get(url).get_data(as_text=True)
        return re.search(r'name="csrf" value="([^"]+)"', html).group(1)

    def _fila(self, correo):
        with db.session(self.ruta) as conn:
            fila = conn.execute("SELECT * FROM users WHERE username=?", (correo,)).fetchone()
            return dict(fila) if fila else None

    def _detalles(self, accion):
        with db.session(self.ruta) as conn:
            return [r["detail"] or "" for r in conn.execute(
                "SELECT detail FROM audit_log WHERE action=?", (accion,))]

    # ---- alta -----------------------------------------------------------------------
    def test_alta_pide_el_nombre_de_la_persona(self):
        cli = self._cliente()
        csrf = self._csrf(cli)
        html = cli.get("/usuarios/").get_data(as_text=True)
        # Etiqueta visible y campo obligatorio en el formulario de alta
        self.assertIn('<label for="nombre">Nombre y apellidos de la persona', html)
        self.assertRegex(html, r'<input type="text" id="nombre" name="nombre" required maxlength="80"')

        # Sin nombre (campo presente y vacío): se rechaza y no se crea nada
        r = cli.post("/usuarios/crear", data={"csrf": csrf, "nombre": "   ",
                                              "correo": "sinnombre@ejemplo.local", "rol": "ciberseguridad",
                                              "password": "ClaveSegura#2026", "repetir": "ClaveSegura#2026"},
                     follow_redirects=True)
        self.assertIn("Escriba el nombre y apellidos de la persona", r.get_data(as_text=True))
        self.assertIsNone(self._fila("sinnombre@ejemplo.local"))

        # Caracteres que no son de un nombre (marcado, cifras)
        for malo in ("<b>Ana</b>", "Ana 3000", "A"):
            r = cli.post("/usuarios/crear", data={"csrf": csrf, "nombre": malo,
                                                  "correo": "sinnombre@ejemplo.local", "rol": "ciberseguridad",
                                                  "password": "ClaveSegura#2026", "repetir": "ClaveSegura#2026"},
                         follow_redirects=True)
            self.assertIn("Escriba el nombre y apellidos de la persona", r.get_data(as_text=True))
            self.assertIsNone(self._fila("sinnombre@ejemplo.local"))

        # Alta correcta: el nombre se guarda normalizado (espacios colapsados)
        r = cli.post("/usuarios/crear", data={"csrf": csrf, "nombre": "  María  José  Ríos Gómez ",
                                              "correo": "Maria.Rios@ejemplo.local", "rol": "ciberseguridad",
                                              "password": "ClaveSegura#2026", "repetir": "ClaveSegura#2026"},
                     follow_redirects=True)
        html = r.get_data(as_text=True)
        self.assertIn("maria.rios@ejemplo.local creado", html)
        self.assertIn("a nombre de María José Ríos Gómez", html)
        fila = self._fila("maria.rios@ejemplo.local")
        self.assertEqual(fila["nombre"], "María José Ríos Gómez")
        self.assertEqual((fila["role"], fila["must_change"], fila["enabled"]), ("ciberseguridad", 1, 1))
        self.assertTrue(any("nombre=«María José Ríos Gómez»" in d for d in self._detalles("usuario.nombre")))

        # Longitud máxima: 80 caracteres
        largo = "Ana " * 25
        r = cli.post("/usuarios/crear", data={"csrf": csrf, "nombre": largo,
                                              "correo": "larga@ejemplo.local", "rol": "ciberseguridad",
                                              "password": "ClaveSegura#2026", "repetir": "ClaveSegura#2026"},
                     follow_redirects=True)
        self.assertIn("Escriba el nombre y apellidos de la persona", r.get_data(as_text=True))
        self.assertIsNone(self._fila("larga@ejemplo.local"))

    # ---- tabla ----------------------------------------------------------------------
    def test_la_tabla_muestra_el_nombre_y_el_correo_debajo(self):
        cli = self._cliente()
        html = cli.get("/usuarios/").get_data(as_text=True)
        self.assertIn("Persona y correo de acceso</th>", html)
        # Fila con nombre: identidad primero, correo debajo en pequeño y atenuado
        fila = re.search(r"<tr>\s*<td>\s*Jimena Torres Castro.*?</tr>", html, re.S).group(0)
        self.assertIn('<div class="pequeno tenue">jefa@ejemplo.local</div>', fila)
        self.assertIn('<span class="insignia info">usted</span>', fila)
        # Fila sin nombre: se muestra el correo y una nota que invita a completarlo
        sin = re.search(r"<tr>\s*<td>\s*ana\.perez@ejemplo\.local.*?</tr>", html, re.S).group(0)
        self.assertIn("Falta el nombre de la persona", sin)
        self.assertIn('href="/usuarios/?editar=%d#editar-usuario"' % self._fila("ana.perez@ejemplo.local")["id"], sin)
        self.assertIn(">Complételo aquí</a>", sin)
        self.assertNotIn('<div class="pequeno tenue">ana.perez@ejemplo.local</div>', sin,
                         "sin nombre el correo ya es la identidad: no se repite debajo")
        # La métrica cuenta a quien le falta el nombre
        self.assertRegex(html, r"sin nombre de persona")
        # CSP estricta
        self.assertIsNone(re.search(r"\sstyle\s*=", html))
        self.assertIsNone(re.search(r"\son[a-z]+\s*=", html, re.I))

    def test_el_formulario_de_edicion_no_es_en_linea(self):
        cli = self._cliente()
        ana = self._fila("ana.perez@ejemplo.local")["id"]
        # Sin ?editar= no hay formulario de edición; con él, aparece completo
        self.assertNotIn('id="editar-usuario"', cli.get("/usuarios/").get_data(as_text=True))
        html = cli.get(f"/usuarios/?editar={ana}").get_data(as_text=True)
        self.assertIn('<div class="panel" id="editar-usuario">', html)
        self.assertIn(f'action="/usuarios/{ana}/actualizar"', html)
        for etiqueta in ('<label for="editar-nombre">Nombre y apellidos de la persona',
                         '<label for="editar-perfil">Perfil</label>',
                         '<label for="editar-estado">Estado</label>',
                         '<label for="editar-password">Contraseña nueva',
                         '<label for="editar-password-repetir">Repetir la contraseña nueva</label>'):
            self.assertIn(etiqueta, html)
        self.assertIn(">Guardar cambios</button>", html)
        self.assertIn(">Cancelar</a>", html)
        # La propia cuenta: perfil y estado bloqueados y sin campos de contraseña
        jefa = self._fila("jefa@ejemplo.local")["id"]
        propio = cli.get(f"/usuarios/?editar={jefa}").get_data(as_text=True)
        self.assertIn('<select id="editar-perfil" name="rol" disabled>', propio)
        self.assertIn('<select id="editar-estado" name="enabled" disabled>', propio)
        self.assertNotIn('name="password_nueva"', propio)
        self.assertIn("Cambiar mi contraseña", propio)
        # Un identificador que no existe se explica, no revienta
        self.assertIn("El usuario que quería editar ya no existe",
                      cli.get("/usuarios/?editar=99999").get_data(as_text=True))
        self.assertEqual(cli.get("/usuarios/?editar=no-es-numero").status_code, 200)

    # ---- edición ---------------------------------------------------------------------
    def test_edicion_de_nombre_perfil_y_estado(self):
        cli = self._cliente()
        csrf = self._csrf(cli)
        uid = self._fila("estado@ejemplo.local")["id"]
        # Sesión abierta de esa persona: al cambiarle el perfil se cierra
        suya = self._cliente("estado@ejemplo.local", CLAVE_OTROS)
        self.assertEqual(suya.get("/").status_code, 200)
        r = cli.post(f"/usuarios/{uid}/actualizar",
                     data={"csrf": csrf, "nombre": "Pedro Nel Ospina", "rol": "admin", "enabled": "1"},
                     follow_redirects=True)
        html = r.get_data(as_text=True)
        self.assertIn("Nombre de estado@ejemplo.local establecido como «Pedro Nel Ospina»", html)
        self.assertIn("perfil de Pedro Nel Ospina cambiado a Administrador", html)
        self.assertIn("Se han cerrado 1 sesión(es) abierta(s)", html)
        self.assertEqual(suya.get("/").status_code, 302)
        fila = self._fila("estado@ejemplo.local")
        self.assertEqual((fila["nombre"], fila["role"], fila["enabled"]), ("Pedro Nel Ospina", "admin", 1))
        self.assertTrue(any("nombre=«»→«Pedro Nel Ospina»" in d and "rol=ciberseguridad→admin" in d
                            for d in self._detalles("usuario.actualizar")))
        # Cambio de nombre y deshabilitación
        r = cli.post(f"/usuarios/{uid}/actualizar",
                     data={"csrf": csrf, "nombre": "Pedro Nel Ospina Vázquez", "rol": "ciberseguridad", "enabled": "0"},
                     follow_redirects=True)
        html = r.get_data(as_text=True)
        self.assertIn("cambiado de «Pedro Nel Ospina» a «Pedro Nel Ospina Vázquez»", html)
        self.assertIn("usuario Pedro Nel Ospina Vázquez deshabilitado", html)
        fila = self._fila("estado@ejemplo.local")
        self.assertEqual((fila["nombre"], fila["role"], fila["enabled"]), ("Pedro Nel Ospina Vázquez", "ciberseguridad", 0))
        # Sin cambios: lo dice y no toca nada
        r = cli.post(f"/usuarios/{uid}/actualizar",
                     data={"csrf": csrf, "nombre": "Pedro Nel Ospina Vázquez", "rol": "ciberseguridad", "enabled": "0"},
                     follow_redirects=True)
        self.assertIn("Sin cambios: Pedro Nel Ospina Vázquez ya tenía ese nombre, ese perfil y ese estado",
                      r.get_data(as_text=True))
        # El nombre también se valida al editar
        r = cli.post(f"/usuarios/{uid}/actualizar",
                     data={"csrf": csrf, "nombre": "", "rol": "ciberseguridad", "enabled": "0"}, follow_redirects=True)
        self.assertIn("Escriba el nombre y apellidos de la persona", r.get_data(as_text=True))
        self.assertEqual(self._fila("estado@ejemplo.local")["nombre"], "Pedro Nel Ospina Vázquez")
        # Salvaguardas: no puede degradarse ni deshabilitarse a sí misma
        jefa = self._fila("jefa@ejemplo.local")["id"]
        r = cli.post(f"/usuarios/{jefa}/actualizar",
                     data={"csrf": csrf, "nombre": "Jimena Torres Castro", "rol": "ciberseguridad", "enabled": "1"},
                     follow_redirects=True)
        self.assertIn("No puede quitarse a sí mismo el rol de administrador", r.get_data(as_text=True))
        self.assertEqual(self._fila("jefa@ejemplo.local")["role"], "admin")
        # Pero sí puede corregir su propio nombre
        r = cli.post(f"/usuarios/{jefa}/actualizar",
                     data={"csrf": csrf, "nombre": "Jimena Torres Castaño", "rol": "admin", "enabled": "1"},
                     follow_redirects=True)
        self.assertIn("«Jimena Torres Castro» a «Jimena Torres Castaño»", r.get_data(as_text=True))
        with db.session(self.ruta) as conn:
            conn.execute("UPDATE users SET nombre=? WHERE id=?", ("Jimena Torres Castro", jefa))

    def test_contrasena_nueva_con_repeticion_politica_y_revocacion(self):
        cli = self._cliente()
        csrf = self._csrf(cli)
        uid = self._fila("clave@ejemplo.local")["id"]
        datos = {"csrf": csrf, "nombre": "Carlos Andrés Vélez", "rol": "ciberseguridad", "enabled": "1"}
        # Repetición distinta
        r = cli.post(f"/usuarios/{uid}/actualizar",
                     data=dict(datos, password_nueva="ClaveNueva#2026", password_repetir="OtraClave#2026"),
                     follow_redirects=True)
        self.assertIn("Las contraseñas nuevas no coinciden.", r.get_data(as_text=True))
        # Política del proyecto (12 caracteres y tres clases)
        r = cli.post(f"/usuarios/{uid}/actualizar",
                     data=dict(datos, password_nueva="minusculas12", password_repetir="minusculas12"),
                     follow_redirects=True)
        self.assertIn("Contraseña rechazada: Debe combinar al menos tres de", r.get_data(as_text=True))
        r = cli.post(f"/usuarios/{uid}/actualizar",
                     data=dict(datos, password_nueva="Corta#1", password_repetir="Corta#1"),
                     follow_redirects=True)
        self.assertIn("Contraseña rechazada: Debe tener al menos 12 caracteres.", r.get_data(as_text=True))
        # Nada de lo anterior tocó la contraseña ni el nombre
        anterior = self._fila("clave@ejemplo.local")
        self.assertIsNone(anterior["nombre"])
        self.assertTrue(auth.verificar_password(CLAVE_OTROS, anterior["password_hash"]))

        # Contraseña correcta: se guarda, se cierran sus sesiones y debe cambiarla él
        suya = self._cliente("clave@ejemplo.local", CLAVE_OTROS)
        self.assertEqual(suya.get("/").status_code, 200)
        nueva = "ClaveNueva#2026"
        r = cli.post(f"/usuarios/{uid}/actualizar",
                     data=dict(datos, password_nueva=nueva, password_repetir=nueva), follow_redirects=True)
        html = r.get_data(as_text=True)
        self.assertIn("Contraseña nueva guardada", html)
        self.assertIn("Carlos Andrés Vélez deberá cambiarla en su próximo acceso", html)
        self.assertIn("Se han cerrado 1 sesión(es) abierta(s)", html)
        self.assertNotIn(nueva, html, "la contraseña la escribió el administrador: no se repite en pantalla")
        self.assertEqual(suya.get("/").status_code, 302, "sus sesiones se revocan")
        fila = self._fila("clave@ejemplo.local")
        self.assertEqual(fila["nombre"], "Carlos Andrés Vélez")
        self.assertTrue(auth.verificar_password(nueva, fila["password_hash"]))
        self.assertEqual(fila["must_change"], 1)
        # Entra con la nueva y se le exige cambiarla
        entra = self.app.test_client()
        r = entra.post("/login", data={"usuario": "clave@ejemplo.local", "password": nueva})
        self.assertIn("/mi-password", r.headers.get("Location", ""))
        # Auditoría: qué cambió, nunca la contraseña
        with db.session(self.ruta) as conn:
            detalles = [r["detail"] or "" for r in conn.execute("SELECT detail FROM audit_log")]
        self.assertTrue(any("contraseña=cambiada por el administrador" in d for d in detalles))
        for detalle in detalles:
            self.assertNotIn(nueva, detalle)
            self.assertNotIn(CLAVE_OTROS, detalle)
            self.assertNotIn(CLAVE_JEFA, detalle)

    def test_nadie_cambia_su_propia_contrasena_desde_aqui(self):
        """Con solo una sesión robada bastaría; la propia exige la contraseña actual."""
        cli = self._cliente()
        csrf = self._csrf(cli)
        jefa = self._fila("jefa@ejemplo.local")
        r = cli.post(f"/usuarios/{jefa['id']}/actualizar",
                     data={"csrf": csrf, "nombre": "Jimena Torres Castro", "rol": "admin", "enabled": "1",
                           "password_nueva": "OtraClave#2026", "password_repetir": "OtraClave#2026"},
                     follow_redirects=True)
        self.assertIn("No puede cambiar su propia contraseña desde aquí", r.get_data(as_text=True))
        self.assertTrue(auth.verificar_password(CLAVE_JEFA, self._fila("jefa@ejemplo.local")["password_hash"]))
        self.assertEqual(cli.get("/").status_code, 200, "su sesión sigue viva")

    # ---- permisos y CSRF -------------------------------------------------------------
    def test_permisos_y_csrf(self):
        uid = self._fila("ana.perez@ejemplo.local")["id"]
        lector = self._cliente("lector@ejemplo.local", CLAVE_OTROS)
        self.assertIn(lector.get("/usuarios/").status_code, (302, 403))
        csrf_lector = re.search(r'name="csrf" value="([^"]+)"',
                                lector.get("/").get_data(as_text=True)).group(1)
        r = lector.post(f"/usuarios/{uid}/actualizar",
                        data={"csrf": csrf_lector, "nombre": "Intrusa Anónima", "rol": "admin", "enabled": "1"})
        self.assertEqual(r.status_code, 403)
        self.assertIsNone(self._fila("ana.perez@ejemplo.local")["nombre"])
        # Sin token CSRF, ni siquiera un administrador
        cli = self._cliente()
        r = cli.post(f"/usuarios/{uid}/actualizar", data={"nombre": "Ana Pérez", "rol": "ciberseguridad", "enabled": "1"})
        self.assertIn(r.status_code, (400, 403))
        self.assertIsNone(self._fila("ana.perez@ejemplo.local")["nombre"])
        # Y un usuario que no existe no rompe nada
        csrf = self._csrf(cli)
        r = cli.post("/usuarios/99999/actualizar",
                     data={"csrf": csrf, "nombre": "Nadie Nadie", "rol": "ciberseguridad", "enabled": "1"},
                     follow_redirects=True)
        self.assertIn("El usuario no existe.", r.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()

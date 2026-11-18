"""Gestión de usuarios desde la interfaz (2026-09-05): alta con correo como usuario y
política de contraseñas, edición de rol y estado, restablecimiento, desbloqueo y baja,
con las salvaguardas (no eliminarse a sí mismo, al menos un administrador). Solo
administradores. Base temporal bajo data/.

Revisión del 2026-09-05: rol y estado se aplican al cambiar el selector
(data-autosubmit, botón «Guardar» solo en noscript) y el aviso dice qué cambió;
«Desbloquear» reinicia también totp_fallos.

Revisión del 2026-09-06 (hallazgo 7): deshabilitar a un usuario y cambiarle el rol
piden confirmación antes de aplicarse, con data-confirmar en la propia opción."""
from __future__ import annotations

import html as _html
import re
import tempfile
import unittest
from pathlib import Path

from threatintel import db
from threatintel.paths import BASE_DIR
from webui import auth


class TestUsuarios(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "usuarios.db")
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "admin", "AdminSeguro#2026", rol="admin", actor="t")
            auth.crear_usuario(conn, "lector", "LectorSeguro#2026", rol="ciberseguridad", actor="t")
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def _cliente(self, usuario="admin", clave="AdminSeguro#2026"):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": usuario, "password": clave})
        return cli

    def _csrf(self, cli):
        return re.search(r'name="csrf" value="([^"]+)"', cli.get("/usuarios/").get_data(as_text=True)).group(1)

    def _id(self, username):
        with db.session(self.ruta) as conn:
            fila = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
            return fila["id"] if fila else None

    def test_pagina_y_permisos(self):
        cli = self._cliente()
        html = cli.get("/usuarios/").get_data(as_text=True)
        self.assertIn("Usuarios de la interfaz", html)
        self.assertIn("admin", html)
        self.assertIn("Ciberseguridad", html)
        self.assertIsNone(re.search(r"\sstyle\s*=", html))
        self.assertIsNone(re.search(r"\son[a-z]+\s*=", html, re.I))
        # Rol y estado se aplican al cambiar el selector; «Guardar» solo sin JavaScript.
        # Usuario propio de esta prueba (otras pruebas eliminan a «lector»).
        with db.session(self.ruta) as conn:
            if self._id("fila@ejemplo.local") is None:
                auth.crear_usuario(conn, "fila@ejemplo.local", "FilaSegura#2026", rol="ciberseguridad", actor="t")
        fila_id = self._id("fila@ejemplo.local")
        admin_id = self._id("admin")
        html = cli.get("/usuarios/").get_data(as_text=True)
        self.assertRegex(html, rf'<select id="rol-{fila_id}" name="rol"[^>]*\sdata-autosubmit>')
        self.assertRegex(html, rf'<select id="enabled-{fila_id}" name="enabled" form="editar-{fila_id}"[^>]*\sdata-autosubmit>')
        self.assertIn(f'<label for="enabled-{fila_id}" class="oculto-visual">Estado de fila@ejemplo.local</label>', html)
        self.assertIn('<option value="1" selected>Habilitado</option>', html)
        self.assertIn(f'<noscript><button class="btn pequeno" type="submit" form="editar-{fila_id}">Guardar rol y estado</button></noscript>', html)
        self.assertNotIn(">Guardar</button>", html)
        # Hallazgo 7 de la revisión del 2026-09-06: deshabilitar a alguien y cambiarle
        # el rol vuelven a pedir confirmación, sin recuperar el botón «Guardar»: el
        # mensaje va en la propia opción (data-confirmar, atendido por app.js) para que
        # diga exactamente qué va a pasar.
        self.assertIn('<option value="0" data-confirmar="¿Deshabilitar a fila@ejemplo.local? '
                      'Perderá el acceso de inmediato y se cerrarán sus sesiones.">Deshabilitado</option>', html)
        self.assertNotIn('<option value="1" data-confirmar', html)
        # El mensaje lleva el alcance real del perfil, que vive en webui.auth: así la
        # confirmación no puede decir algo distinto de lo que aplica el servidor
        # (2026-09-07, al añadir el perfil de Servicios Tecnológicos).
        from webui import auth as _auth
        for rol in _auth.ROLES:
            with self.subTest(rol=rol):
                self.assertRegex(
                    html,
                    r'<option value="' + rol + r'"[^>]* data-confirmar="¿Cambiar el perfil de '
                    r'fila@ejemplo\.local a ' + re.escape(_auth.ROL_ES[rol]) + r'\? '
                    + re.escape(_auth.ROL_ALCANCE_ES[rol])
                    + r' Se cerrarán sus sesiones abiertas\.">'
                    + re.escape(_auth.ROL_ES[rol]) + r'</option>')
        app_js = (BASE_DIR / "webui" / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn("data-confirmar", app_js, "la confirmación vive en app.js, no en la plantilla")
        self.assertIn("stopImmediatePropagation", app_js, "al cancelar no se envía el formulario")
        # La fila propia va deshabilitada y sin botón de guardar
        self.assertRegex(html, rf'<select id="rol-{admin_id}" name="rol"[^>]*\sdata-autosubmit disabled>')
        self.assertNotIn(f'form="editar-{admin_id}">Guardar', html)
        self.assertEqual(html.count("Guardar rol y estado"),
                         len(re.findall(r'<select id="rol-\d+" name="rol"(?![^>]*disabled)', html)),
                         "un botón noscript por cada fila editable, ninguno en la propia")
        lector = self._cliente("lector", "LectorSeguro#2026")
        self.assertIn(lector.get("/usuarios/").status_code, (302, 403))
        self.assertNotIn("Usuarios</span>", lector.get("/").get_data(as_text=True))
        self.assertIn("Usuarios</span>", cli.get("/").get_data(as_text=True))

    def test_crear_con_correo_y_politica(self):
        cli = self._cliente()
        csrf = self._csrf(cli)
        r = cli.post("/usuarios/crear", data={"csrf": csrf, "nombre": "Ana Pérez Gómez", "correo": "no-es-correo", "rol": "ciberseguridad",
                                              "password": "ClaveSegura#2026", "repetir": "ClaveSegura#2026"}, follow_redirects=True)
        self.assertIn("correo electrónico válido", r.get_data(as_text=True))
        r = cli.post("/usuarios/crear", data={"csrf": csrf, "nombre": "Ana Pérez Gómez", "correo": "Ana.Perez@ejemplo.local", "rol": "ciberseguridad",
                                              "password": "corta", "repetir": "corta"}, follow_redirects=True)
        self.assertIn("Contraseña rechazada", r.get_data(as_text=True))
        r = cli.post("/usuarios/crear", data={"csrf": csrf, "nombre": "Ana Pérez Gómez", "correo": "Ana.Perez@ejemplo.local", "rol": "ciberseguridad",
                                              "password": "ClaveSegura#2026", "repetir": "Otra#Clave2026xx"}, follow_redirects=True)
        self.assertIn("no coinciden", r.get_data(as_text=True))
        r = cli.post("/usuarios/crear", data={"csrf": csrf, "nombre": "Ana Pérez Gómez", "correo": "Ana.Perez@ejemplo.local", "rol": "ciberseguridad",
                                              "password": "ClaveSegura#2026", "repetir": "ClaveSegura#2026"}, follow_redirects=True)
        self.assertIn("ana.perez@ejemplo.local creado", r.get_data(as_text=True))
        with db.session(self.ruta) as conn:
            fila = conn.execute("SELECT role, must_change, enabled FROM users WHERE username='ana.perez@ejemplo.local'").fetchone()
            self.assertEqual((fila["role"], fila["must_change"], fila["enabled"]), ("ciberseguridad", 1, 1))
            self.assertIsNotNone(conn.execute("SELECT 1 FROM audit_log WHERE action='usuario.crear' AND detail LIKE '%ana.perez%'").fetchone())
        # duplicado
        r = cli.post("/usuarios/crear", data={"csrf": csrf, "nombre": "Ana Pérez Gómez", "correo": "ana.perez@ejemplo.local", "rol": "ciberseguridad",
                                              "password": "ClaveSegura#2026", "repetir": "ClaveSegura#2026"}, follow_redirects=True)
        self.assertIn("ya existe", r.get_data(as_text=True))
        # generada
        r = cli.post("/usuarios/crear", data={"csrf": csrf, "nombre": "Ana Pérez Gómez", "correo": "luis@ejemplo.local", "rol": "admin", "generar": "1"},
                     follow_redirects=True)
        html = r.get_data(as_text=True)
        # La contraseña va en un panel propio que se muestra UNA sola vez (2026-09-08), no en
        # el aviso: el usuario no la veía allí.
        self.assertIn('id="credencial-una-vez"', html)
        self.assertIn("Se muestra una sola vez", html)
        generada = _html.unescape(re.search(r'id="credencial-valor"[^>]*value="([^"]+)"', html).group(1))
        self.assertTrue(auth.fuerza_password(generada)[0])
        self.assertNotIn(generada, re.sub(r'value="[^"]*"', "", html), "solo aparece en el campo")
        # al recargar, ya no está
        otra = cli.get("/usuarios/").get_data(as_text=True)
        self.assertNotIn('id="credencial-una-vez"', otra)
        self.assertNotIn(generada, otra)
        # el usuario nuevo entra y debe cambiar la contraseña
        nuevo = self.app.test_client()
        r = nuevo.post("/login", data={"usuario": "luis@ejemplo.local", "password": generada})
        self.assertIn("/mi-password", r.headers.get("Location", ""))

    def test_editar_restablecer_desbloquear_eliminar(self):
        cli = self._cliente()
        csrf = self._csrf(cli)
        lector_id = self._id("lector")
        admin_id = self._id("admin")
        # no puede degradarse ni deshabilitarse a sí mismo
        r = cli.post(f"/usuarios/{admin_id}/editar", data={"csrf": csrf, "rol": "ciberseguridad", "enabled": "1"}, follow_redirects=True)
        self.assertIn("No puede quitarse a sí mismo", r.get_data(as_text=True))
        r = cli.post(f"/usuarios/{admin_id}/eliminar", data={"csrf": csrf}, follow_redirects=True)
        self.assertIn("No puede eliminar su propia cuenta", r.get_data(as_text=True))
        # promover al lector y deshabilitarlo: sus sesiones se cierran
        lector = self._cliente("lector", "LectorSeguro#2026")
        self.assertEqual(lector.get("/").status_code, 200)
        r = cli.post(f"/usuarios/{lector_id}/editar", data={"csrf": csrf, "rol": "admin"}, follow_redirects=True)
        html = r.get_data(as_text=True)
        # El aviso dice exactamente qué cambió (no hay botón «Guardar»: es la única confirmación)
        self.assertIn("Rol de lector cambiado a Administrador; usuario lector deshabilitado.", html)
        self.assertIn("Se han cerrado 1 sesión(es) abierta(s)", html)
        self.assertNotIn("Usuario actualizado", html)
        self.assertEqual(lector.get("/").status_code, 302)          # sesión revocada al cambiar de rol
        with db.session(self.ruta) as conn:
            self.assertEqual(conn.execute("SELECT role, enabled FROM users WHERE id=?", (lector_id,)).fetchone()[0:2], ("admin", 0))
        r = cli.post(f"/usuarios/{lector_id}/editar", data={"csrf": csrf, "rol": "admin", "enabled": "1"}, follow_redirects=True)
        self.assertIn("Usuario lector habilitado.", r.get_data(as_text=True))
        r = cli.post(f"/usuarios/{lector_id}/editar", data={"csrf": csrf, "rol": "admin", "enabled": "1"}, follow_redirects=True)
        self.assertIn("Sin cambios: lector ya tenía ese rol y ese estado.", r.get_data(as_text=True))
        r = cli.post(f"/usuarios/{lector_id}/editar", data={"csrf": csrf, "rol": "ciberseguridad", "enabled": "1"}, follow_redirects=True)
        self.assertIn("Rol de lector cambiado a Ciberseguridad", r.get_data(as_text=True))
        # restablecer contraseña: nueva generada y must_change
        r = cli.post(f"/usuarios/{lector_id}/password", data={"csrf": csrf}, follow_redirects=True)
        html = r.get_data(as_text=True)
        self.assertIn("Contraseña nueva de lector", html)
        nueva = _html.unescape(re.search(r'id="credencial-valor"[^>]*value="([^"]+)"', html).group(1))
        self.assertNotIn('id="credencial-una-vez"', cli.get("/usuarios/").get_data(as_text=True))
        with db.session(self.ruta) as conn:
            fila = conn.execute("SELECT password_hash, must_change FROM users WHERE id=?", (lector_id,)).fetchone()
            self.assertTrue(auth.verificar_password(nueva, fila["password_hash"]))
            self.assertEqual(fila["must_change"], 1)
            conn.execute("UPDATE users SET failed_logins=5, totp_fallos=3, locked_until='2099-01-01T00:00:00Z' WHERE id=?", (lector_id,))
        r = cli.post(f"/usuarios/{lector_id}/desbloquear", data={"csrf": csrf}, follow_redirects=True)
        self.assertIn("desbloqueada", r.get_data(as_text=True))
        with db.session(self.ruta) as conn:
            fila = conn.execute("SELECT locked_until, failed_logins, totp_fallos FROM users WHERE id=?", (lector_id,)).fetchone()
            self.assertIsNone(fila["locked_until"])
            self.assertEqual((fila["failed_logins"], fila["totp_fallos"]), (0, 0), "también los fallos del segundo factor")
        # eliminar
        r = cli.post(f"/usuarios/{lector_id}/eliminar", data={"csrf": csrf}, follow_redirects=True)
        self.assertIn("eliminado", r.get_data(as_text=True))
        self.assertIsNone(self._id("lector"))
        # CSRF obligatorio
        r = cli.post("/usuarios/crear", data={"nombre": "Ana Pérez Gómez", "correo": "x@y.com", "rol": "ciberseguridad", "generar": "1"})
        self.assertIn(r.status_code, (400, 403))


if __name__ == "__main__":
    unittest.main()

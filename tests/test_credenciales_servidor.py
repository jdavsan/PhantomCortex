"""Editar el servidor SMTP (servidor, puerto, usuario, cifrado, remitente) desde
/credenciales/, sin entrar a config/credentials.env a mano.

Petición del usuario (2026-11-17), tras pedir pasarse a Gmail: «la estoy viendo en el
apartado de credenciales de la interfaz web así que eso se tiene que editar». Antes esos
campos solo se LEÍAN en esa pantalla; la contraseña ya tenía su formulario, el resto no.

Ninguna prueba escribe en config/credentials.env de verdad: `config.update_secret` se
sustituye por un registrador, igual que en TestClaveNvd (tests/test_regresiones.py).

Ejecución:
    sudo -n -u si .venv/bin/python -m unittest tests.test_credenciales_servidor
"""
from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path

from threatintel import db
from threatintel.paths import BASE_DIR

sys.path.insert(0, str(BASE_DIR))
from webui import auth  # noqa: E402

CLAVE = "ClaveSegura#2026"


class TestServidorSmtp(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "credenciales.db")
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "admin@ejemplo.local", CLAVE, rol="admin", actor="t")
            if "redes" in auth.ROLES:
                auth.crear_usuario(conn, "redes@ejemplo.local", CLAVE, rol="redes", actor="t")
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def setUp(self):
        from threatintel import config as _config
        self._config = _config
        self._update_secret = _config.update_secret
        self.escritos: list[tuple[str, str]] = []
        _config.update_secret = lambda k, v, **kw: self.escritos.append((k, v))

    def tearDown(self):
        self._config.update_secret = self._update_secret

    def _admin(self):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": "admin@ejemplo.local", "password": CLAVE})
        return cli

    def _csrf(self, cli):
        html = cli.get("/credenciales/").get_data(as_text=True)
        return re.search(r'name="csrf" value="([^"]+)"', html).group(1)

    def _formulario_valido(self, **cambios):
        datos = {
            "servidor": "smtp.gmail.com", "puerto": "587", "usuario_smtp": "alguien@gmail.com",
            "cifrado": "tls", "remitente": "alguien@gmail.com", "remitente_nombre": "Alertas",
        }
        datos.update(cambios)
        return datos

    # ---------------------------------------------------------- lectura
    def test_el_panel_muestra_los_campos_editables_con_el_valor_actual(self):
        html = self._admin().get("/credenciales/").get_data(as_text=True)
        self.assertIn('name="servidor"', html)
        self.assertIn('name="puerto"', html)
        self.assertIn('name="usuario_smtp"', html)
        self.assertIn('name="cifrado"', html)
        self.assertIn('name="remitente"', html)
        self.assertIn(f'action="/credenciales/servidor"', html)

    # ---------------------------------------------------------- permisos
    def test_sin_sesion_redirige_al_login(self):
        r = self.app.test_client().post("/credenciales/servidor", data={})
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.headers["Location"])

    def test_un_perfil_sin_administracion_recibe_403(self):
        if "redes" not in auth.ROLES:
            self.skipTest("este despliegue no tiene el perfil 'redes'")
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": "redes@ejemplo.local", "password": CLAVE})
        r = cli.post("/credenciales/servidor", data=self._formulario_valido())
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self.escritos, [])

    def test_sin_csrf_se_rechaza(self):
        cli = self._admin()
        r = cli.post("/credenciales/servidor", data=self._formulario_valido())
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.escritos, [])

    # ---------------------------------------------------------- guardado correcto
    def test_un_cambio_valido_escribe_las_siete_claves_y_queda_en_auditoria(self):
        cli = self._admin()
        csrf = self._csrf(cli)
        r = cli.post("/credenciales/servidor",
                     data=dict(self._formulario_valido(), csrf=csrf),
                     follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        claves_escritas = dict(self.escritos)
        self.assertEqual(claves_escritas["SMTP_SERVER"], "smtp.gmail.com")
        self.assertEqual(claves_escritas["SMTP_PORT"], "587")
        self.assertEqual(claves_escritas["SMTP_USER"], "alguien@gmail.com")
        self.assertEqual(claves_escritas["SMTP_USE_TLS"], "true")
        self.assertEqual(claves_escritas["SMTP_USE_SSL"], "false")
        self.assertEqual(claves_escritas["EMAIL_FROM"], "alguien@gmail.com")
        self.assertEqual(claves_escritas["EMAIL_FROM_NAME"], "Alertas")
        with db.connect(self.ruta) as conn:
            fila = conn.execute(
                "SELECT * FROM audit_log WHERE action='credencial.servidor' "
                "ORDER BY id DESC LIMIT 1").fetchone()
        self.assertIsNotNone(fila)
        self.assertEqual(fila["username"], "admin@ejemplo.local")
        self.assertIn("smtp.gmail.com", fila["detail"])

    def test_cifrado_ssl_apaga_tls_y_viceversa(self):
        cli = self._admin()
        csrf = self._csrf(cli)
        cli.post("/credenciales/servidor",
                data=dict(self._formulario_valido(cifrado="ssl", puerto="465"), csrf=csrf))
        claves = dict(self.escritos)
        self.assertEqual(claves["SMTP_USE_SSL"], "true")
        self.assertEqual(claves["SMTP_USE_TLS"], "false")

    def test_la_contrasena_no_se_toca_desde_este_formulario(self):
        cli = self._admin()
        csrf = self._csrf(cli)
        cli.post("/credenciales/servidor", data=dict(self._formulario_valido(), csrf=csrf))
        self.assertNotIn("SMTP_PASSWORD", dict(self.escritos))

    # ---------------------------------------------------------- validación
    def test_un_servidor_con_caracteres_raros_se_rechaza(self):
        cli = self._admin()
        csrf = self._csrf(cli)
        r = cli.post("/credenciales/servidor",
                     data=dict(self._formulario_valido(servidor="smtp.gmail.com; rm -rf /"),
                              csrf=csrf),
                     follow_redirects=True)
        self.assertIn("no tiene una forma válida", r.get_data(as_text=True))
        self.assertEqual(self.escritos, [])

    def test_un_puerto_fuera_de_rango_se_rechaza(self):
        cli = self._admin()
        csrf = self._csrf(cli)
        r = cli.post("/credenciales/servidor",
                     data=dict(self._formulario_valido(puerto="70000"), csrf=csrf),
                     follow_redirects=True)
        self.assertIn("entre 1 y 65535", r.get_data(as_text=True))
        self.assertEqual(self.escritos, [])

    def test_un_remitente_sin_forma_de_correo_se_rechaza(self):
        cli = self._admin()
        csrf = self._csrf(cli)
        r = cli.post("/credenciales/servidor",
                     data=dict(self._formulario_valido(remitente="no es un correo"), csrf=csrf),
                     follow_redirects=True)
        self.assertIn("dirección de correo válida", r.get_data(as_text=True))
        self.assertEqual(self.escritos, [])

    def test_un_cifrado_desconocido_se_rechaza(self):
        cli = self._admin()
        csrf = self._csrf(cli)
        r = cli.post("/credenciales/servidor",
                     data=dict(self._formulario_valido(cifrado="otracosa"), csrf=csrf),
                     follow_redirects=True)
        self.assertIn("cifrado válido", r.get_data(as_text=True))
        self.assertEqual(self.escritos, [])


if __name__ == "__main__":
    unittest.main()

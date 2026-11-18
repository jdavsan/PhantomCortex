"""La cookie de sesión no expone información (petición del usuario del 2026-09-08).

«El valor de las cookies debe estar ofuscado y no exponer información» y «las cookies
deben tener secure, httponly y samesite».

Hasta hoy la cookie era la de Flask: firmada pero NO cifrada, un Base64 de un JSON con
el identificador de sesión, los avisos flash y —al crear un usuario con contraseña
generada— la propia contraseña en claro hasta la siguiente carga de la página. Ahora la
cookie «session» lleva únicamente un token aleatorio de 32 bytes y todo el estado vive en
web_sessions (columna «datos», indexada por el SHA-256 del token). Estas pruebas
decodifican lo que llega en Set-Cookie y comprueban que ahí no hay nada legible.

Sin red y con base temporal bajo data/."""
from __future__ import annotations

import base64
import json
import re
import tempfile
import unittest
from pathlib import Path

from threatintel import db
from threatintel.paths import BASE_DIR
from webui import auth, sesion_servidor
from webui.vistas import usuarios

CLAVE = "Clave#Opaca2026"


def _cookie_de(respuesta) -> str:
    """Valor de la cookie «session» de la cabecera Set-Cookie de una respuesta."""
    for linea in respuesta.headers.getlist("Set-Cookie"):
        encontrado = re.match(r"session=([^;]*)", linea)
        if encontrado:
            return encontrado.group(1)
    return ""


def _decodificaciones(valor: str) -> list[str]:
    """Todo lo que un atacante probaría con el valor de la cookie: tal cual, Base64
    normal y Base64 para direcciones (con y sin el relleno que Flask omite)."""
    textos = [valor]
    for segmento in valor.split("."):
        relleno = segmento + "=" * (-len(segmento) % 4)
        for decodificador in (base64.urlsafe_b64decode, base64.b64decode):
            try:
                textos.append(decodificador(relleno).decode("utf-8", "replace"))
            except Exception:  # noqa: BLE001 - no es Base64: mejor
                pass
    return textos


class TestCookieOpaca(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "cookie_opaca.db")
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "opaca@ejemplo.local", CLAVE, rol="admin",
                               nombre="Persona Opaca", actor="t")
            auth.crear_usuario(conn, "lectora@ejemplo.local", CLAVE, rol="ciberseguridad",
                               nombre="Lectora", actor="t")
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def _login(self, usuario="opaca@ejemplo.local"):
        cli = self.app.test_client()
        r = cli.post("/login", data={"usuario": usuario, "password": CLAVE})
        self.assertEqual(r.status_code, 302)
        return cli, r

    def _csrf(self, cli, url="/perfil"):
        return re.search(r'name="csrf" value="([^"]+)"', cli.get(url).get_data(as_text=True)).group(1)

    # ------------------------------------------------------------- contenido
    def test_la_cookie_es_solo_un_token_aleatorio_sin_datos(self):
        """Ni «sid», ni «flash», ni el usuario ni el rol se pueden leer de la cookie por
        ninguna decodificación razonable: es un token de 43 caracteres para direcciones."""
        _cli, r = self._login()
        valor = _cookie_de(r)
        self.assertTrue(sesion_servidor.token_valido(valor), f"cookie inesperada: {valor!r}")
        for texto in _decodificaciones(valor):
            for prohibido in ("sid", "flash", "opaca@ejemplo.local", "opaca", "admin", "csrf",
                              "_permanent", "username", "role"):
                self.assertNotIn(prohibido, texto, f"la cookie expone «{prohibido}»: {texto!r}")
            with self.assertRaises(ValueError, msg="la cookie no debe ser JSON legible"):
                json.loads(texto)

    def test_el_token_se_guarda_como_hash_y_no_en_claro(self):
        _cli, r = self._login()
        token = _cookie_de(r)
        with db.connect(self.ruta) as conn:
            filas = [f["sid_hash"] for f in conn.execute("SELECT sid_hash FROM web_sessions")]
        self.assertNotIn(token, filas, "el token en claro no puede estar en la base")
        self.assertIn(sesion_servidor.hash_token(token), filas)
        self.assertEqual(len(sesion_servidor.hash_token(token)), 64)

    def test_los_avisos_flash_viven_en_el_servidor_y_no_en_la_cookie(self):
        """Tras cerrar sesión, «Sesión cerrada.» debe mostrarse en la pantalla de acceso,
        pero el texto no puede viajar en la cookie: se guarda en web_sessions.datos."""
        cli, _ = self._login()
        csrf = self._csrf(cli)
        r = cli.post("/logout", data={"csrf": csrf})
        self.assertEqual(r.headers["Location"], "/login")
        valor = _cookie_de(r)
        self.assertTrue(sesion_servidor.token_valido(valor), "la sesión anónima también es un token")
        for texto in _decodificaciones(valor):
            self.assertNotIn("Sesi", texto)
            self.assertNotIn("cerrada", texto)
        with db.connect(self.ruta) as conn:
            datos = sesion_servidor.datos_de_sesion(conn, valor)
        self.assertIn("_flashes", datos, "el aviso está en el servidor")
        html = cli.get("/login").get_data(as_text=True)
        self.assertIn("Sesión cerrada.", html)
        # Y una vez mostrado, se consume también en el servidor
        with db.connect(self.ruta) as conn:
            self.assertNotIn("_flashes", sesion_servidor.datos_de_sesion(conn, valor))

    def test_un_acceso_fallido_no_crea_filas_ni_cookie(self):
        """El aviso de error se pinta en la misma respuesta, así que no hay nada que
        guardar: sin fila anónima en web_sessions y sin Set-Cookie. Un ataque de fuerza
        bruta no llena la tabla de sesiones."""
        with db.connect(self.ruta) as conn:
            antes = conn.execute("SELECT COUNT(*) FROM web_sessions").fetchone()[0]
        r = self.app.test_client().post("/login", data={"usuario": "opaca@ejemplo.local",
                                                        "password": "incorrecta"})
        self.assertEqual(r.status_code, 200)
        self.assertIn("Usuario o contraseña incorrectos", r.get_data(as_text=True))
        self.assertEqual(_cookie_de(r), "")
        with db.connect(self.ruta) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM web_sessions").fetchone()[0], antes)

    def test_una_cookie_antigua_firmada_o_inventada_no_da_acceso(self):
        """Las cookies firmadas de Flask que aún tengan los navegadores (o cualquier valor
        inventado) se rechazan sin consultar la base y se piden borrar."""
        for valor in ("eyJzaWQiOiJhYmMifQ.ZtVQAA.firma-falsa", "x" * 43, "", "a" * 44):
            cli = self.app.test_client()
            if valor:
                cli.set_cookie("session", valor)
            r = cli.get("/")
            self.assertEqual(r.headers["Location"].split("?")[0], "/login", valor)

    def test_un_token_bien_formado_pero_desconocido_se_descarta(self):
        cli = self.app.test_client()
        cli.set_cookie("session", sesion_servidor.nuevo_token())
        r = cli.get("/")
        self.assertEqual(r.headers["Location"].split("?")[0], "/login")
        # Desde el 2026-09-08 NO se pide al navegador que la olvide: la respuesta tardía de
        # una petición que llegó con un token ya rotado borraría la cookie nueva que el
        # navegador acababa de recibir en otra respuesta (revisión adversaria). Un token
        # desconocido simplemente no da acceso; la cookie se borra solo al cerrar sesión o
        # cuando la sesión caducó de verdad.
        self.assertNotRegex("\n".join(r.headers.getlist("Set-Cookie")), r"session=")

    # ------------------------------------------------------------- atributos
    def test_httponly_samesite_lax_y_path_raiz_sin_domain(self):
        _cli, r = self._login()
        linea = next(l for l in r.headers.getlist("Set-Cookie") if l.startswith("session="))
        self.assertRegex(linea, re.compile(r"HttpOnly", re.I))
        self.assertRegex(linea, re.compile(r"SameSite=Lax", re.I))
        self.assertRegex(linea, re.compile(r"Path=/", re.I))
        self.assertNotRegex(linea, re.compile(r"Domain=", re.I))
        # Sin Max-Age ni Expires: cookie de navegador, la duración la decide el servidor
        self.assertNotRegex(linea, re.compile(r"Max-Age=|Expires=", re.I))

    def test_secure_sigue_al_ajuste_webui_https(self):
        with db.session(self.ruta) as conn:
            db.set_setting(conn, "webui_https", True)
        try:
            from webui.app import crear_app
            app = crear_app(db_path=self.ruta, testing=True)
            cli = app.test_client()
            r = cli.post("/login", data={"usuario": "lectora@ejemplo.local", "password": CLAVE},
                         base_url="https://omniguard.ejemplo.local")
            linea = next(l for l in r.headers.getlist("Set-Cookie") if l.startswith("session="))
            self.assertRegex(linea, re.compile(r"; Secure", re.I))
            # El borrado al salir también va con Secure
            csrf = re.search(r'name="csrf" value="([^"]+)"',
                             cli.get("/perfil", base_url="https://omniguard.ejemplo.local")
                             .get_data(as_text=True)).group(1)
            r = cli.post("/logout", data={"csrf": csrf}, base_url="https://omniguard.ejemplo.local")
            self.assertRegex("\n".join(r.headers.getlist("Set-Cookie")), re.compile(r"Secure", re.I))
        finally:
            with db.session(self.ruta) as conn:
                db.set_setting(conn, "webui_https", False)

    # --------------------------------------------- credencial de un solo uso
    def test_la_credencial_mostrada_una_vez_va_por_el_servidor(self):
        """Usuarios guarda en session["credencial_una_vez"] solo un identificador opaco; la
        contraseña generada vive en memoria del proceso hasta la siguiente carga de la página
        (revisión del 2026-09-08: ni en la cookie ni en la base de datos). Debe seguir
        funcionando con la sesión en servidor y la contraseña no puede aparecer en la cookie."""
        cli, _ = self._login()
        csrf = self._csrf(cli, "/usuarios/")
        r = cli.post("/usuarios/crear", data={"csrf": csrf, "nombre": "Nueva Persona",
                                              "correo": "nueva@ejemplo.local", "rol": "ciberseguridad",
                                              "generar": "1"})
        self.assertEqual(r.status_code, 302)
        cookie = cli.get_cookie("session")
        self.assertIsNotNone(cookie)
        with db.connect(self.ruta) as conn:
            datos = sesion_servidor.datos_de_sesion(conn, cookie.value)
        self.assertIn("credencial_una_vez", datos)
        identificador = datos["credencial_una_vez"]
        self.assertIsInstance(identificador, str, "en la sesión solo viaja un identificador opaco")
        generada = usuarios._CREDENCIALES_UNA_VEZ[identificador][1]["password"]
        self.assertNotIn(generada, str(datos), "la contraseña no se guarda en la base de datos")
        self.assertTrue(auth.fuerza_password(generada)[0])
        for texto in _decodificaciones(cookie.value):
            self.assertNotIn(generada, texto, "la contraseña generada no puede ir en la cookie")
        html = cli.get("/usuarios/").get_data(as_text=True)
        self.assertIn(generada, html, "se muestra una vez")
        with db.connect(self.ruta) as conn:
            self.assertNotIn("credencial_una_vez", sesion_servidor.datos_de_sesion(conn, cookie.value))
        self.assertNotIn(identificador, usuarios._CREDENCIALES_UNA_VEZ, "y se borra de la memoria")
        self.assertNotIn(generada, cli.get("/usuarios/").get_data(as_text=True), "y solo una vez")

    def test_el_destino_tras_el_segundo_factor_no_viaja_en_la_cookie(self):
        """El destino solicitado antes del segundo factor y la marca de tiempo de la
        activación también son datos de sesión: se guardan en el servidor."""
        cli, _ = self._login()
        csrf = self._csrf(cli, "/perfil")
        r = cli.post("/mi-password/segundo-factor/activar", data={"csrf": csrf, "empezar": "1"})
        self.assertEqual(r.status_code, 200)
        cookie = cli.get_cookie("session").value
        with db.connect(self.ruta) as conn:
            datos = sesion_servidor.datos_de_sesion(conn, cookie)
        self.assertIn("totp_activacion_at", datos)
        for texto in _decodificaciones(cookie):
            self.assertNotIn("totp", texto)


if __name__ == "__main__":
    unittest.main()

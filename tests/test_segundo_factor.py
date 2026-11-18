"""Segundo factor de autenticación (TOTP, RFC 6238) con códigos de recuperación (2026-09-05).

Sin red. Comprueba los vectores oficiales del RFC 6238, el flujo completo con
test_client (contraseña → sesión pendiente → código → acceso; bloqueo por fallos;
código de recuperación de un solo uso; cancelar), la activación con QR (SVG sin
style=), la regeneración y la desactivación, el segundo factor obligatorio para
administradores, el restablecimiento por un administrador y por consola, y que
un usuario sin segundo factor entra como antes. Base temporal bajo data/.

Revisión de seguridad del 2026-09-05: «login.ok» y last_login_at solo al completar
el segundo factor (antes «login.password_ok»); un administrador no restablece su
propio segundo factor; «Desbloquear» reinicia totp_fallos; el campo de código no
lleva inputmode numérico (admite códigos de recuperación con letras); JSON
inconsistente en totp_recuperacion rechaza el código sin error 500; la sesión
pendiente caduca a los diez minutos y no cuenta como sesión abierta.

Revisión de seguridad del 2026-09-06: al superar el código, el identificador de
sesión y el token CSRF son nuevos y el anterior deja de servir (fijación de
sesión); el secreto pendiente de confirmar no viaja en la cookie y no vale como
segundo factor; los códigos incorrectos de «Desactivar» y «Regenerar los códigos»
cuentan para el bloqueo de la cuenta; «Regenerar los códigos» exige contraseña Y
código; las sesiones caducadas se borran al iniciar sesión."""
from __future__ import annotations

import importlib.util
import io
import json
import re
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from threatintel import db
from threatintel.paths import BASE_DIR
from webui import auth, totp

SECRETO_RFC = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"      # "12345678901234567890" en Base32
RE_RECUPERACION = re.compile(r"^[a-z0-9]{5}-[a-z0-9]{5}$")
RE_STYLE = re.compile(r"\sstyle\s*=", re.I)
RE_ON = re.compile(r"\son[a-z]+\s*=", re.I)
CLAVE = "ClaveSegura#2026"


def _codigo_actual(secreto: str) -> str:
    return totp.codigo_en_paso(secreto, totp.paso_actual())


def _cookie_legible(valor: str) -> str:
    """Todo lo que cualquiera podría leer de la cookie de sesión.

    Hasta el 2026-09-08 la cookie era la firmada de Flask (Base64 de un JSON, a veces
    comprimido) y esta función la decodificaba para comprobar que no llevaba el secreto
    TOTP (revisión del 2026-09-06, hallazgo 2). Desde la sesión opaca en servidor
    (webui/sesion_servidor.py) la cookie es solo un token aleatorio: se devuelve el
    valor tal cual más su decodificación Base64 forzada, para que las comprobaciones
    «no contiene…» sigan siendo significativas."""
    import base64
    relleno = valor + "=" * (-len(valor) % 4)
    try:
        decodificado = base64.urlsafe_b64decode(relleno).decode("utf-8", "replace")
    except (ValueError, TypeError):
        decodificado = ""
    return valor + "\n" + decodificado


def _datos_en_servidor(ruta: str, cookie: str) -> dict:
    """Datos de la sesión guardados en web_sessions.datos para un token (2026-09-08)."""
    from webui import sesion_servidor
    with db.connect(ruta) as conn:
        return sesion_servidor.datos_de_sesion(conn, cookie)


class TestTotp(unittest.TestCase):
    def test_vectores_rfc_6238(self):
        for instante, esperado in ((59, "287082"), (1111111109, "081804"), (1234567890, "005924")):
            with mock.patch("time.time", return_value=instante):
                self.assertEqual(totp.codigo_en_paso(SECRETO_RFC, totp.paso_actual()), esperado)
                self.assertTrue(totp.verificar(SECRETO_RFC, esperado))
                self.assertTrue(totp.verificar(SECRETO_RFC, f" {esperado[:3]} {esperado[3:]} "), "tolera espacios")
                self.assertFalse(totp.verificar(SECRETO_RFC, "000000"))
                self.assertFalse(totp.verificar(SECRETO_RFC, esperado + "1"))
                self.assertFalse(totp.verificar(SECRETO_RFC, ""))

    def test_ventana_de_un_paso(self):
        with mock.patch("time.time", return_value=1234567890):
            anterior = totp.codigo_en_paso(SECRETO_RFC, totp.paso_actual() - 1)
            siguiente = totp.codigo_en_paso(SECRETO_RFC, totp.paso_actual() + 1)
            lejano = totp.codigo_en_paso(SECRETO_RFC, totp.paso_actual() + 2)
            self.assertTrue(totp.verificar(SECRETO_RFC, anterior))
            self.assertTrue(totp.verificar(SECRETO_RFC, siguiente))
            self.assertFalse(totp.verificar(SECRETO_RFC, lejano))
            self.assertEqual(totp.paso_valido(SECRETO_RFC, siguiente), totp.paso_actual() + 1)

    def test_secreto_uri_y_qr(self):
        secreto = totp.generar_secreto()
        self.assertEqual(len(secreto), 32)
        self.assertRegex(secreto, r"^[A-Z2-7]{32}$")
        self.assertNotEqual(secreto, totp.generar_secreto())
        uri = totp.uri(SECRETO_RFC, "soc@ejemplo.local")
        self.assertTrue(uri.startswith("otpauth://totp/Inteligencia%20de%20Amenazas:soc@ejemplo.local?"))
        self.assertIn(f"secret={SECRETO_RFC}", uri)
        self.assertIn("issuer=Inteligencia%20de%20Amenazas", uri)
        self.assertIn("algorithm=SHA1&digits=6&period=30", uri)
        svg = str(totp.qr_svg(uri))
        self.assertTrue(svg.startswith("<svg "))
        self.assertIn('role="img"', svg)
        self.assertIn("aria-label=", svg)
        self.assertIsNone(RE_STYLE.search(svg))
        self.assertIsNone(RE_ON.search(svg))

    def test_codigos_de_recuperacion(self):
        codigos = totp.codigos_recuperacion()
        self.assertEqual(len(codigos), 8)
        self.assertEqual(len(set(codigos)), 8)
        for c in codigos:
            self.assertRegex(c, RE_RECUPERACION)
            for ambiguo in "ilo01":
                self.assertNotIn(ambiguo, c)
        self.assertEqual(totp.normalizar_recuperacion(" ABCDE-FGHJK "), "abcde-fghjk")
        self.assertEqual(totp.normalizar_recuperacion("abcdefghjk"), "abcde-fghjk")
        self.assertIsNone(totp.normalizar_recuperacion("123456"))
        self.assertIsNone(totp.normalizar_recuperacion("x" * 100))


class TestFlujoWeb(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "segundo_factor.db")
        db.init_db(cls.ruta)
        cls.secretos: dict[str, str] = {}
        cls.recuperacion: dict[str, list[str]] = {}
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "admin", CLAVE, rol="admin", actor="t")
            auth.crear_usuario(conn, "lector", CLAVE, rol="ciberseguridad", actor="t")
            auth.crear_usuario(conn, "jefe", CLAVE, rol="admin", actor="t")
            for nombre in ("con2fa", "bloqueable", "recupera", "cancela", "desactiva",
                           "regenera", "restablecido", "consola", "must", "auditado",
                           "roto", "desbloqueado", "fijacion", "bloqueodesac"):
                auth.crear_usuario(conn, nombre, CLAVE, rol="ciberseguridad", actor="t")
                secreto = totp.generar_secreto()
                cls.secretos[nombre] = secreto
                cls.recuperacion[nombre] = auth.activar_2fa(conn, nombre, secreto, 0, actor="t")
            auth.crear_usuario(conn, "activador", CLAVE, rol="ciberseguridad", actor="t")
            auth.crear_usuario(conn, "activador2", CLAVE, rol="ciberseguridad", actor="t")
            auth.crear_usuario(conn, "limpieza", CLAVE, rol="ciberseguridad", actor="t")
            auth.crear_usuario(conn, "jefa2fa", CLAVE, rol="admin", actor="t")
            cls.secretos["jefa2fa"] = totp.generar_secreto()
            cls.recuperacion["jefa2fa"] = auth.activar_2fa(conn, "jefa2fa", cls.secretos["jefa2fa"], 0, actor="t")
            conn.execute("UPDATE users SET must_change=1 WHERE username='must'")
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    # ---- utilidades -------------------------------------------------------
    def _login(self, usuario, clave=CLAVE, **kw):
        cli = self.app.test_client()
        r = cli.post("/login", data={"usuario": usuario, "password": clave}, **kw)
        return cli, r

    def _empezar_activacion(self, cli):
        """Pulsa «Generar el código QR» (POST): desde la revisión del 2026-09-06 el GET de la
        página de activación no crea ningún secreto. Devuelve el HTML con el QR."""
        pagina = cli.get("/mi-password/segundo-factor/activar")
        assert pagina.status_code == 200, pagina.status_code
        csrf = re.search(r'name="csrf" value="([^"]+)"', pagina.get_data(as_text=True)).group(1)
        r = cli.post("/mi-password/segundo-factor/activar", data={"csrf": csrf, "empezar": "1"})
        assert r.status_code == 200, r.status_code
        return r

    def _csrf(self, cli, url="/mi-password"):
        return re.search(r'name="csrf" value="([^"]+)"', cli.get(url).get_data(as_text=True)).group(1)

    def _cookie(self, cli):
        galleta = cli.get_cookie("session")
        return galleta.value if galleta else ""

    def _fila(self, usuario):
        with db.session(self.ruta) as conn:
            return dict(conn.execute("SELECT * FROM users WHERE username=?", (usuario,)).fetchone())

    def _auditoria(self, accion):
        with db.session(self.ruta) as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM audit_log WHERE action=? ORDER BY id", (accion,))]

    def _ajuste(self, clave, valor):
        with db.session(self.ruta) as conn:
            db.set_setting(conn, clave, valor)

    # ---- acceso -------------------------------------------------------------
    def test_usuario_sin_segundo_factor_entra_como_antes(self):
        cli, r = self._login("lector")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers["Location"], "/")
        self.assertEqual(cli.get("/").status_code, 200)
        self.assertEqual(cli.get("/login/segundo-factor").headers["Location"], "/")

    def test_login_no_revela_si_hay_segundo_factor(self):
        a = self.app.test_client().post("/login", data={"usuario": "con2fa", "password": "mal"},
                                        follow_redirects=True).get_data(as_text=True)
        b = self.app.test_client().post("/login", data={"usuario": "lector", "password": "mal"},
                                        follow_redirects=True).get_data(as_text=True)
        patron = r'class="aviso[^"]*"[^>]*>([^<]+)<'
        self.assertEqual(re.findall(patron, a), re.findall(patron, b))
        self.assertNotIn("segundo factor", a.lower())

    def test_flujo_completo_con_codigo_de_la_aplicacion(self):
        cli, r = self._login("con2fa")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers["Location"], "/login/segundo-factor")
        # Mientras esté pendiente, nada es accesible
        for url in ("/", "/mi-password", "/usuarios/", "/amenazas/", "/ajustes/"):
            r = cli.get(url)
            self.assertEqual(r.status_code, 302, url)
            self.assertEqual(r.headers["Location"], "/login/segundo-factor", url)
        self.assertEqual(cli.get("/login").headers["Location"], "/login/segundo-factor")
        pagina = cli.get("/login/segundo-factor")
        self.assertEqual(pagina.status_code, 200)
        html = pagina.get_data(as_text=True)
        self.assertIn("Segundo factor de autenticación", html)
        self.assertIn('autocomplete="one-time-code"', html)
        # Hallazgo 4 (2026-09-05): el campo admite códigos de recuperación con letras,
        # así que no debe forzar el teclado numérico.
        self.assertNotIn("inputmode=", html)
        self.assertIn('rel="icon"', html)
        self.assertIn("Verificar", html)
        self.assertIn('action="/logout"', html)
        self.assertIn("no-store", pagina.headers.get("Cache-Control", ""))
        self.assertIsNone(RE_STYLE.search(html))
        self.assertIsNone(RE_ON.search(html))
        csrf = re.search(r'name="csrf" value="([^"]+)"', html).group(1)
        self.assertTrue(csrf)
        # Sin CSRF: rechazado
        self.assertEqual(cli.post("/login/segundo-factor", data={"codigo": "123456"}).status_code, 400)
        # Código incorrecto: sigue pendiente, con mensaje
        r = cli.post("/login/segundo-factor", data={"csrf": csrf, "codigo": "000000"})
        self.assertEqual(r.status_code, 200)
        self.assertIn("El código no es válido", r.get_data(as_text=True))
        self.assertEqual(self._fila("con2fa")["totp_fallos"], 1)
        self.assertEqual(cli.get("/").status_code, 302)
        # Código correcto: acceso
        with mock.patch.object(totp, "time") as reloj:
            reloj.time.return_value = 1_800_000_000.0
            codigo = _codigo_actual(self.secretos["con2fa"])
            r = cli.post("/login/segundo-factor", data={"csrf": csrf, "codigo": codigo})
            self.assertEqual(r.status_code, 302)
            self.assertEqual(r.headers["Location"], "/")
            self.assertEqual(cli.get("/").status_code, 200)
            self.assertEqual(self._fila("con2fa")["totp_fallos"], 0)
            self.assertTrue(self._auditoria("login.2fa.ok"))
            self.assertTrue(any("intento 1/" in (a["detail"] or "") for a in self._auditoria("login.2fa.fallo")))
            # Ya dentro, la página del segundo factor redirige al panel
            self.assertEqual(cli.get("/login/segundo-factor").headers["Location"], "/")
            # El MISMO código no vale una segunda vez (otra sesión, mismo paso)
            cli2, _ = self._login("con2fa")
            csrf2 = self._csrf(cli2, "/login/segundo-factor")
            r = cli2.post("/login/segundo-factor", data={"csrf": csrf2, "codigo": codigo})
            self.assertEqual(r.status_code, 200)
            self.assertIn("El código no es válido", r.get_data(as_text=True))
            self.assertTrue(any("repetido" in (a["detail"] or "") for a in self._auditoria("login.2fa.fallo")))
            # El del paso siguiente sí
            reloj.time.return_value = 1_800_000_030.0
            r = cli2.post("/login/segundo-factor", data={"csrf": csrf2, "codigo": _codigo_actual(self.secretos["con2fa"])})
            self.assertEqual(r.status_code, 302)
            self.assertEqual(cli2.get("/").status_code, 200)

    def test_ultimo_acceso_y_login_ok_solo_al_completar_el_segundo_factor(self):
        """Hallazgo 1 y 7: la contraseña correcta NO es un acceso. Se audita
        «login.password_ok», last_login_at no cambia y la sesión pendiente caduca a
        los diez minutos y no cuenta como abierta. Al superar el código: «login.ok»,
        last_login_at y caducidad completa."""
        from datetime import datetime, timedelta, timezone
        self.assertIsNone(self._fila("auditado")["last_login_at"])
        cli, r = self._login("auditado")
        self.assertEqual(r.headers["Location"], "/login/segundo-factor")
        self.assertIsNone(self._fila("auditado")["last_login_at"])
        self.assertTrue(any(a["username"] == "auditado" for a in self._auditoria("login.password_ok")))
        self.assertFalse(any(a["username"] == "auditado" for a in self._auditoria("login.ok")))
        with db.session(self.ruta) as conn:
            sesion = dict(conn.execute("SELECT * FROM web_sessions WHERE username='auditado' "
                                       "ORDER BY created_at DESC, rowid DESC").fetchone())
        self.assertEqual(sesion["mfa_pendiente"], 1)
        expira = datetime.fromisoformat(sesion["expires_at"].replace("Z", "+00:00"))
        ahora = datetime.now(timezone.utc)
        self.assertLessEqual(expira, ahora + timedelta(minutes=auth.MINUTOS_SESION_PENDIENTE_2FA, seconds=5))
        self.assertGreater(expira, ahora + timedelta(minutes=auth.MINUTOS_SESION_PENDIENTE_2FA - 1))
        # La lista de Usuarios no la cuenta como sesión abierta
        admin, _ = self._login("admin")
        html = admin.get("/usuarios/").get_data(as_text=True)
        fila_html = re.search(r"<tr>\s*<td>\s*auditado.*?</tr>", html, re.S).group(0)
        self.assertIn('<td class="num">0</td>', fila_html)
        # Se completa el segundo factor
        csrf = self._csrf(cli, "/login/segundo-factor")
        r = cli.post("/login/segundo-factor", data={"csrf": csrf, "codigo": self.recuperacion["auditado"][0]})
        self.assertEqual(r.status_code, 302)
        fila = self._fila("auditado")
        self.assertIsNotNone(fila["last_login_at"])
        self.assertTrue(any(a["username"] == "auditado" for a in self._auditoria("login.ok")))
        with db.session(self.ruta) as conn:
            sesion = dict(conn.execute("SELECT * FROM web_sessions WHERE username='auditado' "
                                       "ORDER BY created_at DESC, rowid DESC").fetchone())
        self.assertEqual(sesion["mfa_pendiente"], 0)
        expira = datetime.fromisoformat(sesion["expires_at"].replace("Z", "+00:00"))
        self.assertGreater(expira, datetime.now(timezone.utc) + timedelta(hours=7))
        html = admin.get("/usuarios/").get_data(as_text=True)
        fila_html = re.search(r"<tr>\s*<td>\s*auditado.*?</tr>", html, re.S).group(0)
        self.assertIn('<td class="num">1</td>', fila_html)
        # Un usuario sin segundo factor sigue registrando login.ok y last_login_at al entrar
        self.assertTrue(any(a["username"] == "admin" for a in self._auditoria("login.ok")))
        self.assertIsNotNone(self._fila("admin")["last_login_at"])

    def test_identificador_de_sesion_nuevo_al_superar_el_segundo_factor(self):
        """Hallazgo 1 de la revisión del 2026-09-06: fijación de sesión.

        La fila de web_sessions se reutilizaba tal cual, así que el identificador de
        sesión y el token CSRF emitidos cuando solo se había comprobado la contraseña
        seguían valiendo para la sesión ya completa. Ahora los dos son nuevos y el
        anterior deja de dar acceso."""
        cli, r = self._login("fijacion")
        self.assertEqual(r.headers["Location"], "/login/segundo-factor")
        cookie_antes = self._cookie(cli)
        csrf_antes = self._csrf(cli, "/login/segundo-factor")
        with db.session(self.ruta) as conn:
            sid_antes = conn.execute("SELECT sid_hash FROM web_sessions WHERE username='fijacion' "
                                     "ORDER BY rowid DESC").fetchone()["sid_hash"]
        r = cli.post("/login/segundo-factor",
                     data={"csrf": csrf_antes, "codigo": self.recuperacion["fijacion"][0]})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(cli.get("/").status_code, 200)
        cookie_despues = self._cookie(cli)
        csrf_despues = self._csrf(cli, "/mi-password")
        self.assertNotEqual(cookie_antes, cookie_despues, "la cookie de sesión debe cambiar")
        self.assertNotEqual(csrf_antes, csrf_despues, "el token CSRF debe cambiar")
        with db.session(self.ruta) as conn:
            filas = [dict(f) for f in conn.execute(
                "SELECT * FROM web_sessions WHERE username='fijacion'")]
        self.assertEqual(len(filas), 1, "una sola fila de sesión, no dos")
        self.assertNotEqual(filas[0]["sid_hash"], sid_antes)
        self.assertEqual(filas[0]["mfa_pendiente"], 0)
        # El identificador anterior ya no sirve para nada
        viejo = self.app.test_client()
        viejo.set_cookie("session", cookie_antes)
        self.assertEqual(viejo.get("/").headers["Location"].split("?")[0], "/login")
        self.assertEqual(viejo.get("/login/segundo-factor").headers["Location"], "/login")
        self.assertEqual(viejo.get("/mi-password").headers["Location"].split("?")[0], "/login")
        # Y el token CSRF anterior tampoco vale en la sesión nueva
        self.assertEqual(cli.post("/logout", data={"csrf": csrf_antes}).status_code, 400)
        self.assertEqual(cli.post("/logout", data={"csrf": csrf_despues}).headers["Location"], "/login")

    def test_las_sesiones_caducadas_se_borran_al_iniciar_sesion(self):
        """Hallazgo 6 de la revisión del 2026-09-06: limpiar_sesiones_caducadas no se
        invocaba desde ningún punto, así que las filas de web_sessions no se borraban
        nunca. Ahora cada acceso nuevo limpia las caducadas."""
        cli, _ = self._login("limpieza")
        self.assertEqual(cli.get("/").status_code, 200)
        with db.session(self.ruta) as conn:
            conn.execute("UPDATE web_sessions SET expires_at='2000-01-01T00:00:00Z' "
                         "WHERE username='limpieza'")
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM web_sessions "
                                          "WHERE username='limpieza'").fetchone()[0], 1)
        self._login("lector")
        with db.session(self.ruta) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM web_sessions "
                                          "WHERE username='limpieza'").fetchone()[0], 0,
                             "la sesión caducada ha desaparecido de la tabla")

    def test_sesion_pendiente_caducada_no_da_acceso(self):
        cli, _ = self._login("auditado")
        with db.session(self.ruta) as conn:
            conn.execute("UPDATE web_sessions SET expires_at='2000-01-01T00:00:00Z' WHERE username='auditado' AND mfa_pendiente=1")
            self.assertEqual(auth.limpiar_sesiones_caducadas(conn), 1,
                             "la limpieza explícita borra la fila caducada")
        self.assertEqual(cli.get("/login/segundo-factor").headers["Location"], "/login")
        self.assertEqual(cli.get("/").headers["Location"].split("?")[0], "/login")

    def test_sesion_pendiente_caducada_se_borra_al_usarla(self):
        """Adaptación del 2026-09-08 (sesión opaca en servidor): la interfaz de sesión
        borra la fila caducada en el momento en que el navegador la presenta, sin
        esperar a la limpieza del siguiente acceso, así que después ya no queda nada
        que limpiar."""
        cli, _ = self._login("auditado")
        with db.session(self.ruta) as conn:
            conn.execute("UPDATE web_sessions SET expires_at='2000-01-01T00:00:00Z' WHERE username='auditado' AND mfa_pendiente=1")
        self.assertEqual(cli.get("/login/segundo-factor").headers["Location"], "/login")
        with db.session(self.ruta) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM web_sessions WHERE username='auditado' "
                                          "AND mfa_pendiente=1").fetchone()[0], 0)
            self.assertEqual(auth.limpiar_sesiones_caducadas(conn), 0)

    def test_json_de_recuperacion_inconsistente_no_provoca_error(self):
        """Hallazgo 5: un JSON con la forma equivocada rechaza el código, nunca un 500."""
        uid = self._fila("roto")["id"]
        for bruto in ('{"codigos": 5}', '{"codigos": "abc", "ultimo_paso": "x"}', 'esto no es json',
                      '[1, 2, 3]', '{"codigos": [1, "x", null]}', '42', ''):
            with db.session(self.ruta) as conn:
                conn.execute("UPDATE users SET totp_recuperacion=? WHERE id=?", (bruto, uid))
            fila = self._fila("roto")
            self.assertEqual(auth.estado_2fa(fila)["restantes"], 0, bruto)
            with db.session(self.ruta) as conn:
                self.assertEqual(auth.verificar_codigo_2fa(conn, fila, "abcde-fghjk"), (False, ""), bruto)
                self.assertEqual(auth.verificar_codigo_2fa(conn, fila, "000000")[0], False, bruto)
            cli, _ = self._login("roto")
            csrf = self._csrf(cli, "/login/segundo-factor")
            r = cli.post("/login/segundo-factor", data={"csrf": csrf, "codigo": "abcde-fghjk"})
            self.assertEqual(r.status_code, 200, bruto)
            self.assertIn("El código no es válido", r.get_data(as_text=True))
            # El código de la aplicación sigue valiendo aunque el JSON esté roto
            with mock.patch.object(totp, "time") as reloj:
                reloj.time.return_value = 1_900_000_000.0 + 60 * len(bruto)
                r = cli.post("/login/segundo-factor", data={"csrf": csrf, "codigo": _codigo_actual(self.secretos["roto"])})
            self.assertEqual(r.status_code, 302, bruto)
            self.assertEqual(cli.get("/").status_code, 200, bruto)
        with db.session(self.ruta) as conn:
            conn.execute("UPDATE users SET totp_fallos=0 WHERE id=?", (uid,))

    def test_destino_seguro_se_conserva_tras_el_segundo_factor(self):
        cli = self.app.test_client()
        cli.post("/login?siguiente=/mi-password", data={"usuario": "con2fa", "password": CLAVE})
        csrf = self._csrf(cli, "/login/segundo-factor")
        with mock.patch.object(totp, "time") as reloj:
            reloj.time.return_value = 1_700_000_000.0
            r = cli.post("/login/segundo-factor", data={"csrf": csrf, "codigo": _codigo_actual(self.secretos["con2fa"])})
        self.assertEqual(r.headers["Location"], "/mi-password")
        cli = self.app.test_client()
        cli.post("/login?siguiente=//evil.example/", data={"usuario": "con2fa", "password": CLAVE})
        csrf = self._csrf(cli, "/login/segundo-factor")
        with mock.patch.object(totp, "time") as reloj:
            reloj.time.return_value = 1_700_000_060.0
            r = cli.post("/login/segundo-factor", data={"csrf": csrf, "codigo": _codigo_actual(self.secretos["con2fa"])})
        self.assertEqual(r.headers["Location"], "/")

    def test_must_change_sigue_funcionando_tras_el_segundo_factor(self):
        cli, _ = self._login("must")
        csrf = self._csrf(cli, "/login/segundo-factor")
        r = cli.post("/login/segundo-factor", data={"csrf": csrf, "codigo": _codigo_actual(self.secretos["must"])})
        self.assertEqual(r.headers["Location"], "/mi-password")

    def test_bloqueo_tras_codigos_incorrectos_repetidos(self):
        cli, _ = self._login("bloqueable")
        csrf = self._csrf(cli, "/login/segundo-factor")
        ultimo = None
        for _ in range(5):
            ultimo = cli.post("/login/segundo-factor", data={"csrf": csrf, "codigo": "111111"})
        self.assertEqual(ultimo.status_code, 302)
        self.assertEqual(ultimo.headers["Location"], "/login")
        html = cli.get("/login").get_data(as_text=True)
        self.assertIn("Demasiados intentos", html)
        fila = self._fila("bloqueable")
        self.assertIsNotNone(fila["locked_until"])
        self.assertGreaterEqual(fila["totp_fallos"], 5)
        # La sesión pendiente murió y la contraseña correcta tampoco entra mientras dure el bloqueo
        self.assertEqual(cli.get("/login/segundo-factor").headers["Location"], "/login")
        _, r = self._login("bloqueable", follow_redirects=True)
        # 2026-09-08: el acceso con contraseña no confirma el bloqueo (sería enumerar
        # cuentas); responde como a una contraseña incorrecta y no deja entrar.
        self.assertIn("usuario o contraseña incorrectos", r.get_data(as_text=True).lower())
        self.assertNotIn("/panel", r.headers.get("Location", ""))

    def test_codigo_de_recuperacion_de_un_solo_uso(self):
        codigo = self.recuperacion["recupera"][0]
        cli, _ = self._login("recupera")
        csrf = self._csrf(cli, "/login/segundo-factor")
        r = cli.post("/login/segundo-factor", data={"csrf": csrf, "codigo": codigo.upper()}, follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        html = r.get_data(as_text=True)
        self.assertIn("código de recuperación", html)
        self.assertIn("le quedan 7", html)
        self.assertEqual(auth.estado_2fa(self._fila("recupera"))["restantes"], 7)
        # Segunda vez: rechazado
        cli2, _ = self._login("recupera")
        csrf2 = self._csrf(cli2, "/login/segundo-factor")
        r = cli2.post("/login/segundo-factor", data={"csrf": csrf2, "codigo": codigo})
        self.assertEqual(r.status_code, 200)
        self.assertIn("El código no es válido", r.get_data(as_text=True))
        # Otro código sin usar sí entra
        r = cli2.post("/login/segundo-factor", data={"csrf": csrf2, "codigo": self.recuperacion["recupera"][1]})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(cli2.get("/").status_code, 200)

    def test_cancelar_cierra_la_sesion_pendiente(self):
        cli, _ = self._login("cancela")
        csrf = self._csrf(cli, "/login/segundo-factor")
        r = cli.post("/logout", data={"csrf": csrf})
        self.assertEqual(r.headers["Location"], "/login")
        self.assertEqual(cli.get("/login/segundo-factor").headers["Location"], "/login")
        self.assertEqual(cli.get("/").headers["Location"].split("?")[0], "/login")
        with db.session(self.ruta) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM web_sessions WHERE username='cancela'").fetchone()[0], 0)

    def test_anonimo_en_segundo_factor_va_al_login(self):
        r = self.app.test_client().get("/login/segundo-factor")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers["Location"], "/login")

    # ---- activación, regeneración y desactivación -------------------------------
    def test_activacion_con_qr_y_codigos(self):
        cli, _ = self._login("activador")
        html = cli.get("/mi-password").get_data(as_text=True)
        self.assertIn("No activado", html)
        self.assertIn("Segundo factor de autenticación", html)
        self.assertIn('data-tour="3"', html)
        self.assertIsNone(RE_STYLE.search(html))
        pagina = self._empezar_activacion(cli)
        html = pagina.get_data(as_text=True)
        self.assertIn("<svg ", html)
        self.assertIn('class="qr"', html)
        self.assertIsNone(RE_STYLE.search(html))
        self.assertIsNone(RE_ON.search(html))
        self.assertIn("no-store", pagina.headers.get("Cache-Control", ""))
        secreto = re.search(r'<p class="mono envolver">([A-Z2-7 ]+)</p>', html).group(1).replace(" ", "")
        self.assertEqual(len(secreto), 32)
        csrf = re.search(r'name="csrf" value="([^"]+)"', html).group(1)
        # Recargar mantiene el mismo secreto (aún no caducado)
        html2 = cli.get("/mi-password/segundo-factor/activar").get_data(as_text=True)
        self.assertIn(totp.agrupar_secreto(secreto), html2)
        # Código inválido: no activa
        r = cli.post("/mi-password/segundo-factor/activar", data={"csrf": csrf, "codigo": "000000"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("El código no coincide", r.get_data(as_text=True))
        self.assertIsNone(self._fila("activador")["totp_activado_at"])
        # Código válido: activa y muestra 8 códigos una sola vez
        r = cli.post("/mi-password/segundo-factor/activar", data={"csrf": csrf, "codigo": _codigo_actual(secreto)})
        self.assertEqual(r.status_code, 200)
        html = r.get_data(as_text=True)
        self.assertIn("Segundo factor activado", html)
        codigos = re.findall(r"<li>([a-z0-9]{5}-[a-z0-9]{5})</li>", html)
        self.assertEqual(len(codigos), 8)
        self.assertIsNone(RE_STYLE.search(html))
        fila = self._fila("activador")
        self.assertEqual(fila["totp_secret"], secreto)
        self.assertIsNotNone(fila["totp_activado_at"])
        guardado = json.loads(fila["totp_recuperacion"])
        self.assertEqual(len(guardado["codigos"]), 8)
        for entrada in guardado["codigos"]:
            self.assertTrue(entrada["hash"].startswith("$2"), "los códigos se guardan como hash bcrypt")
        self.assertNotIn(codigos[0], fila["totp_recuperacion"])
        self.assertTrue(any(a["username"] == "activador" for a in self._auditoria("2fa.activar")))
        # La sesión actual sigue viva y la página ya muestra el estado
        html = cli.get("/mi-password").get_data(as_text=True)
        self.assertIn("Activo desde", html)
        self.assertIn("8 sin usar", html)
        self.assertIn("Regenerar códigos de recuperación", html)
        # Volver a activar no procede
        self.assertEqual(cli.get("/mi-password/segundo-factor/activar").headers["Location"], "/mi-password")
        # Y el siguiente acceso exige el código
        cli2, r = self._login("activador")
        self.assertEqual(r.headers["Location"], "/login/segundo-factor")

    def test_el_secreto_pendiente_no_viaja_en_la_cookie(self):
        """Hallazgo 2 de la revisión del 2026-09-06.

        El secreto TOTP aún sin confirmar viajaba en la cookie de sesión de Flask,
        que va firmada pero NO cifrada: se leía con un Base64 y servía para generar
        códigos. Ahora vive en el servidor (users.totp_secret con
        users.totp_activado_at NULL, que no cuenta como segundo factor) y en la
        cookie solo queda la marca de tiempo del inicio."""
        cli, _ = self._login("activador2")
        html = self._empezar_activacion(cli).get_data(as_text=True)
        secreto = re.search(r'<p class="mono envolver">([A-Z2-7 ]+)</p>', html).group(1).replace(" ", "")
        csrf = re.search(r'name="csrf" value="([^"]+)"', html).group(1)
        legible = _cookie_legible(self._cookie(cli))
        self.assertNotIn(secreto, legible, "el secreto no puede estar en la cookie")
        for trozo in (secreto[:10], secreto[10:20], secreto[-10:]):
            self.assertNotIn(trozo, legible, "ni siquiera un trozo del secreto")
        # Adaptada el 2026-09-08: la marca de tiempo del inicio ya no viaja en la cookie
        # (sesión opaca en servidor) sino en web_sessions.datos; la cookie no lleva nada.
        self.assertNotIn("totp_activacion_at", legible, "la cookie no lleva ningún dato")
        self.assertIn("totp_activacion_at", _datos_en_servidor(self.ruta, self._cookie(cli)),
                      "la marca de tiempo está en el servidor")
        # El secreto está en el servidor y NO cuenta como segundo factor
        fila = self._fila("activador2")
        self.assertEqual(fila["totp_secret"], secreto)
        self.assertIsNone(fila["totp_activado_at"])
        self.assertFalse(auth.estado_2fa(fila)["activo"])
        with db.session(self.ruta) as conn:
            self.assertEqual(auth.secreto_pendiente_2fa(conn, "activador2"), secreto)
            self.assertEqual(auth.verificar_codigo_2fa(conn, fila, _codigo_actual(secreto)),
                             (False, ""), "un secreto sin confirmar no vale como código")
        # Y mientras no se confirme, el acceso sigue siendo solo con contraseña.
        # Con la política de una sola sesión (2026-09-07) este acceso cierra el de
        # «cli»; además, la activación a medias está atada a la sesión que la empezó
        # (la marca «totp_activacion_at» vive en su cookie), así que al volver a entrar
        # hay que empezarla de nuevo y sale un secreto distinto. Se comprueba también
        # eso: el secreto anterior deja de servir.
        otro, r = self._login("activador2")
        self.assertEqual(r.headers["Location"], "/")
        self.assertEqual(otro.get("/login/segundo-factor").headers["Location"], "/")
        cli, _ = self._login("activador2")
        html = self._empezar_activacion(cli).get_data(as_text=True)
        secreto_nuevo = re.search(r'<p class="mono envolver">([A-Z2-7 ]+)</p>', html).group(1).replace(" ", "")
        csrf = re.search(r'name="csrf" value="([^"]+)"', html).group(1)
        self.assertNotEqual(secreto_nuevo, secreto, "empezar de nuevo debe dar otro secreto")
        secreto = secreto_nuevo
        # Al confirmar, el mismo secreto queda activo y la cookie se vacía
        r = cli.post("/mi-password/segundo-factor/activar",
                     data={"csrf": csrf, "codigo": _codigo_actual(secreto)})
        self.assertEqual(r.status_code, 200)
        self.assertIn("Segundo factor activado", r.get_data(as_text=True))
        fila = self._fila("activador2")
        self.assertEqual(fila["totp_secret"], secreto)
        self.assertIsNotNone(fila["totp_activado_at"])
        self.assertNotIn("totp_activacion_at", _cookie_legible(self._cookie(cli)))
        self.assertNotIn("totp_activacion_at", _datos_en_servidor(self.ruta, self._cookie(cli)),
                         "al confirmar, la marca desaparece también del servidor")
        _, r = self._login("activador2")
        self.assertEqual(r.headers["Location"], "/login/segundo-factor")

    def test_activacion_caducada(self):
        cli, _ = self._login("lector")
        html = self._empezar_activacion(cli).get_data(as_text=True)
        csrf = re.search(r'name="csrf" value="([^"]+)"', html).group(1)
        secreto = re.search(r'<p class="mono envolver">([A-Z2-7 ]+)</p>', html).group(1).replace(" ", "")
        from webui.vistas import sesion as vista
        with mock.patch.object(vista, "time") as reloj:
            reloj.time.return_value = 10 ** 10       # once minutos en el futuro y más
            r = cli.post("/mi-password/segundo-factor/activar", data={"csrf": csrf, "codigo": _codigo_actual(secreto)})
        self.assertEqual(r.headers["Location"], "/mi-password/segundo-factor/activar")
        self.assertIsNone(self._fila("lector")["totp_activado_at"])
        # Al caducar, el secreto sin confirmar se borra del servidor (hallazgo 2)
        self.assertIsNone(self._fila("lector")["totp_secret"])
        with db.session(self.ruta) as conn:
            self.assertIsNone(auth.secreto_pendiente_2fa(conn, "lector"))
        self.assertIn("caducó", cli.get("/mi-password/segundo-factor/activar").get_data(as_text=True))
        # Al volver a empezar se crea un secreto nuevo, distinto del caducado
        self._empezar_activacion(cli)
        nuevo_secreto = self._fila("lector")["totp_secret"]
        self.assertIsNotNone(nuevo_secreto)
        self.assertNotEqual(nuevo_secreto, secreto)

    def _entrar_con_2fa(self, usuario, indice=-1):
        """Entra con un código de recuperación (cada llamada debe usar uno distinto)."""
        cli, _ = self._login(usuario)
        csrf = self._csrf(cli, "/login/segundo-factor")
        r = cli.post("/login/segundo-factor", data={"csrf": csrf, "codigo": self.recuperacion[usuario][indice]})
        self.assertEqual(r.status_code, 302)
        return cli

    def test_regenerar_codigos_exige_contrasena_y_codigo(self):
        """Hallazgos 3 y 4 de la revisión del 2026-09-06.

        «Regenerar los códigos de recuperación» entregaba ocho códigos nuevos solo
        con la contraseña, sin código del segundo factor y sin contar los fallos.
        Ahora exige las dos cosas y los fallos cuentan para el bloqueo."""
        cli = self._entrar_con_2fa("regenera")
        csrf = self._csrf(cli)
        antes = json.loads(self._fila("regenera")["totp_recuperacion"])["codigos"]
        # El formulario pide el código, con su etiqueta visible
        html = cli.get("/mi-password").get_data(as_text=True)
        self.assertIn('<label for="codigo-regenerar">Código de la aplicación o código de recuperación</label>', html)
        self.assertIn('id="codigo-regenerar" name="codigo" required', html)
        self.assertIsNone(RE_STYLE.search(html))
        self.assertIsNone(RE_ON.search(html))
        # Contraseña incorrecta: no se comprueba el código, pero el intento SÍ cuenta y se
        # audita (revisión del 2026-09-06: antes se podían probar contraseñas sin límite
        # ni rastro desde una sesión robada).
        r = cli.post("/mi-password/segundo-factor/codigos",
                     data={"csrf": csrf, "password": "mala", "codigo": _codigo_actual(self.secretos["regenera"])},
                     follow_redirects=True)
        self.assertIn("La contraseña actual no es correcta", r.get_data(as_text=True))
        self.assertEqual(self._fila("regenera")["totp_fallos"], 1,
                         "una contraseña incorrecta también cuenta como intento fallido")
        with db.session(self.ruta) as conn:
            detalle = conn.execute(
                "SELECT detail FROM audit_log WHERE action='2fa.codigos.fallo' ORDER BY id DESC LIMIT 1").fetchone()
        self.assertIn("contrasena incorrecta", detalle["detail"])
        # Contraseña correcta pero sin código: rechazado y se cuenta otro fallo
        r = cli.post("/mi-password/segundo-factor/codigos", data={"csrf": csrf, "password": CLAVE},
                     follow_redirects=True)
        self.assertIn("El código no es válido", r.get_data(as_text=True))
        self.assertEqual(self._fila("regenera")["totp_fallos"], 2)
        self.assertTrue(any("intento 1/" in (a["detail"] or "") for a in self._auditoria("2fa.codigos.fallo")))
        r = cli.post("/mi-password/segundo-factor/codigos",
                     data={"csrf": csrf, "password": CLAVE, "codigo": "000000"}, follow_redirects=True)
        self.assertIn("El código no es válido", r.get_data(as_text=True))
        self.assertEqual(self._fila("regenera")["totp_fallos"], 3)
        self.assertEqual(json.loads(self._fila("regenera")["totp_recuperacion"])["codigos"], antes)
        # Contraseña y código correctos: ocho códigos nuevos y contador a cero
        r = cli.post("/mi-password/segundo-factor/codigos",
                     data={"csrf": csrf, "password": CLAVE, "codigo": _codigo_actual(self.secretos["regenera"])})
        self.assertEqual(r.status_code, 200)
        html = r.get_data(as_text=True)
        self.assertIn("Códigos de recuperación nuevos", html)
        codigos = re.findall(r"<li>([a-z0-9]{5}-[a-z0-9]{5})</li>", html)
        self.assertEqual(len(codigos), 8)
        despues = json.loads(self._fila("regenera")["totp_recuperacion"])["codigos"]
        self.assertNotEqual(despues, antes)
        self.assertEqual(auth.estado_2fa(self._fila("regenera"))["restantes"], 8)
        self.assertEqual(self._fila("regenera")["totp_fallos"], 0, "un acierto reinicia el contador")
        self.assertTrue(self._auditoria("2fa.codigos"))

    def test_los_fallos_de_codigo_al_desactivar_bloquean_la_cuenta(self):
        """Hallazgo 3 de la revisión del 2026-09-06: los códigos incorrectos de
        «Desactivar el segundo factor» no se contaban ni bloqueaban la cuenta, así
        que desde una sesión robada se podían probar sin límite."""
        cli = self._entrar_con_2fa("bloqueodesac")
        csrf = self._csrf(cli)
        self.assertEqual(self._fila("bloqueodesac")["totp_fallos"], 0)
        r = cli.post("/mi-password/segundo-factor/desactivar",
                     data={"csrf": csrf, "password": CLAVE, "codigo": "000000"}, follow_redirects=True)
        self.assertIn("sigue activo", r.get_data(as_text=True))
        self.assertEqual(self._fila("bloqueodesac")["totp_fallos"], 1)
        self.assertTrue(any("intento 1/" in (a["detail"] or "")
                            for a in self._auditoria("2fa.desactivar.fallo")))
        # Un acierto reinicia el contador (aquí con la ruta de códigos, sin desactivar)
        r = cli.post("/mi-password/segundo-factor/codigos",
                     data={"csrf": csrf, "password": CLAVE,
                           "codigo": _codigo_actual(self.secretos["bloqueodesac"])})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self._fila("bloqueodesac")["totp_fallos"], 0)
        # Cinco fallos seguidos: cuenta bloqueada, sesión cerrada, segundo factor intacto
        ultimo = None
        for _ in range(5):
            ultimo = cli.post("/mi-password/segundo-factor/desactivar",
                              data={"csrf": csrf, "password": CLAVE, "codigo": "000000"})
        self.assertEqual(ultimo.status_code, 302)
        self.assertEqual(ultimo.headers["Location"], "/login")
        fila = self._fila("bloqueodesac")
        self.assertGreaterEqual(fila["totp_fallos"], 5)
        self.assertIsNotNone(fila["locked_until"])
        self.assertIsNotNone(fila["totp_activado_at"], "el segundo factor sigue activo")
        self.assertEqual(cli.get("/").headers["Location"].split("?")[0], "/login")
        self.assertIn("bloquead", cli.get("/login").get_data(as_text=True).lower())
        _, r = self._login("bloqueodesac", follow_redirects=True)
        self.assertIn("usuario o contraseña incorrectos", r.get_data(as_text=True).lower())  # 2026-09-08
        with db.session(self.ruta) as conn:
            conn.execute("UPDATE users SET totp_fallos=0, locked_until=NULL WHERE username='bloqueodesac'")

    def test_desactivar_exige_contrasena_y_codigo(self):
        cli = self._entrar_con_2fa("desactiva")
        csrf = self._csrf(cli)
        codigo = _codigo_actual(self.secretos["desactiva"])
        r = cli.post("/mi-password/segundo-factor/desactivar", data={"csrf": csrf, "password": "mala", "codigo": codigo},
                     follow_redirects=True)
        self.assertIn("La contraseña actual no es correcta", r.get_data(as_text=True))
        r = cli.post("/mi-password/segundo-factor/desactivar", data={"csrf": csrf, "password": CLAVE, "codigo": "000000"},
                     follow_redirects=True)
        self.assertIn("sigue activo", r.get_data(as_text=True))
        self.assertIsNotNone(self._fila("desactiva")["totp_activado_at"])
        # Con la política de una sola sesión (2026-09-07) no puede haber otra sesión
        # abierta del mismo usuario: entrar de nuevo ya cierra la anterior. Se comprueba
        # eso y se sigue desactivando desde la sesión que queda viva.
        otra = self._entrar_con_2fa("desactiva", indice=-2)
        self.assertEqual(otra.get("/").status_code, 200)
        self.assertEqual(cli.get("/").headers["Location"].split("?")[0], "/login",
                         "el nuevo acceso debía cerrar la sesión anterior")
        cli, csrf = otra, self._csrf(otra, "/perfil")
        r = cli.post("/mi-password/segundo-factor/desactivar", data={"csrf": csrf, "password": CLAVE, "codigo": codigo},
                     follow_redirects=True)
        self.assertIn("Segundo factor desactivado", r.get_data(as_text=True))
        fila = self._fila("desactiva")
        self.assertIsNone(fila["totp_secret"])
        self.assertIsNone(fila["totp_activado_at"])
        self.assertIsNone(fila["totp_recuperacion"])
        self.assertTrue(self._auditoria("2fa.desactivar"))
        self.assertEqual(cli.get("/").status_code, 200, "la sesión propia se conserva")
        # Con sesión única no puede quedar ninguna otra: se comprueba con la tabla.
        with db.session(self.ruta) as conn:
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM web_sessions WHERE username='desactiva'").fetchone()[0], 1,
                "tras desactivar debe quedar solo la sesión propia")
        _, r = self._login("desactiva")
        self.assertEqual(r.headers["Location"], "/", "vuelve a entrar solo con contraseña")

    # ---- administrador obligado -----------------------------------------------------
    def test_administrador_obligado_por_ajuste(self):
        self._ajuste("mfa_obligatorio_admin", True)
        try:
            cli, r = self._login("jefe")
            self.assertEqual(r.headers["Location"], "/mi-password/segundo-factor/activar")
            for url in ("/", "/usuarios/", "/ajustes/", "/amenazas/"):
                r = cli.get(url)
                self.assertEqual(r.status_code, 302, url)
                self.assertEqual(r.headers["Location"], "/mi-password/segundo-factor/activar", url)
            self.assertEqual(cli.get("/mi-password").status_code, 200)
            html = cli.get("/mi-password").get_data(as_text=True)
            self.assertIn("Los administradores deben tener el segundo factor activado", html)
            html = self._empezar_activacion(cli).get_data(as_text=True)
            # Un lector no está obligado
            lector, r = self._login("lector")
            self.assertEqual(r.headers["Location"], "/")
            self.assertEqual(lector.get("/").status_code, 200)
            # Al activar, el administrador recupera el acceso
            secreto = re.search(r'<p class="mono envolver">([A-Z2-7 ]+)</p>', html).group(1).replace(" ", "")
            csrf = re.search(r'name="csrf" value="([^"]+)"', html).group(1)
            r = cli.post("/mi-password/segundo-factor/activar", data={"csrf": csrf, "codigo": _codigo_actual(secreto)})
            self.assertEqual(r.status_code, 200)
            self.assertEqual(cli.get("/").status_code, 200)
            # Cerrar sesión funciona aun estando obligado (otro administrador sin 2FA)
            admin, _ = self._login("admin")
            csrf = self._csrf(admin)
            self.assertEqual(admin.post("/logout", data={"csrf": csrf}).headers["Location"], "/login")
        finally:
            self._ajuste("mfa_obligatorio_admin", False)
        admin, r = self._login("admin")
        self.assertEqual(r.headers["Location"], "/", "sin el ajuste no se exige")

    # ---- restablecimiento ---------------------------------------------------------------
    def test_restablecer_por_administrador(self):
        admin, _ = self._login("admin")
        html = admin.get("/usuarios/").get_data(as_text=True)
        self.assertIn("Segundo factor</th>", html)
        self.assertIn("Activo desde", html)
        self.assertIn("Restablecer segundo factor", html)
        self.assertIsNone(RE_STYLE.search(html))
        uid = self._fila("restablecido")["id"]
        csrf = re.search(r'name="csrf" value="([^"]+)"', html).group(1)
        # El lector no puede
        lector, _ = self._login("lector")
        csrf_lector = self._csrf(lector)
        self.assertEqual(lector.post(f"/usuarios/{uid}/segundo-factor/restablecer", data={"csrf": csrf_lector}).status_code, 403)
        # Sesión abierta del usuario que será restablecido
        sesion = self._entrar_con_2fa("restablecido")
        self.assertEqual(sesion.get("/").status_code, 200)
        r = admin.post(f"/usuarios/{uid}/segundo-factor/restablecer", data={"csrf": csrf}, follow_redirects=True)
        html = r.get_data(as_text=True)
        self.assertIn("Segundo factor de restablecido restablecido", html)
        fila = self._fila("restablecido")
        self.assertIsNone(fila["totp_secret"])
        self.assertIsNone(fila["totp_activado_at"])
        self.assertIsNone(fila["totp_recuperacion"])
        self.assertEqual(sesion.get("/").status_code, 302, "sus sesiones se revocan")
        auditoria = self._auditoria("2fa.restablecer")
        self.assertTrue(any(a["username"] == "admin" for a in auditoria))
        # Repetir sobre alguien sin segundo factor: mensaje claro, sin error
        r = admin.post(f"/usuarios/{uid}/segundo-factor/restablecer", data={"csrf": csrf}, follow_redirects=True)
        self.assertIn("no tiene el segundo factor activado", r.get_data(as_text=True))
        _, r = self._login("restablecido")
        self.assertEqual(r.headers["Location"], "/")

    def test_administrador_no_restablece_su_propio_segundo_factor(self):
        """Hallazgo 2: el propio se desactiva solo con contraseña y código."""
        cli = self._entrar_con_2fa("jefa2fa")
        uid = self._fila("jefa2fa")["id"]
        html = cli.get("/usuarios/").get_data(as_text=True)
        fila_html = re.search(r"<tr>\s*<td>\s*jefa2fa.*?</tr>", html, re.S).group(0)
        self.assertNotIn(f"/usuarios/{uid}/segundo-factor/restablecer", fila_html)
        self.assertIn("Mi segundo factor", fila_html)
        self.assertIn('href="/mi-password"', fila_html)
        csrf = re.search(r'name="csrf" value="([^"]+)"', html).group(1)
        r = cli.post(f"/usuarios/{uid}/segundo-factor/restablecer", data={"csrf": csrf}, follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        self.assertIn("No puede restablecer su propio segundo factor", r.get_data(as_text=True))
        fila = self._fila("jefa2fa")
        self.assertIsNotNone(fila["totp_activado_at"])
        self.assertIsNotNone(fila["totp_secret"])
        self.assertEqual(cli.get("/").status_code, 200, "su sesión no se toca")
        self.assertTrue(any(a["username"] == "jefa2fa" for a in self._auditoria("2fa.restablecer.rechazado")))
        self.assertFalse(any(str(a["entity_id"]) == str(uid) for a in self._auditoria("2fa.restablecer")))
        # Sí puede restablecer el de OTRO usuario
        otro = self._fila("con2fa")["id"]
        self.assertIn(f"/usuarios/{otro}/segundo-factor/restablecer", html)

    def _modulo_consola(self):
        ruta_bin = BASE_DIR / "bin" / "gestionar_usuario.py"
        spec = importlib.util.spec_from_file_location("gestionar_usuario_prueba", ruta_bin)
        modulo = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(modulo)
        return modulo

    def _consola(self, modulo, *argumentos):
        ruta = self.ruta
        sesion_real = db.session
        conectar_real = db.connect
        salida = io.StringIO()
        with mock.patch.object(modulo.db, "init_db", lambda *a, **k: None), \
                mock.patch.object(modulo.db, "session", lambda path=None: sesion_real(ruta)), \
                mock.patch.object(modulo.db, "connect", lambda path=None: conectar_real(ruta)), \
                mock.patch.object(modulo.sys, "argv", ["gestionar_usuario.py", *argumentos]), \
                redirect_stdout(salida):
            codigo = modulo.main()
        return codigo, salida.getvalue()

    def test_desbloquear_reinicia_los_fallos_del_segundo_factor_por_consola(self):
        """Hallazgo 3 y 6: «desbloquear» reinicia totp_fallos; «listar» dice «Segundo factor» y «sí»."""
        uid = self._fila("desbloqueado")["id"]
        with db.session(self.ruta) as conn:
            conn.execute("UPDATE users SET failed_logins=2, totp_fallos=4, locked_until='2099-01-01T00:00:00Z' WHERE id=?", (uid,))
        modulo = self._modulo_consola()
        codigo, salida = self._consola(modulo, "desbloquear", "desbloqueado")
        self.assertEqual(codigo, 0)
        self.assertIn("desbloqueado", salida)
        fila = self._fila("desbloqueado")
        self.assertEqual((fila["failed_logins"], fila["totp_fallos"], fila["locked_until"]), (0, 0, None))
        codigo, salida = self._consola(modulo, "listar")
        self.assertEqual(codigo, 0)
        self.assertIn("SEGUNDO FACTOR", salida)
        self.assertNotIn("2FA", salida)
        self.assertIn("ÚLTIMO ACCESO", salida)
        linea = next(l for l in salida.splitlines() if l.strip().startswith("desbloqueado"))
        self.assertTrue(linea.rstrip().endswith("sí"), linea)
        linea = next(l for l in salida.splitlines() if l.strip().startswith("lector"))
        self.assertTrue(linea.rstrip().endswith("no"), linea)

    def test_restablecer_por_consola(self):
        ruta_bin = BASE_DIR / "bin" / "gestionar_usuario.py"
        spec = importlib.util.spec_from_file_location("gestionar_usuario_prueba", ruta_bin)
        modulo = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(modulo)
        ruta = self.ruta
        sesion_real = db.session
        salida = io.StringIO()
        with mock.patch.object(modulo.db, "init_db", lambda *a, **k: None), \
                mock.patch.object(modulo.db, "session", lambda path=None: sesion_real(ruta)), \
                mock.patch.object(modulo.sys, "argv", ["gestionar_usuario.py", "2fa-restablecer", "consola"]), \
                redirect_stdout(salida):
            codigo = modulo.main()
        self.assertEqual(codigo, 0)
        self.assertIn("Segundo factor de 'consola' restablecido", salida.getvalue())
        self.assertIsNone(self._fila("consola")["totp_activado_at"])
        self.assertTrue(any(a["username"] == "cli" for a in self._auditoria("2fa.restablecer")))
        salida = io.StringIO()
        with mock.patch.object(modulo.db, "init_db", lambda *a, **k: None), \
                mock.patch.object(modulo.db, "session", lambda path=None: sesion_real(ruta)), \
                mock.patch.object(modulo.sys, "argv", ["gestionar_usuario.py", "2fa-restablecer", "noexiste"]), \
                redirect_stdout(salida):
            codigo = modulo.main()
        self.assertEqual(codigo, 1)
        self.assertIn("No existe el usuario", salida.getvalue())


if __name__ == "__main__":
    unittest.main()

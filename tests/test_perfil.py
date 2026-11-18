"""Cambio de contraseña obligatorio y apartado de perfil (2026-09-07).

Tres peticiones del usuario y un fallo grave de seguridad:

  (a) «Cuando un usuario ingresa por primera vez y lo lleva a cambiar de clave, veo
      que le da acceso directamente a la plataforma y eso no debería ser así.» El
      fallo estaba en que `webui.vistas.sesion._tras_acceso` redirigía al formulario
      de contraseña cuando `users.must_change` valía 1, pero el decorador
      `webui.auth.requiere_login` NO lo comprobaba: bastaba escribir «/»,
      «/activos/» o «/amenazas/» para entrar con la contraseña inicial, que conoce
      quien creó la cuenta (A07:2025). Reproducido antes de corregirlo: las seis
      direcciones devolvían 200. Aquí queda fijado que redirigen a la pantalla
      bloqueante /cambiar-contrasena y que ninguna ruta de la aplicación devuelve 200.
  (b) «El botón de contraseña que se encuentra en la parte superior derecha no
      debería existir; se debe crear un apartado para consultar el usuario de cada
      persona… además se debe tener y contar con el registro de último inicio de
      sesión de cada usuario.» → /perfil.
  (c) «Que haya también un apartado en el perfil de cada usuario para que active el
      OTP para el MFA.» → el panel del segundo factor vive en el perfil.

Sin red y con base temporal bajo data/."""
from __future__ import annotations

import re
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from pathlib import Path

from threatintel import db
from threatintel.paths import BASE_DIR
from webui import auth

CLAVE = "Clave#Segura2026"
INICIAL = "Inicial#Clave2026"
NUEVA = "Recien#Puesta2026"
#: Rutas que de verdad no exigen sesión completa, así que no entran en el barrido
#: del bloqueo: los ficheros estáticos, el acceso, el segundo factor del acceso,
#: salir, la propia pantalla del cambio obligatorio y la dirección histórica que
#: reenvía a ella.
FUERA_DEL_BARRIDO = {"static", "auth.login", "auth.segundo_factor", "auth.logout",
                     "auth.cambiar_contrasena", "auth.mi_password",
                     # El logo es la imagen de marca, no un dato de la plataforma: se ve
                     # igual en el login (antes de iniciar sesión) que ya dentro, como el
                     # favicon (que tampoco exige sesión). Sin sesión, sin logo subido,
                     # responde 404; nunca 200 con contenido de la plataforma.
                     "ajustes.logo"}

#: HUECO CONOCIDO, pendiente de una corrección en un fichero del coordinador.
#:
#: /salud.json (webui/vistas/panel.py) NO usa @auth.requiere_login: comprueba el
#: token de Zabbix y, si no hay HEALTH_TOKEN configurado, se conforma con que haya
#: sesión. Por eso un usuario con users.must_change=1 puede leer las métricas, y por
#: eso queda fuera del barrido. NO es que «no exija sesión completa»: es un hueco
#: real, comprobado el 2026-09-07, y HEALTH_TOKEN no está configurado en producción.
#:
#: La corrección es de una línea en webui/vistas/panel.py (fichero del coordinador):
#:     elif not auth.usuario_actual() or auth.cambio_password_obligatorio():
#: Cuando se aplique, quítese esta lista y vuelva /salud.json al barrido general;
#: test_hueco_conocido_de_salud_json describe los dos comportamientos.
HUECO_PENDIENTE = {"panel.salud_json"}


class _Atributos(HTMLParser):
    """Atributos reales de cada etiqueta: un «onerror=» dentro de un texto escapado
    no es un atributo y no debe contar como incumplimiento de la CSP."""

    def __init__(self):
        super().__init__()
        self.peligrosos: list[str] = []

    def handle_starttag(self, tag, attrs):
        for nombre, _valor in attrs:
            n = (nombre or "").lower()
            if n == "style" or n.startswith("on"):
                self.peligrosos.append(f"<{tag} {n}>")


def atributos_peligrosos(html: str) -> list[str]:
    p = _Atributos()
    p.feed(html)
    return p.peligrosos


def _hace_dias(dias: int) -> str:
    return ((datetime.now(timezone.utc) - timedelta(days=dias, hours=1))
            .replace(microsecond=0).isoformat().replace("+00:00", "Z"))


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "perfil.db")
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "ana@ejemplo.local", CLAVE, rol="admin", actor="t")
            auth.crear_usuario(conn, "luis@ejemplo.local", CLAVE, rol="ciberseguridad", actor="t")
            auth.crear_usuario(conn, "sinnombre@ejemplo.local", CLAVE, rol="ciberseguridad", actor="t")
            auth.crear_usuario(conn, "cambio@ejemplo.local", CLAVE, rol="ciberseguridad", actor="t")
            auth.crear_usuario(conn, "fuerza@ejemplo.local", CLAVE, rol="ciberseguridad", actor="t")
            auth.crear_usuario(conn, "apagado@ejemplo.local", CLAVE, rol="ciberseguridad", actor="t")
            auth.crear_usuario(conn, "minutos@ejemplo.local", CLAVE, rol="ciberseguridad", actor="t")
            for nombre in ("bloqueo", "guardar", "orden", "salir", "historica",
                           "renueva", "avisos", "metricas"):
                auth.crear_usuario(conn, f"{nombre}@ejemplo.local", INICIAL, rol="admin",
                                   must_change=True, actor="t")
            conn.execute("UPDATE users SET nombre='Ana Gómez Ruiz' WHERE username='ana@ejemplo.local'")
            conn.execute("UPDATE users SET nombre='Luis Peña Ríos' WHERE username='luis@ejemplo.local'")
            conn.execute("UPDATE users SET nombre='Marta Cruz' WHERE username='guardar@ejemplo.local'")
            conn.execute("UPDATE users SET nombre='Rosa Díaz' WHERE username='cambio@ejemplo.local'")
            # Un acceso de hace tres días en la auditoría, para el «hace N días»
            db.audit(conn, "luis@ejemplo.local", "login.ok", "users", "luis@ejemplo.local",
                     None, "10.1.1.45")
            conn.execute("UPDATE audit_log SET at=? WHERE username='luis@ejemplo.local' AND action='login.ok'",
                         (_hace_dias(3),))
            conn.execute("UPDATE users SET last_login_at=? WHERE username='ana@ejemplo.local'",
                         (_hace_dias(3),))
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    # ---- utilidades ------------------------------------------------------
    def _login(self, usuario, clave=CLAVE, **kw):
        cli = self.app.test_client()
        r = cli.post("/login", data={"usuario": usuario, "password": clave}, **kw)
        return cli, r

    def _csrf(self, cli, url):
        cuerpo = cli.get(url).get_data(as_text=True)
        encontrado = re.search(r'name="csrf" value="([^"]+)"', cuerpo)
        self.assertIsNotNone(encontrado, f"{url} no trae token CSRF")
        return encontrado.group(1)

    def _fila(self, usuario):
        with db.session(self.ruta) as conn:
            return dict(conn.execute("SELECT * FROM users WHERE username=?", (usuario,)).fetchone())

    def _ajuste(self, clave, valor):
        with db.session(self.ruta) as conn:
            db.set_setting(conn, clave, valor)

    def _auditoria(self, accion, usuario=None):
        with db.session(self.ruta) as conn:
            if usuario:
                filas = conn.execute("SELECT * FROM audit_log WHERE action=? AND username=? ORDER BY id",
                                     (accion, usuario))
            else:
                filas = conn.execute("SELECT * FROM audit_log WHERE action=? ORDER BY id", (accion,))
            return [dict(f) for f in filas]

    def _urls_de_la_aplicacion(self):
        """Todas las rutas GET de la aplicación que exigen sesión completa."""
        from flask import url_for
        urls = []
        for regla in self.app.url_map.iter_rules():
            if (regla.endpoint in FUERA_DEL_BARRIDO
                    or regla.endpoint in HUECO_PENDIENTE
                    or "GET" not in regla.methods):
                continue
            valores = {}
            for arg in regla.arguments:
                valores[arg] = 1 if regla._converters[arg].__class__.__name__ == "IntegerConverter" else "x"
            with self.app.test_request_context():
                urls.append(url_for(regla.endpoint, **valores))
        return sorted(set(urls))


class TestCambioObligatorioBloqueante(_Base):
    """(a) Con users.must_change=1 no se accede a NADA salvo a la propia pantalla."""

    def test_ninguna_ruta_de_la_plataforma_es_accesible(self):
        cli, r = self._login("bloqueo@ejemplo.local", INICIAL)
        self.assertEqual(r.status_code, 302)
        # Las direcciones exactas que el usuario probó a mano
        for url in ("/", "/activos/", "/amenazas/", "/usuarios/", "/ajustes/",
                    "/remediaciones/", "/perfil"):
            respuesta = cli.get(url)
            self.assertEqual(respuesta.status_code, 302, f"{url} deja entrar")
            self.assertEqual(respuesta.headers["Location"], "/cambiar-contrasena", url)
            self.assertNotEqual(respuesta.status_code, 200, url)
        # Y ninguna otra ruta de la aplicación, presente o futura
        for url in self._urls_de_la_aplicacion():
            respuesta = cli.get(url)
            self.assertEqual(respuesta.status_code, 302, f"{url} deja entrar")
            self.assertEqual(respuesta.headers["Location"], "/cambiar-contrasena", url)
        # Siguiendo la redirección se llega a la pantalla, no a la plataforma
        html = cli.get("/", follow_redirects=True).get_data(as_text=True)
        self.assertIn("Cambie su contraseña para continuar", html)
        self.assertIn("Debe cambiar la contraseña antes de continuar.", html)

    def test_la_pantalla_esta_aislada_de_la_interfaz(self):
        cli, _ = self._login("bloqueo@ejemplo.local", INICIAL)
        respuesta = cli.get("/cambiar-contrasena")
        self.assertEqual(respuesta.status_code, 200)
        html = respuesta.get_data(as_text=True)
        for prohibido in ("nav-lateral", "barra-superior", "busqueda-global",
                          "data-tour", "data-iniciar-tour", "sesion-usuario"):
            self.assertNotIn(prohibido, html, f"la pantalla no debe traer {prohibido}")
        self.assertIn('name="nueva"', html)
        self.assertIn('name="repetir"', html)
        self.assertIn("Guardar y entrar", html)
        self.assertIn("doce caracteres", html)
        self.assertIn("Salir sin cambiarla", html)
        self.assertIn('action="/logout"', html)
        self.assertEqual(atributos_peligrosos(html), [], "style= u on*= en la pantalla")
        self.assertIn("no-store", respuesta.headers.get("Cache-Control", ""))

    def test_salir_funciona_aunque_no_haya_cambiado_la_contrasena(self):
        cli, _ = self._login("salir@ejemplo.local", INICIAL)
        csrf = self._csrf(cli, "/cambiar-contrasena")
        r = cli.post("/logout", data={"csrf": csrf})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers["Location"], "/login")
        self.assertEqual(cli.get("/").headers["Location"].split("?")[0], "/login")
        self.assertEqual(self._fila("salir@ejemplo.local")["must_change"], 1)

    def test_contrasena_que_no_cumple_la_politica_se_rechaza(self):
        cli, _ = self._login("bloqueo@ejemplo.local", INICIAL)
        csrf = self._csrf(cli, "/cambiar-contrasena")
        casos = {
            "Corta#1a": "Debe tener al menos 12 caracteres.",
            "abcdefghijklm": "Debe combinar al menos tres de: minúsculas, mayúsculas, dígitos y símbolos.",
        }
        for clave, mensaje in casos.items():
            r = cli.post("/cambiar-contrasena", data={"csrf": csrf, "nueva": clave, "repetir": clave},
                         follow_redirects=True)
            self.assertEqual(r.status_code, 200)
            self.assertIn(mensaje, r.get_data(as_text=True), clave)
            self.assertEqual(self._fila("bloqueo@ejemplo.local")["must_change"], 1, clave)
        # Repetición distinta
        r = cli.post("/cambiar-contrasena",
                     data={"csrf": csrf, "nueva": NUEVA, "repetir": NUEVA + "x"},
                     follow_redirects=True)
        self.assertIn("Las contraseñas nuevas no coinciden.", r.get_data(as_text=True))
        self.assertEqual(self._fila("bloqueo@ejemplo.local")["must_change"], 1)
        # La contraseña sigue siendo la inicial y sigue sin dar acceso
        self.assertEqual(cli.get("/").headers["Location"], "/cambiar-contrasena")

    def test_no_se_puede_repetir_la_contrasena_actual(self):
        cli, _ = self._login("bloqueo@ejemplo.local", INICIAL)
        csrf = self._csrf(cli, "/cambiar-contrasena")
        r = cli.post("/cambiar-contrasena", data={"csrf": csrf, "nueva": INICIAL, "repetir": INICIAL},
                     follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        self.assertIn("La contraseña nueva es la misma que la actual.", r.get_data(as_text=True))
        self.assertEqual(self._fila("bloqueo@ejemplo.local")["must_change"], 1)
        self.assertEqual(cli.get("/").headers["Location"], "/cambiar-contrasena")

    def test_sin_token_csrf_no_se_cambia(self):
        cli, _ = self._login("bloqueo@ejemplo.local", INICIAL)
        r = cli.post("/cambiar-contrasena", data={"nueva": NUEVA, "repetir": NUEVA})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self._fila("bloqueo@ejemplo.local")["must_change"], 1)

    def test_al_guardar_entra_revoca_las_demas_sesiones_y_queda_auditado(self):
        usuario = "guardar@ejemplo.local"
        # Desde el 2026-09-07 la plataforma admite UNA sola sesión por usuario, así que
        # el segundo acceso ya cierra el primero: aquí se comprueba que el cambio de
        # contraseña conserva la sesión que lo hace y no deja ninguna otra abierta.
        otra, _ = self._login(usuario, INICIAL)
        cli, _ = self._login(usuario, INICIAL)
        self.assertEqual(otra.get("/").headers["Location"].split("?")[0], "/login",
                         "el segundo acceso debía cerrar el primero (sesión única)")
        with db.session(self.ruta) as conn:
            abiertas = conn.execute("SELECT COUNT(*) FROM web_sessions WHERE username=?",
                                    (usuario,)).fetchone()[0]
        self.assertEqual(abiertas, 1)

        csrf = self._csrf(cli, "/cambiar-contrasena")
        r = cli.post("/cambiar-contrasena", data={"csrf": csrf, "nueva": NUEVA, "repetir": NUEVA})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers["Location"], "/")
        # Entra de verdad: la plataforma responde 200 y el aviso lo dice
        html = cli.get("/", follow_redirects=True).get_data(as_text=True)
        self.assertIn("Contraseña actualizada. Ya puede usar la plataforma.", html)
        self.assertEqual(cli.get("/activos/").status_code, 200)
        self.assertEqual(cli.get("/perfil").status_code, 200)

        fila = self._fila(usuario)
        self.assertEqual(fila["must_change"], 0)
        self.assertTrue(auth.verificar_password(NUEVA, fila["password_hash"]))
        self.assertFalse(auth.verificar_password(INICIAL, fila["password_hash"]))
        # Solo queda la sesión que hizo el cambio
        with db.session(self.ruta) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM web_sessions WHERE username=?",
                                          (usuario,)).fetchone()[0], 1)
        # Auditoría: el cambio obligatorio y el cambio de contraseña
        obligatorio = self._auditoria("password.cambio_obligatorio", usuario)
        self.assertTrue(obligatorio, "el cambio obligatorio debe quedar auditado")
        self.assertIn("sesiones", obligatorio[-1]["detail"])
        self.assertTrue(any(a["entity_id"] == usuario for a in self._auditoria("usuario.password")))
        # Y ya no vuelve a pedirse
        cli2, r2 = self._login(usuario, NUEVA)
        self.assertEqual(r2.headers["Location"], "/")
        self.assertEqual(cli2.get("/").status_code, 200)

    def test_primero_la_contrasena_y_despues_el_segundo_factor(self):
        usuario = "orden@ejemplo.local"
        self._ajuste("mfa_obligatorio_admin", True)
        try:
            cli, r = self._login(usuario, INICIAL)
            self.assertEqual(r.status_code, 302)
            # Ni siquiera la activación del segundo factor: primero la contraseña
            self.assertEqual(cli.get("/mi-password/segundo-factor/activar").headers["Location"],
                             "/cambiar-contrasena")
            csrf = self._csrf(cli, "/cambiar-contrasena")
            r = cli.post("/cambiar-contrasena", data={"csrf": csrf, "nueva": NUEVA, "repetir": NUEVA})
            self.assertEqual(r.headers["Location"], "/")
            # Ahora sí toca el segundo factor obligatorio
            self.assertEqual(cli.get("/").headers["Location"], "/mi-password/segundo-factor/activar")
            self.assertEqual(cli.get("/mi-password/segundo-factor/activar").status_code, 200)
            self.assertEqual(self._fila(usuario)["must_change"], 0)
        finally:
            self._ajuste("mfa_obligatorio_admin", False)

    def test_la_direccion_historica_tambien_lleva_a_la_pantalla(self):
        cli, r = self._login("historica@ejemplo.local", INICIAL)
        self.assertEqual(r.headers["Location"], "/mi-password")
        respuesta = cli.get("/mi-password")
        self.assertEqual(respuesta.status_code, 302)
        self.assertEqual(respuesta.headers["Location"], "/cambiar-contrasena")

    def test_un_administrador_que_restablece_bloquea_la_sesion_abierta(self):
        """El valor se lee en cada petición: si un administrador marca must_change
        mientras la persona está dentro, su sesión queda en la pantalla del cambio."""
        cli, _ = self._login("luis@ejemplo.local")
        self.assertEqual(cli.get("/").status_code, 200)
        with db.session(self.ruta) as conn:
            conn.execute("UPDATE users SET must_change=1 WHERE username='luis@ejemplo.local'")
        try:
            self.assertEqual(cli.get("/").headers["Location"], "/cambiar-contrasena")
        finally:
            with db.session(self.ruta) as conn:
                conn.execute("UPDATE users SET must_change=0 WHERE username='luis@ejemplo.local'")

    def test_la_pantalla_no_se_muestra_a_quien_no_debe_cambiarla(self):
        cli, _ = self._login("ana@ejemplo.local")
        r = cli.get("/cambiar-contrasena")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers["Location"], "/perfil")

    def test_el_aviso_no_se_repite_por_cada_ruta_bloqueada(self):
        """Hallazgo bajo del revisor: el navegador pide varias direcciones bloqueadas
        (pestañas abiertas, recursos) y cada una encolaba el mismo aviso, así que la
        pantalla mostraba el recuadro tres o cuatro veces."""
        cli, _ = self._login("avisos@ejemplo.local", INICIAL)
        for url in ("/", "/activos/", "/amenazas/", "/usuarios/"):
            self.assertEqual(cli.get(url).status_code, 302, url)
        html = cli.get("/cambiar-contrasena").get_data(as_text=True)
        self.assertEqual(html.count("Debe cambiar la contraseña antes de continuar."), 1,
                         "el mismo aviso no debe apilarse")

    def test_al_guardar_se_renueva_el_identificador_de_sesion(self):
        """Hallazgo bajo del revisor: la sesión pasa de «solo ve una pantalla» a
        «acceso completo», así que no debe conservar el identificador con el que se
        entró usando la contraseña del administrador (fijación de sesión, A07:2025).
        Es la misma defensa que ya tenía el segundo factor."""
        usuario = "renueva@ejemplo.local"
        cli, _ = self._login(usuario, INICIAL)
        # Adaptada el 2026-09-08: con la sesión opaca en servidor el identificador ya no
        # es una clave del diccionario de sesión sino el propio token de la cookie
        # (session.sid); en la base solo está su hash. Se compara el token.
        antes = cli.get_cookie("session").value
        self.assertTrue(antes)
        with cli.session_transaction() as sesion:
            self.assertEqual(sesion.sid, antes)
            self.assertNotIn(auth.SESION_SID, sesion, "el token no se guarda como dato")
        csrf_antes = self._csrf(cli, "/cambiar-contrasena")
        r = cli.post("/cambiar-contrasena", data={"csrf": csrf_antes, "nueva": NUEVA,
                                                  "repetir": NUEVA})
        self.assertEqual(r.status_code, 302)
        despues = cli.get_cookie("session").value
        self.assertTrue(despues)
        self.assertNotEqual(antes, despues, "el identificador de sesión debe cambiar")
        # El token CSRF también es nuevo, y la sesión sigue sirviendo
        self.assertEqual(cli.get("/perfil").status_code, 200)
        self.assertNotEqual(self._csrf(cli, "/perfil"), csrf_antes,
                            "el token CSRF debe renovarse con el identificador")
        # Y sigue habiendo UNA sola sesión de este usuario
        with db.session(self.ruta) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM web_sessions WHERE username=?",
                                          (usuario,)).fetchone()[0], 1)

    def test_una_cuenta_deshabilitada_pierde_la_sesion(self):
        """Hallazgo bajo del revisor: requiere_login no comprobaba users.enabled, así
        que una cuenta deshabilitada escribiendo en la base seguía navegando (A01:2025).
        Ahora se lee en la misma consulta que users.must_change."""
        usuario = "apagado@ejemplo.local"
        cli, _ = self._login(usuario)
        self.assertEqual(cli.get("/perfil").status_code, 200)
        with db.session(self.ruta) as conn:
            conn.execute("UPDATE users SET enabled=0 WHERE username=?", (usuario,))
        try:
            for url in ("/perfil", "/", "/activos/"):
                respuesta = cli.get(url)
                self.assertEqual(respuesta.status_code, 302, url)
                self.assertEqual(respuesta.headers["Location"].split("?")[0], "/login", url)
            html = cli.get("/", follow_redirects=True).get_data(as_text=True)
            self.assertIn("La cuenta está deshabilitada.", html)
            # Y tampoco puede completar el cambio obligatorio para entrar
            with db.session(self.ruta) as conn:
                conn.execute("UPDATE users SET must_change=1 WHERE username=?", (usuario,))
            self.assertEqual(cli.get("/cambiar-contrasena").headers["Location"].split("?")[0],
                             "/login")
        finally:
            with db.session(self.ruta) as conn:
                conn.execute("UPDATE users SET enabled=1, must_change=0 WHERE username=?",
                             (usuario,))

    def test_salud_json_no_atiende_a_quien_debe_cambiar_la_contrasena(self):
        """/salud.json no lleva @auth.requiere_login: comprueba el token de Zabbix y,
        sin HEALTH_TOKEN configurado, se conformaba con que hubiera sesión. Era el único
        hueco del control: un usuario con must_change=1 leía las métricas.

        Cerrado por el coordinador el 2026-09-07 (webui/vistas/panel.py) exigiendo
        además que la sesión no esté pendiente de cambiar la contraseña ni la cuenta
        deshabilitada. Esta prueba vigila que no se reabra."""
        cli, _ = self._login("metricas@ejemplo.local", INICIAL)
        respuesta = cli.get("/salud.json")
        self.assertEqual(respuesta.status_code, 403,
                         "HUECO REABIERTO: /salud.json atiende a un usuario con "
                         "users.must_change=1 (webui/vistas/panel.py)")
        self.assertNotIn(b"activos", respuesta.data)

    def test_anonimo_va_al_acceso(self):
        anonimo = self.app.test_client()
        for metodo in ("get", "post"):
            r = getattr(anonimo, metodo)("/cambiar-contrasena")
            self.assertEqual(r.status_code, 302, metodo)
            self.assertIn("/login", r.headers["Location"], metodo)


class TestPerfil(_Base):
    """(b) y (c): el apartado de perfil con identidad, accesos, contraseña y 2FA."""

    def test_quien_soy_y_ultimo_acceso(self):
        cli, _ = self._login("ana@ejemplo.local")
        html = cli.get("/perfil").get_data(as_text=True)
        self.assertIn("Mi perfil", html)
        self.assertIn("Ana Gómez Ruiz", html)          # nombre de la persona, no el correo
        self.assertIn("ana@ejemplo.local", html)          # y el correo de acceso
        self.assertIn("Administrador", html)
        self.assertIn("Cuenta creada", html)
        self.assertIn("Último inicio de sesión", html)
        self.assertIn("Sesiones abiertas", html)
        self.assertIn("Intentos fallidos", html)
        self.assertIn("Cuenta bloqueada", html)
        self.assertEqual(atributos_peligrosos(html), [], "style= u on*= en el perfil")
        # Recorrido guiado para alguien nuevo: al menos cuatro pasos
        pasos = re.findall(r'data-tour="(\d+)"[^>]*data-tour-titulo="([^"]+)"[^>]*data-tour-texto="([^"]+)"', html)
        self.assertGreaterEqual(len(pasos), 4)
        for _n, titulo, texto in pasos:
            self.assertGreater(len(texto), 40, titulo)

    def test_el_ultimo_acceso_se_lee_del_registro(self):
        """El usuario pidió «contar con el registro de último inicio de sesión de
        cada usuario»: fecha y hora en español, «hace N días» y la lista de audit_log."""
        cliente = self.app.test_client()
        cliente.post("/login", data={"usuario": "luis@ejemplo.local", "password": "no-es-la-suya"})
        cli, _ = self._login("luis@ejemplo.local")
        html = cli.get("/perfil").get_data(as_text=True)
        self.assertIn("Registro de mis accesos", html)
        self.assertIn("Acceso completado", html)
        self.assertIn("Intento fallido", html)
        self.assertIn("Dirección de red", html)
        # Fecha en español y tiempo relativo
        self.assertRegex(html, r"\d+ de (enero|febrero|marzo|abril|mayo|junio|julio|agosto|"
                               r"septiembre|octubre|noviembre|diciembre) de 20\d\d")
        self.assertIn("hace ", html)
        # El acceso de hace tres días se describe con «hace 3 días» y con su dirección
        self.assertIn("hace 3 días", html)
        self.assertIn("10.1.1.45", html)
        # Y el último inicio de sesión es el de ahora mismo
        self.assertIn("Último inicio de sesión", html)
        self.assertIn("hace unos segundos", html)

    def test_el_perfil_solo_ensena_lo_propio(self):
        cli, _ = self._login("luis@ejemplo.local")
        html = cli.get("/perfil").get_data(as_text=True)
        self.assertIn("Luis Peña Ríos", html)
        self.assertIn("Ciberseguridad", html)
        for ajeno in ("Ana Gómez Ruiz", "ana@ejemplo.local", "Marta Cruz", "guardar@ejemplo.local"):
            self.assertNotIn(ajeno, html, f"el perfil no debe mostrar datos de {ajeno}")

    def test_sin_nombre_se_muestra_el_correo_con_una_nota(self):
        cli, _ = self._login("sinnombre@ejemplo.local")
        html = cli.get("/perfil").get_data(as_text=True)
        self.assertIn("sinnombre@ejemplo.local", html)
        self.assertIn("Todavía no consta su nombre", html)
        self.assertIn("Un administrador puede completarlo", html)

    def test_el_segundo_factor_se_activa_desde_el_perfil(self):
        cli, _ = self._login("luis@ejemplo.local")
        html = cli.get("/perfil").get_data(as_text=True)
        self.assertIn("Segundo factor de autenticación", html)
        self.assertIn("No activado", html)
        self.assertIn('action="/mi-password/segundo-factor/activar"', html)
        self.assertIn("Microsoft Authenticator", html)
        self.assertIn("códigos de recuperación", html)

    def test_la_contrasena_se_cambia_desde_el_perfil(self):
        usuario = "cambio@ejemplo.local"
        cli, _ = self._login(usuario)
        csrf = self._csrf(cli, "/perfil")
        # La actual mal escrita no cambia nada
        r = cli.post("/perfil", data={"csrf": csrf, "actual": "no-es", "nueva": NUEVA,
                                      "repetir": NUEVA}, follow_redirects=True)
        self.assertIn("La contraseña actual no es correcta.", r.get_data(as_text=True))
        # Repetir la actual tampoco
        r = cli.post("/perfil", data={"csrf": csrf, "actual": CLAVE, "nueva": CLAVE,
                                      "repetir": CLAVE}, follow_redirects=True)
        self.assertIn("La contraseña nueva es la misma que la actual.", r.get_data(as_text=True))
        # Bien escrita: se cambia y se cierran TODAS las sesiones (también esta)
        r = cli.post("/perfil", data={"csrf": csrf, "actual": CLAVE, "nueva": NUEVA,
                                      "repetir": NUEVA})
        self.assertEqual(r.status_code, 302)
        self.assertTrue(auth.verificar_password(NUEVA, self._fila(usuario)["password_hash"]))
        self.assertEqual(cli.get("/perfil").headers["Location"].split("?")[0], "/login")
        cli2, r2 = self._login(usuario, NUEVA)
        self.assertEqual(cli2.get("/perfil").status_code, 200)

    def test_la_direccion_historica_muestra_el_mismo_perfil(self):
        """/mi-password se conserva para no romper enlaces ni marcadores: enseña el
        perfil. Al quitar del todo la dirección antigua bastará con redirigirla."""
        cli, _ = self._login("ana@ejemplo.local")
        respuesta = cli.get("/mi-password")
        self.assertEqual(respuesta.status_code, 200)
        html = respuesta.get_data(as_text=True)
        self.assertIn("Mi perfil", html)
        self.assertIn("Registro de mis accesos", html)
        self.assertIn("Ana Gómez Ruiz", html)
        self.assertEqual(atributos_peligrosos(html), [])

    def test_el_detalle_de_la_auditoria_se_muestra_en_espanol(self):
        """Hallazgo medio del revisor: la columna «Detalle» volcaba audit_log.detail
        tal cual y los detalles históricos se escribieron sin tildes, así que la
        interfaz mostraba «contrasena incorrecta (intento 1/5)» a cada persona."""
        usuario = "tildes@ejemplo.local"
        with db.session(self.ruta) as conn:
            if conn.execute("SELECT 1 FROM users WHERE username=?", (usuario,)).fetchone() is None:
                auth.crear_usuario(conn, usuario, CLAVE, rol="ciberseguridad", actor="t")
            # Una fila ANTIGUA, escrita antes de la corrección, como las de la base real
            db.audit(conn, None, "login.fallo", "users", usuario,
                     "contrasena incorrecta (intento 1/5)", "10.1.1.77")
        # Y un intento de ahora, que ya se audita con tildes
        anonimo = self.app.test_client()
        anonimo.post("/login", data={"usuario": usuario, "password": "no-es-la-suya"})
        cli, _ = self._login(usuario)
        html = cli.get("/perfil").get_data(as_text=True)
        self.assertNotIn("contrasena", html, "ningún texto visible sin tilde")
        self.assertNotIn("Contrasena", html)
        self.assertIn("Contraseña incorrecta (intento 1 de 5", html)
        self.assertNotRegex(html, r"intento \d+/\d+", "«1/5» se escribe «1 de 5»")
        with db.session(self.ruta) as conn:
            detalle = conn.execute(
                "SELECT detail FROM audit_log WHERE action='login.fallo' AND entity_id=? "
                "ORDER BY id DESC LIMIT 1", (usuario,)).fetchone()["detail"]
        self.assertIn("contraseña incorrecta", detalle,
                      "los detalles nuevos ya se guardan con tildes")

    def test_el_detalle_redundante_no_se_repite(self):
        """«contraseña correcta; pendiente el segundo factor» ya lo dice la columna
        «Qué ocurrió», así que la de «Detalle» no lo repite."""
        from webui.vistas import sesion as vista
        self.assertEqual(vista.detalle_en_espanol("contrasena correcta; pendiente el segundo factor"), "")
        self.assertEqual(vista.detalle_en_espanol("contraseña correcta; pendiente el segundo factor"), "")
        self.assertEqual(vista.detalle_en_espanol(None), "")
        self.assertEqual(vista.detalle_en_espanol("usuario inexistente"),
                         "El correo escrito no corresponde a ninguna cuenta.")
        self.assertIn("dirección", vista.detalle_en_espanol("direccion de red desconocida"))

    def test_solo_lectura_no_recibe_enlaces_que_no_puede_abrir(self):
        """Hallazgo medio del revisor: el perfil ofrecía a todo el mundo enlaces a
        Usuarios y a Correo, que responden 403 a quien tiene «Solo lectura»: un
        callejón sin salida en la primera página que visita alguien nuevo."""
        cli, _ = self._login("luis@ejemplo.local")
        html = cli.get("/perfil").get_data(as_text=True)
        self.assertNotIn('href="/usuarios/"', html)
        self.assertNotIn('href="/credenciales/"', html)
        # Sigue explicándose quién lo hace, sin dejar a la persona sin instrucción
        self.assertIn("solo entran los administradores", html)
        self.assertIn("un administrador en el apartado de Correo", html)
        self.assertEqual(cli.get("/usuarios/").status_code, 403)
        self.assertEqual(cli.get("/credenciales/").status_code, 403)
        # Y una administradora sí los tiene
        admin, _ = self._login("ana@ejemplo.local")
        html = admin.get("/perfil").get_data(as_text=True)
        self.assertIn('href="/usuarios/"', html)
        self.assertIn('href="/credenciales/"', html)

    def test_los_fallos_de_la_contrasena_actual_se_cuentan_y_se_auditan(self):
        """Hallazgo medio del revisor: el formulario del perfil comprobaba la
        contraseña actual sin límite, sin bloqueo y sin rastro, así que desde una
        sesión robada se podía adivinar indefinidamente (A07:2025 y A09:2025)."""
        usuario = "fuerza@ejemplo.local"
        cli, _ = self._login(usuario)
        csrf = self._csrf(cli, "/perfil")
        datos = {"csrf": csrf, "actual": "no-es-la-suya", "nueva": NUEVA, "repetir": NUEVA}
        r = cli.post("/perfil", data=datos, follow_redirects=True)
        self.assertIn("La contraseña actual no es correcta.", r.get_data(as_text=True))
        self.assertEqual(self._fila(usuario)["totp_fallos"], 1,
                         "una contraseña actual incorrecta cuenta como intento fallido")
        fallos = self._auditoria("usuario.password.fallo", usuario)
        self.assertTrue(fallos, "el intento debe quedar en la auditoría")
        self.assertIn("intento 1", fallos[-1]["detail"])
        # Al llegar al máximo la cuenta se bloquea y las sesiones se cierran
        for _ in range(4):
            r = cli.post("/perfil", data=datos, follow_redirects=True)
        html = r.get_data(as_text=True)
        self.assertIn("la cuenta queda bloqueada 15 minutos", html)
        fila = self._fila(usuario)
        self.assertEqual(fila["totp_fallos"], 5)
        self.assertTrue(fila["locked_until"], "la cuenta debe quedar bloqueada")
        self.assertEqual(cli.get("/perfil").headers["Location"].split("?")[0], "/login")
        self.assertEqual(len(self._auditoria("usuario.password.fallo", usuario)), 5)
        # La contraseña sigue siendo la de siempre: no se ha cambiado nada
        self.assertTrue(auth.verificar_password(CLAVE, fila["password_hash"]))

    def test_los_minutos_de_bloqueo_concuerdan(self):
        """Hallazgo bajo del revisor: decía «Sí, quedan 1 minutos»."""
        usuario = "minutos@ejemplo.local"
        cli, _ = self._login(usuario)
        hasta = ((datetime.now(timezone.utc) + timedelta(seconds=20))
                 .replace(microsecond=0).isoformat().replace("+00:00", "Z"))
        with db.session(self.ruta) as conn:
            conn.execute("UPDATE users SET locked_until=? WHERE username=?", (hasta, usuario))
        try:
            html = cli.get("/perfil").get_data(as_text=True)
            self.assertIn("Sí, quedan 1 minuto<", html)
            self.assertNotIn("1 minutos", html)
        finally:
            with db.session(self.ruta) as conn:
                conn.execute("UPDATE users SET locked_until=NULL WHERE username=?", (usuario,))

    def test_las_cifras_van_en_formato_espanol(self):
        cli, _ = self._login("ana@ejemplo.local")
        html = cli.get("/perfil").get_data(as_text=True)
        self.assertNotIn("Solo lectura</span>", html.split("Perfil</dt>")[1][:200])
        self.assertIn("Sesiones abiertas", html)
        self.assertNotRegex(html, r"\bmin\.", "«min.» es una abreviatura")


if __name__ == "__main__":
    unittest.main()

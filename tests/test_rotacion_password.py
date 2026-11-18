"""Rotación de credenciales: caducidad a los 30 días e historial de 12 contraseñas.

Petición del usuario del 2026-09-08: «implementar el cambio de clave cada 30 días por
seguridad como rotación de credenciales y que no permita reutilizar contraseñas».

Lo que estas pruebas fijan:
  * users.password_changed_at se anota al crear la cuenta y en cada cambio; a las cuentas
    anteriores a la columna se les pone la fecha de hoy al arrancar (nadie es expulsado el
    primer día);
  * al cambiar la contraseña, por cualquier vía (perfil, cambio obligatorio, administrador,
    restablecimiento, consola), se rechaza la actual y cualquiera de las últimas
    «password_historial» (12), con el mensaje «No puede reutilizar ninguna de sus últimas
    12 contraseñas»; el hash sustituido pasa a password_historial, que se recorta a 12;
  * pasados «password_max_dias» (30) la cuenta entra en el cambio obligatorio que ya
    existía (pantalla bloqueante) con su propio aviso;
  * desde 5 días antes, al entrar se avisa cuántos quedan;
  * el perfil muestra la fecha del último cambio y los días que quedan;
  * con password_max_dias = 0 no hay caducidad.

bcrypt se baja a 4 rondas SOLO en estas pruebas (auth.BCRYPT_RONDAS) porque encadenan más
de una docena de cambios de contraseña, cada uno con hasta trece comparaciones; en
producción el coste es 12. Sin red, base temporal bajo data/."""
from __future__ import annotations

import re
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from threatintel import db
from threatintel.paths import BASE_DIR
from webui import auth

CLAVE = "Rotacion#Inicial2026"
MENSAJE_HISTORIAL = "No puede reutilizar ninguna de sus últimas 12 contraseñas."


def _hace_dias(dias: int) -> str:
    return ((datetime.now(timezone.utc) - timedelta(days=dias))
            .replace(microsecond=0).isoformat().replace("+00:00", "Z"))


def _clave(n: int) -> str:
    return f"Historial#{n:02d}Clave2026"


class TestRotacionPassword(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._rondas = auth.BCRYPT_RONDAS
        auth.BCRYPT_RONDAS = 4
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "rotacion.db")
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            for nombre in ("historial", "caducada", "aviso", "perfil", "sincaducidad",
                           "admin", "consola", "obligatorio", "cinco", "uno", "seis"):
                auth.crear_usuario(conn, f"{nombre}@ejemplo.local", CLAVE, rol="admin",
                                   nombre=f"Persona {nombre}", actor="t")
            auth.crear_usuario(conn, "lectora@ejemplo.local", CLAVE, rol="ciberseguridad",
                               nombre="Lectora", actor="t")
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        auth.BCRYPT_RONDAS = cls._rondas
        cls.dir.cleanup()

    # ------------------------------------------------------------------ ayudas
    def _login(self, nombre: str, clave: str = CLAVE, **kw):
        cli = self.app.test_client()
        r = cli.post("/login", data={"usuario": f"{nombre}@ejemplo.local", "password": clave}, **kw)
        return cli, r

    def _csrf(self, cli, url):
        return re.search(r'name="csrf" value="([^"]+)"', cli.get(url).get_data(as_text=True)).group(1)

    def _usuario(self, nombre: str) -> dict:
        with db.connect(self.ruta) as conn:
            return dict(conn.execute("SELECT * FROM users WHERE username=?",
                                     (f"{nombre}@ejemplo.local",)).fetchone())

    def _fecha_cambio(self, nombre: str, dias: int) -> None:
        with db.session(self.ruta) as conn:
            conn.execute("UPDATE users SET password_changed_at=? WHERE username=?",
                         (_hace_dias(dias), f"{nombre}@ejemplo.local"))

    def _ajuste(self, clave, valor):
        with db.session(self.ruta) as conn:
            db.set_setting(conn, clave, valor)

    # ---------------------------------------------------------------- fechas
    def test_crear_usuario_anota_la_fecha_de_la_contrasena(self):
        fila = self._usuario("perfil")
        self.assertIsNotNone(fila["password_changed_at"])
        cambiada = datetime.fromisoformat(fila["password_changed_at"].replace("Z", "+00:00"))
        self.assertGreater(cambiada, datetime.now(timezone.utc) - timedelta(minutes=5))

    def test_las_cuentas_antiguas_reciben_la_fecha_de_hoy_al_arrancar(self):
        """Migración suave: sin fecha la caducidad no puede contarse, y ponerla a la fecha
        de creación expulsaría el primer día a todo el que lleve más de 30 días."""
        with db.session(self.ruta) as conn:
            conn.execute("UPDATE users SET password_changed_at=NULL WHERE username='consola@ejemplo.local'")
            self.assertIsNone(auth.estado_password({"password_changed_at": None})["restantes"],
                              "sin fecha no caduca")
            self.assertEqual(auth.completar_fecha_password(conn), 1)
            self.assertEqual(auth.completar_fecha_password(conn), 0, "idempotente")
        self.assertIsNotNone(self._usuario("consola")["password_changed_at"])

    def test_estado_password_calcula_dias_restantes(self):
        ahora = datetime(2026, 9, 8, 12, 0, tzinfo=timezone.utc)
        fila = {"password_changed_at": "2026-08-14T12:00:00Z"}   # hace 25 días
        estado = auth.estado_password(fila, cfg={"password_max_dias": 30}, ahora=ahora)
        self.assertEqual((estado["dias"], estado["restantes"]), (25, 5))
        self.assertTrue(estado["avisar"])
        self.assertFalse(estado["caducada"])
        estado = auth.estado_password({"password_changed_at": "2026-08-09T11:00:00Z"},
                                      cfg={"password_max_dias": 30}, ahora=ahora)
        self.assertTrue(estado["caducada"])
        self.assertEqual(estado["restantes"], 0)
        estado = auth.estado_password({"password_changed_at": "2026-09-01T11:00:00Z"},
                                      cfg={"password_max_dias": 30}, ahora=ahora)
        self.assertFalse(estado["avisar"])
        self.assertEqual(estado["restantes"], 23)
        estado = auth.estado_password(fila, cfg={"password_max_dias": 0}, ahora=ahora)
        self.assertIsNone(estado["restantes"])
        self.assertFalse(estado["caducada"])

    # -------------------------------------------------------------- historial
    def test_no_se_puede_reutilizar_ninguna_de_las_ultimas_doce(self):
        usuario = "historial@ejemplo.local"
        with db.session(self.ruta) as conn:
            # La actual no vale
            with self.assertRaises(ValueError) as ctx:
                auth.cambiar_password(conn, usuario, CLAVE, actor="t")
            self.assertEqual(str(ctx.exception), MENSAJE_HISTORIAL)
            for n in range(1, 13):
                auth.cambiar_password(conn, usuario, _clave(n), actor="t")
            # Ahora la actual es la 12 y en el historial están la inicial y de la 1 a la 11
            for repetida in [CLAVE] + [_clave(n) for n in range(1, 13)]:
                with self.assertRaises(ValueError, msg=repetida) as ctx:
                    auth.cambiar_password(conn, usuario, repetida, actor="t")
                self.assertEqual(str(ctx.exception), MENSAJE_HISTORIAL)
            filas = conn.execute("SELECT COUNT(*) FROM password_historial WHERE username=?",
                                 (usuario,)).fetchone()[0]
            self.assertEqual(filas, 12, "el historial se recorta a doce")
            # Una decimotercera saca a la inicial del historial: vuelve a admitirse
            auth.cambiar_password(conn, usuario, _clave(13), actor="t")
            auth.cambiar_password(conn, usuario, CLAVE, actor="t")
            # Y la fecha del cambio se actualiza
            fila = conn.execute("SELECT password_changed_at FROM users WHERE username=?", (usuario,)).fetchone()
            cambiada = datetime.fromisoformat(fila["password_changed_at"].replace("Z", "+00:00"))
            self.assertGreater(cambiada, datetime.now(timezone.utc) - timedelta(minutes=1))

    def test_el_historial_solo_guarda_hashes(self):
        with db.session(self.ruta) as conn:
            auth.cambiar_password(conn, "consola@ejemplo.local", _clave(41), actor="cli")
        with db.connect(self.ruta) as conn:
            filas = conn.execute("SELECT password_hash FROM password_historial").fetchall()
        self.assertTrue(filas)
        for fila in filas:
            self.assertTrue(fila["password_hash"].startswith("$2"), "hash bcrypt, nunca la contraseña")
            self.assertNotIn("Clave2026", fila["password_hash"])

    def test_el_tamano_del_historial_es_configurable(self):
        usuario = "sincaducidad@ejemplo.local"
        self._ajuste("password_historial", 2)
        try:
            with db.session(self.ruta) as conn:
                auth.cambiar_password(conn, usuario, _clave(1), actor="t")
                auth.cambiar_password(conn, usuario, _clave(2), actor="t")
                auth.cambiar_password(conn, usuario, _clave(3), actor="t")
                with self.assertRaises(ValueError) as ctx:
                    auth.cambiar_password(conn, usuario, _clave(2), actor="t")
                self.assertEqual(str(ctx.exception),
                                 "No puede reutilizar ninguna de sus últimas 2 contraseñas.")
                # La inicial ya salió del historial de dos
                auth.cambiar_password(conn, usuario, CLAVE, actor="t")
        finally:
            self._ajuste("password_historial", 12)

    def test_el_perfil_rechaza_repetir_una_anterior_con_el_mensaje(self):
        nombre = "perfil"
        cli, _ = self._login(nombre)
        csrf = self._csrf(cli, "/perfil")
        r = cli.post("/perfil", data={"csrf": csrf, "actual": CLAVE, "nueva": _clave(21),
                                      "repetir": _clave(21)}, follow_redirects=True)
        self.assertIn("Contraseña actualizada.", r.get_data(as_text=True))
        cli, _ = self._login(nombre, _clave(21))
        csrf = self._csrf(cli, "/perfil")
        r = cli.post("/perfil", data={"csrf": csrf, "actual": _clave(21), "nueva": CLAVE,
                                      "repetir": CLAVE}, follow_redirects=True)
        self.assertIn(MENSAJE_HISTORIAL, r.get_data(as_text=True))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(cli.get("/").status_code, 200, "la sesión sigue: no se cambió nada")

    def test_el_administrador_y_el_restablecimiento_tambien_respetan_el_historial(self):
        """La edición de Usuarios y el restablecimiento pasan por auth.cambiar_password, así
        que un administrador tampoco puede poner a alguien una contraseña ya usada.

        webui/vistas/usuarios.py (fichero del coordinador) todavía no captura el ValueError
        del historial en «actualizar», así que hoy responde con un error 500 en vez de con
        el aviso; lo que esta prueba exige es que la contraseña NO cambie. Cuando el
        coordinador añada el try/except, el aviso aparecerá y la comprobación de abajo
        seguirá valiendo."""
        admin, _ = self._login("admin")
        csrf = self._csrf(admin, "/usuarios/")
        uid = self._usuario("lectora")["id"]
        hash_antes = self._usuario("lectora")["password_hash"]
        try:
            r = admin.post(f"/usuarios/{uid}/actualizar",
                           data={"csrf": csrf, "nombre": "Lectora", "rol": "ciberseguridad", "enabled": "1",
                                 "password_nueva": CLAVE, "password_repetir": CLAVE},
                           follow_redirects=True)
        except ValueError as exc:
            # En modo de pruebas Flask propaga la excepción en vez de responder 500.
            self.assertEqual(str(exc), MENSAJE_HISTORIAL)
        else:
            self.assertEqual(r.status_code, 200)
            self.assertIn(MENSAJE_HISTORIAL, r.get_data(as_text=True))
        self.assertEqual(self._usuario("lectora")["password_hash"], hash_antes,
                         "la contraseña repetida no se guarda")
        with db.connect(self.ruta) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM password_historial WHERE username=?",
                                          ("lectora@ejemplo.local",)).fetchone()[0], 0)
        # Restablecer genera una contraseña aleatoria nueva: no puede coincidir con la actual
        r = admin.post(f"/usuarios/{uid}/password", data={"csrf": csrf}, follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        self.assertNotEqual(self._usuario("lectora")["password_hash"], hash_antes)
        with db.connect(self.ruta) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM password_historial WHERE username=?",
                                          ("lectora@ejemplo.local",)).fetchone()[0], 1)

    # ------------------------------------------------------------- caducidad
    def test_a_los_treinta_dias_toca_cambiar_la_contrasena_obligatoriamente(self):
        nombre = "caducada"
        self._fecha_cambio(nombre, 31)
        cli, r = self._login(nombre)
        self.assertEqual(r.headers["Location"], "/cambiar-contrasena")
        # Ninguna ruta de la plataforma responde: todas llevan a la pantalla bloqueante
        for url in ("/", "/activos/", "/amenazas/", "/perfil", "/usuarios/"):
            respuesta = cli.get(url)
            self.assertEqual(respuesta.status_code, 302, url)
            self.assertEqual(respuesta.headers["Location"], "/cambiar-contrasena", url)
        html = cli.get("/cambiar-contrasena").get_data(as_text=True)
        self.assertIn("Su contraseña tiene más de 30 días: por política de seguridad debe "
                      "cambiarla ahora.", html)
        self.assertIn("se renuevan cada 30 días", html)
        self.assertNotIn("la escribió la persona que creó la cuenta", html,
                         "el texto es el de la caducidad, no el de la contraseña inicial")
        self.assertIn("ni ninguna de sus últimas 12 contraseñas", html)
        self.assertEqual(html.count("por política de seguridad debe cambiarla ahora"), 1,
                         "el aviso no se apila")
        # Repetir la actual se rechaza; una nueva desbloquea la plataforma
        csrf = re.search(r'name="csrf" value="([^"]+)"', html).group(1)
        r = cli.post("/cambiar-contrasena", data={"csrf": csrf, "nueva": CLAVE, "repetir": CLAVE},
                     follow_redirects=True)
        self.assertIn("es la misma que la actual", r.get_data(as_text=True))
        r = cli.post("/cambiar-contrasena", data={"csrf": csrf, "nueva": _clave(31), "repetir": _clave(31)})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(cli.get("/").status_code, 200)
        fila = self._usuario(nombre)
        self.assertEqual(fila["must_change"], 0)
        cambiada = datetime.fromisoformat(fila["password_changed_at"].replace("Z", "+00:00"))
        self.assertGreater(cambiada, datetime.now(timezone.utc) - timedelta(minutes=1))
        with db.connect(self.ruta) as conn:
            detalle = conn.execute("SELECT detail FROM audit_log WHERE action='password.cambio_obligatorio' "
                                   "ORDER BY id DESC").fetchone()["detail"]
        self.assertIn("contraseña caducada renovada", detalle)

    def test_una_sesion_abierta_se_bloquea_cuando_la_contrasena_caduca(self):
        """La fecha se lee en cada petición: quien está dentro cuando se cumplen los 30
        días pasa a la pantalla bloqueante en la siguiente página."""
        nombre = "obligatorio"
        cli, _ = self._login(nombre)
        self.assertEqual(cli.get("/").status_code, 200)
        self._fecha_cambio(nombre, 30)
        r = cli.get("/activos/")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers["Location"], "/cambiar-contrasena")
        self._fecha_cambio(nombre, 1)     # deshacer para las demás pruebas

    def test_la_contrasena_inicial_tiene_prioridad_sobre_la_caducidad(self):
        """Con must_change=1 y además caducada, el mensaje es el de la contraseña inicial
        (es la que conoce quien creó la cuenta) y el destino histórico /mi-password."""
        nombre = "seis"
        with db.session(self.ruta) as conn:
            conn.execute("UPDATE users SET must_change=1 WHERE username=?", (f"{nombre}@ejemplo.local",))
        self._fecha_cambio(nombre, 40)
        cli, r = self._login(nombre)
        self.assertIn("/mi-password", r.headers["Location"])
        html = cli.get("/cambiar-contrasena").get_data(as_text=True)
        self.assertIn("Debe cambiar la contraseña antes de continuar.", html)
        self.assertIn("la escribió la persona que creó la cuenta", html)

    def test_con_cero_dias_no_hay_caducidad(self):
        self._ajuste("password_max_dias", 0)
        try:
            nombre = "sincaducidad"
            self._fecha_cambio(nombre, 400)
            cli, r = self._login(nombre)
            self.assertEqual(r.headers["Location"], "/")
            self.assertEqual(cli.get("/").status_code, 200)
            html = cli.get("/perfil").get_data(as_text=True)
            self.assertIn("Sin caducidad", html)
        finally:
            self._ajuste("password_max_dias", 30)

    # ------------------------------------------------------------------ avisos
    def test_cinco_dias_antes_se_avisa_al_entrar(self):
        nombre = "cinco"
        self._fecha_cambio(nombre, 25)
        cli, r = self._login(nombre, follow_redirects=True)
        html = r.get_data(as_text=True)
        self.assertIn("Su contraseña caduca en 5 días.", html)
        self.assertIn("Cámbiela desde Mi perfil", html)
        self.assertEqual(cli.get("/activos/").status_code, 200, "se deja pasar")

    def test_a_un_dia_el_aviso_concuerda_en_singular(self):
        nombre = "uno"
        self._fecha_cambio(nombre, 29)
        _cli, r = self._login(nombre, follow_redirects=True)
        self.assertIn("Su contraseña caduca en 1 día.", r.get_data(as_text=True))

    def test_a_seis_dias_no_se_avisa(self):
        nombre = "aviso"
        self._fecha_cambio(nombre, 24)
        _cli, r = self._login(nombre, follow_redirects=True)
        self.assertNotIn("Su contraseña caduca en", r.get_data(as_text=True))

    # ------------------------------------------------------------------ perfil
    def test_el_perfil_muestra_la_fecha_del_ultimo_cambio_y_los_dias_que_quedan(self):
        nombre = "aviso"
        self._fecha_cambio(nombre, 10)
        cli, _ = self._login(nombre)
        html = cli.get("/perfil").get_data(as_text=True)
        self.assertIn("Último cambio de contraseña", html)
        self.assertIn("Caducidad de la contraseña", html)
        self.assertIn("Quedan 20 días", html)
        self.assertIn("se renuevan cada 30 días", html)
        self.assertIn("ni ninguna de sus últimas 12 contraseñas", html)
        self._fecha_cambio(nombre, 27)
        html = cli.get("/perfil").get_data(as_text=True)
        self.assertIn("Quedan 3 días", html)
        self.assertIn("cámbiela ya", html)
        self._fecha_cambio(nombre, 1)

    def test_bin_gestionar_usuario_comparte_la_politica(self):
        """La consola (bin/gestionar_usuario.py) cambia contraseñas con auth.cambiar_password,
        así que hereda el historial sin código propio."""
        fuente = (BASE_DIR / "bin" / "gestionar_usuario.py").read_text(encoding="utf-8")
        self.assertIn("auth.cambiar_password(", fuente)
        self.assertNotIn("UPDATE users SET password_hash", fuente)


if __name__ == "__main__":
    unittest.main()

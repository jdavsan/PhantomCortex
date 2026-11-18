"""Tiempo de sesión: 30 minutos de inactividad, tope absoluto y rotación del token.

Peticiones del usuario del 2026-09-08: «Establecer el tiempo de sesión máximo de 30
minutos» y «valida el tiempo de validación de cada token donde siempre se pueda renovar
después de cierto tiempo haciendo la app más segura». Diseño que estas pruebas fijan:

  * inactividad («webui_session_minutos», 30): sin peticiones durante ese tiempo la sesión
    muere y la pantalla de acceso dice «Su sesión caducó por inactividad tras 30 minutos»;
  * renovación: cada petición autenticada actualiza last_seen_at, así que quien trabaja
    no se ve expulsado a los 30 minutos («siempre se pueda renovar»);
  * tope absoluto («webui_session_maximo_horas», 12): la renovación no es infinita;
  * rotación («webui_session_rotacion_minutos», 15): cada 15 minutos de actividad se emite
    un token nuevo y el anterior deja de valer en ese mismo instante; el token CSRF no
    cambia, para no romper formularios abiertos en otra pestaña;
  * la sesión pendiente del segundo factor sigue caducando a los diez minutos y la política
    de una sola sesión por usuario se mantiene.

Las fechas se manipulan directamente en web_sessions (last_seen_at, rotado_at, expires_at)
en vez de esperar: es lo que haría el paso del tiempo. Sin red, base temporal bajo data/."""
from __future__ import annotations

import re
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from threatintel import db
from threatintel.paths import BASE_DIR
from webui import auth, totp

CLAVE = "Sesion#Treinta2026"


def _hace(minutos: int = 0, horas: int = 0) -> str:
    """Marca ISO en UTC de hace tantos minutos u horas, en el formato de la base."""
    return ((datetime.now(timezone.utc) - timedelta(minutes=minutos, hours=horas))
            .replace(microsecond=0).isoformat().replace("+00:00", "Z"))


class TestSesionTreintaMinutos(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "sesion_30.db")
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            for nombre in ("inactiva", "renueva", "tope", "rota", "rotacsrf", "pendiente",
                           "directa", "limpieza", "ajustes", "anonima"):
                auth.crear_usuario(conn, f"{nombre}@ejemplo.local", CLAVE, rol="admin",
                                   nombre=f"Persona {nombre}", actor="t")
            cls.secreto = totp.generar_secreto()
            auth.activar_2fa(conn, "pendiente@ejemplo.local", cls.secreto, 0, actor="t")
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    # ------------------------------------------------------------------ ayudas
    def _login(self, nombre: str):
        cli = self.app.test_client()
        r = cli.post("/login", data={"usuario": f"{nombre}@ejemplo.local", "password": CLAVE})
        self.assertEqual(r.status_code, 302)
        return cli

    def _fila(self, nombre: str) -> dict:
        with db.connect(self.ruta) as conn:
            fila = conn.execute("SELECT * FROM web_sessions WHERE username=? ORDER BY rowid DESC",
                                (f"{nombre}@ejemplo.local",)).fetchone()
        return dict(fila) if fila else {}

    def _poner(self, nombre: str, **columnas) -> None:
        asignaciones = ", ".join(f"{c}=?" for c in columnas)
        with db.session(self.ruta) as conn:
            conn.execute(f"UPDATE web_sessions SET {asignaciones} WHERE username=?",
                         (*columnas.values(), f"{nombre}@ejemplo.local"))

    def _csrf(self, cli, url="/perfil"):
        return re.search(r'name="csrf" value="([^"]+)"', cli.get(url).get_data(as_text=True)).group(1)

    def _ajuste(self, clave, valor):
        with db.session(self.ruta) as conn:
            db.set_setting(conn, clave, valor)

    # ------------------------------------------------------------ inactividad
    def test_los_valores_por_defecto_son_los_pedidos(self):
        self.assertEqual(self.app.config["SESSION_MINUTOS"], 30)
        self.assertEqual(self.app.config["SESSION_MAXIMO_HORAS"], 12)
        self.assertEqual(self.app.config["SESSION_ROTACION_MINUTOS"], 15)
        self.assertNotIn("SESSION_HOURS", self.app.config, "el ajuste antiguo ya no se lee")

    def test_tras_treinta_minutos_sin_actividad_la_sesion_caduca_y_se_explica(self):
        cli = self._login("inactiva")
        self.assertEqual(cli.get("/").status_code, 200)
        self._poner("inactiva", last_seen_at=_hace(minutos=31))
        r = cli.get("/activos/")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers["Location"].split("?")[0], "/login")
        html = cli.get("/login").get_data(as_text=True)
        self.assertIn("Su sesión caducó por inactividad tras 30 minutos.", html)
        self.assertEqual(self._fila("inactiva"), {}, "la fila caducada se borra al usarla")
        # El aviso se muestra una sola vez
        self.assertNotIn("caducó por inactividad", cli.get("/login").get_data(as_text=True))

    def test_a_los_veintinueve_minutos_sigue_viva(self):
        cli = self._login("inactiva")
        self._poner("inactiva", last_seen_at=_hace(minutos=29))
        self.assertEqual(cli.get("/").status_code, 200)

    def test_cada_peticion_renueva_la_sesion(self):
        """«Siempre se pueda renovar»: a los 20 minutos se usa, y otros 20 después sigue
        viva porque la actividad reinició la cuenta; last_seen_at se actualiza."""
        cli = self._login("renueva")
        for _ in range(3):
            self._poner("renueva", last_seen_at=_hace(minutos=20))
            self.assertEqual(cli.get("/").status_code, 200)
            visto = datetime.fromisoformat(self._fila("renueva")["last_seen_at"].replace("Z", "+00:00"))
            self.assertGreater(visto, datetime.now(timezone.utc) - timedelta(minutes=1),
                               "la actividad debe renovar last_seen_at")

    def test_el_tiempo_de_inactividad_es_configurable(self):
        self._ajuste("webui_session_minutos", 10)
        try:
            cli = self._login("ajustes")
            self._poner("ajustes", last_seen_at=_hace(minutos=11))
            r = cli.get("/")
            self.assertEqual(r.status_code, 302)
            self.assertIn("caducó por inactividad tras 10 minutos", cli.get("/login").get_data(as_text=True))
        finally:
            self._ajuste("webui_session_minutos", 30)

    def test_llegar_directamente_a_login_con_la_sesion_caducada_tambien_lo_explica(self):
        cli = self._login("directa")
        self._poner("directa", last_seen_at=_hace(minutos=45))
        html = cli.get("/login").get_data(as_text=True)
        self.assertIn("Su sesión caducó por inactividad tras 30 minutos.", html)

    # -------------------------------------------------------------- tope absoluto
    def test_la_sesion_dura_como_maximo_doce_horas_aunque_haya_actividad(self):
        cli = self._login("tope")
        expira = datetime.fromisoformat(self._fila("tope")["expires_at"].replace("Z", "+00:00"))
        ahora = datetime.now(timezone.utc)
        self.assertGreater(expira, ahora + timedelta(hours=11, minutes=58))
        self.assertLess(expira, ahora + timedelta(hours=12, minutes=2))
        # Pasado el tope, ni la actividad reciente la salva
        self._poner("tope", expires_at=_hace(minutos=1), last_seen_at=_hace(minutos=0))
        r = cli.get("/")
        self.assertEqual(r.status_code, 302)
        html = cli.get("/login").get_data(as_text=True)
        self.assertIn("Su sesión alcanzó la duración máxima de 12 horas", html)

    def test_la_rotacion_no_alarga_el_tope_absoluto(self):
        cli = self._login("tope")
        antes = self._fila("tope")["expires_at"]
        self._poner("tope", rotado_at=_hace(minutos=16))
        self.assertEqual(cli.get("/").status_code, 200)
        self.assertEqual(self._fila("tope")["expires_at"], antes)

    # ------------------------------------------------------------------ rotación
    def test_a_los_quince_minutos_de_actividad_se_emite_un_token_nuevo(self):
        cli = self._login("rota")
        viejo = cli.get_cookie("session").value
        hash_viejo = self._fila("rota")["sid_hash"]
        # Antes de los 15 minutos no rota
        self._poner("rota", rotado_at=_hace(minutos=14))
        r = cli.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(cli.get_cookie("session").value, viejo)
        # A los 15 minutos, sí: cookie nueva en la respuesta y hash nuevo en la base
        self._poner("rota", rotado_at=_hace(minutos=15))
        r = cli.get("/")
        self.assertEqual(r.status_code, 200)
        nuevo = cli.get_cookie("session").value
        self.assertNotEqual(nuevo, viejo, "la cookie debe cambiar")
        self.assertRegex("\n".join(r.headers.getlist("Set-Cookie")), r"session=" + re.escape(nuevo))
        fila = self._fila("rota")
        self.assertNotEqual(fila["sid_hash"], hash_viejo)
        self.assertEqual(fila["sid_hash"], auth._hash_sid(nuevo))
        rotado = datetime.fromisoformat(fila["rotado_at"].replace("Z", "+00:00"))
        self.assertGreater(rotado, datetime.now(timezone.utc) - timedelta(minutes=1))
        # El token viejo sigue sirviendo SOLO para leer durante un minuto (periodo de
        # gracia, revisión adversaria del 2026-09-08): una petición que ya estaba en vuelo
        # al rotar (filtro en vivo, segunda pestaña) no expulsa al usuario ni borra la
        # cookie nueva del navegador...
        otro = self.app.test_client()
        otro.set_cookie("session", viejo)
        r_viejo = otro.get("/activos/")
        self.assertEqual(r_viejo.status_code, 200, "dentro de la gracia se lee con el token viejo")
        self.assertNotIn("session=;", "\n".join(r_viejo.headers.getlist("Set-Cookie")),
                         "la respuesta tardía jamás pide borrar la cookie")
        self.assertNotIn("session=", "\n".join(r_viejo.headers.getlist("Set-Cookie")),
                         "ni reemite una cookie con el token viejo")
        # ...y pasado el minuto deja de valer del todo
        self._poner("rota", rotado_at=_hace(minutos=2))
        self.assertEqual(otro.get("/").headers["Location"].split("?")[0], "/login")
        # ...y el nuevo sigue funcionando, con UNA sola fila de sesión
        self.assertEqual(cli.get("/activos/").status_code, 200)
        with db.connect(self.ruta) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM web_sessions WHERE username=?",
                                          ("rota@ejemplo.local",)).fetchone()[0], 1)

    def test_la_rotacion_periodica_conserva_el_token_csrf(self):
        """Un formulario abierto en otra pestaña antes de la rotación debe seguir
        enviándose: el token CSRF solo cambia al entrar y al superar el segundo factor."""
        cli = self._login("rotacsrf")
        csrf = self._csrf(cli)
        self._poner("rotacsrf", rotado_at=_hace(minutos=20))
        self.assertEqual(cli.get("/").status_code, 200)
        self.assertEqual(self._csrf(cli), csrf)
        r = cli.post("/logout", data={"csrf": csrf})
        self.assertEqual(r.headers["Location"], "/login")

    def test_la_rotacion_se_puede_desactivar(self):
        self._ajuste("webui_session_rotacion_minutos", 0)
        try:
            cli = self._login("rota")
            viejo = cli.get_cookie("session").value
            self._poner("rota", rotado_at=_hace(horas=3))
            self.assertEqual(cli.get("/").status_code, 200)
            self.assertEqual(cli.get_cookie("session").value, viejo)
        finally:
            self._ajuste("webui_session_rotacion_minutos", 15)

    # ------------------------------------------------ segundo factor y sesión única
    def test_la_sesion_pendiente_del_segundo_factor_sigue_caducando_a_los_diez_minutos(self):
        cli = self.app.test_client()
        r = cli.post("/login", data={"usuario": "pendiente@ejemplo.local", "password": CLAVE})
        self.assertEqual(r.headers["Location"], "/login/segundo-factor")
        fila = self._fila("pendiente")
        self.assertEqual(fila["mfa_pendiente"], 1)
        expira = datetime.fromisoformat(fila["expires_at"].replace("Z", "+00:00"))
        ahora = datetime.now(timezone.utc)
        self.assertLessEqual(expira, ahora + timedelta(minutes=auth.MINUTOS_SESION_PENDIENTE_2FA, seconds=5))
        # La inactividad no la mata antes: su único límite son los diez minutos
        self._poner("pendiente", last_seen_at=_hace(minutos=9))
        self.assertEqual(cli.get("/login/segundo-factor").status_code, 200)
        # Al completar el código, el tope pasa a ser el absoluto
        csrf = self._csrf(cli, "/login/segundo-factor")
        r = cli.post("/login/segundo-factor", data={"csrf": csrf, "codigo": totp.codigo_en_paso(self.secreto, totp.paso_actual())})
        self.assertEqual(r.status_code, 302)
        expira = datetime.fromisoformat(self._fila("pendiente")["expires_at"].replace("Z", "+00:00"))
        self.assertGreater(expira, datetime.now(timezone.utc) + timedelta(hours=11))

    def test_sigue_habiendo_una_sola_sesion_por_usuario(self):
        a = self._login("limpieza")
        self.assertEqual(a.get("/").status_code, 200)
        b = self._login("limpieza")
        self.assertEqual(a.get("/").status_code, 302, "la primera ventana queda fuera")
        self.assertEqual(b.get("/").status_code, 200)

    def test_la_limpieza_borra_tambien_las_sesiones_inactivas(self):
        self._login("limpieza")
        self._poner("limpieza", last_seen_at=_hace(minutos=40))
        with db.session(self.ruta) as conn:
            self.assertGreaterEqual(auth.limpiar_sesiones_caducadas(conn), 1)
        self.assertEqual(self._fila("limpieza"), {})

    def test_la_sesion_anonima_de_los_avisos_caduca_a_los_treinta_minutos(self):
        """La fila anónima que guarda «Sesión cerrada.» no debe quedarse para siempre."""
        cli = self._login("anonima")
        csrf = self._csrf(cli)
        cli.post("/logout", data={"csrf": csrf})
        token = cli.get_cookie("session").value
        with db.connect(self.ruta) as conn:
            fila = dict(conn.execute("SELECT * FROM web_sessions WHERE sid_hash=?",
                                     (auth._hash_sid(token),)).fetchone())
        self.assertEqual(fila["username"], "")
        expira = datetime.fromisoformat(fila["expires_at"].replace("Z", "+00:00"))
        self.assertLessEqual(expira, datetime.now(timezone.utc) + timedelta(minutes=30, seconds=5))


if __name__ == "__main__":
    unittest.main()

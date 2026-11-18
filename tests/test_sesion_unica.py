"""Una sola sesión por usuario (petición del usuario del 2026-09-07).

«Ajusta que solamente permita una sesión por usuario y no varias». Al completar el
acceso se cierran las demás sesiones de esa persona, de modo que entrar desde otro
navegador o desde otro equipo deja fuera al anterior.

La decisión de diseño que estas pruebas fijan es CUÁNDO se cierran: en el momento en que
el acceso queda completo, no cuando solo se ha comprobado la contraseña. Si se revocara
con la contraseña, quien la robase sin tener el código del segundo factor podría echar de
la plataforma al usuario legítimo cuantas veces quisiera, y además sabría por el efecto
que la contraseña es correcta. Con la comprobación tardía, una sesión a medio abrir no
cierra nada.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from threatintel import db
from threatintel.paths import BASE_DIR

sys.path.insert(0, str(BASE_DIR))
from webui import auth, totp  # noqa: E402

CLAVE = "ClaveSegura#2026"


def _codigo(secreto: str) -> str:
    return totp.codigo_en_paso(secreto, totp.paso_actual())


class TestUnaSolaSesion(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "sesion_unica.db")
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "sola@ejemplo.local", CLAVE, rol="admin",
                               nombre="Persona Sin Doble Factor", actor="t")
            auth.crear_usuario(conn, "otra@ejemplo.local", CLAVE, rol="ciberseguridad",
                               nombre="Otra Persona", actor="t")
            auth.crear_usuario(conn, "con2fa@ejemplo.local", CLAVE, rol="ciberseguridad",
                               nombre="Persona Con Doble Factor", actor="t")
            cls.secreto = totp.generar_secreto()
            auth.activar_2fa(conn, "con2fa@ejemplo.local", cls.secreto, 0, actor="t")
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    # ------------------------------------------------------------------ ayudas
    def _ventana(self, usuario: str = "sola@ejemplo.local"):
        """Un navegador nuevo que entra con contraseña (sin segundo factor)."""
        cli = self.app.test_client()
        respuesta = cli.post("/login", data={"usuario": usuario, "password": CLAVE},
                             follow_redirects=True)
        self.assertEqual(respuesta.status_code, 200)
        return cli, respuesta.get_data(as_text=True)

    def _dentro(self, cli) -> bool:
        return cli.get("/activos/").status_code == 200

    def _sesiones(self, usuario: str) -> int:
        with db.session(self.ruta) as conn:
            return conn.execute("SELECT COUNT(*) FROM web_sessions WHERE username=?",
                                (usuario,)).fetchone()[0]

    # ------------------------------------------------------- sin segundo factor
    def test_el_segundo_acceso_cierra_el_primero(self):
        a, _ = self._ventana()
        self.assertTrue(self._dentro(a))
        b, html = self._ventana()
        self.assertFalse(self._dentro(a), "la primera ventana sigue dentro")
        self.assertTrue(self._dentro(b))
        self.assertEqual(self._sesiones("sola@ejemplo.local"), 1)
        self.assertIn("Se ha cerrado la sesión que tenía abierta", html,
                      "no se avisa de que se cerró la otra sesión")

    def test_el_aviso_dice_qué_hacer_si_no_ha_sido_la_persona(self):
        self._ventana()
        _, html = self._ventana()
        self.assertIn("una sola sesión por usuario", html)
        self.assertIn("cambie su contraseña", html)
        self.assertIn("administración", html)

    def test_el_primer_acceso_no_avisa_de_nada(self):
        with db.session(self.ruta) as conn:
            auth.revocar_sesiones(conn, "otra@ejemplo.local")
        _, html = self._ventana("otra@ejemplo.local")
        self.assertNotIn("Se ha cerrado la sesión que tenía abierta", html)

    def test_no_toca_las_sesiones_de_otras_personas(self):
        otra, _ = self._ventana("otra@ejemplo.local")
        self._ventana("sola@ejemplo.local")
        self._ventana("sola@ejemplo.local")
        self.assertTrue(self._dentro(otra), "el acceso de una persona cerró el de otra")
        self.assertEqual(self._sesiones("otra@ejemplo.local"), 1)

    def test_queda_constancia_en_la_auditoria(self):
        self._ventana()
        self._ventana()
        with db.session(self.ruta) as conn:
            fila = conn.execute(
                """SELECT username, detail FROM audit_log WHERE action='sesion.unica'
                   ORDER BY id DESC LIMIT 1""").fetchone()
        self.assertIsNotNone(fila, "el cierre por sesión única no se audita")
        self.assertEqual(fila["username"], "sola@ejemplo.local")
        self.assertIn("se cerró la sesión anterior", fila["detail"])

    def test_la_concordancia_del_detalle_es_correcta(self):
        """«se cerraron 1 sesión anteriores» era el texto de la primera versión."""
        self._ventana()
        self._ventana()
        with db.session(self.ruta) as conn:
            detalles = [r["detail"] for r in conn.execute(
                "SELECT detail FROM audit_log WHERE action='sesion.unica'")]
        for d in detalles:
            self.assertNotIn("se cerraron 1 ", d)
            self.assertFalse(d.endswith("1 sesiones anteriores"), d)

    # ------------------------------------------------------- con segundo factor
    def _entrar_con_2fa(self, cli) -> None:
        """Acceso completo de la cuenta con segundo factor.

        Se usa un código de recuperación recién generado en cada llamada: el código de
        la aplicación no vale dos veces en el mismo paso de 30 segundos, así que dos
        pruebas seguidas se pisarían entre ellas."""
        cli.post("/login", data={"usuario": "con2fa@ejemplo.local", "password": CLAVE})
        with db.session(self.ruta) as conn:
            codigos = auth.regenerar_codigos_2fa(conn, "con2fa@ejemplo.local", actor="t")
        cli.post("/login/segundo-factor",
                 data={"codigo": codigos[0], "csrf": self._csrf(cli)},
                 follow_redirects=True)

    def test_la_contrasena_sola_no_cierra_la_sesion_de_nadie(self):
        """El punto importante: quien roba la contraseña de una cuenta con segundo
        factor NO puede echar al usuario legítimo, porque su sesión se queda a medias
        y las demás no se revocan hasta que se acierta el código."""
        legitima = self.app.test_client()
        self._entrar_con_2fa(legitima)
        self.assertTrue(self._dentro(legitima), "la persona legítima no llegó a entrar")

        # El atacante conoce la contraseña pero no el código: su sesión queda pendiente
        atacante = self.app.test_client()
        atacante.post("/login", data={"usuario": "con2fa@ejemplo.local", "password": CLAVE})
        self.assertFalse(self._dentro(atacante), "una sesión pendiente da acceso")
        self.assertTrue(self._dentro(legitima),
                        "una contraseña robada sin el código echó al usuario legítimo")
        # y un código equivocado tampoco cierra nada
        atacante.post("/login/segundo-factor",
                      data={"codigo": "000000", "csrf": self._csrf(atacante)})
        self.assertTrue(self._dentro(legitima),
                        "un código equivocado echó al usuario legítimo")

    def test_completar_el_codigo_si_cierra_la_anterior(self):
        primera = self.app.test_client()
        self._entrar_con_2fa(primera)
        self.assertTrue(self._dentro(primera))

        segunda = self.app.test_client()
        self._entrar_con_2fa(segunda)
        self.assertTrue(self._dentro(segunda), "la segunda ventana no entró")
        self.assertFalse(self._dentro(primera), "la primera ventana sigue dentro")
        self.assertEqual(self._sesiones("con2fa@ejemplo.local"), 1)

    def _csrf(self, cli) -> str:
        import re
        html = cli.get("/login/segundo-factor").get_data(as_text=True)
        encontrado = re.search(r'name="csrf" value="([^"]+)"', html)
        self.assertIsNotNone(encontrado, "sin token CSRF en la pantalla del segundo factor")
        return encontrado.group(1)


if __name__ == "__main__":
    unittest.main()

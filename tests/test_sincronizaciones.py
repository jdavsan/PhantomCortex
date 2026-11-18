"""Módulo «Consultas a OCS Inventory» y el horario en dos fases (2026-09-07).

El usuario pidió «un módulo en administración que me deje ver las fechas y horas en las
que se ejecutó la consulta a las 2 bases de datos», y que la consulta diaria pase a las
07:30 «para que de esta forma las alertas se envíen a las 8 am y no después de las 8 am».

Lo segundo obligó a partir la ejecución diaria en dos: a las 07:30 todo el trabajo (OCS,
recolección, enriquecimiento) y a las 08:00 solo clasificar y enviar. El motivo medido:
el correo salía entre 7 y 22 minutos después de las 08:00, y la mayor parte era el
enriquecimiento contra NVD sin clave de API, no la consulta a OCS (que cuesta un minuto).
"""
from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path

from threatintel import db, programacion
from threatintel.paths import BASE_DIR

sys.path.insert(0, str(BASE_DIR))
from webui import auth  # noqa: E402
from webui.vistas.sincronizaciones import POR_PAGINA  # noqa: E402

CLAVE = "ClaveSegura#2026"

CRONTAB_DE_PRUEBA = """\
# Comentario que no debe salir
SHELL=/bin/bash
DIR=/opt/inteligencia_amenazas
30 7 * * * cd $DIR && $PY bin/ejecucion_diaria.py --sin-alerta >> logs/cron_diario.log 2>&1
0 8 * * * cd $DIR && $PY bin/ejecucion_diaria.py --solo-alerta >> logs/cron_diario.log 2>&1
0 13 * * * cd $DIR && $PY bin/enriquecer.py >> logs/cron_enriquecimiento.log 2>&1
*/5 * * * * /usr/local/bin/mantenimiento_raid.sh >/dev/null 2>&1
0 3 * * 1 cd $DIR && ./create_backup.sh >> logs/backup.log 2>&1
"""


class TestHorarioDelProgramador(unittest.TestCase):
    """El horario sale del cron, que es la única fuente de verdad."""

    def test_solo_las_ordenes_de_la_plataforma(self):
        horario = programacion.leer_crontab(CRONTAB_DE_PRUEBA)
        horas = {h["hora"]: h["orden"] for h in horario}
        self.assertEqual(horas.get("07:30"), "ejecucion_diaria.py --sin-alerta")
        self.assertEqual(horas.get("08:00"), "ejecucion_diaria.py --solo-alerta")
        self.assertEqual(horas.get("13:00"), "enriquecer.py")
        # El respaldo y el guion del RAID no son de la plataforma
        self.assertNotIn("03:00", horas)
        self.assertFalse(any("mantenimiento_raid" in h["orden"] for h in horario))

    def test_no_se_muestran_los_comentarios_ni_las_variables(self):
        for h in programacion.leer_crontab(CRONTAB_DE_PRUEBA):
            self.assertFalse(h["orden"].startswith("#"))
            self.assertNotIn("SHELL", h["orden"])

    def test_los_horarios_que_no_son_una_hora_fija_se_descartan(self):
        """«*/5» no es una hora que se pueda mostrar en una lista de horarios."""
        self.assertEqual(programacion.leer_crontab("*/5 * * * * bin/ejecucion_diaria.py"), [])
        self.assertEqual(programacion.leer_crontab("0 7,19 * * * bin/ejecucion_diaria.py"), [])

    def test_la_orden_mas_especifica_gana(self):
        """«--sin-alerta» debe reconocerse antes que «ejecucion_diaria.py» a secas."""
        h = programacion.leer_crontab("30 7 * * * $PY bin/ejecucion_diaria.py --sin-alerta")
        self.assertEqual(h[0]["orden"], "ejecucion_diaria.py --sin-alerta")

    def test_van_ordenados_por_hora(self):
        horas = [h["hora"] for h in programacion.leer_crontab(CRONTAB_DE_PRUEBA)]
        self.assertEqual(horas, sorted(horas))

    def test_si_no_se_puede_leer_no_se_borra_lo_anterior(self):
        """Un horario de ayer con su fecha a la vista es mejor que ninguno."""
        with tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data")) as d:
            ruta = str(Path(d) / "h.db")
            db.init_db(ruta)
            with db.session(ruta) as conn:
                programacion.registrar(conn, texto=CRONTAB_DE_PRUEBA)
                antes = programacion.guardado(conn)
                self.assertTrue(antes["horario"])
                programacion.registrar(conn, texto="# nada que reconocer")
                despues = programacion.guardado(conn)
            self.assertEqual(antes["horario"], despues["horario"])
            self.assertIsNotNone(despues["leido_at"])


class TestPaginaDeConsultas(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "sincronizaciones.db")
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "jefa@ejemplo.local", CLAVE, rol="admin",
                               nombre="Jefa Administradora", actor="t")
            auth.crear_usuario(conn, "lectora@ejemplo.local", CLAVE, rol="ciberseguridad",
                               nombre="Lectora Sin Permisos", actor="t")
            programacion.registrar(conn, texto=CRONTAB_DE_PRUEBA)
            # 25 consultas correctas de cada base y una fallida en cada una: más de una
            # página, para comprobar la paginación de 20.
            for i in range(25):
                for origen in ("servidores", "equipos"):
                    conn.execute(
                        """INSERT INTO sync_ocs(origen, started_at, finished_at, status,
                                activos, software, nuevos, cambiados, desaparecidos, duracion_ms)
                           VALUES(?,?,?,'success',?,?,?,?,?,?)""",
                        (origen, f"2026-08-{i + 1:02d}T12:30:00Z", f"2026-08-{i + 1:02d}T12:31:00Z",
                         500 + i, 400000 + i, i, i * 2, 0, 45000 + i))
            for origen in ("servidores", "equipos"):
                conn.execute(
                    """INSERT INTO sync_ocs(origen, started_at, finished_at, status, error)
                       VALUES(?,?,?,'failed',?)""",
                    (origen, "2026-09-01T12:30:00Z", "2026-09-01T12:30:08Z",
                     "OperationalError: (2003, \"Can't connect to MySQL server\")"))
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def _cliente(self, usuario="jefa@ejemplo.local"):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": usuario, "password": CLAVE})
        return cli

    def _html(self, url: str) -> str:
        respuesta = self._cliente().get(url)
        self.assertEqual(respuesta.status_code, 200, url)
        html = respuesta.get_data(as_text=True)
        # CSP estricta: la página no puede traer estilo ni código en línea
        self.assertIsNone(re.search(r"\sstyle\s*=", html), f"style= en {url}")
        self.assertIsNone(re.search(r"\son[a-z]+\s*=", html), f"on*= en {url}")
        return html

    # ------------------------------------------------------------ contenido
    def test_muestra_las_dos_bases_con_su_fecha_y_hora(self):
        html = self._html("/sincronizaciones/")
        self.assertIn("Servidores", html)
        # «Equipos de cómputo» desde el 2026-09-08: era el tercer nombre que la
        # plataforma daba a la misma cosa y el usuario lo señaló.
        self.assertIn("Equipos de cómputo", html)
        self.assertNotIn("Equipos de usuario", html)
        # la fecha y la hora de la última consulta de cada base, en español
        self.assertIn("1 de septiembre de 2026", html)
        self.assertIn("Última consulta", html)

    def test_muestra_el_horario_leido_del_programador(self):
        html = self._html("/sincronizaciones/")
        self.assertIn("07:30", html)
        self.assertIn("08:00", html)
        self.assertIn("Consulta a OCS, recolección y enriquecimiento", html)
        self.assertIn("Clasificación y envío de la alerta", html)
        self.assertNotIn("Todavía no hay horario registrado", html)

    def test_dice_a_que_servidor_y_base_se_conecta_sin_la_contrasena(self):
        html = self._html("/sincronizaciones/")
        self.assertIn("A qué base se conecta", html)
        self.assertIn("ocsweb", html)
        # ninguna contraseña ni nombre de variable de credenciales
        for prohibido in ("PASSWORD", "_PASSWORD", "password="):
            self.assertNotIn(prohibido, html, "la página no debe nombrar la contraseña")

    def test_el_error_de_una_consulta_fallida_se_ve(self):
        html = self._html("/sincronizaciones/?estado=failed")
        self.assertIn("Fallida", html)
        self.assertIn("Can&#39;t connect to MySQL server", html)

    # ------------------------------------------------------------ paginación
    def test_se_pagina_de_a_veinte(self):
        html = self._html("/sincronizaciones/")
        cuerpo = html.split('id="tabla-sincronizaciones"', 1)[1].split("<tbody>", 1)[1]
        cuerpo = cuerpo.split("</tbody>", 1)[0]
        self.assertEqual(cuerpo.count("<tr"), POR_PAGINA)
        self.assertIn("consultas ·", html)

    def test_el_filtro_se_conserva_al_cambiar_de_pagina(self):
        html = self._html("/sincronizaciones/?origen=equipos")
        nav = re.search(r'<nav class="paginacion"[^>]*>.*?</nav>', html, re.S)
        self.assertIsNotNone(nav, "sin paginación")
        self.assertIn("origen=equipos", nav.group(0))

    def test_pagina_fuera_de_rango_no_da_error(self):
        for sufijo in ("?pagina=0", "?pagina=-3", "?pagina=abc", "?pagina=99999", "?pagina="):
            with self.subTest(sufijo=sufijo):
                self.assertIn("Registro de consultas", self._html(f"/sincronizaciones/{sufijo}"))

    def test_un_filtro_inventado_se_ignora_en_lugar_de_romper(self):
        html = self._html("/sincronizaciones/?origen=inventado&estado=inventado")
        self.assertIn("Registro de consultas", html)

    # ------------------------------------------------------------ permisos
    def test_solo_para_administradores(self):
        lectora = self._cliente("lectora@ejemplo.local")
        self.assertEqual(lectora.get("/sincronizaciones/").status_code, 403)
        self.assertEqual(self._cliente().get("/sincronizaciones/").status_code, 200)
        self.assertEqual(self.app.test_client().get("/sincronizaciones/").status_code, 302)

    def test_esta_en_el_menu_de_administracion(self):
        html = self._html("/sincronizaciones/")
        self.assertIn("Sincronización", html)
        self.assertIn('href="/sincronizaciones/"', html)
        # y la lectora no ve la entrada, porque no ve el grupo de administración
        lectora = self._cliente("lectora@ejemplo.local")
        self.assertNotIn('href="/sincronizaciones/"',
                         lectora.get("/").get_data(as_text=True))

    # ------------------------------------------------------------ no acciona
    def test_la_pagina_no_lanza_ninguna_consulta(self):
        """Es de consulta: la sincronización a demanda sigue en Activos."""
        reglas = [r for r in self.app.url_map.iter_rules()
                  if r.endpoint.startswith("sincronizaciones.")]
        self.assertTrue(reglas)
        for r in reglas:
            self.assertNotIn("POST", r.methods or set(), f"{r.endpoint} acepta POST")


class TestDosFasesDeLaEjecucionDiaria(unittest.TestCase):
    """El correo debe salir a las 08:00, no cuando termine todo el trabajo."""

    def test_el_guion_admite_las_dos_fases(self):
        texto = (BASE_DIR / "bin" / "ejecucion_diaria.py").read_text(encoding="utf-8")
        self.assertIn('"--solo-alerta"', texto)
        self.assertIn('"--sin-ocs"', texto)
        self.assertIn('"--sin-alerta"', texto)

    def test_solo_alerta_omite_el_trabajo_pesado(self):
        """Con --solo-alerta no se consulta OCS, ni se recolecta, ni se enriquece."""
        texto = (BASE_DIR / "bin" / "ejecucion_diaria.py").read_text(encoding="utf-8")
        for guarda in ("args.solo_alerta or args.sin_ocs",
                       "if args.solo_alerta:"):
            self.assertIn(guarda, texto)
        # y avisa si el inventario que va a usar es viejo
        self.assertIn("el inventario tiene más de 6 horas", texto)

    def test_la_ejecucion_diaria_registra_el_horario(self):
        texto = (BASE_DIR / "bin" / "ejecucion_diaria.py").read_text(encoding="utf-8")
        self.assertIn("programacion.registrar(conn)", texto)


if __name__ == "__main__":
    unittest.main()
